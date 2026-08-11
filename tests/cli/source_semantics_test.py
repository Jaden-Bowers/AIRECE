#!/usr/bin/env python3
"""Check source-backed compiler output for conservative semantic contracts."""

from __future__ import annotations

import json
import argparse
import pathlib
import re
import struct
import subprocess
import sys
import tempfile


def run(airece: pathlib.Path, *arguments: str) -> str:
    completed = subprocess.run(
        [str(airece), *arguments], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=20, check=False,
    )
    if completed.returncode not in (0, 3):
        raise AssertionError(
            f"command failed ({completed.returncode}): {completed.stderr}")
    return completed.stdout


def pe_exports(path: pathlib.Path) -> dict[str, str]:
    """Read enough of a PE export directory to locate the source fixtures."""
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise AssertionError("source fixture is not PE")
    sections_count, optional_size = struct.unpack_from("<H12xH", data, pe + 6)
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        directory = optional + 112
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
        directory = optional + 96
    else:
        raise AssertionError(f"unsupported PE optional-header magic: {magic:#x}")
    export_rva = struct.unpack_from("<I", data, directory)[0]
    sections = optional + optional_size

    def offset(rva: int) -> int:
        for index in range(sections_count):
            section = sections + index * 40
            virtual_size, virtual_address, raw_size, raw = struct.unpack_from(
                "<IIII", data, section + 8)
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                return raw + rva - virtual_address
        raise AssertionError(f"RVA is outside file-backed sections: {rva:#x}")

    export = offset(export_rva)
    function_count, name_count, functions_rva, names_rva, ordinals_rva = \
        struct.unpack_from("<IIIII", data, export + 20)
    function_table = offset(functions_rva)
    name_table = offset(names_rva)
    ordinal_table = offset(ordinals_rva)
    result: dict[str, str] = {}
    for index in range(name_count):
        name_rva = struct.unpack_from("<I", data, name_table + index * 4)[0]
        name_offset = offset(name_rva)
        end = data.index(b"\0", name_offset)
        name = data[name_offset:end].decode("ascii")
        ordinal = struct.unpack_from("<H", data, ordinal_table + index * 2)[0]
        if ordinal >= function_count:
            continue
        function_rva = struct.unpack_from(
            "<I", data, function_table + ordinal * 4)[0]
        result[name] = f"0x{image_base + function_rva:x}"
    return result


def clang_fixtures(source: pathlib.Path, clang_cl: pathlib.Path,
                   lld_link: pathlib.Path, directory: pathlib.Path) -> list[pathlib.Path]:
    fixtures: list[pathlib.Path] = []
    for label, optimize in (("o0", "/Od"), ("o2", "/O2")):
        object_path = directory / f"semantic-clang-{label}.obj"
        fixture = directory / f"semantic-clang-{label}.dll"
        compile_result = subprocess.run(
            [str(clang_cl), "/nologo", "/c", optimize, "/Ob0" if label == "o0" else "/Ob2",
             "/GS-", f"/Fo{object_path}", str(source)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if compile_result.returncode != 0:
            raise AssertionError(f"clang-cl fixture compile failed: {compile_result.stderr}")
        link_result = subprocess.run(
            [str(lld_link), "/dll", "/entry:airece_semantic_entry", "/nodefaultlib",
             f"/out:{fixture}", str(object_path)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if link_result.returncode != 0:
            raise AssertionError(f"lld-link fixture link failed: {link_result.stderr}")
        fixtures.append(fixture)
    return fixtures


def verify_fixture(airece: pathlib.Path, fixture: pathlib.Path) -> None:
    exports = pe_exports(fixture)
    expected = {
        "airece_semantic_load", "airece_semantic_branch",
        "airece_semantic_switch", "airece_semantic_dense_switch",
        "airece_semantic_agent_dense_switch",
        "airece_semantic_loop", "airece_semantic_storage",
        "airece_semantic_transform", "airece_semantic_interproc",
        "airece_semantic_memory_flow",
    }
    missing = expected - exports.keys()
    if missing:
        raise AssertionError(f"compiler fixture exports not discovered: {sorted(missing)}")

    expected_arguments = {
        "airece_semantic_load": 1,
        "airece_semantic_branch": 1,
        "airece_semantic_switch": 1,
        "airece_semantic_dense_switch": 1,
        "airece_semantic_agent_dense_switch": 2,
        "airece_semantic_loop": 2,
        "airece_semantic_storage": 1,
        "airece_semantic_transform": 1,
        "airece_semantic_interproc": 1,
        "airece_semantic_memory_flow": 2,
    }
    documents: dict[str, dict[str, object]] = {}
    optimized = "opt" in fixture.stem or "o2" in fixture.stem
    for name in sorted(expected):
        address = exports[name]
        document = json.loads(run(
            airece, "fn", str(fixture), address, "--view", "json",
            "--profile", "fast", "--max-bytes", "65536",
            "--max-statements", "256", "--max-evidence", "256",
        ))
        documents[name] = document
        parameters = document.get("parameters", [])
        argument_indices = sorted(parameter["argument_index"] for parameter in parameters)
        wanted = list(range(expected_arguments[name]))
        if argument_indices != wanted:
            raise AssertionError(
                f"wrong parameter identity/count for {name}: "
                f"expected {wanted}, got {argument_indices}")
        statements = document["statements"]
        by_node: dict[int, list[dict[str, object]]] = {}
        for statement in statements:
            by_node.setdefault(statement["node"], []).append(statement)
            if statement["kind"] == "return":
                if len(statement["values"]) > 1:
                    raise AssertionError(f"machine state leaked into return: {statement}")
                if re.search(r"\b(rsp|carry|parity|auxiliary|zero|sign|overflow)\b",
                             statement["text"], re.IGNORECASE):
                    raise AssertionError(f"machine state leaked into return text: {statement}")
            if statement["kind"] == "memory-read":
                destination = statement["text"].split("=", 1)[0].strip()
                if "(" in destination or destination.startswith("load"):
                    raise AssertionError(f"expression used as load destination: {statement}")
            if statement["kind"] == "memory-write":
                match = re.match(r"store\d+\(([^,]+),\s*(.+)\)$", statement["text"])
                if match and match.group(1).strip() == match.group(2).strip():
                    raise AssertionError(f"storage address reused as stored data: {statement}")

        terminal = {"return", "trap", "fault"}
        for node, node_statements in by_node.items():
            terminal_seen = False
            for statement in node_statements:
                if terminal_seen:
                    raise AssertionError(
                        f"statement follows terminal transfer in node {node}: {statement}")
                terminal_seen = statement["kind"] in terminal or bool(
                    statement.get("no_return"))
        if name == "airece_semantic_storage":
            memory_text = "\n".join(
                statement["text"] for statement in statements
                if statement["kind"] in {"memory-read", "memory-write"})
            if "&stack_" not in memory_text:
                raise AssertionError(
                    f"storage fixture lacks an address-qualified stack identity: {memory_text}")

        if (name == "airece_semantic_branch" and optimized and
                fixture.name == "airece-semantic-source-fixture-opt.dll"):
            predicates = [statement for statement in statements
                          if statement["kind"] == "branch" and
                          statement["values"]]
            if not predicates or not any("arg0" in statement["text"]
                                         for statement in predicates):
                raise AssertionError(
                    f"optimized branch predicate lost its arg0 dependency: {predicates}")

        if (name == "airece_semantic_loop" and not optimized and
                fixture.name == "airece-semantic-source-fixture.dll"):
            inductions = [region["induction"] for region in document["control"]["regions"]
                          if region["kind"] in {"while", "do-while"}]
            if not any(induction["recovered"] and induction["step"] == 1 and
                       induction["comparison"] in {"ult", "ule"}
                       for induction in inductions):
                raise AssertionError(
                    f"simple source loop lacks an unsigned +1 induction fact: {inductions}")

        if name == "airece_semantic_dense_switch":
            mappings = [region for region in document["control"]["regions"]
                        if region["kind"] == "switch"]
            required_mapping = fixture.name.startswith("airece-semantic-source-fixture")
            if (required_mapping and not mappings) or (mappings and not any(
                    region["switch_values_complete"] and
                    [case["value"] for case in region["switch_cases"]] ==
                    [0, 1, 2, 3, 4, 5] for region in mappings)):
                raise AssertionError(
                    f"dense switch lacks its exact source case values: {mappings}")

        if name == "airece_semantic_agent_dense_switch" and optimized:
            raw_agent = run(
                airece, "fn", str(fixture), address, "--view", "agent",
                "--profile", "balanced", "--max-bytes", "4096",
                "--max-statements", "128", "--max-evidence", "128",
            )
            if len(raw_agent.encode("utf-8")) > 4096:
                raise AssertionError("agent view exceeded its byte budget")
            agent = json.loads(raw_agent)
            if agent["function"]["entry"].lower() != address.lower():
                raise AssertionError(f"agent view resolved the wrong entry: {agent}")
            switches = agent.get("switches", [])
            expected_results = [
                "arg1 + 0xb", "arg1 * 3", "arg1 - 0x13",
                "arg1 ^ 0x55", "arg1 + 0x65", "arg1 - 7",
            ]
            if (len(switches) != 1 or switches[0]["selector"] != "arg0 & 7" or
                    [item["value"] for item in switches[0]["cases"]] != list(range(6)) or
                    [item["result"] for item in switches[0]["cases"]] != expected_results or
                    switches[0]["default"]["result"] != "arg1 ^ 0x313"):
                raise AssertionError(f"agent dense-switch semantics incomplete: {switches}")
            if agent.get("memory_effects") or "trap" in raw_agent.lower():
                raise AssertionError(f"agent view leaked dispatch machinery: {agent}")

        pseudo = run(
            airece, "fn", str(fixture), address, "--view", "pseudo",
            "--profile", "fast", "--max-bytes", "65536",
            "--max-statements", "256",
        )
        if re.search(r"(?m)^\s*case\s+0x", pseudo):
            raise AssertionError("switch destination address emitted as a case value")
        if re.search(r"\b[^;()]+\s+-\s+[^;()]+\s+==\s+0\b", pseudo):
            raise AssertionError("subtraction-zero flag leaked instead of a comparison")
        definitions = set(re.findall(r"(?m)^(F[0-9a-fA-F]+_L\d+):", pseudo))
        references = set(re.findall(r"\b(F[0-9a-fA-F]+_L\d+)\b", pseudo))
        if references - definitions:
            raise AssertionError(
                f"undefined qualified labels: {sorted(references - definitions)}")
        if "undefined_x86_flag" in pseudo or "multi_bit_shift_of" in pseudo:
            raise AssertionError("undefined flag bookkeeping leaked into pseudocode")

    # Source-backed directed-flow facts. These intentionally run only where a
    # real call remains after optimization; optimized tail calls are validated
    # by the ordinary semantic contract above.
    interproc = documents["airece_semantic_interproc"]
    calls = [statement for statement in interproc["statements"]
             if statement["kind"] == "call"]
    if calls:
        call_address = calls[0]["address"]
        returned = [statement for statement in interproc["statements"]
                    if statement["kind"] == "return"]
        call_values = set(calls[0]["values"])
        if not returned or not any(call_values & set(statement["dependencies"])
                                   for statement in returned):
            raise AssertionError(
                f"caller return does not depend on its callee result: {returned}")
        flow = json.loads(run(
            airece, "flow", str(fixture),
            "--source", f"funcarg(0)@{exports['airece_semantic_interproc']}",
            "--target", f"callresult@{call_address}",
            "--mode", "taint", "--function-depth", "3",
            "--max-paths", "4", "--max-states", "2000", "--json",
        ))
        if flow["verdict"] != "may-flow" or not flow["influences"]:
            raise AssertionError(
                f"source argument did not flow through the source-backed callee: {flow}")

    memory = documents["airece_semantic_memory_flow"]
    writes = [statement for statement in memory["statements"]
              if statement["kind"] == "memory-write" and
              "&stack_" not in statement["text"]]
    if not writes:
        raise AssertionError("source memory-flow fixture has no pointee write")
    memory_flow = json.loads(run(
        airece, "flow", str(fixture),
        "--source", f"funcarg(1)@{exports['airece_semantic_memory_flow']}",
        "--target", f"memory-write@{writes[-1]['address']}",
        "--mode", "taint", "--function-depth", "1",
        "--max-paths", "4", "--max-states", "2000", "--json",
    ))
    if memory_flow["verdict"] != "may-flow" or not memory_flow["influences"]:
        raise AssertionError(
            f"source argument did not reach the source-backed pointee write: {memory_flow}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("airece", type=pathlib.Path)
    parser.add_argument("fixtures", nargs="+", type=pathlib.Path)
    parser.add_argument("--source", type=pathlib.Path)
    parser.add_argument("--clang-cl", type=pathlib.Path)
    parser.add_argument("--lld-link", type=pathlib.Path)
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="airece-semantic-") as temporary:
        fixtures = list(arguments.fixtures)
        if arguments.source and arguments.clang_cl and arguments.lld_link:
            fixtures.extend(clang_fixtures(
                arguments.source, arguments.clang_cl, arguments.lld_link,
                pathlib.Path(temporary)))
        for fixture in fixtures:
            verify_fixture(arguments.airece, fixture)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
