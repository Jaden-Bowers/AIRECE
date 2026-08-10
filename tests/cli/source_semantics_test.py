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
        "airece_semantic_loop", "airece_semantic_storage",
    }
    missing = expected - exports.keys()
    if missing:
        raise AssertionError(f"compiler fixture exports not discovered: {sorted(missing)}")

    for name in sorted(expected):
        address = exports[name]
        document = json.loads(run(
            airece, "fn", str(fixture), address, "--view", "json",
            "--profile", "fast", "--max-bytes", "65536",
            "--max-statements", "256", "--max-evidence", "256",
        ))
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
