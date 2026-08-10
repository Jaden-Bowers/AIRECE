#!/usr/bin/env python3
"""Bounded semantic-quality evaluation for synthetic, compiler, and Assemblage PE corpora."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import Counter
from typing import Any, Iterable


PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"}


def command(executable: pathlib.Path, *arguments: str, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [str(executable), *arguments],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        return {
            "exit": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        }
    except subprocess.TimeoutExpired as error:
        return {
            "exit": None,
            "stdout": error.stdout or "",
            "stderr": error.stderr or "",
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "timeout": True,
        }


def manifest_inputs(path: pathlib.Path) -> Iterable[tuple[pathlib.Path, list[str]]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    for source in document.get("sources", []):
        root = pathlib.Path(source["root"])
        categories = list(source.get("categories", []))
        if root.is_file():
            yield root, categories
        elif root.is_dir():
            for candidate in sorted(root.rglob("*")):
                if candidate.is_file() and candidate.suffix.lower() in PE_SUFFIXES:
                    yield candidate, categories


def undefined_labels(pseudo: str) -> list[str]:
    definitions = set(re.findall(r"(?m)^(F[0-9a-fA-F]+_L\d+):", pseudo))
    references = set(re.findall(r"\b(F[0-9a-fA-F]+_L\d+)\b", pseudo))
    return sorted(references - definitions)


def sampled_function_addresses(
    listing: str, entry: str, limit: int,
) -> list[str]:
    """Select the entry plus deterministic, evenly spread discovered functions."""
    addresses = [
        match.group(1).lower()
        for match in re.finditer(r"(?m)^(0x[0-9a-fA-F]+)\s+", listing)
    ]
    addresses = list(dict.fromkeys(addresses))
    entry = entry.lower()
    if entry not in addresses:
        addresses.insert(0, entry)
    if limit <= 0 or len(addresses) <= limit:
        selected = addresses
    elif limit == 1:
        selected = [entry]
    else:
        indexes = {
            round(index * (len(addresses) - 1) / (limit - 1))
            for index in range(limit)
        }
        selected = [addresses[index] for index in sorted(indexes)]
        if entry not in selected:
            selected[-1] = entry
    return [entry, *(address for address in selected if address != entry)][:limit]


def evaluate_function(
    executable: pathlib.Path,
    binary: pathlib.Path,
    address: str,
    common: tuple[str, ...],
    timeout: float,
) -> dict[str, Any]:
    record: dict[str, Any] = {"address": address, "checks": {}}
    full = command(
        executable, "fn", str(binary), address, "--view", "json",
        "--max-bytes", "65536", "--max-statements", "128",
        "--max-evidence", "128", *common, timeout=timeout,
    )
    limited = command(
        executable, "fn", str(binary), address, "--view", "json",
        "--max-bytes", "65536", "--max-statements", "2",
        "--max-evidence", "1", *common, timeout=timeout,
    )
    pseudo = command(
        executable, "fn", str(binary), address, "--view", "pseudo",
        "--max-bytes", "65536", "--max-statements", "128", *common,
        timeout=timeout,
    )
    try:
        full_json = json.loads(full["stdout"])
        limited_json = json.loads(limited["stdout"])
        json_valid = True
    except json.JSONDecodeError as error:
        full_json = {}
        limited_json = {}
        json_valid = False
        record["json_error"] = str(error)
    record["checks"]["json_valid"] = json_valid
    record["checks"]["json_bounded"] = len(full["stdout"].encode("utf-8")) <= 65536
    full_ids = [item.get("id") for item in full_json.get("statements", [])]
    limited_ids = [item.get("id") for item in limited_json.get("statements", [])]
    record["checks"]["stable_ids"] = full_ids[: len(limited_ids)] == limited_ids
    missing = undefined_labels(pseudo["stdout"])
    record["checks"]["no_undefined_labels"] = not missing
    if missing:
        record["undefined_labels"] = missing

    statements = full_json.get("statements", [])
    machine_state = re.compile(
        r"\b(rsp|carry|parity|auxiliary|zero|sign|overflow)\b", re.IGNORECASE)
    returns = [item for item in statements if item.get("kind") == "return"]
    record["checks"]["abi_returns_only"] = all(
        len(item.get("values", [])) <= 1 and not machine_state.search(item.get("text", ""))
        for item in returns
    )
    reads = [item for item in statements if item.get("kind") == "memory-read"]
    record["checks"]["result_destinations"] = all(
        "(" not in item.get("text", "").split("=", 1)[0]
        for item in reads
    )
    writes = [item for item in statements if item.get("kind") == "memory-write"]
    record["checks"]["storage_identities"] = all(
        not (match := re.match(r"store\d+\(([^,]+),\s*(.+)\)$",
                               item.get("text", "")))
        or match.group(1).strip() != match.group(2).strip()
        for item in writes
    )
    terminal_seen: set[int] = set()
    source_order_safe = True
    for item in statements:
        node = item.get("node")
        if node in terminal_seen:
            source_order_safe = False
            break
        if item.get("kind") in {"return", "trap", "fault"} or item.get("no_return"):
            terminal_seen.add(node)
    record["checks"]["no_statements_after_terminal"] = source_order_safe
    record["checks"]["switch_values_safe"] = not re.search(
        r"(?m)^\s*case\s+0x", pseudo["stdout"])
    record["checks"]["canonical_comparisons"] = not re.search(
        r"\b[^;()]+\s+-\s+[^;()]+\s+==\s+0\b", pseudo["stdout"])
    record["unresolved_semantic_ids"] = dict(Counter(
        item.get("semantic_id") for item in statements
        if item.get("kind") == "unresolved" and item.get("semantic_id")
    ))
    record["coverage"] = full_json.get("coverage", {})
    record["statements"] = len(statements)
    record["regions"] = len(full_json.get("control", {}).get("regions", []))
    record["transfers"] = len(full_json.get("control", {}).get("transfers", []))
    record["semantic_json_bytes"] = len(full["stdout"].encode("utf-8"))
    record["passed"] = all(record["checks"].values())
    return record


def evaluate_binary(
    executable: pathlib.Path,
    binary: pathlib.Path,
    label: str,
    categories: list[str],
    timeout: float,
    wall_time_ms: int,
    functions_per_binary: int,
) -> dict[str, Any]:
    common = (
        "--profile", "fast",
        "--max-functions", "256",
        "--max-blocks", "5000",
        "--max-edges", "20000",
        "--max-ir-values", "250000",
        "--max-wall-time-ms", str(wall_time_ms),
    )
    record: dict[str, Any] = {
        "label": label,
        "categories": categories,
        "size": binary.stat().st_size,
        "checks": {},
    }
    inspect = command(executable, "inspect", str(binary), *common, timeout=timeout)
    record["inspect_exit"] = inspect["exit"]
    record["elapsed_ms"] = inspect["elapsed_ms"]
    record["checks"]["opened"] = inspect["exit"] in (0, 3)
    record["checks"]["deadline"] = inspect["elapsed_ms"] <= timeout * 1000
    record["checks"]["solver_lazy"] = (
        "solver: not-initialized" in inspect["stdout"]
        and "symbolic-context: not-initialized" in inspect["stdout"]
    )
    entry_match = re.search(r"(?m)^entry: (0x[0-9a-fA-F]+)$", inspect["stdout"])
    if inspect["exit"] not in (0, 3) or entry_match is None:
        record["diagnostic"] = inspect["stderr"].strip()[:1000]
        record["passed"] = False
        return record

    entry = entry_match.group(1)
    listing = command(executable, "functions", str(binary), *common, timeout=timeout)
    record["checks"]["functions_listed"] = listing["exit"] in (0, 3)
    addresses = sampled_function_addresses(
        listing["stdout"], entry, functions_per_binary)
    record["function_results"] = [
        evaluate_function(executable, binary, address, common, timeout)
        for address in addresses
    ]
    record["functions_sampled"] = len(record["function_results"])
    record["checks"]["sampled_functions_pass"] = all(
        item["passed"] for item in record["function_results"])
    coverage = {
        key: sum(item.get("coverage", {}).get(key, 0)
                 for item in record["function_results"])
        for key in ("exact_blocks", "partial_blocks", "opaque_blocks",
                    "exact_instructions", "nonexact_instructions",
                    "total_instructions")
    }
    record["coverage"] = coverage
    nonexact_mnemonics: Counter[str] = Counter()
    for item in record["function_results"]:
        nonexact_mnemonics.update(
            item.get("coverage", {}).get("nonexact_mnemonics", {}))
    record["nonexact_mnemonics"] = dict(nonexact_mnemonics.most_common())
    unresolved: Counter[str] = Counter()
    for item in record["function_results"]:
        unresolved.update(item.get("unresolved_semantic_ids", {}))
    record["unresolved_semantic_ids"] = dict(unresolved.most_common())
    record["passed"] = all(record["checks"].values())
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--airece", type=pathlib.Path, required=True)
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--assemblage", type=pathlib.Path,
                        help="Assemblage PE binaries.tar.xz (streamed; never fully extracted)")
    parser.add_argument("--binary", action="append", type=pathlib.Path, default=[])
    parser.add_argument("--max-samples", type=int, default=20)
    parser.add_argument("--functions-per-binary", type=int, default=5,
                        help="deterministic entry-plus-spread function sample")
    parser.add_argument("--max-member-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    parser.add_argument("--wall-time-ms", type=int, default=5000)
    parser.add_argument("--output", type=pathlib.Path)
    arguments = parser.parse_args()
    if not arguments.airece.is_file():
        parser.error(f"AIRECE executable does not exist: {arguments.airece}")

    results: list[dict[str, Any]] = []
    candidates: list[tuple[pathlib.Path, list[str]]] = [
        (path, ["explicit"]) for path in arguments.binary
    ]
    if arguments.manifest:
        candidates.extend(manifest_inputs(arguments.manifest))
    seen: set[str] = set()
    for path, categories in candidates:
        key = str(path.resolve()).lower()
        if key in seen or not path.is_file() or len(results) >= arguments.max_samples:
            continue
        seen.add(key)
        results.append(evaluate_binary(
            arguments.airece, path, str(path), categories,
            arguments.timeout_seconds, arguments.wall_time_ms,
            arguments.functions_per_binary,
        ))

    if arguments.assemblage and len(results) < arguments.max_samples:
        with tempfile.TemporaryDirectory(prefix="airece-assemblage-") as temporary:
            temporary_root = pathlib.Path(temporary)
            # Assemblage releases have used both XZ and Zstandard payloads,
            # including files whose historical `.xz` name contains Zstd data.
            # Streaming auto-detection keeps the evaluator format- and size-safe.
            with tarfile.open(arguments.assemblage, mode="r|*") as archive:
                for member in archive:
                    if len(results) >= arguments.max_samples:
                        break
                    if not member.isfile() or member.size == 0 or \
                            member.size > arguments.max_member_bytes:
                        continue
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        continue
                    prefix = extracted.read(2)
                    if prefix != b"MZ":
                        continue
                    destination = temporary_root / f"sample-{len(results):05d}.bin"
                    with destination.open("wb") as output:
                        output.write(prefix)
                        while True:
                            chunk = extracted.read(1024 * 1024)
                            if not chunk:
                                break
                            output.write(chunk)
                    results.append(evaluate_binary(
                        arguments.airece, destination,
                        f"assemblage:{member.name}", ["assemblage", "pe"],
                        arguments.timeout_seconds, arguments.wall_time_ms,
                        arguments.functions_per_binary,
                    ))

    exact_blocks = sum(item.get("coverage", {}).get("exact_blocks", 0) for item in results)
    partial_blocks = sum(item.get("coverage", {}).get("partial_blocks", 0) for item in results)
    opaque_blocks = sum(item.get("coverage", {}).get("opaque_blocks", 0) for item in results)
    total_blocks = exact_blocks + partial_blocks + opaque_blocks
    exact_instructions = sum(
        item.get("coverage", {}).get("exact_instructions", 0) for item in results)
    nonexact_instructions = sum(
        item.get("coverage", {}).get("nonexact_instructions", 0) for item in results)
    total_instructions = sum(
        item.get("coverage", {}).get("total_instructions", 0) for item in results)
    unresolved_semantic_ids: Counter[str] = Counter()
    nonexact_mnemonics: Counter[str] = Counter()
    for item in results:
        unresolved_semantic_ids.update(item.get("unresolved_semantic_ids", {}))
        nonexact_mnemonics.update(item.get("nonexact_mnemonics", {}))
    report = {
        "schema": "airece.evaluation.v1",
        "samples": len(results),
        "passed": sum(bool(item.get("passed")) for item in results),
        "failed": sum(not bool(item.get("passed")) for item in results),
        "coverage": {
            "exact_blocks": exact_blocks,
            "partial_blocks": partial_blocks,
            "opaque_blocks": opaque_blocks,
            "exact_instructions": exact_instructions,
            "nonexact_instructions": nonexact_instructions,
            "total_instructions": total_instructions,
            "frequency_weighted_exact_percent":
                round(exact_instructions * 100 / total_instructions, 3)
                if total_instructions else 0.0,
            "block_weighted_exact_percent":
                round(exact_blocks * 100 / total_blocks, 3) if total_blocks else 0.0,
            "top_unresolved_semantic_ids":
                dict(unresolved_semantic_ids.most_common(25)),
            "top_nonexact_mnemonics":
                dict(nonexact_mnemonics.most_common(25)),
        },
        "results": results,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if report["failed"] == 0 and report["samples"] != 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
