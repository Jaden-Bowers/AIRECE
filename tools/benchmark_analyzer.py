#!/usr/bin/env python3
"""Run the quick, reproducible AIRECE analyzer-correctness benchmark."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import time
from typing import Any


SCHEMA = "airece.analyzer-benchmark.v1"
FREEZE_ID = "v0.11.0-benchmark-rc2"
CORRECTNESS_TESTS = (
    r"^(airece_(decoder_boundary|expression_view|variable_view|control_view|"
    r"api_model|directed_flow|protocol_cli|source_semantics|evaluation_smoke))$"
)


def run(arguments: list[str], timeout: float, cwd: pathlib.Path) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            arguments, cwd=cwd, capture_output=True, text=True, check=False,
            timeout=timeout, encoding="utf-8", errors="replace")
        return {
            "command": arguments,
            "exit": completed.returncode,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired as error:
        return {
            "command": arguments,
            "exit": None,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "stdout": error.stdout or "",
            "stderr": error.stderr or "",
            "timeout": True,
        }


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_text(root: pathlib.Path, *arguments: str) -> str | None:
    result = run(["git", "-C", str(root), *arguments], 10, root)
    return result["stdout"].strip() if result["exit"] == 0 else None


def repository_snapshot(root: pathlib.Path) -> dict[str, Any]:
    revision = git_text(root, "rev-parse", "HEAD")
    status = git_text(root, "status", "--porcelain")
    return {
        "path": str(root.resolve()),
        "revision": revision,
        "branch": git_text(root, "branch", "--show-current"),
        "clean": status == "" if status is not None else False,
        "available": revision is not None,
    }


def cmake_cache_path(build_dir: pathlib.Path, key: str) -> pathlib.Path | None:
    cache = build_dir / "CMakeCache.txt"
    if not cache.is_file():
        return None
    pattern = re.compile(rf"^{re.escape(key)}(?::[^=]*)?=(.*)$")
    for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.match(line)
        if match:
            return pathlib.Path(match.group(1))
    return None


def parse_component_revisions(version: str) -> dict[str, str]:
    revisions: dict[str, str] = {}
    for component in ("xair", "xair_cfg", "xair_sym"):
        match = re.search(
            rf"(?m)^{re.escape(component)}\s+\S+\s+\(([0-9a-f]{{40}})\)$", version)
        if match:
            revisions[component] = match.group(1)
    return revisions


def evaluate(
    source_root: pathlib.Path,
    executable: pathlib.Path,
    timeout: float,
    wall_time_ms: int,
    functions_per_binary: int,
    samples: int,
    option: str,
    corpus: pathlib.Path,
) -> dict[str, Any]:
    command = [
        sys.executable, str(source_root / "tools" / "evaluate.py"),
        "--airece", str(executable), option, str(corpus),
        "--max-samples", str(samples),
        "--functions-per-binary", str(functions_per_binary),
        "--timeout-seconds", str(timeout),
        "--wall-time-ms", str(wall_time_ms),
    ]
    result = run(command, max(60.0, timeout * max(2, samples)), source_root)
    try:
        report = json.loads(result["stdout"])
    except (json.JSONDecodeError, TypeError) as error:
        report = {
            "schema": "invalid",
            "samples": 0,
            "passed": 0,
            "failed": 1,
            "diagnostic": f"evaluation output was not valid JSON: {error}",
        }
    return {
        "process": {
            "command": result["command"],
            "exit": result["exit"],
            "elapsed_ms": result["elapsed_ms"],
            "stderr": result["stderr"][-4000:],
            "timeout": result.get("timeout", False),
        },
        "report": report,
    }


def coverage_passes(
    report: dict[str, Any],
    minimum_instruction: float,
    minimum_block: float,
) -> bool:
    coverage = report.get("coverage", {})
    return (
        report.get("samples", 0) > 0
        and report.get("failed", 1) == 0
        and coverage.get("frequency_weighted_exact_percent", 0.0)
        >= minimum_instruction
        and coverage.get("block_weighted_exact_percent", 0.0) >= minimum_block
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--airece", required=True, type=pathlib.Path)
    parser.add_argument("--source-root", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument("--build-dir", type=pathlib.Path,
                        default=pathlib.Path("out/build/windows-msvc"))
    parser.add_argument("--configuration", default="Release")
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--assemblage", type=pathlib.Path)
    parser.add_argument("--compiler-samples", type=int, default=10)
    parser.add_argument("--assemblage-samples", type=int, default=10)
    parser.add_argument("--functions-per-binary", type=int, default=5)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--wall-time-ms", type=int, default=5000)
    parser.add_argument("--minimum-instruction-exact-percent", type=float,
                        default=95.0)
    parser.add_argument("--minimum-block-exact-percent", type=float, default=90.0)
    parser.add_argument("--skip-contract-tests", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    arguments = parser.parse_args()

    source_root = arguments.source_root.resolve()
    build_dir = (source_root / arguments.build_dir).resolve() \
        if not arguments.build_dir.is_absolute() else arguments.build_dir.resolve()
    executable = (source_root / arguments.airece).resolve() \
        if not arguments.airece.is_absolute() else arguments.airece.resolve()
    if not executable.is_file():
        parser.error(f"AIRECE executable does not exist: {executable}")
    if arguments.manifest and not arguments.manifest.is_file():
        parser.error(f"manifest does not exist: {arguments.manifest}")
    if arguments.assemblage and not arguments.assemblage.is_file():
        parser.error(f"Assemblage archive does not exist: {arguments.assemblage}")
    if not arguments.manifest and not arguments.assemblage:
        parser.error("at least one of --manifest or --assemblage is required")

    version_result = run([str(executable), "--version"], 10, source_root)
    version = version_result["stdout"]
    component_revisions = parse_component_revisions(version)
    dependency_keys = {
        "xair": "AIRECE_XAIR_SOURCE_DIR",
        "xair_cfg": "AIRECE_XAIR_CFG_SOURCE_DIR",
        "xair_sym": "AIRECE_XAIR_SYM_SOURCE_DIR",
    }
    repositories = {"airece": repository_snapshot(source_root)}
    for component, key in dependency_keys.items():
        path = cmake_cache_path(build_dir, key)
        repositories[component] = repository_snapshot(path) if path else {
            "path": None, "revision": None, "branch": None,
            "clean": False, "available": False,
        }

    revisions_match = all(
        repositories[name].get("revision") == revision
        for name, revision in component_revisions.items()
    ) and len(component_revisions) == len(dependency_keys)
    clean = all(item.get("clean", False) for item in repositories.values())

    contract: dict[str, Any] = {"skipped": arguments.skip_contract_tests}
    if not arguments.skip_contract_tests:
        contract_result = run([
            "ctest", "--test-dir", str(build_dir), "-C", arguments.configuration,
            "--output-on-failure", "-R", CORRECTNESS_TESTS,
        ], 120, source_root)
        contract = {
            "skipped": False,
            "exit": contract_result["exit"],
            "elapsed_ms": contract_result["elapsed_ms"],
            "passed": contract_result["exit"] == 0,
            "stdout": contract_result["stdout"][-12000:],
            "stderr": contract_result["stderr"][-4000:],
        }

    evaluations: dict[str, Any] = {}
    if arguments.manifest:
        evaluations["compiler"] = evaluate(
            source_root, executable, arguments.timeout_seconds,
            arguments.wall_time_ms, arguments.functions_per_binary,
            arguments.compiler_samples, "--manifest", arguments.manifest.resolve())
    if arguments.assemblage:
        evaluations["assemblage"] = evaluate(
            source_root, executable, arguments.timeout_seconds,
            arguments.wall_time_ms, arguments.functions_per_binary,
            arguments.assemblage_samples, "--assemblage",
            arguments.assemblage.resolve())

    gates = {
        "freeze_identifier": f"benchmark-freeze {FREEZE_ID}" in version,
        "release_build": "build Release" in version
            if arguments.configuration.lower() == "release" else True,
        "repositories_clean": clean or arguments.allow_dirty,
        "component_revisions_match": revisions_match,
        "contract_tests": contract.get("passed", False)
            if not arguments.skip_contract_tests else True,
        "evaluations": all(
            item["process"]["exit"] == 0 and coverage_passes(
                item["report"], arguments.minimum_instruction_exact_percent,
                arguments.minimum_block_exact_percent)
            for item in evaluations.values()),
    }
    report = {
        "schema": SCHEMA,
        "freeze_id": FREEZE_ID,
        "passed": all(gates.values()),
        "gates": gates,
        "thresholds": {
            "minimum_instruction_exact_percent":
                arguments.minimum_instruction_exact_percent,
            "minimum_block_exact_percent": arguments.minimum_block_exact_percent,
        },
        "artifact": {
            "path": str(executable),
            "bytes": executable.stat().st_size,
            "sha256": sha256(executable),
            "version": version.splitlines(),
        },
        "repositories": repositories,
        "contract_tests": contract,
        "evaluations": evaluations,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        output = arguments.output if arguments.output.is_absolute() \
            else source_root / arguments.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)

    print(
        f"AIRECE analyzer benchmark: {'PASS' if report['passed'] else 'FAIL'}",
        file=sys.stderr)
    for name, evaluation in evaluations.items():
        summary = evaluation["report"]
        coverage = summary.get("coverage", {})
        print(
            f"  {name}: {summary.get('passed', 0)}/{summary.get('samples', 0)} "
            f"binaries, {coverage.get('frequency_weighted_exact_percent', 0)}% "
            f"instructions, {coverage.get('block_weighted_exact_percent', 0)}% blocks",
            file=sys.stderr)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
