from __future__ import annotations

import argparse
import json
import pathlib

from .runner import BenchmarkRunner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the paired AIRECE AI-utility benchmark")
    parser.add_argument("--config", default="benchmarks/config.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--max-cases", type=int, default=2)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--no-rebuild-corpus", action="store_true")
    parser.add_argument("--task-timeout-seconds", type=float)
    parser.add_argument("--analyzer-timeout-seconds", type=float)
    parser.add_argument("--ghidra-timeout-seconds", type=float)
    parser.add_argument("--compile-timeout-seconds", type=float)
    parser.add_argument("--execute-timeout-seconds", type=float)
    arguments = parser.parse_args(argv)
    root = pathlib.Path(__file__).resolve().parents[2]
    overrides = {name: getattr(arguments, name) for name in
        ("task_timeout_seconds", "analyzer_timeout_seconds", "ghidra_timeout_seconds",
         "compile_timeout_seconds", "execute_timeout_seconds")}
    runner = BenchmarkRunner(root, (root / arguments.config).resolve(), overrides)
    result = runner.execute(arguments.max_cases, arguments.repetitions,
                            arguments.dry_run, not arguments.no_rebuild_corpus)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

