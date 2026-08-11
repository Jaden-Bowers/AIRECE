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
    parser.add_argument("--split", choices=("development", "heldout"), default="heldout")
    parser.add_argument("--track", action="append", choices=("common", "native"),
                        help="Run only the selected track; may be repeated")
    parser.add_argument("--category", action="append",
                        help="Select one deterministic case from each named category; may repeat")
    parser.add_argument("--task", action="append", choices=("objective", "reconstruction"),
                        help="Run only the selected task; may be repeated")
    parser.add_argument("--output-root",
                        help="Override paths.output_root without editing the config")
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
    if arguments.track:
        runner.config["tracks"] = arguments.track
    if arguments.category:
        runner.config["selection_categories"] = arguments.category
    if arguments.task:
        runner.config["selection_tasks"] = arguments.task
    if arguments.output_root:
        runner.config["paths"]["output_root"] = arguments.output_root
        runner.output = (root / arguments.output_root).resolve()
    result = runner.execute(arguments.max_cases, arguments.repetitions,
                            arguments.dry_run, arguments.split,
                            not arguments.no_rebuild_corpus)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
