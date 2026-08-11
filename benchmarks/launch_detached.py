from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    from benchmarks.airece_bench.util import atomic_write_json

    parser = argparse.ArgumentParser(description="Launch the benchmark without an attached console")
    parser.add_argument("--max-cases", type=int, default=20)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--split", choices=("development", "heldout"), default="heldout")
    parser.add_argument("--no-rebuild-corpus", action="store_true")
    arguments = parser.parse_args()

    root = ROOT
    config = json.loads((root / "benchmarks" / "config.json").read_text(encoding="utf-8"))
    output = (root / config["paths"]["output_root"]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    stdout_path = output / "detached-run.stdout.log"
    stderr_path = output / "detached-run.stderr.log"
    status_path = output / "detached-run.json"
    command = [sys.executable, "-u", "-m", "benchmarks.airece_bench.cli",
               "--split", arguments.split, "--max-cases", str(arguments.max_cases),
               "--repetitions", str(arguments.repetitions)]
    if arguments.no_rebuild_corpus:
        command.append("--no-rebuild-corpus")

    creation_flags = (subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP |
                      subprocess.CREATE_NO_WINDOW)
    with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
        process = subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL,
                                   stdout=stdout_file, stderr=stderr_file,
                                   close_fds=True, creationflags=creation_flags)
    atomic_write_json(status_path, {
        "schema": "airece.detached-benchmark.v1",
        "pid": process.pid,
        "started_unix": int(time.time()),
        "command": command,
        "cwd": str(root),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
    })
    print(json.dumps({"pid": process.pid, "status": str(status_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
