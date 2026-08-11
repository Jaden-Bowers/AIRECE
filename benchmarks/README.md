# AIRECE AI-utility benchmark harness

This harness measures a frozen local model against the frozen AIRECE analyzer
and Ghidra 12.1.2 headless. It implements blinded common-capability and matched
native-agent tracks, objective JSON scoring, source reconstruction with hidden
behavioral tests, atomic resumable records, and paired bootstrap intervals.

Generated binaries, Ghidra projects/cache, transcripts, and reports live under
`out/ai-utility-benchmark` and are ignored by Git. Corpus source and answer
oracles are controller-only: no source path, opaque symbol, case ID, expected
answer, or test vector is inserted into a model prompt.

## Exact commands

Run the frozen analyzer gate first:

```powershell
cmake --preset windows-msvc
cmake --build --preset windows-msvc-release
ctest --preset windows-msvc-release
python tools/benchmark_analyzer.py `
  --airece out/build/windows-msvc/Release/airece.exe `
  --build-dir out/build/windows-msvc `
  --manifest C:/Users/Jaden/Desktop/Projects/IR/qualification-private/corpus-manifest.json `
  --assemblage C:/Users/Jaden/Desktop/Projects/IR/assemblage-dataset/Assemblage_PE/binaries.tar.xz `
  --compiler-samples 10 --assemblage-samples 10 --functions-per-binary 5 `
  --output out/benchmark-analyzer-quick.json
```

Build the deterministic MSVC/clang-cl O0/O2 corpus and run tests:

```powershell
python -m benchmarks.airece_bench.corpus
python -m unittest discover -s benchmarks/tests -v
```

Inspect the deterministically randomized smoke plan, then execute it:

```powershell
python -m benchmarks.airece_bench.cli --dry-run --max-cases 2 --repetitions 1
python -m benchmarks.airece_bench.cli --max-cases 2 --repetitions 1
```

Resume the same run without rebuilding the corpus:

```powershell
python -m benchmarks.airece_bench.cli --max-cases 2 --repetitions 1 --no-rebuild-corpus
```

A bounded preliminary run, only after smoke transcripts pass leakage review:

```powershell
python -m benchmarks.airece_bench.cli --max-cases 12 --repetitions 3
```

All stage timeouts can be overridden with `--task-timeout-seconds`,
`--analyzer-timeout-seconds`, `--ghidra-timeout-seconds`,
`--compile-timeout-seconds`, and `--execute-timeout-seconds`. Configuration and
defaults are checked in at `benchmarks/config.json`.

Outputs are `manifest.json`, `runs.jsonl`, `summary.json`, and `report.md` in
`out/ai-utility-benchmark`. Individual atomic records are retained in the
`records` subdirectory, and raw Ghidra exports are retained under `cache`.

