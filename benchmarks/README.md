# AIRECE AI-utility benchmark harness

This harness measures a configured model against the frozen AIRECE analyzer
and Ghidra 12.1.2 headless. It implements three distinct tiers: a blinded
single-context representation test, a blinded common-agentic tool test, and a
matched native-agentic test. It includes objective JSON scoring, source
reconstruction with hidden behavioral tests, atomic resumable records, and both
case-paired and source-program-clustered bootstrap intervals.

In the common track, AIRECE `primary` context is the bounded agent digest and
`low_level` context combines bounded pseudocode with addressed instruction records. Raw IR remains an explicit native
`fn_detail` choice. Text results are trimmed only at complete line boundaries
and include omission and continuation metadata.

Load `prism-ml/bonsai-27b` in LM Studio with the checked-in 16,384-token context
length before running. The benchmark preflight records the native model metadata.

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

Build the deterministic MSVC/clang-cl O0/O2 corpus across no-CRT, static-CRT,
and dynamic-CRT variants, then run tests:

```powershell
python -m benchmarks.airece_bench.corpus
python -m unittest discover -s benchmarks/tests -v
```

Inspect the deterministically randomized smoke plan, then execute it:

```powershell
python -m benchmarks.airece_bench.cli --dry-run --split development --max-cases 2 --repetitions 1
python -m benchmarks.airece_bench.cli --split development --max-cases 2 --repetitions 1
```

Resume the same run without rebuilding the corpus:

```powershell
python -m benchmarks.airece_bench.cli --split development --max-cases 2 --repetitions 1 --no-rebuild-corpus
```

A category-balanced tiered held-out run with one repetition, only after
development smoke transcripts pass leakage review:

```powershell
python -m benchmarks.airece_bench.cli --dry-run --split heldout `
  --balanced-categories --max-cases 20 --repetitions 1
python -m benchmarks.airece_bench.cli --split heldout `
  --balanced-categories --max-cases 20 --repetitions 1
```

A detached 20-case run with three repetitions is reserved for the final frozen
evaluation:

```powershell
python benchmarks/launch_detached.py --max-cases 20 --repetitions 3
```

The launcher records the child PID and exact command in
`out/ai-utility-benchmark/detached-run.json`; stdout and stderr are retained next
to it. Development records are excluded from held-out summaries and reports.

For the OpenRouter Grok 4.6 comparison, put `open_router_key` in the repository
`.env` file and use the separate provider configuration:

```powershell
python benchmarks/validate_protocol.py `
  --config benchmarks/config.openrouter.grok-4.6.json --cases 3 `
  --output out/protocol-validation-grok-4.6.json
python benchmarks/launch_detached.py `
  --config benchmarks/config.openrouter.grok-4.6.json `
  --output-root out/ai-utility-benchmark-grok-4.6 `
  --split heldout --balanced-categories --max-cases 20 --repetitions 1
```

The key is read at runtime, removed from retained envelopes, and never written
to a manifest or run record.

All stage timeouts can be overridden with `--task-timeout-seconds`,
`--analyzer-timeout-seconds`, `--ghidra-timeout-seconds`,
`--compile-timeout-seconds`, and `--execute-timeout-seconds`. Configuration and
defaults are checked in at `benchmarks/config.json`.

Outputs are `manifest.json`, `runs.jsonl`, `summary.json`, and `report.md` in
`out/ai-utility-benchmark`. Individual atomic records are retained in the
`records` subdirectory, and raw Ghidra exports are retained under `cache`.
