# AIRECE benchmark freeze

Freeze identifier: `v0.11.0-benchmark-rc2`

This release candidate is the immutable AIRECE target for the next analyzer and
AI-utility benchmark. The earlier v0.10.0 tag remains the diagnostic baseline.
The annotated Git tag with the current freeze
identifier is authoritative for the AIRECE source revision. Benchmark reports
must record the tag, AIRECE commit, executable SHA-256, and the component
revisions printed by `airece --version`.

Pinned native components:

- XAIR: `edd5c55a9faf974e2147867565ac6a727bd270eb`
- XAIR CFG: `cad38e5822829f466da141ca11101b72ae4013f3`
- XAIR Sym: `b9ee5488ba6141e4429bcbbf80a7bdfb73093242`
- Zydis: `5.0.0`
- Z3: `8e3402b215a810a4154eb183a7dfc4e853eb2f52`

Frozen public protocols:

- Semantic JSON: `airece.semantic.v1`
- Directed flow JSON: `airece.flow.v1`
- Analyzer report: `airece.analyzer-benchmark.v1`
- API model set: `2.0.0`

The freeze is valid only when the AIRECE checkout and the dependency source
directories recorded in the CMake cache are clean. Normal configuration keeps
dependency-pin enforcement enabled.

Release verification:

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

No analyzer implementation change belongs on this tag. Benchmark harnesses,
corpus manifests, scoring code, and result publication may evolve separately,
but every result must identify the frozen analyzer it exercised.
