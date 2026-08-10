# Semantic evaluation

`tools/evaluate.py` exercises the shipped CLI as an agent would: it verifies
bounded opening, lazy solver behavior, valid/bounded semantic JSON, stable IDs
under smaller budgets, ABI-only returns, proper result destinations, terminal
ordering, conservative switch rendering, and pseudocode label integrity. For
each binary it analyzes the entry plus a deterministic sample spread across
the discovered function address space. It reports both block coverage and
frequency-weighted exact/non-exact instruction coverage rather than treating the
decoder's mnemonic table or only the entry function as a workload proxy.

The Assemblage archive is consumed with Python's streaming, compression-
autodetecting `r|*` tar mode (the current `.xz`-named release is Zstandard data).
Only the current bounded sample is written to a temporary directory; the 31+ GiB
archive is never fully extracted.

```powershell
python tools/evaluate.py `
  --airece out/build/windows-msvc/Release/airece.exe `
  --manifest C:/Users/Jaden/Desktop/Projects/IR/qualification-private/corpus-manifest.json `
  --assemblage C:/Users/Jaden/Desktop/Projects/IR/assemblage-dataset/Assemblage_PE/binaries.tar.xz `
  --max-samples 50 `
  --functions-per-binary 5 `
  --output out/evaluation.json
```

Use the compiler manifest for fast regression runs and a progressively larger
Assemblage sample for controlled dogfooding. A passing run is not a malware
readiness claim: it is a reproducible semantic-quality measurement with
per-function and per-binary failures retained in the report. The CTest suite
also builds a CRT-free MSVC fixture from
`tests/fixtures/semantic_contract.c` and checks expected load, return, branch,
and switch presentation contracts against real compiler output.
