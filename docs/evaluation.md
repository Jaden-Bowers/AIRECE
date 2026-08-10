# Semantic evaluation

`tools/evaluate.py` exercises the shipped CLI as an agent would: it verifies
bounded opening, lazy solver behavior, valid/bounded semantic JSON, stable IDs
under smaller budgets, and pseudocode label integrity. It aggregates
frequency-weighted exact/partial/opaque block coverage rather than treating the
decoder's mnemonic table as a proxy for real workload coverage.

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
  --output out/evaluation.json
```

Use the compiler manifest for fast regression runs and a progressively larger
Assemblage sample for controlled dogfooding. A passing run is not a malware
readiness claim: it is a reproducible semantic-quality measurement with the
per-binary failures retained in the report.
