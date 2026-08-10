# AIRECE

AIRECE is an AI-first reverse-engineering context engine. XAIR is its only
semantic IR; AIRECE will build compact, evidence-backed semantic views over
XAIR rather than reconstructing compilable source or introducing another IR.

The current release is experimental and intended for controlled dogfooding and
corpus evaluation. It is not yet a malware-analysis correctness claim.

This repository is the native C++20 composition layer. Phase 0 establishes the
single CLI product and pinned component boundary. Phase 1 makes upstream Zydis
the sole production decoder and caches XAIR-owned decoded records per session.
Phase 2 adds a bounded `AnalysisSession` that owns the binary, CFG, XAIR module,
function/call indexes, decode cache, and lazily created symbolic context. Phase
3 adds cached, bounded expression views over the XAIR def/use graph without
creating a second semantic IR or invoking Z3. Phase 4 adds deterministic
presentation variables for arguments, returns, stack/global storage, call
results, repeated SSA values, and memory-backed buffers. Every inferred name
and type retains XAIR evidence and confidence. Phase 5 adds the primary
budgeted compact function view with stable statement/evidence IDs, calls,
control, memory, references, unresolved behavior, semantic coverage, and
continuation hints. Phase 6 adds conservative display-only control regions
over `xair_cfg` analyses. Pseudocode emits a structured `if` only when both
arms and their join can be certified; loops, unresolved switches, irreducible
regions, and limited graphs retain function-qualified labels and gotos. Switch
destination addresses are never presented as case constants.
Phase 7 adds a compiled-in, versioned Windows API signature set over
`xair_sym_model_identity` and model kinds. It annotates arguments, returns,
constants, effects, taint roles, no-return behavior, and handle relationships;
unknown APIs remain ordinary XAIR calls. Phase 8 adds explicitly requested,
budgeted symbolic questions and xair_sym provenance taint. Solver timeout and
unknown are data, and base semantic output survives enrichment failure. Phase
9 completes the bounded command protocol and the versioned
`airece.semantic.v1` JSON representation. Version 0.10 adds directed
point-to-point flow queries. Sources and targets resolve to XAIR SSA/CFG
anchors; plain taint stays solver-free; optional taint-guided and pure symbolic
modes return a feasible path condition and witness. Propagation crosses direct
call arguments and returns with a user-set function depth (default 3; depth 0
is strictly local). Buffer sources retain byte-offset provenance and relevant
loads expand into independent byte symbols only for symbolic verification.

## Build

The default dependency layout is:

```text
Projects/
  AIRECE/
  IR/
    xair/
    xair_cfg/
    xair_sym/
```

Vendored `xair`, `xair_cfg`, and `xair_sym` directories take precedence when
present. Exact expected commits live in `cmake/DependencyPins.cmake`. A normal
configuration rejects dirty dependencies; local dependency development must
opt in explicitly with `-DAIRECE_ALLOW_DIRTY_DEPENDENCIES=ON`.

```powershell
cmake --preset windows-msvc
cmake --build --preset windows-msvc-release
ctest --preset windows-msvc-release
out/build/windows-msvc/Release/airece.exe --version
out/build/windows-msvc/Release/airece.exe inspect sample.exe --profile fast
out/build/windows-msvc/Release/airece.exe functions sample.exe --max-blocks 50000
out/build/windows-msvc/Release/airece.exe expr sample.exe 42 --max-expression-depth 8
out/build/windows-msvc/Release/airece.exe vars sample.exe 0x140001000 --max-variables 256
out/build/windows-msvc/Release/airece.exe fn sample.exe 0x140001000 --view compact
out/build/windows-msvc/Release/airece.exe fn sample.exe 0x140001000 --view pseudo --max-bytes 8192
out/build/windows-msvc/Release/airece.exe fn sample.exe 0x140001000 --view json
out/build/windows-msvc/Release/airece.exe fn sample.exe 0x140001000 --view compact --symbolic --max-queries 16 --max-states 256 --symbolic-timeout-ms 1000
out/build/windows-msvc/Release/airece.exe calls sample.exe 0x140001000
out/build/windows-msvc/Release/airece.exe xrefs sample.exe 0x140002000
out/build/windows-msvc/Release/airece.exe slice sample.exe F140001000:S:O16
out/build/windows-msvc/Release/airece.exe taint sample.exe 0x140001000 --max-states 256
out/build/windows-msvc/Release/airece.exe flow sample.exe --source "input=buffer(rcx,64)@0x140001020:before" --target "sink=callarg(1)@0x140002040" --mode taint --function-depth 3
out/build/windows-msvc/Release/airece.exe flow sample.exe --source "key=register(rdx)@0x140001020:before" --target "goal=reach@0x140003000" --mode taint-symbolic --function-depth 2 --json
out/build/windows-msvc/Release/airece.exe path sample.exe --from 0x140001000 --to 0x140001080
out/build/windows-msvc/Release/airece.exe evidence sample.exe F140001000:S:O16
python tools/evaluate.py --airece out/build/windows-msvc/Release/airece.exe --manifest C:/path/to/corpus-manifest.json --max-samples 20 --functions-per-binary 5 --output out/evaluation.json
```

The AIRECE build disables XAIR's bootstrap decoder and CFG's `fast-x86` and
`zydis-mini` compatibility decoders. It exposes no decoder-selection CLI flag.

All data commands return exit code `3` when a
resource or rendering limit, an unresolved edge, or incomplete discovery leaves
a useful partial result. They return `1` only when the requested result cannot
be produced. `expr` also returns `3` when its rendering budget degrades part of
a deep graph to named XAIR temporaries. Ordinary import, function navigation,
expression/variable recovery, control structuring, and compact/pseudo rendering
never create a symbolic context or initialize Z3.

## Directed flow selectors

`flow` accepts repeated `--source` and `--target` options. A selector may be
named with `name=selector`; names become stable symbolic byte names and appear
in agent-readable output. Indexes are zero-based.

```text
register(rcx)@0x140001020:before
buffer(rdx,256)@0x140001025:before
memory(0x180010000,64)@0x140001030
value(v42)
funcarg(0)@0x140002000
callarg(1)@0x140001080
callresult@0x140001080
reach@0x140003000
memory-write@0x140003020
```

`--mode taint` answers whether an explicit data/control dependency may flow
from A to B and never initializes the solver. `--mode taint-symbolic` first
requires that structural dependency, then checks a bounded CFG path and emits
the path conditions and a satisfying input witness. `--mode symbolic` asks
only whether B is reachable when A is symbolic. A feasible witness proves one
path; its constraints are not claimed to be necessary for every path.

Calls consume one `--function-depth` level when propagation enters their
callee. The default is 3, and 0 disables cross-function propagation.
Indirect/unresolved calls remain conservative and can cause an `unknown`
completion. `--max-taint-bytes` bounds tracked buffer extent, while
`--max-symbolic-bytes` bounds expansion of relevant offsets into per-byte
symbols. Direct calls use a bounded, matched call/return context; indirect calls
and memory aliases remain conservative. Flow JSON uses schema
`airece.flow.v1`.

CLI stdout contains requested data only; diagnostics go to stderr. Exit codes
are stable: `0` complete, `1` analysis failure, `2` usage error, and `3` useful
partial output. JSON diagnostics never appear inside the JSON document. Model
set version `2.0.0` and all component revisions are reported by `--version`.
Every successful JSON request emits valid JSON within its byte budget. Budgets
of two bytes may degrade to `{}`; a smaller budget fails explicitly on stderr.
