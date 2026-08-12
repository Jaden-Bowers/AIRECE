# AIRECE

AIRECE is a command-line reverse-engineering context engine for PE/x86-64 binaries. It
turns XAIR analysis into bounded function summaries, pseudocode, call information,
references, slices, paths, taint results, and directed flow answers that are practical for
both people and coding agents.

AIRECE does static analysis only. The input binary is never executed.

## Build

The Windows build uses Visual Studio 2022, CMake, and C++20. The three XAIR repositories
should be checked out beside AIRECE:

```text
Projects/
  AIRECE/
  IR/
    xair/
    xair_cfg/
    xair_sym/
```

Expected dependency revisions are listed in `cmake/DependencyPins.cmake`. A matching
vendored XAIR directory is also accepted and takes precedence over a sibling checkout.

Build and test a Release executable from a Visual Studio developer shell:

```powershell
cmake --preset windows-msvc
cmake --build --preset windows-msvc-release
ctest --preset windows-msvc-release
```

The executable is written to:

```text
out/build/windows-msvc/Release/airece.exe
```

Useful CMake options:

| Option | Meaning |
|---|---|
| `AIRECE_ENFORCE_DEPENDENCY_PINS` | Require the exact XAIR and Z3 revisions listed in `cmake/DependencyPins.cmake`. Enabled by the preset. |
| `AIRECE_ALLOW_DIRTY_DEPENDENCIES` | Allow local changes in dependency repositories. Disabled by default. |
| `AIRECE_STATIC_MSVC_RUNTIME` | Link the static MSVC runtime. Enabled by the preset. |
| `AIRECE_XAIR_SOURCE_DIR` | Override the XAIR source directory. |
| `AIRECE_XAIR_CFG_SOURCE_DIR` | Override the xair_cfg source directory. |
| `AIRECE_XAIR_SYM_SOURCE_DIR` | Override the xair_sym source directory. |
| `AIRECE_ZYDIS_SOURCE_DIR` | Override the Zydis source directory. |
| `AIRECE_Z3_SOURCE_DIR` | Override the Z3 source directory. |
| `BUILD_TESTING` | Build the test suite. Enabled by the preset. |

Example override:

```powershell
cmake --preset windows-msvc -DAIRECE_ALLOW_DIRTY_DEPENDENCIES=ON
```

## Command line

```text
airece <command> <binary> [arguments] [options]
```

Addresses and numeric limits accept normal integer notation, including hexadecimal values
such as `0x140001000`.

### Commands

| Command | Arguments | What it does |
|---|---|---|
| `inspect` | `<binary>` | Reports the binary format, architecture, entry point, sections, imports, exports, and analysis coverage. |
| `functions` | `<binary>` | Lists discovered functions and their bounds. |
| `expr` | `<binary> <value-id>` | Renders the recovered expression for one XAIR value. |
| `vars` | `<binary> <function-address>` | Shows recovered parameters, locals, buffers, and repeated values for a function. |
| `fn` | `<binary> <function-address>` | Produces an agent, compact, pseudo, IR, or JSON function view. |
| `calls` | `<binary> [function-address]` | Lists call sites for the program or for one function. |
| `xrefs` | `<binary> <address>` | Finds code and data references to an address. |
| `slice` | `<binary> <address-or-statement>` | Traces the bounded backward data dependencies of an instruction or stable statement ID. |
| `taint` | `<binary> <function-address>` | Runs bounded provenance taint analysis for a function. |
| `flow` | `<binary> --source <selector> --target <selector>` | Answers a directed source-to-target taint or symbolic-flow question. |
| `path` | `<binary> --from <address> --to <address>` | Finds a bounded control-flow path between two addresses. |
| `evidence` | `<binary> <statement-id>` | Resolves a stable statement or evidence ID back to its instructions and XAIR operations. |
| `--version` | none | Prints the AIRECE, schema, model-set, and dependency versions. |
| `--help` | none | Prints the command reference. |

### Analysis options

These options apply to commands that build or query an analysis session.

| Flag | Meaning |
|---|---|
| `--profile <fast\|balanced\|exhaustive>` | Selects the CFG discovery profile. `fast` does the least discovery, `balanced` includes normal metadata roots such as exports, and `exhaustive` spends more work on discovery. |
| `--max-input-bytes <count>` | Maximum number of bytes accepted from the input binary. |
| `--max-functions <count>` | Maximum number of functions to discover. |
| `--max-blocks <count>` | Maximum total CFG blocks. |
| `--max-edges <count>` | Maximum total CFG edges. |
| `--max-ir-values <count>` | Maximum number of lifted XAIR values. |
| `--max-memory-bytes <count>` | Maximum amount of analysis-owned memory. |
| `--max-wall-time-ms <count>` | Analysis wall-clock limit in milliseconds. |
| `--no-ir` | Builds navigation data without lifting XAIR IR. Commands that require IR reject this option. |
| `--no-indirects` | Skips indirect branch and call resolution. |

### Expression options

These apply to `expr` and to views that render expressions.

| Flag | Meaning |
|---|---|
| `--max-expression-depth <count>` | Maximum recursive expression depth. |
| `--max-expression-nodes <count>` | Maximum expression graph nodes. |
| `--max-expression-tokens <count>` | Maximum rendered expression tokens. |
| `--max-expression-characters <count>` | Maximum rendered expression characters. |
| `--no-inline-loads` | Keeps memory loads explicit instead of substituting their recovered values. |
| `--no-inline-single-use` | Keeps single-use temporary values explicit. |

### Variable options

These apply to `vars`.

| Flag | Meaning |
|---|---|
| `--max-variables <count>` | Maximum variables returned. |
| `--repeated-use-threshold <count>` | Minimum use count for presenting a repeated SSA value as a named variable. |
| `--no-repeated-values` | Omits named repeated SSA values. |
| `--no-buffers` | Disables buffer-shaped variable recovery. |

### Function-view options

These apply to `fn`.

| Flag | Meaning |
|---|---|
| `--view <agent\|compact\|pseudo\|disassembly\|ir\|json>` | Selects the output. `agent` is a small behavioral digest, `compact` is bounded semantic text, `pseudo` adds conservative structured control flow, `disassembly` emits bounded addressed instruction records, `ir` exposes lifted operations, and `json` emits `airece.semantic.v1`. |
| `--json` | Alias for `--view json`. |
| `--max-bytes <count>` | Maximum output bytes. |
| `--max-statements <count>` | Maximum statements returned. |
| `--max-calls <count>` | Maximum call records returned. |
| `--max-evidence <count>` | Maximum evidence records returned. |
| `--max-expression-depth <count>` | Maximum expression depth inside the function view. |
| `--offset <call-index>` | Starts the bounded call page at a call index. |
| `--calls` | Includes the bounded call page in compact output. |

### Symbolic and taint options

Symbolic work is opt-in. Normal compact and agent views do not initialize a solver.

The agent view starts with ordered behavior records. These connect branch predicates and
switch cases to their results, preserve guarded indirect-call targets and argument bindings,
summarize internal callees one level deep, describe persistent state updates, and represent
recursive helpers as bounded recurrences when the evidence supports one. The older fact
tables remain in the same JSON document for direct lookup and evidence citation.

| Flag | Meaning |
|---|---|
| `--symbolic` | Enables bounded symbolic enrichment. |
| `--taint` | Enables provenance taint enrichment. |
| `--max-queries <count>` | Maximum solver queries. |
| `--max-states <count>` | Maximum explored symbolic states. |
| `--symbolic-timeout-ms <count>` | Per-query symbolic timeout in milliseconds. |

### Directed-flow options

`flow` accepts repeated sources and targets. Argument indexes are zero-based.

| Flag | Meaning |
|---|---|
| `--source <selector>` | Adds a source point. Repeat for multiple sources. |
| `--target <selector>` | Adds a target point. Repeat for multiple targets. |
| `--mode <taint\|taint-symbolic\|symbolic>` | Chooses solver-free dependency flow, taint-guided symbolic checking, or symbolic reachability. |
| `--function-depth <count>` | Maximum call depth for interprocedural propagation. The default is `3`; `0` stays inside one function. |
| `--max-states <count>` | Maximum states explored. |
| `--max-queries <count>` | Maximum solver queries. |
| `--max-paths <count>` | Maximum candidate paths. |
| `--max-taint-bytes <count>` | Maximum tracked buffer extent. |
| `--max-symbolic-bytes <count>` | Maximum number of relevant bytes expanded into symbolic byte values. |
| `--symbolic-timeout-ms <count>` | Per-query symbolic timeout in milliseconds. |
| `--json` | Emits `airece.flow.v1` JSON. |

Flow selectors:

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

A selector may have a stable name, for example
`input=buffer(rdx,256)@0x140001025:before`.

`path` also requires `--from <address>` and `--to <address>` for the path endpoints.

### Examples

```powershell
airece inspect sample.exe --profile balanced
airece fn sample.exe 0x140001000 --view agent
airece fn sample.exe 0x140001000 --view pseudo --max-bytes 8192
airece fn sample.exe 0x140001000 --view disassembly --max-statements 64
airece calls sample.exe 0x140001000
airece slice sample.exe F140001000:S:O16
airece evidence sample.exe F140001000:S:O16
airece flow sample.exe `
  --source "input=buffer(rcx,64)@0x140001020:before" `
  --target "sink=callarg(1)@0x140002040" `
  --mode taint --function-depth 3 --json
```

Exit codes are stable:

| Code | Meaning |
|---:|---|
| `0` | Complete result. |
| `1` | Analysis failed or the requested result could not be produced. |
| `2` | Invalid command or option. |
| `3` | Useful partial result. Check the output's coverage, omitted, and unresolved fields. |

## Benchmark

The benchmark compares the same model solving the same held-out reverse-engineering tasks
with AIRECE and Ghidra 12.1.2 headless. It has three tiers:

1. **Single context:** one AIRECE agent view or one Ghidra decompilation.
2. **Common agentic:** the same blinded navigation tool schema backed by either analyzer.
3. **Native agentic:** each analyzer exposes its own useful operations and matching guide.

Each tier contains strict objective questions and source reconstruction tasks. Objective
answers are scored against structured facts and evidence locations. Reconstructions are
compiled and run against hidden tests generated from known-benign fixtures. Analyzer output,
model requests, token use, tool calls, failures, and paired bootstrap intervals are retained
in the run artifacts.

### Current results

The current results use the `v0.11.0-benchmark-rc2` analyzer freeze. Each model ran the same
nine balanced held-out cases once, producing 102 paired sessions across the three tiers. These
are useful directional results, but the sample is still small.

Bonsai 27B was run locally as the 4.41 GiB Q1_0 build with a 16,384-token context and one
generation slot. Objective values below are semantic accuracy. Reconstruction values are the
fraction of 512 hidden behavioral tests passed; compile rate is shown separately.

| Bonsai tier | Objective AIRECE | Objective Ghidra | Reconstruction AIRECE | Reconstruction Ghidra | Compile AIRECE / Ghidra |
|---|---:|---:|---:|---:|---:|
| Single context | **59.8%** | 36.5% | 295/512 (57.6%) | **331/512 (64.6%)** | 100% / 100% |
| Common agentic | 46.5% | **50.7%** | **265/512 (51.8%)** | 248/512 (48.4%) | 87.5% / 75.0% |
| Native agentic | **72.0%** | 52.9% | 240/512 (46.9%) | **345/512 (67.4%)** | 62.5% / 75.0% |

All 102 Bonsai jobs completed with no transport retries or transcript compactions. Its simple
three-case protocol check passed cleanly, but the full tasks still exposed weak final-answer
discipline. The harness had to normalize most common and native answers, and some remained
structurally invalid. AIRECE's native objective interface was the clearest result for this
model: it reached 72.0% semantic accuracy versus 52.9% for Ghidra. Ghidra remained stronger
on native behavioral reconstruction.

Grok 4.6 was run through OpenRouter with low reasoning effort. It produced valid final
structures and clean protocol behavior throughout the agentic tiers.

| Grok tier | Objective AIRECE | Objective Ghidra | Reconstruction AIRECE | Reconstruction Ghidra | Compile AIRECE / Ghidra |
|---|---:|---:|---:|---:|---:|
| Single context | **86.4%** | 83.2% | **512/512 (100%)** | 330/512 (64.5%) | 100% / 100% |
| Common agentic | **82.0%** | 75.9% | **512/512 (100%)** | 511/512 (99.8%) | 100% / 100% |
| Native agentic | **84.1%** | 75.9% | **512/512 (100%)** | 511/512 (99.8%) | 100% / 100% |

The Grok run also completed all 102 jobs without failures, retries, or transcript compactions.
In the native tier, AIRECE used 18 tool calls and 170,562 tokens across both tasks, compared
with Ghidra's 41 calls and 240,208 tokens. The recorded OpenRouter generation cost was about
$1.95.

Run the local-model configuration:

```powershell
python -m benchmarks.airece_bench.cli --dry-run --split heldout `
  --balanced-categories --max-cases 20 --repetitions 1
python -m benchmarks.airece_bench.cli --split heldout `
  --balanced-categories --max-cases 20 --repetitions 1
```

Run the OpenRouter Grok 4.6 configuration after setting `open_router_key` in `.env`:

```powershell
python -m benchmarks.airece_bench.cli `
  --config benchmarks/config.openrouter.grok-4.6.json --dry-run `
  --split heldout --balanced-categories --max-cases 20 --repetitions 1
python benchmarks/launch_detached.py `
  --config benchmarks/config.openrouter.grok-4.6.json `
  --output-root out/ai-utility-benchmark-grok-4.6 `
  --split heldout --balanced-categories --max-cases 20 --repetitions 1
```

Benchmark output contains `manifest.json`, `runs.jsonl`, `summary.json`, `report.md`, and
one atomic JSON record per model session. See `benchmarks/README.md` for the full harness
command reference.
