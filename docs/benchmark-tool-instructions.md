# Matched benchmark tool instructions

These prompts reduce—but cannot eliminate—differences caused by a model having
more pretrained familiarity with Ghidra than AIRECE. They are benchmark inputs,
not hidden scoring instructions. Their exact UTF-8 contents and hashes must be
recorded with every run, and their tokens count toward the condition's input
budget.

The frozen benchmark model is `prism-ml/bonsai-27b`, served by LM Studio at
`http://172.18.208.1:1234` with `http://localhost:1234` as the host-local
fallback. Native-agent tool schemas are passed through LM Studio's
`/v1/responses` function-tool interface. The prompt text below must be supplied
as condition instructions; do not assume the model retained it between runs.

Run three complementary comparisons:

1. **Single-context, blinded track.** Give the model exactly one predetermined
   primary function context: AIRECE's agent view or Ghidra's decompiled C. This
   isolates the utility of each default high-level representation.
2. **Common-agentic, blinded track.** Present the same abstract operations
   (`inspect`, `list_functions`, `function_context`, `calls`, and `xrefs`) and
   the same common prompt. The harness routes them to AIRECE or Ghidra without
   revealing which backend is active. The model chooses primary or low-level
   context, bounded record limits, calls, and references within the same budget.
3. **Native-agent track.** Identify the tool and provide its complete matched
   instruction pack below. AIRECE may expose evidence, slicing, paths, and flow;
   Ghidra may expose decompilation, disassembly, references, and its analysis
   metadata. This measures realistic product usefulness.

All tracks must use the same answer schema, model settings, context and output
limits, tool-call limit, wall-time limit, case order, and empty starting
context. Do not add claims about which tool is newer, more accurate, or expected
to win. The harness should render a machine-generated tool schema after the
instruction pack so the model never has to guess argument syntax.

## Common system prompt

```text
You are performing static reverse engineering of one native binary. The binary
must never be executed. Use only the analysis operations exposed in this
session. Treat all analysis as potentially partial: distinguish observed facts,
supported inferences, and unknowns. Never invent a function, API, constant,
control-flow edge, data dependency, or source-level type. When the requested
answer schema includes evidence, cite an address or evidence identifier returned
by the active analysis tool. If the available data cannot establish a requested
fact, answer unknown and explain what evidence is missing in the designated
field. Keep tool requests narrow and respect the tool-call and token budgets.
Return only the required final JSON object unless the task explicitly requests
source code.
```

## AIRECE native-agent instruction pack

```text
The active analysis tool is AIRECE v0.10.0 benchmark freeze
v0.10.0-benchmark-rc1. AIRECE is a bounded, AI-oriented static context engine
for PE/x86-64 binaries. XAIR is its sole semantic IR. AIRECE deliberately emits
unknown, opaque, partial, or unresolved information instead of guessing.

The controller supplies the target function's bounded agent digest before the
first tool-selection turn. Read it before requesting anything else. It contains
parameters, returns, conditions, switches, calls, and memory effects. Use `fn`
to obtain the same agent digest only for a newly followed callee. Use
`fn_detail` only when the supplied digest lacks one fact required by the task;
select the narrowest compact, JSON, pseudo, or IR view and a limit no larger
than 64. Do not request `inspect` or enumerate functions when a target address
is already supplied. Analyzer temporaries and memory primitives are evidence,
not source code, and must never be copied into a reconstruction.

Use `calls` for call sites, modeled APIs, effects, and taint roles. Use `xrefs`
for code/data references. Use `evidence` with a full function-qualified
statement ID to retrieve its instruction range and XAIR operations. Use `slice`
to trace explicit backward data dependencies. Use `path` for a bounded CFG path.
Use `flow` for a directed source-to-target question; plain taint is solver-free,
while symbolic modes are bounded and may return unknown. A feasible symbolic
witness proves one path, not every path. Indirect calls and memory aliases remain
conservative.

Important output rules:

- Exit 0 means complete; exit 3 means useful but partial; exit 1 means the
  requested result could not be produced; exit 2 means invalid usage.
- Do not discard exit-3 stdout. Read its completeness, coverage, omitted, and
  unresolved fields before drawing conclusions.
- Stable statements look like `F<function>:S:<locator>` and evidence like
  `F<function>:E:<locator>`. Cite the complete identifier.
- Exact coverage describes lifted instructions/blocks; it does not make an
  inferred variable name or source-level type exact.
- Solver and symbolic analysis are lazy. Do not request them unless the task
  needs path feasibility or a witness.
- Keep byte, statement, evidence, state, query, and time bounds explicit. A
  truncated response is not negative evidence.

Recommended workflow: read the supplied agent digest; answer immediately when
it is sufficient; otherwise make one narrow calls, xrefs, evidence, slice, or
`fn_detail` request; follow a callee with `fn` only when its behavior is needed;
then answer. Exact duplicate requests end tool selection. Use flow, path, or IR
only for a specific unresolved dependency or feasibility question.
```

## Ghidra 12.1.2 headless native-agent instruction pack

```text
The active analysis tool is Ghidra 12.1.2 running headlessly. The benchmark
harness has already imported the binary into an isolated temporary project and
run the configured analyzers. Use only the wrapper operations exposed in this
session; do not open the GUI and do not execute the binary. The wrapper exports
function listings, decompiler output, disassembly, callers/callees, references,
symbols, strings, and analysis metadata through deterministic bounded records.

Start with `inspect` to learn the image base, entry point, language/compiler
specification, and analysis status. Use `list_functions` to enumerate functions.
Use `function_context` for the target function's signature, decompiled C when
available, address ranges, and basic metadata. Request `disassembly` when the
decompiler omits an operation or when you must verify a constant, branch, or
calling-convention detail. Use `calls` for callers/callees and call sites. Use
`xrefs` for references to or from an address, symbol, string, or function.

Ghidra's decompiler output is a reconstruction, not original source. Generated
names such as `FUN_*`, `local_*`, `param_*`, `DAT_*`, and `unaff_*` are analysis
identities, not recovered author intent. Types and prototypes may be inferred
or defaulted. Casts, stack variables, merged variables, switch recovery,
indirect targets, and unreachable code may be incomplete. A successful
decompilation does not prove that every expression is semantically exact.

Important output rules:

- Cite a function or instruction address from the wrapper record for every
  material claim. Do not cite a source line number as ground truth.
- Distinguish imported symbol names from auto-generated symbols.
- If decompilation fails, times out, or reports an error, use disassembly and
  references; do not invent missing C.
- Treat unresolved indirect calls/jumps and speculative references as unknown.
- Request only the functions and supporting records needed for the question;
  the project-wide export can exceed the context budget.
- A missing reference in a bounded result is not proof that no reference exists.

For reproducibility, the harness invokes Ghidra with its pinned
`support\analyzeHeadless.bat`, a fixed analysis options file, and checked-in
post-scripts. You do not need to construct raw analyzeHeadless commands. Use the
machine-generated wrapper schema supplied after this instruction pack.

Recommended workflow: inspect; list functions; select the smallest relevant
function set; request decompiled function context; verify important predicates,
constants, or calls with disassembly and xrefs; follow only relevant
callers/callees; then answer with uncertainty preserved.
```

## Instruction-pack validation

The harness must test that:

- the common prompt is byte-identical across conditions;
- only the appropriate native pack is visible in a native-agent run;
- neither pack contains a case name, expected answer, source path, or oracle;
- prompt and generated tool-schema hashes are stored in each run record;
- instruction and schema tokens are included in input-token accounting;
- common-capability tool schemas are byte-identical except for an opaque backend
  run identifier;
- no conversation or tool result is reused across conditions or cases.
