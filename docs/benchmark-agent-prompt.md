# Coding-agent prompt: AIRECE AI-utility benchmark

```text
I need you to build and run the first reproducible AI-utility benchmark for a
tool called AIRECE. AIRECE is an AI-first reverse-engineering context engine.
Its purpose is to help coding agents understand statically analyzed malware and
ordinary native binaries more accurately and with fewer input/output tokens.

Locations
---------

- AIRECE: C:\Users\Jaden\Desktop\Projects\AIRECE
- XAIR repositories: C:\Users\Jaden\Desktop\Projects\IR\xair,
  C:\Users\Jaden\Desktop\Projects\IR\xair_cfg, and
  C:\Users\Jaden\Desktop\Projects\IR\xair_sym
- Current XAIR development branch: AIRCE-prep in all three repositories
- Ghidra: C:\Users\Jaden\Desktop\Projects\IR\kb\ghidra_12.1.2_PUBLIC
- Historical XAIR benchmarks: C:\Users\Jaden\Desktop\Projects\IR\benchmarks
- Assemblage: C:\Users\Jaden\Desktop\Projects\IR\assemblage-dataset
- Existing AIRECE tests: C:\Users\Jaden\Desktop\Projects\AIRECE\tests
- Frozen analyzer definition:
  C:\Users\Jaden\Desktop\Projects\AIRECE\BENCHMARK_FREEZE.md
- Matched benchmark instruction packs:
  C:\Users\Jaden\Desktop\Projects\AIRECE\docs\benchmark-tool-instructions.md

The analyzer under test is the annotated Git tag
v0.11.0-benchmark-rc2. Treat that tag and its dependency revisions as
immutable. Do not fix, reformat, or otherwise change analyzer implementation
code while benchmarking. Build harness work on a separate branch such as
benchmark-harness, or in a separate AIRECE-benchmarks directory. Every run must
record the analyzer Git commit, component revisions, executable SHA-256, and
the complete output of `airece --version`.

Before doing anything else
--------------------------

1. Read BENCHMARK_FREEZE.md, README.md, docs/evaluation.md,
   tools/benchmark_analyzer.py, tools/evaluate.py, and the existing tests.
2. Verify the tag, source cleanliness, dependency pins, Release build, and
   quick analyzer report. Do not proceed with an AI comparison if the frozen
   analyzer health report fails.
3. Locate Ghidra's actual `support\analyzeHeadless.bat` and verify a trivial
   import/decompile/export smoke test. Use Ghidra headless scripts, not an MCP
   server and not its GUI.
4. The benchmark model is Bonsai 27B, a roughly 4 GB ternary quantization of a
   Qwen3.6 27B model with reasoning, coding, vision, and tool-use capabilities.
   It is already served by LM Studio with model identifier
   `prism-ml/bonsai-27b`. The preferred base URL is
   `http://172.18.208.1:1234`; `http://localhost:1234` is a verified fallback
   when the harness runs directly on the Windows host. Both currently answer
   `GET /v1/models` and list the required identifier. Do not download a model,
   do not use a paid/cloud API, and do not substitute another listed model
   without explicit user approval. Record the model identifier, model file hash
   where LM Studio exposes it, quantization/build metadata, context length, LM
   Studio version, loaded-model settings, chat/prompt template, reasoning
   controls, seed, temperature, and every generation setting.

   Implement a dedicated LM Studio adapter. Prefer the OpenAI-compatible
   `POST /v1/responses` endpoint for benchmark tasks because it accepts explicit
   function tool definitions and `tool_choice: "auto"`. Also support LM
   Studio's native `POST /api/v1/chat` endpoint for a no-tool connectivity smoke
   test. Make the base URL configurable, probe `/v1/models` before a run, fail
   if `prism-ml/bonsai-27b` is absent, and store sanitized request/response
   envelopes plus usage fields. There is no API key. Never silently fall back
   from a failed tool-capable request to a different model or endpoint.

   Equivalent connectivity examples are:

   `curl http://172.18.208.1:1234/api/v1/chat -H "Content-Type: application/json" -d '{"model":"prism-ml/bonsai-27b","system_prompt":"Reply with OK only.","input":"Connectivity check"}'`

   `curl http://172.18.208.1:1234/v1/responses -H "Content-Type: application/json" -d '{"model":"prism-ml/bonsai-27b","input":"Call the provided echo tool with value OK.","tools":[{"type":"function","name":"echo","description":"Return the provided value","parameters":{"type":"object","properties":{"value":{"type":"string"}},"required":["value"]}}],"tool_choice":"auto"}'`

Goal and experimental question
------------------------------

Measure whether the same frozen local model can answer objective reverse-
engineering questions and reconstruct behaviorally equivalent source more
accurately and/or with fewer tokens when given AIRECE rather than Ghidra
headless output.

This is a paired experiment. The model, binary, question, generation limits,
system prompt, decoding settings, wall-clock budget, and context-window limit
must remain identical between conditions. Only the analysis interface changes.
Do not claim AIRECE is better merely because it emits fewer characters or more
attractive pseudocode.

Required benchmark conditions
-----------------------------

Implement two comparison tracks. The first is a blinded common-capability track
whose abstract operation names and schemas are identical across backends. The
second is a realistic native-agent track using the matched, condition-specific
instruction packs in `docs/benchmark-tool-instructions.md`. Count those
instructions in each condition's token budget and store their hashes.

Implement at least these independent backends in both applicable tracks:

1. `airece`: the model may use only the frozen AIRECE CLI and its documented
   compact, JSON, pseudo, calls, xrefs, evidence, slice, path, and flow commands.
2. `ghidra`: the model receives equivalent function navigation and decompiler
   information exported by Ghidra 12.1.2 headless. Build a deterministic
   headless extraction script and cache its raw results.
3. `raw-disassembly`: optional but strongly preferred as a lower baseline.

Do not give the Ghidra condition AIRECE output or the AIRECE condition Ghidra
pseudocode. Do not give either condition source code, tests, answer keys,
symbols that would not exist in the shipped binary, compiler maps, PDBs, or
manifest fields containing ground truth.

If the model runner does not support native tool calls, implement the same
small JSON tool-request protocol for every condition. The controller should
execute requests and return bounded results. Reject malformed or unavailable
tool requests consistently. Record every prompt, request, tool result, token
count, latency, and final answer.

The matched tool instructions are an experimental control. Do not rely on the
model's pretrained knowledge of Ghidra command names, and do not leave AIRECE
undocumented. Validate prompt isolation and the blinded schemas as specified in
`docs/benchmark-tool-instructions.md`.

Dataset
-------

Create a deterministic benign source-backed corpus whose source and test oracle
are hidden from the model. Include C and C++ functions covering:

- arithmetic and bit manipulation;
- sparse and dense switches;
- nested branches and loops;
- stack, global, structure, array, and pointer accesses;
- direct and indirect calls;
- recursion;
- strings and constants;
- Windows API-shaped calls and source/sink-like data flow;
- transformations that preserve behavior but change layout.

Compile multiple held-out binaries across available MSVC and clang-cl settings,
including O0 and O2 and, where practical, O1/Ox, static/dynamic CRT, and layout
variants. Strip or omit debug information. Assign opaque case IDs. Generate the
train/development fixtures separately from a held-out evaluation split. The
benchmark agent may inspect development ground truth while implementing
scoring, but must not tune prompts or analyzer settings against held-out
answers after seeing held-out results.

Assemblage or malware-like binaries may be used for robustness and qualitative
questions, but never execute them. Never redistribute malware in the harness.
Use paths plus SHA-256 identifiers and stream archives without fully extracting
them. Source-reconstruction execution is allowed only for benchmark-generated,
known-benign fixtures and must occur in a temporary, timeout-bounded directory.

Tasks
-----

Run two completely separate sessions with cleared context for each
case/condition/repetition:

A. Objective understanding

Ask questions whose answers can be scored without an LLM judge. Require a
strict JSON answer schema. Cover facts such as:

- function purpose/category;
- parameter count and roles;
- return-value dependency or formula;
- important constants and strings;
- branch predicates and case values;
- direct callees and relevant API calls;
- memory read/write behavior;
- whether a specified source can influence a specified sink;
- whether a target is reachable and under what condition;
- an evidence identifier/address supporting every material claim;
- explicit unknown when the available evidence is insufficient.

Score exact fields, normalized sets, numeric values/ranges, data-dependency
edges, and evidence validity. Track unsupported claims separately. Do not use
free-form semantic similarity as the primary score.

B. Source reconstruction

In a fresh session, ask the model to emit one self-contained C or C++
implementation for a specified exported function or small module. Extract the
code, compile it with a fixed compiler command, and run only the hidden benign
test oracle. Score:

- syntactically extractable output;
- compilation success;
- test cases passed / total;
- exact output and side-effect agreement;
- timeout/crash behavior;
- source/output tokens and total wall time.

Behavioral equivalence is the primary reconstruction score. Textual similarity
to the original source is diagnostic only and must not decide pass/fail.

Fairness and leakage controls
-----------------------------

- Use the same model and generation configuration for every paired condition.
- Use temperature 0 and a fixed seed when the runner supports them.
- Use identical maximum input, output, tool-call, and wall-time budgets.
- Count all system prompts, tool requests, tool results, retries, and final
  answers. Prefer the runner's tokenizer/usage counters; also record UTF-8 bytes
  and Unicode characters. Label any estimated token count clearly.
- Start every task with an empty model context. No cross-case memory or cache
  may be exposed to the model.
- Randomize condition execution order deterministically to reduce warm-cache
  bias while preserving paired case IDs.
- Cache analyzer and Ghidra extraction artifacts, but never cache model answers
  as if they were new repetitions.
- Use at least three repetitions for final model comparisons. A one-repetition
  smoke test is sufficient during harness development.
- Never place the expected answer, source filename, descriptive test name, or
  original symbol in a model-visible path or prompt.
- Validate that both conditions can navigate the same target functions. Report
  unavailable information as such; do not fill it from the opposing tool.

Metrics and analysis
--------------------

Report per condition and paired differences for:

- objective-question accuracy and per-field precision/recall/F1;
- evidence-validity rate;
- unsupported-claim/hallucination rate;
- explicit-unknown rate;
- reconstruction compile rate;
- reconstruction behavioral test pass rate;
- input, output, and total tokens;
- tool calls, analysis time, model time, and end-to-end time;
- failures, timeouts, and retries.

Calculate paired bootstrap 95% confidence intervals over case IDs for the main
accuracy, behavioral-equivalence, and token-difference metrics. Show raw counts
alongside percentages. Do not turn missing/failed runs into wins for either
condition. Publish negative or neutral results unchanged.

Implementation requirements
---------------------------

Use Python 3 and standard-library components where reasonable. Keep model,
AIRECE, Ghidra, compiler, corpus, controller, and scoring concerns behind
separate adapters/modules. Configuration must be a checked-in JSON or TOML
document with CLI overrides. Provide:

- deterministic dataset generation/build commands;
- a Ghidra headless export script;
- AIRECE and Ghidra tool adapters;
- an LM Studio adapter for `prism-ml/bonsai-27b` using configurable
  `/v1/responses` and `/api/v1/chat` URLs, health/model checks, tool-call loops,
  usage capture, bounded retries, and transcript redaction;
- resumable execution with atomic per-run JSONL records;
- schema validation for model answers;
- hidden-oracle reconstruction compilation/testing;
- paired scoring and confidence intervals;
- unit tests for parsers, scoring, leakage checks, and resume behavior;
- unit tests for instruction-pack isolation, hashing, and common-schema parity;
- `--dry-run`, `--max-cases`, `--repetitions`, and per-stage timeout controls;
- README instructions containing exact commands;
- machine-readable `manifest.json`, `runs.jsonl`, `summary.json`, and a concise
  human-readable `report.md`;
- hashes and version/configuration snapshots for every external artifact.

Do not make a large framework before proving the end-to-end path. First make
one binary, two objective questions, one reconstruction target, both AIRECE and
Ghidra conditions, and one local-model repetition work. Then add the remaining
cases and scoring. Keep generated binaries, Ghidra projects, model transcripts,
and reports out of Git unless they are intentionally small fixtures.

Execution and exit conditions
-----------------------------

1. Run the frozen quick analyzer benchmark and retain its JSON report.
2. Implement and pass harness unit tests.
3. Complete an end-to-end smoke benchmark with at least two benign cases,
   AIRECE and Ghidra, objective QA and reconstruction, one repetition.
4. Inspect the raw transcripts for leakage and unequal information.
5. If the smoke run is valid, run a bounded preliminary benchmark of 10-20
   held-out cases and three repetitions, provided it fits local time/resources.
   This is not a request for an unbounded or overnight run.
6. Produce the raw records, summary, confidence intervals, and report. Clearly
   distinguish analyzer correctness from model usefulness.
7. Leave the AIRECE analyzer tag unchanged and all repositories clean. Commit
   the harness separately with a focused commit message.

At completion, report the exact frozen analyzer revision/hash, Ghidra version,
model and runner configuration, corpus size and compilation matrix, all failed
or skipped cases, headline paired results, report paths, and any reason the
result is not yet publication-quality. Do not claim victory based on a smoke
test. The benchmark is successful if it produces an honest, reproducible answer
about whether AIRECE helps, including if the answer is no.
```
