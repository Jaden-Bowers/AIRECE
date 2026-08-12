# Emitters

The agent emitter is the primary AI-facing output. It emits a small ordered behavior
digest plus compatible fact tables. Branch predicates are linked to results, switches map
case values to results, indirect targets retain their guards and argument bindings, and
internal calls can include bounded one-hop summaries. Recursive callees include a recurrence
when the recovered control and data flow supports one. Callee facts are scoped so they cannot
leak into the caller's return list.

Phase 6 implements conservative pseudocode orientation. It intentionally uses
labels and an explicit CFG-edge ledger, with structured-region annotations for
recognized if/loop/switch shapes. It is not compilable C and never hides a
transfer merely to look cleaner.

Agent, compact, pseudo, semantic JSON, and exact function-restricted XAIR views all derive
from XAIR. Byte limits preserve valid documents and report omitted records explicitly.
