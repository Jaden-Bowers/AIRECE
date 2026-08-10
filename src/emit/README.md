# Emitters

Phase 5 implements the compact text emitter as the primary AI-facing output.
It groups stable semantic statements into calls, control, branches, memory,
references, unresolved behavior, taint status, and evidence. A byte-aware
writer never exceeds its configured body budget; any overflow is reported in a
small deterministic omission/continuation footer.

Phase 6 implements conservative pseudocode orientation. It intentionally uses
labels and an explicit CFG-edge ledger, with structured-region annotations for
recognized if/loop/switch shapes. It is not compilable C and never hides a
transfer merely to look cleaner.

Semantic JSON and exact function-restricted XAIR emission remain future output
modes; neither is emulated by a second IR.
