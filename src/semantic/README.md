# Semantic layer

The Phase 3 expression view walks the XAIR use/definition graph directly. A
`SemanticExpression` keeps its root `xair_value_id`, root operation, all
referenced values and displayed operations, source span, confidence, exact XAIR
type, and deterministic display text. It is a cached presentation object, not a
second semantic IR.

The renderer performs copy propagation, safe single-use inlining, comparison
and address reconstruction, load/store formatting, cast cleanup, boolean
negation, call-result binding, and flag-expression conversion. Constants are
only printed from constants already present in XAIR; the renderer does not
invent symbolic facts or initialize a solver.

Inlining is conservative. Calls, stores, barriers, opaque operations, repeated
loads, and repeated expensive expressions remain bound to named XAIR values.
A load is only inlined within its block when no intervening operation may write
memory, call, act as a barrier, or otherwise carry opaque effects. Depth, node,
node, semantic-token, and character limits bound output; structural limits
degrade to deterministic temporary names and report truncation instead of
recursively expanding without bound.

Public entry points are `airece::ExpressionRecovery` for an existing XAIR
module and `AnalysisSession::expression_view` for normal product use. The CLI
form is:

```text
airece expr <binary> <xair-value-id> [--max-expression-depth N]
```

## Presentation variables

The Phase 4 variable view assigns stable presentation identities without
changing XAIR SSA. Distinct XAIR values stay distinct even when both originated
from the same architectural register. Storage is grouped only when its identity
is proven by the same affine stack base, byte offset, and width, or by the same
constant global address and width. Overlapping stack accesses remain separate
and carry `overlaps_uncertain`.

Naming follows the Phase 4 priority: user/debug hints, import/API roles,
calling-convention or other semantic roles, exact stack/global addresses, then
`tmp_<xair-value-id>`. Collisions receive deterministic suffixes. The initial
type vocabulary is `bool`, signed/unsigned 8/16/32/64-bit integers,
`addr32/addr64`, `ptr`, `ptr<u8>`, `handle`, `function_ptr`, and
`unknown<N>`. `PresentationType::exact_bits` always preserves the underlying
XAIR width even when a semantic role such as `handle` is shown.

Both the name and type include evidence, confidence, and an inference reason.
Binary symbols, XAIR sources, memory operations, call attributes, and calling
conventions remain directly traceable. Variable recovery is cached and does
not initialize the symbolic engine or Z3.

```text
airece vars <binary> <function-address> [--max-variables N]
```

## Compact function view

Phase 5 collects function facts directly from XAIR operations, CFG nodes and
edges, loader metadata, expression views, and presentation variables. Each
material `SemanticStatement` has a stable `S<N>` identity, the original XAIR
operation/value references, a CFG node/block, confidence, and either an address
or an `E<N>` evidence record. Calls, loads, stores, barriers, opaque effects,
`UNKNOWN`, `UNDEF`, terminators, global/string constants, and indirect-target
sets stay visible. Taint is reported as `not-requested` until selective Phase 8
analysis is explicitly enabled.

The independent byte, statement, call, evidence, expression-depth, region, and
transfer limits are deterministic. Truncation records exact omitted categories
and emits a bounded continuation footer; low-value constants are considered
after calls, side effects, memory, and control statements. The ordinary default
is 4096 output bytes plus, only when needed, the small truncation footer.

```text
airece fn <binary> <function-address> --view compact [--max-bytes N]
```

## Conservative control regions

Phase 6 calls `xair_cfg_analyze_function_ex` and presents its reverse postorder,
dominators/postdominators, back edges, natural loops, SCC irreducibility, and
indirect-target facts without copying or rewriting XAIR. `ControlRegion`
recognizes sequences, terminal conditionals, if/else joins, early returns,
natural while/do-while loops, and bounded switches. Every region references the
original CFG nodes and address evidence.

Every function CFG edge, including call and tail-call edges, receives a
`ControlTransfer`. Back edges and loop exits are displayed as continue/break;
unrecognized and irreducible transfers remain explicit gotos. Unreachable
function nodes are appended deterministically instead of being dropped. A
failed or budget-limited analysis therefore degrades to labelled block-order
orientation rather than inventing structured semantics.

```text
airece fn <binary> <function-address> --view pseudo [--max-bytes N]
```
