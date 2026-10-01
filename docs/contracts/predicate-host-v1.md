# Native predicate host v1

`ctxql_service::predicates::NativePredicateExecutor` implements the frozen engine
`PredicateExecutor` seam and `ctxql-predicate-numeric/v2`. It is Send + Sync and
contains no Rhai objects. **The service must invoke evaluate/validate on its bounded
native worker scheduler, not Tokio core threads.** Engine, scope and AST are fresh
and worker-local; no cache or unbounded worker spawning is introduced here.

Dependencies: Rhai exactly 1.26.0, features `decimal`, `no_float`, `internals`,
`unicode-xid-ident`; rust_decimal exactly 1.40.0. Do not enable unchecked. Parent
registers `pub mod predicates` and owns Cargo/lock/scheduler integration.

Original source is validated with optimization None, with scoped function bodies
(clone-functions then retain), unknown-name/cycle rejection and deterministic
LET order. The trait uses None; `evaluate_with_optimization` exposes None/Simple/Full
for parity validation. Optimization occurs before effectful callback registration.
Callback-only lexical adaptation
copies numbers, comments, raw/quoted strings and interpolation text unchanged;
interpolated executable regions are adapted recursively. `fn:external(name,
arg, ...)` supports a dynamic string name and zero through fifteen arguments.
The internal symbol cannot be authored, rebound or obtained with `Fn` reflection.
Native local named/anonymous functions, loops, ranges and switch remain native.
Scientific literals such as `1e-28` reject in the pinned no_float parser; there is
no numeric rewriting or hidden FLOAT path. Errors retain native source positions
in adapted text; these can differ after a callback token on the same line.

External numbers enter as exact Decimal, verified against ExactNumber after
conversion. Native INT/Decimal results preserve their represented value, including
native rounding. Missing uses an opaque tagged value distinct from null/unit;
timestamps and grounding are immutable typed wrappers, with pure comparisons.
Supported numeric/string/boolean/dateTime typed literals are converted by their
semantics; unsupported literals fail. Arrays and canonical maps recursively
convert. External function pointers and arbitrary host Dynamics never enter;
function pointers cannot escape an expression into LET/state/callback results.
`exists` distinguishes Missing from null. Typed values cannot be serialized into
canonical state when canonical JSON cannot preserve their tag.

Every expression receives newly reconstructed readonly bindings. LET values are
owned boundary values, NEXT expressions independently read pre-candidate state,
unspecified keys survive, and KEEP sees complete `next` and must return bool.
NEXT keys must exist in INIT. Controller supplies initial state from INIT once per
root, fresh state for each filter attempt, and exclusively owns admission and
proposal commit/discard. A false Outcome is not a rollback of callback effects.

Source/AST/depth, native operations/recursion/container sizes, boundary nodes/bytes,
state canonical bytes, callback counts and aggregate callback argument tree sizes
are bounded. Zero limits reject explicitly. Interruption is checked on progress,
before and after expressions/callbacks. Callback failure, admission denial,
interruption and aggregate operation exhaustion set an invocation-local sticky
flag: script try/catch cannot restore success. Native resource-limit errors remain
Rhai system errors. These are operational bounds, not a process-memory sandbox.
The lexer also has fixed conservative 16 KiB source/16K token/64 nesting ceilings.

The sole effectful capability is the supplied Arc FunctionCallback. Its service
implementation MUST perform current session/disclosure/dependency authorization
and retain calls in the controller-assigned trace lane. The host never reads a
graph or grants authorization based on a DTO. No ambient IO, eval, imports,
reflection constructors, print/debug or plugins are exposed. Cancellation of a
blocking external call remains the callback/scheduler owner's responsibility.

Tests: `cargo test -p cdb-service --test predicates` plus private scoped-analyzer
unit tests. Cargo validation is parent-serialized; author ran only direct rustfmt.
Authored optimizer-parity tests exercise the actual host, but have not yet been
executed here. Integrated scheduler/controller/replay clearance is not claimed.
