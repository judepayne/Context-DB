# Recording/replay v3

## Portable boundary

`recording_v3::{ReplayDataV3Input, ReplayDataV3, RunEnvelopeV3, StoredV3}`
contains **validated evidence, never authority**. Constructors and decoders use
caller-injected core `Limits`; there is no timestamp/default fallback. The
service must supply its privately authorized original basis, actual controller
trace, exact manifests and current release checks. Public DTOs cannot prove that
an execution happened or that a footprint is complete.

Wire schemas are explicitly `ctxql-replay-data/v3` and
`ctxql-recorded-run/v3`. Execution ABI is `ctxql-execution/v3`, numeric ABI is
`ctxql-predicate-numeric/v2`. `engine` retains existing recording identity;
`executor` separately requires `name`, `version`, and exact `build` hash.
Neither identity implies that an evaluator is installed.

Replay uses a **flattened** schema: all v2 data vocabulary remains at the top
level, with `functions` replaced by v3 compact summaries and required fields
`numeric_abi`, `executor`, `lanes`, `expected_lanes`, `prepared`,
`release_evidence`, and `final_footprint`. Unknown/missing fields reject. An internal v2 vocabulary
validator checks full source/requested pins, stale provenance, exact as_of,
artifact refs, validated plan/response and hashes, pre-cap landings/catalog,
original policy/read observations and four mandatory scopes. This is not a v2
seal or wire promotion. `ReplayDataV3Input.base.functions` must be empty; the
new input's `functions` field is the only function-summary channel. Old v1/v2
constructors, decoders, bytes and nonempty-function rejection are unchanged.
`data()` exposes the validated shared fields; `projection()` exposes all v3
fields. `new`, `from_value`, `read`, and `bytes` share validation.

## Logical lanes

A lane has exactly:

- `identity`: `{phase, evaluation, predicate, attempt, ordinal}`. Phase is
  `preparation`, `walk`, or `filter`; the remaining values are u64.
- `closed`: must be true.
- `outcome`: `empty`, `accepted`, `rejected`, or `cap_denied`.
- `reads`: `{ordinal, observation}` entries. Ordinal is contiguous zero-based
  u64 and observation uses existing validated ReadObservation vocabulary.
  Repeated identical reads retain separate ordinals, including negative/empty
  operations. `policy` and `scopes` are arrays of existing vocabulary. All
  observations must belong to the full recorded footprint.
- `function_counts`: unique `{name, count}` entries, count positive u64.

Lanes are strictly ordered by phase rank then the identity's four integers;
`expected_lanes` is the exact ordered identity list. At least one preparation/
controller lane is represented even for empty execution. Empty closed lanes
are retained, not optimized away. Every base observation/scope is assigned to
at least one lane. Duplicate identities, duplicate observations within a lane,
duplicate base observations, missing assignments and missing/extra/unclosed
lanes reject. The controller deduplicates base observation vocabulary while
preserving separate repeated reads through their lane-local ordinals.

The expected list is evidence, not an authority assertion. Replay must build
its own actual lanes and compare; editing both lists cannot grant permission.
The controller assigns physical callback identity from lane identity plus
local callback ordinal and assigns per-function encounter indices in logical
order before streaming. Per-call hash/payload lists are **not persisted**.
Function counts are per-lane aggregates, not physical retry counts. Rejected
and cap-denied work remains represented. The controller must not collapse
multiple local identical reads into one occurrence when constructing lanes.

## Compact functions and exact source

Each summary has exactly `{name, manifest, source, deterministic, replay,
count, input_root, output_root, destinations}`. `destinations` is a nonempty,
strictly resource-ID-ordered unique array containing the exact original
administrative disclosure destination(s), not endpoint URLs or credentials.
Summaries are name-ordered and unique.
`manifest` is the existing exact ArtifactRef, `source` is original UTF-8 JSON
text. Its raw byte hash must match the artifact, including noncanonical JSON
whitespace. Name, version, URI, hash and determinism must match the immutable
plan's external-function registration. Every encountered name has exactly one
summary; extra unused summaries reject. Counts equal checked u64 sums of lane
counts. Roots must be well-formed existing ContentHashes; nonempty roots are
verified by actual replay, not inferred from the compact DTO.

`replay` is `exact` or `unavailable`; nondeterministic `exact` rejects. These are
retained declarations, not remote attestation or broker permission. The broker
must additionally validate its strict executable manifest schema and actual
capability. Missing evaluator/provider or unavailable declarations must not be
reported as reproduced merely because hashes happen to match.

`function_stream::FunctionRootStream::new(output, manifest, limits, max_calls)`
uses SHA-256 with the exact existing FunctionRootProjection envelope and
ordered `hashes` array bytes. `push(&ContentHash)`, `count()` and consuming
`finish()` retain only a digest, framing suffix and u64 count. There is no
vector, Merkle tree, chain or tenth canonical domain. Canonical string encoding
handles identity escaping. Framing is bounded by core limits; lifetime stream
work is separately bounded by `max_calls`. Failed pushes do not mutate the
stream, including u64 overflow. The caller bounds staged callback values and
must hash FunctionCallProjection only after assigning its final encounter
index. Root framing limits do not pretend the conceptual 100k-element array
must fit the persisted envelope budget.

## Prepared interpretation and current release

`prepared` entries have exactly `{identity, snapshot, as_of, selections,
translator, reasoner, rules, dependencies, reads}`. Identities are unique;
source snapshot/as_of must exactly match original data identity. Selections,
translator, reasoner and rules use exact ArtifactRefs (including build/source
hashes); dependencies are resource IDs and reads must occur in the recorded
footprint. Arrays reject duplicates. Private native preparation must supply
complete positive/negative observations and validate that selections correspond
to the selected executable mapping/rule configuration. It also records exact
artifact reads and one complete-source RAW observation; the preparation lane
contains those reads, and reconstruction repeats preparation and requires exact
read identity/value/hash equality. The recording projection obtains reads from
the prepared object itself, so a caller cannot substitute an empty list. The DTO
does not seal completeness or substitute for INTERPRETATION_SCOPE.

The final complete recording footprint is independently bound by
`final_footprint`, the raw SHA-256 of exact canonical `{snapshot, as_of, reads,
policy, scopes, prepared, functions}` bytes. `footprint_hash(limits)` verifies
and returns that binding. It is not an authorization-check claim.

`release_evidence` is separately bounded and integrity-bound. Each entry is
exactly `{action, requirements, requirements_hash, authorization_head,
allowed}` with a unique action resource identity and complete backend-issued
SnapshotRef head. `requirements` has the closed shape
`{facts:[{resource,predicate}],invocations:[{manifest,provider}]}`. Both arrays
are strictly ordered and duplicate-free; manifest uses the exact ArtifactRef
shape. `requirements_hash` is raw SHA-256 over the exact canonical requirements
object bytes. Facts must correspond to final positive policy observations or
mandatory view scopes. Invocations must correspond to a summary's exact
manifest **and stored original destination**. Every stored manifest/destination
binding requires at least one allowed action receipt. Function callbacks derive
a deterministic callback ID from lane identity and local ordinal. Enqueue and
consume action IDs add a positive physical-attempt number and action kind. The
strict replay-data decoder requires each logical callback to have one contiguous
enqueue attempt sequence starting at one and exactly one consume action at the
final successful attempt; missing, extra, reordered, or unknown callback actions
reject even if another receipt carries the same manifest/provider requirement.
An early action may bind a strict subset of requirements discovered by a later
action; no receipt may claim future dependencies merely because they appear in
`final_footprint`.

Core constructors validate shape, hashes, limits and recording correspondence,
but evidence remains data. The backend's `AuthorizationCheckReceipt` has a
private constructor and is returned with the action value by
`guarded_execution_action_checked`; its requirements projection/hash and actual
checked authorization head have read-only getters. The legacy guarded action
API discards this receipt as a compatibility wrapper. For final publication,
`guarded_execution_commit_v3_built` invokes a bounded envelope builder after
the real precommit gate check and before admission, so that check can be
recorded without a self-referential postcommit claim. The commit admission
receipt remains separate. No credentials or native policy internals are
serialized. A head change cannot change plan/response/function roots, but does
change stored envelope integrity.

`verify_semantics(actual)` compares complete v3 replay evidence except historical
release evidence. Runtime must perform fresh current checks, not require fresh
heads to equal historical heads. Original false masks remain frozen; current
denial is an authorization failure, not pruning. The backend exposes them only
through a non-serializable, private-field replay capability issued after protected
v3 lookup and bound to the run, principal, Replay operation, capture authorization,
and exact stored decisions. The generic native-broker authorizer constructor is
query-only; its replay constructor requires this capability. Stored positives
receive fresh current preflight, while stored false decisions are not re-evaluated
and remain frozen after later grants. A public decoded envelope or independently
captured Replay `ExecutionAuthorization` cannot mint or replace this capability.
Before every provider enqueue/consume gate, the capability additionally requires
the exact stored callback identity and manifest/destination and rejects any fact
or scope outside the stored positive mask. A later grant for a recorded false or
previously unrecorded resource therefore cannot authorize outbound disclosure.
This comparison alone does not execute predicates, authorize release, or establish
an exact replay verdict.

## Storage and integration

`RunEnvelopeV3::new(id, owner, operation_hash, replay, limits)` preserves owner
and operation identity separately from semantic roots. It provides the same
read/projection/bytes/integrity_hash/id/owner/operation_hash/replay accessors
and descriptor helpers as v2. `StoredV3::{to_record, from_record}` is a distinct
storage payload: `ResourceKind::RunDescriptor`, existing `INTERNAL_PREFIX`
run-ID-derived identity, and sole `RUN_PAYLOAD` xsd:string fact. Decoding checks
canonical stored payload bytes and descriptor identity. Dispatcher must inspect
schema and route to v1/v2/v3 without rewriting old records. A protected owner/request lookup and owned commit path still establish
authority. V3 protected commit, reopen and retry derive the required exact
manifest/destination pairs from the envelope. Existing invocation arguments
are compatibility assertions only: they must equal the complete stored pairs,
and cannot substitute a current route or another destination. Fresh policy
must authorize the stored pairs.

Parent registration required in core lib: `pub mod recording_v3; pub mod
function_stream;`. No new dependencies: existing core sha2 suffices. No engine,
native backend, Rhai, broker, manifest or Cargo files are changed here.

## Validation

Authored tests: `cargo test -p cdb-core --test recording_v3 --test
function_stream` plus `cargo test -p cdb-core --lib function_stream` after
parent module registration. Tests cover flattened/storage roundtrip and identity,
missing fields, unknown/schema/ABI guards, pins/hash tampering, limits,
nonempty old function channel, closed/duplicate/negative lanes, compact 100k
counts, exact noncanonical manifest bytes and missing/extra/tampered summaries,
release-head root separation, streaming empty/small/100k vector equivalence,
quote/backslash/Unicode escaping, rejecting budgets and counter overflow.
Only direct rustfmt validation is run by this worker; Cargo is parent-serialized.
Integrated broker execution, native reopen, current authorization and replay
verdict acceptance remain parent integration tests, not claims of this codec.
