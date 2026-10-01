# Reference execution v1 — P2 fixture conventions

Status: implemented supported slice. This local implementation contract does not claim full CTXQL conformance or production security certification.

Normative semantics remain [execution defaults](execution-defaults-v1.md) (especially C3a/C3d), [core model](core-model-v1.md), [backend](backend-v1.md), [configuration](configuration-v1.md), [canonical projection](canonical-v1.md), [exact numbers](numeric-v1.md), [transaction clock](transaction-clock-v1.md), [policy integration](policy-integration-requirements.md) and [evidence selectors](evidence-selectors-v1.md). This describes the narrower executable binding, not amendments to sibling specifications.

## P3 durable preparation extension

P2 fixture restrictions remain unchanged. The real [redb provider](redb-projection-v1.md) instead reads latest immutable per-image provenance across admissions, applies the fixed cutoff and supplies entity/label/origin dependencies for current Fluree policy. `execute` remains exact. `execute_with_consistency` adds explicit Exact/AllowStale and a default-none proposal hook: capture first, validate full older ancestry, use actual-pin artifacts/data, then current policy and same-gate release. Opt-in transport contains requested/actual identities and cutoff; actual stale adds the existing-schema stale_snapshot flag/notice and warning. No error-triggered fallback, canonical-domain change or replay recording is introduced.

## Compiler and artifacts

`ctxql_engine::compiler::compile(QuerySource, Option<SelectedProfile>, &PublishedArtifact, CompileOptions)` returns a privately constructed `ValidatedDraft`. `QuerySource::inline` and `QuerySource::published` distinguish inline bytes from exact published identity. Config is always a published artifact. A selected profile must match the authored selector; unsolicited profiles fail and chaining is unsupported. `ValidatedDraft::finalize(captured_as_of)` constructs `ExecutablePlan` and its canonical plan hash; a requested cutoff must agree with capture.

Parsing is bounded, duplicate-aware, lossless strict JSON, not JSONC or a floating-point bridge. Unknown fields/operators and malformed structures fail validation. Defaults merge config → profile → query: objects recurse, ordinary arrays/scalars replace; phase-local predicate drops precede in-place named replacement and append, inherited unnamed predicates remain, and explicit empty arrays clear. Unsupported inherited predicates can be removed before capability validation. Profile `about` is ignored with a warning.

`max_depth` is required; default seed/fanout/claim/path caps are 2/4/16/8, direction outgoing, and return selection claims/paths/evidence/explain is true/true/false/false. Caps are nonnegative integers; zero is not unlimited. Effective omitted `match` remains approximate and is Unsupported: P2 requires explicit exact.

Local prefix dictionaries expand identifier positions and configured mapping IRIs, not all strings, ext payloads or arbitrary bounds. Reserved namespaces cannot be overridden. Undeclared opaque anchors remain exact text. Bound operands are resolved after merge and typed at use; the complete bounds map is retained. Equivalent unused raw bounds are not promised equivalent hashes.

Supported bare triples and named `{name,where}` predicates use `=`, `!=`, `>`, `>=`, `<`, `<=`, `in`, `not_in`, `contains`, `contains_any`, `exists`. Fixed metadata, generic unconfigured `meta:ext:*`, depth, computed lifecycle and ordered `path.meta:*` lists use exact typed values, preserving Missing versus null and typed literal identity. No implicit coercion/case folding; incompatible dynamic values and late incompatible list members are errors, not false. Bare filter predicates are independently existential over claims; path lists preserve order, duplicates and internal Missing. Walk depth is prospective; filter depth is the claim's one-based position.

`artifacts::Catalog` pins kind/name to immutable artifacts; `resolve` requires an exact expected reference. `read_json(root, kind, name, expected, limits)` reads `root/{queries,profiles,configs}/name.json`. Names reject traversal/absolute-path forms; static symlink escapes, changed bytes and missing pins fail. Exact original bytes establish artifact hashes, not reserialized JSON. The caller must own a **stable filesystem** during canonicalization/open/read: this portable adapter is not race-safe isolation from hostile concurrent filesystem mutation. There is no ambient root/config lookup, publisher or latest-version fallback.

Walk predicates short-circuit in merged order on the first false result; cycle-rejected candidates do not evaluate predicates. A reached predicate still validates all relevant list members before returning. Walk `path.meta:*` is the ordered prospective path, including ancestors and the candidate with one-based depth and internal Missing entries; it never uses scalar substring semantics in place of list containment.

## Explicit stored-predicate mapping opt-in

The ordinary `compile` entry point leaves mapping capability disabled. Opt in with:

```rust,ignore
compiler::compile_with_capabilities(
    query, profile, config, options,
    compiler::MappingCapabilities { stored_predicate: true },
)
```

These names are in `ctxql_engine::compiler`; arguments are the same as `compile`, followed by capabilities. Config mappings name ext fields, e.g. `"meta:ext:score":{"source":"stored_predicate","iri":"https://fixture.example/score"}`. Selected stored mappings cannot have `resolver` or nonempty `requires`. Selected reasoned/computed mappings remain Unsupported. Unused valid mapping/function registry data is retained and hashed; it is not executed. Nonempty `preparation` is currently rejected by the coordinator as unavailable source preparation, even without evidence hydration.

`CompiledPredicate::mapping()` returns a read-only `StoredPredicateMapping` with `field()` and `iri()`. `ViewProvider::mapped_fields() -> Option<&dyn MappedFieldProvider>` defaults to None and is checked after `open`. The provider implements:

- `identity() -> &SnapshotRef` and `supports(&StoredPredicateMapping) -> bool`;
- `dependencies(&ClaimId, &StoredPredicateMapping) -> Result<&[MappingDependency]>`;
- `value(&ClaimId, &StoredPredicateMapping) -> Result<Option<&CanonicalValue>>`.

`MappingDependency { resource: ResourceId, facts: Vec<Iri> }` declares interpretation dependencies. The dependency slice must be nonempty. Resources and their recorded facts are authorized; explicitly named facts must exist and be allowed before `value` is called. Missing/denied mapping dependencies block release, provider errors propagate, and wrong full snapshot identity fails. `None` means Missing, never generic ext fallback. Mappings override predicate lookup in walk/filter, not serialized immutable claim ext metadata.

This is a **trusted dependency-completeness attestation**, not inferred provenance: providers must include every dependency, including facts establishing absence. Methods return immutable borrowed data using deterministic bounded local lookup, without I/O. Capability opt-in is not authorization; the engine cannot detect omitted dependencies or sandbox provider preparation/callbacks. No decisions or mapped-value cache survive an execution.

## Trusted preparation and current-authority release

`execution::execute(draft, backend, policy, principal, provider, options, sink)` accepts `GraphBackend`, `PolicyService`, its issued principal, and a trusted `ViewProvider`; it returns `Result<()>` asynchronously. It captures first, finalizes the cutoff, opens/prepares the exact data view/catalog/mappings and artifact snapshot, then obtains **current** policy. Full `SnapshotRef` equality is required, including backend identity, not merely transport `GraphPin` equality.

The caller must wire backend and policy to the **same authority and mutation/release gate**. Separate generic `B: GraphBackend` and `P: PolicyService` parameters do not prove matching authority. Providers must faithfully represent that captured backend and completely declare landing, metadata, mapping and source interpretation dependencies. Raw views and fixture construction are trusted, not public authorization bypass APIs.

Pinned artifact resources and `artifact.iri`, `artifact.version`, `artifact.hash` facts must be permitted and retained. Candidate guards cover claim metadata, endpoints, available vocabulary interpretation records, lineage source resources, and lifecycle dependencies before usable candidates affect semantic ordering/counters. Vocabulary IRIs without fixture interpretation records remain external symbols, not invented ontology closure. Missing/denied ordinary required dependencies make the dependent candidate unusable; mapping/artifact prerequisites instead fail execution. Backend/policy errors and corruption are not empty-data fallbacks.

The fixture adapter builds a bounded exact MemoryProjection. Its entity/label catalog uses the `reference-initial` admission receipt because `DependencyRecord` has no transaction timestamp: catalog records must equal those in that receipt's snapshot, and its admission time must be visible at cutoff. New/changed catalog resources fail Unsupported (`changed fixture catalog requires new provenance`). Later lifecycle admissions with the initial catalog unchanged are supported; this is not a general temporal source-metadata catalog.

Private response construction, optional source reads, hashing and complete bounded serialization precede `PolicyService::publish`. Publish validates the issued principal/current context under the authority mutation gate. Any authority mutation invalidates the context; stale/foreign context releases nothing and is not silently retried. The trusted sink is `&mut (dyn FnMut(&[u8]) -> Result<()> + Send)`: it must atomically accept/stage the entire buffer and must not re-enter backend/policy services. No such calls occur inside the publish callback. A callback that partially writes then errors cannot be rolled back by this API; arbitrary streaming I/O is not a conforming sink.

## Fixture fact vocabulary and lifecycle

`execution::property_iri(key)` prefixes `https://ctxql.example/reference-property/v1/` and percent-encodes each UTF-8 byte except ASCII alphanumerics, `_` and `-`, using uppercase hex. Thus `lineage.sources` uses `lineage%2Esources`. This is a policy binding, not a new query-field dot grammar. The fixture emits `entity` and `label` facts; claim response `meta` keys map directly (without a `meta.` prefix), recursively guarding dotted object/container paths. Array members reuse the containing path. Artifact fact keys are the three `artifact.*` names above. Dependency records also carry their actual predicate IRIs; those facts are checked directly.

Raw lifecycle support is enumerated before permission filtering. Every visible support, including lower-priority support, and typed target/replacement claim or event references must be usable; denied support cannot disappear and turn a claim active. Support claims' own lifecycle is not recursively evaluated to read their base facts. Transaction cutoff is inclusive; valid time is separate.

Priority is retracted > superseded > contradicted > active. Winning-kind supporting **assertion claim IDs** sort by newest transaction time then smallest ID; event resource IDs are not assertion IDs. Explain uses `ctxql-execution/v1:lifecycle`, sorted returned-claim entries and only winning-kind supporting IDs. Lifecycle is metadata, not an implicit active-only filter: no deletion, replacement auto-hop or confidence transfer.

## Deterministic execution

Exact landing unions exact IDs and exact label strings, deduplicates by entity ID, score 1, ID order, retaining earliest anchor provenance. Authorization precedes landing caps. From/to are independent per block; seed_limit applies only to from, targets are operationally bounded. No fuzzy fallback or zero-hop result.

One breadth-first frontier spans blocks/seeds, ordered by depth, block index, seed rank and parent claim-ID vector. Candidates at each prospective depth order by confidence descending, transaction time descending, then claim ID. Incoming/outgoing/both traverse individual assertions without rewriting stored orientation; both self-loops deduplicate. Supported path-local cycles are no_repeated_claim, allow_repeated_claim (depth bounded), no_repeated_node. Parallel equal triples remain distinct.

Cycle/walk passes consume fanout; rejected candidates do not. A fanout-accepted candidate then faces the global unique traversed max_claims cap: unseen IDs are skipped when full but already-counted IDs may traverse again. Outward queries retain every nonzero prefix; connecting queries retain target-reaching prefixes and keep expanding. Literals terminate, never become frontier nodes. Filters run after traversal and cannot refund traversal budgets. Results rank by depth ascending, exact confidence product descending, weakest grounding descending, ordered transaction-time vector descending, claim-ID vector, block index, seed ID. Global path_limit follows filtering/ranking. Returned claims deduplicate/sort by ID; paths retain rank order.

## Concrete notices, counters and failure boundary

Semantic notices are unique, lexically sorted codes with empty details; no discarded IDs/counts:

| Code | Actual trigger |
|---|---|
| `ignored_profile_about` | compiler notice carried into execution |
| `empty_landing` | a prepared from/to role has no authorized matches |
| `seed_limit` | authorized from matches exceed seed cap |
| `max_depth` | a queued parent reaches the depth cap (not proof of an omitted edge) |
| `fanout_limit` | a cycle/walk-passing candidate exceeds parent fanout |
| `max_claims` | fanout-accepted unseen claim exceeds global unique cap |
| `path_limit` | filtered ranked paths exceed final path cap |

Explain counters are `examined` (authorized usable deduplicated candidates visited), `eligible` (cycle/walk passes before caps), `traversed` (accepted traversal occurrences), `unique_traversed` (distinct accepted IDs), `returned_paths` (after filters/ranking/path cap). They are not raw read counts. Explain also carries authorized landings, captured context and empty `ontology_resolution`. Any semantic notice makes graph_status `ready_with_warnings`; otherwise `ready`.

Unsupported capability, validation/evaluation failure and operational exhaustion are **errors**, not invented successful-response notice codes. `diagnostics::public_code` maps Unsupported to `unsupported_capability`, Invalid/Range/Arithmetic to `validation_or_evaluation_failed`, and Limit/Deadline to `operational_exhaustion`; cancellation shares Deadline. Other errors use core public codes (`access_denied`, `policy_changed`, otherwise `preparation_failed`). Internal Error messages and Display are not safe public output; callers must use the redacted code APIs. No partial successful response is published on failure.

`ExecutionOptions` supplies Limits, max_work, max_records, max_frontier, max_paths, max_retained_bytes, page_size, deadline and cancellation. Checked work, page progress/identity, cumulative canonical retention, queued state, retained paths and serialization are bounded separately from semantic caps. These are logical budgets, often cumulative rather than peak allocation, **not RSS guarantees, timing-side-channel protection or an untrusted-provider sandbox**. Cooperative interruption does not preempt arbitrary callbacks. Nonbinding operational limits do not change semantic hashes; binding limits fail instead of clamping query caps.

## Response and evidence boundary

All four return booleans are applied; canonical claims/paths/explain are null when unselected and selected empties remain selected empties. Transport status is always present. Full claim metadata/lineage and typed path endpoints come from execution, not expected fixture output. Semantic plan/response hashes follow canonical-v1; plan identity excludes operational paths/secrets/budgets and graph pin, while selected explain can carry captured graph context in the response.

Evidence is transport-only, not a canonical evidence:null section. `evidence=false` makes no source read. An optional `ViewProvider::evidence_reader()` receives only authorized returned-path lineage's pinned version and exact selector, never a widened whole document. The trusted reader must honor that identity and byte bound. Outcomes are `verified`, `changed`, `unverifiable`, `unavailable`; only verified UTF-8 bytes become text content. Additional selector witnesses not verifiable from the narrowed bytes produce unverifiable. Missing reader/read failure is unavailable; missing version/selector is unverifiable. Limit/Deadline and selector identity mismatch fail execution.

Nonverified evidence adds transport `evidence_unavailable` and status `ready_with_warnings`, without changing graph_status or response_hash for the same graph selection. Evidence availability is not graph interpretation permission; denied required graph dependencies cannot become hydration warnings.

## Runnable examples and deferred scope

Use the real public-API fixture tests as executable library examples (no CLI exists):

```sh
cargo test --locked -p cdb-testkit --test reference_execution
cargo test --locked -p cdb-engine --test mapped_compilation -p cdb-testkit --test mapped_execution
cargo test --locked -p cdb-testkit --test lifecycle_execution --test execution_boundaries
cargo test --locked -p cdb-testkit --test p2_conformance -- --nocapture
```

Sources: [basic execution](../../crates/cdb-testkit/tests/reference_execution.rs), [mapping provider](../../crates/cdb-testkit/tests/mapped_execution.rs), [lifecycle](../../crates/cdb-testkit/tests/lifecycle_execution.rs), [boundaries](../../crates/cdb-testkit/tests/execution_boundaries.rs), and [case runner](../../crates/cdb-testkit/tests/p2_conformance.rs). These executable entry points establish behavior; they are not performance or full-workspace validation claims.
