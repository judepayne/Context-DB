# Semantic/control boundary — `ctxql-semantic-control-boundary/v1`

Status: current alpha placement contract. It separates semantic truth, CTXQL operational authority, disposable derived state, secrets/source bytes, and process-local state. It does not establish production isolation or deployment certification.

## 1. Authority rule

The semantic Fluree ledger and CTXQL Control Ledger are different authorities with different identities, clocks, policy bases, storage locations, and write capabilities:

- CTXQL opens the semantic ledger through a read-only capability and never bootstraps, repairs, owns, or transacts it.
- CTXQL writes operational records only through the Control Ledger.
- redb and caches are disposable derivations and never become either authority.
- secrets and source payload bytes remain in their designated external stores.
- one control commit may cite an exact semantic capture, but neither ledger's transaction order implies the other's.

Paths, ledger names, backend/authority identities, and writable handles for semantic and control roles must not alias. Public service constructors must not accept one concrete backend as both roles.

## 2. Placement table

| Information or capability | Semantic RDF ledger | Control Ledger | redb / durable derived | Filesystem, source store, or secret manager | Memory only |
|---|:---:|:---:|:---:|:---:|:---:|
| asserted base edges in governed claim graphs | **authority** | prohibited | no; only endpoint indexes derived from claims | no | bounded view allowed |
| explicit `ctxql:Claim` reifiers and immutable metadata | **authority** | prohibited | decoded claim records only | no | bounded decoded values |
| claim lifecycle assertions and attachment history | **authority** | prohibited | derived lifecycle records needed by execution | no | bounded reconstruction state |
| ordinary governed RDF/reference data | **authority** | prohibited | not traversal records | no | authorized native/prepared view |
| ontology graphs and `owl:imports` closure | **authority** | prohibited | no authoritative copy | fixture/source bytes may provision externally | bounded prepared indexes/cache |
| semantic configuration (`schemaSource`, reasoning defaults, import map, closed governed-data scope and claim-graph subset) | **authority** | prohibited | no | deployment connection settings only, not semantic truth | resolved captured values |
| native semantic policy | **authority** | prohibited | no | credentials excluded | current semantic policy context |
| artifact versions: query/config/profile/function | no semantic authority | **authority** | optional non-authoritative cache only | exact function/source files only where existing artifact contract explicitly uses external bytes | verified working copy |
| CTXQL service policy, roles, scopes | no | **authority** | no | credential material excluded | current control policy context |
| operation journals and idempotency | no | **authority** | no | no | in-flight operation state only |
| runs, replay envelopes, response evidence, authorization receipts | semantic capture referenced only | **authority** | no | no secrets/source payloads | bounded construction buffers |
| owner/schema and migration checkpoints | no | **authority** | derived schema/checkpoint version only | backend locator/config | open/migration state |
| semantic capture `(ledger, t, full CID, as_of)` | native source identity | stored as an exact reference where required | generation checkpoint reference | connection locator may be configured | active execution capture |
| control capture/commit reference | no | **authority** | no | control locator may be configured | active execution capture |
| claim adjacency and historical generations | source claims only | prohibited | **derived, rebuildable** | redb files | selected generation handles |
| ontology/profile/prepared caches | source ontology/config only | prohibited | permitted only if validated as disposable and identity-bound | optional cache files, not authority | permitted, bounded |
| authorized-view manifest/descriptor | source facts remain authoritative | roots/counts/member commitments may be stored inside a protected run; copied RDF is prohibited | prohibited as a reusable authority | no | full manifest is bounded construction state only |
| in-memory reasoning sandbox | no; source capture remains authority | prohibited | prohibited | prohibited | **per-execution only; bounded and disposable** |
| queues, sessions, cancellation/lane state | no | prohibited | prohibited | no | **only** |
| pending external effects | no | prohibited | prohibited | provider owns its own protocol state | bounded in-flight state; final evidence later enters control |
| bearer tokens, private keys, provider credentials | prohibited | prohibited | prohibited | **secret manager or protected credential store** | minimum-lifetime handles |
| source documents and exact provider payload bytes | links/claims may refer to governed sources | prohibited | prohibited | **governed source store/filesystem** | bounded processing buffers |
| trusted semantic fixture writer | external writer may transact | no | no | test fixture inputs | testkit only; closed before service start |

“Authority” means the selected POC source of truth, not an assertion of legal ownership or production governance.

## 3. Capture and execution ordering

A semantic query uses paired but independent captures:

1. capture an exact control snapshot for immutable artifact reads;
2. authorize and verify artifacts from that snapshot;
3. resolve `as_of` without accepting semantic-authority overrides;
4. capture exactly one semantic ledger identity, numeric `t`, and full CID;
5. read and classify claim graphs, claims, lifecycle, ordinary data, ontology, imports, and semantic configuration from that semantic capture;
6. construct independent current semantic and control policy contexts;
7. enumerate the complete policy-visible premise set with reasoning disabled, enforce visible-support and whole-bundle ontology authorization, and seal the authorized-view manifest;
8. materialize a fresh bounded in-memory Fluree sandbox, invoke the direct reasoner, freeze prepared indexes/diagnostics, and destroy the sandbox;
9. select/build a redb generation bound to the semantic capture and codec/projection versions;
10. traverse and invoke functions under sealed dependencies and current checks; and
11. publish the run and receipts in a later Control Ledger commit that references, but does not replace, the semantic capture.

An unrelated later control commit does not alter bytes from the captured control snapshot. Policy freshness is tracked separately. A semantic head change does not alter the captured view, but current semantic authority may still deny release. No mutation gate spans native reasoning or provider latency.

## 4. Allowed direction of data flow

```text
external semantic writer ──writes──> semantic ledger
                                      │ exact captured reads only
                                      v
                         decoder / authorized extractor
                                      │
                                      +──> redb generations (claims only)
                                      +──> sealed authorized-view manifest
                                                  │
                                                  v
                                      disposable Fluree sandbox
                                                  │ direct reasoner
                                                  v
                                      prepared ontology/cache
                                                  │
                                      deterministic execution
                                                   │
control snapshot ──artifacts/policy reads──────────+
                                                   │ guarded append
                                                   v
                                             Control Ledger
```

Reverse arrows from CTXQL to the semantic ledger are forbidden. redb, a cache, a recording, or the Control Ledger cannot repair or fill missing semantic facts. Semantic RDF cannot be used as an implicit artifact/run journal. Control records cannot select claim graphs, ontology source, imports, or reasoning defaults.

## 5. Projection and cache rules

redb stores one immutable admitted projection record per complete claim IRI and the lifecycle records required by the existing execution contract. Parallel reifiers for one base edge remain parallel records. Ordinary unreified RDF, sparse/unmarked reifiers, inferred facts, Control Ledger records, and native handles never become traversal rows.

Every generation/checkpoint binds the full semantic capture, semantic codec version, projection schema/algorithm, and required roots. A mismatch causes selection of another exact generation or an atomic rebuild. It never causes a semantic or control write. Incremental changes may be used only after exact annotation/history decoding is established; complete rebuild is the fail-safe POC path.

Ontology/profile caches additionally bind semantic ledger identity, `t`/CID, configuration and import-closure roots, authorized-view/policy identity where relevant, reasoning options/profile, and exact Fluree revision. Cache reuse repeats current authorization. Cache loss changes performance only; missing source history may make exact reconstruction unavailable and must not be hidden by an unverified cache.

## 6. Authorization boundary

Semantic and control policy bases are independent:

- semantic policy governs claims, proposition support, ordinary data, configuration, ontology/import closure, and conclusions;
- control policy governs artifacts, functions/providers/destinations, service operations, protected runs, replay, and publication.

A claim attachment and complete required metadata are one semantic authorization dependency. A proposition enters reasoning only when at least one active supporting claim is visible. Hidden siblings remain hidden, and a visible base edge cannot bypass a hidden claim dependency. Ordinary data is authorized separately. The configuration/ontology/import closure is all-or-nothing. The service fails before traversal/effects if it cannot completely enumerate and seal the authorized premise view.

The sandbox receives only the sealed ephemeral manifest. It is bound to one semantic capture, principal/action, policy basis, graph-role map, extraction/materialization versions, Fluree revision, options, and limits. It has no history or authority, is never shared across principals or executions, exposes no general query handle, and is destroyed on success, denial, cancellation, timeout, cap, panic-safe owner drop, or error. Prepared caches retain only backend-neutral outputs and identity roots, never a reusable sandbox.

Both current policy bases are rechecked after extraction/reasoning and at required broker transmission, result consumption, and final release/publication points. A policy-basis change discards prepared work and denies or whole-query retries. Historical grants cannot broaden recorded false/absent data; later grants do not rewrite a historical view; current revocation may deny use. Receipts in the Control Ledger remain evidence, not credentials.

## 7. Failure and readiness behavior

The service is not ready for semantic execution when any required role is aliased, writable semantic capability is exposed to query paths, control audit fails, semantic history cannot satisfy the configured query/replay horizon, a projection cannot bind the exact semantic capture, or required policy/profile preparation cannot fail closed.

On mismatch or absence:

- missing semantic history yields `semantic_history_unavailable`, not current-state substitution;
- malformed marked claims or ontology/configuration fail before traversal/effects;
- projection/cache mismatch triggers bounded rebuild or failure, not authority repair;
- control corruption blocks control use rather than falling back to semantic storage;
- policy changes deny or require whole-query retry according to the sealed execution contract; and
- diagnostics are bounded and do not disclose protected RDF, records, secrets, or raw backend errors.

## 7.1 Complete-structure sealing

For the v2 profile, E0 must retain and authorize the complete ontology/import bundle before
structural validation. Validation is whole-graph: RDF lists, restrictions, property expressions,
and nested class expressions cannot be admitted member-by-member or pruned into a supported
subset. The in-memory manifest seals the complete bundle, deterministic profile result, and exact
reasoner projection/mapped input as distinct roots. C0 validates those roots without consulting the
source ledger and materializes only the sealed input.

C0 has no query, history, policy, service-config, network, persistent cache, or reusable native
handle. Structural source labels and sandbox mappings never enter recordings or public output.
Exact inferred literals may leave C0 only as backend-neutral prepared facts. Native error, cap,
timeout, cancellation, panic containment, or root mismatch destroys scope-owned state and exposes
no partial overlay. This is a bounded ownership and no-side-channel contract, not OS/RSS isolation;
the native memory-budget field is currently unenforced.

## 8. POC limitations

Capability-level separation does not prove OS permissions, process sandboxing, distributed writer fencing, cluster membership, linearizable publication, split-brain rejection, or coordinated cross-ledger retention. The authorized reasoning sandbox is a bounded POC security mechanism, not a production scalability claim. Production requires upstream policy-before-inference support or a separately validated scalable authorized-view architecture. This contract also does not implement a semantic writer, support counter service, ontology publication, remote imports, or traversal over general RDF assertions.
