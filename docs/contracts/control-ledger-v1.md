# Control Ledger — `ctxql-control-ledger/v1`

Status: current alpha contract. This contract defines CTXQL operational authority and replay storage. It is not a production durability, availability, deployment, or clustered-consensus claim.

## 1. Purpose and trust boundary

The Control Ledger is writable by CTXQL and authoritative for CTXQL operations: immutable artifacts, service policy, idempotency and journal state, protected runs/replays, authorization evidence, and migration metadata. It is never authoritative for domain claims, ontology, semantic configuration/imports, or governed semantic reference data.

The POC physical adapter is the existing strict local Fluree `NativeStore` envelope behind a role-specific `FlureeControlLedger`. Its owner binding, four-string physical mirror, corruption audit, journal, mutation gate, and recovery rules remain in force. Backend-neutral callers depend on artifact, policy, run, publication, and capture capabilities; they do not depend on Fluree flakes, SIDs, local paths, owner locks, or physical envelope fields.

A control snapshot identifies immutable reads. A later control commit does not change bytes read from that snapshot. Current control-policy authority is separately refreshed; a snapshot is not a permission token.

## 2. Record registry

Every record has a stable kind/key, canonical or exact-byte content identity as required by its existing codec, owner/authority binding, and admission journal evidence. Unknown record kinds fail closed.

| Record class | Ownership and mutability | Authorization | Idempotency domain | Minimum retention dependency |
|---|---|---|---|---|
| owner/schema binding | created at control-ledger initialization; immutable except an explicit versioned migration | administrative control authority | ledger identity plus schema version | life of ledger and retained backups |
| artifact version | publisher-owned; immutable `(IRI, version, hash, bytes)` | publish and protected read | artifact IRI + version | every retained run/replay or config reference |
| service policy, roles, scopes | whole-state/versioned append or existing governed replacement protocol; history retained as required | policy administration | policy operation key + normalized digest | all receipts/runs that cite its basis, subject to documented retention |
| operation journal and idempotency entry | append-only admission/recovery state | internal writer plus protected administrative inspection | authority + operation type + idempotency key | through retry window and every dependent receipt/run |
| authorization receipt | immutable evidence of a performed check | protected lookup; never grants permission | action/check identity | every retained run/replay that cites it |
| run envelope and query result | immutable after durable admission | owner/protected lookup and guarded publication | owner + operation hash/idempotency key | replay/retention policy plus all dependencies |
| replay attempt/result | append-only, linked to the source run | replay authorization and guarded publication | source run + replay operation key | while either source or result is retained |
| migration checkpoint | append-only state machine; no in-place history rewrite | migration administrator | migration ID + source/target roots + step | through rollback horizon and validation closure |
| tombstone/retention marker | append-only declaration; does not rewrite retained evidence | retention administrator | target + retention operation key | at least as long as needed to prevent accidental resurrection |

An admission receipt is separate from the admitted run envelope. A final publication receipt may refer to a semantic capture but never turns that capture into control state or advances semantic time.

## 3. Prohibited contents

The Control Ledger must reject or keep outside its publication APIs:

- domain claims, claim lifecycle truth, RDF edge annotations, ontology axioms, `schemaSource`, import maps, claim-graph configuration, and semantic reference data;
- bearer tokens, private keys, provider credentials, secret-manager values, or reusable credentials of any kind;
- source documents/payloads or provider request bodies whose exact bytes belong in governed source storage;
- redb projection tables/generations, ontology caches, prepared native handles, query queues, sessions, or memory caches;
- uncommitted/pending external effects; and
- semantic-ledger repair, bootstrap, ownership, or transaction records.

The ledger may store a content hash, protected locator, or dependency identity where a run contract requires it, but not material excluded above. Receipts are evidence, not credentials.

## 4. Independent identities and clocks

The following clocks and identities never imply ordering across one another:

1. **Semantic transaction identity:** full semantic ledger identity, numeric `t`, and full commit CID, optionally with requested `as_of` and history-horizon evidence.
2. **Control transaction identity:** control authority/ledger, native revision, and full immutable commit receipt/CID.
3. **Wall/expiry time:** trusted-host timestamps used for leases, expiry, or the existing control transaction allocator.

A control record referring to semantic data stores the complete semantic capture. It must not infer semantic identity from control revision, wall time, directory mtime, or publication order. A control commit can reference an earlier semantic capture but cannot advance, recreate, or substitute it.

## 5. Conditional append and idempotency

Every mutation is an atomic conditional append under the physical adapter's short mutation gate:

1. validate the current owner/schema and expected control head;
2. normalize and hash the complete operation input;
3. inspect the authority-scoped idempotency key;
4. append journal, logical records, physical mirrors, and receipt in the native transaction; and
5. publish the resulting exact control commit identity.

Expected-head mismatch is a conflict unless the operation's documented recovery path proves the same already-committed admission.

- Same authority, idempotency key, operation kind, and normalized digest returns the original durable result/receipt without repeating execution or side effects.
- The same key with a different digest is a conflict.
- A key from another authority or operation domain is not equivalent.
- Caller loss after native commit does not transfer ownership or authorize another payload. Recovery audits the committed journal and returns the original result.
- No receipt is fabricated before durable admission.

Mutation gates must not span semantic scans, ontology reasoning, traversal, or provider latency. Those operations prepare immutable inputs first; only final guarded publication enters the gate.

## 6. Crash and recovery states

Recovery is audit-first and fail-closed:

| Observed state | Required behavior |
|---|---|
| prepared operation, no native commit | no admitted record exists; retry may execute after revalidation |
| execution complete, run missing | do not claim publication; reconcile only from durable journal/effect evidence, otherwise require bounded operator resolution and do not repeat an uncertain effect |
| run committed, response/acknowledgement lost | protected same-key/same-digest lookup returns the committed run/receipt without re-execution |
| journal/receipt/logical mirror disagreement | readiness fails as corruption/repair-required; never choose a convenient copy |
| migration interrupted | resume or roll back only from validated checkpoints and matching roots; normal writes stay blocked where the migration protocol requires |
| redb checkpoint differs from the run's semantic capture | rebuild/select the derived generation; never rewrite the Control Ledger or treat redb as authority |
| required semantic capture/history unavailable | report bounded unavailable/divergent status; never substitute current semantics |

Reopen validates owner/schema binding, journal continuity, physical mirrors, receipts, and current control authority before serving writes. Existing committed-but-unacknowledged behavior remains applicable to the local adapter. This does not certify hardware power-loss behavior beyond the underlying tested storage assumptions.

## 7. Retention dependencies

Retention is dependency-aware. A retained run/replay requires:

- its exact artifact bytes and function manifests;
- run envelope, response and integrity evidence;
- referenced control-policy and authorization evidence needed by the recording contract;
- publication/admission receipts and sufficient journal/idempotency state for the supported retry window;
- required tombstones and migration lineage; and
- external retention of the exact semantic capture and claim/config/import history needed to reconstruct it.

Control retention cannot preserve semantic history by itself. Before deleting a dependency, the retention process must either delete every dependent record under an authorized, auditable policy or mark replay unavailable without presenting it as reproduced. Deleting an idempotency entry while its retry promise remains active is forbidden. Tombstones must outlive any restore/replication horizon in which removed records could otherwise reappear.

No fixed production retention period is specified by this POC.

## 8. Access control and disclosure

Writes require the specific operation permission and current control-policy checks. Run, replay, artifact, receipt, journal, and migration reads use protected lookup; possession of an ID or receipt is insufficient. Historical decisions cannot be broadened by a later grant, and current revocation can deny use or release.

Current semantic and control checks are independent. Both are repeated at required broker disclosure, result consumption, and final publication boundaries. Errors and diagnostics are bounded and redacted: they do not expose protected record bytes, hidden resources, secrets, native policy internals, or raw backend errors.

The Control Ledger stores authorization evidence describing checks performed at identified policy bases. Such evidence supports audit/replay comparison only. It is not a credential, capability, or authority to bypass a current check.

## 9. Local POC concurrency boundary

The physical POC uses one local owner lock, one process-owned adapter lifetime, serialized short mutation gates, expected-head checks, and corruption auditing. “Read-only semantic” and “writable control” describe API capabilities, not OS sandboxing or distributed membership.

Not implemented or claimed:

- clustered linearizability or consensus;
- durable distributed writer leases/fencing tokens;
- globally unique idempotency across independent writers;
- split-brain prevention/rejection;
- cross-region replication guarantees; or
- elimination of the distributed race after a final current-policy check.

A production replacement must establish these properties explicitly rather than treating the local file lock as evidence.

## 10. Backup, restore, and readiness

A usable backup set includes the complete control store, immutable owner/schema binding, exact backend locator/version metadata, and protected secret locators without copying secret values into the ledger. Backup tooling must not claim a consistent dual-ledger backup merely because semantic and control files were copied near the same wall time; retained recordings carry exact independent identities.

Restore is accepted only after physical audit, journal/receipt continuity checks, exact root comparison, owner/authority validation, and confirmation that required external semantic captures remain available. Restore to a different path must not silently change logical authority. A restored old copy must not become a second writer under the same authority without a production fencing protocol.

Readiness requires control open/audit success, supported schema, writer ownership, recoverable journal state, and ability to protect required lookups/publications. Overall service readiness additionally depends on semantic connectivity/history and derived projection status, but those are not Control Ledger facts.

These expectations define POC failure behavior; they are not backup, disaster-recovery, or availability certification.

## 11. Backend replacement and migration

A backend-neutral replacement must support:

1. bounded export of every registry class plus owner/schema and journal lineage;
2. validation against the source contract and exact content identities;
3. import into a non-serving target;
4. canonical per-class and whole-ledger root comparison;
5. protected read equivalence and idempotency/recovery tests;
6. an atomic or externally fenced locator switch;
7. a documented rollback horizon; and
8. old-backend read-only retention through that horizon.

Migration checkpoints identify source/target authorities, schema versions, exact roots, completed step, and switch state. Migration never rewrites semantic references or re-hashes exact artifact bytes under a new meaning. On mismatch, serving remains on the validated authority or stops; it does not merge divergent ledgers. The POC specifies the interface and validation obligations, not a production topology or migration tool.
