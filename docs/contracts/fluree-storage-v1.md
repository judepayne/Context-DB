# Embedded Fluree storage v1

Scope: one exclusively owned local file-backed ledger/branch with serialized managed writes. No multiwriter, reset/branch merge, arbitrary external RDF mutation, remote service or production authentication guarantee. CTXQL claim/canonical/static-policy contracts remain semantic authority.

## Ownership and API

`AuthorityOptions::new(path, ledger, backend, authority, graph)` configures stable logical identity and a trusted wall clock. Ledger names include an explicit branch (`example:main`). `FlureeBackend::create` requires a nonexistent directory; `open` requires an existing recognized managed ledger. Owner identity is persisted, not derived from the directory. Unknown/interrupted bootstrap without complete authority metadata fails repair-required; never reconstruct authority from redb. Lifetime fs2 ownership extends through held snapshots/tasks. An owned async runtime dispatches work with async replies, not blocking reactor channels.

`GraphBackend` implements atomic admission/receipts, persisted cutoff capture, exact snapshots, complete export, ordered changes and hints. Native kernel handles are private. `ArtifactRepository` publication/lookup use exact owner admissions; run/assembly operations return Unsupported, not fake replay success.

## Physical records and immutable identity

Every managed row has kind, key, hash and a lossless UTF-8 payload under a collision-free reserved physical IRI. Logical records use `ctxql-storage/v1` core record/change codecs; canonical typed values never cross a floating JSON conversion. Artifact bytes are encoded losslessly and checked against their immutable reference hash. Physical mirrors must match the bounded decoded payload. The storage codec is not a new CTXQL canonical domain.

Managed kinds are `record`, `control`, `journal`, `receipt`. Owner control contains schema, backend/authority/graph/ledger, native t and optional canonical last/closed timestamps. Journals contain native t, exact predecessor t/CID, operation, assigned time, original normalized admission payload/digest/key, claim IDs and complete encoded changes. Receipts duplicate their admission journal. Strings encode control numbers; absent timestamps are empty strings, not epoch zero. Native bootstrap is t=1; managed init is t=2. Every later admission/capture/policy commit has a journal, including empty semantic changes.

Data, clock, receipt, journal and system origins share one native transaction. Its detached native task retains the already-held authority gate through commit completion and epoch publication even when the caller is canceled; cancellation never opens a gap around final policy publication. Result CID is derived/validated after publication or recovery, not embedded self-referentially or added in a second completion commit. Idempotent normalized retries return the original receipt; changed payloads conflict. Claims, lifecycle events and published artifact versions never mutate. Resource replacement/retraction checks the exact previous logical content hash.

## Time, provenance and permissions

Allocation is checked `max(wall, last+1, closed+1)` over full core UTC timestamps, including pre-epoch time. Capture closes a nonfuture requested cutoff durably even when idle. Source dates cannot allocate authority time. The historical audit checks monotonic last/closed transitions but cannot independently prove a historical host wall-clock observation.

`ctxql-record-origin/v1` immutable SourceDescriptors bind each logical image/key to native sequence, assigned time, image hash and put/remove operation. IDs and predicate are under `https://ctxql.example/storage/v1/`. Ordinary admission cannot supply reserved IDs or administrative receipt keys. Full exports and changes carry the same origins. Consumers choose the latest sequence, then verify its current image; A→B→A never reuses the first A's date. Logical resource hashes are not altered to hold assigned timestamps.

The trusted `PolicyState` API persists static-v1 policy, enabled principal roles and direct resource classes as one reserved ordinary Policy record, using normal journal/origin admission. Whole-state replacement is not a merge API. Private issuer-bound principals must be reissued by the trusted host after reopen. Current policy is rebuilt from current Fluree, never historical redb. Context binds the full authority head; every write invalidates it. Final publication checks current principal/state/head while holding the same gate as admission, capture and policy writes. Sink callbacks must be bounded and non-reentrant. JSON credentials/service authentication/replay remain P4.

## Exact history and failure behavior

Full SnapshotRef validation includes backend, authority, graph, native t and full CID. Read-back validates `commit_t(t)` identity, then uses exact `AtT(t)` including committed novelty; never latest or indexed t fallback. Keyed artifact/resource reads do not rebuild the complete logical graph.

Audits compare complete managed physical images against journal changes, rederive payloads/origins, validate lifecycle references and clock transitions, and detect missing/extra mirrors/rows, unmanaged triples, gaps and unexpected predecessors. An owner-local exact-CID verified checkpoint avoids replay on repeated current reads; new commits are audited under the write gate. Reopen independently audits from genesis. Explicit history and bus validation may perform bounded full ancestry audits. Cursors bind full target, stream/range and progress; empty ranges still validate both endpoints. Invalid/corrupt history never becomes an empty successful export.

The real Fluree LedgerEventBus is nondurable. Its matching ledger commit notifications are filtered and validated before becoming neutral Head hints; lag/close remain explicit, unrelated ledger/index events are ignored. Messages are wakeups, not authoritative changes.

## Limits and recovery

Defaults: 4 MiB prepared transaction, 64 KiB query text, 16 MiB formatted native result, 10,000 native rows, 30-second cooperative native query timeout; 1,000 logical changes/admission and 100,000 history commits, plus core codec Limits. Cumulative audit work can hit native bounds well before the history-count ceiling. Prospective cumulative audit rows/change bytes and exact formatted image bytes are checked before each authority mutation (including bootstrap/capture/policy), so accepted writes remain auditable under unchanged options. This preflight is bounded O(current image size), not O(1); lowering limits on reopen can still fail explicitly. Unsupported/oversized/corrupt input fails explicitly. Native formatting allocates before post-query byte validation; these are logical bounds, not hard RSS/cancellation guarantees. New-commit audit still checks a bounded full image; explicit history/export pages can rematerialize bounded state. No throughput/scale certification.

Recovery: reopen with the original binding, recover receipts and current authority state, then reconcile/rebuild recognized derived storage. Never reset authority. Process-kill tests exercise loss of acknowledgement and committed state recovery; they do not certify hardware power loss or distributed storage.
