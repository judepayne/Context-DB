# Durable redb projection v1

Derived storage only. Fluree remains authority; corruption or missing projection data never authorizes reconstructing/resetting the ledger. Raw views are trusted-local and unprivileged, not authorized query endpoints.

## Kernel and generations

`Database` uses one record per independent claim/lifecycle/resource/artifact, collision-free composite outgoing/incoming/both/lifecycle indexes, and a versioned kernel table. Self-loops deduplicate only within the both-direction index; equal triples with distinct IDs remain separate. Lifecycle assertions appear through all ordinary claim/incident and support lookups. No ranking, decay, aggregation, active-only filtering or authorization is stored.

One explicitly Immediate redb transaction updates records, indexes, counters, exact checkpoint and accepted batch digest. Staged typed references, previous hashes, immutable identity and predecessor/schema/authority/algorithm are validated before commit. An identical last accepted retry is idempotent; conflicting retries/gaps fail. Ordinary apply touches only relevant indexed records, not a full projection scan. Errors propagate instead of becoming absence.

`RedbProjection::create/open(path, binding, options)` exclusively owns a separately created derived directory. A durable catalog identifies one live database and bounded immutable historical databases. The live checkpoint is read inside the data database, never from a separately updated stale pointer. Views own exact read transactions plus generation/directory leases; held old views survive later writes, rebuilds and worker shutdown.

Initial `build` stages and validates a complete database, syncs the directory, then atomically publishes its catalog pointer. Subsequent `build` materializes exact history without moving live. `rebuild_live` stages a replacement before changing the active pointer. Cached-ahead apply compares a bounded staged authoritative image with the cached target before mutating live; cache presence alone is not proof. This exceptional comparison may scan complete bounded images.

The durable slot reservation precedes staging creation. Reopen cleans only recognized unreferenced reserved slots; unrelated files and symlinks are never adopted/deleted. Unknown catalog bootstrap fails explicitly. Eviction refuses active or held generations; retry after releasing readers. Default capacity is eight published generations plus one staging slot. It is explicit capacity refusal/controlled eviction, not a hidden unbounded history cache.

## Coordinator and preparation

`Coordinator::start(Arc<B: GraphBackend>, store, binding, options)` subscribes before initial reconciliation. Each pass rereads authoritative head and durable checkpoint, fixes a target, and completely validates paged exports or linear changes through that target. First continuation establishes the adapter's stream identity (which may vary with range); PageTracker then binds every continuation and explicit completion. Optional stream labels in options apply only to terminal-only pages, not a guessed native cursor protocol.

Hints wake reconciliation; no notification counter is persisted as truth. Lag triggers reconciliation, closure triggers bounded resubscription/degraded status, failures retry with backoff even without later writes, and an independent timer repairs missed notifications. Exact wait/history requests have bounded admission and a single historical worker. Ready/view release occurs only after durable completion. An old exact target is opened from cache or reconstructed from authoritative exact export, never mislabeled latest. Graceful shutdown joins ongoing native work and preserves already-held views.

`RedbViewProvider::new(coordinator, store, wait_timeout)` integrates the unchanged exact engine API. It waits for the captured full pin, then offloads catalog preparation from one held read transaction. The catalog scans records/origins with bounds, validates the latest image, applies the fixed cutoff, and supplies the entity/label plus minimal origin dependencies for current authorization. Missing/corrupt provenance is an error, not a backdated label.

Explicit `execute_with_consistency(..., Consistency::AllowStale, ...)` may request the provider's current checkpoint as a proposal. The engine independently validates exact existence and retained ancestry; a foreign/ahead proposal is rejected, never silently substituted. No stale fallback follows authorization, artifact, corruption or evaluation errors. Actual data/artifacts come from the chosen pin, with current policy afterward and same-gate publication. Requested/actual identities and stale choice are transported even without explain; actual stale adds semantic warning/notice/flag. Default execute bytes/hashes are unchanged. This is not replay recording.

## Operational bounds and limitations

Kernel defaults: 100,000 live records, 128 MiB encoded live records, 10,000 changes/16 MiB encoded changes per apply, 1,000 records/16 MiB per page, plus codec limits. Aggregate generation payload is bounded by capacity plus staging times per-database ceilings; file pages/indexes and held read transactions have additional native overhead. Catalog preparation cumulatively charges two scans against execution work/byte budgets. Logical ceilings are not hard RSS/disk/sandbox guarantees.

Manager I/O runs on spawn_blocking under one serialization gate. RawQueryView reads remain synchronous trusted-local work. Caller deadlines bound waiting; already-dispatched native mutations can finish after caller cancellation. Coordinator drains those operations before graceful join, so a timeout never proves no durable write occurred. Always recover from the stored checkpoint. Last-owner destruction can perform synchronous native cleanup.

Recovery procedure: reopen authority, open the known derived directory with its binding, start reconciliation. To repair recognized derived state, stage a complete exact authoritative export and publish through rebuild_live; if a corrupt file cannot be opened, create a new separately owned derived directory and rebuild there, retaining the corrupt directory for diagnosis. Never clear/delete authority or arbitrary paths. Process kills before/after apply and rebuild publication test software recovery, not universal power-loss/fsync certification.
