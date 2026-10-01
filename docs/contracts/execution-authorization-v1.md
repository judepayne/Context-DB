# Execution authorization v1

`execution_authorization` is a separate application API; strict contexts, epoch checks and guarded entrypoints retain their meaning. Parent registers this public backend module. No migration, selective epoch or historical permission lookup is introduced.

`capture_execution(principal, data_snapshot, as_of, run_id, plan_hash, operation)` captures current policy, existence and permission pin under the mutation gate. The private original basis retains the full validated data pin separately. Only the backend can construct execution capabilities or release footprints; none is a serde DTO.

`original_resource_allowed` / `original_fact_allowed` evaluate only captured policy, principal roles, resource classes and existence. Later grants never broaden lazy original-false results. Every positive observation is accumulated, including rejected work. Requirements are capped at 4096 distinct facts and 1 MiB of resource/property text before cloning. Scope reads and graph/state-derived argument dependencies must pass these methods too. Caller-visible DTO evidence is not a replacement for these calls.

`release_footprint` snapshots this cumulative set (conservative for per-action releases). A foreign or outdated footprint fails closed. During a guarded action new positive dependencies cannot be added; afterward evaluation may continue and a new footprint must be taken. This prevents concurrent observation from escaping final validation. Operation is privately bound in the original basis.

`guarded_execution_release` recomputes current policy at actual head under the owned mutation gate. It checks all positive facts and operation, invokes a bounded local callback, checks again, and sends at most 1 MiB to a whole-buffer sink. Current revocation is `Denied`, not predicate false. Callback and sink cannot reenter the authority or perform network I/O. Callback allocation itself remains a trusted host obligation; output-size enforcement is not an RSS guarantee.

`guarded_execution_commit` binds candidate owner/run/plan/data/as_of to the basis, authorizes a prospective descriptor, or authorizes and returns the already stored original on idempotent owner/operation retry. The detached task owns gate and fence through durability, epoch publication, fresh postchecks and stored-original enqueue. Caller loss does not release these leases. Return value is the complete commit snapshot, never the original data snapshot. A sink failure does not roll back durability.

## Required service composition (parent-owned; not implemented here)

The `ExecutionFence` implementation must already own the service session read lease before backend entry; lock order is session then authority. Its checks must enforce cancellation, expiration/deadline and explicit invocation/disclosure grants. Its privately owned grant binding must include exact function manifest/version, destination/provider and full state/argument references; graph `view` permission and endpoint registration alone NEVER confer disclosure permission. Graph-backed manifest/provider/state resources and interpretation/completeness scopes additionally enter the original-positive footprint through the original decision methods. Do not create this fence from client JSON. Queue/backoff/retry must reenter the guarded boundary; remote latency occurs outside the authority gate. No network atomicity is claimed.

The component does not itself implement SessionLease, broker grants, service manifests, controller completeness or artifact/state-reference completeness verification. Consequently this component alone is not integrated authorization assurance.

## Native collection limits

Native mirror queries use deterministic 128-row pages at a fully validated pin and accumulate record/byte budgets before retaining another page. Policy capture decodes each page into the existence set without retaining every authority payload. Policy state itself is a bounded keyed journal record. Native query timeout remains per page. The pinned SDK's `FormatterConfig::with_max_bytes` is AgentJson truncation, not a SPARQL binding memory limit, so it is deliberately not used as a security bound. SDK sorting/query intermediates and an individual page are not bounded by a hard RSS assertion; decoded aggregate bytes, record count and footprint bytes are bounded. Service deadline checks fence waiting and eventual consumption; there is no backend timer that removes an expired waiter from the mutex queue.

## Validation handoff

Parent serial Cargo commands after module registration:

```
cargo test -p cdb-backend-fluree --test execution_authorization
cargo test -p cdb-backend-fluree --test p5_gate_c
cargo test -p cdb-backend-fluree gate_c_refresh_probe
cargo test -p cdb-backend-fluree
```

Conformance must cover barrier-paused execution across a peer run commit, unrelated head advancement/idempotent original receipts, unchanged-policy role revocation, lazy false before/after grant, foreign/omitted footprints, cancellation after callback, class/fact/scope changes, unrelated data admission, queued expiry, and retained-owner cancellation.
