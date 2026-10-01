# Context DB instance configuration v3

Status: supported configuration contract. Schema identifier: `ctxql-instance/v3`.

V3 replaces the legacy `[authority]` block with mandatory, disjoint `[semantic]` and `[control]` blocks. Each block contains `path`, `ledger`, `backend`, `authority`, and `graph`. Unknown fields are rejected.

The Semantic Ledger is pre-existing and read-only. Initialization, repair, bootstrap, transaction, and write controls are not valid semantic settings. The Control Ledger is the only writable authority for artifacts, runs, journals, receipts, and service policy.

Semantic and control paths must differ. Their complete backend/authority/ledger/graph identities must not alias. V3 never falls back to `[authority]`, and v1/v2 never infer semantic/control roles.

Published query/config artifacts must not contain the retired `native_interpretation` member or caller-selected semantic resources/claims. Field mapping definitions remain valid only in `fields`. Every semantic instance-v3 execution is admitted as recording v4; its nested recording-v3 body is portable execution data, not semantic authority. Recording v3 remains executable only for retained non-semantic compatibility.

The service route accepts v3 only after validating both role identities. Initialization opens
the pre-existing Semantic Ledger read-only and creates/initializes only the Control Ledger; it never
bootstraps or repairs semantic state. Startup captures the semantic head and operates in
`exact-probe-only` history mode unless independently trusted horizon evidence is configured. Each
historical query/replay still proves its requested numeric t and full CID, and unavailable history
fails as `semantic_history_unavailable`.
