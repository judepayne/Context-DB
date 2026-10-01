# Complete POC configuration — ctxql-configuration/v1

Status: future P8/P9 contract, not a claim about today's field-by-field startup schema. Current instance schemas remain documented by the service and versioned instance contracts. Read with [architecture](../architecture.md), [future roadmap](../roadmap.md), [execution defaults](execution-defaults-v1.md), and [canonical projections](canonical-v1.md).

## Configuration classes

Use one instance startup file, conventionally `cdb.toml`, plus an exact reference to the default immutable semantic configuration artifact. TOML wires an instance; semantic CTXQL configurations remain versioned JSON artifacts. Credentials use explicit secret references and never create a second mutable policy authority.

**Instance settings** locate resources and impose operational ceilings. **Semantic settings** can change successful query answers and belong in immutable configuration/plan identity. Acquisition, structured preparation, and assembly settings retain their own provenance; they are not automatically part of every query-plan hash.

Components receive validated typed options from the composition root. They must not independently read ambient files/environment or invent competing defaults. Library users provide equivalent typed options without depending on TOML.

## Required startup groups

| Group | Required direction |
|---|---|
| Storage | Separate Fluree Semantic/Control identity and paths, redb projection, source/artifact storage. Opening existing authority validates identity and never resets it. |
| HTTP | Explicit bind and request/concurrency limits. Loopback is the alpha default; non-loopback needs documented transport/authentication protection. |
| Authentication | Explicit credential secret references and principal mapping. Roles and policies remain authoritative ledger data; startup cannot overwrite current permissions. |
| Execution | Deadlines, work, response/evidence bytes, Rhai operations, external-function calls. Ceilings are cumulative/cooperative, not hard RSS sandbox claims. |
| Projection | Catch-up deadline, reconciliation, historical-generation cache. Eviction touches only disposable generations, never authority/history. |
| Acquisition | Allowed roots, deterministic folder limits, transient windows, worker concurrency, provider/model/prompt/bundle identity. No provider fallback. |
| Evidence/PDF | Permitted roots, converter executable/hash/options and timeout. Configuration does not grant arbitrary document reads. |
| Structured sources | Physical source-ID-to-local-Iceberg-folder bindings, independently bounded from semantic source/mapping/selection identity. |
| Python assemblies | Python executable/environment identity and execution/input/output limits. Published assemblies are trusted code; subprocess limits are not a hostile-code sandbox. |
| Diagnostics | Redacted level/destination. No credentials, source bodies, or raw model responses by default. |

## Semantic groups

- Traversal defaults: `seed_limit`, `fanout_limit`, `max_claims`, and `path_limit`; current defaults are 2, 4, 16, and 8. `max_depth` remains query/profile supplied.
- Supported deterministic cycle policy and landing resolver identity/threshold where available.
- Field mappings, required reasoning capabilities, grounding registry, and immutable external-function manifests. Required unavailable capabilities fail; ordinary extension fields need no mapping.
- P7 structured preparation: enabled source IDs, import/live mode, mapping/provider versions, typed row keys, finite selection/parameters, configured confidence, and semantic preparation limits. Physical folders stay instance wiring.
- Any future calculation rounding requires a concrete versioned operator contract and hashed semantic settings. It is not a storage precision switch.

[`numeric-v1`](numeric-v1.md) remains fixed for authoritative numbers. Display formatting and assembly presentation do not alter individual query-plan hashes.

## Resolution and safety

- Merge defaults → selected profile → query only where semantic override is permitted. Nothing raises instance ceilings or permissions.
- Semantic caps may produce their specified notices. Operational exhaustion fails explicitly; never clamp to a smaller answer and call it complete.
- Replay uses the recorded semantic configuration/plan and current permission. Tighter present operational ceilings may block replay but cannot alter its semantics or create a false divergence verdict.
- Paths, secrets, logging, and timeouts stay out of query semantic hashes. Logical semantic selections and structured preparation declarations enter identity where specified.
- A locator cannot impersonate content: verify graph pins, source objects/snapshots, model/bundle/converter identities, and assembly environment at their boundaries.
- Record effective non-secret acquisition settings because they affect admitted claims; do not pretend they are query semantics.
- Unknown, duplicate, mistyped, out-of-range, incompatible, or unresolved-secret settings fail before enabled work. Error text identifies the setting without revealing secret values.
- Resolve relative paths against the configuration file. Avoid includes, broad environment overlays, and component-local environment reads. Explicitly supported authoring inputs cannot override recorded replay artifacts.
- No hot reload: instance changes require restart. Authoritative policy changes remain current and do not wait for restart.
- Diagnostics expose only a redacted effective summary, schema version, and selected artifact identities.

## P8/P9 acceptance

P8 supplies one versioned shared TOML loader, typed library equivalent, default immutable semantic reference, explicit secret resolution, Python options, and minimal reference documentation. P9 verifies clean setup/restart, malformed/unknown settings, missing secrets, semantic-config changes versus historical replay, tighter operational ceilings, current-policy behavior, and library/CLI/HTTP parity.

Current-permission enforcement, independent immutable claims, atomic admission/idempotency, closed-past time, exact snapshot validation, canonical/hash versions, numeric fidelity, evidence validation, and no silent provider fallback are invariants—not switches.
