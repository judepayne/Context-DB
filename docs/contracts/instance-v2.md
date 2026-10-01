# Context DB instance configuration v2

Status: supported compatibility startup contract. Schema identifier: `ctxql-instance/v2`.

## Compatibility and loading

`cdb serve --config /absolute/instance.toml` loads this closed TOML schema once. Unknown fields, unknown schemas, fractional integers, overflows, invalid references, unavailable adapters, and unenforceable controls fail startup. Reload requires restart.

`ctxql-instance/v1` remains accepted with its existing defaults, 300-second request/session ceilings, and no `broker` table. A v1 file containing broker settings is invalid. In v2 the broker defaults to disabled when `[broker]` is absent or has `enabled = false`; a disabled broker cannot carry dormant groups, manifests, or providers.

All existing authority, projection, credential, source, bind, role, default-config, and service-limit rules remain. Paths are resolved relative to the absolute instance file after lexical normalization. Credential and manifest files use the existing bounded, regular-file, private-mode, single-link, no-symlink/ancestor-swap checks. Configuration and manifests are capped before parsing.

## Lifetimes

V2 retains `deadline_seconds = 30` and `session_ttl_seconds = 300` defaults. Either may be explicitly set from 1 through 86,400 seconds. V1 remains capped at 300. `AuthStore` has the same 86,400-second absolute ceiling; the instance schema supplies the lower version-specific ceiling.

A session receives one monotonic deadline at authentication. It is not renewed. Every lease/final fence checks that deadline and the credential's wall-clock `expires_at`; whichever expires first wins. Longer v2 values do not renew credentials, weaken live revocation, create durable background jobs, or extend a broker call beyond the remaining request/session lifetime. The latter clipping remains a parent Service/controller integration requirement because invocation currently supplies only the broker call timeout.

## Broker tables

All omitted scalar values below use these defaults when the broker is enabled:

| Field | Default | Hard rule |
|---|---:|---|
| `rhai_workers` | 32 | 1..=1024 |
| `local_workers` | 2 | 1..=1024 |
| `per_request_pending` | 64 | 1..=1,000,000 |
| `global_pending_bytes` | 64 MiB | 1..=1 GiB |
| `per_request_pending_bytes` | 64 MiB | 1..=1 GiB and no greater than global |
| `max_logical_calls` | 250,000 | 1..=100,000,000 |
| `max_argument_bytes` | 256 KiB | 1..=16 MiB |
| `max_result_bytes` | 1 MiB | 1..=16 MiB |
| `max_state_bytes` | 64 KiB | 1..=16 MiB |
| `call_timeout_ms` | 30,000 | 1..=86,400,000; shared by all attempts |
| `max_attempts` | 2 | 1..=8 |

Pending count includes queued, running, and completed-but-unreduced logical calls. Argument plus reserved result bytes are charged before an effect. There is no zero-as-unlimited convention, spill, pruning, or implicit grant.

`[broker.script]` defaults to `max_operations = 10000000`, `max_recursion = 64`, `max_ast_bytes = 1048576`, and `max_container_items = 100000`. Values must be positive and within the implementation maxima (1 billion operations, 1024 recursion, 16 MiB AST, 10 million container items). These settings are delivered in `ExecutorSettings`; selected INT/Decimal semantics are not configurable.

### Simultaneous resources

`[broker.global]`, each `[broker.groups.<id>]`, and each provider's `resources` use:

- `max_in_flight`
- `max_queued_bytes`
- `requests_per_second`
- `burst_requests`

All resolve to finite positive values. Group/provider omissions inherit tuning values, but dispatch independently acquires global, group, and provider gates; inheritance never removes a stricter parent gate. Providers naming the same group share the same gate, so aliases cannot multiply that resource's permits/rate/queue bytes. Provider/group references and IDs are validated.

The closed schema reserves `tokens_per_second`, `burst_tokens`, and `token_accounting`. Current `Invocation`/`Adapter` APIs expose no trustworthy pre-dispatch token quantity or reconciliation capability. Any of these fields therefore fails with `unsupported startup control: token rates require dispatch token accounting capability`; they are not silently ignored or approximated by request counts.

## Exact manifests

Each `[broker.manifests.<alias>]` contains exactly `iri`, `version`, `hash`, and `file`. Startup reads the protected file bytes, constructs the declared `ArtifactRef`, and passes the original bytes to `PublishedArtifact` and `ExternalFunctionManifest`. Hash verification is over those exact published bytes. Parsed or reserialized JSON is never used as the published hash input.

Every provider has a nonempty, duplicate-free `allowed_manifests` list of aliases. The registry resolves each alias to its exact `(IRI, version, hash)` tuple and requires the selected adapter to support the manifest's exact implementation/version/build identity. Registration is only an operational binding. It grants neither function invocation nor disclosure permission, and query data cannot choose a URL, model, executable, library, weights, or alternate manifest.

## Providers and execution classes

Every `[broker.providers.<id>]` requires `class`, `adapter`, `destination`, `group`, `allowed_manifests`, `implementation`, `implementation_version`, and `implementation_build`.

- `http_service` requires the exact built-in adapter ID `ctxql-http-json/v1` and an `endpoint`. HTTPS uses certificate validation. Plain HTTP requires `allow_loopback_plaintext = true` and a loopback host. Userinfo, query, fragment, redirects, and environment proxies are rejected/disabled. Optional `credential_file` is a protected config-relative file consumed into a non-Debug secret value. Native capacity fields are invalid.
- `cpu_blocking` requires a trusted parent-registered adapter. `workers` and `internal_threads` must exactly match its declared fixed `NativeCapacity`; HTTP/device fields are rejected. There is no dynamic library or executable loading.
- `accelerator` likewise requires exact registered capacity including optional `device_memory_bytes` and `max_batch`. This implementation accepts only adapters explicitly labelled `test_only`; an uncompiled/unavailable real accelerator fails startup rather than being simulated or claimed.

A native adapter missing from `AdapterCatalog`, a class mismatch, or capacity values the registered implementation cannot enforce produces a specific unsupported/invalid startup error. Paid requests and real-provider smoke calls never occur during startup or default tests.

## Construction hook and secret boundary

The parent Service construction hook is:

```rust
let bundle = instance.startup_bundle(&trusted_adapter_catalog)?;
```

`StartupBundle` owns:

- `auth`: the real `AuthStore` built with the v1/v2-validated TTL;
- `broker`: the validated `Broker`, exact `Registry`, and simultaneous gates;
- `executor`: worker, pending/state, and script settings for native predicate/controller construction;
- `providers`: non-secret IDs, classes, groups, adapter IDs/builds, and test labels.

`SecretString`, bearer bytes, and credential contents implement no Debug/Display/serialization and are absent from resolved settings. Public/canonical diagnostics must not expose credential paths or values, endpoint credentials, source paths, or secret-bearing request headers.

## Remaining Service integration

The bundle is intentionally not wired into `Service` by this bounded change. The parent composition must: retain it for Service lifetime; construct Rhai/local pools from `ExecutorSettings`; enforce global pending evaluation/effect bytes and state/script limits in the controller; clip attempt deadlines to request and session remainder; connect the real guarded current-permission authorizer; require exact function/destination and argument/state dependency grants for every attempt and result; and drain broker/native owners in shutdown order. Until those hooks exist, no authenticated broker acceptance, long-query support, paid request, or production accelerator capability may be claimed.
