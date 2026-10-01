# Future roadmap: P7–P9

Everything in this document is **future scope**. It is not a claim of current implementation or support. Current behavior is documented in [architecture](architecture.md), [service](service.md), and implemented contracts.

## Cross-cutting contracts

P7–P9 must preserve the accepted future contracts:

- [`structured-preparation-v1`](contracts/structured-preparation-v1.md): finite preparation into one immutable local overlay before landing; ordered configured source identities; exact source/mapping/provider/snapshot identities; typed row keys and values; stable claim identity; no partial successful overlays; explicit live temporal and replay classification.
- [`assembly-inputs-v1`](contracts/assembly-inputs-v1.md): ordered, named, independently identified query-result inputs; current authorization over every input/source; deterministic products retaining notices, lineage, citations, and replay status; no forged concatenated query result.
- [`configuration-v1`](contracts/configuration-v1.md): one validated startup configuration plus immutable semantic artifacts; typed library equivalent; strict unknown/duplicate/secret handling; semantic settings recorded separately from operational ceilings; no hot reload or policy freezing.

These documents are design contracts for future work. Their existence does not expose a runtime connector, Python assembly runner, or complete final configuration surface today.

## P7 — Iceberg imports and live data

### Deliverables

- Neutral structured-source request/result/capability interfaces and a local-folder Iceberg adapter.
- Versioned Turtle mappings, typed row-to-claim conversion, row lineage, and import idempotency.
- Persisted imports through the ordinary authoritative claim-admission boundary.
- Config-declared bounded preparation and a query-local immutable overlay; never per-hop unbounded remote scans.
- Validation of source capabilities/results/policy, resource and cancellation limits, and explicit snapshot-support failures.
- Replayability classification for live-dependent runs; no automatic persistence of all live results.
- Strict separation of physical folder bindings from logical source IDs, mappings, provider versions, modes, row keys, selections, confidence, and preparation limits. Instance ceilings are independently enforced; exhaustion cannot return a successful partial overlay.

### Accepted local Iceberg constraints

The selected POC direction is local Iceberg v2 metadata, manifest lists, manifests, and Parquet—not S3, REST catalogs, containers, or general Iceberg certification. Exact identity must bind table UUID, snapshot/schema IDs, metadata hash, mapping/provider versions, and the ordered reachable object paths, hashes, and sizes. Paths must remain canonical relative paths below the configured root; reject symlinks, traversal, duplicates, missing/corrupt objects, and unsupported exact pins before execution.

The feasibility work established only a tiny unpartitioned two-snapshot shape. P7 must not infer broader guarantees from it:

- preserve typed integers/decimals/nulls before CTXQL operations; do not accept string-valued numeric behavior;
- reject unsupported bound patterns, variable-predicate/type binding shapes, mapping languages, SQL queries, or source-time behavior explicitly;
- require unique declared parent keys until complete multiplicity semantics exist;
- query `LIMIT` is not a scan or memory bound; preflight and charge files, bytes, rows, columns, generated claims, and deadlines;
- whole-object/batch materialization needs explicit resource and cancellation control;
- no automatic result archival makes an unpinned live run exactly replayable.

Default request ceilings remain: four sources, 1,000 rows, 10,000 generated claims, 64 columns per row, 64 KiB encoded row, 16 MiB decoded/logical payload, 64 MiB file bytes, 256 referenced files, and a 30-second cooperative deadline. Unsupported capability, cancellation, or any bound failure aborts preparation without a partial overlay.

### Exit evidence

- Tiny real Iceberg table → mapping → claims → Fluree → redb; repeated import is idempotent.
- A new source version creates new graph history while preserving source lineage.
- Live queries join configured local identity mappings without implicitly admitting their observations.
- Numeric, null, bound-pattern, and parent-key cases are correct or explicitly unsupported.
- Source work—not merely returned rows—is bounded; credentials and raw source results stay out of logs.
- Imported and transient claims obey current policy.
- Native graph replay remains exact; unpinned live execution defaults to `not_replayable`, with a fresh rerun represented separately.

## P8 — assemblies and complete delivery surfaces

### Deliverables

- A small Python base package and bounded Rust runner implementing the published trusted-assembly contract and dependency identity.
- Separate one- or multi-input assembly invocation with explicit order/names, Python entrypoint, and replay provenance.
- Authorized source helper bridge and deterministic Context Product hashing with required-section/capability validation across all inputs.
- A reference formatting assembly preserving notices and lineage, with no graph traversal or LLM calls.
- Complete library, CLI, and HTTP surfaces for ingestion/jobs, query, publication, replay, projection health, and assembly output.
- One versioned startup schema/loader shared by all delivery entrypoints: default immutable semantic configuration, explicit secret references, redacted effective diagnostics, and restart-only instance changes. Library callers provide equivalent typed options.
- Python executable/environment identity and execution/input/output limits. Published assemblies remain trusted code; subprocess limits are not a hostile-code sandbox.
- Current configuration/reference documentation, authentication setup, isolated agent guidance, dependency prerequisites, and minimal examples.

### Exit evidence

- One- and multi-query assemblies produce repeatable hashes over retained source versions while preserving ordered input identity, lineage, notices, and authorization.
- Presentation changes do not alter query plan hashes.
- Missing/changed source material yields the documented evidence/product outcome, never false exactness.
- Assemblies cannot bypass source authorization or access graph traversal/write APIs.
- Library, CLI, and HTTP return equivalent semantics under the same read policy.
- Operational routes and ingestion use the chosen deployment/authentication boundary without inventing out-of-scope write ACLs.
- Unknown, duplicate, invalid, or unresolved-secret configuration fails before work with redacted errors. Paths resolve relative to the configuration file; restart cannot restore revoked policy assignments.

## P9 — integrated acceptance and handover

### Required work

- Complete every required conformance row; do not silently relabel missing language support as acceptable.
- Select the business demonstration with the user. Synthetic connected fixtures may precede it but cannot choose the domain.
- Exercise documented clean setup and restart in an isolated directory.
- Measure acquisition throughput, source work, projection catch-up, query latency, historical-generation cost, and disk/RAM growth as baselines—not unagreed promises.
- Run fault-injection, authorization, and replay suites across initial adapters.
- Verify startup/restart and library/CLI/HTTP parity. A new default semantic config must not rewrite old runs; current permissions remain current; tighter operational ceilings fail explicitly rather than altering results or claiming divergence.
- Publish current limitations and supported connector/query shapes.

### Final acceptance flow

```text
ingest text/Markdown/PDF folder + import Iceberg
  → independent grounded claims in Fluree
  → checkpointed redb projection
  → full CTXQL query through CLI/HTTP with read policy
  → claims/paths/evidence + optional Context Product
  → restart and reproduce pinned graph execution
  → revoke permission and deny unsafe replay
  → live Iceberg query with explicit non-exact replay classification
```

## Validation discipline

Pure tests require no agents, network, model downloads, or commercial credentials. Storage tests use disposable isolated ledgers and deterministic fault hooks. Iceberg and real-agent integration is opt-in, bounded, and documents dependencies/costs. Expected semantics come from CTXQL contracts, not hmem parity. Preserve attribution and license notices. Never destructively operate on source projects or user data.
