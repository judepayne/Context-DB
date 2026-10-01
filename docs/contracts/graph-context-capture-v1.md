# Graph context capture contract v1

Status: current implementation contract for `graph_capture.rs`, `graph_context.rs`, `ingest.rs`, `sources.rs`, `acquisition_work.rs`, and `acquisition_inspection.rs`. It defines implemented integrity, offline reconstruction, and authorization boundaries.

## Version dispatch

Graph-enabled capture adds versions; it does not reinterpret old captures:

| Object | Schema |
|---|---|
| Provider + graph wrapper | `ctxql-provider-graph-capture-manifest/v1` (graph-only), `/v2` (initial gazetteer) |
| Graph export | `ctxql-provider-graph-capture/v2` (graph-only), `/v3` (initial gazetteer) |
| Transcript leaf | `ctxql-graph-transcript-leaf/v1` |
| Capture index | `ctxql-graph-capture-index/v1` (graph-only), `/v2` (initial gazetteer) |
| Graph authority context | `ctxql-graph-context/v1` (graph-only), `/v2` (initial gazetteer) |
| Final private workspace state | `ctxql-graph-workspace-state/v1` |
| Aggregate passage capture | `ctxql-passage-graph-capture/v1` |
| Aggregate graph passage leaf | `ctxql-passage-graph-capture-leaf/v1` |
| Frozen graph acquisition work | `ctxql-acquisition-graph-work/v1` |
| Source-plus-graph artifact descriptor | `ctxql-acquisition-artifact-descriptor/v3` |

`CaptureManifest` dispatches the closed graph wrapper separately from existing single-passage and multipassage manifests. Graph capture requires one issued passage. Existing graph-disabled single/multipassage manifests and stored-v3 passage capture continue under their existing semantics. Historical captures do not receive fabricated empty graph transcripts.

The wrapper is a closed object:

```json
{
  "schema": "ctxql-provider-graph-capture-manifest/v1",
  "provider": { "...": "existing ProviderCaptureManifest" },
  "graph": { "...": "GraphCaptureExport" }
}
```

The graph capability embedded in the provider request must exactly equal `graph.capability`; graph context source version/range root must bind to the provider capture. Unknown fields or mismatched versions/roots fail verification.

## `GraphCaptureExport`

`ctxql-provider-graph-capture/v2` is a closed Rust/Serde object with:

| Field | Meaning |
|---|---|
| `schema` | Exactly `ctxql-provider-graph-capture/v2`. |
| `capability` | Exact model-visible `ctxql-graph-query-capability/v1` summary included in the provider request. |
| `workspace` | Canonical final `ctxql-graph-workspace-state/v1`. |
| `context` | Canonical `ctxql-graph-context/v1`. |
| `transcript_leaves` | Ordered canonical transcript leaf values. |
| `graph_payloads` | Map from content hash string to complete canonical `IssuedGraph` value. |
| `index` | Canonical `ctxql-graph-capture-index/v1`. |

The capability summary currently binds `query_language: "ctxql-inline/v1"`, read-only behavior, configured node/claim/live-graph/tool-call/query/timeout limits, `complete_results_only: true`, required skill names, host query config/profile references, renderer `ctxql-graph-renderer/v1`, and tools `ctxql-graph-tools/v1`.

## Graph context manifest

`ctxql-graph-context/v1` is closed and canonical:

```json
{
  "schema": "ctxql-graph-context/v1",
  "issuer": "...",
  "session_id": "...",
  "attempt_id": "...",
  "source_version": "...",
  "source_range_root": "...",
  "semantic_snapshot": "...",
  "disclosed_claim_ids": ["..."],
  "graphs": [
    {"graph_handle":"g1~<session>","claim_ids":["..."]}
  ]
}
```

Graph handles are unique. Claim IDs and identifiers are non-empty, control-character-free, at most 2 KiB, and dependencies parse as resource IDs. Arrays are canonical set projections. `disclosed_claim_ids` must equal the union of every graph's `claim_ids` exactly.

Context v2 adds exactly one `initial_context` entry: `{kind: "entity_gazetteer", commitment, claim_ids, snapshot}`. `snapshot` is the retained JSON text of `ctxql-retained-gazetteer/v1`, containing `entities`, eligible `approved` identities, an opaque `approval_root` binding the configured approval set, `class_supports`, `commitment`, and `dependencies`. Hidden or ineligible configured identities are not disclosed in the retained snapshot. The context root binds this snapshot; its commitment/dependencies must match the entry and provider request. Initial dependencies join the graph/leaf dependency union without fabricating a query or tool response. Gazetteer facts lacking exact authorized claim supports cannot use this protected path.

The context is append-only disclosure history: releasing a live graph does not remove its graph entry or dependencies. Default verification limits are 12 retained graph disclosures, 300 distinct dependencies, and 2 MiB canonical context bytes. During a configured live capture, the dependency ceiling is `max_claims * max_live_graphs` (300 at the maximum configuration).

## Transcript leaf

Every actual dispatched graph tool request and actual model-visible response is captured as a closed `ctxql-graph-transcript-leaf/v1` object:

```json
{
  "schema": "ctxql-graph-transcript-leaf/v1",
  "ordinal": 0,
  "previous_leaf_root": null,
  "capability": "graph_query",
  "request": "{...exact JSON text...}",
  "request_root": "sha256:...",
  "response": "{...exact JSON text...}",
  "response_root": "sha256:...",
  "revision_before": 0,
  "revision_after": 0,
  "result_kind": "graph",
  "issued_handles": ["g1~<session>"],
  "graph_payload_root": "sha256:...",
  "claim_dependencies": ["..."]
}
```

Allowed capabilities are `graph_query` and `graph_playground`. Allowed result kinds are `graph`, `diagnostic`, `view`, `mutation`, `check`, and `error`.

Requests and responses must be UTF-8. Their hashes are recomputed. Ordinals begin at zero; `previous_leaf_root` and before/after revisions must be contiguous. Issued handles must be unique, session-bound, and newly issued in that leaf.

A `graph` leaf must contain a graph payload root and a graph handle. A diagnostic/error must contain neither and cannot change the revision. Query leaves never change the draft revision. Successful `import`, `release_graph`, and `apply` may advance by at most one; other playground operations do not. Successful apply response revision must equal `revision_after`.

The recorder persists the canonical leaf to the immutable source-object sink **before** returning its exact response bytes to Pi. Capture failure cancels the session; a final proposal cannot be accepted after undisclosed/unretained graph context.

Default capture limits are 40 leaves, 32 KiB request, 64 KiB response, 1 MiB cumulative canonical leaf plus retained payload bytes, and 300 dependencies. The enabled configuration may lower the call/request/response/aggregate/dependency bounds. Live request/response accounting is additionally clamped to `reserved-tool-result-bytes`, so model-visible tool context cannot outgrow the whole-document preflight reservation. Retained internal payloads remain independently charged to the capture ceiling.

## Complete query payloads, including released graphs

A successful query response can show only its compact overview, so its transcript leaf additionally commits `graph_payload_root`. `graph_payloads[root]` contains the complete canonical `IssuedGraph` needed to rebuild the pending/imported state. The root, response handle, snapshot, node count, claim count, completeness flag, and payload dependencies are verified together.

The payload is persisted and charged to the cumulative capture budget before the response is disclosed. `release_graph` removes the graph from live workspace state and frees a live slot, but it does **not** remove the already retained payload from `GraphCaptureExport`, erase its transcript leaf, reduce capture bytes, or remove its claims from `GraphContextManifest`. Export verification requires the payload map to contain exactly the roots referenced by transcript leaves—no missing or unreferenced payloads.

Oversized/incomplete/denied queries retain the exact bounded diagnostic/error response but have no graph payload root or invented graph state.

## Capture index

`ctxql-graph-capture-index/v1` is closed and contains:

- `stable_session_seed`;
- `capability_summary_root`;
- `semantic_snapshot`;
- `source_version` and `source_range_root`;
- ordered `leaf_roots` and their `transcript_root`;
- `final_workspace_root`;
- `graph_context_root`;
- `final_revision`;
- `claim_dependencies`.

The transcript root is the hash of the canonical ordered leaf-root array. Finalization requires the stable seed to equal the session ID and copies the complete context dependency set. Verification recomputes every commitment and requires the union of initial-context and leaf dependencies to equal the index/context dependencies.

## Final workspace state and offline mutation reconstruction

`ctxql-graph-workspace-state/v1` is the private final state projection with exactly:

- `schema`, `issuer`, `session_id`, `revision`;
- complete `limits`;
- `graphs` registry, including pending/attached status and issued payloads still live;
- `records` registry;
- retained `idempotency` requests/results;
- `counters`;
- `next` graph/node/claim/reference/hypothesis/question/operation IDs.

Offline verification starts a fresh pure `Workspace` from the recorded issuer/session/limits and replays leaves in order:

1. successful graph-query leaves load the verified payload by root and register it;
2. successful `import`, `release_graph`, and `apply` execute against the pure workspace;
3. query diagnostics and recoverable errors reconstruct accounting without inventing a graph; error accounting uses the exact closed public `ctxql-graph-tool-error/v1` envelope. Playground errors must reproduce deterministically from the request and workspace state. Terminal, exhausted, authority-invalidated, and nondeterministic check errors cannot produce an accepted replay;
4. view/inspect/check and successful operation responses are deterministically regenerated and compared byte-for-byte with the recorded response;
5. evidence references are checked against the provider capture's issued ranges;
6. the complete reconstructed projection—including call/query/request/response/retry counters, registries, limits, revisions and next IDs—must equal the final projection.

The transcript verifier separately checks wire counters and exact model-visible response bytes. Reconstruction invokes no provider, converter, native graph query, or admission capability. Stored replay may perform current authorization and evaluation/admission reads; “offline” means that the original graph interaction is reconstructed rather than rerun against today's graph.

## Frozen graph work schema

Graph-enabled durable evaluation uses closed `ctxql-acquisition-graph-work/v1`, not the legacy work schema. Its fields are:

- `schema`, `job_id`, `review`, `claims`, `assertions`, `ontology_mode`, `extraction_run`, `report`;
- `graph`;
- `graph_artifact_descriptors`.

`graph` is closed and contains:

```json
{
  "capture_root": "<registered graph_capture work root>",
  "context_root": "<registered graph_context work root>",
  "workspace_root": "<registered graph_workspace work root>",
  "capability_root": "<registered graph_capability work root>",
  "leaf_roots": ["..."]
}
```

Sealing first verifies the export, then registers workspace, context, capability, transcript leaves, payload objects, and index under their expected work stages. Graph work cannot be completed through the unguarded admission path: current graph authority and exact disclosed dependencies are required before preparation and again through the guarded Control/Semantic mutation boundary.

The aggregate capture uses `ctxql-passage-graph-capture/v1`; graph-enabled passage leaves use `ctxql-passage-graph-capture-leaf/v1`. Graph-disabled aggregate capture remains `ctxql-passage-capture/v3` with its existing leaf version.

## Source-plus-graph artifact descriptor v3

`ctxql-acquisition-artifact-descriptor/v3` is separate from source-only v2 and is closed:

```json
{
  "schema": "ctxql-acquisition-artifact-descriptor/v3",
  "source_id": "...",
  "source_version": "sha256:...",
  "source_selector": {"kind":"whole_document"},
  "source_fragment_hash": "sha256:...",
  "artifact_root": "sha256:...",
  "artifact_kind": "...",
  "context_root": "sha256:...",
  "graph_context_root": "sha256:...",
  "context_access": "source_plus_graph"
}
```

The selector may instead be exact `utf8_span` with `start`/`end`. Artifact kind is non-empty, control-character-free, and at most 128 bytes. `context_root` binds the provider/source capture; `graph_context_root` binds the graph authority context. Neither a descriptor nor either hash is a bearer capability.

A v3 grant is created only when the entire descriptor image is found in authenticated frozen work and both roots equal registered work roots. Reads then require the existing exact source selector authorization **and** current authorization of every retained graph claim dependency. The service rechecks lease, Control read permission, current Semantic authority, and graph dependencies before final release.

### Graph artifact pages

Large source-plus-graph artifacts use UTF-8-safe pages with a target/cap of `min(source read cap, canonical input cap, 256 KiB)`.

The page index is closed `ctxql-acquisition-source-plus-graph-artifact-page-index/v1`:

```json
{
  "schema": "ctxql-acquisition-source-plus-graph-artifact-page-index/v1",
  "artifact": {"...":"v3 descriptor"},
  "total_bytes": 0,
  "page_bytes": 0,
  "pages": [{"ordinal":0,"root":"sha256:...","bytes":0}]
}
```

The catalog is closed `ctxql-acquisition-source-plus-graph-artifact-pages/v1`:

```json
{
  "schema": "ctxql-acquisition-source-plus-graph-artifact-pages/v1",
  "job_id": "...",
  "entries": [{
    "authority": {"...":"original v3 descriptor"},
    "artifact": {"...":"derived v3 descriptor"},
    "index": {"...":"v3 artifact_page_index descriptor"}
  }]
}
```

All derived descriptors preserve one exact source/version/selector/fragment, source-capture root, and graph-context root. Mixed restrictions are rejected rather than represented as a weaker convenient descriptor. Authenticated graph page targets currently include the provider graph capture, final workspace, graph context, graph capture index, evaluation checkpoint, and—when present—graph admission result.

## Current authorization and replay

The implementation conservatively treats every disclosed imported claim as a dependency, whether or not it remains live or appears in final claims. Current authorization is required for cached workspace disclosure, artifact metadata/content/pages, replay, final output release, and new review/business preparation/admission. Revocation denies the affected operation as a whole; hashes, handles, snapshots, and recorded historical visibility do not bypass current policy.

Replay authenticates the registered capture/work binding, verifies source/converter representation and graph capture integrity, reconstructs tool state without Pi or graph-query execution, then re-evaluates the unchanged final provider response. It still opens current authorized graph/source context to enforce present permissions. Ephemeral replay uses a temporary store and extract-only mode, producing no new durable acquisition state or admission. Exact source-selector requirements are retained from authorized descriptors and rechecked within the Control mutation guard for graph-backed replay/resume and within the final disclosure guard. The guard's already-validated current policy context is reused without reacquiring its non-reentrant lock; an earlier source check alone never authorizes later mutation or release.

## Protected initial identity context

Graph-enabled acquisition can retain the initial approved gazetteer in context v2 and issue v3 artifacts governed by the union of initial and queried claim dependencies. Ordinary source-only descriptors remain withheld for protected entity context; graph-disabled historical captures do not gain a fabricated graph grant.

Replay restores the retained identity facts and exact classification references only after validating current approval, fact visibility, exact dependencies and identifier uniqueness. It does not replace the original model context with today's gazetteer. The replay's fresh authorized observation supplies its release fence; the existing live gazetteer still requires exact head freshness. Query visibility, labels and playground hypotheses never add approvals. Changing the original query/profile binding denies graph-backed inspection or completion rather than substituting another readable configuration.

## Completion honesty

The hermetic socket fixture exercises an explicitly approved existing agreement, a readable-but-unapproved party, two proposed borrowers and a private collective reference. It tests the configured identity mechanism, not a new jurisdiction/registration matcher or real-model legal interpretation. These schemas do not by themselves establish model-quality improvement or document-interpretation correctness. The unchanged final parser, host eligibility rules, classification support checks, and admission policy remain authoritative.
