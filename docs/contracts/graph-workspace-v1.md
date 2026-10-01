# Graph workspace contract v1

Status: current implementation contract. The Rust query/session/workspace implementation, Pi bridge dispatch, durable graph capture, offline workspace reconstruction, and source-plus-graph artifact path described here exist. This contract does not claim real-model quality or automatic identity reuse.

Primary schema identifier: `ctxql.graph-workspace/v1`.

## Scope and final-output firewall

The graph workspace is private, document/attempt scoped working state. It separates:

- immutable imported nodes and claims from an authorized query result;
- draft nodes and claims grounded in this document;
- working document references, identity hypotheses, and open questions.

It is not an authoritative graph writer. Query and playground tools cannot admit Semantic or Control records. The final model response uses the host-bound `ctxql-extraction-text/v1` format: ENTITY/ALIAS/CLAIM blocks, CLAIM_METADATA sections and exact evidence, or NO_CLAIMS. Only entity reference labels are model-assigned; Rust generates classification, attribute and relation component IDs. Historical JSON v2/v3 responses retain their original parsing semantics. Structured tool arguments do not change this text-only final output contract. There is no graph submission envelope, graph delta, workspace field, or claim-metadata field. Playground handles and hypotheses do not authorize known-IRI reuse.

The enabled implementation requires acquisition protocol `ontology-v2` and `window.mode = "off"`. Chunking remains implemented for graph-disabled ingestion; graph-workspace configuration with `auto` or `always` is rejected.

## Session and handles

One `GraphSession` binds an issuer, stable session ID, attempt/job ID, source text version, issued-range root, owned evidence handles, a pinned Semantic snapshot, host-owned query configuration/profile, deadline, cancellation state, and a `GraphContextManifest`.

Handles are host-issued, session-suffixed strings such as `g1~<session>`, `n1~<session>`, `c1~<session>`, `r1~<session>`, `h1~<session>`, and `q1~<session>`. They are never recycled. They are neither IRIs nor read capabilities. Unknown, released, wrong-type, forged-evidence, and cross-session handles fail closed. Labels never establish identity.

Session operations are serialized. Query work is staged outside workspace mutation and is published only after revision and current-authority checks. A limit exhaustion, policy denial/change, timeout, or cancellation terminates or invalidates the session as appropriate.

## Authorized graph query tool

Tool name: `ctxql_graph_query`.

The accepted closed request object has:

| Field | Requirement |
|---|---|
| `query` | Required non-empty inline CTXQL string, at most 32 KiB. |
| `max_nodes` | Optional lower cap. |
| `max_claims` | Optional lower cap. |
| `max_response_bytes` | Optional lower cap. |
| `timeout_ms` | Optional lower timeout. |

No principal, ledger, native query, write flag, arbitrary function, query configuration, profile, or snapshot selector is model-controlled. Rust uses the host-selected published configuration/profile, restrictive compiler capabilities, an authorized historical Semantic view pinned for the session, and current Control/Semantic publication fences. Query access does not include review-graph business reasoning or bypass policy-before-inference.

A successful complete result is:

```json
{
  "schema": "ctxql-graph-query-result/v1",
  "status": "graph",
  "handle": "g1~<session>",
  "snapshot": "<snapshot binding>",
  "node_count": 2,
  "claim_count": 1,
  "complete": true,
  "overview": "COMPLETE GRAPH ..."
}
```

The host retains the complete `IssuedGraph` payload, including canonical IRIs, distinct claim IDs, typed literals, metadata, and claim dependencies. Results are endpoint-closed. Equal SPO claims with different claim IDs remain distinct. The overview may show only the first eight nodes and explicitly report view-only omissions; that does not crop the retained graph.

A bounded failure returns either `status: "diagnostic"` under `ctxql-graph-query-result/v1` or `ctxql-graph-tool-error/v1`. Query overflow, engine truncation/incompleteness, capacity, execution exhaustion, timeout, and authority denial are not successful partial graphs. No graph handle or payload is published for a diagnostic/error. At the configured/default ceilings, 50 nodes and 100 claims are allowed; 51 or 101 are rejected. Authorization is applied before visible counts or overflow diagnostics.

A successfully returned graph is initially `Pending` and already consumes a live graph slot. The model must explicitly import it before its nodes/claims become workspace records.

## Playground tool

Tool name: `ctxql_graph_playground`. Requests are closed by operation:

| Operation | Accepted request fields | Current behavior |
|---|---|---|
| `import` | `operation`, `handle` | Atomically attaches a pending graph, creates imported record handles, and advances the revision. |
| `release_graph` | `operation`, `handle` | Releases pending/attached live state and advances the revision; active draft dependencies cause failure. |
| `apply` | `operation`, `expected_revision`, `idempotency_key`, `edits` | Applies one atomic batch. |
| `inspect` | `operation`, `handle`, optional `max_bytes` | Returns the bounded neighbourhood representation for one record. |
| `view` | `operation`, `view`, optional `handle`, optional `max_bytes` | Supports `overview`, `neighbourhood`, `changes`, and `open_questions`; neighbourhood requires `handle`. |
| `check` | `operation` | Returns deterministic structural issues. |

Success is wrapped as:

```json
{"schema":"ctxql-graph-playground-result/v1","status":"ok","result":{}}
```

Failures use:

```json
{"schema":"ctxql-graph-tool-error/v1","status":"error","code":"<public code>"}
```

### Imported graph payload

`IssuedGraph` is a closed object with `schema`, `issuer`, `session_id`, `snapshot`, `nodes`, and `claims`:

- each node has `key`, `canonical_iri`, `label`, string/string `metadata`, and `dependencies`;
- each claim has `claim_id`, `subject_key`, `predicate`, tagged `object`, string/string `metadata`, and `dependencies`;
- an object is `{ "kind":"node", "key":... }` or `{ "kind":"literal", "value": { "lexical", "datatype", "language" } }`.

Imported records are immutable. Release cannot silently detach imported records referenced by an active draft claim, reference, hypothesis, or question. The dependent records must first be withdrawn. Release frees live workspace capacity but not cumulative call/transcript accounting or durable disclosure history.

### Apply schema

The internal `ApplyRequest` is closed and contains `schema: "ctxql.graph-workspace/v1"`, the current `session_id`, `expected_revision`, non-empty bounded `idempotency_key`, and 1–20 tagged edits. The Pi operation supplies the latter three fields and `edits`; the host supplies schema/session.

Edits are closed, tagged by `op`:

- `add_node`: `temp_id`, `local_id`, `label`, `evidence`;
- `add_claim`: `temp_id`, `subject`, `predicate`, `object`, `evidence`, `fit_note`;
- `add_reference`: `temp_id`, `label`, `scope`, `definition_evidence`, `referent_shape`, nullable `target_text`, `members`, `membership_evidence`, `status` (`unresolved|partial|resolved`);
- `add_hypothesis`: `temp_id`, `proposed`, `existing`, `comparison_evidence`, `note`;
- `add_question`: `temp_id`, `code`, `message`, `relevant`;
- `withdraw`: `handle`.

Record references are `{ "kind":"handle", "handle":... }` or `{ "kind":"temp", "id":... }`. Endpoints are tagged record references or typed literals. Temporary IDs may refer only to an earlier addition in the same batch and never become canonical IDs.

A successful `ApplyResult` contains `schema`, `operation_id`, new `revision`, `idempotent_replay`, and the temporary-ID-to-handle map. The batch stages all edits, validates evidence ownership and resulting limits, and commits once. Failure leaves records/revision unchanged, though attempted-call accounting remains. An exact retained retry returns the original result; reuse of a key with different input conflicts.

Withdrawal changes only draft state. It is not authoritative retraction and cannot edit or withdraw imports. An identity hypothesis keeps proposed and existing records distinct and can be withdrawn; it is not an identity merge or eligibility decision.

### Views and checks

`ViewResponse` has `schema`, `revision`, `kind`, `rendered`, `view_partial`, `omitted_records`, and `included_handles`. Every rendered record is marked `EXISTING`, `PROPOSED`, or `WORKING`. A bounded view may omit display records while preserving valid UTF-8/JSON and reporting `view_partial`; the loaded graph remains complete.

`CheckResponse` has `schema`, `revision`, `structurally_valid`, `issues`, `check_partial`, `omitted_issues`, and `note`. Issues contain `code`, `severity` (`error|warning`), `handles`, and `message`. Checks cover structural/evidence problems, unresolved/contradictory references, and ambiguous hypotheses. They do not parse `fit_note`, apply English plural/name heuristics, certify ontology fit, authorize identity reuse, or admit claims.

## Exact implemented budgets

Host configuration may lower these ceilings, never raise them:

| Budget | Ceiling/default in Rust |
|---|---:|
| Nodes / claims per query graph | 50 / 100 |
| Live pending or attached graphs | 3 |
| Imported nodes / claims retained | 150 / 300 |
| Draft nodes / draft edges and working links | 100 / 200 |
| Edits per atomic batch | 20 |
| Tool calls / graph queries | 40 / 12 |
| One request / response | 32 KiB / 64 KiB |
| Default overview | 8 KiB |
| Aggregate requests + responses | 1 MiB |
| Retained workspace allocation | 2 MiB |
| Idempotency records | 64 |
| Label / identifier / literal / note | 512 B / 2 KiB / 16 KiB / 2 KiB |
| Evidence handles / metadata entries per record | 32 / 64 |

The allocation check uses serialized state plus a conservative allocation estimate. Literal endpoints and metadata count toward bytes. Live release does not reset cumulative work.

### Whole-document preflight

Graph mode is exactly one `window.mode = "off"` passage and still obeys configured `max_document_bytes`, `max_source_bytes`, and the window maximum. It does not excerpt, paginate, or silently fall back to chunks.

Before the provider call, Rust enforces this byte equation:

```text
serialized provider request bytes
+ system/instruction bytes
+ reserved_final_output_bytes
+ reserved_tool_result_bytes
<= max_context_bytes
```

`max_context_bytes` is required, non-zero, and at most 512 KiB. Both reserves are required and non-zero; `reserved_tool_result_bytes` cannot exceed the aggregate 1 MiB tool ceiling, and the two reserves together cannot exceed `max_context_bytes`. `max_request_bytes` also cannot exceed `max_context_bytes`. Failure is `context_budget_insufficient` before provider execution. These are byte reservations, not a claim of tokenizer-exact capacity.

## Authorization and lifecycle boundaries

Graph queries require the configured extraction principal's current Query permission and authorized Semantic view. Each query, import/view/inspect/check/edit disclosure, cached/idempotent response, final model release, and guarded admission rechecks current authority for the append-only set of disclosed claim dependencies. An authority denial invalidates the session. A graph handle, content hash, snapshot identifier, or artifact descriptor is not a capability.

The pinned data basis remains stable during a session, while current authorization is re-evaluated. Every disclosed imported claim remains a conservative dependency even after graph release or if the final proposal does not mention it. Existing final known-IRI eligibility and exact classification-support checks remain additional requirements. Query visibility and a workspace hypothesis do not add an IRI to `approved_entity_iris` and do not prove the jurisdiction/scheme identity matching integration.

`ExtractOnly` can use the same graph tools through an isolated read-only Semantic/projection composition. It creates no business/review admission and no durable acquisition work; final release is still authority-checked. Ephemeral stored replay likewise uses temporary storage and extract-only behavior. Normal startup/read-snapshot mechanics are not playground writes.

Capture and protected artifact details are specified in [graph-context-capture-v1.md](graph-context-capture-v1.md).

## Current limitations and claim discipline

This contract documents implemented schemas and boundaries. In particular:

- no claim is made here that a real model has demonstrated the required quality improvement;
- no claim is made that PDF07 or broader identity integration has passed acceptance;
- graph readability is broader than identity reuse eligibility;
- references and hypotheses remain working interpretation unless the unchanged final envelope independently expresses and passes validation for supported claims;
- protected initial gazetteers require exact authorized claim support for every retained fact and the versioned captured snapshot; graph-disabled entity captures remain withheld from source-only artifact access. See the capture contract.
