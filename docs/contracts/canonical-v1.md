# Canonical projections — ctxql-canonical/v1

Status: implemented canonical codec and active identity contract. Response/evidence boundaries and exact numeric behavior are versioned independently where specified below.

## Bytes and domains

SHA-256 input is UTF-8 canonical JSON of exactly `{domain,version,payload}`, version string `ctxql-canonical/v1`; digest spelling `sha256:` plus 64 lowercase hex digits. Object keys sort by Unicode scalar value, not UTF-16 code units. Arrays preserve order; producers normalize set-valued fields before hashing as specified below. Duplicate keys, invalid Unicode/nonfinite numbers fail before normalization. No NFC/NFD conversion. Escape quote/backslash and controls only, using short JSON escapes for backspace/tab/LF/formfeed/CR and lowercase `\u00xx` for other controls; slash and valid non-ASCII stay literal. No whitespace or final newline outside JSON strings. Numbers follow [numeric-v1](numeric-v1.md), not host floating serialization. Typed literal datatype/language are retained even where numeric values compare equal.

Domain registry: `ctxql.plan`, `ctxql.response`, `ctxql.function.input`, `ctxql.function.output`, `ctxql.function.input-root`, `ctxql.function.output-root`, `ctxql.product.structured`, `ctxql.product.text`, `ctxql.structured-claim`. Unknown domain/version fails. Source whole/fragment byte hashes are ordinary SHA-256 of exact bytes, explicitly **not** these JSON envelope hashes.

Only schema-declared timestamp fields normalize to UTC exactly millisecond precision (`2026-03-31T00:00:00.000Z`). Reject nonzero submillisecond precision, leap seconds, range outside years 0001–9999 or invalid offsets; arbitrary strings and numeric decimals are not timestamp-normalized. Clock allocation/capture follows the separate [transaction-clock protocol](transaction-clock-v1.md); its synthetic integer experiment does not implement this UTC renderer. Text products normalize CRLF/CR to LF and append one LF only if absent; empty text becomes LF; preserve additional terminal LF and other whitespace. Source evidence bytes never undergo this product-text normalization.

## Closed projection schemas

All listed keys required unless explicitly conditional; unknown fields at these projection boundaries fail rather than silently disappear. Transport diagnostics remain outside. Null is explicit only where allowed, not a substitute for absent data. ArtifactRef is `{iri,version,hash}`; graph Pin is `{authority,graph,revision,receipt}` with strings, where revision is adapter-stable exact revision spelling and receipt immutable content identity (never t alone). Public neutral adapter conversion retains backend identities here without exposing backend structs. No current-policy epoch/principal is hashed into graph semantics.

| Domain | Exact payload fields |
|---|---|
| ctxql.plan | `query,artifacts,config,as_of` |
| ctxql.response | `selection,graph_status,semantic_flags,notices,claims,paths,explain` |
| ctxql.function.input / output | `name,version,manifest_hash,call_index,value` |
| ctxql.function.input-root / output-root | `name,version,manifest_hash,hashes` |
| ctxql.product.structured / text | `assembly,product_type,inputs,sources,notices,citations,content` |
| ctxql.structured-claim | `mode,source_id,snapshot,row_key,mapping_hash,slot,occurrence` |

Structured-claim identity payloads follow [structured-v1](structured-preparation-v1.md); occurrence is an admission batch key for imports and null for live entries. The versioned domain prevents mixing these identity hashes with response or source-byte hashes.

Plan query is the executable normalized `{about,bounds,walk,filter,return}` with expanded IRIs; as_of is materialized both in bounds and payload and must agree. Defaults/state/order/config mappings are explicit per [execution-v1](execution-defaults-v1.md). artifacts is `{query:ArtifactRef|null,profile:ArtifactRef|null,config:ArtifactRef}`; dev inline queries use null, replayable mode requires published refs. Config is full semantic config content including name/version/runtime/fields/external_functions and selected preparation declarations, not a pathname. No assembly, db_time, plan_hash, run ID, file location or timing enters the plan projection. Engine identity and graph pin are separately mandatory ExecutionRun prerequisites, not query semantics. Hash-bearing references to other objects are included; only this object's own hash is excluded.

Response selection is the complete four-boolean return object. claims/paths/explain are null if not selected, not empty arrays; evidence bytes never appear. Claims are sorted claim_id ascending, each `{meta}` containing normalized core fields listed in design §5.1, computed lifecycle_state and ext (default `{}`). Lineage uses exactly A.5 `ctxql.lineage.v1`, sources remain ordered, backend provenance only in ext. Optional lineage fields remain absent when absent; do not invent immutable versions/hashes. Subject/entity objects remain distinguished from typed literal endpoints. Paths preserve result rank and fields `seed_id,node_ids,endpoints,claim_ids,depth,reached_target,block_index,scores` as execution-v1. Null reached_target is explicit. No incidental backend fields are allowed in claims/path wrappers.

Explain when selected is exactly `{evaluation_context,seeds,ontology_resolution,traversal_stats,lifecycle}`. evaluation_context is `{as_of,db_time,profile,bounds}`, profile ArtifactRef|null, db_time Pin; seeds are ordered `{block_index,role,anchor,id,score}` entries from recorded landings; ontology_resolution is ordered `{predicate_index,operator,requested,matched,rule}` records using expanded IRIs and immutable rule identities; traversal_stats is `{examined,eligible,traversed,unique_traversed,returned_paths}` exact nonnegative integer counters; lifecycle is ordered `{claim_id,rule,state,supporting_ids}` sorted by claim ID. Query plan is separately retrievable via run; transport explain can show plan/hash/capabilities/timing but these are not additional projection keys. Semantic flags are sorted unique strings. Notices are `{code,details}` with deterministic JSON details, deduplicated and sorted by their canonical bytes; localized prose, timing, denied IDs and raw backend errors are excluded. All graph degradation notices remain projected even when explain=false. New deterministic response fields require a projection version change, not an implicit allowlist extension.

Function call_index is zero-based **per manifest** encounter index. Manifest summaries ordered by first encounter; roots hash ordered digest strings (empty list has a root). Same values in input/output differ by domain; repeated identical calls remain separate indexed positions. Ordered broker calls on rejected walk/filter attempts remain recorded. No archive of every input/output is required.

Product assembly is ArtifactRef plus `name`; inputs/sources/notices/citations are defined by [assembly-v1](assembly-inputs-v1.md). Structured content is arbitrary supported canonical JSON; text content is the normalized text string. Invocation ID, output self hash, execution duration and host paths are excluded. Source references and input run IDs are included as product provenance; differing provenance may therefore change product hash while equal query plans remain equal.

## Graph status and hydration separation

Keep required transport status vocabulary ready/ready_with_warnings/blocked/error. Add POC envelope `graph_status` with the same vocabulary and `evidence_verification` ordered records `{source_id,version,fragment_id,outcome}`; outcomes verified/unverifiable/missing/changed/denied/not_requested. Product availability/reproduction is separately reported, never folded into graph_status. Transport status is graph_status unless successful graph execution has an evidence warning, then ready_with_warnings; graph blocked/error takes precedence. Hydration missing/changed/denied does not change response hash. Denial of a graph interpretation dependency or replay footprint **does** block release/replay, not get mislabeled as evidence-only failure. Current-policy non-disclosure still applies to every returned verification record.

## Discriminating byte examples and fixed expectations

[bytes-v1.json](../../fixtures/conformance/canonical/bytes-v1.json) contains six fixed normalized envelopes, exact UTF-8 byte strings and SHA-256 expectations with a real hash of an inline synthetic manifest. They cover input/output domains, ordered arrays, Unicode scalar key order and an integer above 2^53. They were authored and checked with Python's standard library on these fixed integer/string inputs, not by an implemented CTXQL canonicalizer. P1 independently reproduces them without changing the six original values. The illustrative placeholder example below is separate from those valid-digest vectors.

For an empty function input value, the exact ASCII byte string (no final LF) is:

```text
{"domain":"ctxql.function.input","payload":{"call_index":0,"manifest_hash":"sha256:example","name":"demo/f","value":{},"version":"1"},"version":"ctxql-canonical/v1"}
```

`sha256:example` is a symbolic fixture placeholder, not a valid production digest. A production manifest reference must contain a verified 64-hex digest. Key ordering discriminator payload keys U+E000 then U+10000 serialize in that order (opposite UTF-16 ordering). `{"a":1,"b":2}` and reversed input keys project equally; `[1,2]` versus `[2,1]` differ; `é` versus `é` differ. `1.0` becomes numeric token `1`, but string `"1.0"` remains unchanged. A timestamp-like arbitrary string keeps its spelling. Evidence body A→B and timing 1→9 preserve graph projection, but fragment verification changes. claims selection true→false changes plan and response projection; assembly-only changes do not change plan. `x` and `x\n` text normalize equally; `x\n\n` remains different.

P1 implements duplicate-aware lossless parsing, closed schemas and golden digest tests; P4/P5/P8 integrate replay/broker/products. These schemas and the codec are not evidence of a full compiler or executable replay.
