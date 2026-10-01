# Extraction capture v2

`ctxql-provider-capture-manifest/v2` preserves one passage's exact provider input and final response under the current Fluree 4.2.1 acquisition profile (`82dbcec3e435d6ed1d45bc0ed929432323b6b201`). It is distinct from a query recording (`ctxql-recorded-run/v5`), an evaluation, and an admission receipt. Historical capture v1 artifacts retain their original schema and evidence status; decoding them does not make a historical backend executable.

## Retained bytes

The closed manifest contains:

- source identity: `source_id`, `locator`, `text_version`, `source_text`;
- coordinates: `window_id`, `coordinate_seed`, absolute UTF-8 `window_start`/`window_end`, ordered `issued_ranges`;
- exact input: `request`, `request_root`, `ontology_lookup`;
- executed assets: `asset_manifest`, path-to-UTF-8-byte-content `assets`, `agent_bundle_hash`;
- execution selection: `model`, `thinking`;
- final output: `response`, `response_root`.

The response is advisory. Retaining its hash does not establish grounding, vocabulary membership, entity identity, semantic correctness, or permission to admit it. Do not retain provider reasoning or credentials in this manifest.

## Independent integrity verification

Run:

```sh
python3 scripts/check_acquisition_capture_v2.py /path/to/provider-capture-manifest.json
python3 -m unittest scripts.test_acquisition_capture_v2
```

The checker reconstructs exact request/response hashes, issued window and line handles, original UTF-8 range text, asset file hashes/sizes, bundle serialization, and request/ontology/model bindings. Duplicate JSON keys, changed source ranges, and missing or substituted asset bytes fail verification. Request definition/briefing text is retained as part of the exact request bytes; a changed definition changes the request commitment.

This is an **integrity check, not an authorization capability**. An attacker can generate a self-consistent manifest. Production replay must additionally compare the manifest with host-approved source, context, coordinate, model and executed-asset bindings, apply current disclosure/admission policy, and validate proposals normally. Never turn arbitrary captured bytes into a validated bundle.

## Coordinate reconstruction

Coordinates count original UTF-8 bytes, not Unicode code points or normalized characters. Newlines and CRLF are preserved. The window handle hashes the domain-separated seed, window ID and absolute start/end. Line handles hash the coordinate seed, window ID and local line ordinal. Evidence occurrences must match exact substrings in an issued range; quote repair is forbidden.

For a streaming document, each later request binds its preceding captured document context. The aggregate root must not remint already issued coordinates or claim IDs. A single-passage export does not by itself prove complete multipassage capture.

## Multipassage manifests and registered replay

`ctxql-provider-multipassage-capture-manifest/v1` retains the source and asset bindings once, followed by ordered passage leaves. Each leaf binds its ordinal, window, request seed, before/after entity checkpoint roots, exact request/response bytes and roots, issued ranges, and leaf root. The final entity checkpoint and aggregate root bind the ordered document capture. Missing, reordered, substituted, or context-mismatched leaves are rejected before provider access. Partial durable captures report missing passage ordinals; resuming must not implicitly request them from a provider.

`ctxql_service::ingest::verify_capture_manifest_bytes` checks single- and multipassage manifest integrity offline. The Python checker above remains specific to single-passage v2. Neither API grants access or authorizes admission.

New durable `ctxql-passage-capture/v3` checkpoints embed a replay manifest. Authenticated stored replay discovers the supplied root only through registered work, verifies admitted review history and inherited source/context permissions, and revalidates current ontology authority. Pre-v3 stored captures without an embedded manifest report unsupported rather than inventing missing context. Extraction replay is separate from query recording replay:

```sh
cdb ingest replay --config /absolute/cdb.toml --token-file /absolute/owner.secret \
  --capture ROOT --ontology-mode hard --assertions accepted
cdb ingest replay --config /absolute/cdb.toml --token-file /absolute/owner.secret \
  --capture ROOT --ontology-mode soft --assertions evidence-only
```

The implemented CLI requires credentials from a private file:

```sh
cdb ingest replay --config /absolute/cdb.toml \
  --token-file /absolute/owner.secret --capture ROOT \
  --ontology-mode hard --assertions accepted
```

Use `--ephemeral` (alias `--extract-only`) for evaluation with **no review or business admissions** and no durable source/work changes. This differs from durable `--assertions evidence-only`, which may admit review evidence while suppressing business claims. An arbitrary self-consistent manifest or content hash is not a registered replay capability.

## Disclosure and evaluation

Full request/response content can contain more than the selected claim excerpt. Artifact release therefore needs authorization for the originating source selection and all captured context. Content hashes are identifiers, not read grants. Protected gazetteer context must not be released under a source-only descriptor.

Large eligible artifacts are persisted as immutable UTF-8-safe pages and a `ctxql-acquisition-artifact-page-index/v1` index. Pages are bounded by the minimum of the configured artifact/source bound, canonical input limit, and 256 KiB. The index records ordered page roots and byte counts; concatenating page bytes in ordinal order reconstructs the original artifact exactly. Pages and indexes inherit the original exact source selector, fragment commitment and context root. Inspection authenticates their catalog and admitted review history before source authorization and final guarded release; it creates no pages. Missing or revoked source permissions deny both metadata and content. Aggregate artifacts spanning different source/context restrictions are withheld rather than authorized using only one contributing source.

For PDF acquisition, the registered capture also depends on the stored source-representation chain: rehashed immutable original PDF bytes and original manifest, converter manifest (executable hash, declared version, effective arguments and normalization), and separately rehashed extracted UTF-8 object/text manifest. Evidence ranges address the extracted text. Replay verifies and consumes this chain without rerunning `pdftotext` or Pi; a substituted original, converter manifest, text descriptor, or text object fails closed.

Hard, soft and evidence-only evaluations may share one unchanged capture; mode changes must not rewrite its ranges or model output. New context or ontology definitions require a new capture/evaluation binding. Extract-only exports are explicit user-requested files, not durable Semantic/Control/source-store admission and not fetchable store capabilities.

Historical provider captures and query recordings remain available to their versioned decoders for archival integrity checking. Execution that names the old Fluree `603974f` backend is unsupported in the current 4.2.1 process; it is never silently executed with current semantics. Focused capture/replay checks do not by themselves assert that the active plan's complete real-document acceptance or final review has finished.
