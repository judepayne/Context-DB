# Acquisition configuration v1

This document describes the **current** closed acquisition section used by `ctxql-instance/v4`, plus explicit legacy dispatch. Current ontology-v2 execution embeds Fluree 4.2.1 at `82dbcec3e435d6ed1d45bc0ed929432323b6b201`.

## Protocol dispatch and compatibility

`[acquisition] protocol` is `ontology-v2` or `legacy-v1`. New configurations must specify `ontology-v2`; omitting the field deliberately selects deprecated `legacy-v1` behavior so an old configuration is not silently reinterpreted. Ontology-v2 requires:

```toml
protocol = "ontology-v2"
assertions = "accepted" # or "evidence-only"
ontology-profile = "ctxql-ontology-profile/fluree-4.2.1-82dbcec3e435d6ed1d45bc0ed929432323b6b201/v1-uncertified-acquisition"
```

`assertions` defaults to `accepted` only for compatibility; current configurations should state it. It is independent of the CLI's `--ontology-mode hard|soft`: hard admits only eligible verified ontology mappings, while soft may admit versioned provisional claims. `evidence-only` persists review evidence but no business claims. `--extract-only` overrides persistence entirely.

Legacy-v1 retains the versioned FACT/`EVIDENCE` foreground protocol, strict CLAIM parser APIs, old fixture identities, and old recording decoders. It is not a fallback when ontology-v2 output is malformed. Historical Fluree `603974f` recordings are supported for archival decoding/integrity verification only; this 4.2.1 process reports their executor unavailable rather than reproducing them under different semantics.

## Closed ontology-v2 fields

The acquisition table contains:

- `access-mode = "direct"`;
- `protocol`, `assertions`, disjoint `claims-graph` and required `review-graph` IRIs;
- acquisition `principal` and Semantic policy `action`;
- absolute `pi-command`, closed `pi-bundle`, exact `extractor_model = "openrouter/deepseek/deepseek-v4.1-flash"`, section-local `thinking = "high"`, and `batch-size = 2`;
- optional absolute `pi-session-log-dir`; absent keeps extraction Pi sessions ephemeral, while present retains sensitive native Pi JSONL plus content-free host lifecycle/outcome diagnostics in a private owner-only directory. Logged sessions are never resumed automatically and can contain prompts, reasoning, tool data and source text;
- nonzero source/document/folder, provider/projection timeout, and Control-journal bounds;
- current `ontology-profile`, a `sha256:` `ontology-catalog-root`, and optional `ontology-ledger-path`;
- at least one `allowed-local-roots` path, optional named HTTPS adapters, converters, window settings, ontology briefing, and established-entity source.

Unknown fields and invalid enum values fail. Configured paths resolve against the instance file and then pass existing symlink, overlap, ownership and permission checks. Local source targets must resolve beneath one allowed root. Folders are non-recursive. HTTPS URLs with query strings are rejected and a URL must match exactly one configured adapter.

The claims and review graphs must differ. Review records describe proposals with fixed host metadata and literal suggestion strings; they do not assert the proposed business triple and are excluded from business scans and inference.

## Vocabulary and known entities

`ontology-ledger-path` selects the verified, pinned read-only vocabulary ledger. It is a lookup source, not an automatic cross-ledger reasoning import. Alternatively, a closed `ontology-briefing` seed manifest may select terms from the configured verified vocabulary view. Raw vocabulary is `loaded_uncertified`: membership does not claim complete OWL/FIBO reasoning support.

Established identity lookup is optional and deny-by-default:

```toml
approved-entity-iris = ["https://example.test/entity/acme"]

[acquisition.entity-source]
graphs = ["https://example.test/graph/entities"]
classes = ["https://example.test/ontology/Organization"]
identifying-predicates = ["https://example.test/id/company-number"]
```

A candidate must be explicitly approved (maximum 4,096 IRIs), present in the pinned Semantic snapshot, satisfy the graph/class/identifier filters, and pass current source policy. An empty list means no global established candidates. Names alone do not establish identity. The captured gazetteer and its authorization observation participate in capture identity. Protected labels, identifiers, candidates, counts, and context are not released under source-only permission.

## Windowing and multipassage

```toml
[acquisition.window]
mode = "auto"       # off | auto | always
target-bytes = 32768
max-bytes = 65536
overlap-bytes = 1024
```

Windowing is not required to be off. `off` creates one passage and fails if the document exceeds `max-bytes`. `auto` splits when needed; `always` applies deterministic passage planning even to small documents. Overlap must be smaller than `max-bytes`, and `target-bytes <= max-bytes <= max-document-bytes`.

Ontology-v2 binds each passage's source span, issued UTF-8 ranges, ontology briefing, prior captured document context, coverage ledger, and entity checkpoint. Later passages can reuse host-issued document handles. Completed leaves are immutable; a final multipassage root orders them without reminting earlier coordinates. Partial captures report missing ordinals and resume does not request them from Pi implicitly.

## Optional graph workspace (whole-document POC)

The feature is off when `[acquisition.graph-workspace]` is absent. Enabling it requires `protocol = "ontology-v2"` and `[acquisition.window] mode = "off"`; chunking remains available when the feature is off. All numeric fields below are required, nonzero ceilings, not provider token-limit guarantees:

```toml
[acquisition.graph-workspace]
# Omit query-config to use the instance's published default config.
# An explicit reference has { iri, version, hash }.
# profile-selector and profile must either both be present or both absent.
query-timeout-seconds = 10
max-nodes = 50
max-claims = 100
max-live-graphs = 3
max-tool-calls = 40
max-graph-queries = 12
max-request-bytes = 32768
max-response-bytes = 65536
max-aggregate-bytes = 1048576
max-state-bytes = 2097152
max-context-bytes = 524288
reserved-final-output-bytes = 65536
reserved-tool-result-bytes = 131072
```

The configured acquisition principal needs current Control Query permission and access to the already-published query configuration/profile, plus current Semantic access to every disclosed claim. Tools do not publish prerequisite artifacts.

For approximate name queries, publish `fixtures/conformance/graph-workspace/config.json` and bind its exact `{ iri, version, hash }` as `query-config` (or the instance default). Unlike the exact-only `fixtures/conformance/p2/config.json`, it includes a `landing` section with the versioned lexical resolver, pinned Unicode tables and minimum token overlap. A missing or incompatible section is a preparation error, not an empty name-search result. The compiler-tested fixture pins Unicode 17.0.0; do not silently substitute different tables after a runtime upgrade. Publish a new artifact/binding rather than rewriting an old artifact or capture.

Semantic name search uses explicit, authorized string-valued `rdfs:label`, `skos:prefLabel` and `skos:altLabel` claims, not arbitrary attributes, source excerpts or local extraction names. Entity `Name:`/aliases in final extraction output do not automatically admit label claims. No matching authorized label means no name match, even when an entity's opaque ID is present. Search visibility never grants identity-reuse eligibility. If name search fails preparation, do not invent an IRI and treat an empty exact lookup as proof of absence.

The query timeout cannot exceed the provider timeout. Configuration and model-requested limits cannot exceed the host ceilings; the smallest applicable limit wins.

Whole-document preflight reserves the complete rendered request, verified instructions/skills, final output and cumulative tool context using a conservative byte bound. An oversized input fails before Pi; there is no automatic excerpting or fallback to chunks. The query tool returns a handle only for a complete result; overflow or engine truncation requires explicit refinement. The playground is private draft state, never an admission tool. Final output uses the host-bound `ctxql-extraction-text/v1` blocks; the `ontology-v2` configuration value remains the protocol-family name, not the final-output syntax. Historical JSON captures remain version-bound.

See [workspace operations](graph-workspace-v1.md) and [protected capture/replay](graph-context-capture-v1.md) for exact disclosure, retention and replay boundaries.

## PDF converter

PDF support is manual. Install Poppler's `pdftotext`, determine its absolute path and hash the executable bytes, then configure it explicitly:

```toml
[acquisition.converters.pdf]
command = "/opt/homebrew/bin/pdftotext"
version = "pdftotext 25.x (operator-verified)"
executable-hash = "sha256:..."
arguments = ["-layout"]
normalization = "none"
```

`application/pdf` is also accepted as the converter table key. Context DB rehashes a regular, non-symlink executable before each conversion, appends `- -` so PDF bytes enter stdin and UTF-8 text leaves stdout, enforces timeout/output bounds, and rejects empty/non-UTF-8 output. The `version` is an operator declaration retained in the converter manifest; executable-byte hash verification is the enforcement mechanism.

Durable ingestion stores and independently rehashes:

1. the immutable original PDF object and original-representation manifest;
2. the converter manifest (executable hash, declared version, ordered effective arguments, timeout, encoding/normalization);
3. the extracted UTF-8 object and text-representation manifest linking it to the original and converter.

The text-version descriptor resolves to that separately rehashed text object. Evidence coordinates address the retained extraction text, while provenance retains the original PDF. Registered replay verifies this chain and uses stored bytes; it does not rerun Poppler or Pi. Extract-only uses private ephemeral representations and publishes none of these objects to configured durable stores.

## Secrets and access

Provider credentials come from bounded private files or documented environment entries used by the Pi subprocess. They never belong in argv, prompts, capture manifests, reports, review records, or Control journals. Acquisition inspection/replay credentials use `--token-file`; no command-line bearer value is accepted.

Inspection and artifact release require the configured principal, current Control operation authority, current Semantic policy, admitted review history, and inherited source/context authorization. A root or descriptor is not a read grant. Aggregate pages that combine incompatible source/context scopes are withheld, and later revocation denies metadata and content.

## CLI overrides

`cdb ingest start` accepts exactly one of `--file`, `--folder`, or `--url`, plus `--ontology-mode hard|soft` (default `hard`) and `--assertions accepted|evidence-only`. The assertion flag overrides the configured ontology-v2 assertion policy for that invocation and enters evaluation identity. `--wait admitted|projected` defaults to `projected`. `--extract-only` is mutually exclusive with `--wait`.

`cdb ingest replay` requires `--config`, `--token-file`, `--capture`, `--ontology-mode`, and `--assertions`. `--ephemeral`/`--extract-only` suppresses all replay admissions and durable work/source changes; it is stronger than durable `evidence-only`.

These are implemented current contracts, not a declaration that the active plan's complete real-document acceptance and final review have finished.
