# Structured claim import v1

`cdb import` admits bounded administrator-curated claims without invoking a model:

```sh
cdb import \
  --config /absolute/cdb.toml \
  --token-file /absolute/owner.secret \
  --input /absolute/claims.json
```

The selected paths are absolute. `--config` and `--token-file` may instead come
from `CDB_CONFIG` and `CDB_TOKEN_FILE`. The token must authenticate the configured
acquisition principal and authorize Admin in both the service and Control ledger.
Semantic authority is checked before parsing and again around every durable action
and receipt release.

## Closed request

The UTF-8 input is a canonical-value-compatible JSON object. Unknown fields are
rejected. Input must fit both the instance's `max_body_bytes` and v1's 16 MiB
parser/canonical-input ceiling (canonical serialization must also fit). V1
additionally allows at most 256 sources, 4,096 entities, 10,000 claims, and 64
evidence references per claim. Individual fields and native admission/artifact
budgets impose further bounds; these maxima do not guarantee that every possible
combination fits an instance's budgets.

```json
{
  "schema": "ctxql-structured-claim-import/v1",
  "dataset": {
    "id": "urn:example:companies",
    "version": "2026-10-01"
  },
  "sources": [{
    "id": "urn:example:source:registry",
    "kind": "ctxql.source.curated-dataset",
    "uri": "https://example.org/registry.csv",
    "version": "2026-09-30",
    "content_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }],
  "entities": [{
    "id": "https://example.org/company/acme",
    "type": "https://example.org/ontology/Company"
  }],
  "claims": [{
    "id": "acme-name",
    "subject": "https://example.org/company/acme",
    "predicate": "https://example.org/ontology/legalName",
    "object": {
      "type": "literal",
      "value": "Acme Limited",
      "datatype": "http://www.w3.org/2001/XMLSchema#string"
    },
    "evidence": [{
      "source": "urn:example:source:registry",
      "selector": {
        "contract": "ctxql-evidence/v1",
        "whole_document": true
      },
      "note": "administrator-curated registry row"
    }]
  }]
}
```

Dataset IDs, versions and source metadata are retained provenance supplied by the
administrator. CDB verifies shape, hash syntax and references; it does **not** fetch the
URI or independently prove that the source bytes, quote, note or assertion are
true. The complete canonical import is retained as the immutable source object.
Claims are labelled curated dataset assertions, not model extractions. Their
verified lineage binds the exact retained import and its hash, not the external
sources asserted by the curator. External citations remain inside that immutable
import; they do not grant access to an external document or certify its bytes.

Dataset and entity identifiers are absolute IRIs (including URNs). Every entity
has a unique identifier. `type` is optional endpoint metadata: when omitted, CDB
uses `owl:Thing` internally as a safe candidate-claim endpoint shape without
asserting or requiring that class in the import vocabulary. When supplied, the
type must be an approved ontology class. Only explicit `rdf:type` claims assert
class membership; if both metadata and an explicit type claim are present, they
must agree. Claim IDs
are unique within the import. Subjects and IRI objects must name declared
entities. An `rdf:type` claim must agree with the entity's metadata type when
that metadata type is supplied.
Predicates and classes must be unique, approved, extraction-eligible terms in the
configured exact ontology bootstrap. Declared object/datatype property kinds must
match the supplied object shape; domain/range entailment is not certified. This is
not a vocabulary creation API.

Objects are either:

- `{"type":"iri","value":"..."}`; or
- `{"type":"literal","value":...,"datatype":"..."}` with optional
  `language`. Use JSON numbers for integer/decimal datatypes, JSON booleans for
  `xsd:boolean`, and strings for strings and dates. Empty strings are valid.
  Language is required for `rdf:langString` and forbidden for other datatypes.
  Candidate-claim parsing applies the core model's datatype, range and lexical
  rules before admission; see [core-model-v1.md](core-model-v1.md).

Evidence is non-empty and references a declared source. Its selector uses
`ctxql-evidence/v1`: either `whole_document: true` or
`utf8: {"start": 0, "end": 12}` (zero-based, half-open byte offsets, with
`start <= end`), optionally supplemented by a positive one-based `page`.
These external-source selectors are curator-declared references: their shape is
validated, but source length, UTF-8 boundaries, and optional `quote`/`note` text
cannot be independently verified without the original source bytes. They are
retained and hash-bound, never promoted to verified grounding or read grants.

## Admission, retry, and output

The canonical import and exact ontology provenance determine the import identity.
Claims are lowered through normal claim-centric semantic admission in batches of
at most 64. Each batch freezes its validation capture before admission. Repeating
identical canonical input resumes recorded checkpoints or reconstructs the same
receipts; it does not intentionally create duplicate claims.

The whole file is **not one atomic transaction**. If a later batch fails, earlier
committed batches remain committed. Retrying identical input is the supported
recovery operation. Whitespace and object-key ordering do not change canonical
identity; changing canonical content (including array order) does. A changed
import is not an upsert or correction of earlier claims and can create distinct
claims for equal triples.
The command returns nonzero on any error and never reports successful partial
completion.

On success stdout is canonical JSON with schema
`ctxql-structured-claim-import-result/v1`, `status`, deterministic `import_id`,
entity and claim counts, and ordered `admissions` and `projections` arrays.
Each batch has an admission receipt. Intermediate `projections` entries are
`null`: only the final batch waits for projection. Its non-null receipt records a
completed generation through the final committed capture, encompassing preceding
batches; it does not imply separate projection receipts for each batch. Receipt
release is subject to fresh current authorization. No model/provider call occurs.
Raw Semantic/Control writes, missing ontology prerequisites, stale authorization,
truncation, exhausted limits, cancellation, and deadline expiration fail
explicitly. Cancellation and deadlines are cooperative at fenced boundaries:
an already-started native operation is awaited rather than abandoned, so exit can
occur after the configured deadline. No successful partial receipt is returned.
