# Semantic RDF claims — `ctxql-semantic-rdf/v1`

Status: current alpha contract. This document specifies the RDF subset accepted by the semantic-ledger adapter. It does not claim support for all RDF 1.2 reification, all Fluree deployments, or a production writer.

## 1. Scope and vocabulary

The semantic ledger is heterogeneous RDF. Ordinary assertions, ontology/configuration statements, and reifiers not owned by CTXQL may coexist with CTXQL claims. Only an explicit IRI reifier that has `rdf:type ctxql:Claim` and satisfies this entire contract is a traversal claim.

The versioned POC namespace is:

```turtle
@prefix ctxql: <https://ctxql.example/semantic-rdf/v1/> .
@prefix rdf:   <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .
```

`ctxql-semantic-rdf/v1` is the codec/profile identifier; it is not an RDF namespace alias. Implementations compare expanded IRIs. Prefix spelling has no semantic effect.

The reserved CTXQL registry is closed:

| IRI local name | Kind | Cardinality on a marked reifier | Value |
|---|---|---:|---|
| `Claim` | class marker | exactly 1 `rdf:type` occurrence | the object `ctxql:Claim` |
| `relationType` | predicate | 1 | IRI |
| `subjectType` | predicate | 1 | IRI |
| `objectType` | predicate | 1 | IRI |
| `claimType` | predicate | 1 | IRI other than the marker role |
| `confidence` | predicate | 1 | exact `xsd:decimal` in `[0,1]` |
| `groundingLevel` | predicate | 1 | one governed value below |
| `lineage` | predicate | 1 | canonical `rdf:JSON` |
| `extensions` | predicate | 1 | canonical `rdf:JSON` object |
| `validTime` | predicate | 0 or 1 | `xsd:dateTime` |
| `sourceObservedAt` | predicate | 0 or 1 | `xsd:dateTime` |
| `ClaimOnly` | governed value | n/a | grounding value |
| `SourceLineageAvailable` | governed value | n/a | grounding value |
| `SourceSpansAvailable` | governed value | n/a | grounding value |
| `superseded_by` | lifecycle edge predicate | n/a | target claim → replacement claim |
| `contradicted_by` | lifecycle edge predicate | n/a | target claim → contradicting claim |
| `retracted_by` | lifecycle edge predicate | n/a | target claim → lifecycle event |

Any metadata predicate in this namespace not listed above makes a marked claim malformed. Extra `rdf:type` values and annotations in non-CTXQL namespaces are permitted if they do not create ambiguity, alter the attachment target, or violate configured bounds. They are ordinary RDF and are not copied into `CandidateClaim.ext`.

The lifecycle relations used by the existing core model retain their exact core spellings `ctxql:superseded_by`, `ctxql:contradicted_by`, and `ctxql:retracted_by`. The codec maps the RDF IRIs `ctxql:superseded_by`, `ctxql:contradicted_by`, and `ctxql:retracted_by` in the namespace above to those core relation strings. Those three relation IRIs are reserved for lifecycle assertions and are not metadata predicates.

## 2. Claim shape and graph placement

A conforming claim consists of one asserted ordinary edge, one Fluree 4.2 edge annotation with an explicit IRI reifier, and the complete metadata body:

```turtle
:alice :knows :bob ~ :claim1 {|
    a ctxql:Claim ;
    ctxql:relationType :SocialRelation ;
    ctxql:subjectType :Person ;
    ctxql:objectType :Person ;
    ctxql:claimType :ObservedRelationship ;
    ctxql:confidence "0.8"^^xsd:decimal ;
    ctxql:groundingLevel ctxql:SourceLineageAvailable ;
    ctxql:lineage "{...canonical JSON...}"^^rdf:JSON ;
    ctxql:extensions "{}"^^rdf:JSON
|} .
```

The governed configuration graph selects a finite set of claim graphs at the captured semantic transaction. Requests, artifacts, and local service configuration cannot add, remove, or redirect that set. The base edge, attachment, marker, and metadata of a claim must occur in the same selected named graph. Default-graph claims are eligible only if the governed set explicitly identifies the default graph. A reifier split across graphs, or an attachment whose edge graph differs from its metadata graph, is malformed.

A marked reifier must:

- be an absolute IRI, never a blank node;
- have exactly one live attachment target while active;
- reify exactly one RDF edge `(subject, predicate, object, graph)`;
- use an IRI subject and predicate;
- use an IRI or exact RDF literal object; and
- not reify another annotation in this profile.

The adapter uses public Fluree edge-annotation/`rdf:reifies` behavior. Fluree's internal `f:reifies*` facts and sidecar indexes are not portable contract fields.

## 3. Mapping to the core claim model

| Core value | Authoritative RDF source |
|---|---|
| `claim_id` | reifier IRI |
| `subject_id` | attached edge subject IRI |
| `relation` | attached edge predicate IRI, with the lifecycle mapping above |
| `object_id` | attached edge object, preserving IRI or exact literal identity |
| `relation_type` | `ctxql:relationType` |
| `subject_type` | `ctxql:subjectType` |
| `object_type` | `ctxql:objectType` |
| `claim_type` | `ctxql:claimType` |
| `confidence` | `ctxql:confidence` |
| `grounding_level` | `ctxql:groundingLevel` |
| `lineage` | decoded `ctxql:lineage` JSON |
| `ext` | decoded `ctxql:extensions` JSON object |
| `valid_time` | optional `ctxql:validTime` |
| `source_observed_at` | optional `ctxql:sourceObservedAt` |
| `transaction_time` | Fluree attachment assertion history |

Fluree 4.2 commit metadata may carry finer-than-millisecond wall-clock precision while the portable CTXQL `Timestamp` is millisecond based. The adapter deterministically projects commit history in ascending `t`: truncate the backend wall clock to milliseconds, then apply the CTXQL monotonic-clock rule `max(observed_ms, previous_projected_ms + 1)`. Missing commit time/history, duplicate marker assertions, or a marker retraction fails closed; capture time and the Unix epoch are never substitutes.

IRI lexical identity, named-graph identity, literal datatype IRI, lexical value, and language tag are preserved. The decoder must not infer an entity from a literal or normalize an IRI. Language-tagged literals retain their language identity. Numeric literal handling must not pass through binary floating point.

`subjectType` and `objectType` are claim metadata only. They do not assert endpoint `rdf:type` edges. Endpoint typing requires separate ordinary RDF assertions; source-attributed type assertions require separate complete claims. Native ontology reasoning may derive types independently.

## 4. Exact values and canonical JSON

`confidence` has exactly datatype `xsd:decimal`, a valid decimal lexical form, and mathematical value from zero through one inclusive. Exponent notation, `xsd:double`, `xsd:float`, NaN, infinity, and conversion through a host float are rejected. The codec retains an exact decimal value according to the CTXQL numeric contract.

Both JSON properties have datatype `rdf:JSON`. Their lexical form must already equal the UTF-8 CTXQL canonical serialization of the decoded value under `ctxql-canonical/v1`; semantically equivalent but noncanonical JSON is rejected rather than rewritten during read. Duplicate object keys, invalid Unicode, nonfinite or lossy numbers, and values over configured depth/count/byte limits are rejected.

- `lineage` must match schema `ctxql.lineage.v1` and the existing grounding rules. An empty source array is valid only for `ctxql:ClaimOnly` where the core contract permits it.
- `extensions` must decode to a JSON object. It may be empty. Reserved core keys remain subject to the core model contract.

The semantic codec requires both JSON properties even though retained non-semantic wire decoders may provide defaults.

Each timestamp is an exact `xsd:dateTime` accepted by the core timestamp rules and normalized to UTC millisecond precision when projected. A timestamp with invalid calendar/offset syntax, leap second, nonzero submillisecond precision, or out-of-range year is malformed. Neither optional timestamp supplies transaction time.

## 5. Admission and immutability invariants

A trusted external semantic writer creates a claim in one transaction containing:

1. the base edge;
2. its explicit-IRI attachment;
3. the `ctxql:Claim` marker; and
4. every required metadata statement.

CTXQL's semantic adapter is read-only and does not provide this writer. Observation of a partially created marked claim is a conformance failure, not a pending claim to skip.

After admission, the attachment target and every required or optional profile value are immutable. Reasserting the same explicit ID with the same complete content may be idempotent. The same ID with changed metadata, graph, or target is malformed. Corrections use a new claim IRI. Metadata removal and later restoration do not erase the invalid historical transition.

Writers must not add an indistinguishable independent bare support for the same edge inside a claim-managed graph. RDF set semantics cannot later distinguish that support from the edge maintained for annotations.

## 6. Lifecycle and edge support

A lifecycle transition is itself an independently identified, complete claim. Its edge subject is the target claim IRI. Its object is:

- the replacement claim IRI for `ctxql:superseded_by`;
- the contradicting claim IRI for `ctxql:contradicted_by`; or
- an immutable lifecycle-event IRI for `ctxql:retracted_by`.

Self-reference and literal lifecycle objects are invalid. Referenced claims/events must satisfy the existing core lifecycle dependency rules. The lifecycle claim's attachment assertion time is the lifecycle transaction time; it never replaces the target claim's original transaction time.

Transition behavior is:

| Transition | Target attachment | Base edge |
|---|---|---|
| superseded | retract in the same transaction that appends the lifecycle claim | retain while another active support exists; otherwise retract |
| retracted | retract in the same transaction that appends the lifecycle claim | retain while another active support exists; otherwise retract |
| contradicted | retain | retain |

Required target metadata remains in history and is never rewritten. A target is detached only when exactly one matching lifecycle transition explains it. Detachment and transition must share one Fluree transaction. Removing one of several active attachments must preserve sibling attachments and the base edge. Removal of final active support must remove the base edge without removing unrelated support.

Projection emits a non-lifecycle claim as one `ExportRecord::Claim`. A lifecycle claim emits one `ExportRecord::Lifecycle`; its existing `claim()` view supplies the admitted lifecycle claim. It must not also be emitted as a duplicate ordinary record.

## 7. Live and historical decoding

At one exact semantic capture `(ledger identity, t, full CID)`, the adapter reads the governed claim-graph set and applies finite row, byte, page, query-time, metadata, and JSON limits.

For a live marked claim, exactly one live attachment and exact metadata cardinalities are required. For a detached historical target, bounded public history must prove:

1. exactly one original attachment target and graph;
2. the attachment assertion transaction and its backend-authored time;
3. immutable complete metadata at admission;
4. one authorized lifecycle transition explaining detachment; and
5. same-transaction detachment and required base-edge support behavior.

Caller-authored transaction metadata is never authoritative. History validation compares attachment assertion time with marker/profile-metadata assertion time, rejects any later marker or profile-metadata mutation, rejects retargeting, and requires the lifecycle attachment plus target detachment in one transaction. Contradiction is valid only while the target attachment remains live. Missing/pruned history, ambiguous original targets, unexplained detachment, malformed sibling/final-support cascade, or exhausted history bounds fails with a stable history/unavailable error; current state is not substituted.

## 8. Authorization unit

A claim occurrence is authorized independently. Its attachment, target edge, marker, and complete required metadata form one indivisible disclosure dependency. Partial visibility cannot produce a partial `CandidateClaim`.

For a base edge with multiple active supports, the proposition may enter the authorized reasoning view if and only if at least one active supporting claim is visible to the principal. That does not disclose hidden sibling IDs or metadata. If every active support is hidden, the edge and conclusions derived solely from it must be absent before reasoning. A visible bare edge in a claim-managed graph cannot bypass this support test. Ontology/configuration/import closure is authorized as one complete bundle, never axiom-by-axiom pruning.

The authorized reasoning view is sealed as a bounded canonical manifest and materialized into a fresh per-execution in-memory Fluree sandbox. Only admitted propositions, separately authorized ordinary RDF, and the complete authorized ontology bundle enter it. Fluree's direct reasoner receives the sandbox, never the unrestricted semantic view. The sandbox is not claim or semantic authority, creates no claim provenance, is not shared or persisted, and is destroyed on success or failure.

Historical capture fixes what existed; current semantic policy separately decides whether it may be used now. The manifest binds the exact capture, principal/action, policy basis, visible-support selection, graph scopes, component roots/counts, algorithms, limits, and reasoner identity. Recorded receipts are evidence, not credentials. Current checks are repeated after extraction/reasoning and at disclosure and release boundaries.

## 9. Failure behavior and bounds

Only a reifier marked `rdf:type ctxql:Claim` enters this decoder. Ordinary RDF and unmarked or sparse reifiers are not malformed claims and never become traversal candidates. Once marked, a claim is all-or-error: missing, duplicate, malformed, cross-graph, ambiguous, conflicting, anonymous, unknown-reserved, mutable, unsupported, or over-limit state invalidates preparation before traversal or effects. The adapter never truncates or silently skips a malformed marked claim.

Diagnostics use stable reason classes, deterministic bounded details, and no protected RDF payloads. Applicable classes include claim profile/configuration/history invalidity and `semantic_history_unavailable`. Raw backend errors and hidden sibling identities are not public diagnostics.

Configured limits cover claim graphs, annotation rows, metadata facts and bytes, exact JSON bytes, historical events, pages, query duration, and decoded output. Exhaustion is failure, never partial success.

Protected completeness evidence commits the deterministic extraction algorithm, semantic hard bounds, graph-role scope, and the terminal empty-page proof required for replay. Actual page, row, and byte counts are private operational telemetry: they are excluded from `protected_completeness`, `ExecutionManifestRoot`, and recorded semantic equality. Changing query batching alone therefore cannot change semantic roots; changing an authorized member or a committed completeness bound must.

## 10. Mapping authority

Before sealing the authorized manifest, the complete historical ontology/import bundle is checked
against `ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v2`.
The v2 profile admits only structures proven against the pinned direct reasoner: hierarchy,
domain/range, inverse and property characteristics, equivalent class, same-as, property chains,
reference-valued keys, supported restrictions, intersection/union/reference one-of, and exactly
native numeric-one maximum cardinalities. It rejects unsupported neighbors such as
`owl:equivalentProperty`, complement/disjointness, datatype reasoning, literal has-value/one-of/key
members, and other cardinalities. Harmless metadata remains in the complete bundle commitment but
not the reasoner projection. Unknown application IRIs remain open.

Stable Fluree `_:fdb-…` identities are accepted only for ontology structure and are scoped by graph
and exact capture before deterministic sandbox mapping. Arbitrary blank labels and all blank-node
claim/business/policy/configuration identities remain invalid. RDF collections must be complete,
nonbranching `rdf:first`/`rdf:rest` spines; list-index-only storage is not treated as an executable
list. Cross-graph structure, cycles, duplicate/missing facets, unsupported shapes, or incomplete
imports fail the entire bundle before C0. The sealed descriptor separately commits the complete
bundle, profile result, exact reasoner input, mapping algorithm, and limits.

Inferred public facts may contain exact literals copied by the direct reasoner. Their lexical form,
datatype IRI, and optional language are represented exactly as for asserted values; structural
sandbox identities are excluded. This matrix is revision-bound direct-materializer compatibility,
not complete OWL 2 RL/DL or external-ontology/FIBO certification.

Captured resolved configuration is authoritative for mapping definitions. Stored and reasoned
mapping values are derived solely from authorized captured members and the bound prepared ontology.
A computed mapping may invoke only an exact, protected Control-Ledger artifact in the closed local
resolver registry. Requests, current defaults, recordings, and caches cannot redefine a historical
mapping. The v4 mapping descriptor commits definitions, resolver identities, values/counts, capture,
and prepared root without embedding RDF.

The current history availability mode is exact-point proof. A successful requested t/CID probe says
nothing about older unprobed commits or a global retention horizon. Every detached history event and
replay point consumed must be opened and CID-checked within bounds; retention is an operator/source
responsibility.

## 11. Explicit non-guarantees

This POC profile does not support traversal over ordinary unreified RDF or sparse reifiers, blank-node claim identities, unasserted propositions, arbitrary triple-term values, multi-target reifiers, annotation-of-annotation, inferred-fact claim/proof provenance, remote imports, or production concurrent-writer governance. Fluree-derived facts may answer bounded ontology or mapped-field operations but never become `CandidateClaim`s.
