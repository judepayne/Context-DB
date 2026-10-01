# Core model — ctxql-core-model/v1

P1 Rust constructors are validation boundaries, not credentials. Domain identifiers are lexical, nonempty control-free strings up to 4096 UTF-8 bytes. Iri requires absolute syntax without parser repairs, preserving lexical spelling. JSON uses CanonicalValue, never a floating-point or serde_json::Value intermediate; Missing is a lookup sentinel only.

## Literal and claim wire

Entity objects project to the entity ID string in meta.object_id. Literal objects project to exactly `{kind:"literal",datatype,value,language}`. Endpoints reuse that literal body; entity endpoints are `{kind:"iri",value}`. Language is null unless an rdf:langString, whose nonempty BCP47-like ASCII language tag is retained without case normalization. xsd:string uses string, boolean uses bool, integer uses an integral exact number, decimal uses an exact number. Float/double use `{format:"binary32"|"binary64",bits:<8|16 lowercase hex digits>}` with finite IEEE bits. Other datatypes retain a string lexical value, not an inferred numeric/entity value. No datatype is fabricated. Decimal mathematical equality is separate from typed literal identity.

Candidate claims require claim/subject/object identity, concrete relation and relation_type, subject_type/object_type/claim_type IRIs, confidence in [0,1] and grounding. Claim-only may omit lineage, normalized to `{schema:"ctxql.lineage.v1",sources:[]}`; stronger grounding requires sources and, for spans, exact span selectors. ext defaults to {}. Admitted claims have a transaction time assigned only through the explicitly trusted adapter constructor. There is no Deserialize for admitted claims or permission handles. ResponseClaim requires an independently supplied lifecycle state; it never assumes active.

Optional valid_time and source_observed_at project inside reserved ext key `ctxql.core.temporal/v1`, containing only the supplied timestamp fields (normalized .mmmZ). Absent fields stay absent. User ext may not set this reserved key or core metadata names. These are source semantics, not admission time, and cannot backdate admission. Lifecycle assertions are append-only and never overwrite claim data.

## Lifecycle claims

`LifecycleAssertion::new(CandidateClaim)` validates a full ordinary immutable claim, not a stored lifecycle state. Its wire/projection is exactly the candidate claim wire, retaining concrete relation, all ontology types, exact confidence, grounding, ordered lineage, extensions and optional source times. `from_value` uses the same closed candidate boundary; the former lossy `{id,target,state,replacement}` shape is not accepted. Backend-assigned transaction time remains alongside the assertion in `ExportRecord::Lifecycle` / `RecordChange::LifecycleAdded`; `ExportRecord::claim()` reconstructs the complete admitted claim without a duplicate stored identity.

Subject is the target ClaimId. The exact concrete relations `ctxql:superseded_by` and `ctxql:contradicted_by` require an entity object interpreted as `LifecycleReference::Claim(ClaimId)`; `ctxql:retracted_by` requires `LifecycleReference::Event(ResourceId)`. Self references and literal objects fail. Referenced claims must exist in staged state (including lifecycle claims); events must resolve to immutable `ResourceKind::LifecycleEvent` dependency records, with explicit nonempty facts. Event IDs, target IDs and assertion IDs are distinct. This local event representation adds no event evaluator or event-specific required fact vocabulary.

Lifecycle relations must enter admission/export/changes through the validated lifecycle wrapper, not a parallel ordinary-claim variant. The assertion occupies one shared claim/resource identity key. Ordinary claim and incident lookup include these claims, while lifecycle lookup returns the same records indexed by target. No lifecycle-state evaluation, temporal inference or default active state is performed.

## Artifact and normalized-plan identity

Artifact record keys distinguish `(iri, version)`; different versions can coexist, while conflicting content for the same pair is rejected. These keys are not claim IDs or new public hash domains. `FunctionManifest::new` authors canonical JSON content; `from_published` retains the exact verified published byte hash, even if its JSON uses different whitespace/numeric spelling.

Normalized query DTOs retain `walk.direction`, built-in predicate triples and named/custom predicate objects. Bounds retain arbitrary query-bound values as well as validated execution caps; the external-function registry remains a name-keyed object. P1 validates structural shape, not executability: merging, expression/type/capability validation and strategy resolution remain P2/P5. No operational paths, secrets or timeouts enter semantic config DTOs.

## Operational injection

Limits::default is 8 MiB input, depth 64, 100000 values, 1000000 work, 16 MiB output. Limits::new permits zero (explicit failure), depth at most 256. All bytes APIs return a complete value or error, not partial output. Numeric-v1 precision/range is fixed. Libraries read no environment or configuration file. P2 resolves semantic config/defaults; later application wiring injects operational limits independently. Trusted in-process adapters are not sandboxed by DTO constructors.
