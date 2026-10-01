# Ontology profile v3 supported subset

Status: current supported-subset contract. The executable identity is:

`ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v3-supported-subset`

The superseded `/v3` identity is unsupported and is not an alias. Profile v2 remains unchanged.

## Classification

Every quad in an accepted exact ontology closure belongs to exactly one category:

1. **Reasoned** — covered by the pinned Fluree reasoner inventory.
2. **Inference-inert declaration** — exact IRI `rdf:type owl:NamedIndividual` declaration.
3. **Retained annotation** — an exact registered annotation predicate/object shape. It remains in the loaded bundle but is omitted from ontology C0.
4. **Retained uninterpreted semantic** — a complete exact registered component. It remains in the loaded bundle and C0 but does not authorize inference, extraction, admission, validation, or consistency claims.

Classification is source-aware, total, disjoint, bounded, and fail closed. Permission is never granted by namespace alone. Structural components move atomically; malformed, incomplete, shared, ambiguous, cyclic, unregistered, or over-limit structures fail.

The immutable Gate 1 audit remains a collecting inventory. Profile-v3 classification is a separate rooted projection and does not rewrite Gate 1 dispositions or occurrence identities.

## Certification

Analysis alone uses the candidate identity and `classification_pending_gate3`. Only evidence-bound certification may emit the executable identity and result label `fluree_supported_subset`.

Certification binds the pinned Fluree revision and limits, exact source/dependency closure, audit, four categories and occurrences, registry and components, annotation policy, reasoned-family inventory, declaration evidence, uninterpreted non-interference, applicability/parity evidence, semantic coverage, caveats, ontology C0, and executable profile root.

The executable profile manifest is canonical content-free JSON stored as one literal in the same historical configuration graph as activation. Its SHA-256 is `executableProfileRoot`; it does not contain its own root. Historical preparation verifies the manifest from the exact captured ledger without an external cache, catalog, network lookup, or official RDF bytes.

For this POC, the manifest retains the source-exact certification roots while historical execution separately roots and blindly blesses Fluree's complete stored projection. Fluree may reidentify blank nodes, lowercase language tags, or canonicalize typed-literal lexical forms. Historical execution reruns the closed classifier over that stored projection, requires unchanged total/category/C0 counts and policy identities, and binds both source and stored roots in the versioned verification root. It does not prove source-term-exact storage equivalence.

Only retained annotations are removed from the stored ontology C0. The sealed reasoner input combines authorized data with that rooted C0 and runs pinned Fluree with an empty schema overlay.

## POC scopes

The certified POC scopes are exact dependency closures rooted at:

- `FND/Relations/Relations`;
- design-selected `FND/Agreements/Agreements`.

Candidate-scoped dependency-universe v2 commits release-wide cycles and unresolved edges but rejects them when reachable from the selected closure. It does not suppress imports. Existing dependency-universe v1 behavior is unchanged.

Each complete profile is loaded in one bounded native transaction. The writer is disposed before serving, and exact `(ledger,t,CID)` preparation is reproduced after two read-only reopens. Multi-transaction bootstrap is unsupported.

## Mandatory caveats

- minimum/exact cardinalities are not enforced;
- data-range/datatype facets are not enforced;
- disjointness violations are not detected;
- uninterpreted axioms do not drive extraction/admission;
- answers may be incomplete relative to OWL/FIBO;
- absence of inconsistency is not proof of FIBO compliance;
- evidence is POC-, revision-, and profile-root-specific, not production/legal clearance;
- replay blindly blesses Fluree's complete stored RDF projection; source-exact and stored roots may differ because blank-node identifiers, language-tag case, and typed-literal lexical forms are not preserved exactly.

Engineering completion does not imply legal or deployment clearance. Fluree BUSL-1.1 and ontology licensing remain subject to independent review.
