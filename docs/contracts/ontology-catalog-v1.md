# Ontology catalog v1

An acquisition catalog is an immutable projection of one exact Semantic-Ledger capture activated under `ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v3-supported-subset`.

Its identity binds the exact capture, certified profile root, ordered catalog root, semantic-coverage root, and caveat root. Every term has one IRI, kind, vocabulary status, extraction-eligibility flag, superterms, domains, and ranges. Deprecated or discouraged terms cannot be extraction eligible.

The provider tool is bounded and read-only. Tool answers are advisory; the host rechecks every emitted term against the same catalog capture. There is no ambient catalog, network lookup, import suppression, replacement ontology, or compile-time scope allowlist.
