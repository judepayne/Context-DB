---
name: ctxql-query
description: Build and refine bounded read-only CTXQL queries using verified entities, predicates, explicit-label landing, filters, and complete-result diagnostics.
---

# Query CTXQL

A query follows `about` → `bounds` → optional `walk` → optional `filter` → return. The `ctxql_graph_query` tool expects the CTXQL object serialized in its `query` string field; it does not accept SPARQL or a nested object. Use only capabilities reported by the host. The restricted graph tool permits exact and bounded approximate landing plus configured stored-predicate and lexical mappings; it denies custom/native executable predicates, external functions, prepared interpretations, reasoning, ontology mappings, and writes. A stored custom relationship IRI is ordinary claim data, not an executable custom predicate, and remains queryable.

Discover actual IDs and predicates before relying on them. Exact IDs must come from the user or verified authorized discovery; example URNs below are placeholders, never facts. Approximate Semantic landing searches authorized explicit string-valued `rdfs:label`, `skos:prefLabel`, `skos:altLabel`, and Commons `https://www.omg.org/spec/Commons/Designators/hasTextualName` claims when the selected lexical configuration supports them. It does not search arbitrary identifiers, types, property values, or document text, and extraction-local names are not automatically stored labels. Equal labels can identify different entities, so inspect candidates rather than assuming identity. If label landing is unavailable, use a verified exact ID or state the limitation.

These examples are mirrored by `fixtures/conformance/graph-workspace/query-examples-v1.json` and compiler-tested with its published lexical configuration.

### exact-party
```json
{"about":[{"from":["urn:party:example"],"match":"exact"}],"bounds":{"max_depth":1,"seed_limit":1,"fanout_limit":4,"max_claims":16,"path_limit":8}}
```

### name-or-identifier
```json
{"about":[{"from":["Example Borrower"],"match":"approximate"}],"bounds":{"max_depth":1,"seed_limit":4,"fanout_limit":4,"max_claims":16,"path_limit":8}}
```

### incoming-borrower-role
```json
{"about":[{"from":["urn:party:example"],"match":"exact"}],"bounds":{"max_depth":2,"seed_limit":1,"fanout_limit":8,"max_claims":32,"path_limit":16},"walk":{"direction":"incoming","predicates":[["meta:relation","=","urn:relation:borrower"]]}}
```

Directions are `incoming`, `outgoing`, or `both`. Useful configured metadata fields include `meta:claim_id`, `meta:subject_id`, `meta:object_id`, `meta:relation`, `meta:subject_type`, `meta:object_type`, `meta:claim_type`, `meta:confidence`, `meta:grounding_level`, `meta:lifecycle_state`, `meta:transaction_time`, `meta:lineage`, `meta:ext:<key>`, and `meta:depth`. Apply traversal predicates in `walk`; use `filter` only where the selected restricted configuration supports the field and operator.

## Chat inventory and counting

When capabilities advertises `inventory: "ctxql.chat-inventory/v1"`, the same `ctxql_graph_query` tool additionally accepts the following **chat-only host envelopes**, serialized inside its `query` string. These are not CTXQL grammar and are unavailable to extraction graph tools or profile-selected chat.

First discover the explicit classes actually used:
```json
{"schema":"ctxql.chat-inventory/v1","operation":"classes","page_size":20}
```
Interpret returned IRIs with ontology search/describe. For a party inventory consider legal entities, organizations, trusts, public bodies and explicit Party classifications, not just a class literally named Party. Then enumerate a verified union (replace these placeholder IRIs):
```json
{"schema":"ctxql.chat-inventory/v1","operation":"entities","classes":["urn:verified:class"],"relations":["urn:verified:address-property"],"page_size":20}
```
`classes` is a required nonempty OR-filter of at most 32 exact class IRIs; `relations` is an optional list of at most 16 exact outgoing predicates. Related entity objects include their active literal claims in `evidence.claims`, linked by `related_literal_claims`. Discover actual address properties from ontology; preserve registered, mailing and service address distinctions. No subclass reasoning or identity merging is implied.

`total` counts distinct graph subjects across the entire authorized active explicit-type scope, not only this page. Class counts can overlap: never sum them to count a union. `entities_with_relations` counts subjects having at least one selected visible outgoing relationship, or is null if none were requested. Missing links mean no matching visible assertion, not no real-world address. Untyped parties and contractual-role-only participants are outside this count; explain that limitation and investigate role relationships separately when relevant.

One inventory chain is active at a time. Follow every `next_cursor` unchanged (including its offset), keeping the same operation/classes/relations; add it as `cursor` to the next request. Page size may be reduced (1–25) on response capacity. A page is complete, but the listing is exhaustive only when `next_cursor` is null. On `inventory_changed`, discard the old aggregate and restart; never combine pages from changed views. Every page is freshly authorized; a modified, completed, replaced or cleared cursor is invalid. Finish a chain before starting another. Counts/IRIs are not a claim that differently identified graph nodes are different real-world parties. Cite the supporting C/S tokens in `evidence`, not raw claim IDs. Count provenance is the inventory scope and `evidence.snapshot`.

## Refine without sampling

A `query_too_broad`, incomplete, capacity, timeout, or cancellation response has no usable graph handle. Never treat it as a partial result or crop it. Narrow the actual question with a more specific verified start, fewer predicates, shallower depth, lower fan-out, or tighter supported filters, and disclose the changed scope. Do not repeatedly shrink a query when even a minimal exact-ID query fails with capacity: the failure may concern internal preparation, not returned breadth. A capacity `stage` of `internal_work` or `internal_retained_bytes` identifies execution cost, not the response page size; reducing inventory page size will not lower its complete-scan cost. After one meaningful refinement still fails, report the operational blocker rather than trying synonym variants against a broken read path.

A category word is not an entity name: searching names for `Party`, `Borrower`, or `Agreement` does not enumerate instances of that class. Use ontology-guided type/relationship discovery or the advertised inventory operation.

### broad-before-refinement
```json
{"about":[{"from":["Agreement"],"match":"approximate"}],"bounds":{"max_depth":3,"seed_limit":20,"fanout_limit":20,"max_claims":100,"path_limit":100}}
```

### narrow-after-refinement
```json
{"about":[{"from":["urn:agreement:example"],"match":"exact"}],"bounds":{"max_depth":1,"seed_limit":1,"fanout_limit":4,"max_claims":12,"path_limit":6},"walk":{"direction":"outgoing","predicates":[["meta:relation","=","urn:relation:borrower"]]}}
```

## Optional classification

### typed-borrower-role
```json
{"about":[{"from":["urn:agreement:example"],"match":"exact"}],"bounds":{"max_depth":1,"seed_limit":1,"fanout_limit":4,"max_claims":12,"path_limit":6},"walk":{"direction":"outgoing","predicates":[["meta:relation","=","urn:relation:borrower"],["meta:subject_type","=","urn:class:LoanAgreement"]]}}
```

Use a verified explicit class only where relevant. A missing classification must not hide otherwise useful assertions. Deliberately remove the type constraint to include untyped/provisional assertions, explaining that the scope has broadened; the replacement still includes typed assertions.

### untyped-borrower-role
```json
{"about":[{"from":["urn:agreement:example"],"match":"exact"}],"bounds":{"max_depth":1,"seed_limit":1,"fanout_limit":4,"max_claims":12,"path_limit":6},"walk":{"direction":"outgoing","predicates":[["meta:relation","=","urn:relation:borrower"]]}}
```

Empty results mean no matches in this authorized bounded query and scope, not that the assertion is false. Typed and untyped claims can coexist; do not make classification mandatory unless the question truly requires it.
