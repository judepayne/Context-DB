---
name: ctxql-ontology
description: Investigate optional CTXQL vocabulary definitions, classes, properties, roles, and available hierarchies without turning ontology guidance into instance facts.
---

# CTXQL ontology guidance

Ontology is optional guidance for interpreting a question or extraction. It is not a prerequisite for querying source-backed claims. If no vocabulary is configured, continue with explicit claim predicates and disclose that ontology guidance was unavailable. If configured vocabulary cannot be verified, report that failure rather than pretending it was absent.

Use `ctxql_ontology` only for the host-supported bounded operations. Search by relevant source wording or concept, then describe exact IRIs returned by the host. Inspect definitions, property kind, domain/range, format notes, restrictions, and exposed hierarchy links. Hierarchy discovery guides selection; it does not imply that query execution performs OWL reasoning.

For a broad category question, try a small, deliberate family of ontology search terms, not repeated entity-name searches: e.g. `party`, `legal entity`, `organization`/`organisation`, `company`, `trust`; examine borrower/lender/agent as roles separately. For addresses explore `registered address`, `mailing address`, `service address`, and `address`. Describe promising returned IRIs and inspect hierarchy before choosing actual instance predicates/classes. Use at most a few useful alternatives; a denial or capacity error is not a cue for more synonyms.

`search` takes a nonempty search string; `describe`, `hierarchy`, and `vocabulary_status` take an exact returned IRI. Vocabulary status is about that term, not a query-free global status call. Optional limits must be positive integers; omit unused fields rather than sending null.

Distinguish an entity's classification from a role it performs. An organization is not globally a Borrower merely because one agreement assigns it a borrower role. Domain and range declarations constrain a property's intended use; they do not prove that an instance relationship exists. Never invent an instance fact, IRI, mapping, or negative assertion from an ontology declaration.

Treat mappings, suggestions, and explicit classifications distinctly. Missing typing or mapping does not invalidate an authorized source-backed claim. Custom predicates and provisional mappings may remain useful evidence. Broaden deliberately to untyped claims when a type-constrained investigation would otherwise hide relevant source assertions, and explain that scope change.

The current direct vocabulary host supports only its verified public bootstrap inventories. Do not imply arbitrary or private vocabulary access, certification of every returned term, or permission conferred by a skill. A lookup denial or unsupported operation is an operational result, not proof that a term does not exist.
