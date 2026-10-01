# Trusted acquisition v1

This contract records the current trusted-acquisition boundary and its explicit compatibility behavior. Acquisition runs in the invoking `cdb` process with separate source-read/source-write, Control-mutation, Semantic-admission, provider, ontology, entity, inspection, and projection capabilities. Ordinary query service code does not receive an acquisition writer.

## Current ontology-v2 path

A configuration with `protocol = "ontology-v2"` requests the JSON-free [`ctxql-extraction-text/v1`](extraction-text-v1.md) response protocol. The configuration/protocol-family name and staged asset filenames remain unchanged. The host request explicitly binds the response protocol; parsing never guesses or falls back from malformed text to JSON. Each passage response consists of ENTITY/ALIAS/CLAIM blocks with CLAIM_METADATA and exact evidence, or exactly `NO_CLAIMS`. Suggestions remain advisory strings until Rust resolves them. The host alone owns source coordinates, document/entity/claim IDs, vocabulary authority, assertion shape, timestamps, graph selection, and admission.

### Model-normalized calendar dates

Current text instructions retain one bounded exception to source-exact attribute lexical values: the model normalizes an unambiguous complete calendar date to ISO `YYYY-MM-DD`, while retaining the original exact evidence quote and noting the conversion in `Fit note:`. No new wire field or Rust normalization is introduced. Ambiguous/incomplete dates and unresolved relative rules are not guessed or calculated. Other values remain source-exact. A verified ontology date entity and compatible value property are required: Commons `hasDateValue` uses an ISO date string despite its `xsd:string` range; `xsd:date` applies only where the selected property permits it. This is an advisory model task, not a new host guarantee that the normalized value is entailed by the quote. Existing grounding, lexical validation and admission checks remain unchanged. Historical captures are not rewritten.

The loan skill teaches bounded related-concept discovery, inspecting available definitions/constraints, small terms/date/recurrence graphs, and a verified contractual-description fallback. Supported fit requires source support, verified term semantics, compatible shape and preserved qualifications for the specific proposition; uncertain fit must identify a material gap. A verified description/inclusion of a provision can be supported without claiming its complete financial interpretation. This guidance neither forces certainty nor changes Rust's semantic/admission checks. The ontology tool uses existing operations; it does not add a neighborhood API or relax permissions.

When graph workspace is enabled for a substantive extraction, instructions require actual bounded query, draft apply, view and check calls, reserving tool budget for them. Empty query results do not prevent source-backed drafting. Permission failures cannot be bypassed; budget/timeout limits remain explicit. Existing graph patterns are advisory and a playground check is structural, not semantic certification. Tool use is assessed from the retained transcript, not assumed merely because the skill was loaded.

### Host-owned proposal component identities

As in the historical JSON v3 protocol, text ENTITY blocks retain a required, unique, nonempty `Id:` label for local references. Classification, attribute, relation and alias blocks have no model-assigned component IDs. Rust assigns deterministic proposal-local component IDs from zero-based structural positions: `host/classification/{entity_index}/{class_index}`, `host/attribute/{index}` and `host/relation/{index}`, scoped by the host passage namespace. Entity labels colliding with these reserved generated-ID forms are rejected. These are bookkeeping identities, not final claim IDs or evidence of entity equivalence. Reordering components can change their proposal-local identities; this is not semantic graph canonicalization.

Duplicate or unresolved entity labels remain errors: numbering cannot disambiguate what the model meant. Unexpected model-supplied IDs on text classifications, attributes or relations are rejected by the closed grammar, not ignored. Grounding, ontology resolution, literal checks and final admission remain unchanged.

Historical `ctxql-extraction-proposals/v2` and `/v3` JSON responses retain their original parser and ID semantics through their historical request binding. Version dispatch does not repair or reinterpret them. Any experimental text conversion must be a separately labelled derived input, never a rewrite of the captured response. Actual raw text records are retained separately from normalized internal JSON projections. Existing capture/request/asset integrity checks remain in force.

The host supplies the model with a bounded ontology briefing, source passage/ranges, prior captured document context, and only policy-permitted known-entity information. The model may propose ontology identifiers and classes; it cannot create ontology terms, execute arbitrary SPARQL, or write a ledger. Exact quotation establishes grounding, not semantic entailment.

Evaluation independently records:

1. component shape and reference validity;
2. exact UTF-8 evidence grounding, including bounded contiguous multiline ranges and selected occurrences;
3. authorized established-entity or document-local identity resolution;
4. vocabulary and property-kind resolution, including deterministic unique repairs and ambiguities;
5. literal lexical/datatype checks and source assertion mode/qualifiers;
6. semantic-fit and assertion-policy disposition; and
7. review, business-admission, and projection states.

A bad component does not erase valid siblings. Unknown classes retain reviewable mentions without a false ontology type. Negative, conditional, hypothetical, attributed, uncertain, unresolved-object, and unsupported-qualifier proposals do not become an unqualified positive edge. Suggestions and host resolutions remain distinct.

Classification is source-backed but does not require the class label or an affirmative role phrase to occur literally. Multiple eligible classifications for one entity become independent evidenced `rdf:type` claims. Extracted types remain distinguishable from established and reasoner-derived types. Representative endpoint metadata is not a complete class list and does not itself assert a native type.

Supported typed literals include the closed implemented lexical spaces for string/language string, integer, exact decimal, boolean, date-time, and `xsd:date`; a property must authorize the corresponding object shape. RDFS domain/range can support diagnostics/inference but is not treated as a general transaction-rejection constraint.

## Modes and persistence

Ontology disposition and assertion policy are independent:

| Evaluation | `accepted` | `evidence-only` |
|---|---|---|
| `hard` | admit only grounded, uniquely resolved, faithfully representable positive ontology claims | persist the same review evaluation; no business claims |
| `soft` | eligible mapped claims plus versioned provisional lowering where supported | persist review evaluation; no business claims |

Soft claims are CTXQL provisional claims, not ontology declarations, and do not inherit FIBO hierarchy/domain/range semantics merely from suggestion text. Mode and assertion policy enter evaluation identity. One immutable capture can be evaluated under different modes without changing its model output or coordinates.

Normal ingestion first publishes content-addressed capture/outcome artifacts, then commits review records, then validates business bundles against the resulting current Semantic head. Review and business writes share one fenced writer session. Review-only, mention-only, explicit-no-claims, and all-rejected jobs can therefore complete with a review receipt and zero business claim IDs. Projection status remains independent from durable admission status.

Review RDF uses fixed host predicates in the configured review graph. Proposed predicates/classes are literal review data, never the predicate or native type of a described business triple. Review graphs and admission markers are excluded from business preparation, inference, established-entity authority, and normal claim export.

Control stores bounded content-free roots, IDs, counts, closed states and receipts. Complete proposal, source-bearing outcome, request/response and result content belongs in the immutable source/evidence store under inherited policy. Credentials, private reasoning, and unrestricted tool transcripts are never retained.

## Extract-only and replay

`cdb ingest start --extract-only` runs conversion, capture and evaluation ephemerally. It writes no configured Semantic, Control, projection, durable source/evidence, review, or business admission. It cannot be combined with `--wait`. Its response may contain sensitive source/model text and is bounded; overflow fails rather than inventing a durable reference.

Authenticated stored replay accepts only a capture root registered by existing acquisition work. It verifies the embedded single- or multipassage manifest, retained source/context/asset/model/ontology bindings, admitted review history, and current authority before evaluation. It never treats a self-consistent caller-supplied hash as authority and never calls Pi implicitly.

Durable `--assertions evidence-only` replay may write review admissions. `cdb ingest replay ... --ephemeral` (also spelled `--extract-only`) writes **no admissions at all**—neither review nor business—and leaves configured source/work trees unchanged. Stored PDF replay uses the verified retained original/converter/text representation and does not rerun `pdftotext`.

Pre-v3 stored passage captures without an embedded replay manifest, incomplete captures, missing artifacts, and commitment mismatches are unsupported/fail closed. Resume reconstructs only registered committed work and never fills missing passages by contacting the provider.

## Source, context, and gazetteer permissions

Source IDs, immutable versions, and exact selectors are authorized before content reads. Permission for one span does not grant a whole document. Capture and review artifacts inherit the originating exact source scope and every included context restriction; an aggregate with incompatible scopes is withheld.

Established-entity lookup is restricted to explicitly configured approved IRIs intersected with graph/class/identifier filters and the current Semantic policy at a pinned snapshot. Labels alone do not establish identity. Hidden entities, labels, identifiers, candidate counts, and protected gazetteer context cannot influence a released response. A source-only descriptor does not authorize gazetteer context; protected mixed artifacts are withheld rather than partially disclosed. A final current-policy guard applies at release, so revocation blocks inspection and artifact content even after ingestion.

## PDF representation integrity

For a durable PDF source, acquisition stores immutable original bytes, an original-representation manifest, a converter manifest, extracted UTF-8 bytes, and a text-representation manifest linking all three. Reads rehash complete objects. Evidence selectors bind the extracted text version and exact text object; provenance retains the original PDF and converter identity. Converter or text substitution breaks the chain. This verification is representation integrity, not a claim that Poppler performed OCR or that extracted text is semantically complete.

## Legacy and historical execution

When `protocol` is omitted, configuration intentionally selects deprecated `legacy-v1`. That path retains atomic FACT/`EVIDENCE` foreground parsing and existing strict CLAIM APIs and fixtures. It does not accept ontology-v2 IRIs/classes through the old grammar, does not gain durable v2 review semantics, and is never used as fallback for malformed v2 output.

Historical capture/recording schemas, fixture commitments, and Fluree `603974f` descriptors remain decodable for archival verification. The current Fluree 4.2.1 process does **not** execute a recording that requires the historical backend; it returns the explicit historical-executor-unavailable result. A known old ledger has only been demonstrated read-only on a disposable copy. Write compatibility/migration is not inferred; current writes use fresh stores or an explicit operator-run export/reimport process.

The current implementation has focused unit/integration coverage for this contract. This document does not claim the active plan's full paid-provider, governing-document/holdout acceptance evidence or final manual review is complete.
