# Extraction text v1 — proposed specification

**Status: implemented for new ontology-v2-family extraction requests.** This document specifies a JSON-free model response with the information content of `ctxql-extraction-proposals/v3`. The parser, skills and prompts now use this explicitly request-bound text protocol. It reconstructs a new contract from surviving historical formats; it is not a claim that this exact format was previously agreed.

## 1. Purpose and authority

Use the historical `CLAIM:`, `CLAIM_METADATA:`, evidence and `---` block conventions, but replace JSON bodies with labelled text fields. Preserve entity mentions, aliases, ontology suggestions, literal attributes, relationships, uncertainty and source evidence. A `CLAIM` block is an **advisory proposal component**, not an admitted claim.

Rust continues to own component bookkeeping IDs, persistent identities, source selectors, grounding, ontology resolution, authorization and admission. The model supplies only entity reference labels, proposed content, evidence and advisory metadata. No persistent claim IDs, source coordinates, hashes, timestamps, receipts or admission status are model output.

The host request/capture binds the response protocol to `ctxql-extraction-text/v1`. The model does not emit a schema header. Dispatch is by that explicit host binding, never by heuristic fallback from failed JSON. Existing v2/v3 JSON captures retain their original parsers and bytes.

Tool-call arguments and tool responses are outside this final-response format; they may continue to use their existing structured transport.

## 2. Document grammar

A response is either:

- exactly `NO_CLAIMS`, with no surrounding whitespace or other content; or
- one or more complete `ENTITY:`, `ALIAS:` or `CLAIM:` blocks, each terminated by a line containing exactly `---`.

Entity-only output is permitted: a source-backed mention need not have a supported class or relationship. Nonempty blocks imply `no_claims = false`; the sentinel implies true and three empty proposal arrays.

No prose, code fences, Markdown tables, JSON objects/arrays, comments or additional headings are allowed. These are Markdown-readable text blocks, **not general Markdown parsed through a renderer**.

Structural lines and field labels are case-sensitive and unindented. Blocks follow the field order specified below. Blank lines are allowed only between complete blocks. The last block may end immediately after `---` or with one final line ending. Structural line endings may be LF or CRLF; mixed line endings are invalid.

A value line is `Label: value`: exactly one ASCII space separates the colon from a nonempty value. That separator is not part of the value. An allowed empty value is written `Label:` with no trailing space. Values are literal text, not quoted or escaped strings. Quotes, backslashes, colons, pipes, braces and Unicode within values are ordinary characters. For example, `Quote: ---` is evidence text, not a block terminator. Do not apply JSON unescaping, Markdown unescaping, Unicode normalization, trimming or whitespace repair.

Values must be valid UTF-8, contain no control characters, and have no leading/trailing whitespace. This matches the current v3 parser's `valid_text` restriction. Nonempty means at least one character. Empty values are allowed only for suggestion notes and fit notes.

**Existing discrepancy:** current prompts mention multiline evidence, but the current v3 parser rejects control characters, including newlines, in all these strings. This strict text equivalent therefore uses single-line values/quotes. Multiple evidence items may cite different lines within the same host range. Supporting a single multiline or whitespace-edge quote requires an explicit subsequent contract/parser extension, not silent reformatting of source text.

## 3. Shared field groups

Angle-bracket placeholders in the following templates are explanatory, not literal output. `*`, `+` and alternatives in prose denote repetition/choice, not text to emit.

### 3.1 References

`Subject:` and `Object:` take one of these tagged values:

```text
Subject: local <entity label>
Subject: document <host-issued document handle>
Subject: known <proposed stable IRI>
```

The tag and one following ASCII space are syntax; the rest is the exact nonempty payload. Entity labels may themselves contain spaces. A local reference is passage-scoped by Rust. Document handles must have been issued by the host. Known IRIs remain suggestions and do not confer identity-reuse eligibility.

Only a relationship `Object:` may additionally use:

```text
Object: unresolved <source-grounded description>
```

A classification subject must be `local`, identifying the entity whose nested v3 classification it represents. Attribute subjects and relationship subjects/objects support the reference variants above. Forward local references are allowed; resolution occurs after reading all records.

### 3.2 Term choices

For each choice name `Term`, `Predicate` or `Datatype`, emit one to eight ordered suggestion pairs, followed by one selection:

```text
Predicate: <first proposed term spelling or IRI>
Predicate note: <brief advisory note, or empty>
Predicate: <second genuine alternative>
Predicate note:
Predicate selected: 0
```

Every suggestion requires its note line, even if empty. `selected` is a zero-based suggestion index or the literal `none`. It never refers to an ID. Empty suggestion lists, missing note lines, out-of-range selections and duplicate selection fields are invalid. Do not pad the list with non-equivalent terms. A single verified candidate is sufficient. An unresolved choice still requires at least one genuine suggestion with `selected: none`.

All integers use `0` or a nonzero decimal digit followed by zero or more decimal digits. Signs, leading zeros, decimal points and exponent notation are invalid. Values must fit the host's integer bounds.

### 3.3 Evidence

Each evidence item has exactly this group, in this order:

```text
EVIDENCE:
Range: <host-issued range handle>
Occurrence: 0
Quote: <exact contiguous source quote>
```

`Occurrence` is the zero-based exact occurrence within that specific range. Never invent a range, normalize a quote or move it to a different range. Each group contributes one evidence object. Multiple groups preserve their order.

Entities and claims permit zero to sixteen groups at the structural parsing stage, matching current v3 array parsing. **The model must supply at least one source-supporting item.** An empty evidence collection cannot pass grounding/admission. An alias requires exactly one group.

### 3.4 Claim metadata

Every claim has exactly one metadata section:

```text
CLAIM_METADATA:
Source mode: affirmative
Fit: supported
Fit note: <brief explanation, or empty>
Qualifier: <exact source-grounded qualifier>
```

Allowed source modes: `affirmative`, `negative`, `conditional`, `attributed`, `hypothetical`, `unknown`.

Allowed fits: `supported`, `uncertain`, `not_evaluated`.

For attributes and relationships, zero to eight `Qualifier:` lines follow `Fit note:`. No qualifier lines means an empty array. Classification claims do not accept qualifiers, matching their current JSON shape. Evidence groups follow the metadata section and any qualifiers, before `---`.

`Fit: supported` is advisory, not authorization or a validation result. Metadata belongs only to the current claim block. It cannot float independently or refer to another block by ID.

## 4. Complete record forms

### 4.1 Entity

```text
ENTITY:
Id: <unique local reference label>
Name: <source-grounded name>
Known entity: none
EVIDENCE:
Range: <issued range>
Occurrence: 0
Quote: <exact quote>
---
```

`Known entity:` is exactly `none` or `iri <nonempty proposed IRI>`. The `iri` tag disambiguates a value from the null marker. Additional evidence groups may follow the first. Aliases and classifications are separate records assigned to this entity as below; their absence means empty arrays.

### 4.2 Alias

```text
ALIAS:
Entity: <local entity label>
Name: <source-grounded alternative name>
EVIDENCE:
Range: <issued range>
Occurrence: 0
Quote: <exact quote supporting the alias>
---
```

`Entity:` is a local label, not a tagged reference; aliases can only attach to an entity in this response. There is no alias ID, fit metadata or additional evidence item. A description is not automatically an alias.

### 4.3 Classification claim

```text
CLAIM:
Kind: classification
Subject: local <entity label>
Term: <class suggestion>
Term note: <note, or empty>
Term selected: 0
CLAIM_METADATA:
Source mode: affirmative
Fit: supported
Fit note: <note, or empty>
EVIDENCE:
Range: <issued range>
Occurrence: 0
Quote: <exact source support for this classification>
---
```

The term group and evidence groups may repeat as specified above. No predicate, object, literal, datatype or qualifier fields are permitted.

### 4.4 Literal attribute claim

```text
CLAIM:
Kind: attribute
Subject: local <entity label>
Predicate: <datatype-property suggestion>
Predicate note:
Predicate selected: 0
Value: <literal lexical value>
Datatype: <datatype suggestion>
Datatype note:
Datatype selected: 0
CLAIM_METADATA:
Source mode: affirmative
Fit: supported
Fit note:
EVIDENCE:
Range: <issued range>
Occurrence: 0
Quote: <exact source quote>
---
```

`Value:` is text even for a numeric datatype. `Datatype:` is a term-choice group, not a raw unchecked datatype token. Qualifiers, if any, occur after `Fit note:`. Object-valued properties cannot be made literal attributes just because a narrative fits in `Value:`.

### 4.5 Relationship claim

```text
CLAIM:
Kind: relation
Subject: local <entity label>
Predicate: <object-property suggestion>
Predicate note:
Predicate selected: 0
Object: local <entity label>
CLAIM_METADATA:
Source mode: affirmative
Fit: supported
Fit note:
EVIDENCE:
Range: <issued range>
Occurrence: 0
Quote: <exact source quote>
---
```

The object may instead be a document reference, known-IRI suggestion or unresolved description. No `Value:` or datatype group is permitted.

## 5. Exact mapping to the current proposal model

| Text | Current v3 meaning |
|---|---|
| Response protocol bound by host | Distinct text wire version, normalized to the same advisory proposal types |
| ENTITY record | `entities[]`: id, name, known_entity, evidence |
| ALIAS record's Entity + Name + evidence | Owning entity's `aliases[]`: name, single evidence object |
| Classification CLAIM | Owning entity's `classes[]`: term, evidence, source_mode, fit, fit_note |
| Attribute CLAIM | `attributes[]`: subject, predicate, value.lexical, value.datatype, evidence, source_mode, qualifiers, fit, fit_note |
| Relation CLAIM | `relations[]`: subject, predicate, object, evidence, source_mode, qualifiers, fit, fit_note |
| Repeated term/note pairs + selection | Ordered `suggestions[]` and nullable `selected` |
| EVIDENCE group | range, quote, occurrence |
| Omitted repeated collection | Empty collection, not a guessed value |

No current semantic field is dropped. The grouping/parent label on alias and classification records replaces JSON nesting; it is not new graph content. No confidence field is added: it is absent from the current v3 proposal schema despite appearing in older recorder formats.

Entity order is ENTITY-record order. Alias/classification order is encounter order among records assigned to the same entity. Attribute and relationship arrays each retain their own encounter order. Interleaving record kinds does not change that rule. There is no automatic sorting or semantic deduplication.

Rust generates `host/classification/{entity_index}/{class_index}`, `host/attribute/{index}` and `host/relation/{index}` using zero-based positions in those arrays, with the existing passage-scoping behavior. Only entity labels are model-assigned. Invalid but locatable component slots retain their positions; rejection must not renumber later siblings. Valid records of different kinds may be interleaved, though emitting entities before claims is recommended.

All duplicate entity labels are invalidated; aliases/classifications cannot choose between them. Unknown, duplicate or invalid parent labels make dependent records invalid rather than causing reassignment. Reserved host-generated ID forms are forbidden as entity labels, as in v3. No fuzzy label matching, case folding, ordinal guessing or reference repair is allowed.

## 6. Evidence, date and provision semantics

All source/evidence/authorization rules remain unchanged. A name match or visible known entity is not proof of identity; graph workspace content is advisory, not document evidence.

The model may normalize **unambiguous complete calendar dates only**, retaining the original quote and explaining the conversion in `Fit note:`. Example semantic pattern:

```text
Value: 2022-12-06
Datatype: http://www.w3.org/2001/XMLSchema#string
Datatype note: Verified Commons hasDateValue range; content must be ISO date text.
Datatype selected: 0
```

This belongs to a verified date-value attribute on a separately evidenced ontology date entity, for example Commons `ExplicitDate`. Its evidence quote remains `6 December 2022`. Commons `hasDateValue` has a string range but requires ISO date content. Use `xsd:date` only where the verified property permits it. No Rust conversion, invented timezone, guessed ambiguous date, inferred execution/effectiveness role, or unstated relative-date calculation. Other literal values remain source-exact under the current contract.

Provision inclusion and description are affirmative when the source affirms them, even if the described rule prohibits an action or has conditions. Negation/conditions apply to the proposition actually expressed. Preserve full rule content and exceptions in a verified `hasLegalDescription` fallback and on any separately modeled action/rule. Do not claim that describing a rule proves it was triggered or satisfied.

## 7. Limits and rejection behavior

Default limits remain those of `ProposalLimits`; a lower host-advertised budget wins:

| Limit | Default |
|---|---:|
| Total raw response UTF-8 bytes | 262144 |
| Entity / attribute / relation records | 64 each |
| Classifications / aliases per entity | 8 each |
| Entities + classifications + attributes + relations | 256 (aliases excluded, matching current count) |
| Suggestions per choice | 1–8 |
| Evidence items per entity/claim | 0–16 structurally; at least one required for grounded output |
| Evidence items per alias | Exactly 1 |
| Qualifiers per attribute/relation | 0–8 |
| Entity label / local reference payload bytes | 128 |
| Names, known/document/unresolved reference payloads, term spellings, range handles | 1024 bytes each |
| Literal value / evidence quote | 16384 bytes each |
| Suggestion note / fit note / qualifier | 1024 bytes each |

All limits apply to UTF-8 bytes, not displayed character counts. Flat alias/claim records remain bounded by parent limits and a physical-record ceiling of 768 (256 counted components plus at most 512 aliases), even before parent resolution. Host tool/response budgets remain independent ceilings.

Unknown fields, duplicate singleton fields, wrong field order, missing required fields, invalid enums or references, invalid empty values and illegal fields for a record kind are rejected. Repetition is legal only for complete term/note pairs, evidence groups and qualifiers where specified. Never synthesize a missing `note` line, default a missing source mode, repair source text, close a truncated record or remove extra trailing content.

A complete, delimited record with identifiable kind/parent but invalid content is retained as a rejected component; valid independent siblings may survive. A bad alias/classification does not erase a valid parent entity. A bad parent prevents dependent claims from grounding/resolving against it. Unassignable parent records are retained as diagnostics, not silently dropped.

Invalid UTF-8, raw-size/global-count overflow, content outside records, unknown top-level record headers, an invalid/missing claim kind, an unclosed record, sentinel mixed with records, or ambiguous record boundaries fail the whole response. In particular, a new top-level header before `---` does not silently terminate the preceding block. Parsers must preserve raw bytes and rejection locations for inspection.

Internal capture/outcome serialization may remain JSON. The text parser must retain original record spans/bytes separately from any synthesized normalized representation; synthesized JSON must never be labelled original model output. New text evaluation pages use `ctxql-extraction-outcomes/v3`, with raw blocks in `original` and separately labelled `normalized_projection` for internal semantics. Historical JSON outcomes retain their existing representation. The request's `response_protocol` field binds text parsing; absent binding selects historical JSON behavior, and unknown bindings fail closed.

## 8. Complete illustrative response

For a host-issued range `range-1` containing `Agreement date: 6 December 2022`, and assuming the following ontology choices have been verified, this is a complete text response. `range-1` is only an example handle; real runs must use their issued handle.

```text
ENTITY:
Id: agreement-date
Name: 6 December 2022
Known entity: none
EVIDENCE:
Range: range-1
Occurrence: 0
Quote: 6 December 2022
---
CLAIM:
Kind: classification
Subject: local agreement-date
Term: https://www.omg.org/spec/Commons/DatesAndTimes/ExplicitDate
Term note: Complete calendar date; no execution or effectiveness role inferred.
Term selected: 0
CLAIM_METADATA:
Source mode: affirmative
Fit: supported
Fit note:
EVIDENCE:
Range: range-1
Occurrence: 0
Quote: 6 December 2022
---
CLAIM:
Kind: attribute
Subject: local agreement-date
Predicate: https://www.omg.org/spec/Commons/DatesAndTimes/hasDateValue
Predicate note: ISO date content with declared string range.
Predicate selected: 0
Value: 2022-12-06
Datatype: http://www.w3.org/2001/XMLSchema#string
Datatype note:
Datatype selected: 0
CLAIM_METADATA:
Source mode: affirmative
Fit: supported
Fit note: Model normalized unambiguous 6 December 2022 to ISO 2022-12-06; evidence unchanged.
EVIDENCE:
Range: range-1
Occurrence: 0
Quote: 6 December 2022
---
```

## 9. Implementation acceptance requirements

Before activation, tests must demonstrate:

1. Every valid v3 semantic field has a text round-trip, preserving collection order, reference kinds, null selections, empty notes, aliases and evidence occurrences.
2. Literal pipes, quotes, backslashes, colons, braces and structural-looking values round-trip without escaping or accidental record boundaries; Unicode byte limits and structural LF/CRLF rules are exercised.
3. Duplicate/missing fields, missing notes, malformed references, sentinel misuse, unknown headers, extra trailing content and truncated blocks fail at the specified scope; no silent repair.
4. Bad alias/classification/component isolation and generated IDs remain deterministic despite invalid slots, interleaving and forward references; duplicate parents never cause reassignment.
5. Source-exact grounding, date lexical checks, ontology checks, current authorization, graph-context restrictions and admission still operate after normalization to the internal proposal types.
6. Captures bind the explicit text protocol and verified assets, preserve the actual raw text, and replay deterministically without interpreting historical JSON as text.
7. Skill, system/acquisition prompts, request instructions, fixtures and verified asset tests agree on this one format. No new final-output JSON request remains in the activated text path.
8. A live extract-only test reports syntax failures, grounded components, mapped proposals and admissions separately. JSON-free output is not itself proof of semantic correctness.

## Historical and current sources

- `assets/pi/prompts/ctxql-acquisition-v1.md`: FACT/TYPED_FACT, exact evidence, NO_CLAIMS and block delimiters.
- `crates/cdb-provider-pi/tests/parser.rs`: historical CLAIM/CLAIM_METADATA framing, whose bodies were JSON.
- `assets/pi/prompts/recorder-extraction-hmem-baseline.md`: earlier pipe-delimited claims and evidence; its MEMORY/JSON extensions are not adopted here.
- `assets/pi/prompts/ctxql-acquisition-v2.md` and `assets/pi/skills/read-loan-agreement-v2/SKILL.md`: current v3 fields, interpretation and date/provision instructions.
- `crates/cdb-acquisition/src/proposals.rs` and `crates/cdb-provider-pi/src/proposal_protocol.rs`: authoritative current field shapes, bounds, reference checks and generated-ID behavior.
