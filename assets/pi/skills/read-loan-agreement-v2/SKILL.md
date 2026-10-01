---
name: read-loan-agreement-v2
description: Extract ontology-guided loan-agreement entities, classifications, typed attributes, and relations with exact source evidence.
---

# Read a loan agreement for structured acquisition

Read the complete supplied document coverage, not only the current sentence. Build one shared local entity table for the passage and reuse host document handles when supplied. Distinguish the legal agreement from a credit facility, individual loans, parties, monetary amounts, dates, rates, and legal terms.

Prioritize:

1. Agreement identity and supported classes, including whether the source meaning supports a written credit agreement or facility. A title is context; quote the wording that supports each classification.
2. Named borrower, lender, agents, guarantors, obligors, and other finance parties. Preserve exact legal names and role direction. Source meaning may support a role class without repeating its ontology label.
3. Facility kind, commitment/currency, tranches, availability, purpose, utilisation limits, interest/rates/fees, repayment, maturity, prepayment, and cancellation.
4. Security, guarantees, conditions, defaults, governing law, and jurisdiction when explicit.
5. Concrete dates only with their actual stated semantics. “Agreement date” alone is not execution, effectiveness, or issuance. A relative termination rule is not an absolute calendar date.

## Coverage before submission

Privately account for each substantive clause or bullet: represent its supported meaning in components, or identify why it remains unresolved. Do not stop after the headline names, amounts and dates. This coverage check is working bookkeeping, not a new output field.

Check explicitly for:

- utilisation conditions, including no continuing or resulting default, representations remaining true, and any materiality qualification;
- who must repay what, and when: a termination rule does not replace a separate obligation to repay each loan on that date;
- minimum draw amounts, maximum outstanding-loan counts, availability and the exceptions to each;
- interest calculation/basis, payment or capitalisation, repayment, prepayment and reborrowing permissions or prohibitions;
- conditional overrides, alternatives and scope: which agreement, facility, loan or party a term concerns.

Missing source facts stay missing. Unsupported mappings stay explicit unresolved proposals; do not omit a supported provision merely because its ontology mapping is difficult. Do not distribute a facility-level amount or obligation across individual loans or parties without evidence.

## Ontology and entity interpretation

Use ontology definitions supplied by the host before extraction. The initial briefing is a selection, not the whole available vocabulary. Before leaving a priority predicate unresolved, use `ctxql_ontology` to investigate its source wording and relevant financial concepts, within the host tool budget. Inspect candidate definitions, property kind, domain and range—not just labels. Retain genuine alternatives and uncertainty; if the budget or vocabulary prevents resolution, say so briefly in the component's `Fit note:`. Never invent an IRI or claim that a term is verified merely because it looks plausible.

Object properties require entity objects. A date class or monetary amount class is represented as an entity with its own value attribute when the ontology specifies that shape. Use literal attributes only when the verified property is datatype-valued. Prefer a coherent amount/currency, rate/basis or date structure to one untyped narrative blob when the source and available vocabulary support it.

Keep an organization distinct from its contractual role. Check whether a proposed Borrower or Lender class describes a party acting in that capacity or requires a separate role structure; follow the verified definitions and relation direction. Do not replace an organization's identity with its role. Quote the role assignment, not only the party name, when grounding that classification or relationship.

A description such as “Facility agreement” is not automatically an alias for a named agreement. Add an alias only when the source actually supplies another name or defined designation for the same referent. When reading a derived summary, distinguish the underlying agreement it describes from the summary document itself; do not infer signatures or execution from the summary's title.

Use `ctxql_entities` only to inspect host-approved possible identities. A matching label is not proof of identity. Suggest a known IRI only when identifying source context supports it; otherwise use a local entity. Never merge parties by spelling alone.

Preserve source assertion mode and qualifiers. Negative, conditional, hypothetical, attributed, semantically uncertain, or unresolved statements remain explicit proposals; do not weaken them into positive edges or invent predicate names containing the qualifier. Preserve exceptions such as “unless the available commitment is lower” and “unless the lender and borrower agree another date in writing”; a prohibition is not an affirmative permission.

## Decide fit from a concrete proposition

Use `Fit: supported` when (1) exact source evidence supports this component's actual proposition, (2) the term is verified in the supplied pinned briefing or a successful lookup and its definition matches, (3) property kind and subject/object or literal shape fit, including known domain/range and format requirements, and (4) material scope, negation and exceptions are preserved. Existing briefing metadata is usable verification; do not downgrade a verified term solely because a redundant follow-up lookup failed. Certification status alone is not uncertainty about a source statement. Missing unrelated restrictions do not require `uncertain`; a missing constraint that is material to this mapping does.

For `Fit: uncertain`, give the specific unresolved issue in `Fit note:`: missing source support, ambiguity between meanings, unverified required term, incompatible shape, unresolved reference or material missing constraint. State what would resolve it. Do not write only 'predicate verified' while marking uncertain. If verified evidence and semantics support the proposition, mark it supported rather than hedge by default. Do not invent confidence or promote a genuinely unresolved interpretation just to increase mapped counts.

Judge description separately from interpretation. A verified ContractualElement/hasLegalDescription fallback can be supported when the source clearly supplies that provision and the string copies its exact content, even if its specialized financial meaning cannot yet be modeled. 'The agreement contains this provision' and 'this provision has this description' are narrower propositions than a fully interpreted repayment, prohibition or compounding rule. Uncertainty about the latter does not automatically transfer to the former.

## Bounded discovery and small-graph construction

Before marking a priority clause unresolved, search its financial meaning as well as its wording. Use the existing `ctxql_ontology` operations `search`, `describe` and `hierarchy`, within the remaining host budget: try the source concept and at most two related concepts, inspect at most three promising candidates, and stop when a defensible match is established. Do not exhaust the budget repeating unsuccessful searches. Use exact IRIs returned by the host for describe/hierarchy queries; inspect definitions, notes, property kind, domain/range and available restrictions. Missing or incomplete constraints are not proof of compatibility.

Use `search` with keywords, for example `{"operation":"search","query":"legal description","limit":5}`. Use `describe` or `hierarchy` only with a full valid IRI returned by the host, not a label such as `hasLegalDescription`. Issue ontology calls sequentially. Treat a denial as an operational/authorization result, not proof that a term is absent: check the request shape, correct an invalid shape once, and otherwise respect the denial. Do not invent a diagnosis such as 'snapshot permission missing'. Retain verified briefing/earlier lookup knowledge, and identify only the specific mapping still blocked.

Prioritize lookups that can complete high-value source clauses rather than exploring more names or classes. Reuse results already verified in the current host-pinned context instead of repeating calls. Suggestion arrays are alternatives for the same meaning, not lists of nearby terms: `hasContractualElement` and `hasContractParty` are not interchangeable. One genuine candidate is better than unrelated padding; use the choice's `selected: none` when no candidate is justified.

Search hints, not automatic mappings:

| Clause | Concepts / candidate local names to investigate |
|---|---|
| Purpose | business purpose, objective, hasBusinessPurposeDescription |
| Availability | date period, start/end date, RelativeDate |
| Termination | hasTerminationDate, RelativeDate, isRelativeTo |
| Repayment | PrincipalRepaymentTerms, hasPrincipalRepaymentDate |
| Interest capitalisation | InterestPaymentTerms, compounding, hasCompoundingFrequency |
| Non-reborrowing | revolving credit, contractual prohibition, ContractualElement |

Treat these names as leads; verify their actual availability and meaning. ClosedEndCredit is not automatically equivalent to a ban on reborrowing. hasBusinessPurposeDescription has a CommercialLoan domain: do not conflate the facility, agreement and individual loans to use it. When a class description exposes a relevant property/restriction or superclass, follow that lead with a bounded describe/hierarchy lookup rather than guessing an IRI. If metadata does not expose the needed connection, use a related-concept search, not an unsupported tool operation.

Construct small graphs when the verified schema requires them. Illustrative shapes, not mandatory assertions:

- agreement → hasContractualElement → PrincipalRepaymentTerms → hasPrincipalRepaymentDate → termination-date entity;
- contractual availability provision → hasDatePeriod → DatePeriod → hasStartDate / hasEndDate → date entities;
- interest terms → hasCompoundingFrequency → RecurrenceInterval.

Finish one useful structure before adding more speculative nodes. For each terms, amount or date node, supply the meaningful links and values supported by the source and verified vocabulary. If a required part remains unresolved, identify it briefly in `Fit note:` or use the textual fallback; never invent values merely to complete a shape. This is a construction priority, not permission to omit other source clauses.

Quote support for every node, classification and edge. Preserve the meaning of availability, the scope of 'each loan', and the interest-period-end trigger; a generic date period or frequency alone does not encode them. Never invent a monthly frequency. Keep conditional termination overrides attached and do not promote a default rule to an unconditional fact.

If precise structured mapping is unavailable, investigate Contracts/ContractualElement, hasContractualElement and hasLegalDescription. The latter is a string-valued description of a contractual provision, not a machine-enforceable financial rule. Use the exact source clause on an evidenced provision node, retaining qualifications and source modes; do not merely attach a generic string to the wrong subject or weaken a prohibition. Complete this fallback with the actual `hasLegalDescription` attribute: a provision name plus an evidence quote alone is not the completed representation. If the fallback vocabulary cannot be verified, retain explicit uncertainty rather than asserting an invented mapping.

### Worked example: provision existence versus content

For the source clause `Repaid or prepaid amounts cannot be reborrowed`, after verifying the vocabulary:

- create an evidenced provision entity classified as `ContractualElement`;
- propose agreement → `hasContractualElement` → provision with `Source mode: affirmative`;
- propose provision → `hasLegalDescription` → the exact clause as `xsd:string`, also affirmative: this asserts the provision's description, not permission to reborrow.

The negative content remains intact in the description. If separately modeling the prohibited reborrowing action, that assertion is negative. Likewise, a conditional repayment rule does not make the agreement's inclusion of the rule conditional. Apply source mode to the proposition each component actually expresses; preserve conditions and exceptions in the clause description and on any corresponding rule/action assertions. If the source really makes inclusion itself conditional, retain that condition. Do not infer that a described rule has been triggered, performed or satisfied.

## Values, exact evidence and model-normalized dates

Keep evidence quotes exact in all cases. Keep source spelling in `Value:` except for the explicit calendar-date normalization below. You, the model, perform that normalization; Rust does not convert the value for you. Check the actual lexical value against both the datatype and the property's definition, notes and range:

- `GBP 50,000,000` is not an `xsd:decimal` lexical value. Do not remove currency/commas or extract a misleading fragment such as `50` and silently change the amount.
- `7% per annum` is not an `xsd:decimal`. A source-exact numeric substring such as `7` is usable only when it denotes the complete intended numeric value and the percentage unit and annual basis remain correctly represented. Do not silently convert it to `0.07` or lose its units.
- `five` is not an `xsd:integer`; this date-only exception does not authorize numeric or monetary normalization.
- A relative termination rule is not a calendar date. Preserve its anchor, duration and exception without calculating an unstated date.

### Calendar dates: normalize the value, never the quotation

For an unambiguous complete calendar date, emit its ISO `YYYY-MM-DD` value. Example: evidence quote `6 December 2022`, date entity named `6 December 2022`, normalized attribute `Value: 2022-12-06`. State the source-to-ISO conversion briefly in `Fit note:`. Validate month/day and leap-year plausibility; do not invent a day, month, century, time or timezone. Ambiguous `06/12/2022` stays unresolved unless the supplied source explicitly establishes the date convention. Incomplete dates and relative rules stay unresolved rather than being guessed or calculated.

Represent the date as an ontology date entity (for example, verified Commons DatesAndTimes/ExplicitDate), not merely a string attached to the agreement. Link it using a property with the actual source meaning; 'agreement date' does not establish execution, effectiveness or issuance. A concrete date can be classified as ExplicitDate even when its specific contractual role remains unresolved.

Then select a verified date-value property and its required datatype. Commons DatesAndTimes/hasDateValue declares `xsd:string` but requires ISO date content by definition: use `"2022-12-06"` with `xsd:string` on the date entity, never `"6 December 2022"` marked supported. If a different verified property requires `xsd:date`, use the normalized lexical with `xsd:date`. Do not override the declared range merely to make the datatype look more date-like. A proper ontology date entity and semantically valid value are both required.

For unsupported conversions outside this date-only allowance, retain the source value and uncertainty. Every term-choice group, including Datatype, needs one to eight genuine suggestions, each with its required note line (which may be empty). Use `Datatype selected: none`, `Predicate selected: none` or `Term selected: none` when no candidate is justified; do not omit the group or fabricate alternatives. If no defensible datatype suggestion exists, use the verified contractual-description fallback where appropriate rather than an invalid attribute. Do not add a normalization field or force an object-valued date property into a literal attribute.

Every component must have exact host-range evidence. Quotes are exact contiguous substrings with zero-based occurrence selectors. Multiple spans may support one component. Never repair source text or invent handles.

## Flexible booking and reference-resolution workflow

When graph tools are enabled, load `ctxql-ontology`, `ctxql-query`, and then `graph-workspace`; follow the shared skills and perform the workspace's required query → draft → view → check cycle before final submission. Loading skills alone is not use of the playground. Start with source-grounded names/identifiers or verified analogous structures, not the example placeholders. Import useful complete results as context, but do not cite imported facts as evidence from this document and do not reuse an identity merely because it is visible. An empty graph is a valid result: continue building the source-backed draft without imported examples. Existing graph patterns help select candidate shapes; they do not certify ontology fit or establish facts about this source.

Build a flexible private booking draft rather than forcing every document into mandatory fields:

- distinguish the agreement document, each facility and each utilisation;
- record parties with exact names, roles and explicit identifiers, keeping readable-but-unapproved or ambiguous identities local;
- record financial terms with currency, amount/rate semantics and scope;
- distinguish signing, execution, effectiveness, availability, maturity and termination dates;
- keep conditions, obligations, permissions, prohibitions and defaults qualified;
- leave missing or uncertain items as questions rather than positive facts.

Resolve defined references in their actual scope. Record definition evidence separately from membership evidence. A collective such as “Initial Lenders”, “Acceding Guarantors”, or “Finance Parties” may resolve to multiple named parties when a definition or schedule supplies them. “Original Borrowers” likewise may resolve to two or more schedule entries and is not a third borrower entity. Conversely, a genuine legal name ending in `s`, a jointly stated obligation, or an aggregate amount is not evidence of collective membership and must not be blindly distributed. Preserve partial or unresolved membership when a referenced schedule is missing.

Use neighbourhood/changes views and structural checks to inspect the draft. Identity hypotheses remain working records; they never merge entities or approve final IRI reuse. The booking template guides investigation only and does not add fields to the final response.

## Final response check

In `ctxql-extraction-text/v1`, only ENTITY blocks carry model-assigned `Id:` labels. Give each entity a unique, nonempty label such as `entity-borrower` or `entity-lender`, and reuse it in `Subject: local ...` and `Object: local ...` references. Do not put Id fields on classification, attribute, relation or alias blocks. Rust assigns component identities from their structural positions; do not invent `c1`, `c2`, attribute IDs, relation IDs or persistent claim IDs. Ambiguous entity references cannot be repaired by host numbering, so never give two entities the same label.

Before returning, check entity-label uniqueness, absence of IDs on other components, reference targets, exact evidence, predicate/object shape, lexical/datatype compatibility, source modes and retained exceptions. Recheck the coverage list above. Also check: provision inclusion is distinguished from rule polarity; each verified textual fallback includes `hasLegalDescription`; each structured node has its source-supported links/values or an explicit unresolved gap; and every suggested alternative fits the same intended meaning. `Fit: supported` is an advisory judgment about source meaning, not a substitute for these checks or proof that a vocabulary mapping is valid.

Return only the ENTITY/ALIAS/CLAIM text blocks and CLAIM_METADATA sections required by the acquisition prompt, each block terminated by `---`, or exactly `NO_CLAIMS`. Check field order, required suggestion-note lines (even empty) and every block terminator. No JSON, Markdown fences, prose, reasoning, coverage bookkeeping, workspace handles or tool transcripts.
