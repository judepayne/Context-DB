---
name: read-loan-agreement
description: Read a document classified as a loan agreement and extract its key parties, roles, facility terms, dates, economics, repayment terms, and governing law with exact source evidence.
---

# Read a loan agreement

Use this generic loan-agreement extraction skill only after the main acquisition prompt classifies the current full supplied document as a `loan agreement`. Apply it to the whole document, not only its title, opening page, one clause, or another apparent section. Follow the main prompt's exact legacy and typed fact-block grammar and evidence rules without repeating or weakening them.

## Reading method

1. Read the full document, including its title, opening paragraph, parties section, definitions, facility provisions, interest provisions, repayment provisions, and governing-law clause where present.
2. Build a private checklist of explicit facts before emitting anything.
3. Extract each requested, source-supported fact even when no ontology term is available. Ontology availability is never a condition for factual output.
4. Keep facts atomic and independently supported. Preserve directionality, legal distinctions, negation, conditions, exceptions, scope, and other material qualifiers in the predicate or object using exact source wording.
5. Optionally use `ctxql_ontology` for bounded, read-only, advisory mapping. Do not require a lookup, do not let a mapping replace the source wording, and never invent or emit an IRI, class token, or property token.
6. Attach one exact, single-line source quote and its host-issued line ID to every fact. Never generate an ID or use fuzzy evidence.

## Priority facts

Look for these facts in order across the full document. The document may explicitly support only a subset.

### Agreement identity and type

- The document's explicit agreement or facility-agreement type.
- The agreement date, only when stated as a concrete date.
- The agreement's own name or designation when explicit.

Do not treat a filename, editorial heading, or quick-start description as a legal term unless the supplied document itself presents it as document content.

### Parties and roles

Identify each explicitly named party and its explicit role, including:

- borrower;
- lender;
- facility agent or administrative agent;
- security agent or trustee;
- arranger;
- guarantor;
- obligor;
- other explicitly defined finance party.

Preserve directionality. A statement that an entity is a borrower does not support reversing the relation or calling it a lender. Preserve the exact role stated by the source; do not weaken a specific borrower or lender role to generic party status. Use each legal name exactly as stated. Do not silently merge affiliated companies, funds, agents, trustees, or similarly named entities.

For a relationship between two parties whose endpoint roles are both explicit, prefer the main prompt's `TYPED_FACT` form. Supply each party's plain-text role and its own exact line/quote evidence independently from the relation evidence. The same line/quote may be reused only when it explicitly proves each use. Never infer an endpoint role or emit an ontology IRI, class token, or generated type identifier. If either endpoint role lacks direct evidence, retain the supported relationship in legacy `FACT` form.

### Facility and commitment

Look for:

- facility type, such as term loan, revolving facility, bridge facility, or syndicated facility;
- total commitment or facility amount;
- currency;
- tranches or sub-facilities;
- availability period;
- purpose or permitted use of proceeds;
- minimum utilisation amount and utilisation limits.

Preserve amount and currency wording together when needed to retain the source meaning. Do not convert, round, calculate, reformat, or silently remove punctuation from a source value.

### Interest and fees

Look for:

- fixed interest rate;
- reference rate and margin;
- default interest;
- interest period;
- capitalisation of interest;
- commitment, arrangement, or other fees.

Distinguish a fixed rate from a margin over a reference rate. Do not combine percentages that play different contractual roles. Do not infer a numeric rate from prose that gives only a calculation method. Preserve conditions and qualifiers that determine when a rate or fee applies.

### Repayment, maturity, and cancellation

Look for:

- stated maturity or termination date;
- repayment schedule;
- repayment on the termination date;
- amortisation;
- prepayment rights or requirements;
- cancellation;
- whether repaid amounts may be reborrowed.

A relative rule such as “three years after first utilisation” is not a concrete calendar date. Preserve it as the contractual wording; never calculate a date without the required source event date. Preserve negatives and conditions, such as an amount not being available for reborrowing, instead of turning them into an unqualified positive fact.

### Security, guarantees, conditions, and law

Look for:

- guarantees and guarantors;
- security or secured status;
- conditions precedent to utilisation;
- explicit events of default only when the document states them;
- governing law and jurisdiction.

Do not infer security merely because the document is a finance agreement. Do not convert a purpose involving another financing structure into a security claim.

## Evidence discipline

- Ground every relation in one host-issued line and one exact contiguous quote copied from that same line.
- In a typed block, separately ground each endpoint role in its stated host-issued line and exact contiguous quote.
- Each quote must be single-line and directly prove the relation or endpoint role for which it is supplied.
- Never paraphrase, normalize, repair, widen, or approximately match evidence.
- A heading may provide context but does not by itself prove a detailed term.
- Do not use source-reference commentary as evidence unless that commentary itself is part of the supplied document being classified.
- Do not infer omitted party roles, dates, amounts, currencies, rates, conditions, or legal effects.
- Do not generate line IDs, fact IDs, ontology identifiers, coordinates, byte ranges, or JSON.

## Final quality check

Before emitting, verify privately that:

- classification and extraction covered the current full document;
- every fact is explicitly supported and atomic;
- subject and object direction is correct;
- party roles are not weakened or swapped;
- exact values, negation, conditions, exceptions, and qualifiers are preserved in source wording;
- every relation and endpoint-role evidence quote is an exact single-line substring of the line named by its host-issued line ID;
- typed blocks contain explicit, independently evidenced roles for both endpoints, with no inferred or model-authored ontology identifiers;
- no supported priority fact was omitted merely because ontology mapping was absent;
- every block exactly matches the main prompt's legacy or typed fact grammar; and
- no reasoning, classification label, checklist, IRI, generated ID, coordinate, JSON, or skill text appears in the final output.
