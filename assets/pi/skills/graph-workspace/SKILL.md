---
name: graph-workspace
description: Use the extraction-only private graph workspace for immutable imports, source-backed drafts, references, hypotheses, checks, and final extraction preparation.
---

# Extraction graph workspace

Use `ctxql-query` for CTXQL syntax and refinement guidance. This skill owns only the extraction workspace workflow. `ctxql_graph_query` supplies authorized complete read-only context; `ctxql_graph_playground` holds private working state. Neither tool admits business facts. Imported records are immutable `EXISTING` context; draft entities and claims are `PROPOSED`; references, identity hypotheses, and questions are `WORKING`. Imported facts are not evidence from the current document.

## Tool-call shapes, not final output

First inspect the draft with `{"operation":"view","view":"overview"}` to obtain its revision. Then adapt this small draft: replace `0` with the current revision, both SOURCE labels with source-backed labels, and HOST_RANGE with actual issued range handles. Use the shown predicate only after verifying it. Temporary IDs are batch-local; use returned handles later.

```text
{"operation":"apply","expected_revision":0,"idempotency_key":"provision-draft-1","edits":[{"op":"add_node","temp_id":"agreement","local_id":"entity-agreement","label":"SOURCE_AGREEMENT_NAME","evidence":["HOST_RANGE"]},{"op":"add_node","temp_id":"provision","local_id":"entity-provision","label":"SOURCE_PROVISION_NAME","evidence":["HOST_RANGE"]},{"op":"add_claim","temp_id":"includes","subject":{"kind":"temp","id":"agreement"},"predicate":"https://spec.edmcouncil.org/fibo/ontology/FND/Agreements/Contracts/hasContractualElement","object":{"kind":"record","record":{"kind":"temp","id":"provision"}},"evidence":["HOST_RANGE"],"fit_note":"Affirmative inclusion of a source-stated provision; its conditions/prohibitions stay in the clause content."}]}
```

After success, inspect with `{"operation":"view","view":"changes"}` and validate with `{"operation":"check"}`. These are tool calls, not prose or final output. If no imported graph is useful, the private source-backed draft remains available. Construct final ENTITY/CLAIM text separately with exact evidence; the workspace never submits it.

## Required playground workflow

When the host enables this capability and the document contains supported extraction candidates, you must actually use the tools before final text. Reading skills or describing a hypothetical draft is insufficient. Reserve at least six calls from the shared budget for one narrow query, optional import, initial view, draft apply, view, and check. Do not consume the entire budget on ontology exploration. An explicit `NO_CLAIMS` result for a nonmatching document does not require a dummy draft.

1. Follow `ctxql-query` to query narrowly. A successful complete result has a session-bound graph handle.
2. `import` a useful complete graph before referring to imported nodes. Keep within the live-graph limit; `release_graph` only when no active draft depends on it.
3. Call `view` with `view: overview`, then use one atomic `apply` with that revision and a fresh idempotency key. Add a useful small draft (e.g. two source-backed entities and a supported edge, or a provision and its exact description). Do not build the entire final output if a representative draft suffices; stay within edit/state limits. Only use a predicate verified in the briefing or lookup. If none is verified, add source-backed nodes and a question rather than inventing one. Never edit imported records.
4. After successful apply, call `view` (overview, neighbourhood, changes or open_questions), then `check`. Address actionable findings with a bounded correction and another check if budget permits; otherwise retain explicit unresolved issues. A `view_partial` marker means display omission, not an incomplete loaded graph. Checks are structural diagnostics, not semantic approval or evidence that a fact is true.
5. Identity reuse requires host eligibility. Keep label-only or ambiguous matches as hypotheses; visibility does not approve an IRI.
6. Defined references need separate definition and membership evidence. Preserve partial or unresolved status rather than inventing members.
7. If no useful query matches exist, continue source-only drafting; do not skip apply/view/check. Correct an invalid request shape once. For denial, timeout, or exhausted budget, do not circumvent permissions or retry indefinitely; use available context and state any material limitation in the affected Fit note. Never claim tool use that did not occur.
8. Produce the `ctxql-extraction-text/v1` final ENTITY/ALIAS/CLAIM blocks with CLAIM_METADATA and exact evidence. Only ENTITY blocks have model-assigned Id labels; Rust owns other component identities. End every block with `---`; include required note lines. Final output is text, never JSON. Tool arguments and the shared CTXQL examples still use JSON transport; do not copy that syntax into the final extraction response. Do not submit handles, workspace records, or graph metadata, and do not assume drafts are automatically submitted.
