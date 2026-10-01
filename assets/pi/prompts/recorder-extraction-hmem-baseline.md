Task: record_fragment or record_fragment_batch

hmem stores source-backed knowledge in this audit chain:

Document -> Fragment -> Evidence -> Memory -> Claim

Key terms:
- Document: the original ingested file.
- Fragment: a small chunk of that document. You only extract facts supported by the current fragment.
- Evidence: an exact, unique substring copied from the fragment body. This is the audit anchor.
- Memory: a short plain-English factual statement, with markup/formatting removed for clarity.
- Claim: a graph edge derived from a memory: subject --predicate--> object. Claims make the knowledge graph joinable.

Your job:
For each fragment, create clear memories and source-faithful graph claims. Return text blocks only. hmem will parse them, map evidence to byte spans, create JSON/entities/links, and validate everything.

Workflow for each fragment:
1. Read the `source_fragment_card` body as the source. Use front matter only for scope/context.
2. Extract every distinct durable fact the fragment supports — a large fragment often contains many. Skip filler and restatements, but never merge several distinct facts into one memory.
3. Write one memory per fact in plain English.
4. Choose evidence: copy the exact raw substring from the fragment body that best supports the memory.
5. Write one or more claims that reconstruct the memory as connected graph edges.

Evidence rules:
- Evidence must be copied exactly from the fragment body.
- Copy bytes as they appear: never add escape characters (write `.\target`, not `.\\target`), never re-wrap or reflow lines, never normalize quotes or dashes.
- Quote raw Markdown, HTML, or other source format exactly as shown, including links, tags, code tags, emphasis markers, punctuation, and line breaks when they are part of the support.
- Do not quote rendered text. If the body has `<strong>Batch mode</strong> (<code>meld run</code>)`, evidence must include that raw HTML, not `Batch mode (meld run)`.
- Use longer evidence when a short quote is ambiguous.
- Evidence must contain substantive human-readable support. Do not use markup-only, tag-only, structural-only, or whitespace-only evidence.

Memory rules:
- Make each memory atomic: one fact, relationship, behavior, setting, command, requirement, status, or procedure step.
- Preserve important names, commands, paths, numbers, thresholds, qualifiers, and directionality.
- Remove formatting/markup from the memory text itself. Keep the memory easy for a human to read.
- Example use cases, scenarios, and recommendations stated by the source are durable facts; attribute each to the feature or mode it illustrates.
- For numbered steps, bulleted lists, and table rows, extract each item's distinct fact — do not collapse a list into one memory.
- If a fragment has no durable factual content, output `NO_MEMORIES` for that fragment.

Claim rules:
- Claims are graph edges: `subject | subject_type | predicate | object | object_type | confidence`.
- Confidence is optional; omit it if unsure.
- Each graphable memory should have a connected claim bundle that lets the memory be reconstructed.
- Within one memory's claim bundle, every claim must share its subject or object term with another claim in the bundle (a single-claim bundle is fine). If a second claim would not connect, split the memory or leave the bundle as one claim.
- Within one memory's claim bundle, use a consistent entity type for the same subject or object term. Do not make `src/main.rs | path | ...` and `src/main.rs | component | ...` in the same bundle; choose one type or split into separate memories.
- Prefer precise source-faithful predicates such as `loads`, `matches`, `writes`, `starts`, `accepts`, `returns`, `finds`, `scores`, `documents`, `stored_at`.
- Use `has_property` mainly for scalar/literal values: commands, paths, versions, ports, thresholds, booleans, IDs, exact status labels.
- Stable entity types include: project, component, feature, mode, method, command, artifact, document, module, concept, threshold, score, pipeline_stage, property_value, tutorial, path.
- Do not output separate `entities`, `relations`, `spans`, or `source_assertions`; hmem creates those.

Valid-time rules:
- Set memory/claim `valid_time_start` and `valid_time_end` only when the evidence text explicitly provides domain validity, or when the input source fragment explicitly has valid-time fields.
- Use `CLAIM_JSON` for any claim with valid-time fields.
- Use `METADATA` JSON for memory-level valid-time fields when the whole memory has a clear window.
- Do not infer valid time from ingest time, current date, file timestamps, copyright dates, release dates, headings, section titles, or vague wording.
- `valid_time_start` means the memory/claim became true in the domain.
- `valid_time_end` means the memory/claim stopped being true, expires, is deprecated, or is no longer valid in the domain.
- If only one boundary is stated, emit only that boundary.
- Use RFC3339 timestamps. For date-only evidence, normalize starts to `YYYY-MM-DDT00:00:00Z` and ends to `YYYY-MM-DDT23:59:59Z`.
- If a memory block would contain claims with different valid-time windows, split it into separate memories; otherwise leave memory-level valid time unset and set valid time only on claims.
- Treat “deprecated on DATE” as a new status claim starting on DATE, e.g. `API v1 --has_status--> deprecated`, unless the evidence explicitly says a prior support/active claim ended.
- If no explicit validity is provided, omit valid-time fields.

Context/special cases:
- If the `hmem-ontology-vocabulary` skill is loaded and `hmem_ontology` is available, call it exactly once before returning any `MEMORY:` or `CLAIM:`. Use the skill's guidance. If there is clearly no durable content, output `NO_MEMORIES` without a tool call.
- `graph_context`, if present, is advisory only. It is never evidence.
- Implicit document subject rule: if the fragment uses context-dependent terms like “this project,” “the CLI,” “the config,” “your config,” “both modes,” “the server,” “the binary,” or “the tool,” resolve the implicit subject from `source_document` metadata/title when clear.
- Prefer anchoring such claims through the document/project subject instead of leaving abstract nodes isolated. Example: for “You define a list of match fields in your config,” write `Melder config --defines--> match fields`, not only `match fields --has_property--> defined in config`.
- If later claims mention fields, weights, scores, modes, commands, or datasets, connect them back to that anchor when source-supported.
- `html_block`: treat HTML tags as structure/emphasis/code/list cues. Do not make claims about HTML itself unless the syntax is the topic.
- `link_index` or `navigation`: extract documentation/resource relationships from labels and destinations, not facts about Markdown syntax.
- Add sequence metadata only for source-supported ordered procedures, timelines, lifecycles, causal flows, priority orders, numbered steps, or operational pipelines.

Output format:
- Your final answer must begin with `FRAGMENT:`, `MEMORY:`, or `NO_MEMORIES`.
- No prose, explanations, Markdown fences, or comments around the blocks.
- For batch requests, output one `FRAGMENT: <source_fragment_id>` section for each input fragment.

Use this block shape:

MEMORY:
plain-English memory
EVIDENCE:
exact unique raw substring from the fragment body
CLAIM:
subject | subject_type | predicate | object | object_type | confidence
CLAIM:
subject | subject_type | predicate | object | object_type
---

Escapes:
- Use multiple `EVIDENCE:` lines when a memory needs multiple snippets.
- If evidence contains a line exactly equal to `---`, `MEMORY:`, `EVIDENCE:`, `CLAIM:`, or `METADATA:`, use `EVIDENCE_JSON: "exact quote"`.
- If a claim field contains `|`, or you need non-default claim_kind, linked_assertion_ids, valid times, metadata, or sequence metadata, use `CLAIM_JSON:` with a JSON object or array.
- Use `METADATA:` with a JSON object for memory-level fields such as `valid_time_start`, `valid_time_end`, and `valid_time_source`.

Temporal examples:

MEMORY:
Melder has been production grade software since 2025-01-20.
EVIDENCE:
Since 2025-01-20, Melder is production grade software.
CLAIM_JSON:
{"subject":"Melder","subject_type":"project","predicate":"has_property","object":"production grade software","object_type":"property_value","confidence":0.9,"valid_time_start":"2025-01-20T00:00:00Z","metadata":{"valid_time_source":"evidence_text"}}
METADATA:
{"valid_time_start":"2025-01-20T00:00:00Z","valid_time_source":"evidence_text"}
---

MEMORY:
Melder v1 is supported until 2027-09-27.
EVIDENCE:
Melder v1 is supported until 2027-09-27.
CLAIM_JSON:
{"subject":"Melder v1","subject_type":"component","predicate":"has_property","object":"supported","object_type":"property_value","confidence":0.9,"valid_time_end":"2027-09-27T23:59:59Z","metadata":{"valid_time_source":"evidence_text"}}
METADATA:
{"valid_time_end":"2027-09-27T23:59:59Z","valid_time_source":"evidence_text"}
---

Examples:
- Memory: Batch mode loads both datasets.
  Claim: `Batch mode | mode | loads | both datasets | dataset`
- Memory: Batch mode writes result CSVs.
  Claim: `Batch mode | mode | writes | result CSVs | artifact`
- Memory: Live mode starts an HTTP server.
  Claim: `Live mode | mode | starts | HTTP server | component`
- Memory: Melder is a high-performance record matching engine.
  Claim: `Melder | project | is_a | high-performance record matching engine | concept`
