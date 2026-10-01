# Context DB terminal chat v1

Status: implemented local POC contract. This contract describes the current `cdb chat` surface; it is not a conversation-storage or replay format.

## Purpose and boundary

`cdb chat` is an interactive, read-only investigation interface over an already provisioned CTXQL instance. Pi can use host-controlled tools to inspect authorized claims, optional vocabulary and exact source evidence. Rust retains authority over configuration, identity, query execution, references, limits and authorization.

Chat does **not** ingest or admit claims, publish query/configuration artifacts, record normal query runs, modify ontology, export conversations, or provide chat replay. Local conversation persistence is off by default; the explicit diagnostic option below can retain native Pi sessions for troubleshooting. Existing ingestion, extraction replay and recorded-query replay are separate operations. Starting chat does not auto-provision ledgers, credentials, projections, a lexical configuration or published artifacts.

The process/tool isolation described here is application-level isolation, not an OS sandbox. Provider-side logging or retention is governed by the selected provider and is not disabled by local ephemeral-session behavior.

## Launch and terminal behavior

```sh
cdb chat --config /absolute/cdb.toml \
  --token-file /absolute/private-secret

# Equivalent environment fallback:
export CDB_CONFIG=/absolute/cdb.toml
export CDB_TOKEN_FILE=/absolute/private-secret
cdb chat
```

`cdb chat --help` and `cdb chat -h` print help without opening stores, authenticating or starting Pi. Chat requires both stdin and stdout to be TTYs. Startup validates configuration, authenticates the fixed principal, requires Query capability, verifies the configured published query artifacts and prepares read resources before starting Pi. There is no noninteractive/stdin batch mode.

`--config` overrides `CDB_CONFIG`, and `--token-file` independently overrides `CDB_TOKEN_FILE`. A flag for one path may therefore be combined with the environment value for the other. The selected paths must be nonempty absolute paths. A missing, relative or invalid selected value fails; it does not fall back to the other source.

The token variable identifies a file, not a bearer token. Token files are read with protected-file checks: on supported Unix hosts the path and ancestor chain must not use unsafe symlinks, the file must be a single-link regular file with mode `0600`, and replacement during the bounded read is rejected. The CTXQL token and `CDB_CONFIG`/`CDB_TOKEN_FILE` are not forwarded to Pi. The current provider credential is separate: chat passes `OPENROUTER_API_KEY`, when present, into its cleared child environment.

After startup the terminal prints the exact configured model/thinking and ontology availability. Assistant text is streamed as it arrives; thinking, raw RPC records and raw tool payloads are not displayed. Routine tool-progress events are consumed without printing read notices or repeating `cdb>`; they still count toward transport budgets. The chat-only system prompt asks for quiet investigation and concise, answer-first replies, while preserving material uncertainty and citations. Terminal control sequences are filtered. If a streamed turn fails or is cancelled, already printed text remains visible and is marked incomplete.

A small `[session cost: $0.03]` line appears beneath each completed answer and after cancellation or `/clear`. It reports cumulative provider-reported USD cost for this process, including earlier turns and cleared conversations—not just the last turn. Positive totals below one cent display `<$0.01`; larger totals are rounded to cents. Unknown accounting displays `unavailable`, never a fabricated zero. The line updates at turn boundaries rather than repainting during streaming, and is not a guaranteed final bill or prepaid spending cap.

Local controls are case-insensitive where applicable:

- `/help` lists local controls.
- `/queries` shows the exact queries and sanitized outcomes attempted in the last turn. It performs no new protected read and is not durable query recording.
- `/evidence C1` or `/evidence S1` (optional brackets) displays sanitized, retained citation metadata, including claim metadata or the source reference. It makes no provider call or fresh protected read, does not fetch source bytes, and is available during a turn. Metadata already held in the conversation is not retroactively erased by revocation; new source reads still require current permission. `/clear` invalidates these references.
- `/clear` creates a fresh in-memory Pi conversation and invalidates session-local graph/source/citation references. Process-wide usage and call ceilings do not reset.
- `quit` exits. EOF also exits. During a turn, either first cancels current host/provider work.
- Ctrl-C while idle exits; while busy it cancels the turn. Ordinary questions entered while busy are rejected rather than queued.

Cancellation clears Pi's queue and aborts, then requires bounded confirmation that Pi is idle. Shutdown closes stdin, waits the configured grace period, and kills and reaps the child if it does not exit. A failure to prove a safe idle state closes the chat rather than reusing uncertain context.

## Configuration

Chat can be present in a chat-only `ctxql-instance/v3` configuration or alongside acquisition in `ctxql-instance/v4`. See the deliberately non-runnable structural example at [`../../fixtures/examples/chat/cdb.toml`](../../fixtures/examples/chat/cdb.toml). Every placeholder store, credential, artifact binding, Pi path and optional ontology receipt must be replaced with a separately provisioned value; chat does not publish or initialize them.

The current live keys are exact:

```toml
[chat]
chat_model = "openrouter/deepseek/deepseek-v4.1-flash"
thinking = "high"
# pi-session-log-dir = "/private/diagnostics/chat"

[acquisition]
extractor_model = "openrouter/deepseek/deepseek-v4.1-flash"
thinking = "high"
# pi-session-log-dir = "/private/diagnostics/extraction"
```

Each model string includes provider and model. `thinking` is section-local and independent. `pi-session-log-dir` is also independent and optional in each section. When absent, Pi uses an in-memory session and Context DB retains no local provider transcript. When present, the directory must be absolute, must be owner-only (`0700` on Unix), and must not overlap protected stores, source roots, bundles or ontology paths. Each process creates a unique native Pi session directory plus a content-free `host-*.jsonl` lifecycle/protocol diagnostic. Context DB never resumes these sessions automatically. Native Pi JSONL can contain prompts, model reasoning, tool arguments/results and source text; protect and delete it as sensitive data. Chat prints the host diagnostic path at startup. Host diagnostics record only fixed event/outcome categories, not payloads, credentials or reasoning.

The present implementation pins both sections to exactly `openrouter/deepseek/deepseek-v4.1-flash` with `high`; there is no silent model/thinking fallback. For **live configuration only**, rename the old acquisition `model` key to `extractor_model`; chat uses `chat_model`. This migration does not rename or rewrite model fields in historical captures, recordings or retained bundle commitments.

`chat.query-config` is a required exact published artifact reference. `profile-selector` and `chat.profile` are either both absent or both present and exact. Optional `chat.ontology` identifies a previously verified supported public ontology bootstrap and exact SHA-256 of its `bootstrap.json`. Raw or private vocabulary availability is not implied by this option.

`chat.unsafe-direct-projection` is a boolean that defaults to `false`. It is an explicit opt-in only for a trusted single-user POC. When true, chat displays a conspicuous startup warning and bypasses live graph-data permission checks. Each graph query opens a native snapshot of the latest completed redb projection; the snapshot is per-query, not frozen for the chat session, may lag Fluree, and is not synchronized automatically. Startup login, the configured query credential and Query capability, source authorization, and all normal limits remain enforced. This switch affects only chat read resources, never ordinary HTTP queries or extraction. Capabilities and graph results explicitly report `graph_permissions = "bypassed_unsafe_direct_projection"` rather than claiming an authorized view.

The current redb version uses exclusive process ownership. Unsafe chat opens and releases projection and Control handles for each call; another process may update them between calls, but a concurrent owner causes an explicit failure, not fallback to a copied or older view. It selects the highest completed Semantic transaction among catalog-published generations (including completed cached generations newer than the active generation), never by filename ordering. The native transaction remains fixed for that call; a later call can select a newer completed transaction. No coordinator, rebuild or orphan cleanup runs in this path. Native redb opening/closing may perform internal allocator/header housekeeping; this is read-only at the application/claim level, not a guarantee of byte-identical index files. The projection's commit identity and cutoff are still verified against Fluree. Lexical landing and ordinary claim traversal are supported; Semantic stored-predicate mappings are explicitly unavailable in this mode because the projection does not replace the original RDF interpretation data. Source bytes still require the normal protected source tool; graph metadata itself is unfiltered and may include quoted evidence.

### Current default ceilings

All ceilings are finite. Except for conversation context, settings may only be tightened below these defaults; service limits can clamp applicable reads further. `chat.limits.max-context-bytes` accepts **1–67,108,864 bytes (64 MiB)** independently of its 512 KiB default; changing it within the supported range requires a chat restart, not another build. This host byte budget does not increase the provider model's own context window.

| Area | Current default ceiling |
|---|---:|
| user input / answer | 8 KiB / 64 KiB per turn |
| user turns / model rounds | 20 / 100 per process |
| turn / host call / shutdown | 300 s / 10 s / 2 s |
| RPC record / queue / events | 1 MiB / 2 MiB / 16,384 per turn |
| graph nodes / claims / retained complete graphs | 50 / 100 / 3 |
| tool calls | 40 per turn, 200 per process |
| graph queries | 12 per turn, 60 per process |
| tool request / response | 32 KiB / 64 KiB |
| all tool responses | 1 MiB per turn |
| retained host state / conversation context | 2 MiB / 512 KiB |
| one source span / all source bytes | 16 KiB / 64 KiB per turn |
| citations / work | 4,096 / 1,000,000 |
| provider-reported tokens / cost | 1,000,000 / 5,000,000 micro-USD per process |

The token ceiling is cumulative throughput across the process, including repeated cached context, not the model's context-window size. Multi-page inventory turns may send the growing context many times; the configurable conversation byte ceiling remains separate. The whole-turn deadline includes both provider and host-tool time. `/clear` does not reset process-lifetime usage/cost budgets.

On an incomplete turn the terminal prints a closed, sanitized stop reason (for example cumulative token limit, whole-turn deadline, provider failure or protocol failure) before the cost footer. Terminal failures that close the chat then produce the generic CLI exit error; a recoverable context/output-limit event returns to the prompt instead. Provider messages, stderr, raw RPC payloads and unknown internal limit strings are never echoed. `session cost: unavailable` means final accounting is unknown; it does not by itself identify which limit or failure occurred. There is no automatic paid retry.

Malformed and failed calls consume applicable tool/query budgets. Limit, timeout, overflow and unknown final provider usage fail closed. A provider-reported context-length stop can offer `/clear` when the process remains safely idle with known usage. Exceeding the host's hard conversation-byte ceiling closes the process; start a new chat in that case. History is never silently compacted or truncated. Provider token/cost fields are provider-reported accounting used as a stop condition, **not** a reservation, invoice check or billing cap; an upstream provider can charge differently or report late. If final usage is missing or invalid, usage becomes unknown and no further prompt is accepted.

## Skills and tools

Chat eagerly composes exactly three verified shared skills: `ctxql-ontology`, `ctxql-query` and `ctxql-answer`. It exposes only `ctxql_capabilities`, `ctxql_ontology`, `ctxql_graph_query` and `ctxql_source`. It does not load the extraction-only `graph-workspace` or loan-reading skills and has no shell, arbitrary filesystem, web or write tool.

Graph-enabled extraction reuses the ontology/query guidance but keeps its private extraction workspace and loan guidance. Its playground drafts and hypotheses are not chat state and are not authoritative claims.

Ontology is useful but optional. Without configured verified public ontology, explicit-ID and untyped/custom-predicate graph queries remain possible. Name landing is only the engine's configured authorized lexical behavior over explicit string-valued `rdfs:label`, `skos:prefLabel`, `skos:altLabel` and Commons `https://www.omg.org/spec/Commons/Designators/hasTextualName` claims. It is not arbitrary-property, identifier, type, source-text or embedding search. Exact IDs must come from the user or verified discovery; example URNs must not be guessed. Chat does not add OWL inference or promise arbitrary aggregation/global exhaustive search.

## Bounded chat inventory

When `ctxql_capabilities.inventory` is `ctxql.chat-inventory/v1`, `ctxql_graph_query.query` also accepts a serialized chat-only inventory envelope. This is not CTXQL language syntax and is not enabled in extraction or profile-selected chat.

```json
{"schema":"ctxql.chat-inventory/v1","operation":"classes","page_size":20}
```

`classes` lists explicit active `rdf:type` classes with distinct subject counts. For an entity union use `operation: "entities"`, `classes: ["verified-class-IRI", ...]` (1–32), and optionally `relations: ["verified-predicate-IRI", ...]` (0–16). Page size is 1–25, default 20. Unknown/duplicate fields and invalid bounds fail closed.

The host executes a complete bounded one-hop scan through the ordinary engine and publication/authorization fences, not raw unfiltered ledger access. Internal scan ceilings are 2,048 nodes, 4,096 claims/paths, the caller's work/deadline limits (chat defaults to 1,000,000 work units, still clamped by service limits), and the ordinary bounded internal working budget. Overflow yields no count or partial inventory. Known engine work/retention failures include a safe `stage` (`internal_work` or `internal_retained_bytes`) with the `capacity` diagnostic, never raw internal errors or hidden counts. General graph queries now separate 10,000 internal records (clamped to work) and 16 MiB canonical retained working bytes from their unchanged 50-node/100-claim/64-KiB output defaults. Private inventory encoding/parsing separately allows 16 MiB, depth 64, 1,000,000 values and 32,000,000 canonical work units, rather than the small-result canonical defaults. These are operational bounds, not guaranteed process heap limits.

An inventory page includes `total`, sorted `entries`, `offset`, `page_complete`, `next_cursor` and compact supporting `evidence` with ordinary C/S tokens. Entity counts deduplicate subjects, not names or claim IDs, and do not merge real-world identities. Only active explicit `rdf:type` membership is counted; no subclass inference, effective-date filter, untyped-party discovery or arbitrary aggregation is implied. Class counts overlap and must not be summed for a union. Selected outgoing relations retain every active assertion, with the related entity's active literal claims available as evidence. `entities_with_relations` counts subjects with any selected visible link; it is null when no relations were selected. Missing visible links are not negative real-world facts.

Continue with the returned `cursor`, unchanged operation/classes/relations, and optionally a smaller page size. Cursors are session-issued positions, never read capabilities. Only the last issued cursor of one active inventory chain is accepted, byte-for-byte including its offset; tampering, replay after completion, cross-session reuse, and reuse after `/clear` fail as invalid. The current cursor is charged to session state bytes; starting a new inventory replaces the prior chain. Every page reconstructs and reauthorizes the current view. A commitment to scope, snapshot, configuration and authorized active claims rejects changed-view/scope continuation as `inventory_changed`; restart rather than mixing pages. Listings are exhaustive only after `next_cursor` is null. No durable cursor, query recording or chat persistence is introduced. Output bytes, citations, source access, per-turn/process tools and state limits still apply. Compact evidence omits repeated source descriptors and most metadata from the model response; issued C/S bindings retain their full metadata/exact-source authorization semantics.

## Results, evidence and authorization

By default, each graph query uses current graph authorization and its own exact snapshot/configuration/profile bindings. In explicitly enabled unsafe direct-projection mode, the graph-data authorization check is bypassed and each query instead uses a fresh native snapshot of the latest completed redb projection, subject to the configuration and limits described above. Results preserve distinct claim IDs and conflicts. A graph is usable only when complete within the configured bounds: timeout, cancellation, truncation or overflow returns a diagnostic and no usable result handle. Refining a query changes its scope; results are never silently cropped into a sample.

Source access is independent from graph visibility. `ctxql_source` accepts only a session-issued reference associated with a visible claim and reauthorizes the exact source/version/selectors on every read. It returns the bounded exact span or a diagnostic; it does not truncate a quotation, read arbitrary files or fetch model-selected URLs. A claim can remain visible while its source bytes are denied or unavailable.

Claim tokens (`[C…]`) and source tokens (`[S…]`) are session-local references. After each answer the terminal checks recognized tokens against already-issued metadata and flags unknown tokens. Valid inline citations remain in the answer without automatic JSON footnotes; `/evidence` makes the retained metadata available on request. The chat prompt favors plain language and relevant explanations over implementation terminology, without prescribing a task-specific answer template. This validates referential existence only: a syntactically valid citation does not prove that the prose is semantically correct or that a cited claim supports the model's conclusion.

The principal is fixed at startup. Outside unsafe direct-projection mode, every new graph read refreshes applicable credentials and current authority; every ontology or source read does so in either mode. Cached handles and hashes do not bypass checks that apply. Accepted POC limitation: data successfully read before a revocation may remain on screen and in the in-memory Pi conversation, and later prose may refer to that history without a new authorization check. Revocation still governs every new protected read; unsafe direct-projection graph reads are deliberately not protected graph-data reads. `/clear` or exit drops local context but cannot erase already displayed text or any prior provider disclosure.

