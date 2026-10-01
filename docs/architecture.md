# Context DB architecture

## Status and boundaries

This document describes the current public alpha. Future structured-source and assembly work is isolated in [the roadmap](roadmap.md).

Context DB implements CTXQL over a claim-centric graph. A claim is independently identified and can carry evidence, provenance, transaction time, optional valid time, lifecycle state, confidence, and extension metadata. Equal subject/predicate/object values do not force claim identity, and conflicts are not silently collapsed.

CTXQL follows `about → bounds → walk → filter → return`. It is not a general SPARQL endpoint. Rust owns language semantics, authorization, state, identity, grounding, and admission. Model output and TypeScript tools are untrusted proposals, not authority.

## Data ownership

| Component | Current role |
|---|---|
| Semantic ledger | Authoritative claims and the semantic policy/configuration needed to interpret them. Ordinary claims and acquisition review records use separate graph roles. |
| Control ledger | Published query/configuration/profile artifacts, credentials and operation authorization, query recordings, and coordination metadata. It is not Semantic data authority. |
| Ontology ledger | Separately bootstrapped, pinned vocabulary used for acquisition guidance. Loaded vocabulary is not automatically a certified reasoning profile. |
| redb projection | Derived, rebuildable traversal data. It is never an independent business authority. |
| Private source store | Content-addressed source bytes, extracted representations, conversion manifests, and protected evidence/artifacts. |
| Pi provider | Isolated external extraction/chat process using verified assets and host-controlled tools. |

The workspace embeds Fluree 4.2.1 at revision `82dbcec3e435d6ed1d45bc0ed929432323b6b201`; no external Fluree server is required. Dependency versions are pinned by `Cargo.lock`.

## Query and replay

The service authenticates the caller, resolves exact published artifacts, captures an authorized data view, compiles CTXQL, and executes a bounded traversal. Inaccessible claims and label supports cannot affect landing, ranking, traversal, inference, or serialization. Semantic and Control authority are checked in their respective domains.

A recorded execution binds the query, plan, configuration/profile, data snapshot, policy dependencies, and result identity. Replay reconstructs that execution under current permission; it is not a fresh query against current data and never bypasses revocation. Unsupported or unavailable historical native state fails explicitly.

## Acquisition

1. Resolve an allowed local, folder, or HTTPS source and retain or temporarily stage exact bytes.
2. For PDF input, run the explicitly configured converter and bind its executable/options to the extracted-text representation. This is not OCR.
3. Issue host-owned evidence coordinates and bounded document context; optionally provide authorized ontology and graph context.
4. Run Pi with a verified profile, model, prompt, skills, and tool closure.
5. Parse proposals, verify evidence, resolve eligible identities and mappings, and construct host-owned claim identities.
6. Return an extract-only report or retain review evidence and admit eligible business assertions through the ordinary writer/recovery path.

The current final model syntax is [`ctxql-extraction-text/v1`](contracts/extraction-text-v1.md). Exact evidence is retained. Only unambiguous complete calendar dates may be normalized while preserving their source quote; relative or ambiguous dates are not silently calculated. `hard|soft` ontology disposition and `accepted|evidence-only` assertion policy are independent.

Graph-assisted acquisition offers an authorized read-only CTXQL query tool and a private draft playground. Imported facts remain immutable; drafts, references, and identity hypotheses are not authoritative writes. Whole-document graph mode fails when its limits are exceeded—there is no silent excerpt or partial graph handle.

## Chat

`cdb chat` is a TTY-only, read-only, ephemeral streaming interface over provisioned resources. It uses verified ontology, query, and answer skills and independently authorized graph/source tools. It does not admit claims, publish artifacts, record queries durably, persist chat, or replay conversations. New protected reads use current authorization; content already displayed or retained in the in-memory conversation is not retroactively erased after revocation. See [`chat-v1`](contracts/chat-v1.md).

## Workspace

| Path | Responsibility |
|---|---|
| `crates/cdb-core` | Backend-neutral model, canonical encodings, evidence, storage/policy contracts, recordings. |
| `crates/cdb-engine` | Frontends, compiler, profiles/configuration, predicates, bounded authorized execution and query replay. |
| `crates/cdb-backend-fluree` | Embedded authoritative Semantic/Control storage, policy, ontology, reasoning, publication and recovery. |
| `crates/cdb-projection-redb` | Derived traversal generations and coordination. |
| `crates/cdb-acquisition` | Source/proposal contracts, windows, grounding, validation and evaluation. |
| `crates/cdb-provider-pi` | Verified Pi transport, tools and extraction parsers. |
| `crates/cdb-source-store` | Immutable source objects and representation chains. |
| `crates/cdb-service` | Application composition, authentication, CLI/HTTP/query/acquisition/chat services. |
| `crates/cdb-testkit` | Shared reference backends and conformance/integration support. |
| `assets/pi` | Production prompts, skills, profiles and extension tools. |
| `fixtures/conformance` | Current contract and conformance fixtures. |

## Non-negotiable invariants

- No model suggestion, graph handle, hash, historical visibility, or cached view grants authority.
- Current permission checks apply to new graph, source, artifact, and replay reads.
- Missing prerequisites and exhausted ceilings fail explicitly; they do not produce successful partial results.
- Provider/native blocking work stays off asynchronous executor threads and remains bounded/cancellable at host boundaries.
- Existing stores and retained source evidence are never casually initialized, reset, migrated, or pruned.
