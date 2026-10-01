# Context DB contributor guide

## Product

Context DB is a Rust alpha for evidence-backed, claim-centric knowledge graphs queried with CTXQL. CTXQL uses `about → bounds → walk → filter → return`; this is not a general SPARQL service. Current behavior is defined by source, tests, and versioned contracts under `docs/contracts/`. Future Iceberg/assembly work is explicitly separated in `docs/roadmap.md`.

Claims retain independent identity, provenance, evidence, transaction time, and supported temporal/lifecycle metadata. Equal triples may remain distinct and conflicts may coexist. Rust—not Pi, model output, or TypeScript tools—owns semantics, authorization, grounding, identity, and admission.

## Architecture

- **Semantic ledger:** authoritative claims and Semantic policy/configuration.
- **Control ledger:** published artifacts, credentials/operation authorization, recordings, coordination.
- **Ontology ledger:** separate pinned acquisition vocabulary; loading does not certify all reasoning.
- **redb:** derived/rebuildable traversal projection, never business authority.
- **Source store:** immutable private source representations and evidence.
- **Pi:** isolated advisory extraction/chat process with verified assets and host tools.

The workspace embeds Fluree 4.2.1 at `82dbcec3e435d6ed1d45bc0ed929432323b6b201`. No Fluree server is required.

| Path | Responsibility |
|---|---|
| `crates/cdb-core` | Neutral model, identifiers, evidence, canonical forms, storage/policy contracts. |
| `crates/cdb-engine` | CTXQL frontends/compiler, profiles, predicates, execution, recording/replay. |
| `crates/cdb-backend-fluree` | Embedded Semantic/Control authority, policy, ontology, admission/recovery. |
| `crates/cdb-projection-redb` | Derived traversal generations and coordination. |
| `crates/cdb-acquisition` | Source/proposal contracts, grounding, validation, evaluation. |
| `crates/cdb-provider-pi` | Verified Pi transport/tools/parsers. |
| `crates/cdb-source-store` | Content-addressed sources and representation chains. |
| `crates/cdb-service` | Composition, config/auth, CLI/HTTP/query/acquisition/chat. |
| `crates/cdb-testkit` | Shared reference and integration support. |

## Engineering rules

- Keep inaccessible claims out of discovery, ranking, traversal, inference, and output—not only serialization.
- Current authorization governs every new protected read and replay. A hash, handle, cache entry, or historical visibility is not permission.
- Keep Semantic and Control authority checks in their own domains.
- Fail explicitly on missing pins/prerequisites, unsupported capabilities, truncation, cancellation, or exhausted ceilings; never return a successful partial graph.
- Do not initialize, reset, migrate, or prune existing stores/evidence as a side effect of tests or experiments. Use fresh disposable directories.
- Keep provider/native blocking off Tokio executor threads; preserve ownership, budgets, cancellation, and final disclosure checks.
- Preserve exact source originals and conversion/provenance chains. PDF conversion is configured extraction, not OCR.
- Backward compatibility is not a general product requirement, but supported recorded contracts and retained evidence must not be rewritten.
- Do not infer a project license from dependency licenses. Preserve `third_party/` notices and record any dependency/license gaps.

## Development and validation

Use pinned dependencies (`--locked`). Builds and native tests should run outside synchronized folders with a large stack and serial test execution. Use the checked-in staging and Cargo-serialization helpers; create a fresh staging root and evidence directory for each run, and restage after source changes. Python tests generally use `PYTHONPATH=scripts`.

Typical checks are:

```sh
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets -- --test-threads=1
cargo clippy --locked --workspace --all-targets -- -D warnings
PYTHONPATH=scripts python3 -m unittest discover -s scripts
```

For this repository's native/Dropbox workflow, run equivalent Cargo commands through `scripts/cargo_serial.py` against a fresh mirror produced by `scripts/stage_validation.py` when those helpers are present. Do not treat ignored wrapper tests as executed unless their child output is retained. Real-provider checks require explicit approval, credentials, finite cost/time bounds, and honest reporting; deterministic tests use fake or loopback providers.

Before changing behavior, read the relevant current contract and nearby tests. Make the smallest complete change, preserve unrelated worktree edits, and update contracts/fixtures together when semantics change.
