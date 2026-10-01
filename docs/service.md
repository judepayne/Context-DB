# Context DB service guide

This guide covers the current alpha. Exact schemas and limits are in [`contracts/`](contracts/); future Iceberg and assembly surfaces are in [`roadmap.md`](roadmap.md).

## Build and command model

```sh
cargo build --locked -p cdb-service --bin cdb
./target/debug/cdb --help
./target/debug/cdb ingest --help
```

The Rust library, CLI, and local HTTP endpoint share application services and semantic responses. Commands reject unknown fields/options rather than silently supplying compatibility defaults.

Stateful commands require an explicit absolute `--config` path. Authenticated commands also require an absolute protected `--token-file`; token contents never belong on argv. `CDB_CONFIG` and `CDB_TOKEN_FILE` are independent path fallbacks, with the corresponding flag taking precedence. Invalid selected values do not fall back.

## Instance and authentication

A current `ctxql-instance/v4` configuration identifies separate Semantic and Control authorities, redb projection, private source storage, credentials, finite service limits, and acquisition settings. Optional chat settings can coexist with acquisition. Paths are resolved and checked before enabled work. Secrets remain separate from semantic configuration and provider credentials.

```sh
cdb init --config /absolute/path/cdb.toml --secret-file /absolute/path/bootstrap.secret
cdb provision --config /absolute/path/cdb.toml --secret-file /absolute/path/bootstrap.secret --request-file /absolute/path/provision.json
```

`init` creates Control-side instance state and a bootstrap credential; it does not create or reset an acquisition Semantic ledger. Provisioning publishes explicit principals, roles, policies, query configurations, and profiles. Startup never silently repairs authority or restores revoked policy.

## Query, publication, recording, and replay

Closed request files are used for ordinary operations:

```sh
cdb publish --config /absolute/path/cdb.toml --token-file /absolute/path/user.secret --request-file /absolute/path/publish.json
cdb query   --config /absolute/path/cdb.toml --token-file /absolute/path/user.secret --request-file /absolute/path/query.json
cdb replay  --config /absolute/path/cdb.toml --token-file /absolute/path/user.secret --request-file /absolute/path/replay.json
cdb source  --config /absolute/path/cdb.toml --token-file /absolute/path/user.secret --request-file /absolute/path/source.json
```

Queries resolve immutable published configuration/profile references and execute against an exact authorized view. Bounds exhaustion, cancellation, timeout, or incomplete projection returns an explicit failure rather than a cropped successful response. Recorded replay uses the original bindings and current permissions. Exact source reads have independent source/version/selector authorization; a claim read does not grant its source bytes.

## HTTP

```sh
cdb serve --config /absolute/path/cdb.toml
```

The current server exposes `POST /v1/operation` and requires one bearer credential for protected operations. It shares CLI/library contracts and limits. Loopback is the intended alpha deployment. Non-loopback binding requires the configured transport/authentication protections and must not be treated as an internet-safe default.

## Acquisition

The current grouped commands are:

```sh
cdb ingest start    --config ABS [--token-file ABS] ...
cdb ingest inspect  --config ABS --token-file ABS --request-file ABS
cdb ingest artifact --config ABS --token-file ABS --request-file ABS
cdb ingest resume   --config ABS --token-file ABS --request-file ABS
cdb ingest replay   --config ABS --token-file ABS ...
```

`start` accepts exactly one configured local file, folder, or HTTPS URL source. Folder traversal is deterministic, bounded, and non-recursive; symlinks are not followed. Durable work records checkpoints, immutable sources/representations, review outcomes, admissions, and projection progress. Retry/resume uses the registered work identity and does not implicitly call the model again.

Live acquisition uses `protocol = "ontology-v2"`, exact `extractor_model` and section-local `thinking` settings, separate claims/review graph roles, and `assertions = "accepted"|"evidence-only"`. The former live `model` key is rejected. Supported acquisition settings and graph prerequisites are specified in [`acquisition-configuration-v1`](contracts/acquisition-configuration-v1.md).

`--extract-only` performs provider evaluation without extraction admissions or durable configured source/work writes. It is distinct from durable `evidence-only`, which retains review evidence but suppresses business claims. Extract-only is not a blanket promise that opening a disposable native store has no index/setup effects.

PDF input invokes only the explicitly configured converter executable after identity verification. Original and extracted representations, converter identity/options, and source-relative evidence coordinates remain distinct. Conversion extracts embedded text; no OCR is supplied.

Replay accepts only registered supported captures and verifies retained source, ontology, context, model, bundle, request, response, and protocol commitments before evaluation. A hash is an identifier, not permission. See [`recording-replay-v4`](contracts/recording-replay-v4.md), [`graph-context-capture-v1`](contracts/graph-context-capture-v1.md), and [`source-representations-v1`](contracts/source-representations-v1.md).

## Terminal chat

```sh
cdb chat --config /absolute/path/cdb.toml --token-file /absolute/path/user.secret
```

Chat requires terminal stdin/stdout. It streams one active answer at a time, retains an in-memory conversation for follow-ups, and discards it on exit. Host commands include `/help`, `/queries`, `/evidence C1` (or `S1`), `/clear`, and `quit`. Chat performs no admissions, hidden artifact publication, durable query recording, or chat replay.

The configured Pi executable/profile/model are verified before a paid turn. Context DB credentials are never forwarded to Pi; provider credentials are supplied separately. Graph results are complete or rejected, source spans are independently authorized, and citation tokens prove only that a reference was issued—not that answer prose logically follows. Previously displayed/in-memory content can remain after revocation, while every new protected read checks current authorization. Full controls and limits are in [`chat-v1`](contracts/chat-v1.md).

## Ontology vocabulary

`cdb ontology bootstrap` creates a separate pinned vocabulary ledger from verified configured sources. Raw vocabulary availability is `loaded_uncertified`; it does not claim complete OWL support or automatically certify an acquisition profile. The business Semantic ledger, ontology ledger, and Control ledger are distinct.

## Operational safety

- Use fresh disposable stores for tests and experiments; never point another project at real data casually.
- Keep provider credentials, Context DB credentials, source content, raw model responses, and diagnostic session logs private.
- Projection is rebuildable; Semantic/Control ledgers and retained source evidence are authoritative and must not be deleted as cache.
- Native setup/index effects must be reported separately from business admissions.
- Use exact current contract versions. Obsolete recordings may be decodable without being executable on the current Fluree revision.
