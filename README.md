# Context DB

Context DB (`cdb`) is a local Rust alpha for acquiring, querying, and replaying evidence-backed claims with the CTXQL query language. Claims retain independent identity, provenance, source evidence, transaction time, and supported lifecycle metadata; conflicting assertions can coexist.

This repository is a technical alpha, not a hosted service, a general SPARQL endpoint, legal or financial advice, or a complete OWL reasoner. Structured Iceberg sources and Context Product assemblies are roadmap work, not current features.

## Build

Prerequisites:

- the Rust toolchain selected by `rust-toolchain.toml`;
- Python 3 for repository utilities;
- Node.js and Pi 0.87.1 for model-backed acquisition or chat;
- optional `pdftotext` (Poppler) for text-bearing PDFs; no OCR is provided.

No separate Fluree server is needed. The workspace embeds Fluree 4.2.1 at revision `82dbcec3e435d6ed1d45bc0ed929432323b6b201`.

```sh
cargo build --locked -p cdb-service --bin cdb
./target/debug/cdb --help
```

For large/native test runs, build outside synchronized folders and use the checked-in staging and serial-Cargo helpers described in [`AGENTS.md`](AGENTS.md).

## Current use

All stateful commands use an explicit absolute instance configuration path. Commands that authenticate also use a protected token file; a token is never supplied directly on the command line.

```sh
./target/debug/cdb init --config /absolute/path/cdb.toml --secret-file /absolute/path/bootstrap.secret
./target/debug/cdb query --config /absolute/path/cdb.toml --token-file /absolute/path/user.secret --request-file /absolute/path/query.json
./target/debug/cdb ingest --help
./target/debug/cdb chat --config /absolute/path/cdb.toml --token-file /absolute/path/user.secret
./target/debug/cdb serve --config /absolute/path/cdb.toml
```

For commands accepting both inputs, `--config` and `--token-file` independently override `CDB_CONFIG` and `CDB_TOKEN_FILE`. The environment variables contain paths, not configuration or token contents. Invalid selected values fail rather than falling back.

Acquisition can read configured local roots, HTTPS sources, or folders. PDF conversion must be explicitly configured with the converter path and identity. Pi output is advisory: Rust grounds evidence, resolves eligible identities, applies authorization, and owns admission. `--extract-only` performs evaluation without extraction admissions. Terminal chat is TTY-only, read-only, ephemeral, and operates over an already provisioned instance.

Finance-demo setup lives in the separate `cdb-demo` directory/repository: its
`scripts/load_fibo.py` and `scripts/load_parties.py` own ontology acquisition and
curated client/party seeding. This repository retains the native implementations
and pinned fixtures required by Rust; it does not require a demo checkout to build
or test.

See:

- [`docs/architecture.md`](docs/architecture.md) — current system and trust boundaries;
- [`docs/service.md`](docs/service.md) — current CLI, HTTP, configuration, acquisition, replay, and chat behavior;
- [`docs/contracts/`](docs/contracts/) — versioned implemented and compatibility contracts;
- [`docs/roadmap.md`](docs/roadmap.md) — future P7–P9 work, clearly separated from current support;
- [`docs/releases.md`](docs/releases.md) — Apple Silicon/Linux x86-64 CI, packages and release procedure;
- [`third_party/README.md`](third_party/README.md) — dependency, license, and attribution information.

No project-wide license has been selected by this documentation cleanup. Do not infer one from third-party license files.
