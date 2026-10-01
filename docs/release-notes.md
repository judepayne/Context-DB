# Context DB 0.1.0 — initial alpha

Evidence-backed claim acquisition, CTXQL query execution, recording/replay, and
bounded read-only chat, with embedded Fluree authority and derived redb traversal.
No separate Fluree server is required.

## Downloads

- Apple Silicon: `cdb-0.1.0-aarch64-apple-darwin.tar.gz` (macOS 15 baseline).
- Linux x86-64: `cdb-0.1.0-x86_64-unknown-linux-gnu.tar.gz`
  (Ubuntu 24.04 / glibc 2.39 baseline; not a static binary).
- Each archive has a SHA-256 checksum file. Packages are unsigned; macOS packages
  are not notarized.

Extract the archive, run `bin/cdb --help`, and follow `docs/service.md` for explicit
instance configuration. The included `assets/pi` directory supplies the provider
bundle. Pi 0.87.1, Node, provider credentials and optional PDF conversion tools are
separate installations. No populated demonstration ledgers or credentials ship.

## Important limits

This is a technical alpha, not a hosted service, full OWL reasoner or legal/financial
advice. Iceberg and assemblies are roadmap work. Unsafe direct-projection chat is
an explicit, default-off graph-permission bypass and must not be used where graph
access isolation is required. Model-backed operations can incur provider charges.

CI uses deterministic fake/loopback providers. Ignored paid-provider and external
ontology acceptance tests are not implied by a green build.

## Publication gate

This draft must not be published until project licensing and third-party notice
obligations are resolved. Context DB's own license has not yet been selected.
Fluree 4.2.1 remains BUSL-1.1, not Apache-2.0 today; retained notices and unresolved
gaps are documented in `third_party/README.md`. Green CI is not redistribution
clearance. Review this section and update it before publication.
