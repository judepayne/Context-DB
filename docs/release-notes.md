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

## Licensing

Context DB's own code is licensed under MIT; the license is included in each
archive. Third-party components retain their respective licenses. Embedded Fluree
4.2.1 remains BUSL-1.1, not MIT or Apache-2.0 today. Review `third_party/README.md`
and the included license texts for attribution, source availability and use
restrictions. This alpha release does not override upstream terms.

Four dependencies explicitly declare MIT but omit standalone upstream license
texts. Their exact published declarations, existing notices and clearly labeled
canonical MIT terms are retained; `third_party/license-sources.json` records the
provenance and these upstream omissions without claiming legal clearance.
