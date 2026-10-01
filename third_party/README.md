# Third-party dependencies and attribution

This directory preserves current dependency inventory and available license/notice texts for the public alpha. It is engineering evidence, not legal advice or release clearance, and it does not license Context DB's own source.

## Rust dependency inventory

- [`current-dependencies.json`](current-dependencies.json) is the machine-readable all-feature workspace inventory for the locked graph: 412 external packages and the Fluree 4.2.1 revision.
- [`license-manifest.json`](license-manifest.json) maps those exact package identities to retained named license/notice files under [`licenses/`](licenses/), with SHA-256 hashes.
- [`license-sources.json`](license-sources.json) records recovery provenance for the 15 formerly missing entries: package/version, Cargo package checksum, repository, exact VCS revision, immutable source URL, and retained-file hash.
- The manifest explicitly lists the four packages for which no verified upstream standalone license text could be recovered. For those packages it retains the exact published Cargo declaration and README, plus separately labeled canonical MIT standard terms; it does not present the canonical template as an upstream file or claim legal clearance.

The inventory is generated from the current locked Cargo metadata, without workstation paths or historical validation receipts. `Cargo.lock` remains the authoritative dependency resolution. Regenerate/review the inventory whenever package identities, sources, or selected features change.

## Recovered texts and remaining gaps

Exact installed-crate files or files at the revision recorded in `.cargo_vcs_info.json` recovered license text for `oxilangtag`, `oxiri`, `oxrdf`, `oxrdfxml`, `quick-xml`, and `rhai_codegen`. The two winapi target crates do not carry their own VCS record; their texts come from their target directories at the revision recorded by the co-resolved `winapi` 0.3.9 crate. Recovery provenance and hashes are in `license-sources.json`.

`base256emoji` 1.0.2, `base45` 3.2.0, `cid` 0.11.3, and `seahash` 4.1.0 explicitly declare MIT in their checksum-bound published `Cargo.toml`, but omit a standalone license text. Their exact published declarations and READMEs are retained. The `cid` README specifically says `[MIT](LICENSE) © 2017 Friedel Ziegelmayer`, but its `LICENSE` link points to a file absent at the recorded revision; the other three retained READMEs contain no copyright/license notice. The `base45` VCS record also marks the packaged source dirty.

Each of these four directories also contains `STANDARD-MIT.txt`: the unmodified MIT template (including its `<year>` and `<copyright holders>` placeholders) from immutable SPDX license-list-data commit `f91a5bae39a51863221095e9e293b9fde095cf63`. It is supplied as the standard license terms referenced by the explicit MIT metadata, not as a license file supplied by upstream, a fabricated upstream grant, or an assertion about copyright ownership. `license-sources.json` records the package URL/checksum, every retained-file hash, and the canonical MIT URL/hash; both provenance files continue to mark `upstream_text_missing: true`. A distributor must independently assess the evidence and obligations; no legal clearance is claimed.

## MPL dependencies and source availability

`bitmaps` 3.2.1, `imbl` 3.0.0, and `imbl-sized-chunks` 0.1.3 declare `MPL-2.0+`, and their exact release READMEs contain the MPL notice and copyright lines. Each retained directory includes the canonical MPL-2.0 text and that exact README. `license-sources.json` gives an immutable public source archive for each exact VCS revision as the Source Code Form location. Distributors remain responsible for satisfying MPL source-availability and notice obligations for the form they distribute; if those immutable public archives cannot remain available for the required period, ship the corresponding source instead.

## Fluree

Context DB embeds Fluree 4.2.1 from revision `82dbcec3e435d6ed1d45bc0ed929432323b6b201`. The retained upstream text is [`licenses/fluree-db-api-4.2.1/LICENSE.fluree`](licenses/fluree-db-api-4.2.1/LICENSE.fluree); the same exact text is mapped to every resolved Fluree package.

The current license is BUSL-1.1. The Database Service restriction, conspicuous-display requirement, and version-specific fourth-anniversary change-date condition remain relevant. This project has not established the first-public-distribution date and does **not** treat 4.2.1 as Apache-2.0 today. Production, hosted, commercial, and distribution use requires an independent review of the actual deployment and obligations; no commercial permission or prohibition is invented here.

## hmem reuse

Selected storage, projection, acquisition/evidence, and Pi transport mechanics were copied or adapted from the sibling `hmem` project at revision `16a3e6ebf482b852dd539887292b335a7eb7728a`, with the copyright owner's explicit authorization. Source files retain focused provenance comments. hmem declared its workspace MIT, but the reviewed source did not include a root license text; this directory therefore does not fabricate one. Author-owned adaptations in this Context DB distribution are covered by the author's explicit [MIT grant](../LICENSE). This does not create a standalone license for the whole hmem repository or license contributions owned by others; applicable upstream notices and the recorded reuse provenance remain relevant.

Context DB does not depend on hmem at runtime and does not port its memory/tree product semantics, legacy compiler, effective-edge aggregation, or reset-on-open behavior.

## Pi

Model-backed acquisition and chat invoke `@earendil-works/pi-coding-agent` as a separately installed external program and use its extension API. The supported runtime version is documented in the service configuration and verified by the application. The npm package declares MIT and identifies Mario Zechner / Earendil Works; the installed package inspected during development did not ship a root license file, so no text is invented here. Operators/distributors must inspect and preserve the exact selected Pi distribution's license and transitive notices.

Pi/provider terms, model terms, and provider data-retention rules are separate from Context DB's Rust dependency inventory. Local `--no-session` behavior is not a claim of zero provider retention.

## Project license

Context DB's own code is distributed under the [MIT License](../LICENSE), selected by its copyright owner. It applies only to rights the project can grant and does not override third-party terms, Fluree's BUSL-1.1, or the upstream notice omissions described above. See the distribution's [NOTICE.md](../NOTICE.md) and full [LICENSE-FLUREE](../LICENSE-FLUREE).
