# Third-party dependencies and attribution

This directory preserves current dependency inventory and available license/notice texts for the public alpha. It is engineering evidence, not legal advice or release clearance, and it does not license Context DB's own source.

## Rust dependency inventory

- [`current-dependencies.json`](current-dependencies.json) is the machine-readable all-feature workspace inventory for the locked graph: 412 external packages and the Fluree 4.2.1 revision.
- [`license-manifest.json`](license-manifest.json) maps those exact package identities to retained named license/notice files under [`licenses/`](licenses/), with SHA-256 hashes.
- The manifest explicitly lists packages for which the former evidence corpus contained no named license text. Package metadata is not substituted for missing text, and no permissive choice or legal clearance is inferred.

The inventory is generated from the current locked Cargo metadata, without workstation paths or historical validation receipts. `Cargo.lock` remains the authoritative dependency resolution. Regenerate/review the inventory whenever package identities, sources, or selected features change.

## Fluree

Context DB embeds Fluree 4.2.1 from revision `82dbcec3e435d6ed1d45bc0ed929432323b6b201`. The retained upstream text is [`licenses/fluree-db-api-4.2.1/LICENSE.fluree`](licenses/fluree-db-api-4.2.1/LICENSE.fluree); the same exact text is mapped to every resolved Fluree package.

The current license is BUSL-1.1. The Database Service restriction, conspicuous-display requirement, and version-specific fourth-anniversary change-date condition remain relevant. This project has not established the first-public-distribution date and does **not** treat 4.2.1 as Apache-2.0 today. Production, hosted, commercial, and distribution use requires an independent review of the actual deployment and obligations; no commercial permission or prohibition is invented here.

## hmem reuse

Selected storage, projection, acquisition/evidence, and Pi transport mechanics were copied or adapted from the sibling `hmem` project at revision `16a3e6ebf482b852dd539887292b335a7eb7728a`, with the copyright owner's explicit authorization. Source files retain focused provenance comments. hmem declared its workspace MIT, but the reviewed source did not include a root license text; this directory therefore does not fabricate one. Confirm and retain the owner's applicable grant before redistribution.

Context DB does not depend on hmem at runtime and does not port its memory/tree product semantics, legacy compiler, effective-edge aggregation, or reset-on-open behavior.

## Pi

Model-backed acquisition and chat invoke `@earendil-works/pi-coding-agent` as a separately installed external program and use its extension API. The supported runtime version is documented in the service configuration and verified by the application. The npm package declares MIT and identifies Mario Zechner / Earendil Works; the installed package inspected during development did not ship a root license file, so no text is invented here. Operators/distributors must inspect and preserve the exact selected Pi distribution's license and transitive notices.

Pi/provider terms, model terms, and provider data-retention rules are separate from Context DB's Rust dependency inventory. Local `--no-session` behavior is not a claim of zero provider retention.

## Project license

No license for Context DB itself has been selected or added by this cleanup. Third-party license files apply to their respective works only.
