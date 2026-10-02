# CI and alpha releases

GitHub Actions tests and builds these native targets on every `main` push, pull
request and manual run:

| Target | Runner / supported baseline |
| --- | --- |
| `aarch64-apple-darwin` | Apple Silicon, macOS 15 |
| `x86_64-unknown-linux-gnu` | Ubuntu 24.04, glibc 2.39 or newer |

These are not Intel Mac, Linux ARM64 or static musl builds. The workflow checks the
native Rust host, tests the binary's `--help`, and retains architecture/linking
inspection with the Cargo output. macOS archives are unsigned and not notarized.
Do not disable system security globally to install them.

Rust 1.94.0, Node 22.19.0 and Python 3.12 are provisioned explicitly. Formatting,
all-feature/all-target Clippy and Rust tests, dependency-boundary checks and Python
tests must pass before that platform's release build/package is uploaded. Native
Cargo commands are serialized and Rust tests use a 32 MiB stack and one test thread.
Provider tests use fake/loopback implementations; ignored real-provider and
external-ontology tests are not claimed as executed. Full wrapper child output is
retained in `validation-*` artifacts, including on failure.

## Artifacts

Each passing matrix job produces:

- `cdb-VERSION-TARGET.tar.gz`
- `cdb-VERSION-TARGET.tar.gz.sha256`

The archive includes `bin/cdb`, the Pi asset bundle, usage documentation, locked
source dependency information and retained third-party notices. It never includes
credentials, populated stores, demo loan documents or Pi/Node installations.
Configure `pi-bundle` to the extracted `assets/pi` directory. Core query/service
use does not require Pi; model-backed acquisition/chat requires a separate supported
Pi 0.87.1 installation and provider credentials. PDF conversion is separately
configured and is not OCR.

Checksums detect accidental corruption; they are not signing or provenance
attestations. CI artifacts expire after 14 days. A release must preserve the
reviewed packages rather than rely on expiring CI storage.

## Release procedure

1. Confirm the exact `main` commit is green on both platforms and review the retained
   linking/validation evidence. Resolve distribution/license obligations: a green
   build is not legal clearance. Context DB's own code is MIT-licensed; embedded
   dependencies retain their terms, as described in `third_party/README.md`.
2. Ensure `[workspace.package].version` in `Cargo.toml` is the intended version and
   update `docs/release-notes.md`. Tags must match it exactly (for example `v0.1.1`).
3. Create and push the version tag. The tag run repeats both complete test/build
   jobs. Only after both pass does the release job verify checksums and create a
   **draft prerelease** with both platform archives and checksum files.
4. Inspect the draft, notices, assets and release notes. Publish explicitly using
   GitHub or `gh release edit v0.1.1 --draft=false --prerelease`. Do not publish while
   license/notice or validation blockers remain.

The workflow never automatically publishes a draft. Release creation refuses an
existing release rather than silently replacing published artifacts. For a failed
draft-creation retry, inspect the existing draft and assets before taking action.

Local packaging (no build or model calls):

```sh
python3 scripts/package_release.py --binary /absolute/path/cdb \
  --target aarch64-apple-darwin --output-dir /absolute/new-packages --tag v0.1.1
```

Build locally through the external staging and serial-Cargo helpers described in
`AGENTS.md`. Linux compatibility must be tested on Linux; a local macOS pass is not
proof that the Linux CI job passed.
