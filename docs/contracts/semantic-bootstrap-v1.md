# Fresh Semantic bootstrap v1

`cdb semantic bootstrap --config /absolute/cdb.toml` is the generic create-once bootstrap for an independent `ctxql-instance/v4` Semantic authority. It reads only the selected configuration and creates only `[semantic].path`. It does not create or modify Control, credentials, projection, source storage, ontology stores, or provider state.

The command requires a valid absolute configuration path, a fresh absolute Semantic destination, and ontology-v2 acquisition configuration with an absolute-IRI `principal`, distinct absolute-IRI `claims-graph` and `review-graph`, and native action `https://ns.flur.ee/db#modify`. `[semantic].graph` is the infrastructure/schema graph role and must also be a distinct absolute IRI. The configured Semantic ledger ID must be a safe native `name[:branch]` identifier, and `[semantic].backend` must be the pinned native identity `fluree-db/4.2.1@82dbcec3e435d6ed1d45bc0ed929432323b6b201`. Authority, ledger, graph, path separation, and all other instance identities retain normal configuration validation.

Any filesystem object already at the destination—including a directory, file, or symlink—is refused. The immediate parent must already be a real directory. Bootstrap never opens, resets, migrates, removes, repairs, or creates parent paths. Validation completes before destination creation. The new root is owner-only (`0700` on Unix); operators remain responsible for an equivalently private platform ACL and private parent directory.

The single initial Semantic transaction installs:

- the configured claim, review, and infrastructure graph roles;
- `f:none` reasoning, no import following, and a minimal neutral `owl:Ontology` declaration in the configured infrastructure graph;
- same-ledger native policy with `f:defaultAllow false`;
- one owner policy class bound to the configured acquisition principal, with explicit native `f:view` and `f:modify` allows.

No default-allow fixture policy, synthetic domain claims, party identifiers, or ontology certification is installed. Principals without the configured owner policy class remain denied by native policy. Before reporting success, bootstrap prepares the owner's actual authorized empty business view and derives its acquisition catalog. A successful command emits `ctxql-fresh-semantic-bootstrap/v1` JSON with the exact path, ledger, transaction/CID, configured identities, `reasoning_mode: "none"`, `default_allow: false`, and the derived `catalog_root` and `ontology_profile`. The emitted catalog values—not a pre-bootstrap placeholder—are the values to retain in acquisition configuration for subsequent service startup.

After success, the same configuration can create the independent Control authority and owner credential:

```sh
cdb init --config /absolute/cdb.toml \
  --principal 'the same configured acquisition principal' \
  --secret-file /absolute/new-owner.secret
```

`init` still does not create or mutate Semantic state.
