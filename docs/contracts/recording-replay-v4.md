# Recording and replay v4

Status: current implementation contract with the additive supported-subset projection.

`ctxql-replay-data/v4` wraps the complete closed v3 execution evidence and one closed semantic evidence descriptor. `ctxql-recorded-run/v4` binds that replay object to the run id, owner, and operation hash.

The semantic descriptor records only:

- the exact Semantic Ledger capture;
- requested `as_of` spelling;
- policy mode, dependency root, source observation, principal, and action;
- historical configuration and graph-role-map roots;
- authorized data/schema roots and authorized counts;
- sorted, duplicate-free SHA-256 selectors over the backend's canonical `SourceQuad::commitment` bytes and the exact originally visible support IDs;
- historical configuration, governed/claim graph, schema source, and import-closure graph selectors;
- `AuthorizedPremiseRoot`, protected `ExecutionManifestRoot`, prepared ontology root, and deterministic diagnostics root;
- ontology profile identity, `full_ontology_bundle_root`, `ontology_profile_result_root`, and `reasoner_input_root`;
- structural mapping algorithm and complete profile, materialization, reasoning, and aggregate budget identities; and
- semantic codec, commitment, extraction, materializer, direct reasoner, and protected completeness identities.

All selector arrays and aggregate wire bytes are bounded. It MUST NOT contain source RDF, the in-memory manifest, inferred facts, unrestricted scan counters, hidden claim identities, or wall-clock diagnostics. Debug/display formatting is never an identity source.

For the exact ontology profile `ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v3-supported-subset`, semantic evidence additionally requires the closed `supported_subset` object. It binds the source-exact result label, construct-audit and executable-profile roots, reasoned-family and declaration evidence, uninterpreted non-interference and parity evidence, four category roots, registry/family/component/source-occurrence roots, annotation policy, semantic coverage, caveats, and source ontology-C0 root. The ordinary authorized schema/input/profile/prepared roots separately bind the Fluree-stored execution projection. The object is physically absent—not `null`—for every other profile. A final-v3 recording without it, or a non-v3 recording with it, is invalid. Existing profile-v2 canonical bytes are unchanged.

Replay reopens the exact semantic `t`/CID, runs current production authorization and historical preparation, and intersects that result with the recorded member selectors. Every original positive member must still resolve and be authorized; extra members made visible later are ignored. The historical complete bundle is selected from positive commitments, rerun through the v2
structural validator, deterministically remapped, and resealed with its recorded historical policy
commitment. For final v3, the source manifest root and the complete stored-projection/input/prepared roots are both compared; this POC does not require their RDF-term roots to be equal. Other profiles retain their existing exact comparisons. A fresh sandbox then reruns the direct reasoner. Current authorization remains a separate release check and may
deny use; it is not substituted into historical authority.

The wire objects are closed and canonical. Unknown fields, malformed identities, root mismatches, unavailable exact history, incomplete reconstruction, unsupported RDF terms, and capped reasoning fail closed.

Same-key/same-operation-digest retry returns the already admitted v4 bytes and receipt without
semantic extraction, reasoning, resolver execution, or publication a second time. A changed digest
conflicts. Restart replay must re-open the exact semantic t/CID and exact Control-Ledger artifacts;
it may report unavailable or diverged but may not substitute either current head. Grants added after
the original run do not broaden recorded members or a recorded absence. Current semantic or control
revocation can deny reconstruction, resolver use, disclosure, hydration, or final publication.
Recorded receipts and selectors remain evidence, never replay credentials.

V4 stores no source RDF, source blank labels, structural mapping table, sandbox, or inferred-fact
payload. Named-graph identity is reconstructed from recorded graph-role selectors and authorized
member commitments, not from treating a public `rdf:reifies` triple as if it encoded a graph term.
Earlier alpha v4 bytes are not silently adapted to current semantics: absent/new-field, unsupported
profile, or root mismatch fails strict parsing/replay. This is an intentional fail-closed migration,
not a promise that every earlier alpha recording remains executable.
