# Current Fluree 4.2.1 reasoning compatibility

## Current executable scope

The only current executable ontology profile is:

`ctxql-ontology-profile/fluree-4.2.1-82dbcec3e435d6ed1d45bc0ed929432323b6b201/v1-supported-reasoning`

It is distinct from the raw, uncertified acquisition-vocabulary identity and from every profile containing historical revision `603974fad5c13efed9d147d214d613849fb43c73`. The profile uses the bounded structural validator in `ontology_profile_v2` (100,000 bundle quads, 10,000 list members, expression depth 10, at most 128 diagnostics by default). Its result commitment binds the complete bundle, exact reasoner projection, inert metadata, limits, construct counts, current backend identity, and current profile identity.

The executable rule-family boundary is the closed inventory in `fixtures/conformance/p5_6/direct-reasoner-inventory.json`. Current parity executes every inventoried vector against both the direct Fluree 4.2.1 reasoner and the sealed authorized sandbox and compares normalized inferred sets. This is bounded subset parity, **not** full OWL 2 RL/FIBO certification. Constructs rejected by the validator remain unsupported/inert; raw acquisition vocabulary lookup does not imply executability.

Profiles naming `603974f` remain archival evidence only. Their decoders and commitments are preserved, but the 4.2.1 sandbox returns `Unsupported` with `historical Fluree 603974f executor unavailable; archival decoding only`. It never impersonates the historical executor.

Current limitation: the backend can classify, seal, execute, and describe this current profile, but service/config selection of the profile is not wired in this bounded change. Until that dispatch is added and validated, deployed query execution should use explicit `none`; callers cannot claim configured current reasoning solely from these backend tests.

Historical `603974f` recordings remain decode-only. Arbitrary old ledgers are not certified for current writes or migration; use fresh 4.2.1 stores unless a separately reviewed operator migration preserves exact authorized graph data, terms, policies, and backups.
