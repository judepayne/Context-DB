# Policy integration requirements — ctxql-policy-integration/v1

Status: current policy integration contract. It defines service requirements rather than a replacement security implementation; replay remains subject to current permissions.

## Historical meaning, current permission

Use historical db_time for claims, ontology closure, identity/alias resolution, labels, lifecycle events, artifacts and recorded run semantics. Independently use one current authority context for enabled principal, memberships, policy records, resource existence and direct policy-target classes. No historical grant/class fallback and no native schema bypass. Exact run pin never authorizes historical data by itself.

| Read/use | Required protected footprint |
|---|---|
| Landing | anchor/alias descriptors, target identity and every label/index fact consumed, including rejected candidates used for ranking |
| Ontology/identity | every closure/rule/identity dependency actually consumed, including negative-answer completeness descriptors |
| Claims/lifecycle | complete coherent claim facts plus every required lifecycle event/interpretation dependency; denied event must not mean active |
| Labels/explain | independently protected labels, selectors and explanatory facts; do not leak forbidden IDs through notices/counts |
| Evidence | source-version/span descriptor closure; visible lineage reference is not full-document or byte permission |
| Artifacts/runs | protected published artifact/config/function/run and sealed replay footprint, not caller-supplied trusted manifests |
| Assemblies/products | every input run/response footprint, required section and source selector plus assembly artifact; product release repeats freshness check |

Normal execution removes unusable coherent claims before reachability/caps; mandatory explicitly requested descriptors fail the request. Replay requires the complete sealed historical read footprint under **current** permissions; if any required dependency is denied/missing, block without returning a pruned response as exact reproduction. Public authorization result is blocked/access_denied; graph replay verdict not_replayable may be recorded internally, without revealing the denied run/hash/ID. Missing external evidence alone remains separate from graph replay.

## Sealing, caches and release

Use instrumented private preparation → sealed pending handle → guarded release, and protected immutable run manifests. Keep used dependency selectors distinct from explicitly requested output selectors; closure must not widen evidence output. Negative lookups and candidate-ordering inputs also need complete dependency capture; finite fixtures alone do not prove instrumentation completeness.

Selected POC default is **no cross-request response/evidence cache**. Any future cache key must include authority, graph exact pin, principal identity, current authorization epoch, contract/guard/value-schema versions, config/plan, source version and exact selector. Every authority head change invalidates pending authorization, even a new grant or unrelated commit. In future integrated execution, persist clock closure/capture before preparing the current authorization context: clock metadata writes also advance the head and must not be mistaken for an exception to freshness checks. Clock and policy ordering remains an integration requirement. No cache grants or unauthorized negative-result metadata may cross principals. Disposable historical data projections are not permission caches.

Release under the same single-owner mutation gate: refresh current head, compare complete private context, enforce shared deadline, publish to bounded non-reentrant trusted sink while holding gate. Changed head/error discards body; no automatic retry or stale success. Record current footprint and retain immutable historical snapshot. Assemblies may not bypass guard with direct filesystem/network access. Denied IDs, source snippets, counts, old hashes and backend diagnostics never enter public errors. Use the existing `access_denied`/`policy_changed`/`preparation_failed` envelope.

## Assurance limits

Current tests cover finite sealed manifests, current classes, selector closure, source spans, and local release freshness. They do **not** establish production authentication/HTTP transport, network revocation, arbitrary-ledger preparation, complete ontology/lifecycle/landing instrumentation, Python isolation, or hard native CPU/RSS bounds. Future P7/P8 integrations must preserve these requirements. This contract makes no production-security claim and does not weaken fail-closed behavior.
