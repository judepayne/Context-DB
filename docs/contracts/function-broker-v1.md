# Function broker v1

Status: implemented native execution contract.

The broker is a startup-fixed execution boundary for CTXQL external functions. Query data and Rhai programs cannot select an endpoint, adapter, model, device, credential, or manifest source.

## Identity and registration

A function binding names one exact published manifest by IRI, version, SHA-256 source-byte hash, and original UTF-8 bytes. The manifest declares its function name, numeric ABI, deterministic/replay mode, retry and batching properties. A configured provider has one immutable destination resource, execution class, adapter build identity, resource group, and an allowlist of exact manifests.

Startup rejects unknown fields, duplicate identities, unavailable adapters, class mismatches, unsafe HTTP endpoints, unsupported accelerator claims, unbounded capacities, and manifest byte/hash mismatches. CPU and accelerator adapters are embedding registrations; they are not loaded from query-controlled paths. HTTP uses a configured endpoint and credential file, permits plaintext only for explicitly enabled loopback testing, and fixes method, path, headers, and bounded JSON framing.

## Authorization

Every enqueue attempt and every result consumption performs a fresh check while retaining the original execution basis. Authorization requires:

- the authenticated Query or Replay session lease;
- every immutable argument, inherited-state, fact, and scope dependency for that action;
- the exact manifest/provider destination invocation role;
- current positive disclosure permission.

Each action receipt binds only the requirements checked for that action and the actual authority head. Requirements discovered by later concurrent jobs cannot enter an earlier receipt. A separate bounded final footprint accumulates every reached positive dependency and invocation, including rejected or cap-denied effects, for guarded publication.

No read grant implies invocation permission. No manifest grant implies an arbitrary destination. Replay derives destinations from the protected stored v3 run and resolves exactly one matching startup provider; caller substitution is rejected before transmission.

## Scheduling and ownership

Admission is bounded globally, per request, per resource group, by queued bytes, logical calls, retained result bytes, and provider rate/capacity controls. Controller-issued lane and callback identities define semantic order independently of worker arrival. A later group cannot reduce before all earlier candidates close.

Timeout, cancellation, dropped callers, or worker failure do not release physical capacity while native/provider work is still running. Completed-but-unreduced results retain their reservations. Shutdown stops admission, cancels queued work, and joins retained workers; non-cooperative native code may therefore delay shutdown.

Retries are allowed only when the exact manifest/provider declaration permits them. Authorization is repeated before each transmission and before consumption. A denial is sticky and cannot be caught by Rhai as a successful value.

## Recording and replay

Durable v3 recording stores, per function, the exact manifest and source bytes, deterministic/replay declaration, checked call count, canonical streaming input/output roots, and sorted original destinations. Operational attempts, timings, credentials, endpoints, and authorization heads are excluded from semantic roots.

Actual replay preflights the stored identities and current permissions, invokes the exact configured destination again, and compares function names, counts, input roots, output roots, lane trace, and response. Matching deterministic execution reports `reproduced`; changed output or graph reports `diverged`. Missing or non-replayable identities report unsupported/not replayable and do not silently reopen an output tape.

## Non-guarantees

The contract supplies bounded logical accounting, not a universal hard-RSS or forced native-code cancellation guarantee. Paid network, arbitrary plugins/downloads, implicit invocation grants, and unregistered accelerators are outside the default implementation and tests.
