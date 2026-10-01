# POC transaction clock — ctxql-transaction-clock/v1

Status: implemented finite single-owner alpha protocol. This is not a general Fluree timestamp guarantee or a production clock service.

## Invariant and authority

A successful capture closes an admission-time interval. No later domain admission may receive a transaction timestamp at or below that cutoff, even after wall-clock rollback or process restart. Valid/source observation time is independent and may describe the past.

Fluree holds the durable closed-through watermark, last admission timestamp and admission idempotency receipt. A process-lifetime exclusive owner lock and an in-process coordinator serialize domain admission and capture. Direct external writers bypassing this coordinator are outside the experiment's supported topology. No JSONL/SQLite/sidecar clock truth is introduced.

## Selected protocol

- Use millisecond units and checked signed-64-bit arithmetic; the executable fixture restricts admission/cutoff values to nonnegative i64 and permits negative independent valid times. Application timestamps are authoritative RDF integer fields, not native Fluree commit datetimes. Production UTC/date rendering must additionally fit canonical-v1's supported datetime range; it remains P1 work. Reject out-of-range input/results rather than wrap or truncate.
- Define logical now as `max(wall_ms, last_admission_ms, closed_through_ms)`. An omitted cutoff captures this value once inside the serialization gate.
- An explicit cutoff at or before logical now can be closed. An explicit future cutoff is an **unsupported experiment capability**, not an assertion that future timestamps are invalid CTXQL syntax. Fail before publishing a successful capture; do not clamp it or pretend its future is closed.
- Persist `closed_through = max(previous_closed_through, cutoff)` through a Fluree metadata transaction before returning a successful capture. Idle captures must also survive restart. A control-metadata write is not a fabricated domain claim.
- Subsequent domain admissions receive `max(wall_ms, last_admission_ms + 1, closed_through_ms + 1)`. Persist that timestamp, domain data and idempotency receipt in one authoritative transaction.
- Record the exact receipt/graph identity corresponding to the capture. `db_time` pins graph interpretation independently from the admission cutoff. Metadata-only commits may advance `db_time` without adding domain claims.
- Logical timestamps can advance beyond the wall clock under equal ticks or rollback. Expose the effective assigned timestamp; never claim it is an independently accurate observation timestamp. Versioned bounds and explicit overflow errors prevent unlimited representational growth, not arbitrary operational load.

Future-cutoff support beyond this bounded protocol remains a later adapter capability decision. The experiment must report the limitation honestly without degrading supported closed, pinned graph executions to best effort.

## Errors, recovery and replay

Reject caller-supplied domain transaction timestamps. Source valid time is accepted in its separate fixture field and cannot affect admission ordering.

A failed capture persistence yields no successful pin. A failed admission yields no successful receipt or partial domain batch. A committed-but-unacknowledged admission is found by its persisted idempotency key: identical payload returns its original timestamp/identity; changed payload under the key fails. A lost capture response can be retried conservatively because the persisted closure is monotonic; recapture may return a later graph receipt and must not impersonate the missing original response.

Reopen reads clock metadata from authoritative Fluree. Missing/corrupt metadata in an existing clock ledger fails closed; initialization is a separate explicit operation. Do not interpret a missing timestamp as native fallback-to-head. Historical replay uses recorded pins; it does not recapture current wall time and call that exact replay.

## Required experiment evidence

Use deterministic fake wall readings and controlled process/gate ordering, not sleeps: staged-before/committed-after capture; equal ticks; rollback; idle capture; restart; failed persistence; lost acknowledgement/retry; past valid time; future/overflow/malformed cutoff; corrupt clock state. Compare the same cutoff against later heads to show that new domain claim IDs cannot enter its interval. Changes in historical ontology/lifecycle interpretation belong to independently pinned `db_time`, not the admission-set assertion.

Seven clock integration tests now cover these cases, alongside six preserved durability/history tests. The synthetic integer-clock evidence does not execute a CTXQL query, UTC renderer or native datetime lookup. Process-kill recovery after acknowledgement does not prove power-loss/fsync guarantees. Production authentication, distributed ownership, projection checkpoints and transport-release ordering remain later work.
