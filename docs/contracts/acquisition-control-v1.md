# Acquisition Control records v1

The Control authority owns foreground job/attempt state, prepared commitments, admission receipts, projection receipts, bounded failures, and recovery outcomes. It does not own ontology RDF, business facts, source bytes, provider output, tool traffic, or candidate graphs.

Job states are `created`, `acquiring`, `converting`, `planning`, `extracting`, `validating`, `admitting`, `waiting_projection`, `completed`, `completed_with_errors`, `failed`, `cancelled`, and `recovery_required`. Bundle states are `candidate_rejected`, `validated`, `prepared`, `admission_unknown`, `admitted`, `projected`, and `conflict`. Terminal transitions fail closed.

Records are append-only canonical values. A final admission receipt is idempotent only when byte-equivalent; a different receipt for the same bundle is a conflict. Recovery checks the final receipt first, then prepared state, then exact Semantic-Ledger history. Provider work and semantic writes are not repeated while admission may already have occurred.
