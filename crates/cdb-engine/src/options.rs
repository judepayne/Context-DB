use cdb_core::Limits;

/// Operational parsing/normalization budgets, never semantic traversal caps.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompileOptions {
    pub limits: Limits,
}
