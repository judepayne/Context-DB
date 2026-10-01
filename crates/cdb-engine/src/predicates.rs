//! Portable custom-predicate execution seam. These DTOs are not authorization seals.
//! The trusted controller resolves bindings and owns admission, visibility and effects;
//! native executors return a proposal and never admit a graph child themselves.
use crate::values::Value;
use cdb_core::{CanonicalValue, Result};
use std::{collections::BTreeMap, sync::Arc};

pub const NUMERIC_ABI: &str = "ctxql-predicate-numeric/v2";

/// Original authored expressions; numeric text is parsed by the selected native
/// runtime, not rewritten into a custom numeric language. BIND is compiled and
/// resolved separately by the controller into `bindings` at evaluation time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Program {
    pub init: BTreeMap<String, CanonicalValue>,
    pub lets: BTreeMap<String, String>,
    pub next: BTreeMap<String, String>,
    pub keep: String,
}

#[derive(Clone, Copy, Debug)]
pub struct EvaluationLimits {
    pub max_source_bytes: usize,
    pub max_operations: u64,
    pub max_depth: usize,
    pub max_state_bytes: usize,
    pub max_value_nodes: usize,
    pub max_collection_len: usize,
    pub max_calls: usize,
    pub max_argument_bytes: usize,
    pub max_result_bytes: usize,
}
impl Default for EvaluationLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 16_384,
            max_operations: 100_000,
            max_depth: 32,
            max_state_bytes: 65_536,
            max_value_nodes: 16_384,
            max_collection_len: 4096,
            max_calls: 1024,
            max_argument_bytes: 262_144,
            max_result_bytes: 1_048_576,
        }
    }
}

/// Implemented by the trusted native invocation host. The implementation must
/// perform current session/disclosure/dependency checks at actual release and
/// retain logical calls in the controller-assigned trace lane. A public callback
/// implementation by itself grants neither graph access nor durable publication.
pub trait FunctionCallback: Send + Sync {
    fn call(&self, name: &str, arguments: &[Value]) -> Result<Value>;
    fn check_interrupted(&self) -> Result<()>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub keep: bool,
    /// Only the controller can commit this state, after every predicate passes
    /// and the child is admitted. Rejected/filter attempts discard the proposal.
    pub next: CanonicalValue,
}

pub trait PredicateExecutor: Send + Sync {
    /// Validate scopes, LET dependencies, capabilities and budgets before graph
    /// execution. Binding names are supplied by the compiler, not native reads.
    fn validate(
        &self,
        program: &Program,
        binding_names: &[String],
        limits: EvaluationLimits,
    ) -> Result<()>;

    /// Runs on an owned native worker, not a borrowed RAW view or Tokio core
    /// thread. State and bindings are immutable inputs; effects belong to host.
    fn evaluate(
        &self,
        program: &Program,
        state: &CanonicalValue,
        bindings: &BTreeMap<String, Value>,
        host: Arc<dyn FunctionCallback>,
        limits: EvaluationLimits,
    ) -> Result<Outcome>;
}
