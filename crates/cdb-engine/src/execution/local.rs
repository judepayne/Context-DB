//! Local custom predicates for the serial semantic driver. No external effects.
use super::{
    controller::{
        ControllerBounds, ControllerRuntime, ControllerTicket, EvaluationCompletion, EvaluationJob,
    },
    ExecutionOptions,
};
use crate::{
    predicates::{EvaluationLimits, FunctionCallback, Outcome, PredicateExecutor},
    values::Value,
};
use cdb_core::{Error, ErrorKind, Result};
use std::sync::Arc;

/// Trusted native executor supplied by an embedding, never by a request DTO.
/// The embedding must drive this serial path on an owned blocking/native thread,
/// not a shared async server worker. Broker calls are deliberately unavailable.
#[derive(Clone, Copy)]
pub struct LocalPredicateRuntime<'a> {
    pub executor: &'a dyn PredicateExecutor,
    pub limits: EvaluationLimits,
}
struct NoExternalEffects(ExecutionOptions);
impl FunctionCallback for NoExternalEffects {
    fn call(&self, _: &str, _: &[Value]) -> Result<Value> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "external calls require the recorded P5 controller",
        ))
    }
    fn check_interrupted(&self) -> Result<()> {
        self.0.check_interrupted()
    }
}

/// Window-one adapter used by the unchanged local/no-effects provider path.
pub(super) struct LocalControllerRuntime<'a> {
    local: LocalPredicateRuntime<'a>,
    options: ExecutionOptions,
}
impl<'a> LocalControllerRuntime<'a> {
    pub(super) fn new(local: LocalPredicateRuntime<'a>, options: &ExecutionOptions) -> Self {
        Self {
            local,
            options: options.clone(),
        }
    }
}
impl ControllerRuntime for LocalControllerRuntime<'_> {
    fn validate(
        &self,
        program: &crate::predicates::Program,
        binding_names: &[String],
        limits: EvaluationLimits,
    ) -> Result<()> {
        self.local.executor.validate(program, binding_names, limits)
    }
    fn bounds(&self) -> ControllerBounds {
        ControllerBounds {
            max_outstanding: 1,
            max_pending_bytes: self
                .local
                .limits
                .max_source_bytes
                .saturating_add(self.local.limits.max_state_bytes)
                .saturating_add(self.local.limits.max_argument_bytes)
                .max(1),
        }
    }
    fn evaluation_limits(&self) -> EvaluationLimits {
        self.local.limits
    }
    fn submit(&self, job: EvaluationJob) -> Result<ControllerTicket> {
        self.options.check_interrupted()?;
        let outcome = self.local.executor.evaluate(
            &job.program,
            &job.state,
            &job.bindings,
            Arc::new(NoExternalEffects(self.options.clone())),
            job.limits,
        );
        self.options.check_interrupted()?;
        let lane = job.lane;
        Ok(ControllerTicket::new(lane, outcome))
    }
    fn wait(&self, ticket: ControllerTicket) -> EvaluationCompletion {
        let lane = ticket.lane().clone();
        let outcome = ticket.into_payload::<Result<Outcome>>().unwrap_or_else(Err);
        EvaluationCompletion { lane, outcome }
    }
}
