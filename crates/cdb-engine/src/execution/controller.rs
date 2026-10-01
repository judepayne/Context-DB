//! Portable, bounded custom-predicate controller protocol.
//!
//! Jobs contain owned semantic inputs only. Graph/policy handles never cross this
//! boundary, and returned state remains a proposal until ordered reduction.
use crate::{
    predicates::{EvaluationLimits, Outcome, Program},
    values::Value,
};
use cdb_core::{
    id::{Iri, ResourceId},
    CanonicalValue, Error, Result,
};
use std::collections::{BTreeMap, BTreeSet};

/// Immutable positive graph provenance carried with one evaluation. This is
/// execution data only; a trusted backend must still authorize every release.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DependencyFootprint {
    resources: BTreeSet<ResourceId>,
    facts: BTreeSet<(ResourceId, Iri)>,
    scopes: BTreeSet<ResourceId>,
}
impl DependencyFootprint {
    pub fn resources(&self) -> impl Iterator<Item = &ResourceId> {
        self.resources.iter()
    }
    pub fn facts(&self) -> impl Iterator<Item = &(ResourceId, Iri)> {
        self.facts.iter()
    }
    pub fn scopes(&self) -> impl Iterator<Item = &ResourceId> {
        self.scopes.iter()
    }
    pub(crate) fn insert_resource(&mut self, resource: ResourceId) {
        self.resources.insert(resource);
    }
    pub(crate) fn insert_fact(&mut self, resource: ResourceId, property: Iri) {
        self.facts.insert((resource, property));
    }
    pub(crate) fn extend(&mut self, other: &Self) {
        self.resources.extend(other.resources.iter().cloned());
        self.facts.extend(other.facts.iter().cloned());
        self.scopes.extend(other.scopes.iter().cloned());
    }
    fn retained_bytes(&self) -> Result<usize> {
        let mut bytes = 0usize;
        for resource in self.resources.iter().chain(&self.scopes) {
            bytes = bytes
                .checked_add(resource.as_str().len())
                .ok_or_else(Error::limit)?;
        }
        for (resource, property) in &self.facts {
            bytes = bytes
                .checked_add(resource.as_str().len())
                .and_then(|n| n.checked_add(property.as_str().len()))
                .ok_or_else(Error::limit)?;
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PredicatePhase {
    Walk,
    Filter,
}

/// Stable logical identity assigned by the controller before submission.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LaneIdentityV3 {
    pub phase: PredicatePhase,
    pub evaluation_ordinal: u64,
    pub predicate_index: u64,
    pub attempt: u64,
}
impl LaneIdentityV3 {
    pub fn callback(&self, local_ordinal: u64) -> CallbackIdentityV3 {
        CallbackIdentityV3 {
            lane: self.clone(),
            local_ordinal,
        }
    }
}

/// Callback identity is authored-call order within a lane, never arrival order.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CallbackIdentityV3 {
    pub lane: LaneIdentityV3,
    pub local_ordinal: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerBounds {
    pub max_outstanding: usize,
    pub max_pending_bytes: usize,
}
impl ControllerBounds {
    pub fn validate(self) -> Result<Self> {
        if self.max_outstanding == 0 || self.max_pending_bytes == 0 {
            return Err(Error::invalid("controller bounds"));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug)]
pub struct EvaluationJob {
    pub lane: LaneIdentityV3,
    pub program: Program,
    pub state: CanonicalValue,
    pub bindings: BTreeMap<String, Value>,
    pub argument_dependencies: DependencyFootprint,
    pub state_dependencies: DependencyFootprint,
    pub limits: EvaluationLimits,
}
impl EvaluationJob {
    pub(crate) fn retained_bytes(&self, limits: cdb_core::Limits) -> Result<usize> {
        let mut bytes = self.state.canonical_bytes(limits)?.len();
        bytes = bytes
            .checked_add(
                CanonicalValue::Object(self.program.init.clone())
                    .canonical_bytes(limits)?
                    .len(),
            )
            .ok_or_else(Error::limit)?;
        for (name, text) in self.program.lets.iter().chain(&self.program.next) {
            bytes = bytes
                .checked_add(name.len())
                .and_then(|n| n.checked_add(text.len()))
                .ok_or_else(Error::limit)?;
        }
        bytes = bytes
            .checked_add(self.program.keep.len())
            .ok_or_else(Error::limit)?;
        for (name, value) in &self.bindings {
            let value_bytes = value_bytes(value, limits)?;
            bytes = bytes
                .checked_add(name.len())
                .and_then(|n| n.checked_add(value_bytes))
                .ok_or_else(Error::limit)?;
        }
        bytes = bytes
            .checked_add(self.argument_dependencies.retained_bytes()?)
            .ok_or_else(Error::limit)?;
        bytes = bytes
            .checked_add(self.state_dependencies.retained_bytes()?)
            .ok_or_else(Error::limit)?;
        // Reserve the largest permitted proposed NEXT value while the runtime
        // owns the job/completion. Callback/effect storage is additionally
        // reserved and bounded by the native runtime before submission.
        bytes
            .checked_add(self.limits.max_state_bytes)
            .ok_or_else(Error::limit)
    }
}

fn value_bytes(value: &Value, limits: cdb_core::Limits) -> Result<usize> {
    Ok(match value {
        Value::Missing | Value::Null | Value::Bool(_) => 1,
        Value::Number(n) => format!("{n:?}").len(),
        Value::String(s) => s.len(),
        Value::Timestamp(t) => t.canonical().len(),
        Value::Grounding(g) => g.as_str().len(),
        Value::Literal(v) => v.projection().canonical_bytes(limits)?.len(),
        Value::List(values) => values.iter().try_fold(1usize, |n, value| {
            n.checked_add(value_bytes(value, limits)?)
                .ok_or_else(Error::limit)
        })?,
        Value::Object(v) => v.canonical_bytes(limits)?.len(),
    })
}

/// Runtime-owned admission/completion token. The payload is private native
/// state; the engine can inspect only the controller-issued lane.
pub struct ControllerTicket {
    lane: LaneIdentityV3,
    payload: Box<dyn std::any::Any + Send>,
}
impl ControllerTicket {
    pub fn new<T: Send + 'static>(lane: LaneIdentityV3, payload: T) -> Self {
        Self {
            lane,
            payload: Box::new(payload),
        }
    }
    pub fn lane(&self) -> &LaneIdentityV3 {
        &self.lane
    }
    pub fn into_payload<T: Send + 'static>(self) -> Result<T> {
        self.payload
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| Error::invalid("controller ticket payload"))
    }
}

pub struct EvaluationCompletion {
    pub lane: LaneIdentityV3,
    pub outcome: Result<Outcome>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControllerEvent {
    TraversalStarted,
    FinalizationStarted,
    EvaluationOpened {
        phase: PredicatePhase,
        ordinal: u64,
    },
    EvaluationClosed {
        phase: PredicatePhase,
        ordinal: u64,
        outcome: super::trace::LaneOutcomeV3,
    },
    ReadLane(LaneIdentityV3),
    LaneClosed(LaneIdentityV3, super::trace::LaneOutcomeV3),
    Submitted(LaneIdentityV3),
    AdmissionRejected(LaneIdentityV3),
    Completed(LaneIdentityV3),
    Reduced(LaneIdentityV3),
}

/// Native implementations may queue work asynchronously. `wait` may block: the
/// service drives this controller on an owned blocking thread.
pub trait ControllerRuntime: Send + Sync {
    fn validate(
        &self,
        program: &Program,
        binding_names: &[String],
        limits: EvaluationLimits,
    ) -> Result<()>;
    fn bounds(&self) -> ControllerBounds;
    fn evaluation_limits(&self) -> EvaluationLimits {
        EvaluationLimits::default()
    }
    fn submit(&self, job: EvaluationJob) -> Result<ControllerTicket>;
    fn wait(&self, ticket: ControllerTicket) -> EvaluationCompletion;
    fn event(&self, _event: ControllerEvent) -> Result<()> {
        Ok(())
    }
}
