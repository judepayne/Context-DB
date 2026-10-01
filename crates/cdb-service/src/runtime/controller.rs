//! Native adapter for the portable ordered controller. RAW never enters workers.
use super::*;
use cdb_core::{
    id::ResourceId,
    recording_v3::{LaneIdentityV3 as CoreLane, LanePhaseV3},
    Limits,
};
use cdb_engine::execution::{
    controller::*,
    trace::{FunctionCountV3, LaneOutcomeV3, TraceLog},
};
use cdb_engine::predicates::PredicateExecutor;
use std::sync::mpsc;

type Counts = Arc<Mutex<BTreeMap<String, u64>>>;
struct NativeTicket {
    receiver: mpsc::Receiver<Result<RuntimeResult>>,
    lane: LaneIdentityV3,
}
pub struct RecordedController {
    runtime: Arc<NativeRuntime>,
    request: RuntimeRequest,
    effects: effects::EffectLedger,
    trace: TraceLog,
    bounds: ControllerBounds,
    completed: Mutex<BTreeMap<LaneIdentityV3, RuntimeResult>>,
    counts: Mutex<BTreeMap<LaneIdentityV3, Counts>>,
}
pub fn preparation_lane() -> CoreLane {
    CoreLane {
        phase: LanePhaseV3::Preparation,
        evaluation: 0,
        predicate: 0,
        attempt: 0,
        ordinal: 0,
    }
}
fn finalization_lane() -> CoreLane {
    CoreLane {
        phase: LanePhaseV3::Preparation,
        evaluation: 1,
        predicate: 0,
        attempt: 0,
        ordinal: 0,
    }
}
fn phase(value: PredicatePhase) -> LanePhaseV3 {
    match value {
        PredicatePhase::Walk => LanePhaseV3::Walk,
        PredicatePhase::Filter => LanePhaseV3::Filter,
    }
}
fn lane(value: &LaneIdentityV3) -> CoreLane {
    CoreLane {
        phase: phase(value.phase),
        evaluation: value.evaluation_ordinal,
        predicate: value.predicate_index,
        attempt: value.attempt,
        ordinal: 0,
    }
}
impl RecordedController {
    pub fn new(
        runtime: Arc<NativeRuntime>,
        request: RuntimeRequest,
        trace: TraceLog,
        values: Limits,
    ) -> Result<Self> {
        let settings = &runtime.executor;
        let max_outstanding = (settings.per_request_pending / 2)
            .max(1)
            .min(settings.rhai_workers.saturating_add(settings.local_workers));
        let head_bytes = runtime
            .evaluation_limits
            .max_argument_bytes
            .checked_add(runtime.evaluation_limits.max_result_bytes)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(Error::limit)?;
        let maximum = settings
            .per_request_pending_bytes
            .min(settings.global_pending_bytes);
        let bindings = request
            .0
            .bindings
            .values()
            .map(|binding| {
                let (manifest, provider) = runtime.broker.registry().resolve(
                    &binding.function_name,
                    &binding.function_version,
                    &binding.provider,
                )?;
                Ok((manifest, provider.destination.clone()))
            })
            .collect::<Result<Vec<_>>>()?;
        let effects = effects::EffectLedger::new(
            effects::EffectLimits {
                max_groups: max_outstanding,
                max_calls: runtime.broker.settings().limits.max_logical_calls,
                max_pending_bytes: maximum,
                head_bytes: head_bytes.min(maximum),
                values,
            },
            bindings,
        )?;
        Ok(Self {
            runtime,
            request,
            effects,
            trace,
            bounds: ControllerBounds {
                max_outstanding,
                max_pending_bytes: maximum,
            },
            completed: Mutex::new(BTreeMap::new()),
            counts: Mutex::new(BTreeMap::new()),
        })
    }
    fn close_trace(&self, outcome: LaneOutcomeV3, counts: Vec<FunctionCountV3>) -> Result<()> {
        self.trace.close_lane_deferred(outcome, counts)
    }

    pub fn finish(&self) -> Result<Vec<effects::CompletedFunction>> {
        if !self
            .completed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
            || !self
                .counts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        {
            return Err(Error::invalid("unreduced native results"));
        }
        self.trace.resume_lane(finalization_lane())?;
        self.close_trace(LaneOutcomeV3::Accepted, vec![])?;
        self.effects.finish()
    }
    pub fn trace(&self) -> &TraceLog {
        &self.trace
    }
}
impl ControllerRuntime for RecordedController {
    fn validate(
        &self,
        program: &Program,
        names: &[String],
        limits: EvaluationLimits,
    ) -> Result<()> {
        crate::predicates::NativePredicateExecutor.validate(program, names, limits)
    }
    fn bounds(&self) -> ControllerBounds {
        self.bounds
    }
    fn evaluation_limits(&self) -> EvaluationLimits {
        self.runtime.evaluation_limits
    }
    fn submit(&self, job: EvaluationJob) -> Result<ControllerTicket> {
        let counts = Arc::new(Mutex::new(BTreeMap::new()));
        let host = self.runtime.recorded_host(
            &self.request,
            lane(&job.lane),
            self.effects.clone(),
            counts.clone(),
            job.argument_dependencies,
            job.state_dependencies,
        );
        let evaluation = self.runtime.evaluate_with_host(
            &self.request,
            job.program,
            job.state,
            job.bindings,
            Some(host),
        )?;
        if self
            .counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(job.lane.clone(), counts)
            .is_some()
        {
            return Err(Error::invalid("duplicate native lane"));
        }
        let (tx, receiver) = mpsc::sync_channel(1);
        self.runtime.handle.spawn(async move {
            let _ = tx.send(evaluation.await);
        });
        Ok(ControllerTicket::new(
            job.lane.clone(),
            NativeTicket {
                receiver,
                lane: job.lane,
            },
        ))
    }
    fn wait(&self, ticket: ControllerTicket) -> EvaluationCompletion {
        let lane = ticket.lane().clone();
        let outcome = (|| {
            let ticket = ticket.into_payload::<NativeTicket>()?;
            if ticket.lane != lane {
                return Err(Error::invalid("native lane identity"));
            }
            let result = ticket
                .receiver
                .recv()
                .map_err(|_| Error::new(ErrorKind::Backend, "native completion owner stopped"))??;
            let outcome = result.outcome().clone();
            self.completed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(lane.clone(), result);
            Ok(outcome)
        })();
        EvaluationCompletion { lane, outcome }
    }
    fn event(&self, event: ControllerEvent) -> Result<()> {
        match event {
            ControllerEvent::TraversalStarted => {
                self.trace.resume_lane(preparation_lane())?;
                self.close_trace(LaneOutcomeV3::Accepted, vec![])?;
            }
            ControllerEvent::FinalizationStarted => self.trace.enter_lane(finalization_lane())?,
            ControllerEvent::EvaluationOpened { phase: p, ordinal } => {
                self.effects.open_group(effects::EffectGroup {
                    phase: phase(p),
                    evaluation: ordinal,
                })?
            }
            ControllerEvent::EvaluationClosed {
                phase: p,
                ordinal,
                outcome,
            } => {
                self.effects.close_group(effects::EffectGroup {
                    phase: phase(p),
                    evaluation: ordinal,
                })?;
                let control = CoreLane {
                    phase: phase(p),
                    evaluation: ordinal,
                    predicate: u64::MAX,
                    attempt: u64::MAX,
                    ordinal: 1,
                };
                self.trace.enter_lane(control)?;
                self.close_trace(outcome, vec![])?;
            }
            ControllerEvent::ReadLane(id) => self.trace.enter_lane(lane(&id))?,
            ControllerEvent::LaneClosed(id, outcome) => {
                self.trace.resume_lane(lane(&id))?;
                let counts = self
                    .counts
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&id);
                let counts = if let Some(counts) = counts {
                    counts
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .iter()
                        .map(|(name, count)| {
                            Ok(FunctionCountV3 {
                                name: ResourceId::new(name)?,
                                count: *count,
                            })
                        })
                        .collect::<Result<Vec<_>>>()?
                } else {
                    vec![]
                };
                self.close_trace(outcome, counts)?;
            }
            ControllerEvent::Reduced(id) => {
                self.completed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&id);
            }
            ControllerEvent::AdmissionRejected(_) => self.request.cancel(),
            ControllerEvent::Submitted(_) | ControllerEvent::Completed(_) => {}
        }
        Ok(())
    }
}
