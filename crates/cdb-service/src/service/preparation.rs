//! Authenticated, owned preparation used by the native controller. No value here
//! is a durable run seal and the public recorded dispatch remains version-gated.
use super::semantic_interpretation::{
    mappings_from_config, SemanticInterpretation, SemanticProvider, SEMANTIC_COUNT_RESOLVER,
};
use super::*;
use crate::{
    broker::native_authorization::NativeBrokerAuthorizer,
    predicates::NativePredicateExecutor,
    runtime::{
        controller::RecordedController, DependencyExtension, FunctionBinding, NativeEvaluation,
        RuntimeRequest,
    },
};
use cdb_backend_fluree::{
    execution_authorization::{ExecutionAuthorization, RecordedReplayAuthorization},
    reasoning_sandbox::{reason_authorized_manifest, SandboxLimits},
    semantic_policy::verify_semantic_authority_current,
    semantic_preparation::{
        prepare_historical_authorized_view, reconstruct_recorded_authorized_view, ExtractionLimits,
    },
};
use cdb_engine::{
    compiler::{
        compile_with_compiler_capabilities, CompilerCapabilities, MappingCapabilities,
        ValidatedDraft,
    },
    execution::{
        capture_dual_execution, capture_execution, prepare_recorded_v3, prepare_replay_v3,
        prepare_replay_v3_with_control, recording_trace_v3, replay_trace_v3, stage_captured,
        ControllerRuntime, ExecutionCapture, LocalPredicateRuntime,
    },
    predicates::{EvaluationLimits, PredicateExecutor},
    values::Value,
};
use std::{collections::BTreeMap, sync::mpsc};

pub struct PreparationRequest {
    pub run_id: RunId,
    pub query: ArtifactRef,
    pub config: Option<ArtifactRef>,
    pub profile: Option<(String, ArtifactRef)>,
}
/// Native host handle, deliberately not serializable. The controller retains it
/// through evaluation/reduction. Dropping it cancels its request, not native code.
pub struct PreparedExecution {
    service: Arc<Service>,
    principal: FlureePrincipal,
    session: auth::AuthSession,
    run_id: RunId,
    draft: ValidatedDraft,
    capture: ExecutionCapture,
    semantic_interpretation: Option<SemanticInterpretation>,
    semantic_fence: Option<SemanticFenceCheck>,
    options: ExecutionOptions,
    request: RuntimeRequest,
    original: ExecutionAuthorization,
    authorizer: Arc<NativeBrokerAuthorizer>,
    authorization_log: Arc<crate::broker::authorization_log::AuthorizationLog>,
    mode: std::sync::atomic::AtomicU8,
    _permit: OwnedSemaphorePermit,
}
impl Drop for PreparedExecution {
    fn drop(&mut self) {
        self.request.cancel();
    }
}
pub struct RecordedExecutionV3 {
    pub run: cdb_core::recording_v3::RunEnvelopeV3,
    pub recording_snapshot: SnapshotRef,
    pub response: Vec<u8>,
}

pub struct RecordedExecutionV5 {
    pub run: cdb_core::recording_v5::RunEnvelopeV5,
    pub base_run: cdb_core::recording_v3::RunEnvelopeV3,
    pub recording_snapshot: SnapshotRef,
    pub response: Vec<u8>,
}

struct RecordedExecution {
    base_run: cdb_core::recording_v3::RunEnvelopeV3,
    semantic_run: Option<cdb_core::recording_v5::RunEnvelopeV5>,
    recording_snapshot: SnapshotRef,
    response: Vec<u8>,
}

pub struct ReplayedExecution {
    pub response: Vec<u8>,
    pub sources: Vec<cdb_core::evidence::SourceReference>,
}

async fn control_mapping_resources(
    backend: &FlureeBackend,
    capture: &SnapshotRef,
    _artifacts: &[ArtifactRef],
) -> Result<Vec<cdb_core::admission::DependencyRecord>> {
    let snapshot = GraphBackend::open_snapshot(backend, capture).await?;
    // Resolver artifacts are verified through ArtifactRepository at this exact
    // control capture. They are not dependency resources and must not be
    // coerced through RawQueryView::resource. Only the portable recording
    // scopes need resource records injected into the semantic view.
    let ids = cdb_core::recording::REQUIRED_SCOPES
        .iter()
        .map(|scope| ResourceId::new(*scope))
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    let mut resources = Vec::with_capacity(ids.len());
    for id in ids {
        resources.push(snapshot.resource(&id).await?.ok_or_else(|| {
            Error::new(ErrorKind::Denied, "required control dependency unavailable")
        })?);
    }
    Ok(resources)
}

fn recorded_semantic_error(reason: String) -> Error {
    let kind = match reason.as_str() {
        "semantic_history_unavailable" => ErrorKind::Backend,
        "ontology_authorization_denied" => ErrorKind::Denied,
        _ => ErrorKind::Snapshot,
    };
    Error::new(kind, reason)
}

#[derive(Clone)]
struct FrozenContext {
    principal: PrincipalId,
}
struct FrozenPolicy {
    authorization: RecordedReplayAuthorization,
    context: FrozenContext,
}
impl FrozenPolicy {
    fn new(authorization: RecordedReplayAuthorization) -> Self {
        let context = FrozenContext {
            principal: authorization.principal().clone(),
        };
        Self {
            authorization,
            context,
        }
    }
    fn decision(&self, resource: &ResourceId, predicate: Option<&Iri>) -> Result<bool> {
        self.authorization.original_decision(resource, predicate)
    }
}
impl PolicyService for FrozenPolicy {
    type Principal = FlureePrincipal;
    type Context = FrozenContext;
    fn current<'a>(&'a self, principal: &'a FlureePrincipal) -> IoFuture<'a, FrozenContext> {
        Box::pin(async move {
            if principal.id() != &self.context.principal {
                return Err(denied());
            }
            Ok(self.context.clone())
        })
    }
    fn resource_allowed(&self, context: &FrozenContext, resource: &ResourceId) -> Result<bool> {
        if context.principal != self.context.principal {
            return Err(denied());
        }
        self.decision(resource, None)
    }
    fn fact_allowed(
        &self,
        context: &FrozenContext,
        resource: &ResourceId,
        predicate: &Iri,
    ) -> Result<bool> {
        if context.principal != self.context.principal {
            return Err(denied());
        }
        self.decision(resource, Some(predicate))
    }
    fn publish<'a>(
        &'a self,
        _: &'a FlureePrincipal,
        _: &'a FrozenContext,
        _: &'a mut (dyn FnMut() -> Result<()> + Send),
    ) -> IoFuture<'a, ()> {
        Box::pin(async { Err(Error::new(ErrorKind::Unsupported, "frozen policy publish")) })
    }
}

struct ReplayOwner {
    _request: RuntimeRequest,
    options: ExecutionOptions,
    semantic: Option<SemanticFenceCheck>,
    _permit: OwnedSemaphorePermit,
}
struct ReplayFence {
    lease: SessionLease,
    owner: Arc<ReplayOwner>,
}
impl ExternalPublicationFence for ReplayFence {
    fn check(&self) -> Result<()> {
        self.lease.check().map_err(|_| denied())?;
        self.owner.options.check_interrupted()?;
        if let Some(semantic) = &self.owner.semantic {
            semantic.check()?;
        }
        Ok(())
    }
}
impl cdb_backend_fluree::execution_authorization::ExecutionFence for ReplayFence {
    fn check_disclosure(&self) -> Result<()> {
        self.check()
    }
}

impl PreparedExecution {
    pub fn capture(&self) -> &CapturedSnapshot {
        self.capture.snapshot()
    }
    pub fn captures(&self) -> &cdb_core::contracts::ExecutionCaptures {
        self.capture.captures()
    }
    pub fn draft(&self) -> &ValidatedDraft {
        &self.draft
    }
    pub fn extend_dependencies(&self, extension: DependencyExtension) -> Result<()> {
        self.request.extend_dependencies(extension)
    }
    /// Evaluate a compiled predicate on owned materialized inputs. This does not
    /// admit a child, commit NEXT, serialize a response, or publish a run.
    pub fn evaluate_predicate(
        &self,
        filter: bool,
        index: usize,
        state: V,
        bindings: BTreeMap<String, Value>,
    ) -> Result<NativeEvaluation> {
        match self
            .mode
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) | Err(2) => {}
            _ => {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "local execution already selected",
                ))
            }
        }
        self.options.check_interrupted()?;
        let predicates = if filter {
            self.draft.filter_predicates()
        } else {
            self.draft.walk_predicates()
        };
        let custom = predicates
            .get(index)
            .and_then(|p| p.custom())
            .ok_or_else(|| Error::invalid("compiled custom predicate required"))?;
        if bindings.keys().cloned().collect::<Vec<_>>() != custom.binding_names() {
            return Err(Error::invalid("compiled binding names required"));
        }
        self.service
            .runtime
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Unsupported, "native runtime unavailable"))?
            .evaluate(&self.request, custom.program().clone(), state, bindings)
    }
    pub fn is_semantic(&self) -> bool {
        self.semantic_interpretation.is_some()
    }

    /// Execute a retained non-semantic/P4 route. Semantic instance-v3 execution
    /// cannot enter or persist through this recording-v3 entry point.
    pub async fn execute_recorded_v3_portable(
        self: &Arc<Self>,
        operation_hash: ContentHash,
    ) -> Result<RecordedExecutionV3> {
        if self.is_semantic() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "semantic instance/v3 requires recording v5",
            ));
        }
        let recorded = self.execute_recorded(operation_hash).await?;
        if recorded.semantic_run.is_some() {
            return Err(Error::invalid("portable v3 semantic envelope"));
        }
        Ok(RecordedExecutionV3 {
            run: recorded.base_run,
            recording_snapshot: recorded.recording_snapshot,
            response: recorded.response,
        })
    }

    /// Execute a semantic instance-v3 route. The portable v3/V4 evidence is
    /// nested inside, but only the truthful V5 envelope is admitted and returned.
    #[deprecated(note = "current semantic recordings use the V5 wire descriptor")]
    pub async fn execute_recorded_v4(
        self: &Arc<Self>,
        operation_hash: ContentHash,
    ) -> Result<RecordedExecutionV5> {
        self.execute_recorded_v5(operation_hash).await
    }

    pub async fn execute_recorded_v5(
        self: &Arc<Self>,
        operation_hash: ContentHash,
    ) -> Result<RecordedExecutionV5> {
        if !self.is_semantic() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "recording v5 requires semantic instance/v3",
            ));
        }
        let recorded = self.execute_recorded(operation_hash).await?;
        let run = recorded
            .semantic_run
            .ok_or_else(|| Error::invalid("semantic v5 envelope missing"))?;
        Ok(RecordedExecutionV5 {
            run,
            base_run: recorded.base_run,
            recording_snapshot: recorded.recording_snapshot,
            response: recorded.response,
        })
    }

    async fn execute_recorded(
        self: &Arc<Self>,
        operation_hash: ContentHash,
    ) -> Result<RecordedExecution> {
        self.mode
            .compare_exchange(0, 3, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::new(ErrorKind::Conflict, "execution mode already selected"))?;
        let _cancel_on_drop = CallerDrop(
            self.options
                .cancellation
                .clone()
                .expect("owned request cancellation"),
        );
        let prepared = self.clone();
        run_native(
            async move {
                prepared.options.check_interrupted()?;
                let trace = recording_trace_v3(&prepared.options)?;
                let runtime = prepared
                    .service
                    .runtime
                    .as_ref()
                    .ok_or_else(|| {
                        Error::new(ErrorKind::Unsupported, "native runtime unavailable")
                    })?
                    .clone();
                let controller = RecordedController::new(
                    runtime,
                    prepared.request.clone(),
                    trace.clone(),
                    prepared.options.limits,
                )?;
                let base = prepared.service.provider(
                    prepared.principal.clone(),
                    Some(prepared.capture.captures().control().clone()),
                )?;
                let controlled = ControllerView {
                    base: &base,
                    controller: &controller,
                    trace: &trace,
                    preparation_reads: &[],
                };
                let policy = OriginalPolicy {
                    backend: prepared.service.backend.as_ref(),
                    execution: &prepared.original,
                    coordination: prepared.authorizer.coordination(),
                    handle: tokio::runtime::Handle::current(),
                };
                let semantic = prepared
                    .semantic_interpretation
                    .as_ref()
                    .map(|interpretation| SemanticProvider::new(&controlled, interpretation));
                let provider: &dyn ViewProvider = semantic
                    .as_ref()
                    .map(|value| value as &dyn ViewProvider)
                    .unwrap_or(&controlled);
                let pending = prepare_recorded_v3(
                    prepared.draft.clone(),
                    prepared.service.backend.as_ref(),
                    &policy,
                    &prepared.principal,
                    &prepared.capture,
                    provider,
                    prepared.options.clone(),
                    trace.clone(),
                )
                .await?;
                let completed = controller.finish()?;
                let engine = pending.finish(&trace, &prepared.options)?;
                let (base, trace_data, context, response) = engine.into_parts();
                if context.principal_id() != prepared.original.principal_id() {
                    return Err(denied());
                }
                let functions = completed
                    .iter()
                    .map(|function| function.recording_value(prepared.options.limits))
                    .collect::<Result<Vec<_>>>()?;
                // V4 semantic reconstruction is bound by SemanticEvidenceV4. Portable
                // v3/P4 runs retain an empty prepared list; the removed P5 descriptor
                // is never minted by current production code.
                let prepared_entries = Vec::new();
                let release_evidence = prepared.authorization_log.values();
                let footprint = prepared.original.release_footprint()?;
                let lease = prepared
                    .service
                    .auth
                    .lease(&prepared.session, auth::Operation::Query)
                    .await
                    .map_err(|_| denied())?;
                let fence = LocalFence {
                    lease,
                    owner: prepared.clone(),
                };
                let run_id = prepared.run_id.clone();
                let owner = prepared.principal.id().clone();
                let limits = prepared.options.limits;
                let commit_action = ResourceId::new(format!(
                    "urn:ctxql:release:commit:{}",
                    ContentHash::of_bytes(run_id.as_str().as_bytes()).as_str()
                ))?;
                let semantic_evidence = prepared
                    .semantic_interpretation
                    .as_ref()
                    .map(|value| value.recording_evidence().clone());
                let captures = prepared.capture.captures().clone();
                let (run, semantic_run, recording_snapshot) =
                    if let Some(semantic_evidence) = semantic_evidence {
                        let (tx, rx) = mpsc::sync_channel(1);
                        prepared
                            .service
                            .backend
                            .clone()
                            .guarded_execution_commit_v5_built(
                                prepared.original.clone(),
                                footprint,
                                Box::new(fence),
                                move |receipt| {
                                    let mut evidence = release_evidence;
                                    evidence.push(
                                        receipt
                                            .release_evidence(commit_action, limits)?
                                            .projection(),
                                    );
                                    let base_replay = cdb_core::recording_v3::ReplayDataV3::new(
                                        cdb_core::recording_v3::ReplayDataV3Input {
                                            base,
                                            lanes: trace_data.lane_values(),
                                            expected_lanes: trace_data.expected_lane_values(),
                                            functions,
                                            prepared: prepared_entries,
                                            release_evidence: evidence,
                                            executor: crate::native_identity::executor()?,
                                        },
                                        limits,
                                    )?;
                                    let replay = cdb_core::recording_v4::ReplayDataV4::new(
                                        base_replay,
                                        semantic_evidence,
                                        &captures,
                                        limits,
                                    )?;
                                    let replay =
                                        cdb_core::recording_v5::ReplayDataV5::new(replay, limits)?;
                                    cdb_core::recording_v5::RunEnvelopeV5::new(
                                        run_id,
                                        owner,
                                        operation_hash,
                                        replay,
                                        limits,
                                    )
                                },
                                move |stored, snapshot| {
                                    let base_run = cdb_core::recording_v3::RunEnvelopeV3::new(
                                        stored.id().clone(),
                                        stored.owner().clone(),
                                        stored.operation_hash().clone(),
                                        stored.replay().base().clone(),
                                        limits,
                                    )?;
                                    tx.send((base_run, stored.clone(), snapshot.clone()))
                                        .map_err(|_| denied())
                                },
                            )
                            .await?;
                        let (base_run, semantic_run, snapshot) = rx.recv().map_err(|_| {
                            Error::new(ErrorKind::Backend, "v5 commit owner stopped")
                        })?;
                        (base_run, Some(semantic_run), snapshot)
                    } else {
                        let (tx, rx) = mpsc::sync_channel(1);
                        prepared
                            .service
                            .backend
                            .clone()
                            .guarded_execution_commit_v3_built(
                                prepared.original.clone(),
                                footprint,
                                Box::new(fence),
                                move |receipt| {
                                    let mut evidence = release_evidence;
                                    evidence.push(
                                        receipt
                                            .release_evidence(commit_action, limits)?
                                            .projection(),
                                    );
                                    let replay = cdb_core::recording_v3::ReplayDataV3::new(
                                        cdb_core::recording_v3::ReplayDataV3Input {
                                            base,
                                            lanes: trace_data.lane_values(),
                                            expected_lanes: trace_data.expected_lane_values(),
                                            functions,
                                            prepared: prepared_entries,
                                            release_evidence: evidence,
                                            executor: crate::native_identity::executor()?,
                                        },
                                        limits,
                                    )?;
                                    cdb_core::recording_v3::RunEnvelopeV3::new(
                                        run_id,
                                        owner,
                                        operation_hash,
                                        replay,
                                        limits,
                                    )
                                },
                                move |stored, snapshot| {
                                    tx.send((stored.clone(), snapshot.clone()))
                                        .map_err(|_| denied())
                                },
                            )
                            .await?;
                        let (run, snapshot) = rx.recv().map_err(|_| {
                            Error::new(ErrorKind::Backend, "v3 commit owner stopped")
                        })?;
                        (run, None, snapshot)
                    };
                Ok(RecordedExecution {
                    base_run: run,
                    semantic_run,
                    recording_snapshot,
                    response,
                })
            },
            "ctxql-record-v3",
        )
        .await
    }

    /// Explicit local-only library execution. No broker callback is enabled here;
    /// no v1/v2/v3 recording claim is produced. Run persistence is a separate step.
    pub async fn execute_local(self: &Arc<Self>) -> Result<Vec<u8>> {
        if self.semantic_interpretation.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "semantic v3 execution requires v5 recording",
            ));
        }
        self.mode
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::new(ErrorKind::Conflict, "execution mode already selected"))?;
        let _cancel_on_drop = CallerDrop(
            self.options
                .cancellation
                .clone()
                .expect("owned request cancellation"),
        );
        let prepared = self.clone();
        run_native(
            async move {
                prepared.options.check_interrupted()?;
                let base = prepared.service.provider(
                    prepared.principal.clone(),
                    Some(prepared.capture.captures().control().clone()),
                )?;
                let executor = PooledLocal {
                    runtime: prepared.service.runtime.as_ref().expect("native runtime"),
                    request: &prepared.request,
                    handle: tokio::runtime::Handle::current(),
                };
                let limits = prepared
                    .service
                    .runtime
                    .as_ref()
                    .expect("native prepared request")
                    .evaluation_limits();
                let local = LocalView {
                    base,
                    executor: &executor,
                    limits,
                };
                let policy = OriginalPolicy {
                    backend: prepared.service.backend.as_ref(),
                    execution: &prepared.original,
                    coordination: prepared.authorizer.coordination(),
                    handle: tokio::runtime::Handle::current(),
                };
                let semantic = prepared
                    .semantic_interpretation
                    .as_ref()
                    .map(|interpretation| SemanticProvider::new(&local, interpretation));
                let provider: &dyn ViewProvider = semantic
                    .as_ref()
                    .map(|p| p as &dyn ViewProvider)
                    .unwrap_or(&local);
                let bytes = stage_captured(
                    prepared.draft.clone(),
                    prepared.service.backend.as_ref(),
                    &policy,
                    &prepared.principal,
                    &prepared.capture,
                    provider,
                    prepared.options.clone(),
                )
                .await?;
                if let Some(interpretation) = &prepared.semantic_interpretation {
                    let semantic = prepared
                        .service
                        .semantic
                        .as_ref()
                        .ok_or_else(|| Error::invalid("semantic role unavailable"))?;
                    verify_semantic_authority_current(semantic, interpretation.policy_basis())
                        .await
                        .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
                }
                let lease = prepared
                    .service
                    .auth
                    .lease(&prepared.session, auth::Operation::Query)
                    .await
                    .map_err(|_| denied())?;
                let footprint = prepared.original.release_footprint()?;
                let fence = LocalFence {
                    lease,
                    owner: prepared.clone(),
                };
                prepared
                    .service
                    .backend
                    .clone()
                    .guarded_execution_action(
                        prepared.original.clone(),
                        footprint,
                        Box::new(fence),
                        move || Ok(bytes),
                    )
                    .await
            },
            "ctxql-execute-local",
        )
        .await
    }
}
// Read-only adapter for staging. This is not a reusable current policy context:
// legacy publication is forbidden; only the execution capability can release.
struct OriginalPolicy<'a> {
    backend: &'a FlureeBackend,
    execution: &'a ExecutionAuthorization,
    coordination: Arc<tokio::sync::Mutex<()>>,
    handle: tokio::runtime::Handle,
}
impl OriginalPolicy<'_> {
    fn read_guard(&self) -> Result<tokio::sync::OwnedMutexGuard<()>> {
        let coordination = self.coordination.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.handle.spawn(async move {
            let _ = tx.send(coordination.lock_owned().await);
        });
        rx.recv()
            .map_err(|_| Error::new(ErrorKind::Backend, "authorization coordinator stopped"))
    }
}
impl PolicyService for OriginalPolicy<'_> {
    type Principal = FlureePrincipal;
    type Context = ExecutionAuthorization;
    fn current<'a>(
        &'a self,
        principal: &'a FlureePrincipal,
    ) -> IoFuture<'a, ExecutionAuthorization> {
        Box::pin(async move {
            if principal.id() != self.execution.principal_id() {
                return Err(denied());
            }
            Ok(self.execution.clone())
        })
    }
    fn resource_allowed(
        &self,
        context: &ExecutionAuthorization,
        resource: &ResourceId,
    ) -> Result<bool> {
        let _coordination = self.read_guard()?;
        self.backend.original_resource_allowed(context, resource)
    }
    fn fact_allowed(
        &self,
        context: &ExecutionAuthorization,
        resource: &ResourceId,
        property: &Iri,
    ) -> Result<bool> {
        let _coordination = self.read_guard()?;
        self.backend
            .original_fact_allowed(context, resource, property)
    }
    fn publish<'a>(
        &'a self,
        _: &'a FlureePrincipal,
        _: &'a ExecutionAuthorization,
        _: &'a mut (dyn FnMut() -> Result<()> + Send),
    ) -> IoFuture<'a, ()> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "original reads require execution release",
            ))
        })
    }
}
struct LocalFence {
    lease: SessionLease,
    owner: Arc<PreparedExecution>,
}
impl ExternalPublicationFence for LocalFence {
    fn check(&self) -> Result<()> {
        self.lease.check().map_err(|_| denied())?;
        self.owner.options.check_interrupted()?;
        if let Some(semantic) = &self.owner.semantic_fence {
            semantic.check()?;
        }
        Ok(())
    }
}
impl cdb_backend_fluree::execution_authorization::ExecutionFence for LocalFence {
    fn check_disclosure(&self) -> Result<()> {
        self.check()
    }
}
struct PooledLocal<'a> {
    runtime: &'a NativeRuntime,
    request: &'a RuntimeRequest,
    handle: tokio::runtime::Handle,
}
impl PredicateExecutor for PooledLocal<'_> {
    fn validate(
        &self,
        program: &cdb_engine::predicates::Program,
        names: &[String],
        limits: EvaluationLimits,
    ) -> Result<()> {
        NativePredicateExecutor.validate(program, names, limits)
    }
    fn evaluate(
        &self,
        program: &cdb_engine::predicates::Program,
        state: &V,
        bindings: &BTreeMap<String, Value>,
        host: Arc<dyn cdb_engine::predicates::FunctionCallback>,
        _: EvaluationLimits,
    ) -> Result<cdb_engine::predicates::Outcome> {
        let evaluation = self.runtime.evaluate_with_host(
            self.request,
            program.clone(),
            state.clone(),
            bindings.clone(),
            Some(host),
        )?;
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.handle.spawn(async move {
            let _ = tx.send(evaluation.await);
        });
        // Owned blocking driver: never recursively block_on its graph-I/O runtime.
        Ok(rx
            .recv()
            .map_err(|_| Error::new(ErrorKind::Backend, "native evaluation owner stopped"))??
            .into_outcome())
    }
}
struct LocalView<'a> {
    base: Provider,
    executor: &'a PooledLocal<'a>,
    limits: EvaluationLimits,
}
impl ViewProvider for LocalView<'_> {
    fn local_predicates(&self) -> Option<LocalPredicateRuntime<'_>> {
        Some(LocalPredicateRuntime {
            executor: self.executor,
            limits: self.limits,
        })
    }
    fn open<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        self.base.open(captured, options)
    }
    fn evidence_reader(&self) -> Option<&dyn SourceReader> {
        self.base.evidence_reader()
    }
    fn evidence_footprint(&self) -> Result<Vec<PolicyObservation>> {
        self.base.evidence_footprint()
    }
}

struct ControllerView<'a> {
    base: &'a dyn ViewProvider,
    controller: &'a dyn ControllerRuntime,
    trace: &'a cdb_engine::execution::trace::TraceLog,
    preparation_reads: &'a [cdb_core::recording::ReadObservation],
}
impl ViewProvider for ControllerView<'_> {
    fn controller_runtime(&self) -> Option<&dyn ControllerRuntime> {
        Some(self.controller)
    }
    fn local_predicates(&self) -> Option<LocalPredicateRuntime<'_>> {
        self.base.local_predicates()
    }
    fn propose_stale<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, Option<SnapshotRef>> {
        self.base.propose_stale(captured, options)
    }
    fn mapped_fields(&self) -> Option<&dyn cdb_engine::execution::MappedFieldProvider> {
        self.base.mapped_fields()
    }
    fn ontology(&self) -> Option<&dyn cdb_engine::execution::OntologyProvider> {
        self.base.ontology()
    }
    fn evidence_reader(&self) -> Option<&dyn SourceReader> {
        self.base.evidence_reader()
    }
    fn evidence_footprint(&self) -> Result<Vec<PolicyObservation>> {
        self.base.evidence_footprint()
    }
    fn open<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        Box::pin(async move {
            self.trace
                .import_preparation_reads(self.preparation_reads)?;
            self.base.open(captured, options).await
        })
    }
}

fn recording_engine_from_value(value: &V) -> Result<cdb_core::recording::RecordingEngine> {
    value.closed(&["name", "version", "build"], &[])?;
    Ok(cdb_core::recording::RecordingEngine {
        name: ResourceId::new(value.field("name")?.as_str()?)?,
        version: VersionId::new(value.field("version")?.as_str()?)?,
        build: ContentHash::parse(value.field("build")?.as_str()?)?,
    })
}

pub(super) async fn run_native<T, F>(future: F, name: &'static str) -> Result<T>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T>> + Send + 'static,
{
    let runtime = tokio::runtime::Handle::current();
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let _ = tx.send(runtime.block_on(future));
        })
        .map_err(|_| Error::new(ErrorKind::Backend, "native driver start failed"))?;
    rx.await
        .map_err(|_| Error::new(ErrorKind::Backend, "native driver stopped"))?
}

impl Service {
    pub(crate) async fn execute_replay(
        self: &Arc<Self>,
        token: &str,
        run_id: RunId,
        cancellation: Arc<AtomicBool>,
        semantic_v5: bool,
    ) -> Result<ReplayedExecution> {
        let session = self.auth.authenticate(token).await.map_err(|_| denied())?;
        let principal = native(
            self.backend
                .issue_principal(self.auth.principal(&session).await.map_err(|_| denied())?)
                .await,
        )?;
        let lease = self
            .auth
            .lease(&session, auth::Operation::Replay)
            .await
            .map_err(|_| denied())?;
        let deadline = lease
            .deadline()
            .map_err(|_| denied())?
            .min(Instant::now() + self.config.limits.deadline());
        let options = ExecutionOptions {
            deadline: Some(deadline),
            cancellation: Some(cancellation.clone()),
            max_retained_bytes: self.config.limits.run_bytes,
            max_records: self.config.limits.trace_entries,
            max_work: self.config.limits.max_work,
            ..Default::default()
        };
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::limit())?;
        let context = self.backend.current(&principal).await?;
        let (replay_authorization, semantic_evidence) = if semantic_v5 {
            let (run, authorization) = self
                .backend
                .prepare_recorded_replay_v5(principal.clone(), &context, &run_id)
                .await?;
            (
                authorization,
                Some((
                    run.replay().semantic().clone(),
                    run.replay().control_capture().clone(),
                )),
            )
        } else {
            (
                self.backend
                    .prepare_recorded_replay(principal.clone(), &context, &run_id)
                    .await?,
                None,
            )
        };
        let run = replay_authorization.run().clone();
        let source_control_capture = semantic_evidence
            .as_ref()
            .map(|(_, control)| control.clone())
            .unwrap_or_else(|| run.replay().data().snapshot.clone());
        let replay_mapping_enabled = semantic_evidence
            .as_ref()
            .map(|(evidence, _)| {
                Ok::<bool, Error>(
                    evidence
                        .mapping(options.limits)?
                        .projection()
                        .field("algorithm")?
                        .as_str()?
                        != "none/v1",
                )
            })
            .transpose()?
            .unwrap_or(false);
        let replay_mappings = if replay_mapping_enabled {
            mappings_from_config(run.replay().data().plan.payload().field("config")?)?
        } else {
            Vec::new()
        };
        let mut replay_mapping_artifacts = replay_mappings
            .iter()
            .filter_map(|mapping| mapping.resolver().cloned())
            .collect::<Vec<_>>();
        replay_mapping_artifacts.sort_by(|left, right| {
            (left.iri(), left.version(), left.hash()).cmp(&(
                right.iri(),
                right.version(),
                right.hash(),
            ))
        });
        replay_mapping_artifacts.dedup();
        for resolver in &replay_mapping_artifacts {
            let artifact = self
                .preload(&context, &source_control_capture, resolver)
                .await?;
            if artifact.content() != SEMANTIC_COUNT_RESOLVER {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "semantic mapping resolver unavailable",
                ));
            }
        }
        let semantic_interpretation = if let Some((evidence, control_capture)) = semantic_evidence {
            if evidence.principal()? != *principal.id() {
                return Err(denied());
            }
            let semantic = self
                .semantic
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::Backend, "semantic role unavailable"))?;
            let snapshot = evidence.capture(options.limits)?;
            let t = snapshot
                .pin()
                .revision()
                .as_str()
                .parse::<i64>()
                .map_err(|_| Error::invalid("semantic transaction"))?;
            let source_capture = semantic
                .capture_at_t(
                    t,
                    Some(snapshot.pin().receipt()),
                    evidence.requested_as_of()?,
                )
                .await?;
            let authorized = reconstruct_recorded_authorized_view(
                semantic,
                &source_capture,
                &evidence,
                ExtractionLimits::default(),
                options.limits,
            )
            .await
            .map_err(recorded_semantic_error)?;
            let captured = CapturedSnapshot {
                snapshot,
                as_of: run.replay().data().as_of,
            };
            let reasoner = evidence.version_field("reasoner")?;
            let interpretation = match reasoner.as_str() {
                "none/v1" => {
                    if evidence.version_field("materializer")?.as_str() != "none/v1" {
                        return Err(Error::new(
                            ErrorKind::Snapshot,
                            "ontology_snapshot_divergence",
                        ));
                    }
                    if replay_mapping_enabled {
                        SemanticInterpretation::new_authorized_mapped(
                            &captured,
                            authorized,
                            replay_mappings.clone(),
                            replay_mapping_artifacts.clone(),
                        )?
                    } else {
                        SemanticInterpretation::new_authorized(&captured, authorized)?
                    }
                }
                value if value.starts_with(cdb_core::recording_v5::REASONER_PREFIX) => {
                    if evidence.version_field("materializer")?.as_str()
                        != "ctxql-fluree-authorized-union/v2"
                    {
                        return Err(Error::new(
                            ErrorKind::Snapshot,
                            "ontology_snapshot_divergence",
                        ));
                    }
                    let ontology =
                        reason_authorized_manifest(&authorized.manifest, SandboxLimits::default())
                            .await?;
                    if replay_mapping_enabled {
                        SemanticInterpretation::new_mapped(
                            &captured,
                            authorized,
                            ontology,
                            replay_mappings.clone(),
                            replay_mapping_artifacts.clone(),
                        )?
                    } else {
                        SemanticInterpretation::new(&captured, authorized, ontology)?
                    }
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::Snapshot,
                        "ontology_snapshot_divergence",
                    ))
                }
            }
            .with_control_resources(
                control_mapping_resources(
                    self.backend.as_ref(),
                    &control_capture,
                    &replay_mapping_artifacts,
                )
                .await?,
            );
            let actual = interpretation.recording_evidence().projection();
            for field in [
                "full_ontology_bundle_root",
                "ontology_profile_result_root",
                "reasoner_input_root",
                "profile_limits_identity",
                "materialization_limits_identity",
                "reasoning_limits_identity",
                "prepared_root",
                "diagnostics_root",
                "budget_identity",
            ] {
                if ContentHash::parse(actual.field(field)?.as_str()?)?
                    != evidence.hash_field(field)?
                {
                    return Err(Error::new(
                        ErrorKind::Snapshot,
                        "ontology_snapshot_divergence",
                    ));
                }
            }
            for field in [
                "ontology_profile",
                "structural_mapping_algorithm",
                "materializer",
                "reasoner",
            ] {
                if VersionId::new(actual.field(field)?.as_str()?)?
                    != evidence.version_field(field)?
                {
                    return Err(Error::new(
                        ErrorKind::Snapshot,
                        "ontology_snapshot_divergence",
                    ));
                }
            }
            if interpretation.mapping_descriptor().projection()
                != evidence.mapping(options.limits)?.projection()
            {
                return Err(Error::new(
                    ErrorKind::Snapshot,
                    "semantic_mapping_snapshot_divergence",
                ));
            }
            verify_semantic_authority_current(semantic, interpretation.policy_basis())
                .await
                .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
            Some(interpretation)
        } else {
            None
        };
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Unsupported, "native runtime unavailable"))?
            .clone();
        if crate::native_identity::executor()?
            != recording_engine_from_value(run.replay().projection().field("executor")?)?
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "native replay executor unavailable",
            ));
        }
        let bindings = self.bind_recorded_functions(&runtime, run.replay())?;
        let authorizer = Arc::new(
            NativeBrokerAuthorizer::new_replay(
                self.backend.clone(),
                self.auth.clone(),
                session.clone(),
                format!("native-replay:{}", run.id().as_str()),
                run.id().as_str().to_owned(),
                &replay_authorization,
            )
            .await?
            .with_request_controls(deadline, cancellation),
        );
        let runtime_request = runtime.request(
            format!("native-replay:{}", run.id().as_str()),
            run.id().as_str().to_owned(),
            bindings,
            authorizer.clone(),
        )?;
        let mut fixed = DependencyExtension::default();
        for observation in run
            .replay()
            .data()
            .policy
            .iter()
            .filter(|observation| observation.allowed)
        {
            match &observation.predicate {
                Some(predicate) => fixed
                    .facts
                    .push((observation.resource.clone(), predicate.clone())),
                None => fixed.graph.push(observation.resource.clone()),
            }
        }
        fixed
            .scopes
            .extend(run.replay().data().scopes.iter().cloned());
        runtime_request.extend_dependencies(fixed)?;
        let frozen = FrozenPolicy::new(replay_authorization);
        if !run
            .replay()
            .projection()
            .field("prepared")?
            .as_array()?
            .is_empty()
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "obsolete P5 semantic recording is not executable",
            ));
        }
        let semantic_fence = semantic_interpretation
            .as_ref()
            .map(|interpretation| {
                Ok::<SemanticFenceCheck, Error>(SemanticFenceCheck::current(
                    self.semantic
                        .as_ref()
                        .ok_or_else(|| Error::invalid("semantic role unavailable"))?
                        .clone(),
                    interpretation.policy_basis().clone(),
                ))
            })
            .transpose()?;
        let owner = Arc::new(ReplayOwner {
            _request: runtime_request.clone(),
            options: options.clone(),
            semantic: semantic_fence,
            _permit: permit,
        });
        let service = self.clone();
        run_native(
            async move {
                let trace = replay_trace_v3(run.replay(), &options)?;
                let controller = RecordedController::new(
                    runtime,
                    runtime_request,
                    trace.clone(),
                    options.limits,
                )?;
                let base =
                    service.provider(principal.clone(), Some(source_control_capture.clone()))?;
                let controlled = ControllerView {
                    base: &base,
                    controller: &controller,
                    trace: &trace,
                    preparation_reads: &[],
                };
                let semantic = semantic_interpretation
                    .as_ref()
                    .map(|value| SemanticProvider::new(&controlled, value));
                let provider: &dyn ViewProvider = semantic
                    .as_ref()
                    .map(|value| value as &dyn ViewProvider)
                    .unwrap_or(&controlled);
                let capabilities = CompilerCapabilities {
                    mappings: MappingCapabilities {
                        stored_predicate: true,
                        reasoned: true,
                        computed: true,
                        ontology: true,
                        lexical_landing: true,
                    },
                    custom_predicates: true,
                    external_functions: true,
                    prepared_interpretation: true,
                    approximate_landing: true,
                };
                let executor = crate::native_identity::executor()?;
                let pending = if semantic_v5 {
                    prepare_replay_v3_with_control(
                        run.replay(),
                        service.backend.as_ref(),
                        &frozen,
                        &principal,
                        provider,
                        capabilities,
                        &executor,
                        &source_control_capture,
                        options.clone(),
                        trace.clone(),
                    )
                    .await?
                } else {
                    prepare_replay_v3(
                        run.replay(),
                        service.backend.as_ref(),
                        &frozen,
                        &principal,
                        provider,
                        capabilities,
                        &executor,
                        options.clone(),
                        trace.clone(),
                    )
                    .await?
                };
                let actual_functions = controller
                    .finish()?
                    .iter()
                    .map(|function| function.recording_value(options.limits))
                    .collect::<Result<Vec<_>>>()?;
                let functions_match =
                    actual_functions == run.replay().projection().field("functions")?.as_array()?;
                let replayed = pending.finish(&trace, &options)?;
                let sources = replayed.sources().to_vec();
                let mut response = V::parse(replayed.wire_bytes(), options.limits)?;
                if !functions_match {
                    let V::Object(fields) = &mut response else {
                        return Err(Error::invalid("replay response object"));
                    };
                    fields.insert("graph".into(), V::string("diverged"));
                }
                let bytes = response.canonical_bytes(options.limits)?;
                if let Some(interpretation) = &semantic_interpretation {
                    let semantic = service.semantic.as_ref().ok_or_else(|| {
                        Error::new(ErrorKind::Backend, "semantic role unavailable")
                    })?;
                    verify_semantic_authority_current(semantic, interpretation.policy_basis())
                        .await
                        .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
                }
                let fence = ReplayFence { lease, owner };
                let response = service
                    .backend
                    .clone()
                    .guarded_recorded_replay_action(
                        &frozen.authorization,
                        Box::new(fence),
                        move || Ok(bytes),
                    )
                    .await?;
                Ok(ReplayedExecution { response, sources })
            },
            "ctxql-replay-v3",
        )
        .await
    }

    fn bind_recorded_functions(
        &self,
        runtime: &NativeRuntime,
        replay: &cdb_core::recording_v3::ReplayDataV3,
    ) -> Result<Vec<FunctionBinding>> {
        let projection = replay.projection();
        let functions = projection.field("functions")?.as_array()?;
        if functions.is_empty() {
            return Ok(vec![]);
        }
        let configured = self
            .config
            .broker
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Unsupported, "function broker unavailable"))?;
        functions
            .iter()
            .map(|function| {
                if function.field("replay")?.as_str()? != "exact"
                    || !function.field("deterministic")?.as_bool()?
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "function is not exactly replayable",
                    ));
                }
                let name = function.field("name")?.as_str()?;
                let reference = ArtifactRef::from_value(function.field("manifest")?)?;
                let manifest = runtime
                    .broker()
                    .registry()
                    .manifest(name, reference.version().as_str())
                    .ok_or_else(|| Error::new(ErrorKind::Unsupported, "manifest unavailable"))?;
                if manifest.artifact() != &reference
                    || manifest.exact_bytes() != function.field("source")?.as_str()?.as_bytes()
                    || manifest.deterministic() != function.field("deterministic")?.as_bool()?
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "exact manifest build unavailable",
                    ));
                }
                let destinations = function.field("destinations")?.as_array()?;
                if destinations.len() != 1 {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "one exact replay destination required",
                    ));
                }
                let destination = ResourceId::new(destinations[0].as_str()?)?;
                let providers = configured
                    .providers
                    .keys()
                    .filter(|id| {
                        runtime
                            .broker()
                            .registry()
                            .provider(id)
                            .is_some_and(|provider| {
                                provider.destination == destination && provider.permits(&manifest)
                            })
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if providers.len() != 1 {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "exact replay provider unavailable",
                    ));
                }
                Ok(FunctionBinding {
                    script_name: name.to_owned(),
                    function_name: name.to_owned(),
                    function_version: reference.version().as_str().to_owned(),
                    manifest: reference,
                    provider: providers[0].clone(),
                    deterministic: manifest.deterministic(),
                    order_independent: manifest.order_independent(),
                    retry_safe: manifest.retry_safe(),
                    batching: manifest.batching(),
                })
            })
            .collect()
    }

    /// Shared authenticated preparation for native library/controller use. CLI and
    /// HTTP recorded queries cannot silently fall back to this unrecorded path.
    pub async fn prepare_execution(
        self: &Arc<Self>,
        token: &str,
        request: PreparationRequest,
        cancellation: Arc<AtomicBool>,
    ) -> Result<Arc<PreparedExecution>> {
        let session = self.auth.authenticate(token).await.map_err(|_| denied())?;
        let principal = native(
            self.backend
                .issue_principal(self.auth.principal(&session).await.map_err(|_| denied())?)
                .await,
        )?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Unsupported, "native instance/v2 required"))?;
        let lease = self
            .auth
            .lease(&session, auth::Operation::Query)
            .await
            .map_err(|_| denied())?;
        let deadline = lease
            .deadline()
            .map_err(|_| denied())?
            .min(Instant::now() + self.config.limits.deadline());
        drop(lease);
        let options = ExecutionOptions {
            deadline: Some(deadline),
            cancellation: Some(cancellation.clone()),
            max_retained_bytes: self.config.limits.run_bytes,
            max_records: self.config.limits.trace_entries,
            max_work: self.config.limits.max_work,
            ..Default::default()
        };
        options.check_interrupted()?;
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::limit())?;
        let context = self.backend.current(&principal).await?;
        self.backend.require_operation(&context, Operation::Query)?;
        let pin = GraphBackend::head(self.backend.as_ref()).await?;
        let query = self.preload(&context, &pin, &request.query).await?;
        let config_ref = match request.config {
            Some(reference) => reference,
            None => self.config.required_default_config()?,
        };
        let config = self.preload(&context, &pin, &config_ref).await?;
        let profile = if let Some((selector, reference)) = request.profile {
            let artifact = self.preload(&context, &pin, &reference).await?;
            let source =
                frontend::parse(ArtifactKind::Profile, artifact.content(), options.limits)?.value;
            if source.field("name")?.as_str()? != selector {
                return Err(Error::invalid("published profile name binding"));
            }
            Some((selector, artifact))
        } else {
            None
        };
        let draft = compile_with_compiler_capabilities(
            QuerySource::published(&query),
            profile
                .as_ref()
                .map(|(selector, artifact)| SelectedProfile { selector, artifact }),
            &config,
            CompileOptions::default(),
            CompilerCapabilities {
                custom_predicates: true,
                external_functions: true,
                prepared_interpretation: true,
                approximate_landing: true,
                mappings: MappingCapabilities {
                    stored_predicate: true,
                    reasoned: true,
                    computed: true,
                    ontology: true,
                    lexical_landing: true,
                },
            },
        )?;
        for predicate in draft
            .walk_predicates()
            .iter()
            .chain(draft.filter_predicates())
        {
            if let Some(custom) = predicate.custom() {
                NativePredicateExecutor.validate(
                    custom.program(),
                    &custom.binding_names(),
                    runtime.evaluation_limits(),
                )?;
            }
        }
        let bindings = self.bind_functions(runtime, &draft.semantic_config())?;
        options.check_interrupted()?;
        let capture = if let Some(semantic) = &self.semantic {
            // Historical selection belongs exclusively to the semantic role.
            // Control artifacts are captured independently at their current head.
            let semantic =
                SemanticProjectionSource::capture(semantic.as_ref(), draft.requested_as_of())
                    .await?;
            let control = GraphBackend::capture(self.backend.as_ref(), None).await?;
            capture_dual_execution(semantic, control.snapshot)
        } else {
            capture_execution(self.backend.as_ref(), draft.requested_as_of()).await?
        };
        let context = self.backend.current(&principal).await?;
        self.backend.require_operation(&context, Operation::Query)?;
        let predicates = draft
            .walk_predicates()
            .iter()
            .chain(draft.filter_predicates())
            .collect::<Vec<_>>();
        let needs_mapping = predicates.iter().any(|p| {
            p.mapping().is_some()
                || p.custom().is_some_and(|c| {
                    c.bindings().values().any(|b| {
                        matches!(b, cdb_engine::compiler::CustomBinding::Field(_, Some(_)))
                    })
                })
        });
        let needs_ontology = predicates.iter().any(|p| {
            p.builtin().is_some_and(|b| {
                matches!(
                    b.operator(),
                    cdb_engine::values::Operator::Isa
                        | cdb_engine::values::Operator::NotIsa
                        | cdb_engine::values::Operator::ContainsIsa
                        | cdb_engine::values::Operator::SubpropertyOf
                        | cdb_engine::values::Operator::NotSubpropertyOf
                        | cdb_engine::values::Operator::ContainsSubpropertyOf
                )
            })
        });
        let semantic_mappings = if self.semantic.is_some() && needs_mapping {
            mappings_from_config(&draft.semantic_config())?
        } else {
            Vec::new()
        };
        let needs_semantic_reasoning = needs_ontology
            || semantic_mappings.iter().any(|mapping| {
                matches!(
                    mapping,
                    cdb_engine::compiler::FieldMapping::Reasoned { .. }
                        | cdb_engine::compiler::FieldMapping::Computed { .. }
                )
            });
        let mut semantic_mapping_artifacts = semantic_mappings
            .iter()
            .filter_map(|mapping| mapping.resolver().cloned())
            .collect::<Vec<_>>();
        semantic_mapping_artifacts.sort_by(|left, right| {
            (left.iri(), left.version(), left.hash()).cmp(&(
                right.iri(),
                right.version(),
                right.hash(),
            ))
        });
        semantic_mapping_artifacts.dedup();
        if self.semantic.is_some() {
            for resolver in &semantic_mapping_artifacts {
                let artifact = self
                    .preload(&context, capture.captures().control(), resolver)
                    .await?;
                if artifact.content() != SEMANTIC_COUNT_RESOLVER {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "semantic mapping resolver unavailable",
                    ));
                }
            }
        }
        let semantic_interpretation = if let Some(semantic) = &self.semantic {
            let semantic_snapshot = &capture.snapshot().snapshot;
            let t = semantic_snapshot
                .pin()
                .revision()
                .as_str()
                .parse::<i64>()
                .map_err(|_| Error::invalid("semantic transaction"))?;
            let source_capture = semantic
                .capture_at_t(
                    t,
                    Some(semantic_snapshot.pin().receipt()),
                    draft.requested_as_of(),
                )
                .await?;
            let authorized = prepare_historical_authorized_view(
                semantic,
                &source_capture,
                principal.id().as_str(),
                "https://ns.flur.ee/db#view",
                ExtractionLimits::default(),
            )
            .await
            .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
            let interpretation = if needs_semantic_reasoning {
                let prepared =
                    reason_authorized_manifest(&authorized.manifest, SandboxLimits::default())
                        .await?;
                SemanticInterpretation::new_mapped(
                    capture.snapshot(),
                    authorized,
                    prepared,
                    semantic_mappings,
                    semantic_mapping_artifacts.clone(),
                )?
            } else if needs_mapping {
                SemanticInterpretation::new_authorized_mapped(
                    capture.snapshot(),
                    authorized,
                    semantic_mappings,
                    semantic_mapping_artifacts.clone(),
                )?
            } else {
                SemanticInterpretation::new_authorized(capture.snapshot(), authorized)?
            }
            .with_control_resources(
                control_mapping_resources(
                    self.backend.as_ref(),
                    capture.captures().control(),
                    &semantic_mapping_artifacts,
                )
                .await?,
            );
            verify_semantic_authority_current(semantic, interpretation.policy_basis())
                .await
                .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
            Some(interpretation)
        } else {
            None
        };
        if self.semantic.is_none() && (needs_mapping || needs_ontology) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "semantic authority unavailable",
            ));
        }
        let plan = draft.clone().finalize(capture.snapshot().as_of)?;
        let execution = self
            .backend
            .capture_execution(
                principal.clone(),
                capture.captures().control().clone(),
                capture.snapshot().as_of,
                request.run_id.clone(),
                plan.hash().clone(),
                Operation::Query,
            )
            .await?;
        let session_id = format!("native:{}", request.run_id.as_str());
        let authorization_log = Arc::new(crate::broker::authorization_log::AuthorizationLog::new(
            options.limits,
            self.config.limits.run_bytes,
            self.config.limits.trace_entries,
        ));
        let authorizer = Arc::new(
            NativeBrokerAuthorizer::new(
                self.backend.clone(),
                self.auth.clone(),
                session.clone(),
                session_id.clone(),
                request.run_id.as_str().into(),
                execution.clone(),
            )
            .await?
            .with_request_controls(deadline, cancellation)
            .with_recording(authorization_log.clone()),
        );
        let runtime_request = runtime.request(
            session_id,
            request.run_id.as_str().into(),
            bindings,
            authorizer.clone(),
        )?;
        let mut dependencies = DependencyExtension::default();
        for value in plan
            .projection()
            .canonical()
            .payload()
            .field("artifacts")?
            .as_object()?
            .values()
        {
            if *value != V::Null {
                let artifact = ArtifactRef::from_value(value)?;
                let id = ResourceId::new(artifact.iri().as_str())?;
                dependencies.graph.push(id.clone());
                for key in ["iri", "version", "hash"] {
                    dependencies.facts.push((
                        id.clone(),
                        execution::property_iri(&format!("artifact.{key}"))?,
                    ));
                }
            }
        }
        if semantic_interpretation.is_some() {
            dependencies.scopes.extend(
                cdb_core::recording::REQUIRED_SCOPES
                    .iter()
                    .map(|scope| ResourceId::new(*scope))
                    .collect::<Result<Vec<_>>>()?,
            );
        }
        runtime_request.extend_dependencies(dependencies)?;
        options.check_interrupted()?;
        let semantic_fence = semantic_interpretation
            .as_ref()
            .map(|interpretation| {
                Ok::<SemanticFenceCheck, Error>(SemanticFenceCheck::current(
                    self.semantic
                        .as_ref()
                        .ok_or_else(|| Error::invalid("semantic role unavailable"))?
                        .clone(),
                    interpretation.policy_basis().clone(),
                ))
            })
            .transpose()?;
        Ok(Arc::new(PreparedExecution {
            service: self.clone(),
            principal,
            session,
            run_id: request.run_id,
            draft,
            capture,
            semantic_interpretation,
            semantic_fence,
            options,
            request: runtime_request,
            original: execution,
            authorizer,
            authorization_log,
            mode: std::sync::atomic::AtomicU8::new(0),
            _permit: permit,
        }))
    }

    fn bind_functions(
        &self,
        runtime: &NativeRuntime,
        semantic: &V,
    ) -> Result<Vec<FunctionBinding>> {
        let mut result = Vec::new();
        for (name, definition) in semantic.field("external_functions")?.as_object()? {
            let version = definition.field("version")?.as_str()?;
            let manifest = runtime
                .broker()
                .registry()
                .manifest(name, version)
                .ok_or_else(|| Error::new(ErrorKind::Unsupported, "exact function unavailable"))?;
            if manifest.artifact().iri().as_str() != definition.field("manifest_uri")?.as_str()?
                || manifest.artifact().hash().as_str()
                    != definition.field("manifest_hash")?.as_str()?
                || manifest.deterministic() != definition.field("deterministic")?.as_bool()?
            {
                return Err(Error::invalid("exact configured function mismatch"));
            }
            let configured =
                self.config.broker.as_ref().ok_or_else(|| {
                    Error::new(ErrorKind::Unsupported, "function broker unavailable")
                })?;
            let providers: Vec<_> = configured
                .providers
                .keys()
                .filter(|id| {
                    runtime
                        .broker()
                        .registry()
                        .provider(id)
                        .is_some_and(|p| p.permits(&manifest))
                })
                .collect();
            if providers.len() != 1 {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "unambiguous startup function route required",
                ));
            }
            result.push(FunctionBinding {
                script_name: name.clone(),
                function_name: name.clone(),
                function_version: version.into(),
                manifest: manifest.artifact().clone(),
                provider: providers[0].clone(),
                deterministic: manifest.deterministic(),
                order_independent: manifest.order_independent(),
                retry_safe: manifest.retry_safe(),
                batching: manifest.batching(),
            });
        }
        Ok(result)
    }
}
