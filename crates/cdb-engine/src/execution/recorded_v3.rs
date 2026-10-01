//! Trusted v3 engine composition. These pending values are evidence, never publication authority.
use super::trace::{RecordingPolicy, RecordingRawView, TraceDataV3, TraceLog};
use super::*;
use crate::{
    compiler::{load_recorded_plan_with_capabilities, CompilerCapabilities, ExecutablePlan},
    diagnostics::CompileNotice,
};
use cdb_core::{
    admission::ResourceKind,
    recording::{PreparedCatalogEntry, ReplayDataInput, REQUIRED_SCOPES},
    recording_v3::{LaneIdentityV3, LanePhaseV3, ReplayDataV3, REPLAY_ABI},
    replay::{RecordedLanding, ReplayVerdict},
};

fn preparation_lane() -> LaneIdentityV3 {
    LaneIdentityV3 {
        phase: LanePhaseV3::Preparation,
        evaluation: 0,
        predicate: 0,
        attempt: 0,
        ordinal: 0,
    }
}

/// Create a bounded v3 recording trace. The same value must be supplied to the
/// native controller and `prepare_recorded_v3`.
pub fn recording_trace_v3(options: &ExecutionOptions) -> Result<TraceLog> {
    Ok(TraceLog::new_recording_v3(super::recorded::trace_limits(
        options,
    )?))
}

fn trace_data(data: &ReplayDataV3) -> Result<TraceDataV3> {
    let wire = data.projection();
    TraceDataV3::from_values(
        data.data().policy.clone(),
        data.data().reads.clone(),
        data.data().scopes.clone(),
        wire.field("lanes")?.as_array()?,
        wire.field("expected_lanes")?.as_array()?,
    )
}

/// Create the frozen v3 replay trace. The same value must be supplied to the
/// replay controller and `prepare_replay_v3`.
pub fn replay_trace_v3(data: &ReplayDataV3, options: &ExecutionOptions) -> Result<TraceLog> {
    TraceLog::new_replay_v3(super::recorded::trace_limits(options)?, &trace_data(data)?)
}

/// Computation completed while the controller's finalization lane is still open.
/// The host must finish its controller/effect ledger before calling `finish`.
pub struct PendingRecordedExecutionV3<C> {
    computation: Computation<C>,
    landings: Vec<V>,
}

/// Unpublished v3 engine result. The host combines this base and trace with
/// trusted prepared/function/release evidence in the core v3 constructor.
pub struct PreparedExecutionV3<C> {
    base: ReplayDataInput,
    trace: TraceDataV3,
    context: C,
    bytes: Vec<u8>,
}
impl<C> PreparedExecutionV3<C> {
    pub fn base(&self) -> &ReplayDataInput {
        &self.base
    }
    pub fn trace(&self) -> &TraceDataV3 {
        &self.trace
    }
    pub fn context(&self) -> &C {
        &self.context
    }
    pub fn wire_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_parts(self) -> (ReplayDataInput, TraceDataV3, C, Vec<u8>) {
        (self.base, self.trace, self.context, self.bytes)
    }
}
impl<C> PendingRecordedExecutionV3<C> {
    /// Finish only after the native controller has closed finalization.
    pub fn finish(
        self,
        trace: &TraceLog,
        options: &ExecutionOptions,
    ) -> Result<PreparedExecutionV3<C>> {
        let trace = trace.finish_v3()?;
        let c = self.computation;
        let artifacts = c
            .plan
            .projection()
            .canonical()
            .payload()
            .field("artifacts")?;
        let base = ReplayDataInput {
            stale: c.captured.snapshot != c.requested.snapshot,
            snapshot: c.captured.snapshot,
            requested_snapshot: c.requested.snapshot,
            as_of: c.captured.as_of,
            plan: c.plan.projection().canonical().clone(),
            plan_hash: c.plan.hash().clone(),
            response: c.response.canonical().clone(),
            response_hash: c.response.canonical().hash(options.limits)?,
            query: ArtifactRef::from_value(artifacts.field("query")?)?,
            profile: if *artifacts.field("profile")? == V::Null {
                None
            } else {
                Some(ArtifactRef::from_value(artifacts.field("profile")?)?)
            },
            config: ArtifactRef::from_value(artifacts.field("config")?)?,
            engine: super::recorded::engine()?,
            replay_abi: VersionId::new(REPLAY_ABI)?,
            landings: self
                .landings
                .iter()
                .map(RecordedLanding::from_value)
                .collect::<Result<_>>()?,
            catalog: c
                .catalog
                .into_iter()
                .map(|entry| {
                    Ok(PreparedCatalogEntry {
                        id: ResourceId::new(entry.id.as_str())?,
                        label: entry.label,
                        dependencies: entry.dependencies,
                    })
                })
                .collect::<Result<_>>()?,
            policy: trace.policy.clone(),
            reads: trace.reads.clone(),
            scopes: trace.scopes.clone(),
            functions: vec![],
        };
        options.check_interrupted()?;
        Ok(PreparedExecutionV3 {
            base,
            trace,
            context: c.context,
            bytes: c.bytes,
        })
    }
}

/// Execute against a trusted fixed capture and caller-owned v3 trace without publication.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_recorded_v3<B: GraphBackend, P: PolicyService>(
    draft: ValidatedDraft,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    capture: &ExecutionCapture,
    provider: &dyn ViewProvider,
    options: ExecutionOptions,
    trace: TraceLog,
) -> Result<PendingRecordedExecutionV3<P::Context>> {
    options.check_interrupted()?;
    trace.enter_lane(preparation_lane())?;
    let wrapped = RecordingPolicy::new(policy, trace.clone());
    let mut mode = walk::LandingMode::Record {
        log: trace.clone(),
        landings: vec![],
        notices: vec![],
        raw_count: 0,
        outcomes: vec![],
    };
    let computation = compute(
        draft,
        backend,
        &wrapped,
        principal,
        provider,
        None,
        &options,
        Some(&mut mode),
        Some(capture),
        true,
    )
    .await?;
    trace.merge_policy(&provider.evidence_footprint()?)?;
    let walk::LandingMode::Record { landings, .. } = mode else {
        unreachable!()
    };
    Ok(PendingRecordedExecutionV3 {
        computation,
        landings,
    })
}

fn notice_codes(plan_response: &cdb_core::canonical::CanonicalProjection) -> Result<Vec<String>> {
    plan_response
        .payload()
        .field("notices")?
        .as_array()?
        .iter()
        .map(|notice| Ok(notice.field("code")?.as_str()?.to_owned()))
        .collect()
}

fn validate_saved_landings(data: &ReplayDataInput, plan: &ExecutablePlan) -> Result<Vec<V>> {
    let mut out = Vec::with_capacity(data.landings.len());
    let mut seen = std::collections::BTreeSet::new();
    let mut counts = std::collections::BTreeMap::<(usize, bool), u64>::new();
    for landing in &data.landings {
        let value = landing.projection();
        let block =
            usize::try_from(value.field("block_index")?.u64()?).map_err(|_| Error::limit())?;
        let role = value.field("role")?.as_str()?;
        let to = match role {
            "from" => false,
            "to" => true,
            _ => return Err(Error::invalid("landing role")),
        };
        let block_data = plan
            .blocks()
            .get(block)
            .ok_or_else(|| Error::invalid("landing block"))?;
        let anchors = if to {
            block_data
                .to()
                .ok_or_else(|| Error::invalid("landing target"))?
        } else {
            block_data.from()
        };
        if !anchors
            .iter()
            .any(|anchor| anchor == value.field("anchor").and_then(V::as_str).unwrap_or(""))
            || value.field("score")?.u64()? == 0
        {
            return Err(Error::invalid("landing anchor/score"));
        }
        if plan.blocks()[block].match_mode() == crate::compiler::MatchMode::Exact
            && value.field("score")? != &V::integer(1)
        {
            return Err(Error::invalid("exact landing score"));
        }
        let id = value.field("id")?.as_str()?;
        if !data.catalog.iter().any(|entry| entry.id.as_str() == id) {
            return Err(Error::invalid("landing catalog binding"));
        }
        let key = (block, to, id.to_owned());
        if !seen.insert(key) {
            return Err(Error::invalid("duplicate landing"));
        }
        let count = counts.entry((block, to)).or_default();
        *count = count.checked_add(1).ok_or_else(Error::limit)?;
        if !to && *count > plan.caps().seed_limit {
            return Err(Error::invalid("landing seed cap"));
        }
        out.push(value);
    }
    Ok(out)
}

fn recording_engine(value: &V) -> Result<cdb_core::recording::RecordingEngine> {
    value.closed(&["name", "version", "build"], &[])?;
    Ok(cdb_core::recording::RecordingEngine {
        name: ResourceId::new(value.field("name")?.as_str()?)?,
        version: VersionId::new(value.field("version")?.as_str()?)?,
        build: ContentHash::parse(value.field("build")?.as_str()?)?,
    })
}

/// Replay execution completed with finalization still owned by the native controller.
pub struct PendingReplayV3<C> {
    expected_response_hash: ContentHash,
    response: cdb_core::projection::ResponseProjection,
    context: C,
    sources: Vec<cdb_core::evidence::SourceReference>,
}

pub struct PreparedReplayV3<C> {
    verdict: ReplayVerdict,
    context: C,
    bytes: Vec<u8>,
    sources: Vec<cdb_core::evidence::SourceReference>,
}
impl<C> PreparedReplayV3<C> {
    pub fn verdict(&self) -> ReplayVerdict {
        self.verdict
    }
    pub fn context(&self) -> &C {
        &self.context
    }
    pub fn wire_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sources(&self) -> &[cdb_core::evidence::SourceReference] {
        &self.sources
    }
    pub fn into_parts(self) -> (ReplayVerdict, C, Vec<u8>) {
        (self.verdict, self.context, self.bytes)
    }
}
impl<C> PendingReplayV3<C> {
    /// Finish after the controller closes finalization. Missing/extra trace
    /// evidence is a typed graph divergence, never a successful replay.
    pub fn finish(
        self,
        trace: &TraceLog,
        options: &ExecutionOptions,
    ) -> Result<PreparedReplayV3<C>> {
        let trace_verdict = match trace.finish_v3() {
            Ok(_) => ReplayVerdict::Reproduced,
            Err(error) if matches!(error.kind, ErrorKind::Denied | ErrorKind::PolicyChanged) => {
                return Err(error)
            }
            Err(_) => ReplayVerdict::Diverged,
        };
        let actual_hash = self.response.canonical().hash(options.limits)?;
        let verdict = if trace_verdict == ReplayVerdict::Reproduced
            && actual_hash == self.expected_response_hash
        {
            ReplayVerdict::Reproduced
        } else {
            ReplayVerdict::Diverged
        };
        let wire = obj([
            (
                "graph",
                V::string(match verdict {
                    ReplayVerdict::Reproduced => "reproduced",
                    _ => "diverged",
                }),
            ),
            ("product", V::string("not_requested")),
            ("response", self.response.canonical().payload().clone()),
            ("response_hash", V::string(actual_hash.as_str())),
        ]);
        options.check_interrupted()?;
        Ok(PreparedReplayV3 {
            verdict,
            context: self.context,
            bytes: wire.canonical_bytes(options.limits)?,
            sources: self.sources,
        })
    }
}

/// Execute the stored normalized plan over its exact original snapshot using
/// injected saved landings and the caller's exact prepared providers/controller.
/// The caller separately preflights every original positive observation.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_replay_v3<B: GraphBackend, P: PolicyService>(
    data: &ReplayDataV3,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    provider: &dyn ViewProvider,
    capabilities: CompilerCapabilities,
    executor: &cdb_core::recording::RecordingEngine,
    options: ExecutionOptions,
    trace: TraceLog,
) -> Result<PendingReplayV3<P::Context>> {
    prepare_replay_v3_inner(
        data,
        backend,
        policy,
        principal,
        provider,
        capabilities,
        executor,
        None,
        &options,
        trace,
    )
    .await
    .map_err(|error| match error.kind {
        ErrorKind::Denied => Error::new(ErrorKind::Denied, "access_denied"),
        ErrorKind::PolicyChanged => Error::new(ErrorKind::PolicyChanged, "policy_changed"),
        _ => error,
    })
}

/// Replay a v3 execution body whose traversal snapshot is semantic-v3 while
/// artifact/source dependencies are pinned by the enclosing v4 control capture.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_replay_v3_with_control<B: GraphBackend, P: PolicyService>(
    data: &ReplayDataV3,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    provider: &dyn ViewProvider,
    capabilities: CompilerCapabilities,
    executor: &cdb_core::recording::RecordingEngine,
    control_capture: &SnapshotRef,
    options: ExecutionOptions,
    trace: TraceLog,
) -> Result<PendingReplayV3<P::Context>> {
    prepare_replay_v3_inner(
        data,
        backend,
        policy,
        principal,
        provider,
        capabilities,
        executor,
        Some(control_capture),
        &options,
        trace,
    )
    .await
    .map_err(|error| match error.kind {
        ErrorKind::Denied => Error::new(ErrorKind::Denied, "access_denied"),
        ErrorKind::PolicyChanged => Error::new(ErrorKind::PolicyChanged, "policy_changed"),
        _ => error,
    })
}

#[allow(clippy::too_many_arguments)]
async fn prepare_replay_v3_inner<B: GraphBackend, P: PolicyService>(
    data: &ReplayDataV3,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    provider: &dyn ViewProvider,
    capabilities: CompilerCapabilities,
    executor: &cdb_core::recording::RecordingEngine,
    control_capture: Option<&SnapshotRef>,
    options: &ExecutionOptions,
    trace: TraceLog,
) -> Result<PendingReplayV3<P::Context>> {
    options.check_interrupted()?;
    data.bytes(options.limits)?;
    let d = data.data();
    let wire = data.projection();
    if d.engine != super::recorded::engine()?
        || d.replay_abi.as_str() != REPLAY_ABI
        || recording_engine(wire.field("executor")?)? != *executor
    {
        return Err(Error::new(ErrorKind::Unsupported, "engine replay ABI"));
    }
    let codes = notice_codes(&d.response)?;
    let compile_notices = if codes.iter().any(|code| code == "ignored_profile_about") {
        vec![CompileNotice::IgnoredProfileAbout]
    } else {
        vec![]
    };
    let plan = load_recorded_plan_with_capabilities(
        &d.plan.bytes(options.limits)?,
        &d.plan_hash,
        compile_notices,
        options.limits,
        capabilities,
    )?;
    if plan.hash() != &d.plan_hash {
        return Err(Error::invalid("plan identity"));
    }
    let landings = validate_saved_landings(d, &plan)?;
    let captured = CapturedSnapshot {
        snapshot: d.snapshot.clone(),
        as_of: d.as_of,
    };
    trace.enter_lane(preparation_lane())?;
    let prepared_result = provider.open(&captured, options).await;
    let context = policy.current(principal).await?;
    let prepared = prepared_result?;
    if prepared.view.identity() != &d.snapshot || prepared.landing.identity() != &d.snapshot {
        return Err(Error::new(ErrorKind::Snapshot, "recorded exact view"));
    }
    // Consume exactly the recorded preparation RAW occurrences. Native
    // interpretation and lexical/default resolution are never re-run here.
    trace.verify_preparation_lane(prepared.view.as_ref(), preparation_lane(), || {
        options.check_interrupted()
    })?;
    let wrapped = RecordingPolicy::new(policy, trace.clone());
    let expected = trace_data(data)?;
    let preparation = expected
        .lanes
        .iter()
        .find(|lane| lane.identity == preparation_lane())
        .ok_or_else(|| Error::invalid("missing preparation lane"))?;
    // Consume the complete frozen preparation mask by key. This performs no
    // resolver/default work; the service has separately preflighted positives.
    for observation in &preparation.policy {
        let actual = match &observation.predicate {
            Some(predicate) => wrapped.fact_allowed(&context, &observation.resource, predicate)?,
            None => wrapped.resource_allowed(&context, &observation.resource)?,
        };
        if actual != observation.allowed {
            return Err(Error::invalid("preparation policy divergence"));
        }
    }
    let artifact_capture = control_capture.unwrap_or(&d.snapshot);
    let snapshot = backend.open_snapshot(artifact_capture).await?;
    if snapshot.identity() != artifact_capture {
        return Err(Error::new(
            ErrorKind::Snapshot,
            "recorded artifact snapshot",
        ));
    }
    for value in plan
        .projection()
        .canonical()
        .payload()
        .field("artifacts")?
        .as_object()?
        .values()
    {
        if *value == V::Null {
            continue;
        }
        let reference = ArtifactRef::from_value(value)?;
        let id = ResourceId::new(reference.iri().as_str())?;
        if !wrapped.resource_allowed(&context, &id)? {
            return Err(Error::new(ErrorKind::Denied, "access_denied"));
        }
        for key in ["iri", "version", "hash"] {
            if !wrapped.fact_allowed(&context, &id, &property_iri(&format!("artifact.{key}"))?)? {
                return Err(Error::new(ErrorKind::Denied, "access_denied"));
            }
        }
        let artifact = snapshot
            .artifact(&reference)
            .await?
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "recorded artifact"))?;
        if artifact.reference() != &reference {
            return Err(Error::invalid("recorded artifact identity"));
        }
    }
    for scope in REQUIRED_SCOPES {
        let id = ResourceId::new(scope)?;
        let record = prepared
            .view
            .resource(&id)?
            .ok_or_else(|| Error::invalid("recorded scope missing"))?;
        if record.kind() != ResourceKind::SourceDescriptor
            || !wrapped.resource_allowed(&context, &id)?
        {
            return Err(Error::new(ErrorKind::Denied, "access_denied"));
        }
        for fact in record.facts() {
            if !wrapped.fact_allowed(&context, &id, fact.predicate())? {
                return Err(Error::new(ErrorKind::Denied, "access_denied"));
            }
        }
        trace.observe_scope(&id)?;
    }
    let raw = RecordingRawView::new(prepared.view.as_ref(), trace.clone());
    let mut work = Work {
        options,
        count: 0,
        bytes: 0,
    };
    let mut guard = authorized::Guard {
        view: &raw,
        policy: &wrapped,
        context: &context,
        cutoff: d.as_of,
        mappings: provider.mapped_fields(),
        ontology: provider.ontology(),
        work: &mut work,
        dependencies: super::controller::DependencyFootprint::default(),
    };
    struct Empty(SnapshotRef);
    impl LandingCatalog for Empty {
        fn identity(&self) -> &SnapshotRef {
            &self.0
        }
        fn entries(&self) -> &[LandingEntry] {
            &[]
        }
    }
    let saved_notices = codes
        .into_iter()
        .filter(|code| matches!(code.as_str(), "empty_landing" | "seed_limit"))
        .collect();
    let mut mode = walk::LandingMode::Replay {
        landings,
        notices: saved_notices,
    };
    let (response, sources) = walk::run_controller(
        &plan,
        &Empty(d.snapshot.clone()),
        &mut guard,
        d.stale,
        Some(&mut mode),
        provider.controller_runtime(),
        provider.controller_runtime().map_or(
            crate::predicates::EvaluationLimits::default(),
            ControllerRuntime::evaluation_limits,
        ),
    )?;
    trace.merge_policy(&provider.evidence_footprint()?)?;
    Ok(PendingReplayV3 {
        expected_response_hash: d.response_hash.clone(),
        response,
        context,
        sources,
    })
}
