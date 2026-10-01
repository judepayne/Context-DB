//! Bounded reference semantics over explicitly trusted adapters; not a production security boundary.
mod authorized;
pub mod controller;
pub use controller::{
    CallbackIdentityV3, ControllerBounds, ControllerEvent, ControllerRuntime, ControllerTicket,
    EvaluationCompletion, EvaluationJob, LaneIdentityV3, PredicatePhase,
};
mod local;
pub use local::LocalPredicateRuntime;
mod recorded;
mod recorded_v3;
pub mod trace;
mod walk;
use crate::compiler::ValidatedDraft;
use cdb_core::{
    artifact::ArtifactRef, contracts::*, id::*, snapshot::*, CanonicalValue as V, Error, ErrorKind,
    Limits, Result,
};
pub use recorded::{prepare_recorded, prepare_replay, PreparedExecution, PreparedReplay};
pub use recorded_v3::{
    prepare_recorded_v3, prepare_replay_v3, prepare_replay_v3_with_control, recording_trace_v3,
    replay_trace_v3, PendingRecordedExecutionV3, PendingReplayV3, PreparedExecutionV3,
    PreparedReplayV3,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

/// Trusted exact catalog entries. Dependencies include every supporting label fact resource.
#[derive(Clone, Debug)]
pub struct LandingEntry {
    pub id: EntityId,
    pub label: Option<String>,
    pub dependencies: Vec<ResourceId>,
}
pub trait LandingCatalog: Send + Sync {
    fn identity(&self) -> &SnapshotRef;
    fn entries(&self) -> &[LandingEntry];
    /// True only when the provider has already authorized the complete catalog
    /// against the same exact snapshot (for example, semantic E0 extraction).
    /// This includes every label and its support dependencies, not just entity
    /// identifiers. Ordinary catalogs remain subject to per-entity and
    /// dependency policy checks.
    fn entries_are_authorized(&self) -> bool {
        false
    }
}
pub struct PreparedView {
    pub view: Arc<dyn RawQueryView>,
    pub landing: Arc<dyn LandingCatalog>,
}
/// Required interpretation dependencies, checked before resolving a mapped value.
#[derive(Clone, Debug)]
pub struct MappingDependency {
    pub resource: ResourceId,
    pub facts: Vec<Iri>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OntologyKind {
    Class,
    Property,
}
/// Immutable, exact-snapshot ontology capability. `entails` includes exact and
/// native transitive closure; dependencies conservatively cover negative answers.
pub trait OntologyProvider: Send + Sync {
    fn claim_dependencies(&self) -> &[ClaimId] {
        &[]
    }
    fn artifact_dependencies(&self) -> &[ArtifactRef] {
        &[]
    }
    fn identity(&self) -> &SnapshotRef;
    /// Semantic ontology providers must expose the sealed authorized/prepared
    /// identity. Absence never authorizes ontology-dependent execution.
    fn prepared_descriptor(&self) -> Option<&PreparedOntologyDescriptor> {
        None
    }
    fn supports(&self, kind: OntologyKind) -> bool;
    fn dependencies(
        &self,
        kind: OntologyKind,
        actual: &str,
        target: &str,
    ) -> Result<&[MappingDependency]>;
    fn entails(&self, kind: OntologyKind, actual: &str, target: &str) -> Result<bool>;
}
/// Trusted, deterministic resolver. All returned data is borrowed and
/// immutable for the full snapshot. Methods must perform bounded local lookup (no I/O).
/// Dependencies must include every fact used, including facts establishing absence.
/// Returning no value means Missing, never a request for generic ext fallback.
fn verify_prepared_ontology(ontology: &dyn OntologyProvider, capture: &SnapshotRef) -> Result<()> {
    if ontology.identity() != capture {
        return Err(Error::new(
            ErrorKind::Snapshot,
            "exact ontology snapshot required",
        ));
    }
    let descriptor = ontology.prepared_descriptor().ok_or_else(|| {
        Error::new(
            ErrorKind::Unsupported,
            "prepared ontology descriptor unavailable",
        )
    })?;
    if &descriptor.capture != capture
        || descriptor.ontology_profile.as_str() == "none/v1"
        || descriptor.materializer.as_str() == "none/v1"
        || descriptor.reasoner.as_str() == "none/v1"
    {
        return Err(Error::new(
            ErrorKind::Snapshot,
            "prepared ontology identity mismatch",
        ));
    }
    Ok(())
}

pub trait MappedFieldProvider: Send + Sync {
    fn claim_dependencies(&self) -> &[ClaimId] {
        &[]
    }
    fn artifact_dependencies(&self) -> &[ArtifactRef] {
        &[]
    }
    fn identity(&self) -> &SnapshotRef;
    fn supports(&self, mapping: &crate::compiler::StoredPredicateMapping) -> bool;
    fn dependencies(
        &self,
        claim: &ClaimId,
        mapping: &crate::compiler::StoredPredicateMapping,
    ) -> Result<&[MappingDependency]>;
    fn value(
        &self,
        claim: &ClaimId,
        mapping: &crate::compiler::StoredPredicateMapping,
    ) -> Result<Option<&V>>;
}
/// Stale data is selected only before preparation, never as error recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Consistency {
    Exact,
    AllowStale,
}
pub trait ViewProvider: Send + Sync {
    /// Optional bounded native controller. Existing providers remain serial and
    /// no-effects through `local_predicates` when this hook is absent.
    fn controller_runtime(&self) -> Option<&dyn ControllerRuntime> {
        None
    }
    /// Explicit local-only serial execution capability. Default P4 providers
    /// cannot execute custom programs; this is not a recording or egress seal.
    fn local_predicates(&self) -> Option<LocalPredicateRuntime<'_>> {
        None
    }
    /// Called only by explicit AllowStale after authority closes the requested cutoff.
    /// None requests exact preparation. A proposal is not proof of ancestry.
    fn propose_stale<'a>(
        &'a self,
        _requested: &'a CapturedSnapshot,
        _options: &'a ExecutionOptions,
    ) -> IoFuture<'a, Option<SnapshotRef>> {
        Box::pin(async { Ok(None) })
    }
    /// Default-none seam; existing providers and PreparedView literals remain unchanged.
    fn mapped_fields(&self) -> Option<&dyn MappedFieldProvider> {
        None
    }
    /// Prepared interpretation only; absence never degrades to exact-only matching.
    fn ontology(&self) -> Option<&dyn OntologyProvider> {
        None
    }
    /// Optional trusted fixture source adapter. Called only for authorized returned-path
    /// lineage, with its exact pinned selector. No whole-document widening is permitted.
    fn evidence_reader(&self) -> Option<&dyn SourceReader> {
        None
    }
    /// Positive permissions observed by an audited evidence reader; not a caller seal.
    fn evidence_footprint(&self) -> Result<Vec<cdb_core::recording::PolicyObservation>> {
        Ok(vec![])
    }
    fn open<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView>;
}
#[derive(Clone, Debug)]
pub struct ExecutionOptions {
    pub limits: Limits,
    pub max_work: usize,
    pub max_records: usize,
    pub max_frontier: usize,
    pub max_paths: usize,
    pub max_retained_bytes: usize,
    pub page_size: PageSize,
    pub deadline: Option<Instant>,
    pub cancellation: Option<Arc<AtomicBool>>,
}
impl ExecutionOptions {
    /// Cooperative deadline/cancellation check for trusted preparation adapters.
    pub fn check_interrupted(&self) -> Result<()> {
        if self.deadline.is_some_and(|d| Instant::now() >= d)
            || self
                .cancellation
                .as_ref()
                .is_some_and(|c| c.load(Ordering::Relaxed))
        {
            return Err(Error::new(ErrorKind::Deadline, "execution interrupted"));
        }
        Ok(())
    }
}
impl Default for ExecutionOptions {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            max_work: 1_000_000,
            max_records: 100_000,
            max_frontier: 10_000,
            max_paths: 10_000,
            max_retained_bytes: 16 * 1024 * 1024,
            page_size: PageSize::new(128).expect("constant"),
            deadline: None,
            cancellation: None,
        }
    }
}
fn obj<const N: usize>(fields: [(&str, V); N]) -> V {
    V::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
struct Work<'a> {
    options: &'a ExecutionOptions,
    count: usize,
    bytes: usize,
}
impl Work<'_> {
    fn tick(&mut self, n: usize) -> Result<()> {
        self.options.check_interrupted()?;
        self.count = self.count.checked_add(n).ok_or_else(Error::limit)?;
        if self.count > self.options.max_work {
            return Err(Error::new(ErrorKind::Limit, "execution work-unit limit"));
        }
        Ok(())
    }
    // Cumulative allocations/work, deliberately stricter than peak retained bytes.
    fn retain(&mut self, value: &V) -> Result<()> {
        self.tick(1)?;
        self.bytes = self
            .bytes
            .checked_add(value.canonical_bytes(self.options.limits)?.len())
            .ok_or_else(Error::limit)?;
        if self.bytes > self.options.max_retained_bytes {
            return Err(Error::new(
                ErrorKind::Limit,
                "execution retained-byte limit",
            ));
        }
        Ok(())
    }
}
fn full_identity(snapshot: &SnapshotRef) -> V {
    obj([
        ("backend", V::string(snapshot.backend().as_str())),
        ("pin", snapshot.pin().projection()),
    ])
}

async fn validate_proposal<B: GraphBackend>(
    backend: &B,
    proposed: &SnapshotRef,
    target: &SnapshotRef,
    work: &mut Work<'_>,
) -> Result<()> {
    work.retain(&full_identity(proposed))?;
    work.retain(&full_identity(target))?;
    if !proposed.same_authority(target) {
        return Err(Error::new(ErrorKind::Snapshot, "foreign stale proposal"));
    }
    work.tick(1)?;
    if backend.open_snapshot(proposed).await?.identity() != proposed {
        return Err(Error::new(ErrorKind::Snapshot, "stale proposal identity"));
    }
    if proposed == target {
        return Ok(());
    }
    let mut previous = proposed.clone();
    let mut seen = std::collections::BTreeSet::from([proposed.clone()]);
    let mut cursor = None;
    let mut tracker = None;
    let mut records = 0usize;
    loop {
        work.tick(1)?;
        let page = backend
            .changes(proposed, target, cursor.as_ref(), work.options.page_size)
            .await?;
        work.tick(1)?;
        if page.snapshot() != target
            || page.items().len() > work.options.page_size.get()
            || (page.items().is_empty() && page.next().is_some())
        {
            return Err(Error::new(ErrorKind::Snapshot, "stale history page"));
        }
        // Stream identifiers belong to the adapter. A one-page terminal range has none.
        if tracker.is_none() {
            if let Some(next) = page.next() {
                tracker = Some(PageTracker::new(
                    target.clone(),
                    next.stream().clone(),
                    work.options.max_records,
                ));
            }
        }
        if let Some(tracker) = &mut tracker {
            tracker.accept(cursor.as_ref(), &page)?;
        }
        for batch in page.items() {
            work.tick(1)?;
            records = records
                .checked_add(1)
                .and_then(|n| n.checked_add(batch.changes().len()))
                .ok_or_else(Error::limit)?;
            if records > work.options.max_records || seen.len() >= work.options.max_frontier {
                return Err(Error::limit());
            }
            if batch.predecessor() != &previous
                || !batch.result().same_authority(target)
                || !seen.insert(batch.result().clone())
                || previous == *target
            {
                return Err(Error::new(
                    ErrorKind::Snapshot,
                    "disconnected stale history",
                ));
            }
            work.retain(&full_identity(batch.result()))?;
            for change in batch.changes() {
                work.retain(&change.projection())?;
            }
            previous = batch.result().clone();
        }
        cursor = page.next().cloned();
        if let Some(c) = &cursor {
            work.retain(&obj([
                ("snapshot", full_identity(c.snapshot())),
                ("stream", V::string(c.stream().as_str())),
                ("position", V::string(c.position().as_str())),
            ]))?;
        } else {
            break;
        }
    }
    if let Some(tracker) = tracker {
        tracker.finish()?;
    }
    if previous != *target {
        return Err(Error::new(ErrorKind::Snapshot, "incomplete stale ancestry"));
    }
    Ok(())
}

/// Versioned mapping: UTF-8 bytes outside ASCII alphanumerics and `_`/`-` are percent encoded.
/// Dotted paths identify all metadata/lineage leaves; container keys are guarded too.
pub fn property_iri(key: &str) -> Result<Iri> {
    let mut s = String::from("https://ctxql.example/reference-property/v1/");
    for b in key.bytes() {
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
            s.push(char::from(b));
        } else {
            use std::fmt::Write;
            write!(s, "%{b:02X}").expect("string write");
        }
    }
    Iri::new(s)
}
/// Captures first, prepares exact view, then acquires CURRENT authority context. Builds and
/// serializes privately, publishing only under the policy mutation gate. The trusted sink must
/// atomically accept the entire bounded buffer and must not re-enter backend/policy services.
#[allow(clippy::too_many_arguments)]
pub async fn execute<B: GraphBackend, P: PolicyService>(
    draft: ValidatedDraft,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    provider: &dyn ViewProvider,
    options: ExecutionOptions,
    sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
) -> Result<()> {
    execute_inner(
        draft, backend, policy, principal, provider, None, options, sink,
    )
    .await
}

/// Engine-issued immutable captures for preparation followed by execution. This
/// is not a permission or publication seal, and cannot be made from JSON.
#[derive(Clone)]
pub struct ExecutionCapture(ExecutionCaptures);
impl ExecutionCapture {
    /// Legacy accessor: traversal always uses the semantic capture.
    pub fn snapshot(&self) -> &CapturedSnapshot {
        self.0.semantic()
    }

    pub fn captures(&self) -> &ExecutionCaptures {
        &self.0
    }
}
/// Trusted legacy composition. Semantic and control identities are the same.
pub async fn capture_execution<B: GraphBackend>(
    backend: &B,
    requested: Option<cdb_core::Timestamp>,
) -> Result<ExecutionCapture> {
    Ok(ExecutionCapture(ExecutionCaptures::legacy(
        backend.capture(requested).await?,
    )))
}

/// Trusted dual-ledger composition after the caller has independently captured
/// and authorized both roles.
pub fn capture_dual_execution(
    semantic: CapturedSnapshot,
    control: SnapshotRef,
) -> ExecutionCapture {
    ExecutionCapture(ExecutionCaptures::new(semantic, control))
}
/// Opaque staged computation. It retains the exact accumulated policy context and
/// can only yield bytes through `publish_staged`, which performs the policy's
/// fresh publication check. It is not serializable and is not a bearer grant.
pub struct StagedExecution<C> {
    context: C,
    bytes: Vec<u8>,
    notices: Vec<String>,
}

impl<C> StagedExecution<C> {
    /// Result-cropping notices emitted by the traversal engine. `max_depth` is
    /// intentionally excluded: depth is the declared query scope, not a cropped
    /// result within that scope.
    pub fn has_result_truncation(&self) -> bool {
        self.notices.iter().any(|notice| {
            matches!(
                notice.as_str(),
                "seed_limit" | "fanout_limit" | "max_claims" | "path_limit"
            )
        })
    }
}

/// Materialize a bounded result while retaining its exact accumulated policy
/// context for a later fresh publication check.
pub async fn stage_captured_for_publication<B: GraphBackend, P: PolicyService>(
    draft: ValidatedDraft,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    capture: &ExecutionCapture,
    provider: &dyn ViewProvider,
    options: ExecutionOptions,
) -> Result<StagedExecution<P::Context>> {
    let computation = compute(
        draft,
        backend,
        policy,
        principal,
        provider,
        None,
        &options,
        None,
        Some(capture),
        false,
    )
    .await?;
    let notices = computation
        .response
        .canonical()
        .payload()
        .field("notices")?
        .as_array()?
        .iter()
        .map(|notice| Ok(notice.field("code")?.as_str()?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    Ok(StagedExecution {
        context: computation.context,
        bytes: computation.bytes,
        notices,
    })
}

/// Freshly authorize and release an opaque staged result. The policy context is
/// the one accumulated during staging; callers cannot substitute parsed bytes.
pub async fn publish_staged<P: PolicyService>(
    staged: StagedExecution<P::Context>,
    policy: &P,
    principal: &P::Principal,
    options: &ExecutionOptions,
) -> Result<Vec<u8>> {
    let StagedExecution {
        context,
        bytes,
        notices: _,
    } = staged;
    let mut bytes = Some(bytes);
    let mut released = None;
    policy
        .publish(principal, &context, &mut || {
            options.check_interrupted()?;
            released = bytes.take();
            Ok(())
        })
        .await?;
    released.ok_or_else(|| Error::new(ErrorKind::Denied, "staged result not published"))
}

/// Trusted controller primitive: materialize bounded bytes without publishing.
/// The caller must perform a fresh guarded release against the accumulated policy
/// context. This is neither a recording seal nor an authorization to disclose.
pub async fn stage_captured<B: GraphBackend, P: PolicyService>(
    draft: ValidatedDraft,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    capture: &ExecutionCapture,
    provider: &dyn ViewProvider,
    options: ExecutionOptions,
) -> Result<Vec<u8>> {
    Ok(compute(
        draft,
        backend,
        policy,
        principal,
        provider,
        None,
        &options,
        None,
        Some(capture),
        false,
    )
    .await?
    .bytes)
}
#[allow(clippy::too_many_arguments)]
pub async fn execute_captured<B: GraphBackend, P: PolicyService>(
    draft: ValidatedDraft,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    capture: &ExecutionCapture,
    provider: &dyn ViewProvider,
    options: ExecutionOptions,
    sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
) -> Result<()> {
    let computation = compute(
        draft,
        backend,
        policy,
        principal,
        provider,
        None,
        &options,
        None,
        Some(capture),
        false,
    )
    .await?;
    policy
        .publish(principal, &computation.context, &mut || {
            options.check_interrupted()?;
            sink(&computation.bytes)
        })
        .await
}

/// Explicit dual-ledger staging entry point. Artifact reads use the control
/// capture embedded in `capture`; traversal/providers use its semantic capture.
pub async fn stage_dual_captured<B: GraphBackend, P: PolicyService>(
    draft: ValidatedDraft,
    control_backend: &B,
    control_policy: &P,
    principal: &P::Principal,
    capture: &ExecutionCapture,
    provider: &dyn ViewProvider,
    options: ExecutionOptions,
) -> Result<Vec<u8>> {
    stage_captured(
        draft,
        control_backend,
        control_policy,
        principal,
        capture,
        provider,
        options,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn execute_dual_captured<B: GraphBackend, P: PolicyService>(
    draft: ValidatedDraft,
    control_backend: &B,
    control_policy: &P,
    principal: &P::Principal,
    capture: &ExecutionCapture,
    provider: &dyn ViewProvider,
    options: ExecutionOptions,
    sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
) -> Result<()> {
    execute_captured(
        draft,
        control_backend,
        control_policy,
        principal,
        capture,
        provider,
        options,
        sink,
    )
    .await
}

/// Opt-in consistency transport reports full requested/actual identities even without explain.
#[allow(clippy::too_many_arguments)]
pub async fn execute_with_consistency<B: GraphBackend, P: PolicyService>(
    draft: ValidatedDraft,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    provider: &dyn ViewProvider,
    consistency: Consistency,
    options: ExecutionOptions,
    sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
) -> Result<()> {
    execute_inner(
        draft,
        backend,
        policy,
        principal,
        provider,
        Some(consistency),
        options,
        sink,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execute_inner<B: GraphBackend, P: PolicyService>(
    draft: ValidatedDraft,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    provider: &dyn ViewProvider,
    consistency: Option<Consistency>,
    options: ExecutionOptions,
    sink: &mut (dyn FnMut(&[u8]) -> Result<()> + Send),
) -> Result<()> {
    let computation = compute(
        draft,
        backend,
        policy,
        principal,
        provider,
        consistency,
        &options,
        None,
        None,
        false,
    )
    .await?;
    policy
        .publish(principal, &computation.context, &mut || {
            options.check_interrupted()?;
            sink(&computation.bytes)
        })
        .await
}
pub(super) struct Computation<C> {
    pub(super) plan: crate::compiler::ExecutablePlan,
    pub(super) response: cdb_core::projection::ResponseProjection,
    pub(super) context: C,
    pub(super) bytes: Vec<u8>,
    pub(super) captured: CapturedSnapshot,
    pub(super) requested: CapturedSnapshot,
    pub(super) catalog: Vec<LandingEntry>,
}
#[allow(clippy::too_many_arguments)]
async fn compute<B: GraphBackend, P: PolicyService>(
    draft: ValidatedDraft,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    provider: &dyn ViewProvider,
    consistency: Option<Consistency>,
    options: &ExecutionOptions,
    mut recording: Option<&mut walk::LandingMode>,
    fixed_capture: Option<&ExecutionCapture>,
    recording_v3: bool,
) -> Result<Computation<P::Context>> {
    let local = provider.local_predicates();
    let local_controller =
        local.map(|runtime| local::LocalControllerRuntime::new(runtime, options));
    let controller = provider.controller_runtime().or_else(|| {
        local_controller
            .as_ref()
            .map(|r| r as &dyn ControllerRuntime)
    });
    let controller_limits = controller.map_or(
        crate::predicates::EvaluationLimits::default(),
        ControllerRuntime::evaluation_limits,
    );
    if draft.has_custom_predicates() {
        // Recorded/native composition supplies an explicit controller. The old
        // local path remains no-effects and uses the same driver at window one.
        let runtime = controller
            .filter(|_| recording.is_none() || provider.controller_runtime().is_some())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    "custom predicate runtime unavailable",
                )
            })?;
        runtime.bounds().validate()?;
        options.check_interrupted()?;
        for predicate in draft
            .walk_predicates()
            .iter()
            .chain(draft.filter_predicates())
        {
            if let Some(custom) = predicate.custom() {
                runtime.validate(custom.program(), &custom.binding_names(), controller_limits)?;
            }
        }
    }
    let mut work = Work {
        options,
        count: 0,
        bytes: 0,
    };
    work.tick(1)?;
    let dual_capture = fixed_capture.is_some();
    let (requested, mut control_snapshot) = match fixed_capture {
        Some(capture) => {
            let semantic = capture.captures().semantic();
            if draft.requested_as_of().is_some_and(|t| t != semantic.as_of) {
                return Err(Error::new(
                    ErrorKind::Snapshot,
                    "captured query cutoff mismatch",
                ));
            }
            (semantic.clone(), capture.captures().control().clone())
        }
        None => {
            let capture = backend.capture(draft.requested_as_of()).await?;
            (capture.clone(), capture.snapshot)
        }
    };
    let mut captured = requested.clone();
    if consistency == Some(Consistency::AllowStale) {
        work.tick(1)?;
        if let Some(proposed) = provider.propose_stale(&requested, options).await? {
            validate_proposal(backend, &proposed, &requested.snapshot, &mut work).await?;
            if !dual_capture {
                // V2 and unrecorded execution have one authority snapshot. Only
                // explicit V3/V4 captures may keep control artifacts current
                // while selecting an older semantic snapshot.
                control_snapshot = proposed.clone();
            }
            captured.snapshot = proposed;
        }
    }
    let stale = captured.snapshot != requested.snapshot;
    let plan = draft.finalize(captured.as_of)?;
    // Source preparation is a required graph capability, never evidence hydration.
    if let Some(preparation) = plan.semantic_config().as_object()?.get("preparation") {
        if !recording_v3 && !preparation.as_array()?.is_empty() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "source preparation provider unavailable",
            ));
        }
    }
    if recording.is_some() && !recording_v3 {
        recorded::supported(&plan)?;
    }
    let prepared = provider.open(&captured, options).await?;
    if prepared.view.identity() != &captured.snapshot
        || prepared.landing.identity() != &captured.snapshot
    {
        return Err(Error::new(ErrorKind::Snapshot, "exact view required"));
    }
    let mappings = provider.mapped_fields();
    for predicate in plan
        .walk_predicates()
        .iter()
        .chain(plan.filter_predicates())
    {
        let builtin_mapping = predicate.mapping().into_iter();
        let custom_mappings = predicate
            .custom()
            .into_iter()
            .flat_map(|custom| custom.bindings().values())
            .filter_map(|binding| match binding {
                crate::compiler::CustomBinding::Field(_, mapping) => mapping.as_ref(),
                crate::compiler::CustomBinding::Constant(_) => None,
            });
        for mapping in builtin_mapping.chain(custom_mappings) {
            work.tick(1)?;
            let resolver = mappings.ok_or_else(|| {
                Error::new(ErrorKind::Unsupported, "mapped field provider unavailable")
            })?;
            if resolver.identity() != &captured.snapshot {
                return Err(Error::new(
                    ErrorKind::Snapshot,
                    "exact mapped field snapshot required",
                ));
            }
            if !resolver.supports(mapping) {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "mapped field capability unavailable",
                ));
            }
            if !matches!(
                mapping,
                crate::compiler::FieldMapping::StoredPredicate { .. }
            ) {
                let ontology = provider.ontology().ok_or_else(|| {
                    Error::new(ErrorKind::Unsupported, "prepared ontology unavailable")
                })?;
                verify_prepared_ontology(ontology, &captured.snapshot)?;
            }
        }
        if let Some(builtin) = predicate.builtin() {
            let kind = match builtin.operator() {
                crate::values::Operator::Isa
                | crate::values::Operator::NotIsa
                | crate::values::Operator::ContainsIsa => Some(OntologyKind::Class),
                crate::values::Operator::SubpropertyOf
                | crate::values::Operator::NotSubpropertyOf
                | crate::values::Operator::ContainsSubpropertyOf => Some(OntologyKind::Property),
                _ => None,
            };
            if let Some(kind) = kind {
                work.tick(1)?;
                let ontology = provider.ontology().ok_or_else(|| {
                    Error::new(ErrorKind::Unsupported, "ontology provider unavailable")
                })?;
                verify_prepared_ontology(ontology, &captured.snapshot)?;
                if !ontology.supports(kind) {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "ontology capability unavailable",
                    ));
                }
            }
        }
    }
    let snapshot = backend.open_snapshot(&control_snapshot).await?;
    if snapshot.identity() != &control_snapshot {
        return Err(Error::new(
            ErrorKind::Snapshot,
            "exact control artifact snapshot required",
        ));
    }
    let context = policy.current(principal).await?;
    let artifacts = plan.projection().canonical().payload().field("artifacts")?;
    for value in artifacts.as_object()?.values() {
        if *value == V::Null {
            continue;
        }
        work.tick(1)?;
        let reference = ArtifactRef::from_value(value)?;
        let id = ResourceId::new(reference.iri().as_str())?;
        if !policy.resource_allowed(&context, &id)? {
            return Err(Error::new(
                ErrorKind::Denied,
                "required artifact unavailable",
            ));
        }
        for key in ["iri", "version", "hash"] {
            if !policy.fact_allowed(&context, &id, &property_iri(&format!("artifact.{key}"))?)? {
                return Err(Error::new(
                    ErrorKind::Denied,
                    "required artifact unavailable",
                ));
            }
        }
        let artifact = snapshot
            .artifact(&reference)
            .await?
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "required artifact unavailable"))?;
        if artifact.reference() != &reference {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "required artifact identity mismatch",
            ));
        }
    }
    let raw = recording
        .as_ref()
        .and_then(|r| r.log())
        .map(|log| trace::RecordingRawView::new(prepared.view.as_ref(), log));
    let mut guard = authorized::Guard {
        view: raw
            .as_ref()
            .map(|v| v as &dyn RawQueryView)
            .unwrap_or(prepared.view.as_ref()),
        policy,
        context: &context,
        cutoff: captured.as_of,
        mappings,
        ontology: provider.ontology(),
        work: &mut work,
        dependencies: controller::DependencyFootprint::default(),
    };
    if recording.is_some() {
        for scope in cdb_core::recording::REQUIRED_SCOPES {
            let id = ResourceId::new(scope)?;
            if recording_v3 {
                recording
                    .as_ref()
                    .and_then(|mode| mode.log())
                    .ok_or_else(|| Error::invalid("v3 recording trace unavailable"))?
                    .observe_scope(&id)?;
            }
            let record = guard
                .view
                .resource(&id)?
                .ok_or_else(|| Error::new(ErrorKind::Denied, "required scope unavailable"))?;
            if record.kind() != cdb_core::admission::ResourceKind::SourceDescriptor
                || !guard.resource(&id)?
            {
                return Err(Error::new(ErrorKind::Denied, "required scope unavailable"));
            }
        }
    }
    let (response, sources) = walk::run_controller(
        &plan,
        prepared.landing.as_ref(),
        &mut guard,
        stale,
        recording.as_deref_mut(),
        controller,
        controller_limits,
    )?;
    let hash = response.canonical().hash(options.limits)?;
    let mut wire = response.canonical().payload().as_object()?.clone();
    if let Some(mode) = consistency {
        wire.insert(
            "consistency".into(),
            obj([
                (
                    "mode",
                    V::string(match mode {
                        Consistency::Exact => "exact",
                        Consistency::AllowStale => "allow_stale",
                    }),
                ),
                ("requested", full_identity(&requested.snapshot)),
                ("actual", full_identity(&captured.snapshot)),
                ("as_of", V::string(captured.as_of.canonical())),
                ("stale", V::Bool(stale)),
            ]),
        );
    }
    let mut evidence_unavailable = false;
    if plan.selection().evidence {
        let mut evidence = vec![];
        for source in sources {
            work.tick(1)?;
            let value = source.projection();
            let mut outcome = "unavailable";
            let mut content = V::Null;
            if let (Some(reader), Some(version), Some(selectors)) = (
                provider.evidence_reader(),
                source.version(),
                value.as_object()?.get("selectors"),
            ) {
                let request = cdb_core::source::SourceReadRequest {
                    source_id: source.id().clone(),
                    version: version.clone(),
                    selector: cdb_core::evidence::validate_selectors(selectors)?,
                    max_bytes: options
                        .limits
                        .output_bytes()
                        .min(options.max_retained_bytes),
                };
                match reader.read_reference(&source, request.max_bytes).await {
                    Ok(read) => {
                        work.tick(1)?;
                        if read.source_id() != &request.source_id
                            || read.version() != &request.version
                            || read.selector() != &request.selector
                        {
                            return Err(Error::new(ErrorKind::Backend, "source selector identity"));
                        }
                        if read.bytes().len() > request.max_bytes {
                            return Err(Error::limit());
                        }
                        work.bytes = work
                            .bytes
                            .checked_add(read.bytes().len())
                            .ok_or_else(Error::limit)?;
                        if work.bytes > options.max_retained_bytes {
                            return Err(Error::limit());
                        }
                        let selected_hash = ContentHash::of_bytes(read.bytes());
                        outcome = match value.as_object()?.get("content_hash") {
                            Some(hash) if hash.as_str()? == selected_hash.as_str() => "verified",
                            Some(_) => "changed",
                            None => "unverifiable",
                        };
                        // `read_reference` verifies rich quote/line witnesses against the
                        // retained representation before releasing this exact byte slice.
                        if outcome == "verified" {
                            if let Ok(text) = std::str::from_utf8(read.bytes()) {
                                content = V::string(text);
                            }
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind,
                            ErrorKind::Limit
                                | ErrorKind::Deadline
                                | ErrorKind::Denied
                                | ErrorKind::PolicyChanged
                        ) =>
                    {
                        return Err(error)
                    }
                    Err(_) => {}
                }
            } else if source.version().is_none() || !value.as_object()?.contains_key("selectors") {
                outcome = "unverifiable";
            }
            evidence_unavailable |= outcome != "verified";
            let item = obj([
                ("source_id", V::string(source.id().as_str())),
                ("status", V::string(outcome)),
                ("content", content),
            ]);
            work.retain(&item)?;
            evidence.push(item);
        }
        wire.insert("evidence".into(), V::Array(evidence));
    }
    wire.insert(
        "status".into(),
        V::string(if evidence_unavailable {
            "ready_with_warnings"
        } else {
            wire.get("graph_status")
                .ok_or_else(|| Error::invalid("graph status"))?
                .as_str()?
        }),
    );
    wire.insert("response_hash".into(), V::string(hash.as_str()));
    wire.insert("plan_hash".into(), V::string(plan.hash().as_str()));
    if evidence_unavailable {
        wire.insert(
            "transport_notices".into(),
            V::Array(vec![V::string("evidence_unavailable")]),
        );
    }
    let wire = V::Object(wire);
    work.retain(&wire)?;
    let bytes = wire.canonical_bytes(options.limits)?;
    work.tick(1)?;
    Ok(Computation {
        plan,
        response,
        context,
        bytes,
        captured,
        requested,
        catalog: if recording.is_some() {
            prepared.landing.entries().to_vec()
        } else {
            vec![]
        },
    })
}

#[cfg(test)]
mod staged_execution_tests {
    use super::StagedExecution;

    #[test]
    fn result_cropping_notices_are_distinct_from_declared_depth() {
        for notice in ["seed_limit", "fanout_limit", "max_claims", "path_limit"] {
            assert!(StagedExecution {
                context: (),
                bytes: Vec::new(),
                notices: vec![notice.into()],
            }
            .has_result_truncation());
        }
        assert!(!StagedExecution {
            context: (),
            bytes: Vec::new(),
            notices: vec!["max_depth".into(), "empty_landing".into()],
        }
        .has_result_truncation());
    }
}
