//! P5 capabilities. These types deliberately have no serde implementation.
use crate::{
    backend::map,
    policy::{original_fact_allowed, FlureePolicyContext, FlureePrincipal},
    runs::{ExternalPublicationFence, Operation},
    FlureeBackend,
};
use cdb_core::{
    admission::ExportRecord,
    artifact::ArtifactRef,
    contracts::PolicyService,
    id::*,
    recording::RunEnvelope,
    recording_v3::{AuthorizationRequirementsV3, ReleaseEvidenceV3, RunEnvelopeV3},
    recording_v4::RunEnvelopeV4,
    recording_v5::RunEnvelopeV5,
    snapshot::SnapshotRef,
    CanonicalValue, Error, ErrorKind, Limits, Result,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

const MAX_REQUIREMENTS: usize = 4096;
const MAX_REQUIREMENT_BYTES: usize = 1024 * 1024;
fn denied() -> Error {
    Error::new(ErrorKind::Denied, "execution authorization denied")
}

/// Service-owned lease: check explicit invocation/provider grants here, not graph read.
/// The implementation must retain its session read lease before entering the backend.
pub trait ExecutionFence: ExternalPublicationFence {
    fn check_disclosure(&self) -> Result<()>;
}
struct OriginalExecutionBasis {
    context: FlureePolicyContext,
    principal: FlureePrincipal,
    data: SnapshotRef,
    as_of: cdb_core::Timestamp,
    run: RunId,
    plan: ContentHash,
    operation: Operation,
}
/// Exact external-disclosure binding administered as a principal role.
/// This is descriptive data, never an authorization seal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactInvocationRequirement {
    manifest: ArtifactRef,
    provider: ResourceId,
}
impl Ord for ExactInvocationRequirement {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.manifest.iri(),
            self.manifest.version(),
            self.manifest.hash(),
            &self.provider,
        )
            .cmp(&(
                other.manifest.iri(),
                other.manifest.version(),
                other.manifest.hash(),
                &other.provider,
            ))
    }
}
impl PartialOrd for ExactInvocationRequirement {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl ExactInvocationRequirement {
    pub fn new(manifest: ArtifactRef, provider: ResourceId) -> Self {
        Self { manifest, provider }
    }
    pub fn manifest(&self) -> &ArtifactRef {
        &self.manifest
    }
    pub fn provider(&self) -> &ResourceId {
        &self.provider
    }
}
/// Versioned role IRI for trusted administration in `PolicyState::principals`.
/// Percent encoding is identity-preserving; it is not a new hash domain.
pub fn exact_invocation_role(requirement: &ExactInvocationRequirement) -> Result<Iri> {
    fn component(value: &str) -> String {
        let mut out = String::new();
        for byte in value.as_bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                out.push(char::from(*byte));
            } else {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
        out
    }
    Iri::http(format!(
        "https://ctxql.org/roles/exactInvocation/v1?manifest={}&version={}&hash={}&provider={}",
        component(requirement.manifest.iri().as_str()),
        component(requirement.manifest.version().as_str()),
        component(requirement.manifest.hash().as_str()),
        component(requirement.provider.as_str()),
    ))
}
#[derive(Default)]
struct Requirements {
    facts: BTreeSet<(ResourceId, Iri)>,
    invocations: BTreeSet<ExactInvocationRequirement>,
    bytes: usize,
    busy: bool,
}
/// Clones share the cumulative footprint, including positive reads in rejected work.
#[derive(Clone)]
pub struct ExecutionAuthorization {
    basis: Arc<OriginalExecutionBasis>,
    requirements: Arc<Mutex<Requirements>>,
    action_gate: Arc<tokio::sync::Mutex<()>>,
}
/// Sealed by this backend from its cumulative positive observations.
/// A stale footprint is rejected rather than silently omitting later work.
pub struct ReleaseFootprint {
    basis: Arc<OriginalExecutionBasis>,
    facts: BTreeSet<(ResourceId, Iri)>,
    invocations: BTreeSet<ExactInvocationRequirement>,
    complete: bool,
}

/// Backend-issued, non-serializable replay authority. Its decisions can only be
/// built from a protected stored v3 run and remain bound to that run/principal.
#[derive(Clone)]
pub struct RecordedReplayAuthorization {
    run: RunEnvelopeV3,
    principal: PrincipalId,
    operation: Operation,
    execution: ExecutionAuthorization,
    decisions: Arc<BTreeMap<(ResourceId, Option<Iri>), bool>>,
    positive_facts: Arc<BTreeSet<(ResourceId, Iri)>>,
    invocations: Arc<BTreeSet<ExactInvocationRequirement>>,
    callbacks: Arc<BTreeMap<ResourceId, BTreeSet<ExactInvocationRequirement>>>,
}
impl RecordedReplayAuthorization {
    pub fn run(&self) -> &RunEnvelopeV3 {
        &self.run
    }
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    pub fn operation(&self) -> Operation {
        self.operation
    }
    pub fn original_decision(
        &self,
        resource: &ResourceId,
        predicate: Option<&Iri>,
    ) -> Result<bool> {
        self.decisions
            .get(&(resource.clone(), predicate.cloned()))
            .copied()
            .ok_or_else(|| Error::invalid("unrecorded original policy decision"))
    }

    /// Construct an action snapshot only when every pre-disclosure dependency,
    /// destination and callback is part of the protected stored replay.
    pub fn action_footprint(
        &self,
        backend: &FlureeBackend,
        callback: &ResourceId,
        facts: Vec<(ResourceId, Iri)>,
        invocation: ExactInvocationRequirement,
    ) -> Result<ReleaseFootprint> {
        if !self
            .callbacks
            .get(callback)
            .is_some_and(|allowed| allowed.contains(&invocation))
            || !self.invocations.contains(&invocation)
            || facts.iter().any(|fact| !self.positive_facts.contains(fact))
        {
            return Err(denied());
        }
        backend.action_footprint(&self.execution, facts, vec![invocation])
    }

    fn accepts_action(&self, callback: &ResourceId, footprint: &ReleaseFootprint) -> bool {
        Arc::ptr_eq(&self.execution.basis, &footprint.basis)
            && footprint
                .facts
                .iter()
                .all(|fact| self.positive_facts.contains(fact))
            && footprint.invocations.len() == 1
            && footprint.invocations.iter().all(|invocation| {
                self.callbacks
                    .get(callback)
                    .is_some_and(|allowed| allowed.contains(invocation))
            })
    }

    pub fn data_snapshot(&self) -> &SnapshotRef {
        self.execution.data_snapshot()
    }
}
impl ReleaseFootprint {
    /// Bounded prospective requirements, NOT a receipt or permission to release.
    pub fn requirements(&self, limits: Limits) -> Result<AuthorizationRequirementsV3> {
        AuthorizationRequirementsV3::new(
            self.facts.iter().cloned().collect(),
            self.invocations
                .iter()
                .map(|r| (r.manifest.clone(), r.provider.clone()))
                .collect(),
            limits,
        )
    }
}
/// Proof data returned only by an actual successful backend gate check.
/// Fields are private so callers cannot construct or alter a historical check.
pub struct AuthorizationCheckReceipt {
    requirements: AuthorizationRequirementsV3,
    authorization_head: SnapshotRef,
}
impl AuthorizationCheckReceipt {
    fn new(
        footprint: &ReleaseFootprint,
        authorization_head: SnapshotRef,
        limits: Limits,
    ) -> Result<Self> {
        let requirements = AuthorizationRequirementsV3::new(
            footprint.facts.iter().cloned().collect(),
            footprint
                .invocations
                .iter()
                .map(|requirement| {
                    (
                        requirement.manifest().clone(),
                        requirement.provider().clone(),
                    )
                })
                .collect(),
            limits,
        )?;
        Ok(Self {
            requirements,
            authorization_head,
        })
    }
    pub fn requirements(&self) -> &AuthorizationRequirementsV3 {
        &self.requirements
    }
    pub fn requirements_hash(&self) -> &ContentHash {
        self.requirements.hash()
    }
    pub fn requirements_projection(&self) -> CanonicalValue {
        self.requirements.projection()
    }
    pub fn authorization_head(&self) -> &SnapshotRef {
        &self.authorization_head
    }
    pub fn release_evidence(
        &self,
        action: ResourceId,
        limits: Limits,
    ) -> Result<ReleaseEvidenceV3> {
        ReleaseEvidenceV3::new(
            action,
            self.requirements.clone(),
            self.authorization_head.clone(),
            true,
            limits,
        )
    }
}
struct ActionLease(Arc<Mutex<Requirements>>);
impl Drop for ActionLease {
    fn drop(&mut self) {
        if let Ok(mut r) = self.0.lock() {
            r.busy = false;
        }
    }
}
impl ExecutionAuthorization {
    fn action_lease(&self) -> Result<ActionLease> {
        let mut r = self.requirements.lock().map_err(|_| denied())?;
        if r.busy {
            return Err(denied());
        }
        r.busy = true;
        Ok(ActionLease(self.requirements.clone()))
    }
    pub fn operation(&self) -> Operation {
        self.basis.operation
    }
    pub fn data_snapshot(&self) -> &SnapshotRef {
        &self.basis.data
    }
    pub fn plan_hash(&self) -> &ContentHash {
        &self.basis.plan
    }
    /// Narrow identity access for trusted service composition.
    pub fn run_id(&self) -> &RunId {
        &self.basis.run
    }
    /// Narrow owner access for matching the authenticated session before authority entry.
    pub fn principal_id(&self) -> &PrincipalId {
        self.basis.principal.id()
    }
    pub fn release_footprint(&self) -> Result<ReleaseFootprint> {
        let r = self.requirements.lock().map_err(|_| denied())?;
        Ok(ReleaseFootprint {
            basis: self.basis.clone(),
            facts: r.facts.clone(),
            invocations: r.invocations.clone(),
            complete: true,
        })
    }
}
impl FlureeBackend {
    /// Issue frozen replay authority only after protected stored-run lookup.
    pub async fn prepare_recorded_replay(
        &self,
        principal: FlureePrincipal,
        context: &FlureePolicyContext,
        run_id: &RunId,
    ) -> Result<RecordedReplayAuthorization> {
        let run = self
            .guarded_v3_run_for(&principal, context, run_id, Operation::Replay)
            .await?;
        let authorization_snapshot = run.replay().data().snapshot.clone();
        self.prepare_recorded_replay_base(principal, run, authorization_snapshot)
            .await
    }

    /// V4 lookup remains strict, then reuses the unchanged v3 deterministic
    /// execution evidence embedded by the v4 envelope.
    pub async fn prepare_recorded_replay_v4(
        &self,
        _principal: FlureePrincipal,
        _context: &FlureePolicyContext,
        _run_id: &RunId,
    ) -> Result<(RunEnvelopeV4, RecordedReplayAuthorization)> {
        Err(Error::new(
            ErrorKind::Unsupported,
            crate::backend_identity::HISTORICAL_EXECUTOR_UNAVAILABLE,
        ))
    }

    pub async fn prepare_recorded_replay_v5(
        &self,
        principal: FlureePrincipal,
        context: &FlureePolicyContext,
        run_id: &RunId,
    ) -> Result<(RunEnvelopeV5, RecordedReplayAuthorization)> {
        let run = self
            .guarded_v5_run_for(&principal, context, run_id, Operation::Replay)
            .await?;
        let replay_v4 = run.replay().v4();
        let base = RunEnvelopeV3::new(
            run.id().clone(),
            run.owner().clone(),
            run.operation_hash().clone(),
            replay_v4.base().clone(),
            self.options.codec_limits,
        )?;
        let authorization = self
            .prepare_recorded_replay_base(principal, base, replay_v4.control_capture().clone())
            .await?;
        Ok((run, authorization))
    }

    async fn prepare_recorded_replay_base(
        &self,
        principal: FlureePrincipal,
        run: RunEnvelopeV3,
        authorization_snapshot: SnapshotRef,
    ) -> Result<RecordedReplayAuthorization> {
        let execution = self
            .capture_execution(
                principal.clone(),
                authorization_snapshot,
                run.replay().data().as_of,
                run.id().clone(),
                run.replay().data().plan_hash.clone(),
                Operation::Replay,
            )
            .await?;
        let mut decisions = BTreeMap::new();
        for observation in &run.replay().data().policy {
            let positive_still_allowed = if observation.allowed {
                match &observation.predicate {
                    Some(predicate) => {
                        self.original_fact_allowed(&execution, &observation.resource, predicate)?
                    }
                    None => self.original_resource_allowed(&execution, &observation.resource)?,
                }
            } else {
                true
            };
            if !positive_still_allowed
                || decisions
                    .insert(
                        (observation.resource.clone(), observation.predicate.clone()),
                        observation.allowed,
                    )
                    .is_some()
            {
                return Err(denied());
            }
        }
        for scope in &run.replay().data().scopes {
            if !self.original_resource_allowed(&execution, scope)? {
                return Err(denied());
            }
        }
        let invocations = run
            .replay()
            .original_invocations()?
            .into_iter()
            .map(|(manifest, provider)| ExactInvocationRequirement::new(manifest, provider))
            .collect::<BTreeSet<_>>();
        for invocation in &invocations {
            if !self.original_exact_invocation_allowed(&execution, invocation)? {
                return Err(denied());
            }
        }
        let view = Iri::http("https://ns.flur.ee/db#view")?;
        let mut positive_facts = BTreeSet::new();
        for observation in &run.replay().data().policy {
            if observation.allowed {
                positive_facts.insert((
                    observation.resource.clone(),
                    observation
                        .predicate
                        .clone()
                        .unwrap_or_else(|| view.clone()),
                ));
            }
        }
        positive_facts.extend(
            run.replay()
                .data()
                .scopes
                .iter()
                .cloned()
                .map(|scope| (scope, view.clone())),
        );
        let mut callbacks = BTreeMap::<ResourceId, BTreeSet<ExactInvocationRequirement>>::new();
        for evidence in run.replay().release_evidence(self.options.codec_limits)? {
            let projection = evidence.projection();
            let action = ResourceId::new(projection.field("action")?.as_str()?)?;
            let Some(callback) = cdb_core::recording_v3::function_action_callback(&action)? else {
                continue;
            };
            for invocation in projection
                .field("requirements")?
                .field("invocations")?
                .as_array()?
            {
                callbacks.entry(callback.clone()).or_default().insert(
                    ExactInvocationRequirement::new(
                        ArtifactRef::from_value(invocation.field("manifest")?)?,
                        ResourceId::new(invocation.field("provider")?.as_str()?)?,
                    ),
                );
            }
        }
        Ok(RecordedReplayAuthorization {
            run,
            principal: principal.id().clone(),
            operation: Operation::Replay,
            execution,
            decisions: Arc::new(decisions),
            positive_facts: Arc::new(positive_facts),
            invocations: Arc::new(invocations),
            callbacks: Arc::new(callbacks),
        })
    }

    pub async fn capture_execution(
        &self,
        principal: FlureePrincipal,
        data: SnapshotRef,
        as_of: cdb_core::Timestamp,
        run: RunId,
        plan: ContentHash,
        operation: Operation,
    ) -> Result<ExecutionAuthorization> {
        let _gate = self.mutation_gate.lock().await;
        self.validate_snapshot(&data).await.map_err(map)?;
        let context = self.policy_context_locked(&principal).await?;
        self.require_operation(&context, operation)?;
        Ok(ExecutionAuthorization {
            basis: Arc::new(OriginalExecutionBasis {
                context,
                principal,
                data,
                as_of,
                run,
                plan,
                operation,
            }),
            requirements: Arc::new(Mutex::new(Requirements::default())),
            action_gate: Arc::new(tokio::sync::Mutex::new(())),
        })
    }
    /// Add exactly one action's immutable requirements to the cumulative final
    /// footprint while returning only that action's subset for its receipt.
    pub fn action_footprint(
        &self,
        execution: &ExecutionAuthorization,
        facts: Vec<(ResourceId, Iri)>,
        invocations: Vec<ExactInvocationRequirement>,
    ) -> Result<ReleaseFootprint> {
        let facts = facts.into_iter().collect::<BTreeSet<_>>();
        let invocations = invocations.into_iter().collect::<BTreeSet<_>>();
        for (resource, predicate) in &facts {
            if !self.original_fact_allowed(execution, resource, predicate)? {
                return Err(denied());
            }
        }
        for invocation in &invocations {
            if !self.original_exact_invocation_allowed(execution, invocation)? {
                return Err(denied());
            }
        }
        Ok(ReleaseFootprint {
            basis: execution.basis.clone(),
            facts,
            invocations,
            complete: false,
        })
    }

    pub fn original_resource_allowed(
        &self,
        execution: &ExecutionAuthorization,
        resource: &ResourceId,
    ) -> Result<bool> {
        self.original_fact_allowed(
            execution,
            resource,
            &Iri::http("https://ns.flur.ee/db#view")?,
        )
    }
    pub fn original_fact_allowed(
        &self,
        execution: &ExecutionAuthorization,
        resource: &ResourceId,
        property: &Iri,
    ) -> Result<bool> {
        self.check_execution_issuer(execution)?;
        let allowed = original_fact_allowed(&execution.basis.context, resource, property)?;
        if allowed {
            let mut r = execution.requirements.lock().map_err(|_| denied())?;
            let bytes = resource
                .as_str()
                .len()
                .checked_add(property.as_str().len())
                .ok_or_else(Error::limit)?;
            if !r.facts.iter().any(|(a, b)| a == resource && b == property) {
                if r.busy {
                    return Err(denied());
                }
                if r.facts.len().saturating_add(r.invocations.len()) >= MAX_REQUIREMENTS
                    || bytes > MAX_REQUIREMENT_BYTES.saturating_sub(r.bytes)
                {
                    return Err(Error::limit());
                }
                r.facts.insert((resource.clone(), property.clone()));
                r.bytes += bytes;
            }
        }
        Ok(allowed)
    }
    /// Evaluate and retain an exact manifest/provider invocation requirement against
    /// the immutable original role set. A later grant cannot broaden this decision.
    pub fn original_exact_invocation_allowed(
        &self,
        execution: &ExecutionAuthorization,
        requirement: &ExactInvocationRequirement,
    ) -> Result<bool> {
        self.check_execution_issuer(execution)?;
        let role = exact_invocation_role(requirement)?;
        let allowed = execution.basis.context.roles().contains(&role);
        if allowed {
            let mut r = execution.requirements.lock().map_err(|_| denied())?;
            if !r.invocations.contains(requirement) {
                if r.busy {
                    return Err(denied());
                }
                let bytes = role.as_str().len();
                if r.facts.len().saturating_add(r.invocations.len()) >= MAX_REQUIREMENTS
                    || bytes > MAX_REQUIREMENT_BYTES.saturating_sub(r.bytes)
                {
                    return Err(Error::limit());
                }
                r.invocations.insert(requirement.clone());
                r.bytes += bytes;
            }
        }
        Ok(allowed)
    }
    fn check_execution_issuer(&self, e: &ExecutionAuthorization) -> Result<()> {
        self.check_original_context_issuer(&e.basis.context)
    }
    fn check_execution_current(
        &self,
        e: &ExecutionAuthorization,
        footprint: &ReleaseFootprint,
        fresh: &FlureePolicyContext,
    ) -> Result<()> {
        self.check_execution_issuer(e)?;
        if !Arc::ptr_eq(&e.basis, &footprint.basis) {
            return Err(denied());
        }
        let r = e.requirements.lock().map_err(|_| denied())?;
        let matches = if footprint.complete {
            r.facts == footprint.facts && r.invocations == footprint.invocations
        } else {
            footprint.facts.is_subset(&r.facts) && footprint.invocations.is_subset(&r.invocations)
        };
        if !matches {
            return Err(denied());
        }
        self.require_operation(fresh, e.basis.operation)?;
        for (resource, property) in &footprint.facts {
            if !self.fact_allowed(fresh, resource, property)? {
                return Err(denied());
            }
        }
        for requirement in &footprint.invocations {
            if !fresh.roles().contains(&exact_invocation_role(requirement)?) {
                return Err(denied());
            }
        }
        Ok(())
    }
    fn check_recorded_v3_footprint(
        &self,
        footprint: &ReleaseFootprint,
        run: &RunEnvelopeV3,
    ) -> Result<()> {
        if !footprint.complete
            || footprint.requirements(self.options.codec_limits)?
                != run
                    .replay()
                    .original_authorization_requirements(self.options.codec_limits)?
        {
            return Err(denied());
        }
        Ok(())
    }

    fn check_recorded_v4_footprint(
        &self,
        footprint: &ReleaseFootprint,
        run: &RunEnvelopeV4,
    ) -> Result<()> {
        if !footprint.complete
            || footprint.requirements(self.options.codec_limits)?
                != run
                    .replay()
                    .base()
                    .original_authorization_requirements(self.options.codec_limits)?
        {
            return Err(denied());
        }
        Ok(())
    }
    /// Run one bounded local action under a fresh current check and return evidence
    /// from that exact check. The callback must only enqueue local work; it must not
    /// await or perform socket I/O.
    pub async fn guarded_execution_action_checked<T, F>(
        self: Arc<Self>,
        execution: ExecutionAuthorization,
        footprint: ReleaseFootprint,
        fence: Box<dyn ExecutionFence>,
        callback: F,
    ) -> Result<(T, AuthorizationCheckReceipt)>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        tokio::spawn(async move {
            fence.check()?;
            fence.check_disclosure()?;
            let _serial = execution.action_gate.clone().lock_owned().await;
            let _gate = self.mutation_gate.clone().lock_owned().await;
            let _action = execution.action_lease()?;
            fence.check()?;
            fence.check_disclosure()?;
            let fresh = self
                .policy_context_locked(&execution.basis.principal)
                .await?;
            self.check_execution_current(&execution, &footprint, &fresh)?;
            let checked_head = self
                .snapshot(self.native.head().await.map_err(map)?)
                .map_err(map)?;
            let receipt = AuthorizationCheckReceipt::new(
                &footprint,
                checked_head,
                self.options.codec_limits,
            )?;
            let value = callback()?;
            self.check_execution_current(&execution, &footprint, &fresh)?;
            fence.check()?;
            fence.check_disclosure()?;
            Ok((value, receipt))
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "execution action task failed"))?
    }

    /// Replay broker gate: validate the sealed callback/action subset before any
    /// enqueue callback can disclose to a provider.
    pub async fn guarded_recorded_replay_action_checked<T, F>(
        self: Arc<Self>,
        authorization: &RecordedReplayAuthorization,
        callback_id: &ResourceId,
        footprint: ReleaseFootprint,
        fence: Box<dyn ExecutionFence>,
        callback: F,
    ) -> Result<(T, AuthorizationCheckReceipt)>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        if !authorization.accepts_action(callback_id, &footprint) {
            return Err(denied());
        }
        self.guarded_execution_action_checked(
            authorization.execution.clone(),
            footprint,
            fence,
            callback,
        )
        .await
    }

    /// Compatibility wrapper for callers that do not persist check evidence.
    pub async fn guarded_execution_action<T, F>(
        self: Arc<Self>,
        execution: ExecutionAuthorization,
        footprint: ReleaseFootprint,
        fence: Box<dyn ExecutionFence>,
        callback: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        self.guarded_execution_action_checked(execution, footprint, fence, callback)
            .await
            .map(|(value, _)| value)
    }

    /// Final release for a backend-issued replay capability. Broker actions and
    /// this release share the capability's private execution requirements.
    pub async fn guarded_recorded_replay_action<T, F>(
        self: Arc<Self>,
        authorization: &RecordedReplayAuthorization,
        fence: Box<dyn ExecutionFence>,
        callback: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let execution = authorization.execution.clone();
        let footprint = execution.release_footprint()?;
        self.guarded_execution_action(execution, footprint, fence, callback)
            .await
    }

    /// Callback creates a bounded owned result; only the sink may publish it.
    /// Neither callback nor sink may reenter this authority or perform socket I/O.
    pub async fn guarded_execution_release<F, S>(
        self: Arc<Self>,
        execution: ExecutionAuthorization,
        footprint: ReleaseFootprint,
        fence: Box<dyn ExecutionFence>,
        callback: F,
        sink: S,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<Vec<u8>> + Send + 'static,
        S: FnOnce(Vec<u8>) -> Result<()> + Send + 'static,
    {
        tokio::spawn(async move {
            fence.check()?;
            fence.check_disclosure()?;
            let _serial = execution.action_gate.clone().lock_owned().await;
            let _gate = self.mutation_gate.clone().lock_owned().await;
            let _action = execution.action_lease()?;
            fence.check()?;
            fence.check_disclosure()?;
            let fresh = self
                .policy_context_locked(&execution.basis.principal)
                .await?;
            self.check_execution_current(&execution, &footprint, &fresh)?;
            let value = callback()?;
            if value.len() > MAX_REQUIREMENT_BYTES {
                return Err(Error::limit());
            }
            self.check_execution_current(&execution, &footprint, &fresh)?;
            fence.check()?;
            fence.check_disclosure()?;
            sink(value)
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "execution release task failed"))?
    }
    /// Returns the full commit snapshot, never replacing the original data pin.
    pub async fn guarded_execution_commit<S>(
        self: Arc<Self>,
        execution: ExecutionAuthorization,
        footprint: ReleaseFootprint,
        run: RunEnvelope,
        fence: Box<dyn ExecutionFence>,
        sink: S,
    ) -> Result<SnapshotRef>
    where
        S: FnOnce(&RunEnvelope, &SnapshotRef) -> Result<()> + Send + 'static,
    {
        tokio::spawn(async move {
            fence.check()?;
            fence.check_disclosure()?;
            let _serial = execution.action_gate.clone().lock_owned().await;
            let gate = Arc::new(self.mutation_gate.clone().lock_owned().await);
            let _action = execution.action_lease()?;
            fence.check()?;
            fence.check_disclosure()?;
            let fresh = self
                .policy_context_locked(&execution.basis.principal)
                .await?;
            self.check_execution_current(&execution, &footprint, &fresh)?;
            self.require_operation(&fresh, Operation::Query)?;
            if run.id() != &execution.basis.run
                || run.owner() != execution.basis.principal.id()
                || run.replay().data().snapshot != execution.basis.data
                || run.replay().data().as_of != execution.basis.as_of
                || run.replay().data().plan_hash != execution.basis.plan
            {
                return Err(denied());
            }
            let key = crate::runs::run_key(run.id())?;
            let receipt = if let Some(old) = self.envelope_locked(run.id()).await? {
                if old.owner() != run.owner() || old.operation_hash() != run.operation_hash() {
                    return Err(Error::new(ErrorKind::Conflict, "run identity conflict"));
                }
                self.authorize_envelope(&execution.basis.principal, &fresh, &old, true)?;
                self.receipt(&key)
                    .await
                    .map_err(map)?
                    .ok_or_else(|| Error::new(ErrorKind::Backend, "missing run receipt"))?
            } else {
                self.authorize_envelope(
                    &execution.basis.principal,
                    &fresh.clone().with_existing(&run.descriptor_id()?),
                    &run,
                    true,
                )?;
                let ExportRecord::Resource(record) = run.to_record(self.options.codec_limits)?
                else {
                    return Err(denied());
                };
                let batch = crate::runs::batch(vec![record], self.options.codec_limits)?;
                fence.check()?;
                fence.check_disclosure()?;
                self.admit_locked(&key, &batch, true, gate.clone())
                    .await
                    .map_err(map)?
            };
            let fresh = self
                .policy_context_locked(&execution.basis.principal)
                .await?;
            self.check_execution_current(&execution, &footprint, &fresh)?;
            let stored = self.envelope_locked(run.id()).await?.ok_or_else(denied)?;
            self.authorize_envelope(&execution.basis.principal, &fresh, &stored, true)?;
            fence.check()?;
            fence.check_disclosure()?;
            sink(&stored, receipt.snapshot())?;
            Ok(receipt.snapshot().clone())
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "execution commit task failed"))?
    }

    /// Current V5 durable semantic path. V4 remains archival and is never
    /// emitted by the current backend.
    pub async fn guarded_execution_commit_v5_built<B, S>(
        self: Arc<Self>,
        execution: ExecutionAuthorization,
        footprint: ReleaseFootprint,
        fence: Box<dyn ExecutionFence>,
        builder: B,
        sink: S,
    ) -> Result<SnapshotRef>
    where
        B: FnOnce(&AuthorizationCheckReceipt) -> Result<RunEnvelopeV5> + Send + 'static,
        S: FnOnce(&RunEnvelopeV5, &SnapshotRef) -> Result<()> + Send + 'static,
    {
        tokio::spawn(async move {
            fence.check()?;
            fence.check_disclosure()?;
            let _serial = execution.action_gate.clone().lock_owned().await;
            let gate = Arc::new(self.mutation_gate.clone().lock_owned().await);
            let _action = execution.action_lease()?;
            let fresh = self
                .policy_context_locked(&execution.basis.principal)
                .await?;
            self.check_execution_current(&execution, &footprint, &fresh)?;
            self.require_operation(&fresh, Operation::Query)?;
            let checked_head = self
                .snapshot(self.native.head().await.map_err(map)?)
                .map_err(map)?;
            let authorization_receipt = AuthorizationCheckReceipt::new(
                &footprint,
                checked_head,
                self.options.codec_limits,
            )?;
            let run = builder(&authorization_receipt)?;
            if run.id() != &execution.basis.run
                || run.owner() != execution.basis.principal.id()
                || run.replay().control_capture() != &execution.basis.data
                || run.replay().base().data().as_of != execution.basis.as_of
                || run.replay().base().data().plan_hash != execution.basis.plan
            {
                return Err(denied());
            }
            let key = crate::runs::run_key(run.id())?;
            let receipt = if let Some(old) = self.envelope_v5_locked(run.id()).await? {
                if old.owner() != run.owner() || old.operation_hash() != run.operation_hash() {
                    return Err(Error::new(ErrorKind::Conflict, "run identity conflict"));
                }
                let historical = RunEnvelopeV4::new(
                    old.id().clone(),
                    old.owner().clone(),
                    old.operation_hash().clone(),
                    old.replay().v4().clone(),
                    self.options.codec_limits,
                )?;
                self.check_recorded_v4_footprint(&footprint, &historical)?;
                self.authorize_envelope_v5(&execution.basis.principal, &fresh, &old, true)?;
                self.receipt(&key)
                    .await
                    .map_err(map)?
                    .ok_or_else(|| Error::new(ErrorKind::Backend, "missing run receipt"))?
            } else {
                let historical = RunEnvelopeV4::new(
                    run.id().clone(),
                    run.owner().clone(),
                    run.operation_hash().clone(),
                    run.replay().v4().clone(),
                    self.options.codec_limits,
                )?;
                self.check_recorded_v4_footprint(&footprint, &historical)?;
                self.authorize_envelope_v5(
                    &execution.basis.principal,
                    &fresh.clone().with_existing(&run.descriptor_id()?),
                    &run,
                    true,
                )?;
                let ExportRecord::Resource(record) = run.to_record(self.options.codec_limits)?
                else {
                    return Err(denied());
                };
                let batch = crate::runs::batch(vec![record], self.options.codec_limits)?;
                fence.check()?;
                fence.check_disclosure()?;
                self.admit_locked(&key, &batch, true, gate.clone())
                    .await
                    .map_err(map)?
            };
            let fresh = self
                .policy_context_locked(&execution.basis.principal)
                .await?;
            self.check_execution_current(&execution, &footprint, &fresh)?;
            let stored = self
                .envelope_v5_locked(run.id())
                .await?
                .ok_or_else(denied)?;
            self.authorize_envelope_v5(&execution.basis.principal, &fresh, &stored, true)?;
            fence.check()?;
            fence.check_disclosure()?;
            sink(&stored, receipt.snapshot())?;
            Ok(receipt.snapshot().clone())
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "v5 execution commit task failed"))?
    }

    /// V4 durable semantic path. The builder runs under the final current control
    /// authorization check; semantic current-authority verification is performed by
    /// the service immediately before entering this boundary.
    pub async fn guarded_execution_commit_v4_built<B, S>(
        self: Arc<Self>,
        execution: ExecutionAuthorization,
        footprint: ReleaseFootprint,
        fence: Box<dyn ExecutionFence>,
        builder: B,
        sink: S,
    ) -> Result<SnapshotRef>
    where
        B: FnOnce(&AuthorizationCheckReceipt) -> Result<RunEnvelopeV4> + Send + 'static,
        S: FnOnce(&RunEnvelopeV4, &SnapshotRef) -> Result<()> + Send + 'static,
    {
        // V4 is archival evidence for 603974f. Never execute it using 4.2.1.
        if cdb_core::recording_v5::FLUREE_REVISION
            != crate::ontology_profile_v3::PINNED_FLUREE_REVISION
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                crate::backend_identity::HISTORICAL_EXECUTOR_UNAVAILABLE,
            ));
        }
        tokio::spawn(async move {
            fence.check()?;
            fence.check_disclosure()?;
            let _serial = execution.action_gate.clone().lock_owned().await;
            let gate = Arc::new(self.mutation_gate.clone().lock_owned().await);
            let _action = execution.action_lease()?;
            fence.check()?;
            fence.check_disclosure()?;
            let fresh = self
                .policy_context_locked(&execution.basis.principal)
                .await?;
            self.check_execution_current(&execution, &footprint, &fresh)?;
            self.require_operation(&fresh, Operation::Query)?;
            let checked_head = self
                .snapshot(self.native.head().await.map_err(map)?)
                .map_err(map)?;
            let authorization_receipt = AuthorizationCheckReceipt::new(
                &footprint,
                checked_head,
                self.options.codec_limits,
            )?;
            let run = builder(&authorization_receipt)?;
            if run.id() != &execution.basis.run
                || run.owner() != execution.basis.principal.id()
                || run.replay().control_capture() != &execution.basis.data
                || run.replay().base().data().as_of != execution.basis.as_of
                || run.replay().base().data().plan_hash != execution.basis.plan
            {
                return Err(denied());
            }
            let key = crate::runs::run_key(run.id())?;
            let receipt = if let Some(old) = self.envelope_v4_locked(run.id()).await? {
                if old.owner() != run.owner() || old.operation_hash() != run.operation_hash() {
                    return Err(Error::new(ErrorKind::Conflict, "run identity conflict"));
                }
                self.check_recorded_v4_footprint(&footprint, &old)?;
                self.authorize_envelope_v4(&execution.basis.principal, &fresh, &old, true)?;
                self.receipt(&key)
                    .await
                    .map_err(map)?
                    .ok_or_else(|| Error::new(ErrorKind::Backend, "missing run receipt"))?
            } else {
                self.check_recorded_v4_footprint(&footprint, &run)?;
                self.authorize_envelope_v4(
                    &execution.basis.principal,
                    &fresh.clone().with_existing(&run.descriptor_id()?),
                    &run,
                    true,
                )?;
                let ExportRecord::Resource(record) = run.to_record(self.options.codec_limits)?
                else {
                    return Err(denied());
                };
                let batch = crate::runs::batch(vec![record], self.options.codec_limits)?;
                fence.check()?;
                fence.check_disclosure()?;
                self.admit_locked(&key, &batch, true, gate.clone())
                    .await
                    .map_err(map)?
            };
            let fresh = self
                .policy_context_locked(&execution.basis.principal)
                .await?;
            self.check_execution_current(&execution, &footprint, &fresh)?;
            let stored = self
                .envelope_v4_locked(run.id())
                .await?
                .ok_or_else(denied)?;
            self.check_recorded_v4_footprint(&footprint, &stored)?;
            self.authorize_envelope_v4(&execution.basis.principal, &fresh, &stored, true)?;
            fence.check()?;
            fence.check_disclosure()?;
            sink(&stored, receipt.snapshot())?;
            Ok(receipt.snapshot().clone())
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "v4 execution commit task failed"))?
    }

    /// V3-only durable path. It preserves the exact stored original on retry and
    /// keeps the original data snapshot distinct from the commit receipt snapshot.
    pub async fn guarded_execution_commit_v3<S>(
        self: Arc<Self>,
        execution: ExecutionAuthorization,
        footprint: ReleaseFootprint,
        run: RunEnvelopeV3,
        fence: Box<dyn ExecutionFence>,
        sink: S,
    ) -> Result<SnapshotRef>
    where
        S: FnOnce(&RunEnvelopeV3, &SnapshotRef) -> Result<()> + Send + 'static,
    {
        self.guarded_execution_commit_v3_built(execution, footprint, fence, move |_| Ok(run), sink)
            .await
    }

    /// Build the final envelope under the actual precommit guard, allowing its
    /// backend-issued check receipt to be included without a postcommit claim.
    pub async fn guarded_execution_commit_v3_built<B, S>(
        self: Arc<Self>,
        execution: ExecutionAuthorization,
        footprint: ReleaseFootprint,
        fence: Box<dyn ExecutionFence>,
        builder: B,
        sink: S,
    ) -> Result<SnapshotRef>
    where
        B: FnOnce(&AuthorizationCheckReceipt) -> Result<RunEnvelopeV3> + Send + 'static,
        S: FnOnce(&RunEnvelopeV3, &SnapshotRef) -> Result<()> + Send + 'static,
    {
        tokio::spawn(async move {
            fence.check()?;
            fence.check_disclosure()?;
            let _serial = execution.action_gate.clone().lock_owned().await;
            let gate = Arc::new(self.mutation_gate.clone().lock_owned().await);
            let _action = execution.action_lease()?;
            fence.check()?;
            fence.check_disclosure()?;
            let fresh = self
                .policy_context_locked(&execution.basis.principal)
                .await?;
            self.check_execution_current(&execution, &footprint, &fresh)?;
            self.require_operation(&fresh, Operation::Query)?;
            let checked_head = self
                .snapshot(self.native.head().await.map_err(map)?)
                .map_err(map)?;
            let authorization_receipt = AuthorizationCheckReceipt::new(
                &footprint,
                checked_head,
                self.options.codec_limits,
            )?;
            let run = builder(&authorization_receipt)?;
            if run.id() != &execution.basis.run
                || run.owner() != execution.basis.principal.id()
                || run.replay().data().snapshot != execution.basis.data
                || run.replay().data().as_of != execution.basis.as_of
                || run.replay().data().plan_hash != execution.basis.plan
            {
                return Err(denied());
            }
            let key = crate::runs::run_key(run.id())?;
            let receipt = if let Some(old) = self.envelope_v3_locked(run.id()).await? {
                if old.owner() != run.owner() || old.operation_hash() != run.operation_hash() {
                    return Err(Error::new(ErrorKind::Conflict, "run identity conflict"));
                }
                self.check_recorded_v3_footprint(&footprint, &old)?;
                self.authorize_envelope_v3(&execution.basis.principal, &fresh, &old, true)?;
                self.receipt(&key)
                    .await
                    .map_err(map)?
                    .ok_or_else(|| Error::new(ErrorKind::Backend, "missing run receipt"))?
            } else {
                self.check_recorded_v3_footprint(&footprint, &run)?;
                self.authorize_envelope_v3(
                    &execution.basis.principal,
                    &fresh.clone().with_existing(&run.descriptor_id()?),
                    &run,
                    true,
                )?;
                let ExportRecord::Resource(record) = cdb_core::recording_v3::StoredV3(run.clone())
                    .to_record(self.options.codec_limits)?
                else {
                    return Err(denied());
                };
                let batch = crate::runs::batch(vec![record], self.options.codec_limits)?;
                fence.check()?;
                fence.check_disclosure()?;
                self.admit_locked(&key, &batch, true, gate.clone())
                    .await
                    .map_err(map)?
            };
            let fresh = self
                .policy_context_locked(&execution.basis.principal)
                .await?;
            self.check_execution_current(&execution, &footprint, &fresh)?;
            let stored = self
                .envelope_v3_locked(run.id())
                .await?
                .ok_or_else(denied)?;
            self.check_recorded_v3_footprint(&footprint, &stored)?;
            self.authorize_envelope_v3(&execution.basis.principal, &fresh, &stored, true)?;
            fence.check()?;
            fence.check_disclosure()?;
            sink(&stored, receipt.snapshot())?;
            Ok(receipt.snapshot().clone())
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "v3 execution commit task failed"))?
    }
}
