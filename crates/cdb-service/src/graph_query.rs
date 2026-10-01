//! Read-only, acquisition-owned CTXQL execution. The model supplies only inline
//! query bytes; authority, captures, configuration and providers remain host-owned.

use crate::{
    graph_workspace::{IssuedClaim, IssuedEndpoint, IssuedGraph, IssuedNode, TypedLiteral},
    service::semantic_interpretation::{
        mappings_from_config, SemanticInterpretation, SemanticProvider,
    },
};
use cdb_backend_fluree::{
    runs::ExternalPublicationFence,
    runs::Operation,
    semantic_policy::verify_semantic_authority_current,
    semantic_preparation::{prepare_historical_authorized_view, ExtractionLimits},
    FlureeBackend, FlureeSemanticLedger, FlureeSemanticWriter,
};
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    claim::ClaimObject,
    contracts::{GraphBackend, PolicyService, SemanticProjectionSource},
    id::{PrincipalId, ResourceId},
    CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use cdb_engine::{
    compiler::{
        compile_with_compiler_capabilities, CompilerCapabilities, MappingCapabilities, QuerySource,
        SelectedProfile,
    },
    execution::{
        capture_dual_execution, publish_staged, stage_captured_for_publication, ExecutionCapture,
        ExecutionOptions,
    },
    options::CompileOptions,
};
use cdb_projection_redb::{Coordinator, RedbProjection, RedbViewProvider};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

// Content-free diagnostic used by isolated fixture processes to prove replay
// does not execute live graph queries (authorization reads are separate).
static GRAPH_QUERY_EXECUTIONS: AtomicU64 = AtomicU64::new(0);
const MAX_INTERNAL_RECORDS: usize = 10_000;
const MAX_INTERNAL_RETAINED_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn execution_count_for_fixture() -> u64 {
    GRAPH_QUERY_EXECUTIONS.load(Ordering::Relaxed)
}

pub(crate) fn require_graph_query_binding(
    capability: &V,
    query_config: &ArtifactRef,
    profile: Option<&(String, ArtifactRef)>,
) -> Result<()> {
    let denied = || Error::new(ErrorKind::Denied, "graph query capture binding mismatch");
    if capability.field("query_config")? != &query_config.projection() {
        return Err(denied());
    }
    match profile {
        Some((selector, reference))
            if capability.field("profile_selector")?.as_str()? == selector
                && capability.field("profile")? == &reference.projection() =>
        {
            Ok(())
        }
        None if capability.field("profile_selector")? == &V::Null
            && capability.field("profile")? == &V::Null =>
        {
            Ok(())
        }
        _ => Err(denied()),
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct GraphQueryLimits {
    pub max_nodes: usize,
    pub max_claims: usize,
    pub max_response_bytes: usize,
    pub max_work: usize,
    pub timeout: Duration,
}

impl Default for GraphQueryLimits {
    fn default() -> Self {
        Self {
            max_nodes: 50,
            max_claims: 100,
            max_response_bytes: 64 * 1024,
            max_work: 100_000,
            timeout: Duration::from_secs(10),
        }
    }
}

impl GraphQueryLimits {
    /// Private scan ceilings; inventory pages keep ordinary chat output budgets.
    pub(crate) fn for_inventory(self) -> Self {
        Self {
            max_nodes: 2048,
            max_claims: 4096,
            max_response_bytes: MAX_INTERNAL_RETAINED_BYTES,
            ..self
        }
    }

    fn validate(self) -> Result<Self> {
        if self.max_nodes == 0
            || self.max_claims == 0
            || self.max_response_bytes == 0
            || self.max_work == 0
            || self.timeout.is_zero()
        {
            return Err(Error::invalid("graph query limits"));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) enum GraphQueryDiagnostic {
    QueryTooBroad { cap: &'static str },
    Incomplete,
    Capacity,
}

#[derive(Clone, Debug)]
pub(crate) struct AuthorizedGraph {
    pub graph: IssuedGraph,
    pub dependencies: BTreeSet<String>,
}

/// Neutral execution data, not an authorization capability. Normal hosts supply
/// authorized data; the explicitly unsafe chat adapter supplies unfiltered data.
/// Adapters own final projection/size checks and identify that mode to callers;
/// no extraction workspace state or identity eligibility is implied.
#[derive(Clone, Debug)]
pub(crate) struct AuthorizedQuery {
    pub dependencies: BTreeSet<String>,
    pub response: V,
    pub labels: BTreeMap<String, Vec<crate::service::semantic_interpretation::AuthorizedLabel>>,
    pub snapshot: cdb_core::snapshot::SnapshotRef,
    pub query_config: ArtifactRef,
    pub profile: Option<(String, ArtifactRef)>,
}

/// Deliberately contains the projection only as an implementation detail. No
/// raw provider or native store capability is returned from this type.
struct GraphPublicationFence {
    cancellation: Arc<AtomicBool>,
    deadline: Instant,
}

impl ExternalPublicationFence for GraphPublicationFence {
    fn check(&self) -> Result<()> {
        if self.cancellation.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(Error::new(ErrorKind::Deadline, "graph session unavailable"));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct GraphQueryHost {
    semantic: Arc<FlureeSemanticLedger>,
    semantic_writer: Option<Arc<FlureeSemanticWriter>>,
    control: Arc<FlureeBackend>,
    projection: Arc<RedbProjection>,
    coordinator: Option<Arc<Coordinator>>,
    _isolated: Option<Arc<crate::graph_read_only::IsolatedGraphReadSnapshot>>,
    principal: cdb_backend_fluree::policy::FlureePrincipal,
    semantic_principal: String,
    semantic_action: String,
    config: PublishedArtifact,
    profile: Option<(String, PublishedArtifact)>,
    capture: ExecutionCapture,
    interpretation: Arc<SemanticInterpretation>,
    limits: GraphQueryLimits,
    source_authority: Option<crate::sources::SourceAuthorization>,
}

impl GraphQueryHost {
    pub(crate) fn with_source_authority(
        &self,
        authority: crate::sources::SourceAuthorization,
    ) -> Arc<Self> {
        let mut host = self.clone();
        host.source_authority = Some(authority);
        Arc::new(host)
    }

    /// Caller holds the Control gate; the retained exact selector requirements
    /// are evaluated against fresh current policy, not an earlier source grant.
    pub(crate) fn authorize_sources(
        &self,
        context: &cdb_backend_fluree::policy::FlureePolicyContext,
    ) -> Result<()> {
        self.control.require_operation(context, Operation::Query)?;
        authorize_artifact_reference(self.control.as_ref(), context, self.config.reference())?;
        if let Some((_, profile)) = &self.profile {
            authorize_artifact_reference(self.control.as_ref(), context, profile.reference())?;
        }
        if let Some(authority) = &self.source_authority {
            authority.check(self.control.as_ref(), context)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn prepare(
        semantic: Arc<FlureeSemanticLedger>,
        semantic_writer: Arc<FlureeSemanticWriter>,
        control: Arc<FlureeBackend>,
        projection: Arc<RedbProjection>,
        coordinator: Arc<Coordinator>,
        principal: PrincipalId,
        semantic_action: String,
        config_ref: ArtifactRef,
        profile_ref: Option<(String, ArtifactRef)>,
        limits: GraphQueryLimits,
    ) -> Result<Arc<Self>> {
        Self::prepare_resources(
            semantic.clone(),
            semantic,
            Some(semantic_writer),
            control,
            projection,
            Some(coordinator),
            None,
            principal,
            semantic_action,
            config_ref,
            profile_ref,
            limits,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn prepare_read_only(
        original: Arc<FlureeSemanticLedger>,
        isolated: Arc<crate::graph_read_only::IsolatedGraphReadSnapshot>,
        control: Arc<FlureeBackend>,
        principal: PrincipalId,
        semantic_action: String,
        config_ref: ArtifactRef,
        profile_ref: Option<(String, ArtifactRef)>,
        limits: GraphQueryLimits,
    ) -> Result<Arc<Self>> {
        Self::prepare_resources(
            isolated.semantic().clone(),
            original,
            None,
            control,
            isolated.projection().clone(),
            None,
            Some(isolated),
            principal,
            semantic_action,
            config_ref,
            profile_ref,
            limits,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_resources(
        semantic: Arc<FlureeSemanticLedger>,
        current_semantic: Arc<FlureeSemanticLedger>,
        semantic_writer: Option<Arc<FlureeSemanticWriter>>,
        control: Arc<FlureeBackend>,
        projection: Arc<RedbProjection>,
        coordinator: Option<Arc<Coordinator>>,
        isolated: Option<Arc<crate::graph_read_only::IsolatedGraphReadSnapshot>>,
        principal: PrincipalId,
        semantic_action: String,
        config_ref: ArtifactRef,
        profile_ref: Option<(String, ArtifactRef)>,
        limits: GraphQueryLimits,
    ) -> Result<Arc<Self>> {
        let limits = limits.validate()?;
        let semantic_principal = principal.as_str().to_owned();
        let principal = control
            .issue_principal(principal)
            .await
            .map_err(|_| Error::new(ErrorKind::Denied, "graph query principal unavailable"))?;
        // Pin the existing Control head. Creating a fresh capture here would be
        // observable authority housekeeping and could invalidate a concurrently
        // prepared operation; graph reads must be side-effect free.
        let control_capture = GraphBackend::head(control.as_ref()).await?;
        let context = control.current(&principal).await?;
        control.require_operation(&context, Operation::Query)?;
        let config = load_artifact(&control, &context, &control_capture, &config_ref).await?;
        let profile = match profile_ref {
            Some((selector, reference)) => {
                let artifact =
                    load_artifact(&control, &context, &control_capture, &reference).await?;
                let source = cdb_engine::frontend::parse(
                    cdb_engine::artifacts::ArtifactKind::Profile,
                    artifact.content(),
                    Limits::default(),
                )?
                .value;
                if source.field("name")?.as_str()? != selector {
                    return Err(Error::invalid("published profile name binding"));
                }
                Some((selector, artifact))
            }
            None => None,
        };
        let semantic_capture = SemanticProjectionSource::capture(semantic.as_ref(), None).await?;
        let t = semantic_capture
            .snapshot
            .pin()
            .revision()
            .as_str()
            .parse::<i64>()
            .map_err(|_| Error::invalid("semantic transaction"))?;
        let exact = semantic
            .capture_at_t(t, Some(semantic_capture.snapshot.pin().receipt()), None)
            .await?;
        let authorized = prepare_historical_authorized_view(
            semantic.as_ref(),
            &exact,
            &semantic_principal,
            &semantic_action,
            ExtractionLimits::default(),
        )
        .await
        .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        let mappings = mappings_from_config(
            &cdb_engine::frontend::parse(
                cdb_engine::artifacts::ArtifactKind::Config,
                config.content(),
                Limits::default(),
            )?
            .value,
        )?
        .into_iter()
        .filter(|mapping| {
            matches!(
                mapping,
                cdb_engine::compiler::FieldMapping::StoredPredicate { .. }
            )
        })
        .collect();
        let interpretation = SemanticInterpretation::new_authorized_mapped(
            &semantic_capture,
            authorized,
            mappings,
            Vec::new(),
        )?;
        verify_semantic_authority_current(semantic.as_ref(), interpretation.policy_basis())
            .await
            .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        verify_semantic_authority_current(current_semantic.as_ref(), interpretation.policy_basis())
            .await
            .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        Ok(Arc::new(Self {
            semantic: current_semantic,
            semantic_writer,
            control,
            projection,
            coordinator,
            _isolated: isolated,
            principal,
            semantic_principal,
            semantic_action,
            config,
            profile,
            capture: capture_dual_execution(semantic_capture, control_capture),
            interpretation: Arc::new(interpretation),
            limits,
            source_authority: None,
        }))
    }

    pub(crate) fn snapshot_binding(&self) -> String {
        let pin = self.capture.snapshot().snapshot.pin();
        format!(
            "{}:{}:{}",
            pin.graph().as_str(),
            pin.revision().as_str(),
            pin.receipt().as_str()
        )
    }

    pub(crate) async fn reauthorize(&self) -> Result<()> {
        let context = self.control.current(&self.principal).await?;
        self.control.require_operation(&context, Operation::Query)?;
        authorize_artifact_reference(self.control.as_ref(), &context, self.config.reference())?;
        if let Some((_, profile)) = &self.profile {
            authorize_artifact_reference(self.control.as_ref(), &context, profile.reference())?;
        }
        verify_semantic_authority_current(
            self.semantic.as_ref(),
            self.interpretation.policy_basis(),
        )
        .await
        .map_err(|reason| Error::new(ErrorKind::Denied, reason))
    }

    pub(crate) async fn guarded_control_action<T, F, Fut>(
        &self,
        cancellation: Arc<AtomicBool>,
        deadline: Instant,
        action: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        let context = self.control.current(&self.principal).await?;
        self.control.require_operation(&context, Operation::Query)?;
        authorize_artifact_reference(self.control.as_ref(), &context, self.config.reference())?;
        if let Some((_, profile)) = &self.profile {
            authorize_artifact_reference(self.control.as_ref(), &context, profile.reference())?;
        }
        let source_context = context.clone();
        let source_host = self.clone();
        self.control
            .clone()
            .guarded_owned_query_action(
                self.principal.clone(),
                context,
                Box::new(GraphPublicationFence {
                    cancellation,
                    deadline,
                }),
                move || async move {
                    source_host.authorize_sources(&source_context)?;
                    action().await
                },
            )
            .await
    }

    pub(crate) async fn guarded_disclosure_action<T, F, Fut>(
        &self,
        supports: BTreeSet<String>,
        cancellation: Arc<AtomicBool>,
        deadline: Instant,
        action: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        let context = self.control.current(&self.principal).await?;
        self.control.require_operation(&context, Operation::Query)?;
        authorize_artifact_reference(self.control.as_ref(), &context, self.config.reference())?;
        if let Some((_, profile)) = &self.profile {
            authorize_artifact_reference(self.control.as_ref(), &context, profile.reference())?;
        }
        let writer = self.semantic_writer.clone();
        let semantic = self.semantic.clone();
        let principal = self.semantic_principal.clone();
        let semantic_action = self.semantic_action.clone();
        let policy_basis = self.interpretation.policy_basis().clone();
        let published = Arc::new(std::sync::Mutex::new(None));
        let sink = published.clone();
        let source_context = context.clone();
        let source_host = self.clone();
        self.control
            .clone()
            .guarded_owned_query_action(
                self.principal.clone(),
                context,
                Box::new(GraphPublicationFence {
                    cancellation,
                    deadline,
                }),
                move || async move {
                    source_host.authorize_sources(&source_context)?;
                    let guard = match writer.as_ref() {
                        Some(writer) => Some(
                            writer
                                .disclosure_guard(
                                    &principal,
                                    &semantic_action,
                                    &policy_basis,
                                    &supports,
                                )
                                .await?,
                        ),
                        None => {
                            authorize_read_dependencies(
                                &semantic,
                                &principal,
                                &semantic_action,
                                &policy_basis,
                                &supports,
                            )
                            .await?;
                            None
                        }
                    };
                    let value = action().await?;
                    if guard.is_none() {
                        authorize_read_dependencies(
                            &semantic,
                            &principal,
                            &semantic_action,
                            &policy_basis,
                            &supports,
                        )
                        .await?;
                    }
                    source_host.authorize_sources(&source_context)?;
                    *sink
                        .lock()
                        .map_err(|_| Error::new(ErrorKind::Backend, "graph publication sink"))? =
                        Some(value);
                    Ok(())
                },
            )
            .await?;
        let value = published
            .lock()
            .map_err(|_| Error::new(ErrorKind::Backend, "graph publication sink"))?
            .take()
            .ok_or_else(|| Error::new(ErrorKind::Backend, "graph publication missing"))?;
        Ok(value)
    }

    pub(crate) fn require_capture_binding(&self, capability: &V) -> Result<()> {
        let profile = self
            .profile
            .as_ref()
            .map(|(selector, artifact)| (selector.clone(), artifact.reference().clone()));
        require_graph_query_binding(capability, self.config.reference(), profile.as_ref())
    }

    pub(crate) fn policy_basis(&self) -> &cdb_backend_fluree::semantic_policy::SemanticPolicyBasis {
        self.interpretation.policy_basis()
    }

    pub(crate) fn semantic_principal(&self) -> &str {
        &self.semantic_principal
    }

    pub(crate) fn semantic_action(&self) -> &str {
        &self.semantic_action
    }

    /// Validate exact disclosed dependencies while the acquisition workflow
    /// already owns the Semantic writer session. This avoids recursively
    /// acquiring the writer's disclosure lock.
    pub(crate) async fn authorize_writer_session(
        &self,
        session: &cdb_backend_fluree::acquisition_writer::FlureeWriterSession<'_>,
        supports: &BTreeSet<String>,
    ) -> Result<()> {
        session
            .authorize_disclosure(
                &self.semantic_principal,
                &self.semantic_action,
                self.interpretation.policy_basis(),
                supports,
            )
            .await
    }

    pub(crate) async fn query(
        &self,
        issuer: &str,
        session_id: &str,
        inline: &[u8],
        cancellation: Arc<AtomicBool>,
        requested: GraphQueryLimits,
    ) -> Result<std::result::Result<AuthorizedGraph, GraphQueryDiagnostic>> {
        let execution = match self.execute(inline, cancellation, requested).await? {
            Ok(execution) => execution,
            Err(diagnostic) => return Ok(Err(diagnostic)),
        };
        let mut graph = project_graph(
            issuer,
            session_id,
            &self.snapshot_binding(),
            &execution.response,
        )?;
        for node in &mut graph.nodes {
            node.dependencies = self.interpretation.label_dependencies(&node.canonical_iri);
        }
        if serde_json::to_vec(&graph)
            .map_err(|_| Error::new(ErrorKind::Backend, "graph result encoding"))?
            .len()
            > requested
                .max_response_bytes
                .min(self.limits.max_response_bytes)
        {
            return Ok(Err(GraphQueryDiagnostic::Capacity));
        }
        Ok(Ok(AuthorizedGraph {
            graph,
            dependencies: execution.dependencies,
        }))
    }

    pub(crate) fn approximate_explicit_labels(&self) -> bool {
        V::parse(self.config.content(), Limits::default())
            .and_then(|value| {
                Ok(value.field("landing")?.field("resolver")?.as_str()?
                    == "ctxql.lexical-token-overlap/v1")
            })
            .unwrap_or(false)
    }

    pub(crate) async fn execute_inventory(
        &self,
        cancellation: Arc<AtomicBool>,
    ) -> Result<std::result::Result<AuthorizedQuery, GraphQueryDiagnostic>> {
        if self.profile.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "inventory requires an unprofiled explicit view",
            ));
        }
        let mut seeds = self.interpretation.inventory_seeds();
        if seeds.len() > self.limits.max_nodes {
            return Ok(Err(GraphQueryDiagnostic::Capacity));
        }
        if seeds.is_empty() {
            seeds.push("urn:ctxql:inventory:empty".into());
        }
        let query = serde_json::to_vec(&serde_json::json!({
            "about":[{"from":seeds,"match":"exact"}],
            "bounds":{"max_depth":1,"seed_limit":self.limits.max_nodes,
                "fanout_limit":self.limits.max_claims,"max_claims":self.limits.max_claims,
                "path_limit":self.limits.max_claims},
            "walk":{"direction":"outgoing"}
        }))
        .map_err(|_| Error::invalid("inventory scan encoding"))?;
        self.execute_scoped(&query, cancellation, self.limits, true)
            .await
    }

    pub(crate) async fn execute(
        &self,
        inline: &[u8],
        cancellation: Arc<AtomicBool>,
        requested: GraphQueryLimits,
    ) -> Result<std::result::Result<AuthorizedQuery, GraphQueryDiagnostic>> {
        self.execute_scoped(inline, cancellation, requested, false)
            .await
    }

    async fn execute_scoped(
        &self,
        inline: &[u8],
        cancellation: Arc<AtomicBool>,
        requested: GraphQueryLimits,
        inventory: bool,
    ) -> Result<std::result::Result<AuthorizedQuery, GraphQueryDiagnostic>> {
        let _ =
            GRAPH_QUERY_EXECUTIONS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            });
        let requested = requested.validate()?;
        let limits = GraphQueryLimits {
            max_nodes: requested.max_nodes.min(self.limits.max_nodes),
            max_claims: requested.max_claims.min(self.limits.max_claims),
            max_response_bytes: requested
                .max_response_bytes
                .min(self.limits.max_response_bytes),
            max_work: requested.max_work.min(self.limits.max_work),
            timeout: requested.timeout.min(self.limits.timeout),
        };
        self.reauthorize().await?;
        let draft = compile_with_compiler_capabilities(
            QuerySource::inline(inline),
            self.profile
                .as_ref()
                .map(|(selector, artifact)| SelectedProfile { selector, artifact }),
            &self.config,
            CompileOptions::default(),
            graph_query_compiler_capabilities(),
        )?;
        if draft
            .requested_as_of()
            .is_some_and(|value| value != self.capture.snapshot().as_of)
        {
            return Err(Error::new(ErrorKind::Snapshot, "session capture is fixed"));
        }
        // Catalog preparation and landing are internal work, not returned graph
        // records. Keep them bounded independently so a catalog larger than the
        // output ceilings can still produce a small, complete graph.
        let options = ExecutionOptions {
            // A complete private inventory scan can encode more than the
            // ordinary small response. Bound canonical parsing/serialization
            // separately; neither output pages nor traversal work are unbounded.
            limits: if inventory {
                Limits::new(
                    MAX_INTERNAL_RETAINED_BYTES,
                    64,
                    1_000_000,
                    32_000_000,
                    MAX_INTERNAL_RETAINED_BYTES,
                )?
            } else {
                Limits::default()
            },
            deadline: Some(Instant::now() + limits.timeout),
            cancellation: Some(cancellation),
            max_work: limits.max_work,
            max_records: MAX_INTERNAL_RECORDS.min(limits.max_work),
            max_retained_bytes: MAX_INTERNAL_RETAINED_BYTES,
            max_paths: limits.max_claims.saturating_add(1),
            max_frontier: limits.max_nodes.saturating_add(1),
            ..Default::default()
        };
        let provider: Box<dyn cdb_engine::execution::ViewProvider> = match &self.coordinator {
            Some(coordinator) => Box::new(RedbViewProvider::new(
                coordinator.clone(),
                self.projection.clone(),
                limits.timeout,
            )?),
            None => Box::new(ExactReadProvider(self.projection.clone())),
        };
        let semantic_provider = SemanticProvider::new(provider.as_ref(), &self.interpretation);
        let staged = stage_captured_for_publication(
            draft,
            self.control.as_ref(),
            self.control.as_ref(),
            &self.principal,
            &self.capture,
            &semantic_provider,
            options.clone(),
        )
        .await?;
        if staged.has_result_truncation() {
            return Ok(Err(GraphQueryDiagnostic::Incomplete));
        }
        // Check both authorities around the opaque Control publication. Bytes do
        // not leave this host until the second Semantic check succeeds.
        self.reauthorize().await?;
        let bytes =
            publish_staged(staged, self.control.as_ref(), &self.principal, &options).await?;
        self.reauthorize().await?;
        if bytes.len() > limits.max_response_bytes {
            return Ok(Err(GraphQueryDiagnostic::Capacity));
        }
        let value = V::parse(&bytes, options.limits)?;
        let claims = value.field("claims")?.as_array()?;
        let mut identities = BTreeSet::new();
        let mut dependencies = BTreeSet::new();
        for claim in claims {
            let meta = claim.field("meta")?;
            dependencies.insert(meta.field("claim_id")?.as_str()?.to_owned());
            identities.insert(meta.field("subject_id")?.as_str()?.to_owned());
            if let ClaimObject::Entity(id) = ClaimObject::from_value(meta.field("object_id")?)? {
                identities.insert(id.as_str().to_owned());
            }
        }
        if let Some(paths) = value.as_object()?.get("paths") {
            for path in paths.as_array()? {
                for node in path.field("node_ids")?.as_array()? {
                    identities.insert(node.as_str()?.to_owned());
                }
            }
        }
        if claims.len() > limits.max_claims {
            return Ok(Err(GraphQueryDiagnostic::QueryTooBroad { cap: "claims" }));
        }
        if identities.len() > limits.max_nodes {
            return Ok(Err(GraphQueryDiagnostic::QueryTooBroad { cap: "nodes" }));
        }
        // Explicit-label supports remain dependencies even if the query's walk
        // omits their edges. Both adapters must fence them before disclosure.
        let labels = identities
            .into_iter()
            .map(|iri| {
                dependencies.extend(self.interpretation.label_dependencies(&iri));
                let labels = self.interpretation.labels_for(&iri);
                (iri, labels)
            })
            .collect();
        Ok(Ok(AuthorizedQuery {
            dependencies,
            response: value,
            labels,
            snapshot: self.capture.snapshot().snapshot.clone(),
            query_config: self.config.reference().clone(),
            profile: self
                .profile
                .as_ref()
                .map(|(selector, artifact)| (selector.clone(), artifact.reference().clone())),
        }))
    }
}

pub(crate) fn graph_query_compiler_capabilities() -> CompilerCapabilities {
    CompilerCapabilities {
        custom_predicates: false,
        external_functions: false,
        prepared_interpretation: false,
        approximate_landing: true,
        mappings: MappingCapabilities {
            stored_predicate: true,
            lexical_landing: true,
            reasoned: false,
            computed: false,
            ontology: false,
        },
    }
}

/// Exact read-only projection access: no coordinator, repairs or stale fallback.
struct ExactReadProvider(Arc<RedbProjection>);
struct EmptyLanding(cdb_core::snapshot::SnapshotRef);
impl cdb_engine::execution::LandingCatalog for EmptyLanding {
    fn identity(&self) -> &cdb_core::snapshot::SnapshotRef {
        &self.0
    }
    fn entries(&self) -> &[cdb_engine::execution::LandingEntry] {
        &[]
    }
}
impl cdb_engine::execution::ViewProvider for ExactReadProvider {
    fn propose_stale<'a>(
        &'a self,
        _captured: &'a cdb_core::contracts::CapturedSnapshot,
        _options: &'a ExecutionOptions,
    ) -> cdb_core::contracts::IoFuture<'a, Option<cdb_core::snapshot::SnapshotRef>> {
        Box::pin(async { Ok(None) })
    }
    fn open<'a>(
        &'a self,
        captured: &'a cdb_core::contracts::CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> cdb_core::contracts::IoFuture<'a, cdb_engine::execution::PreparedView> {
        Box::pin(async move {
            options.check_interrupted()?;
            let view = self.0.open_generation(&captured.snapshot).await?;
            options.check_interrupted()?;
            Ok(cdb_engine::execution::PreparedView {
                view,
                landing: Arc::new(EmptyLanding(captured.snapshot.clone())),
            })
        })
    }
}

async fn authorize_read_dependencies(
    semantic: &FlureeSemanticLedger,
    principal: &str,
    action: &str,
    basis: &cdb_backend_fluree::semantic_policy::SemanticPolicyBasis,
    supports: &BTreeSet<String>,
) -> Result<()> {
    if supports.len() > 4096 {
        return Err(Error::limit());
    }
    verify_semantic_authority_current(semantic, basis)
        .await
        .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
    let capture = semantic.capture_current(None).await?;
    let current = prepare_historical_authorized_view(
        semantic,
        &capture,
        principal,
        action,
        ExtractionLimits::default(),
    )
    .await
    .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
    if !supports.is_subset(&current.manifest.visible_supports) {
        return Err(Error::new(
            ErrorKind::Denied,
            "graph dependency unavailable",
        ));
    }
    verify_semantic_authority_current(semantic, basis)
        .await
        .map_err(|reason| Error::new(ErrorKind::Denied, reason))
}

fn authorize_artifact_reference(
    backend: &FlureeBackend,
    context: &cdb_backend_fluree::policy::FlureePolicyContext,
    reference: &ArtifactRef,
) -> Result<()> {
    let id = ResourceId::new(reference.iri().as_str())?;
    if !backend.resource_allowed(context, &id)? {
        return Err(Error::new(
            ErrorKind::Denied,
            "query configuration unavailable",
        ));
    }
    for key in ["iri", "version", "hash"] {
        let property = cdb_core::id::Iri::new(format!(
            "https://ctxql.example/reference-property/v1/artifact%2E{key}"
        ))?;
        if !backend.fact_allowed(context, &id, &property)? {
            return Err(Error::new(
                ErrorKind::Denied,
                "query configuration unavailable",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn load_artifact(
    backend: &FlureeBackend,
    context: &cdb_backend_fluree::policy::FlureePolicyContext,
    capture: &cdb_core::snapshot::SnapshotRef,
    reference: &ArtifactRef,
) -> Result<PublishedArtifact> {
    authorize_artifact_reference(backend, context, reference)?;
    let snapshot = backend.open_snapshot(capture).await?;
    let id = ResourceId::new(reference.iri().as_str())?;
    if snapshot
        .resource(&id)
        .await?
        .is_some_and(|record| record.kind() == cdb_core::admission::ResourceKind::RunDescriptor)
    {
        return Err(Error::new(
            ErrorKind::Denied,
            "query configuration unavailable",
        ));
    }
    snapshot
        .artifact(reference)
        .await?
        .ok_or_else(|| Error::new(ErrorKind::Denied, "query configuration unavailable"))
}

fn project_graph(
    issuer: &str,
    session_id: &str,
    snapshot: &str,
    response: &V,
) -> Result<IssuedGraph> {
    let claims = response
        .field("claims")?
        .as_array()?
        .iter()
        .map(project_claim)
        .collect::<Result<Vec<_>>>()?;
    let mut identities = BTreeSet::new();
    for claim in &claims {
        identities.insert(claim.subject_key.clone());
        if let IssuedEndpoint::Node { key } = &claim.object {
            identities.insert(key.clone());
        }
    }
    if let Ok(paths) = response.field("paths").and_then(V::as_array) {
        for path in paths {
            for node in path.field("node_ids")?.as_array()? {
                identities.insert(node.as_str()?.to_owned());
            }
        }
    }
    let nodes = identities
        .into_iter()
        .map(|iri| IssuedNode {
            key: iri.clone(),
            canonical_iri: iri.clone(),
            label: iri,
            // Query visibility never promotes an identity. Until the existing
            // gazetteer proves eligibility for a final proposal, the conservative
            // host calculation is false.
            metadata: BTreeMap::from([("reuse_eligible".into(), "false".into())]),
            dependencies: Vec::new(),
        })
        .collect();
    Ok(IssuedGraph {
        schema: "ctxql.graph-workspace/v1".into(),
        issuer: issuer.into(),
        session_id: session_id.into(),
        snapshot: snapshot.into(),
        nodes,
        claims,
    })
}

fn project_claim(value: &V) -> Result<IssuedClaim> {
    let meta = value.field("meta")?;
    let object = ClaimObject::from_value(meta.field("object_id")?)?;
    let object = match object {
        ClaimObject::Entity(id) => IssuedEndpoint::Node {
            key: id.as_str().to_owned(),
        },
        ClaimObject::Literal(literal) => IssuedEndpoint::Literal {
            value: TypedLiteral {
                lexical: match literal.value() {
                    V::String(value) => value.clone(),
                    value => String::from_utf8(value.canonical_bytes(Limits::default())?)
                        .map_err(|_| Error::invalid("literal encoding"))?,
                },
                datatype: literal.datatype().as_str().to_owned(),
                language: literal.language().map(str::to_owned),
            },
        },
    };
    let mut metadata = BTreeMap::new();
    for (key, item) in meta.as_object()? {
        metadata.insert(
            key.clone(),
            String::from_utf8(item.canonical_bytes(Limits::default())?)
                .map_err(|_| Error::invalid("claim metadata encoding"))?,
        );
    }
    let claim_id = meta.field("claim_id")?.as_str()?.to_owned();
    Ok(IssuedClaim {
        claim_id: claim_id.clone(),
        subject_key: meta.field("subject_id")?.as_str()?.to_owned(),
        predicate: meta.field("relation")?.as_str()?.to_owned(),
        object,
        metadata,
        // Per the graph-playground contract, retained Semantic dependencies are
        // exactly the claims returned into the tool result.
        dependencies: vec![claim_id],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_graph_workspace_queries_match_fixtures_and_restricted_compiler() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/conformance/graph-workspace/query-examples-v1.json"
        ))
        .unwrap();
        // Exercise the actual published-config example, including its pinned
        // Unicode tables, rather than an independently generated test config.
        let config_bytes =
            include_str!("../../../fixtures/conformance/graph-workspace/config.json");
        let config = PublishedArtifact::new(
            ArtifactRef::new(
                cdb_core::id::Iri::new("urn:graph-skill-config").unwrap(),
                cdb_core::id::VersionId::new("1").unwrap(),
                cdb_core::id::ContentHash::of_bytes(config_bytes.as_bytes()),
            ),
            config_bytes.as_bytes().to_vec(),
            Limits::default(),
        )
        .unwrap();
        let examples = fixture["examples"].as_array().unwrap();
        for example in examples {
            let bytes = serde_json::to_vec(&example["query"]).unwrap();
            let result = compile_with_compiler_capabilities(
                QuerySource::inline(&bytes),
                None,
                &config,
                CompileOptions::default(),
                graph_query_compiler_capabilities(),
            );
            assert_eq!(
                result.is_ok(),
                example["compile"].as_bool().unwrap(),
                "{}: {:?}",
                example["id"],
                result.err()
            );
        }

        let skill = include_str!("../../../assets/pi/skills/ctxql-query/SKILL.md");
        let documented = skill
            .split("```json\n")
            .skip(1)
            .map(|block| {
                serde_json::from_str::<serde_json::Value>(block.split("\n```").next().unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let expected = examples
            .iter()
            .filter(|example| example["compile"] == true)
            .map(|example| example["query"].clone())
            .collect::<Vec<_>>();
        let (inventory, documented): (Vec<_>, Vec<_>) = documented.into_iter().partition(|query| {
            query.get("schema").and_then(serde_json::Value::as_str)
                == Some("ctxql.chat-inventory/v1")
        });
        assert_eq!(
            inventory.len(),
            2,
            "chat envelopes are tested separately, not CTXQL syntax"
        );
        assert_eq!(documented, expected);
    }

    #[test]
    fn graph_execution_working_capacity_is_independent_of_output_ceilings() {
        let limits = GraphQueryLimits::default();
        let options = ExecutionOptions {
            max_work: limits.max_work,
            max_records: MAX_INTERNAL_RECORDS.min(limits.max_work),
            max_retained_bytes: MAX_INTERNAL_RETAINED_BYTES,
            max_paths: limits.max_claims.saturating_add(1),
            max_frontier: limits.max_nodes.saturating_add(1),
            ..Default::default()
        };

        assert_eq!(options.max_records, 10_000);
        assert_eq!(options.max_retained_bytes, 16 * 1024 * 1024);
        assert_eq!(limits.max_nodes, 50);
        assert_eq!(limits.max_claims, 100);
        assert_eq!(limits.max_response_bytes, 64 * 1024);
    }

    #[test]
    fn graph_projection_is_endpoint_closed_and_preserves_claim_identity_and_literals() {
        let response = V::parse(
            br#"{
              "claims":[
                {"meta":{"claim_id":"urn:c1","subject_id":"urn:s","relation":"urn:p","object_id":"urn:o"}},
                {"meta":{"claim_id":"urn:c2","subject_id":"urn:s","relation":"urn:p","object_id":"urn:o"}},
                {"meta":{"claim_id":"urn:c3","subject_id":"urn:s","relation":"urn:value","object_id":{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#integer","value":42,"language":null}}}
              ],
              "paths":[]
            }"#,
            Limits::default(),
        )
        .unwrap();
        let graph = project_graph("issuer", "session", "snapshot", &response).unwrap();
        assert_eq!(graph.claims.len(), 3);
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.claims[0].claim_id, "urn:c1");
        assert_eq!(graph.claims[1].claim_id, "urn:c2");
        assert_eq!(graph.claims[0].dependencies, vec!["urn:c1".to_owned()]);
        assert!(matches!(
            &graph.claims[2].object,
            IssuedEndpoint::Literal { value }
                if value.lexical == "42"
                    && value.datatype == "http://www.w3.org/2001/XMLSchema#integer"
        ));
        assert!(graph.nodes.iter().all(|node| node
            .metadata
            .get("reuse_eligible")
            .map(String::as_str)
            == Some("false")));
    }
}
