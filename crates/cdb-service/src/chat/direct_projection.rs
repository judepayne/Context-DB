//! Explicitly unsafe, chat-only projection reads. No Semantic authorization
//! evidence is manufactured. A native transaction is owned for one call only.
use super::reads::check_available;
use crate::{
    config::InstanceConfig,
    graph_query::{
        graph_query_compiler_capabilities, load_artifact, AuthorizedQuery, GraphQueryDiagnostic,
        GraphQueryHost, GraphQueryLimits,
    },
    service::semantic_interpretation::{semantic_landing_entries, AuthorizedLabel},
};
use cdb_backend_fluree::{runs::Operation, FlureeBackend, FlureeSemanticLedger};
use cdb_core::{
    admission::{DependencyRecord, ExportRecord},
    artifact::PublishedArtifact,
    claim::{AdmittedClaim, ClaimObject},
    contracts::{
        CapturedSnapshot, Direction, GraphBackend, IoFuture, PolicyService, RawQueryView,
        SemanticProjectionSource,
    },
    id::{ClaimId, EntityId, Iri, PrincipalId, ResourceId, VersionId},
    snapshot::{Page, PageCursor, PageSize, PageTracker, ProjectionCheckpoint, SnapshotRef},
    CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use cdb_engine::{
    compiler::{compile_with_compiler_capabilities, QuerySource, SelectedProfile},
    execution::{
        capture_dual_execution, publish_staged, stage_captured_for_publication, ExecutionCapture,
        ExecutionOptions, LandingCatalog, LandingEntry, PreparedView, ViewProvider,
    },
    options::CompileOptions,
};
use cdb_projection_redb::{GenerationOptions, GenerationView, RedbProjection};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{atomic::AtomicBool, Arc},
    time::Instant,
};

pub(super) enum ChatGraphHost {
    Enforced(Arc<GraphQueryHost>),
    Unsafe(Box<DirectProjectionHost>),
}
impl ChatGraphHost {
    pub fn approximate_explicit_labels(&self) -> bool {
        match self {
            Self::Enforced(h) => h.approximate_explicit_labels(),
            Self::Unsafe(h) => V::parse(h.config.content(), Limits::default())
                .and_then(|v| {
                    Ok(v.field("landing")?.field("resolver")?.as_str()?
                        == "ctxql.lexical-token-overlap/v1")
                })
                .unwrap_or(false),
        }
    }
    pub async fn execute(
        &self,
        bytes: &[u8],
        cancel: Arc<AtomicBool>,
        limits: GraphQueryLimits,
    ) -> Result<std::result::Result<AuthorizedQuery, GraphQueryDiagnostic>> {
        match self {
            Self::Enforced(h) => h.execute(bytes, cancel, limits).await,
            Self::Unsafe(h) => h.execute(bytes, cancel, limits, false).await,
        }
    }
    pub async fn execute_inventory(
        &self,
        cancel: Arc<AtomicBool>,
    ) -> Result<std::result::Result<AuthorizedQuery, GraphQueryDiagnostic>> {
        match self {
            Self::Enforced(h) => h.execute_inventory(cancel).await,
            Self::Unsafe(h) => {
                if h.profile.is_some() {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "inventory requires an unprofiled explicit view",
                    ));
                }
                let mut seeds = h
                    .provider
                    .catalog
                    .entries
                    .iter()
                    .map(|e| e.id.as_str().to_owned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                if seeds.len() > h.limits.max_nodes {
                    return Ok(Err(GraphQueryDiagnostic::Capacity));
                }
                if seeds.is_empty() {
                    seeds.push("urn:ctxql:inventory:empty".into());
                }
                let query = serde_json::to_vec(&serde_json::json!({"about":[{"from":seeds,"match":"exact"}],"bounds":{"max_depth":1,"seed_limit":h.limits.max_nodes,"fanout_limit":h.limits.max_claims,"max_claims":h.limits.max_claims,"path_limit":h.limits.max_claims},"walk":{"direction":"outgoing"}})).map_err(|_| Error::invalid("inventory scan encoding"))?;
                h.execute(&query, cancel, h.limits, true).await
            }
        }
    }
    pub async fn guarded_control_action<T, F, Fut>(
        &self,
        cancel: Arc<AtomicBool>,
        deadline: Instant,
        action: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        match self {
            Self::Enforced(h) => h.guarded_control_action(cancel, deadline, action).await,
            Self::Unsafe(_) => {
                check_available(&cancel, deadline)?;
                let value = action().await?;
                check_available(&cancel, deadline)?;
                Ok(value)
            }
        }
    }
    pub async fn guarded_disclosure_action<T, F, Fut>(
        &self,
        supports: BTreeSet<String>,
        cancel: Arc<AtomicBool>,
        deadline: Instant,
        action: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        match self {
            Self::Enforced(h) => {
                h.guarded_disclosure_action(supports, cancel, deadline, action)
                    .await
            }
            Self::Unsafe(_) => {
                check_available(&cancel, deadline)?;
                let value = action().await?;
                check_available(&cancel, deadline)?;
                Ok(value)
            }
        }
    }
}

pub(super) struct DirectProjectionHost {
    control: Arc<FlureeBackend>,
    config: PublishedArtifact,
    profile: Option<(String, PublishedArtifact)>,
    capture: ExecutionCapture,
    provider: DirectProvider,
    limits: GraphQueryLimits,
    deadline: Instant,
}
impl DirectProjectionHost {
    pub async fn prepare(
        instance: &InstanceConfig,
        semantic: &FlureeSemanticLedger,
        control: Arc<FlureeBackend>,
        principal: &PrincipalId,
        limits: GraphQueryLimits,
        cancel: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<ChatGraphHost> {
        let chat = instance
            .chat
            .as_ref()
            .ok_or_else(|| Error::invalid("chat required"))?;
        if !chat.unsafe_direct_projection {
            return Err(Error::new(
                ErrorKind::Denied,
                "unsafe projection mode not enabled",
            ));
        }
        check_available(&cancel, deadline)?;
        // Login/query credentials are checked by ChatReadResources. Published
        // configuration is still verified; only graph-data policy is bypassed.
        let principal = control
            .issue_principal(principal.clone())
            .await
            .map_err(|_| Error::new(ErrorKind::Denied, "query principal unavailable"))?;
        let context = control.current(&principal).await?;
        control.require_operation(&context, Operation::Query)?;
        let control_pin = GraphBackend::head(control.as_ref()).await?;
        let config = load_artifact(
            &control,
            &context,
            &control_pin,
            &chat.query_config.artifact_ref()?,
        )
        .await?;
        let profile = match (&chat.profile_selector, &chat.profile) {
            (Some(selector), Some(reference)) => {
                let artifact =
                    load_artifact(&control, &context, &control_pin, &reference.artifact_ref()?)
                        .await?;
                if V::parse(artifact.content(), Limits::default())?
                    .field("name")?
                    .as_str()?
                    != selector
                {
                    return Err(Error::invalid("chat profile binding"));
                }
                Some((selector.clone(), artifact))
            }
            (None, None) => None,
            _ => return Err(Error::invalid("chat profile binding")),
        };
        let binding = ProjectionCheckpoint::new(
            SemanticProjectionSource::head(semantic).await?,
            VersionId::new("ctxql-semantic-rdf/v1")?,
            VersionId::new("live")?,
            Iri::new("urn:ctxql:semantic-projection:v1")?,
        )?;
        let view = RedbProjection::open_latest_semantic_existing(
            &instance.projection,
            binding,
            GenerationOptions::default(),
        )
        .await?;
        let captured = semantic
            .capture_projection_snapshot(view.identity())
            .await?;
        let scan_view = view.clone();
        let scan_cancel = cancel.clone();
        let max_records = 10_000.min(limits.max_work);
        let entries = tokio::task::spawn_blocking(move || {
            let mut records = Vec::new();
            let mut cursor = None;
            let mut tracker = None;
            let mut bytes = 0usize;
            loop {
                check_available(&scan_cancel, deadline)?;
                let page = scan_view.scan(PageSize::new(256)?, cursor.as_ref())?;
                let tracker = tracker.get_or_insert_with(|| {
                    PageTracker::new(
                        scan_view.identity().clone(),
                        page.next().map(|c| c.stream().clone()).unwrap_or_else(|| {
                            ResourceId::new("unsafe-chat-catalog").expect("constant")
                        }),
                        max_records,
                    )
                });
                tracker.accept(cursor.as_ref(), &page)?;
                for record in page.items() {
                    check_available(&scan_cancel, deadline)?;
                    bytes = bytes
                        .checked_add(
                            cdb_core::record_codec::encode_record(record, Limits::default())?.len(),
                        )
                        .ok_or_else(Error::limit)?;
                    if bytes > 16 * 1024 * 1024 {
                        return Err(Error::limit());
                    }
                    if let ExportRecord::Claim(claim) = record {
                        if claim.transaction_time() <= captured.as_of {
                            records.push(record.clone());
                        }
                    }
                }
                cursor = page.next().cloned();
                if cursor.is_none() {
                    break;
                }
            }
            tracker
                .ok_or_else(|| Error::invalid("missing scan"))?
                .finish()?;
            let ids = records
                .iter()
                .filter_map(|r| r.claim().map(|c| c.id().clone()))
                .collect();
            Ok((semantic_landing_entries(&records)?, ids))
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "projection catalog task failed"))??;
        check_available(&cancel, deadline)?;
        let catalog = Arc::new(DirectCatalog {
            identity: view.identity().clone(),
            entries: entries.0,
        });
        let provider = DirectProvider {
            view: Arc::new(DirectView {
                view,
                claims: entries.1,
            }),
            catalog,
        };
        Ok(ChatGraphHost::Unsafe(Box::new(Self {
            control,
            config,
            profile,
            capture: capture_dual_execution(captured, control_pin),
            provider,
            limits,
            deadline,
        })))
    }

    async fn execute(
        &self,
        inline: &[u8],
        cancellation: Arc<AtomicBool>,
        limits: GraphQueryLimits,
        inventory: bool,
    ) -> Result<std::result::Result<AuthorizedQuery, GraphQueryDiagnostic>> {
        let mut capabilities = graph_query_compiler_capabilities();
        // Raw projection claims are not the original RDF data-quads used by
        // semantic mapped fields. Fail explicitly rather than invent equivalence.
        capabilities.mappings.stored_predicate = false;
        let draft = compile_with_compiler_capabilities(
            QuerySource::inline(inline),
            self.profile
                .as_ref()
                .map(|(selector, artifact)| SelectedProfile { selector, artifact }),
            &self.config,
            CompileOptions::default(),
            capabilities,
        )?;
        if draft
            .requested_as_of()
            .is_some_and(|t| t != self.capture.snapshot().as_of)
        {
            return Err(Error::new(ErrorKind::Snapshot, "query snapshot is fixed"));
        }
        let options = ExecutionOptions {
            limits: if inventory {
                Limits::new(
                    16 * 1024 * 1024,
                    64,
                    1_000_000,
                    32_000_000,
                    16 * 1024 * 1024,
                )?
            } else {
                Limits::default()
            },
            deadline: Some(self.deadline.min(Instant::now() + limits.timeout)),
            cancellation: Some(cancellation),
            max_work: limits.max_work,
            max_records: 10_000.min(limits.max_work),
            max_retained_bytes: 16 * 1024 * 1024,
            max_paths: limits.max_claims.saturating_add(1),
            max_frontier: limits.max_nodes.saturating_add(1),
            ..Default::default()
        };
        let staged = stage_captured_for_publication(
            draft,
            self.control.as_ref(),
            &UnsafeGraphPolicy,
            &(),
            &self.capture,
            &self.provider,
            options.clone(),
        )
        .await?;
        if staged.has_result_truncation() {
            return Ok(Err(GraphQueryDiagnostic::Incomplete));
        }
        let bytes = publish_staged(staged, &UnsafeGraphPolicy, &(), &options).await?;
        if bytes.len() > limits.max_response_bytes {
            return Ok(Err(GraphQueryDiagnostic::Capacity));
        }
        let value = V::parse(&bytes, options.limits)?;
        let claims = value.field("claims")?.as_array()?;
        if claims.len() > limits.max_claims {
            return Ok(Err(GraphQueryDiagnostic::QueryTooBroad { cap: "claims" }));
        }
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
        if identities.len() > limits.max_nodes {
            return Ok(Err(GraphQueryDiagnostic::QueryTooBroad { cap: "nodes" }));
        }
        let mut labels = BTreeMap::<String, Vec<AuthorizedLabel>>::new();
        for entry in &self.provider.catalog.entries {
            if identities.contains(entry.id.as_str()) {
                if let Some(label) = &entry.label {
                    let supports = entry
                        .dependencies
                        .iter()
                        .map(|s| s.as_str().to_owned())
                        .collect::<Vec<_>>();
                    dependencies.extend(supports.clone());
                    labels
                        .entry(entry.id.as_str().to_owned())
                        .or_default()
                        .push(AuthorizedLabel {
                            value: label.clone(),
                            dependencies: supports,
                        });
                }
            }
        }
        options.check_interrupted()?;
        Ok(Ok(AuthorizedQuery {
            dependencies,
            response: value,
            labels,
            snapshot: self.capture.snapshot().snapshot.clone(),
            query_config: self.config.reference().clone(),
            profile: self
                .profile
                .as_ref()
                .map(|(s, a)| (s.clone(), a.reference().clone())),
        }))
    }
}

// Deliberately private and reachable only through the explicit unsafe branch.
struct UnsafeGraphPolicy;
impl PolicyService for UnsafeGraphPolicy {
    type Principal = ();
    type Context = ();
    fn current<'a>(&'a self, _: &'a ()) -> IoFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn resource_allowed(&self, _: &(), _: &ResourceId) -> Result<bool> {
        Ok(true)
    }
    fn fact_allowed(&self, _: &(), _: &ResourceId, _: &Iri) -> Result<bool> {
        Ok(true)
    }
    fn publish<'a>(
        &'a self,
        _: &'a (),
        _: &'a (),
        sink: &'a mut (dyn FnMut() -> Result<()> + Send),
    ) -> IoFuture<'a, ()> {
        Box::pin(async move { sink() })
    }
}
struct DirectView {
    view: Arc<GenerationView>,
    claims: BTreeSet<ClaimId>,
}
impl RawQueryView for DirectView {
    fn identity(&self) -> &SnapshotRef {
        self.view.identity()
    }
    fn claim(&self, id: &ClaimId) -> Result<Option<AdmittedClaim>> {
        self.view.claim(id)
    }
    fn claim_is_pre_authorized(&self, id: &ClaimId) -> bool {
        self.claims.contains(id)
    }
    fn entity(&self, id: &EntityId) -> Result<Option<Vec<DependencyRecord>>> {
        self.view.entity(id)
    }
    fn incident(
        &self,
        id: &EntityId,
        d: Direction,
        s: PageSize,
        c: Option<&PageCursor>,
    ) -> Result<Page<AdmittedClaim>> {
        self.view.incident(id, d, s, c)
    }
    fn resource(&self, id: &ResourceId) -> Result<Option<DependencyRecord>> {
        self.view.resource(id)
    }
    fn lifecycle(
        &self,
        id: &ClaimId,
        s: PageSize,
        c: Option<&PageCursor>,
    ) -> Result<Page<ExportRecord>> {
        self.view.lifecycle(id, s, c)
    }
}
struct DirectCatalog {
    identity: SnapshotRef,
    entries: Vec<LandingEntry>,
}
impl LandingCatalog for DirectCatalog {
    fn identity(&self) -> &SnapshotRef {
        &self.identity
    }
    fn entries(&self) -> &[LandingEntry] {
        &self.entries
    }
    fn entries_are_authorized(&self) -> bool {
        true
    }
}
struct DirectProvider {
    view: Arc<DirectView>,
    catalog: Arc<DirectCatalog>,
}
impl ViewProvider for DirectProvider {
    fn propose_stale<'a>(
        &'a self,
        _: &'a CapturedSnapshot,
        _: &'a ExecutionOptions,
    ) -> IoFuture<'a, Option<SnapshotRef>> {
        Box::pin(async { Ok(None) })
    }
    fn open<'a>(
        &'a self,
        c: &'a CapturedSnapshot,
        o: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        Box::pin(async move {
            o.check_interrupted()?;
            if self.view.identity() != &c.snapshot {
                return Err(Error::new(ErrorKind::Snapshot, "exact projection required"));
            }
            if self.catalog.entries.len() > o.max_records {
                return Err(Error::limit());
            }
            Ok(PreparedView {
                view: self.view.clone(),
                landing: self.catalog.clone(),
            })
        })
    }
}
