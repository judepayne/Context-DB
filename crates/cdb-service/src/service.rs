//! One authenticated owner. Final native sinks enqueue complete bounded buffers, never sockets.
#[cfg(test)]
mod p5_5_tests;
mod preparation;
pub(crate) mod semantic_interpretation;
use crate::{
    auth::{self, AuthStore, SessionLease},
    broker::startup::{self, AdapterCatalog},
    config::{
        create_secret_file, BoundedFileRead, CredentialEntry, CredentialTable, InstanceConfig,
    },
    runtime::NativeRuntime,
    sources::{AuthorizedSources, SourceStore},
};
use cdb_backend_fluree::{
    policy::{FlureePolicyContext, FlureePrincipal, PolicyState},
    runs::{ExternalPublicationFence, Operation, ProtectedRun},
    semantic_policy::{verify_semantic_authority_current, SemanticPolicyBasis, SemanticPolicyMode},
    FlureeBackend, FlureeSemanticLedger,
};
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    contracts::*,
    id::*,
    recording::{PolicyObservation, ReplayDataInput, RunEnvelope},
    snapshot::{ProjectionCheckpoint, SnapshotRef},
    CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use cdb_engine::{
    artifacts::ArtifactKind,
    compiler::{compile, QuerySource, SelectedProfile},
    execution::{self, Consistency, ExecutionOptions, PreparedView, ViewProvider},
    frontend,
    options::CompileOptions,
};
use cdb_projection_redb::{
    Coordinator, CoordinatorOptions, GenerationOptions, RedbProjection, RedbViewProvider,
};
pub use preparation::{PreparationRequest, PreparedExecution};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    time::Instant,
};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};
fn denied() -> Error {
    Error::new(ErrorKind::Denied, "service access denied")
}
fn native<T>(r: cdb_backend_fluree::NativeResult<T>) -> Result<T> {
    r.map_err(|e| match e.downcast::<Error>() {
        Ok(e) => *e,
        Err(_) => Error::new(ErrorKind::Backend, "authority operation failed"),
    })
}
fn obj<const N: usize>(p: [(&str, V); N]) -> V {
    V::Object(p.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn bounded(v: V, cap: usize) -> Result<Vec<u8>> {
    let b = v.canonical_bytes(Limits::default())?;
    if b.len() > cap {
        Err(Error::limit())
    } else {
        Ok(b)
    }
}
#[derive(Clone)]
struct SemanticFenceCheck {
    check: Arc<dyn Fn() -> Result<()> + Send + Sync>,
}
impl SemanticFenceCheck {
    fn current(ledger: Arc<FlureeSemanticLedger>, basis: SemanticPolicyBasis) -> Self {
        Self {
            check: Arc::new(move || {
                let ledger = ledger.clone();
                let basis = basis.clone();
                std::thread::scope(|scope| {
                    scope
                        .spawn(move || {
                            tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .map_err(|_| {
                                    Error::new(
                                        ErrorKind::Backend,
                                        "semantic fence runtime unavailable",
                                    )
                                })?
                                .block_on(async move {
                                    verify_semantic_authority_current(&ledger, &basis)
                                        .await
                                        .map_err(|reason| Error::new(ErrorKind::Denied, reason))
                                })
                        })
                        .join()
                        .map_err(|_| {
                            Error::new(ErrorKind::Backend, "semantic fence worker stopped")
                        })?
                })
            }),
        }
    }

    #[cfg(test)]
    fn test(check: impl Fn() -> Result<()> + Send + Sync + 'static) -> Self {
        Self {
            check: Arc::new(check),
        }
    }

    fn check(&self) -> Result<()> {
        (self.check)()
    }
}
struct Fence {
    lease: SessionLease,
    _permit: OwnedSemaphorePermit,
    options: ExecutionOptions,
    semantic: Option<SemanticFenceCheck>,
}
impl ExternalPublicationFence for Fence {
    fn check(&self) -> Result<()> {
        self.lease.check().map_err(|_| denied())?;
        self.options.check_interrupted()?;
        if let Some(semantic) = &self.semantic {
            semantic.check()?;
        }
        Ok(())
    }
}
struct CallerDrop(Arc<AtomicBool>);
impl Drop for CallerDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
type Sources = AuthorizedSources<FlureeBackend, FlureeBackend>;
struct Provider {
    raw: RedbViewProvider,
    sources: Sources,
    control_capture: Option<SnapshotRef>,
}
impl ViewProvider for Provider {
    fn open<'a>(
        &'a self,
        c: &'a CapturedSnapshot,
        o: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        Box::pin(async move {
            self.sources
                .bind_snapshot(self.control_capture.as_ref().unwrap_or(&c.snapshot))?;
            self.raw.open(c, o).await
        })
    }
    fn propose_stale<'a>(
        &'a self,
        c: &'a CapturedSnapshot,
        o: &'a ExecutionOptions,
    ) -> IoFuture<'a, Option<SnapshotRef>> {
        self.raw.propose_stale(c, o)
    }
    fn evidence_reader(&self) -> Option<&dyn SourceReader> {
        Some(&self.sources)
    }
    fn evidence_footprint(&self) -> Result<Vec<PolicyObservation>> {
        self.sources.footprint()
    }
}
pub struct Service {
    config: InstanceConfig,
    backend: Arc<FlureeBackend>,
    semantic: Option<Arc<FlureeSemanticLedger>>,
    projection: Arc<RedbProjection>,
    coordinator: Arc<Coordinator>,
    auth: AuthStore,
    sources: Arc<SourceStore>,
    permits: Arc<Semaphore>,
    executor: startup::ExecutorSettings,
    runtime: Option<Arc<NativeRuntime>>,
    resolved_providers: Vec<startup::ResolvedProvider>,
    native_runs: Mutex<BTreeMap<String, Weak<tokio::sync::Mutex<()>>>>,
}
fn binding(pin: SnapshotRef, semantic: bool) -> Result<ProjectionCheckpoint> {
    ProjectionCheckpoint::new(
        pin,
        VersionId::new(if semantic {
            "ctxql-semantic-rdf/v1"
        } else {
            "ctxql-projection/v1"
        })?,
        VersionId::new("live")?,
        Iri::new(if semantic {
            "urn:ctxql:semantic-projection:v1"
        } else {
            "urn:p3:raw"
        })?,
    )
}
impl Service {
    pub fn config(&self) -> &InstanceConfig {
        &self.config
    }
    /// Resolved non-secret runtime controls; excluded from semantic plan hashes.
    pub fn executor_settings(&self) -> &startup::ExecutorSettings {
        &self.executor
    }
    pub fn resolved_providers(&self) -> &[startup::ResolvedProvider] {
        &self.resolved_providers
    }
    pub async fn open(config: InstanceConfig) -> Result<Arc<Self>> {
        Self::open_with_adapters(config, &AdapterCatalog::default()).await
    }
    /// Native embedders may supply only explicitly registered implementations.
    /// The CLI/HTTP owner uses the same path with no implicit native plugins.
    pub async fn open_with_adapters(
        config: InstanceConfig,
        adapters: &AdapterCatalog,
    ) -> Result<Arc<Self>> {
        config.validate_runtime()?;
        let backend = Arc::new(native(
            FlureeBackend::open(config.authority_options()?).await,
        )?);
        let auth = CredentialTable::load(&config.credential_file)?
            .auth_store(config.limits.session_ttl())?;
        if matches!(
            config.schema.as_str(),
            "ctxql-instance/v3" | "ctxql-instance/v4"
        ) {
            let (path, options) = config.semantic_binding()?;
            let semantic = Arc::new(FlureeSemanticLedger::open_file(path, options).await?);
            let pin = SemanticProjectionSource::head(semantic.as_ref()).await?;
            let projection = Arc::new(
                RedbProjection::open(
                    &config.projection,
                    binding(pin, true)?,
                    GenerationOptions::default(),
                )
                .await?,
            );
            return Self::attach_roles(config, backend, Some(semantic), projection, auth, adapters)
                .await;
        }
        let pin = GraphBackend::head(backend.as_ref()).await?;
        let projection = Arc::new(
            RedbProjection::open(
                &config.projection,
                binding(pin, false)?,
                GenerationOptions::default(),
            )
            .await?,
        );
        Self::attach_roles(config, backend, None, projection, auth, adapters).await
    }
    pub async fn attach(
        config: InstanceConfig,
        backend: Arc<FlureeBackend>,
        projection: Arc<RedbProjection>,
        auth: AuthStore,
    ) -> Result<Arc<Self>> {
        Self::attach_with_adapters(
            config,
            backend,
            projection,
            auth,
            &AdapterCatalog::default(),
        )
        .await
    }
    pub async fn attach_with_adapters(
        config: InstanceConfig,
        backend: Arc<FlureeBackend>,
        projection: Arc<RedbProjection>,
        auth: AuthStore,
        adapters: &AdapterCatalog,
    ) -> Result<Arc<Self>> {
        config.validate_runtime()?;
        if matches!(
            config.schema.as_str(),
            "ctxql-instance/v3" | "ctxql-instance/v4"
        ) {
            return Err(Error::new(
                ErrorKind::Invalid,
                "v3 attachment requires an explicit semantic ledger",
            ));
        }
        Self::attach_roles(config, backend, None, projection, auth, adapters).await
    }

    async fn attach_roles(
        config: InstanceConfig,
        backend: Arc<FlureeBackend>,
        semantic: Option<Arc<FlureeSemanticLedger>>,
        projection: Arc<RedbProjection>,
        auth: AuthStore,
        adapters: &AdapterCatalog,
    ) -> Result<Arc<Self>> {
        let startup = startup::build_with_auth(&config, adapters, auth.clone())
            .map_err(|_| Error::invalid("service runtime configuration failed"))?;
        let runtime = if matches!(
            config.schema.as_str(),
            "ctxql-instance/v2" | "ctxql-instance/v3" | "ctxql-instance/v4"
        ) {
            Some(Arc::new(NativeRuntime::new(
                startup.broker,
                startup.executor.clone(),
            )?))
        } else {
            None
        };
        let control_pin = GraphBackend::head(backend.as_ref()).await?;
        let control = config.authority_options()?;
        if control_pin.backend() != &control.backend
            || control_pin.pin().authority() != &control.authority
            || control_pin.pin().graph() != &control.graph
        {
            return Err(denied());
        }
        let semantic_mode = semantic.is_some();
        let pin = match &semantic {
            Some(semantic) => SemanticProjectionSource::head(semantic.as_ref()).await?,
            None => control_pin,
        };
        let expected = config.projection_binding()?;
        if pin.backend() != &expected.backend
            || pin.pin().authority() != &expected.authority
            || pin.pin().graph() != &expected.graph
        {
            return Err(denied());
        }
        let cp = projection.checkpoint().await?;
        if cp
            .as_ref()
            .is_some_and(|c| !c.snapshot().same_authority(&pin))
        {
            return Err(denied());
        }
        let sources = Arc::new(SourceStore::open(
            config.source_root.clone(),
            config.limits.run_bytes,
        )?);
        // Opening an exact generation also verifies the persisted binding when empty/live differs.
        let projection_binding = binding(pin.clone(), semantic_mode)?;
        let coordinator = if let Some(semantic) = &semantic {
            Arc::new(Coordinator::start(
                semantic.clone(),
                projection.clone(),
                projection_binding,
                CoordinatorOptions::default(),
            )?)
        } else {
            let projection_source = Arc::new(GraphBackendProjectionSource::new(
                backend.clone(),
                projection_binding.schema().clone(),
                projection_binding.algorithm().clone(),
            ));
            Arc::new(Coordinator::start(
                projection_source,
                projection.clone(),
                projection_binding,
                CoordinatorOptions::default(),
            )?)
        };
        if let Err(error) = coordinator
            .wait_exact(&pin, tokio::time::Instant::now() + config.limits.deadline())
            .await
        {
            coordinator.shutdown_shared().await?;
            return Err(error);
        }
        let permits = Arc::new(Semaphore::new(config.limits.concurrency));
        Ok(Arc::new(Self {
            config,
            backend,
            semantic,
            projection,
            coordinator,
            auth,
            sources,
            permits,
            executor: startup.executor,
            runtime,
            resolved_providers: startup.providers,
            native_runs: Mutex::new(BTreeMap::new()),
        }))
    }
    pub async fn initialize(
        config: InstanceConfig,
        principal: PrincipalId,
        secret_path: PathBuf,
    ) -> Result<()> {
        config.validate_runtime()?;
        // A v3 semantic ledger is deployment-owned and must already exist. Open it
        // read-only before creating any control state, then bind the projection to
        // its exact head. Initialization never creates or publishes semantic data.
        let semantic_pin = if matches!(
            config.schema.as_str(),
            "ctxql-instance/v3" | "ctxql-instance/v4"
        ) {
            let (path, options) = config.semantic_binding()?;
            let semantic = FlureeSemanticLedger::open_file(path, options).await?;
            Some(SemanticProjectionSource::head(&semantic).await?)
        } else {
            None
        };
        let backend = native(FlureeBackend::create(config.authority_options()?).await)?;
        backend.bootstrap_governance().await?;
        let mut state = PolicyState::deny_all()?;
        state.policy=cdb_core::policy::PolicySet::parse(br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{"@id":"https://ctxql.org/policies/serviceReader","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceReader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}]}"#,Limits::default())?;
        Self::add_principal(&backend, &mut state, principal.clone(), true).await?;
        let control_pin = GraphBackend::head(&backend).await?;
        let (pin, semantic_mode) = match semantic_pin {
            Some(pin) => (pin, true),
            None => (control_pin, false),
        };
        RedbProjection::create(
            &config.projection,
            binding(pin, semantic_mode)?,
            GenerationOptions::default(),
        )
        .await?;
        private_dir(&config.source_root)?;
        let (secret, entry) = credential(principal)?;
        create_secret_file(&secret_path, secret.as_bytes())?;
        CredentialTable {
            schema: "ctxql-credentials/v1".into(),
            entries: vec![entry],
        }
        .write_new(&config.credential_file)?;
        Ok(())
    }
    pub async fn provision(
        config: InstanceConfig,
        principal: PrincipalId,
        secret_path: PathBuf,
        admin: bool,
    ) -> Result<()> {
        config.validate_runtime()?;
        // Exclusive authority ownership comes before every credential write. No online reload.
        let backend = native(FlureeBackend::open(config.authority_options()?).await)?;
        let before = BoundedFileRead::new(1024 * 1024, true)?.read(&config.credential_file)?;
        let mut table = CredentialTable::parse(&before)?;
        let mut state = native(backend.policy_state().await)?;
        Self::add_principal(&backend, &mut state, principal.clone(), admin).await?;
        let (secret, entry) = credential(principal)?;
        table.entries.push(entry);
        table.auth_store(config.limits.session_ttl())?;
        create_secret_file(&secret_path, secret.as_bytes())?;
        let suffix = ContentHash::of_bytes(secret.as_bytes());
        let backup = config
            .credential_file
            .with_extension(format!("backup-{}", &suffix.as_str()[7..]));
        let replacement = config
            .credential_file
            .with_extension(format!("next-{}", &suffix.as_str()[7..]));
        create_secret_file(&backup, &before)?;
        table.write_new(&replacement)?;
        if BoundedFileRead::new(1024 * 1024, true)?.read(&config.credential_file)? != before {
            return Err(Error::new(
                ErrorKind::Conflict,
                "credential before-image changed",
            ));
        }
        std::fs::rename(&replacement, &config.credential_file)
            .map_err(|_| Error::new(ErrorKind::Backend, "credential replacement failed"))?;
        Ok(())
    }
    async fn add_principal(
        backend: &FlureeBackend,
        state: &mut PolicyState,
        id: PrincipalId,
        admin: bool,
    ) -> Result<()> {
        let entry = state
            .principals
            .entry(id.clone())
            .or_insert_with(|| (true, Default::default()));
        entry.0 = true;
        for op in [Operation::Query, Operation::Read, Operation::Replay] {
            entry.1.insert(Iri::new(op.role())?);
        }
        entry
            .1
            .insert(Iri::new("https://ctxql.org/roles/serviceReader")?);
        if admin {
            entry.1.insert(Iri::new(Operation::Admin.role())?);
        }
        let key = IdempotencyKey::new(format!(
            "service-provision:{}:{}:{admin}",
            native(backend.head().await)?.pin().revision().as_str(),
            ContentHash::of_bytes(id.as_str().as_bytes()).as_str()
        ))?;
        native(backend.set_policy_state(&key, state).await)?;
        Ok(())
    }
    pub(crate) async fn set_graph_query_access_for_fixture(&self, allowed: bool) -> Result<()> {
        let mut state = native(self.backend.policy_state().await)?;
        let principal = PrincipalId::new(
            cdb_backend_fluree::official_bootstrap::ACQUISITION_V2_FIXTURE_PRINCIPAL,
        )?;
        let (_, roles) = state.principals.get_mut(&principal).ok_or_else(denied)?;
        let role = Iri::new(Operation::Query.role())?;
        // The hermetic owner is normally an administrator; remove its bypass
        // too while retaining Read/Replay and source-reader roles.
        let admin = Iri::new(Operation::Admin.role())?;
        if allowed {
            roles.insert(role);
            roles.insert(admin);
        } else {
            roles.remove(&role);
            roles.remove(&admin);
        }
        let head = GraphBackend::head(self.backend.as_ref()).await?;
        let key = IdempotencyKey::new(format!(
            "fixture-query-access:{}:{allowed}",
            head.pin().revision().as_str()
        ))?;
        native(self.backend.set_policy_state(&key, &state).await)?;
        Ok(())
    }

    pub(crate) async fn revoke_source_access_for_fixture(&self) -> Result<()> {
        let mut state = native(self.backend.policy_state().await)?;
        let principal = PrincipalId::new(
            cdb_backend_fluree::official_bootstrap::ACQUISITION_V2_FIXTURE_PRINCIPAL,
        )?;
        let (_, roles) = state.principals.get_mut(&principal).ok_or_else(denied)?;
        roles.remove(&Iri::new("https://ctxql.org/roles/serviceReader")?);
        let head = GraphBackend::head(self.backend.as_ref()).await?;
        let key = IdempotencyKey::new(format!(
            "fixture-revoke-source:{}:{}",
            head.pin().revision().as_str(),
            &ContentHash::of_bytes(b"source-access-revoked").as_str()[7..]
        ))?;
        native(self.backend.set_policy_state(&key, &state).await)?;
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.auth.stop_admitting();
        self.permits.close();
        let runtime_result = if let Some(runtime) = &self.runtime {
            runtime.shutdown().await
        } else {
            Ok(())
        };
        self.auth.shutdown().await;
        let coordinator_result = self.coordinator.shutdown_shared().await;
        runtime_result.and(coordinator_result)
    }
    fn provider(
        &self,
        principal: FlureePrincipal,
        control_capture: Option<SnapshotRef>,
    ) -> Result<Provider> {
        Ok(Provider {
            raw: RedbViewProvider::new(
                self.coordinator.clone(),
                self.projection.clone(),
                self.config.limits.deadline(),
            )?,
            sources: Sources::new(
                self.backend.clone(),
                self.backend.clone(),
                Arc::new(principal),
                self.sources.clone(),
            ),
            control_capture,
        })
    }
    pub async fn dispatch(
        self: &Arc<Self>,
        token: &str,
        request: &[u8],
        cancel: Arc<AtomicBool>,
    ) -> Result<Vec<u8>> {
        Box::pin(self.dispatch_inner(token, request, cancel)).await
    }
    async fn dispatch_inner(
        self: &Arc<Self>,
        token: &str,
        request: &[u8],
        cancel: Arc<AtomicBool>,
    ) -> Result<Vec<u8>> {
        let _drop = CallerDrop(cancel.clone());
        let options = ExecutionOptions {
            deadline: Some(Instant::now() + self.config.limits.deadline()),
            cancellation: Some(cancel.clone()),
            max_retained_bytes: self.config.limits.run_bytes,
            max_records: self.config.limits.trace_entries,
            max_work: self.config.limits.max_work,
            ..Default::default()
        };
        let session = self.auth.authenticate(token).await.map_err(|_| denied())?;
        let id = self.auth.principal(&session).await.map_err(|_| denied())?;
        let principal =
            native(self.backend.issue_principal(id.clone()).await).map_err(|_| denied())?;
        options.check_interrupted()?;
        if request.len() > self.config.limits.max_body_bytes {
            return Err(Error::limit());
        }
        let v = V::parse(request, Limits::default())?;
        if v.field("schema")?.as_str()? != "ctxql-service/v1" {
            return Err(Error::invalid("service schema"));
        }
        let op = match v.field("op")?.as_str()? {
            "query" => Operation::Query,
            "publish" => Operation::Publish,
            "replay" => Operation::Replay,
            "run" | "status" | "source" => Operation::Read,
            _ => return Err(Error::invalid("service operation")),
        };
        let aop = match op {
            Operation::Query => auth::Operation::Query,
            Operation::Read => auth::Operation::Read,
            Operation::Replay => auth::Operation::Replay,
            Operation::Publish => auth::Operation::Publish,
            Operation::Admin => auth::Operation::Admin,
        };
        let context = self.backend.current(&principal).await?;
        self.backend.require_operation(&context, op)?;
        if op == Operation::Query
            && v.as_object()?.get("execution").map(V::as_str).transpose()? == Some("native_v3")
        {
            let service = self.clone();
            let token = token.to_owned();
            let request = v.clone();
            return preparation::run_native(
                async move {
                    service
                        .dispatch_native_v3(&token, &request, cancel, principal, id)
                        .await
                },
                "ctxql-query-v3",
            )
            .await;
        }
        if matches!(v.field("op")?.as_str()?, "run" | "replay") {
            let run_id = RunId::new(v.field("run_id")?.as_str()?)?;
            let protected = preparation::run_native(
                {
                    let backend = self.backend.clone();
                    let principal = principal.clone();
                    let context = context.clone();
                    let run_id = run_id.clone();
                    async move {
                        backend
                            .guarded_find_versioned_run(&principal, &context, &run_id, op)
                            .await
                    }
                },
                "ctxql-read-v3",
            )
            .await?;
            if let Some(ProtectedRun::V3(run)) = protected.clone() {
                v.closed(
                    &["schema", "op", "run_id"],
                    if op == Operation::Replay {
                        &["hydrate"]
                    } else {
                        &[]
                    },
                )?;
                if op == Operation::Read {
                    let lease = self
                        .auth
                        .lease(&session, auth::Operation::Read)
                        .await
                        .map_err(|_| denied())?;
                    let permit = self
                        .permits
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| Error::limit())?;
                    let bytes = bounded(
                        obj([
                            ("schema", V::string("ctxql-service/v1")),
                            (
                                "response",
                                obj([
                                    ("run_id", V::string(run.id().as_str())),
                                    (
                                        "response_hash",
                                        V::string(run.replay().data().response_hash.as_str()),
                                    ),
                                    (
                                        "snapshot",
                                        cdb_core::record_codec::snapshot_value(
                                            &run.replay().data().snapshot,
                                        ),
                                    ),
                                ]),
                            ),
                        ]),
                        self.config.limits.run_bytes,
                    )?;
                    let fence = Box::new(Fence {
                        lease,
                        _permit: permit,
                        options: options.clone(),
                        semantic: None,
                    });
                    let (tx, rx) = oneshot::channel();
                    self.backend
                        .clone()
                        .guarded_owned_release_v3(
                            principal,
                            Operation::Read,
                            run,
                            fence,
                            move || tx.send(bytes).map_err(|_| denied()),
                        )
                        .await?;
                    return rx.await.map_err(|_| denied());
                }
                let gate = self.native_run_gate(&run_id);
                let _run_owner = gate.lock_owned().await;
                let replay_snapshot = run.replay().data().snapshot.clone();
                let replay_run_id = run.id().clone();
                let release_run = run;
                let replayed = preparation::run_native(
                    {
                        let service = self.clone();
                        let token = token.to_owned();
                        let cancellation = cancel.clone();
                        async move {
                            service
                                .execute_replay(&token, replay_run_id, cancellation, false)
                                .await
                        }
                    },
                    "ctxql-replay-prepare-v3",
                )
                .await?;
                let mut response = V::parse(&replayed.response, options.limits)?;
                if v.as_object()?
                    .get("hydrate")
                    .map(V::as_bool)
                    .transpose()?
                    .unwrap_or(false)
                {
                    let provider = self.provider(principal.clone(), Some(replay_snapshot))?;
                    provider
                        .sources
                        .bind_snapshot(provider.control_capture.as_ref().ok_or_else(denied)?)?;
                    let evidence = hydrate(
                        &replayed.sources,
                        &provider.sources,
                        self.config.limits.run_bytes,
                    )
                    .await?;
                    let V::Object(fields) = &mut response else {
                        return Err(Error::invalid("replay response object"));
                    };
                    fields.insert("evidence".into(), V::Array(evidence));
                }
                let bytes = bounded(
                    obj([
                        ("schema", V::string("ctxql-service/v1")),
                        ("response", response),
                    ]),
                    self.config.limits.run_bytes,
                )?;
                let lease = self
                    .auth
                    .lease(&session, auth::Operation::Replay)
                    .await
                    .map_err(|_| denied())?;
                let permit = self
                    .permits
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| Error::limit())?;
                let fence = Box::new(Fence {
                    lease,
                    _permit: permit,
                    options: options.clone(),
                    semantic: None,
                });
                let (tx, rx) = oneshot::channel();
                self.backend
                    .clone()
                    .guarded_owned_release_v3(
                        principal,
                        Operation::Replay,
                        release_run,
                        fence,
                        move || tx.send(bytes).map_err(|_| denied()),
                    )
                    .await?;
                return rx.await.map_err(|_| denied());
            }
            if matches!(protected, Some(ProtectedRun::V4(_))) {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    cdb_backend_fluree::backend_identity::HISTORICAL_EXECUTOR_UNAVAILABLE,
                ));
            }
            if let Some(ProtectedRun::V5(run)) = protected {
                v.closed(
                    &["schema", "op", "run_id"],
                    if op == Operation::Replay {
                        &["hydrate"]
                    } else {
                        &[]
                    },
                )?;
                if op == Operation::Replay {
                    let gate = self.native_run_gate(&run_id);
                    let _run_owner = gate.lock_owned().await;
                    let replay_snapshot = run.replay().control_capture().clone();
                    let replay_run_id = run.id().clone();
                    let release_run = run;
                    let semantic = self.semantic_fence_for_run(&release_run)?;
                    semantic.check()?;
                    let replayed = preparation::run_native(
                        {
                            let service = self.clone();
                            let token = token.to_owned();
                            let cancellation = cancel.clone();
                            async move {
                                service
                                    .execute_replay(&token, replay_run_id, cancellation, true)
                                    .await
                            }
                        },
                        "ctxql-replay-prepare-v5",
                    )
                    .await?;
                    let mut response = V::parse(&replayed.response, options.limits)?;
                    if v.as_object()?
                        .get("hydrate")
                        .map(V::as_bool)
                        .transpose()?
                        .unwrap_or(false)
                    {
                        let provider = self.provider(principal.clone(), Some(replay_snapshot))?;
                        provider
                            .sources
                            .bind_snapshot(provider.control_capture.as_ref().ok_or_else(denied)?)?;
                        let evidence = hydrate(
                            &replayed.sources,
                            &provider.sources,
                            self.config.limits.run_bytes,
                        )
                        .await?;
                        let V::Object(fields) = &mut response else {
                            return Err(Error::invalid("replay response object"));
                        };
                        fields.insert("evidence".into(), V::Array(evidence));
                    }
                    semantic.check()?;
                    let bytes = bounded(
                        obj([
                            ("schema", V::string("ctxql-service/v1")),
                            ("response", response),
                        ]),
                        self.config.limits.run_bytes,
                    )?;
                    let lease = self
                        .auth
                        .lease(&session, auth::Operation::Replay)
                        .await
                        .map_err(|_| denied())?;
                    let permit = self
                        .permits
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| Error::limit())?;
                    let fence = Box::new(Fence {
                        lease,
                        _permit: permit,
                        options: options.clone(),
                        semantic: Some(semantic),
                    });
                    let (tx, rx) = oneshot::channel();
                    self.backend
                        .clone()
                        .guarded_owned_release_v5(
                            principal,
                            Operation::Replay,
                            release_run,
                            fence,
                            move || tx.send(bytes).map_err(|_| denied()),
                        )
                        .await?;
                    return rx.await.map_err(|_| denied());
                }
                self.verify_recorded_semantic_current(&run).await?;
                let base = run.replay().base().data();
                let bytes = bounded(
                    obj([
                        ("schema", V::string("ctxql-service/v1")),
                        (
                            "response",
                            obj([
                                ("run_id", V::string(run.id().as_str())),
                                ("response_hash", V::string(base.response_hash.as_str())),
                                (
                                    "snapshot",
                                    cdb_core::record_codec::snapshot_value(&base.snapshot),
                                ),
                            ]),
                        ),
                    ]),
                    self.config.limits.run_bytes,
                )?;
                let lease = self
                    .auth
                    .lease(&session, auth::Operation::Read)
                    .await
                    .map_err(|_| denied())?;
                let permit = self
                    .permits
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| Error::limit())?;
                let semantic = self.semantic_fence_for_run(&run)?;
                let fence = Box::new(Fence {
                    lease,
                    _permit: permit,
                    options: options.clone(),
                    semantic: Some(semantic),
                });
                let (tx, rx) = oneshot::channel();
                self.backend
                    .clone()
                    .guarded_owned_release_v5(principal, Operation::Read, run, fence, move || {
                        tx.send(bytes).map_err(|_| denied())
                    })
                    .await?;
                return rx.await.map_err(|_| denied());
            }
        }
        let lease = self.auth.lease(&session, aop).await.map_err(|_| denied())?;
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::limit())?;
        let fence = Box::new(Fence {
            lease,
            _permit: permit,
            options: options.clone(),
            semantic: None,
        });
        let (tx, rx) = oneshot::channel();
        let cap = self.config.limits.run_bytes;
        match v.field("op")?.as_str()? {
            "publish" => {
                v.closed(&["schema", "op", "artifact", "content"], &[])?;
                let artifact = PublishedArtifact::new(
                    ArtifactRef::from_value(v.field("artifact")?)?,
                    v.field("content")?.as_str()?.as_bytes().to_vec(),
                    options.limits,
                )?;
                self.backend
                    .clone()
                    .guarded_owned_publish(principal, context, artifact, fence, move |r, p| {
                        let bytes = bounded(
                            obj([
                                ("schema", V::string("ctxql-service/v1")),
                                ("artifact", r.projection()),
                                (
                                    "recording_snapshot",
                                    cdb_core::record_codec::snapshot_value(p),
                                ),
                            ]),
                            cap,
                        )?;
                        tx.send(bytes).map_err(|_| denied())
                    })
                    .await?;
            }
            "query" => {
                v.closed(
                    &["schema", "op", "run_id", "query"],
                    &["config", "profile", "consistency", "execution"],
                )?;
                if v.as_object()?.contains_key("execution") {
                    return Err(Error::invalid("execution mode"));
                }
                let consistency_name = match v
                    .as_object()?
                    .get("consistency")
                    .map(V::as_str)
                    .transpose()?
                    .unwrap_or("exact")
                {
                    "exact" => "exact",
                    "allow_stale" => "allow_stale",
                    _ => return Err(Error::invalid("consistency")),
                };
                let run_id = RunId::new(v.field("run_id")?.as_str()?)?;
                let hash = ContentHash::of_bytes(&v.canonical_bytes(options.limits)?);
                let existing = self
                    .backend
                    .guarded_find_run(&principal, &context, &run_id, Operation::Query)
                    .await?;
                let (run, context, wire) = if let Some(run) = existing {
                    if run.owner() != &id || run.operation_hash() != &hash {
                        return Err(Error::new(ErrorKind::Conflict, "run operation conflict"));
                    }
                    (run, context, None)
                } else {
                    let pin = GraphBackend::head(self.backend.as_ref()).await?;
                    let query = self
                        .preload(&context, &pin, &ArtifactRef::from_value(v.field("query")?)?)
                        .await?;
                    let config_ref = match v.as_object()?.get("config") {
                        Some(c) => ArtifactRef::from_value(c)?,
                        None => self.config.required_default_config()?,
                    };
                    let config = self.preload(&context, &pin, &config_ref).await?;
                    let profile = if let Some(p) = v.as_object()?.get("profile") {
                        p.closed(&["selector", "artifact"], &[])?;
                        Some((
                            p.field("selector")?.as_str()?,
                            self.preload(
                                &context,
                                &pin,
                                &ArtifactRef::from_value(p.field("artifact")?)?,
                            )
                            .await?,
                        ))
                    } else {
                        None
                    };
                    if let Some((selector, artifact)) = &profile {
                        // This local service has no mutable alias registry. The
                        // published bytes themselves bind the authored selector.
                        let body = frontend::parse(
                            ArtifactKind::Profile,
                            artifact.content(),
                            options.limits,
                        )?
                        .value;
                        if body.as_object()?.get("name").map(V::as_str).transpose()?
                            != Some(*selector)
                        {
                            return Err(Error::invalid("published profile name binding"));
                        }
                    }
                    let draft = compile(
                        QuerySource::published(&query),
                        profile.as_ref().map(|(s, a)| SelectedProfile {
                            selector: s,
                            artifact: a,
                        }),
                        &config,
                        CompileOptions::default(),
                    )?;
                    let consistency = match v
                        .as_object()?
                        .get("consistency")
                        .map(V::as_str)
                        .transpose()?
                        .unwrap_or("exact")
                    {
                        "exact" => Consistency::Exact,
                        "allow_stale" => Consistency::AllowStale,
                        _ => return Err(Error::invalid("consistency")),
                    };
                    let provider = self.provider(principal.clone(), None)?;
                    let prepared = Box::pin(execution::prepare_recorded(
                        draft,
                        self.backend.as_ref(),
                        self.backend.as_ref(),
                        &principal,
                        &provider,
                        Some(consistency),
                        options.clone(),
                    ))
                    .await?;
                    let (data, context, wire) = prepared.into_parts();
                    if data.data().reads.len() + data.data().policy.len()
                        > self.config.limits.trace_entries
                    {
                        return Err(Error::limit());
                    }
                    let run = RunEnvelope::new(run_id, id, hash, data, options.limits)?;
                    if run.bytes(options.limits)?.len() > cap {
                        return Err(Error::limit());
                    }
                    (run, context, Some(wire))
                };
                let candidate = run.replay().clone();
                self.backend
                    .clone()
                    .guarded_owned_commit_record(
                        principal,
                        context,
                        run,
                        fence,
                        move |stored, pin| {
                            let response = if stored.replay() == &candidate {
                                match wire {
                                    Some(w) => V::parse(&w, Limits::default())?,
                                    None => original_response(stored, consistency_name)?,
                                }
                            } else {
                                original_response(stored, consistency_name)?
                            };
                            tx.send(bounded(
                                obj([
                                    ("schema", V::string("ctxql-service/v1")),
                                    ("run_id", V::string(stored.id().as_str())),
                                    (
                                        "recording_snapshot",
                                        cdb_core::record_codec::snapshot_value(pin),
                                    ),
                                    ("response", response),
                                ]),
                                cap,
                            )?)
                            .map_err(|_| denied())
                        },
                    )
                    .await?;
            }
            "run" | "replay" => {
                let replay = op == Operation::Replay;
                v.closed(
                    &["schema", "op", "run_id"],
                    if replay { &["hydrate"] } else { &[] },
                )?;
                let run = self
                    .backend
                    .guarded_run_for(
                        &principal,
                        &context,
                        &RunId::new(v.field("run_id")?.as_str()?)?,
                        op,
                    )
                    .await?;
                let (context, response) = if replay {
                    let provider = self.provider(
                        principal.clone(),
                        Some(run.replay().data().snapshot.clone()),
                    )?;
                    let prepared = Box::pin(execution::prepare_replay(
                        run.replay(),
                        self.backend.as_ref(),
                        self.backend.as_ref(),
                        &principal,
                        &provider,
                        options.clone(),
                    ))
                    .await?;
                    let mut response = V::parse(prepared.wire_bytes(), options.limits)?;
                    if v.as_object()?
                        .get("hydrate")
                        .map(V::as_bool)
                        .transpose()?
                        .unwrap_or(false)
                    {
                        let evidence = hydrate(prepared.sources(), &provider.sources, cap).await?;
                        if let V::Object(ref mut o) = response {
                            o.insert("evidence".into(), V::Array(evidence));
                        }
                    }
                    (prepared.context().clone(), response)
                } else {
                    (
                        context,
                        obj([
                            ("run_id", V::string(run.id().as_str())),
                            (
                                "response_hash",
                                V::string(run.replay().data().response_hash.as_str()),
                            ),
                            (
                                "snapshot",
                                cdb_core::record_codec::snapshot_value(
                                    &run.replay().data().snapshot,
                                ),
                            ),
                        ]),
                    )
                };
                let bytes = bounded(
                    obj([
                        ("schema", V::string("ctxql-service/v1")),
                        ("response", response),
                    ]),
                    cap,
                )?;
                self.backend
                    .clone()
                    .guarded_owned_release(principal, context, op, Some(run), fence, move || {
                        tx.send(bytes).map_err(|_| denied())
                    })
                    .await?;
            }
            "status" => {
                v.closed(&["schema", "op"], &[])?;
                let bytes = bounded(
                    obj([
                        ("schema", V::string("ctxql-service/v1")),
                        ("status", V::string("ready")),
                    ]),
                    cap,
                )?;
                self.backend
                    .clone()
                    .guarded_owned_release(principal, context, op, None, fence, move || {
                        tx.send(bytes).map_err(|_| denied())
                    })
                    .await?;
            }
            "source" => {
                v.closed(
                    &[
                        "schema",
                        "op",
                        "source_id",
                        "version",
                        "selectors",
                        "max_bytes",
                    ],
                    &[],
                )?;
                let max_bytes =
                    usize::try_from(v.field("max_bytes")?.u64()?).map_err(|_| Error::limit())?;
                if max_bytes > cap {
                    return Err(Error::limit());
                }
                if v.field("selectors")?.as_object()?.len() != 2 {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "supplementary source witness unavailable",
                    ));
                }
                let request = cdb_core::source::SourceReadRequest {
                    source_id: SourceId::new(v.field("source_id")?.as_str()?)?,
                    version: ContentHash::parse(v.field("version")?.as_str()?)?,
                    selector: cdb_core::evidence::validate_selectors(v.field("selectors")?)?,
                    max_bytes,
                };
                let provider = self.provider(
                    principal.clone(),
                    Some(GraphBackend::head(self.backend.as_ref()).await?),
                )?;
                provider
                    .sources
                    .bind_snapshot(provider.control_capture.as_ref().ok_or_else(denied)?)?;
                let read = provider.sources.read(&request).await?;
                let bytes = bounded(
                    obj([
                        ("schema", V::string("ctxql-service/v1")),
                        (
                            "content",
                            V::string(
                                std::str::from_utf8(read.bytes())
                                    .map_err(|_| Error::invalid("source encoding"))?,
                            ),
                        ),
                    ]),
                    cap,
                )?;
                self.backend
                    .clone()
                    .guarded_owned_release(principal, context, op, None, fence, move || {
                        tx.send(bytes).map_err(|_| denied())
                    })
                    .await?;
            }
            _ => unreachable!(),
        }
        // No deadline failure after the native sink: enqueue is the local linearization point.
        rx.await.map_err(|_| denied())
    }

    fn native_run_gate(&self, run: &RunId) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = self.native_runs.lock().unwrap_or_else(|e| e.into_inner());
        gates.retain(|_, gate| gate.strong_count() != 0);
        if let Some(gate) = gates.get(run.as_str()).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        gates.insert(run.as_str().to_owned(), Arc::downgrade(&gate));
        gate
    }

    fn semantic_fence_for_run(
        &self,
        run: &cdb_core::recording_v5::RunEnvelopeV5,
    ) -> Result<SemanticFenceCheck> {
        let ledger = self
            .semantic
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Denied, "semantic role unavailable"))?
            .clone();
        let evidence = run.replay().semantic().projection();
        let mode = match evidence.field("policy_mode")?.as_str()? {
            "unrestricted" => SemanticPolicyMode::Unrestricted,
            "configured" => SemanticPolicyMode::Configured,
            _ => return Err(Error::invalid("semantic policy mode")),
        };
        Ok(SemanticFenceCheck::current(
            ledger,
            SemanticPolicyBasis {
                mode,
                dependency_root: ContentHash::parse(
                    evidence.field("policy_dependency_root")?.as_str()?,
                )?,
                principal: evidence.field("principal")?.as_str()?.to_owned(),
                action: evidence.field("action")?.as_str()?.to_owned(),
                source_observation: evidence
                    .field("policy_source_observation")?
                    .as_str()?
                    .to_owned(),
            },
        ))
    }

    async fn verify_recorded_semantic_current(
        &self,
        run: &cdb_core::recording_v5::RunEnvelopeV5,
    ) -> Result<()> {
        self.semantic_fence_for_run(run)?.check()
    }

    async fn dispatch_native_v3(
        self: &Arc<Self>,
        token: &str,
        request: &V,
        cancellation: Arc<AtomicBool>,
        principal: FlureePrincipal,
        owner: PrincipalId,
    ) -> Result<Vec<u8>> {
        request.closed(
            &["schema", "op", "run_id", "query", "execution"],
            &["config", "profile", "consistency"],
        )?;
        if request.field("execution")?.as_str()? != "native_v3"
            || request
                .as_object()?
                .get("consistency")
                .map(V::as_str)
                .transpose()?
                .unwrap_or("exact")
                != "exact"
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "native v3 requires exact consistency",
            ));
        }
        let run_id = RunId::new(request.field("run_id")?.as_str()?)?;
        let operation_hash = ContentHash::of_bytes(&request.canonical_bytes(Limits::default())?);
        let gate = self.native_run_gate(&run_id);
        let _run_owner = gate.lock_owned().await;
        let current = self.backend.current(&principal).await?;
        self.backend.require_operation(&current, Operation::Query)?;
        if let Some(existing) = self
            .backend
            .guarded_find_versioned_run(&principal, &current, &run_id, Operation::Query)
            .await?
        {
            let session = self.auth.authenticate(token).await.map_err(|_| denied())?;
            let lease = self
                .auth
                .lease(&session, auth::Operation::Query)
                .await
                .map_err(|_| denied())?;
            let permit = self
                .permits
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::limit())?;
            let semantic = match &existing {
                ProtectedRun::V5(run) => Some(self.semantic_fence_for_run(run)?),
                _ => None,
            };
            let fence = Box::new(Fence {
                lease,
                _permit: permit,
                options: ExecutionOptions {
                    deadline: Some(Instant::now() + self.config.limits.deadline()),
                    cancellation: Some(cancellation),
                    ..Default::default()
                },
                semantic,
            });
            return match existing {
                ProtectedRun::V3(run) => {
                    if run.owner() != &owner || run.operation_hash() != &operation_hash {
                        return Err(Error::new(ErrorKind::Conflict, "run operation conflict"));
                    }
                    let (run, recording_snapshot) = self
                        .backend
                        .retry_original_v3_with_receipt(&principal, &run_id, &operation_hash)
                        .await?;
                    let bytes = bounded(
                        obj([
                            ("schema", V::string("ctxql-service/v1")),
                            ("run_id", V::string(run.id().as_str())),
                            (
                                "recording_snapshot",
                                cdb_core::record_codec::snapshot_value(&recording_snapshot),
                            ),
                            (
                                "response",
                                original_response_data(run.replay().data(), "exact")?,
                            ),
                        ]),
                        self.config.limits.run_bytes,
                    )?;
                    let (tx, rx) = oneshot::channel();
                    self.backend
                        .clone()
                        .guarded_owned_release_v3(
                            principal,
                            Operation::Query,
                            run,
                            fence,
                            move || tx.send(bytes).map_err(|_| denied()),
                        )
                        .await?;
                    rx.await.map_err(|_| denied())
                }
                ProtectedRun::V5(run) => {
                    if run.owner() != &owner || run.operation_hash() != &operation_hash {
                        return Err(Error::new(ErrorKind::Conflict, "run operation conflict"));
                    }
                    self.verify_recorded_semantic_current(&run).await?;
                    let (run, recording_snapshot) = self
                        .backend
                        .retry_original_v5_with_receipt(&principal, &run_id, &operation_hash)
                        .await?;
                    let bytes = bounded(
                        obj([
                            ("schema", V::string("ctxql-service/v1")),
                            ("run_id", V::string(run.id().as_str())),
                            (
                                "recording_snapshot",
                                cdb_core::record_codec::snapshot_value(&recording_snapshot),
                            ),
                            (
                                "response",
                                original_response_data(run.replay().base().data(), "exact")?,
                            ),
                        ]),
                        self.config.limits.run_bytes,
                    )?;
                    let (tx, rx) = oneshot::channel();
                    self.backend
                        .clone()
                        .guarded_owned_release_v5(
                            principal,
                            Operation::Query,
                            run,
                            fence,
                            move || tx.send(bytes).map_err(|_| denied()),
                        )
                        .await?;
                    rx.await.map_err(|_| denied())
                }
                ProtectedRun::V4(_) => Err(Error::new(
                    ErrorKind::Unsupported,
                    cdb_backend_fluree::backend_identity::HISTORICAL_EXECUTOR_UNAVAILABLE,
                )),
                ProtectedRun::V2(_) => Err(Error::new(ErrorKind::Conflict, "run version conflict")),
            };
        }
        let profile = request
            .as_object()?
            .get("profile")
            .map(|value| -> Result<(String, ArtifactRef)> {
                value.closed(&["selector", "artifact"], &[])?;
                Ok((
                    value.field("selector")?.as_str()?.to_owned(),
                    ArtifactRef::from_value(value.field("artifact")?)?,
                ))
            })
            .transpose()?;
        let prepared = self
            .prepare_execution(
                token,
                PreparationRequest {
                    run_id,
                    query: ArtifactRef::from_value(request.field("query")?)?,
                    config: request
                        .as_object()?
                        .get("config")
                        .map(ArtifactRef::from_value)
                        .transpose()?,
                    profile,
                },
                cancellation,
            )
            .await?;
        let (run_id, recording_snapshot, response) = if prepared.is_semantic() {
            let recorded = prepared.execute_recorded_v5(operation_hash).await?;
            (
                recorded.run.id().clone(),
                recorded.recording_snapshot,
                original_response_data(recorded.run.replay().base().data(), "exact")?,
            )
        } else {
            let recorded = prepared
                .execute_recorded_v3_portable(operation_hash)
                .await?;
            (
                recorded.run.id().clone(),
                recorded.recording_snapshot,
                original_response_data(recorded.run.replay().data(), "exact")?,
            )
        };
        bounded(
            obj([
                ("schema", V::string("ctxql-service/v1")),
                ("run_id", V::string(run_id.as_str())),
                (
                    "recording_snapshot",
                    cdb_core::record_codec::snapshot_value(&recording_snapshot),
                ),
                ("response", response),
            ]),
            self.config.limits.run_bytes,
        )
    }

    async fn preload(
        &self,
        context: &FlureePolicyContext,
        pin: &SnapshotRef,
        r: &ArtifactRef,
    ) -> Result<PublishedArtifact> {
        let id = ResourceId::new(r.iri().as_str())?;
        if !self.backend.resource_allowed(context, &id)? {
            return Err(denied());
        }
        for key in ["iri", "version", "hash"] {
            if !self.backend.fact_allowed(
                context,
                &id,
                &Iri::new(format!(
                    "https://ctxql.example/reference-property/v1/artifact%2E{key}"
                ))?,
            )? {
                return Err(denied());
            }
        }
        let snapshot = self.backend.open_snapshot(pin).await?;
        if snapshot
            .resource(&id)
            .await?
            .is_some_and(|r| r.kind() == cdb_core::admission::ResourceKind::RunDescriptor)
        {
            return Err(denied());
        }
        snapshot.artifact(r).await?.ok_or_else(denied)
    }
}
fn original_response(run: &RunEnvelope, consistency: &str) -> Result<V> {
    original_response_data(run.replay().data(), consistency)
}

fn original_response_data(d: &ReplayDataInput, consistency: &str) -> Result<V> {
    let mut v = d.response.payload().clone();
    if let V::Object(ref mut o) = v {
        o.insert("response_hash".into(), V::string(d.response_hash.as_str()));
        o.insert("plan_hash".into(), V::string(d.plan_hash.as_str()));
        let evidence = d
            .plan
            .payload()
            .field("query")?
            .field("return")?
            .field("evidence")?
            .as_bool()?;
        let status = if evidence {
            V::string("ready_with_warnings")
        } else {
            d.response.payload().field("graph_status")?.clone()
        };
        o.insert("status".into(), status);
        o.insert(
            "consistency".into(),
            obj([
                ("mode", V::string(consistency)),
                (
                    "requested",
                    obj([
                        (
                            "backend",
                            V::string(d.requested_snapshot.backend().as_str()),
                        ),
                        ("pin", d.requested_snapshot.pin().projection()),
                    ]),
                ),
                (
                    "actual",
                    obj([
                        ("backend", V::string(d.snapshot.backend().as_str())),
                        ("pin", d.snapshot.pin().projection()),
                    ]),
                ),
                ("as_of", V::string(d.as_of.canonical())),
                ("stale", V::Bool(d.stale)),
            ]),
        );
        if evidence {
            o.insert("evidence".into(), V::Array(vec![]));
            o.insert(
                "transport_notices".into(),
                V::Array(vec![V::string("evidence_unavailable")]),
            );
        }
    }
    Ok(v)
}
async fn hydrate(
    sources: &[cdb_core::evidence::SourceReference],
    reader: &Sources,
    cap: usize,
) -> Result<Vec<V>> {
    let mut out = vec![];
    for source in sources {
        let v = source.projection();
        let mut status = "unverifiable";
        let mut content = V::Null;
        if let (Some(version), Some(selectors)) =
            (source.version(), v.as_object()?.get("selectors"))
        {
            let req = cdb_core::source::SourceReadRequest {
                source_id: source.id().clone(),
                version: version.clone(),
                selector: cdb_core::evidence::validate_selectors(selectors)?,
                max_bytes: cap,
            };
            match reader.read_reference(source, req.max_bytes).await {
                Ok(read) => {
                    status = match v.as_object()?.get("content_hash") {
                        Some(h) if h.as_str()? == ContentHash::of_bytes(read.bytes()).as_str() => {
                            "verified"
                        }
                        Some(_) => "changed",
                        None => "unverifiable",
                    };
                    if status == "verified" {
                        content = V::string(
                            std::str::from_utf8(read.bytes())
                                .map_err(|_| Error::invalid("source encoding"))?,
                        );
                    }
                }
                Err(e)
                    if matches!(
                        e.kind,
                        ErrorKind::Denied
                            | ErrorKind::PolicyChanged
                            | ErrorKind::Deadline
                            | ErrorKind::Limit
                    ) =>
                {
                    return Err(e)
                }
                Err(_) => status = "unavailable",
            }
        }
        out.push(obj([
            ("source_id", V::string(source.id().as_str())),
            ("status", V::string(status)),
            ("content", content),
        ]));
        bounded(V::Array(out.clone()), cap)?;
    }
    Ok(out)
}
fn credential(principal: PrincipalId) -> Result<(String, CredentialEntry)> {
    let (secret, _) = auth::provision(principal.clone(), None, auth::Capabilities::all())
        .map_err(|_| denied())?;
    let secret = secret.into_string();
    let entry = CredentialEntry {
        digest: ContentHash::of_bytes(secret.as_bytes()).as_str().into(),
        principal: principal.as_str().into(),
        enabled: true,
        expires_at: None,
        capabilities: ["query", "read", "replay", "publish", "admin"]
            .map(str::to_owned)
            .to_vec(),
    };
    Ok((secret, entry))
}
fn private_dir(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut b = std::fs::DirBuilder::new();
        b.mode(0o700)
            .create(path)
            .map_err(|_| Error::new(ErrorKind::Backend, "source directory creation failed"))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(Error::new(
            ErrorKind::Unsupported,
            "private directories unsupported",
        ))
    }
}
