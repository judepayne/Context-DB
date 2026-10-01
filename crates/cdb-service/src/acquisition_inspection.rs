//! Authenticated inspection and resume boundary for durable acquisition work.
//!
//! Work links and content hashes are not read capabilities. Discovery is tied
//! to an authenticated principal, a current Semantic authority basis, admitted
//! review records, and a final current Control authority release.

mod party_seed;

use crate::{
    acquisition::{load_current_catalog, AcquisitionService, WaitPoint},
    auth::{self, AuthStore, SessionLease},
    config::{AcquisitionAssertionPolicy, CredentialTable, InstanceConfig},
    graph_context::{GraphContextLimits, GraphContextManifest},
    graph_query::{require_graph_query_binding, GraphQueryHost, GraphQueryLimits},
    ingest::{replay_capture_manifest, IngestWait, OntologyMode},
    sources::{
        AcquisitionArtifactDescriptor, AuthorizedSources, SourceAuthorization,
        SourcePlusGraphArtifactDescriptor, SourceStore,
    },
};
use cdb_backend_fluree::{
    runs::{ExternalPublicationFence, Operation},
    semantic_policy::{
        resolve_current_semantic_authority, verify_semantic_authority_current, SemanticPolicyBasis,
    },
    FlureeBackend, FlureeSemanticLedger,
};
use cdb_core::{
    acquisition::ReviewAdmissionRecovery,
    contracts::{GraphBackend, PolicyService},
    id::{ContentHash, JobId, PrincipalId},
    review::ValidatedReviewBundle,
    CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use std::{
    collections::BTreeSet,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

fn denied() -> Error {
    Error::new(ErrorKind::Denied, "acquisition access denied")
}

fn native<T>(result: cdb_backend_fluree::NativeResult<T>) -> Result<T> {
    result.map_err(|error| match error.downcast::<Error>() {
        Ok(error) => *error,
        Err(_) => Error::new(ErrorKind::Backend, "acquisition authority unavailable"),
    })
}

struct AcquisitionFence {
    lease: SessionLease,
    semantic: Arc<FlureeSemanticLedger>,
    basis: SemanticPolicyBasis,
}
impl ExternalPublicationFence for AcquisitionFence {
    fn check(&self) -> Result<()> {
        self.lease.check().map_err(|_| denied())?;
        let semantic = self.semantic.clone();
        let basis = self.basis.clone();
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| Error::new(ErrorKind::Backend, "semantic fence unavailable"))?
                        .block_on(async move {
                            verify_semantic_authority_current(&semantic, &basis)
                                .await
                                .map_err(|_| denied())
                        })
                })
                .join()
                .map_err(|_| Error::new(ErrorKind::Backend, "semantic fence stopped"))?
        })
    }
}

/// Production composition root for authenticated acquisition inspection/resume.
pub struct AuthorizedAcquisition {
    config: InstanceConfig,
    backend: Arc<FlureeBackend>,
    semantic: Arc<FlureeSemanticLedger>,
    auth: AuthStore,
    acquisition: Arc<AcquisitionService>,
}

impl AuthorizedAcquisition {
    /// Trusted-process constructor. Exposed for embedders that have already
    /// authenticated their startup boundary. CLI callers should use
    /// `open_authenticated` so recovery cannot run for an unauthenticated
    /// request.
    pub async fn open(config: InstanceConfig) -> Result<Arc<Self>> {
        config.validate_runtime()?;
        let auth = CredentialTable::load(&config.credential_file)?
            .auth_store(config.limits.session_ttl())?;
        Self::open_after_authentication(config, auth).await
    }

    /// Authenticate and authorize before opening the recovery-capable
    /// acquisition service. The returned service authenticates again at
    /// dispatch and holds a fresh lease for the complete operation.
    pub async fn open_authenticated(
        config: InstanceConfig,
        token: &str,
        operation: Operation,
        auth_operation: auth::Operation,
    ) -> Result<Arc<Self>> {
        config.validate_runtime()?;
        let auth = CredentialTable::load(&config.credential_file)?
            .auth_store(config.limits.session_ttl())?;
        let session = auth.authenticate(token).await.map_err(|_| denied())?;
        let id = auth.principal(&session).await.map_err(|_| denied())?;
        let configured = config
            .acquisition
            .as_ref()
            .ok_or_else(|| Error::invalid("trusted acquisition configuration required"))?;
        if id.as_str() != configured.principal {
            return Err(denied());
        }
        let lease = auth
            .lease(&session, auth_operation)
            .await
            .map_err(|_| denied())?;
        lease.check().map_err(|_| denied())?;
        let backend = FlureeBackend::open(config.authority_options()?)
            .await
            .map_err(|_| denied())?;
        let principal = native(backend.issue_principal(id.clone()).await).map_err(|_| denied())?;
        let context = backend.current(&principal).await.map_err(|_| denied())?;
        backend
            .require_operation(&context, operation)
            .map_err(|_| denied())?;
        let (path, options) = config.semantic_binding()?;
        let semantic = FlureeSemanticLedger::open_file(path, options).await?;
        let authority = resolve_current_semantic_authority(
            &semantic,
            &configured.principal,
            &configured.action,
        )
        .await
        .map_err(|_| denied())?;
        lease.check().map_err(|_| denied())?;
        // Transfer Control ownership rather than holding two native file locks.
        drop(context);
        drop(principal);
        drop(backend);
        let access = Self::open_after_authentication(config, auth).await?;
        let principal = native(access.backend.issue_principal(id).await).map_err(|_| denied())?;
        let context = access
            .backend
            .current(&principal)
            .await
            .map_err(|_| denied())?;
        // Recovery/opening is inside the authenticated lifetime. If either
        // authority changed while it ran, do not release a usable service.
        lease.check().map_err(|_| denied())?;
        access
            .backend
            .require_operation(&context, operation)
            .map_err(|_| denied())?;
        verify_semantic_authority_current(&semantic, &authority.basis)
            .await
            .map_err(|_| denied())?;
        drop(lease);
        drop(session);
        Ok(access)
    }

    async fn open_after_authentication(
        config: InstanceConfig,
        auth: AuthStore,
    ) -> Result<Arc<Self>> {
        let catalog = load_current_catalog(&config).await?;
        let acquisition = AcquisitionService::open(&config, catalog.identity().clone()).await?;
        let backend = acquisition.authority.clone();
        let (path, options) = config.semantic_binding()?;
        let semantic = Arc::new(FlureeSemanticLedger::open_file(path, options).await?);
        Ok(Arc::new(Self {
            config,
            backend,
            semantic,
            auth,
            acquisition,
        }))
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.auth.stop_admitting();
        self.auth.shutdown().await;
        self.acquisition.shutdown().await
    }

    /// Admit a closed, curated party-background seed under an administrator
    /// lease. The seed is not a model extraction and is never written to the
    /// raw ontology ledger.
    pub async fn seed_party_background(self: &Arc<Self>, token: &str, request: &[u8]) -> Result<V> {
        party_seed::admit(self, token, request).await
    }

    /// Closed request wrapper used by local CLI and embedders.
    pub async fn dispatch(self: &Arc<Self>, token: &str, request: &[u8]) -> Result<Vec<u8>> {
        if request.len() > self.config.limits.max_body_bytes {
            return Err(Error::limit());
        }
        let value = V::parse(request, Limits::default())?;
        if value.field("schema")?.as_str()? != "ctxql-acquisition-access/v1" {
            return Err(Error::invalid("acquisition access schema"));
        }
        let response = match value.field("op")?.as_str()? {
            "inspect" => {
                value.closed(&["schema", "op", "job_id"], &[])?;
                self.inspect(token, JobId::new(value.field("job_id")?.as_str()?)?)
                    .await?
            }
            "resume" => {
                value.closed(&["schema", "op", "job_id"], &["wait"])?;
                let wait = match value
                    .as_object()?
                    .get("wait")
                    .map(V::as_str)
                    .transpose()?
                    .unwrap_or("projected")
                {
                    "admitted" => WaitPoint::Admitted,
                    "projected" => WaitPoint::Projected,
                    _ => return Err(Error::invalid("acquisition resume wait point")),
                };
                self.resume(token, JobId::new(value.field("job_id")?.as_str()?)?, wait)
                    .await?
            }
            "replay" => {
                value.closed(
                    &[
                        "schema",
                        "op",
                        "capture_root",
                        "ontology_mode",
                        "assertions",
                    ],
                    &["wait", "ephemeral"],
                )?;
                let ontology_mode = OntologyMode::parse(value.field("ontology_mode")?.as_str()?)?;
                let assertions =
                    AcquisitionAssertionPolicy::parse(value.field("assertions")?.as_str()?)?;
                let wait = match value
                    .as_object()?
                    .get("wait")
                    .map(V::as_str)
                    .transpose()?
                    .unwrap_or("admitted")
                {
                    "admitted" => IngestWait::Admitted,
                    "projected" => IngestWait::Projected,
                    _ => return Err(Error::invalid("acquisition replay wait point")),
                };
                let ephemeral = value
                    .as_object()?
                    .get("ephemeral")
                    .map(V::as_bool)
                    .transpose()?
                    .unwrap_or(false);
                self.replay_with_persistence(
                    token,
                    ContentHash::parse(value.field("capture_root")?.as_str()?)?,
                    ontology_mode,
                    assertions,
                    wait,
                    ephemeral,
                )
                .await?
            }
            "artifact" => {
                value.closed(&["schema", "op", "job_id", "descriptor"], &[])?;
                self.read_artifact(
                    token,
                    JobId::new(value.field("job_id")?.as_str()?)?,
                    value.field("descriptor")?,
                )
                .await?
            }
            _ => return Err(Error::invalid("acquisition access operation")),
        };
        let bytes = response.canonical_bytes(Limits::default())?;
        if bytes.len() > self.config.limits.run_bytes {
            return Err(Error::limit());
        }
        Ok(bytes)
    }

    async fn authorize(
        &self,
        token: &str,
        operation: Operation,
        auth_operation: auth::Operation,
    ) -> Result<(
        PrincipalId,
        cdb_backend_fluree::policy::FlureePrincipal,
        cdb_backend_fluree::policy::FlureePolicyContext,
        SessionLease,
        SemanticPolicyBasis,
    )> {
        let session = self.auth.authenticate(token).await.map_err(|_| denied())?;
        let id = self.auth.principal(&session).await.map_err(|_| denied())?;
        let configured = self
            .config
            .acquisition
            .as_ref()
            .ok_or_else(|| Error::invalid("trusted acquisition configuration required"))?;
        // The mutation writer was opened for this exact Semantic principal.
        // Never reinterpret another authenticated identity as that principal.
        if id.as_str() != configured.principal {
            return Err(denied());
        }
        let principal =
            native(self.backend.issue_principal(id.clone()).await).map_err(|_| denied())?;
        let context = self.backend.current(&principal).await?;
        self.backend.require_operation(&context, operation)?;
        let lease = self
            .auth
            .lease(&session, auth_operation)
            .await
            .map_err(|_| denied())?;
        let authority =
            resolve_current_semantic_authority(&self.semantic, id.as_str(), &configured.action)
                .await
                .map_err(|_| denied())?;
        // Exact review subjects are policy-checked at their receipt snapshot
        // in discover, before any metadata or artifact descriptor is released.
        Ok((id, principal, context, lease, authority.basis))
    }

    async fn graph_authority_for_job(
        &self,
        job: &JobId,
    ) -> Result<Option<(Arc<GraphQueryHost>, BTreeSet<String>, ContentHash)>> {
        let draft = self
            .acquisition
            .work_value(job, "evaluation")
            .await?
            .ok_or_else(denied)?;
        if draft.field("schema")?.as_str()? != "ctxql-acquisition-graph-work/v1" {
            return Ok(None);
        }
        let graph = draft.field("graph")?;
        let context_root = ContentHash::parse(graph.field("context_root")?.as_str()?)?;
        if self.acquisition.work.get(job, "graph_context")?.as_ref() != Some(&context_root) {
            return Err(denied());
        }
        let context_value = self.acquisition.read_work_object(&context_root).await?;
        let context =
            GraphContextManifest::from_value(&context_value, GraphContextLimits::default())?;
        if context.root()? != context_root || draft.field("job_id")?.as_str()? != job.as_str() {
            return Err(denied());
        }
        let capture_root = self
            .acquisition
            .work
            .get(job, "capture")?
            .ok_or_else(denied)?;
        for value in draft.field("graph_artifact_descriptors")?.as_array()? {
            let descriptor = SourcePlusGraphArtifactDescriptor::from_value(
                value,
                self.acquisition.artifact_limit,
            )?;
            if descriptor.graph_context_root() != &context_root
                || descriptor.context_root() != &capture_root
            {
                return Err(denied());
            }
        }
        let workspace = self
            .config
            .acquisition
            .as_ref()
            .and_then(|config| config.graph_workspace.as_ref())
            .ok_or_else(denied)?;
        let query_config = workspace
            .query_config
            .as_ref()
            .map(|reference| reference.artifact_ref())
            .unwrap_or_else(|| self.config.required_default_config())?;
        let profile = match (&workspace.profile_selector, &workspace.profile) {
            (Some(selector), Some(reference)) => {
                Some((selector.clone(), reference.artifact_ref()?))
            }
            (None, None) => None,
            _ => return Err(denied()),
        };
        // Current configuration cannot substitute a newly readable artifact for
        // the query/profile context that originally influenced this extraction.
        let capability_root = ContentHash::parse(graph.field("capability_root")?.as_str()?)?;
        if self.acquisition.work.get(job, "graph_capability")?.as_ref() != Some(&capability_root) {
            return Err(denied());
        }
        let capability = self.acquisition.read_work_object(&capability_root).await?;
        require_graph_query_binding(&capability, &query_config, profile.as_ref())?;
        let host = self
            .acquisition
            .graph_query_host(
                query_config,
                profile,
                GraphQueryLimits {
                    max_nodes: workspace.max_nodes,
                    max_claims: workspace.max_claims,
                    max_response_bytes: workspace.max_response_bytes,
                    max_work: 100_000,
                    timeout: Duration::from_secs(workspace.query_timeout_seconds as u64),
                },
            )
            .await?;
        host.guarded_disclosure_action(
            context.disclosed().clone(),
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(10),
            || async { Ok(()) },
        )
        .await?;
        Ok(Some((host, context.disclosed().clone(), context_root)))
    }

    #[allow(clippy::too_many_arguments)]
    async fn release_with_graph_authority(
        &self,
        graph: Option<(Arc<GraphQueryHost>, BTreeSet<String>, ContentHash)>,
        principal: cdb_backend_fluree::policy::FlureePrincipal,
        context: cdb_backend_fluree::policy::FlureePolicyContext,
        operation: Operation,
        lease: SessionLease,
        basis: SemanticPolicyBasis,
        value: V,
    ) -> Result<V> {
        let (query, dependencies, _) = graph.ok_or_else(denied)?;
        let configured = self.config.acquisition.as_ref().ok_or_else(denied)?;
        let semantic_principal = configured.principal.clone();
        let semantic_action = configured.action.clone();
        let writer = self.acquisition.semantic_writer.clone();
        let fence = Box::new(AcquisitionFence {
            lease,
            semantic: self.semantic.clone(),
            basis: basis.clone(),
        });
        let (send, receive) = oneshot::channel();
        let source_context = context.clone();
        self.backend
            .clone()
            .guarded_owned_action(principal, context, operation, fence, move || async move {
                query.authorize_sources(&source_context)?;
                let _guard = writer
                    .disclosure_guard(&semantic_principal, &semantic_action, &basis, &dependencies)
                    .await?;
                query.authorize_sources(&source_context)?;
                send.send(value).map_err(|_| denied())
            })
            .await?;
        receive.await.map_err(|_| denied())
    }

    pub async fn inspect(&self, token: &str, job: JobId) -> Result<V> {
        let (_, principal, context, lease, basis) = self
            .authorize(token, Operation::Read, auth::Operation::Read)
            .await?;
        let graph = self.graph_authority_for_job(&job).await?;
        let response = self.discover(&job).await?;
        let sources = self
            .authorize_inspection_sources(&principal, &response)
            .await?;
        let graph = graph.map(|(host, dependencies, root)| {
            (host.with_source_authority(sources), dependencies, root)
        });
        lease.check().map_err(|_| denied())?;
        self.backend.require_operation(&context, Operation::Read)?;
        verify_semantic_authority_current(&self.semantic, &basis)
            .await
            .map_err(|_| denied())?;
        if graph.is_some() {
            self.release_with_graph_authority(
                graph,
                principal,
                context,
                Operation::Read,
                lease,
                basis,
                response,
            )
            .await
        } else {
            self.release(principal, context, Operation::Read, lease, basis, response)
                .await
        }
    }

    pub async fn read_artifact(&self, token: &str, job: JobId, requested: &V) -> Result<V> {
        let (_, principal, context, lease, basis) = self
            .authorize(token, Operation::Read, auth::Operation::Read)
            .await?;
        let graph = self.graph_authority_for_job(&job).await?;
        let inspection = self.discover(&job).await?;
        let sources = self
            .authorize_inspection_sources(&principal, &inspection)
            .await?;
        let graph = graph.map(|(host, dependencies, root)| {
            (host.with_source_authority(sources), dependencies, root)
        });
        let authenticated_image = inspection
            .field("artifacts")?
            .as_array()?
            .iter()
            .find(|image| *image == requested)
            .ok_or_else(denied)?;
        let configured = self.config.acquisition.as_ref().ok_or_else(denied)?;
        let capture_root = self
            .acquisition
            .work
            .get(&job, "capture")?
            .ok_or_else(denied)?;
        let store = Arc::new(SourceStore::open(
            self.config.source_root.clone(),
            self.config
                .acquisition
                .as_ref()
                .ok_or_else(denied)?
                .max_source_bytes
                .min(self.config.limits.run_bytes),
        )?);
        let sources = AuthorizedSources::new(
            self.backend.clone(),
            self.backend.clone(),
            Arc::new(principal.clone()),
            store,
        );
        sources.bind_snapshot(&GraphBackend::head(self.backend.as_ref()).await?)?;
        let artifact_read_limit = self
            .config
            .limits
            .run_bytes
            .min(configured.max_source_bytes);
        let bytes = match authenticated_image.field("schema")?.as_str()? {
            "ctxql-acquisition-artifact-descriptor/v2" if graph.is_none() => {
                let descriptor = AcquisitionArtifactDescriptor::from_value(
                    authenticated_image,
                    configured.max_source_bytes,
                )?;
                let grant = sources.provision_acquisition_artifact(
                    descriptor,
                    authenticated_image,
                    &capture_root,
                )?;
                sources
                    .read_acquisition_artifact(&grant, artifact_read_limit)
                    .await?
            }
            "ctxql-acquisition-artifact-descriptor/v3" => {
                let (_, _, graph_context_root) = graph.as_ref().ok_or_else(denied)?;
                let descriptor = SourcePlusGraphArtifactDescriptor::from_value(
                    authenticated_image,
                    configured.max_source_bytes,
                )?;
                let grant = sources.provision_source_plus_graph_artifact(
                    descriptor,
                    authenticated_image,
                    &capture_root,
                    graph_context_root,
                )?;
                sources
                    .read_source_plus_graph_artifact(&grant, artifact_read_limit)
                    .await?
            }
            _ => return Err(denied()),
        };
        let content = std::str::from_utf8(&bytes)
            .map_err(|_| Error::invalid("acquisition artifact is not UTF-8"))?;
        let response = V::object([
            (
                "schema".into(),
                V::string("ctxql-acquisition-artifact-read/v1"),
            ),
            ("job_id".into(), V::string(job.as_str())),
            ("descriptor".into(), authenticated_image.clone()),
            ("content".into(), V::string(content)),
        ])?;
        lease.check().map_err(|_| denied())?;
        self.backend.require_operation(&context, Operation::Read)?;
        verify_semantic_authority_current(&self.semantic, &basis)
            .await
            .map_err(|_| denied())?;
        if graph.is_some() {
            self.release_with_graph_authority(
                graph,
                principal,
                context,
                Operation::Read,
                lease,
                basis,
                response,
            )
            .await
        } else {
            self.release(principal, context, Operation::Read, lease, basis, response)
                .await
        }
    }

    /// Authenticate a registered capture root, re-check every inherited source
    /// scope, then evaluate its original request/response context without a
    /// provider. A hash supplied by the caller is never treated as authority.
    pub async fn replay(
        &self,
        token: &str,
        capture_root: ContentHash,
        ontology_mode: OntologyMode,
        assertions: AcquisitionAssertionPolicy,
        wait: IngestWait,
    ) -> Result<V> {
        self.replay_with_persistence(token, capture_root, ontology_mode, assertions, wait, false)
            .await
    }

    pub async fn replay_ephemeral(
        &self,
        token: &str,
        capture_root: ContentHash,
        ontology_mode: OntologyMode,
        assertions: AcquisitionAssertionPolicy,
    ) -> Result<V> {
        self.replay_with_persistence(
            token,
            capture_root,
            ontology_mode,
            assertions,
            IngestWait::Admitted,
            true,
        )
        .await
    }

    async fn replay_with_persistence(
        &self,
        token: &str,
        capture_root: ContentHash,
        ontology_mode: OntologyMode,
        assertions: AcquisitionAssertionPolicy,
        wait: IngestWait,
        ephemeral: bool,
    ) -> Result<V> {
        let (_, principal, context, lease, basis) = self
            .authorize(token, Operation::Replay, auth::Operation::Replay)
            .await?;
        let job = self.capture_job(&capture_root).await?;
        let graph = self.graph_authority_for_job(&job).await?;
        let inspection = self.discover(&job).await?;
        let sources = self
            .authorize_inspection_sources(&principal, &inspection)
            .await?;
        let graph = graph.map(|(host, dependencies, root)| {
            (host.with_source_authority(sources), dependencies, root)
        });
        let capture = self
            .acquisition
            .work_value(&job, "capture")
            .await?
            .ok_or_else(denied)?;
        if !matches!(
            capture.field("schema")?.as_str()?,
            "ctxql-passage-capture/v3" | "ctxql-passage-graph-capture/v1"
        ) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "stored capture is not replayable",
            ));
        }
        let manifest = capture.field("manifest")?;
        if manifest == &V::Null {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "stored capture is incomplete",
            ));
        }
        let manifest_bytes = manifest.canonical_bytes(Limits::default())?;
        crate::ingest::verify_capture_manifest_bytes(&manifest_bytes)?;

        // Final pre-mutation freshness fence. The evaluator will independently
        // recheck current ontology/entity authority before any new admission.
        lease.check().map_err(|_| denied())?;
        self.backend
            .require_operation(&context, Operation::Replay)
            .map_err(|_| denied())?;
        verify_semantic_authority_current(&self.semantic, &basis)
            .await
            .map_err(|_| denied())?;
        let mut acquisition_config = self.config.acquisition.as_ref().ok_or_else(denied)?.clone();
        acquisition_config.assertions = assertions;
        let report = replay_capture_manifest(
            &self.config,
            &acquisition_config,
            &self.acquisition,
            &manifest_bytes,
            ontology_mode,
            wait,
            ephemeral,
            graph.as_ref().map(|(host, _, _)| host.clone()),
        )
        .await?;
        lease.check().map_err(|_| denied())?;
        verify_semantic_authority_current(&self.semantic, &basis)
            .await
            .map_err(|_| denied())?;
        let response = V::object([
            (
                "schema".into(),
                V::string("ctxql-acquisition-replay-result/v1"),
            ),
            ("capture_root".into(), V::string(capture_root.as_str())),
            ("source_job_id".into(), V::string(job.as_str())),
            ("ephemeral".into(), V::Bool(ephemeral)),
            (
                "report".into(),
                V::parse(
                    &serde_json::to_vec(&report)
                        .map_err(|_| Error::invalid("replay report encoding"))?,
                    Limits::default(),
                )?,
            ),
        ])?;
        let context = self
            .backend
            .current(&principal)
            .await
            .map_err(|_| denied())?;
        self.backend
            .require_operation(&context, Operation::Replay)
            .map_err(|_| denied())?;
        if graph.is_some() {
            lease.check().map_err(|_| denied())?;
            verify_semantic_authority_current(&self.semantic, &basis)
                .await
                .map_err(|_| denied())?;
            self.release_with_graph_authority(
                graph,
                principal,
                context,
                Operation::Replay,
                lease,
                basis,
                response,
            )
            .await
        } else {
            self.release(
                principal,
                context,
                Operation::Replay,
                lease,
                basis,
                response,
            )
            .await
        }
    }

    async fn capture_job(&self, root: &ContentHash) -> Result<JobId> {
        let mut found = None;
        for job in self.acquisition.work.jobs()? {
            if self.acquisition.work.get(&job, "capture")?.as_ref() != Some(root) {
                continue;
            }
            let value = self
                .acquisition
                .work_value(&job, "capture")
                .await?
                .ok_or_else(denied)?;
            if !matches!(
                value.field("schema")?.as_str()?,
                "ctxql-passage-capture/v3" | "ctxql-passage-graph-capture/v1"
            ) || value.field("manifest")? == &V::Null
                || self.acquisition.work.get(&job, "evaluation")?.is_none()
                || found.is_some()
            {
                return Err(denied());
            }
            found = Some(job);
        }
        found.ok_or_else(denied)
    }

    pub async fn resume(&self, token: &str, job: JobId, wait: WaitPoint) -> Result<V> {
        let (_, principal, context, lease, basis) = self
            .authorize(token, Operation::Replay, auth::Operation::Replay)
            .await?;
        // Check both authorities and the session immediately before mutation.
        // complete_work performs exact immutable replay/recovery and never calls
        // the provider; the lease remains held through final guarded release.
        lease.check().map_err(|_| denied())?;
        self.backend
            .require_operation(&context, Operation::Replay)
            .map_err(|_| denied())?;
        verify_semantic_authority_current(&self.semantic, &basis)
            .await
            .map_err(|_| denied())?;
        let draft = self
            .acquisition
            .work_value(&job, "evaluation")
            .await?
            .ok_or_else(denied)?;
        if draft.field("job_id")?.as_str()? != job.as_str() {
            return Err(denied());
        }
        let graph = self.graph_authority_for_job(&job).await?;
        let inspection_before = self.discover(&job).await?;
        let sources = self
            .authorize_inspection_sources(&principal, &inspection_before)
            .await?;
        let graph = graph.map(|(host, dependencies, root)| {
            (host.with_source_authority(sources), dependencies, root)
        });
        if inspection_before.field("artifacts")?.as_array()?.is_empty() {
            return Err(denied());
        }
        let outcome = if let Some((host, dependencies, _)) = graph.clone() {
            self.acquisition
                .complete_work_guarded_dependencies(
                    &job,
                    wait,
                    host,
                    dependencies,
                    Instant::now() + Duration::from_secs(10),
                )
                .await?
        } else {
            self.acquisition.complete_work(&job, wait).await?
        };
        lease.check().map_err(|_| denied())?;
        verify_semantic_authority_current(&self.semantic, &basis)
            .await
            .map_err(|_| denied())?;
        let response = V::object([
            (
                "schema".into(),
                V::string("ctxql-acquisition-resume-result/v1"),
            ),
            ("job_id".into(), V::string(job.as_str())),
            ("review_receipt".into(), outcome.review.projection()),
            (
                "business_receipt".into(),
                outcome
                    .business
                    .map(|receipt| receipt.projection())
                    .unwrap_or(V::Null),
            ),
            (
                "result_available".into(),
                V::Bool(outcome.result_root.is_some() && outcome.publication_error.is_none()),
            ),
            (
                "result_review_receipt".into(),
                outcome
                    .result_review
                    .map(|receipt| receipt.projection())
                    .unwrap_or(V::Null),
            ),
            (
                "publication_error".into(),
                outcome.publication_error.map(V::string).unwrap_or(V::Null),
            ),
            (
                "projection_error".into(),
                outcome.projection_error.map(V::string).unwrap_or(V::Null),
            ),
        ])?;
        // Successful resume may append Control receipts. Refresh the release
        // context after those intentional mutations and revalidate permission;
        // the final gate still rejects any subsequent authority change.
        let context = self
            .backend
            .current(&principal)
            .await
            .map_err(|_| denied())?;
        self.backend
            .require_operation(&context, Operation::Replay)
            .map_err(|_| denied())?;
        let inspection = self.discover(&job).await?;
        self.authorize_inspection_sources(&principal, &inspection)
            .await?;
        if graph.is_some() {
            lease.check().map_err(|_| denied())?;
            verify_semantic_authority_current(&self.semantic, &basis)
                .await
                .map_err(|_| denied())?;
            self.release_with_graph_authority(
                graph,
                principal,
                context,
                Operation::Replay,
                lease,
                basis,
                response,
            )
            .await
        } else {
            self.release(
                principal,
                context,
                Operation::Replay,
                lease,
                basis,
                response,
            )
            .await
        }
    }

    async fn authorize_inspection_sources(
        &self,
        principal: &cdb_backend_fluree::policy::FlureePrincipal,
        inspection: &V,
    ) -> Result<SourceAuthorization> {
        let configured = self.config.acquisition.as_ref().ok_or_else(denied)?;
        let sources = AuthorizedSources::new(
            self.backend.clone(),
            self.backend.clone(),
            Arc::new(principal.clone()),
            Arc::new(SourceStore::open(
                self.config.source_root.clone(),
                configured
                    .max_source_bytes
                    .min(self.config.limits.run_bytes),
            )?),
        );
        sources.bind_snapshot(&GraphBackend::head(self.backend.as_ref()).await?)?;
        let mut authorized = std::collections::BTreeSet::new();
        let mut requirements = SourceAuthorization::default();
        for value in inspection.field("artifacts")?.as_array()? {
            let source = match value.field("schema")?.as_str()? {
                "ctxql-acquisition-artifact-descriptor/v2" => {
                    AcquisitionArtifactDescriptor::from_value(value, configured.max_source_bytes)?
                        .source()
                        .clone()
                }
                "ctxql-acquisition-artifact-descriptor/v3" => {
                    SourcePlusGraphArtifactDescriptor::from_value(
                        value,
                        configured.max_source_bytes,
                    )?
                    .source()
                    .clone()
                }
                _ => return Err(denied()),
            };
            let grant = sources.authorize(&source).await?;
            requirements.extend(&grant)?;
            authorized.insert(source.source_id.as_str().to_owned());
        }
        for review in inspection.field("reviews")?.as_array()? {
            if !authorized.contains(review.field("source_ref")?.as_str()?) {
                return Err(denied());
            }
        }
        Ok(requirements)
    }

    async fn discover(&self, job: &JobId) -> Result<V> {
        self.acquisition
            .work
            .get(job, "evaluation")?
            .ok_or_else(denied)?;
        let capture_root = self
            .acquisition
            .work
            .get(job, "capture")?
            .ok_or_else(denied)?;
        let draft = self
            .acquisition
            .work_value(job, "evaluation")
            .await?
            .ok_or_else(denied)?;
        if draft.field("job_id")?.as_str()? != job.as_str() {
            return Err(denied());
        }
        let provisioned = draft
            .field("report")?
            .as_object()?
            .get("artifact_descriptors")
            .map(|descriptors| {
                descriptors
                    .as_array()?
                    .iter()
                    .map(|value| {
                        AcquisitionArtifactDescriptor::from_value(
                            value,
                            self.acquisition.artifact_limit,
                        )
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let graph_provisioned =
            if draft.field("schema")?.as_str()? == "ctxql-acquisition-graph-work/v1" {
                draft
                    .field("graph_artifact_descriptors")?
                    .as_array()?
                    .iter()
                    .map(|value| {
                        SourcePlusGraphArtifactDescriptor::from_value(
                            value,
                            self.acquisition.artifact_limit,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                Vec::new()
            };
        if !provisioned.is_empty() && !graph_provisioned.is_empty() {
            return Err(denied());
        }
        let result_root = self.acquisition.work.get(job, "result")?;
        let prepared = self.acquisition.control.review_prepared_records().await?;
        let mut records = Vec::new();
        let mut descriptors = Vec::new();
        let mut authorized_sources = Vec::new();
        let mut authorized_graph_sources = Vec::new();
        let mut result_bound = false;
        for stage in ["review", "result_review"] {
            let Some(value) = self.acquisition.work_value(job, stage).await? else {
                continue;
            };
            let bundle = ValidatedReviewBundle::from_value(&value, Limits::default())?;
            let record = prepared
                .iter()
                .find(|record| record.job_id == *job && record.bundle_id == *bundle.id())
                .ok_or_else(denied)?;
            let receipt = self
                .acquisition
                .control
                .review_admission(bundle.id())
                .await?
                .ok_or_else(denied)?;
            receipt.verify_prepared(record)?;
            match self
                .acquisition
                .semantic_writer
                .recover_review(record)
                .await?
            {
                ReviewAdmissionRecovery::Exact(recovered) if *recovered == receipt => {}
                _ => return Err(denied()),
            }
            let configured = self.config.acquisition.as_ref().ok_or_else(denied)?;
            cdb_backend_fluree::semantic_preparation::authorize_review_records(
                &self.semantic,
                receipt.snapshot(),
                configured.review_graph.as_deref().ok_or_else(denied)?,
                receipt.review_ids(),
                &configured.principal,
                &configured.action,
                cdb_backend_fluree::semantic_preparation::ExtractionLimits::default(),
            )
            .await
            .map_err(|_| denied())?;
            if stage == "result_review" {
                let Some(root) = result_root.as_ref() else {
                    return Err(denied());
                };
                if bundle
                    .records()
                    .iter()
                    .any(|record| record.artifact_root() != root)
                {
                    return Err(denied());
                }
                result_bound = true;
            }
            for review in bundle.records() {
                // Artifact hashes are deliberately removed from review metadata.
                // Only complete source-bound descriptors may cross this boundary.
                let mut projection = review.projection();
                if let V::Object(fields) = &mut projection {
                    fields.remove("artifact_root");
                }
                for descriptor in &provisioned {
                    if descriptor.artifact_root() == review.artifact_root()
                        && descriptor.source().source_id.as_str() == review.source_ref()
                        && descriptor.context_root() == &capture_root
                    {
                        descriptors.push(descriptor.projection());
                        authorized_sources.push(descriptor.clone());
                    }
                }
                for descriptor in &graph_provisioned {
                    if descriptor.artifact_root() == review.artifact_root()
                        && descriptor.source().source_id.as_str() == review.source_ref()
                        && descriptor.context_root() == &capture_root
                    {
                        descriptors.push(descriptor.projection());
                        authorized_graph_sources.push(descriptor.clone());
                    }
                }
                records.push(projection);
            }
        }
        if records.is_empty() {
            return Err(denied());
        }
        // The capture and admission result are independently authenticated by
        // their immutable work links and exact recovered review history. Give
        // them complete source-bound descriptors; never release their roots as
        // capabilities on their own. Protected gazetteer captures have no
        // provisioned source-only base and therefore remain unavailable.
        for source in &authorized_sources {
            descriptors.push(
                source
                    .successor(capture_root.clone(), "provider_capture")?
                    .projection(),
            );
            if result_bound {
                descriptors.push(
                    source
                        .successor(result_root.clone().ok_or_else(denied)?, "admission_result")?
                        .projection(),
                );
            }
        }
        for source in &authorized_graph_sources {
            descriptors.push(
                source
                    .successor(capture_root.clone(), "provider_graph_capture")?
                    .projection(),
            );
            if result_bound {
                descriptors.push(
                    source
                        .successor(
                            result_root.clone().ok_or_else(denied)?,
                            "graph_admission_result",
                        )?
                        .projection(),
                );
            }
        }
        for descriptor in self.acquisition.artifact_page_descriptors(job).await? {
            // Pages must inherit a source/context already authenticated against
            // admitted review history, not merely a local checkpoint hash.
            if !authorized_sources.iter().any(|source| {
                source.source() == descriptor.source()
                    && source.source_fragment_hash() == descriptor.source_fragment_hash()
                    && source.context_root() == descriptor.context_root()
            }) {
                return Err(denied());
            }
            descriptors.push(descriptor.projection());
        }
        for descriptor in self
            .acquisition
            .graph_artifact_page_descriptors(job)
            .await?
        {
            if !authorized_graph_sources.iter().any(|source| {
                source.source() == descriptor.source()
                    && source.source_fragment_hash() == descriptor.source_fragment_hash()
                    && source.context_root() == descriptor.context_root()
                    && source.graph_context_root() == descriptor.graph_context_root()
            }) {
                return Err(denied());
            }
            descriptors.push(descriptor.projection());
        }
        descriptors.sort_by_key(|value| {
            ContentHash::of_bytes(
                &value
                    .canonical_bytes(Limits::default())
                    .expect("descriptor canonical value"),
            )
            .as_str()
            .to_owned()
        });
        descriptors.dedup();
        V::object([
            (
                "schema".into(),
                V::string("ctxql-acquisition-inspection/v1"),
            ),
            ("job_id".into(), V::string(job.as_str())),
            ("reviews".into(), V::Array(records)),
            ("artifacts".into(), V::Array(descriptors)),
        ])
    }

    async fn release(
        &self,
        principal: cdb_backend_fluree::policy::FlureePrincipal,
        context: cdb_backend_fluree::policy::FlureePolicyContext,
        operation: Operation,
        lease: SessionLease,
        basis: SemanticPolicyBasis,
        value: V,
    ) -> Result<V> {
        let fence = Box::new(AcquisitionFence {
            lease,
            semantic: self.semantic.clone(),
            basis,
        });
        let (send, receive) = oneshot::channel();
        self.backend
            .clone()
            .guarded_owned_release(principal, context, operation, None, fence, move || {
                send.send(value).map_err(|_| denied())
            })
            .await?;
        receive.await.map_err(|_| denied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdb_core::{
        artifact::ArtifactRef,
        evidence::{EvidenceSelector, Utf8Span},
        id::{ContentHash, SourceId},
        source::SourceReadRequest,
    };

    #[test]
    fn captured_query_authority_cannot_be_replaced_by_current_configuration() {
        use cdb_core::id::{Iri, VersionId};
        let reference = |name: &str| {
            ArtifactRef::new(
                Iri::new(format!("urn:test:{name}")).unwrap(),
                VersionId::new("1").unwrap(),
                ContentHash::of_bytes(name.as_bytes()),
            )
        };
        let config = reference("config");
        let profile = ("selected".to_owned(), reference("profile"));
        let capability = V::object([
            ("query_config".into(), config.projection()),
            ("profile_selector".into(), V::string(&profile.0)),
            ("profile".into(), profile.1.projection()),
        ])
        .unwrap();
        require_graph_query_binding(&capability, &config, Some(&profile)).unwrap();
        assert!(
            require_graph_query_binding(&capability, &reference("other"), Some(&profile)).is_err()
        );
        assert!(require_graph_query_binding(&capability, &config, None).is_err());
        assert!(require_graph_query_binding(
            &capability,
            &config,
            Some(&("other".into(), profile.1.clone()))
        )
        .is_err());
        assert!(require_graph_query_binding(
            &capability,
            &config,
            Some(&("selected".into(), reference("other-profile")))
        )
        .is_err());
    }

    #[test]
    fn artifact_descriptor_roundtrips_and_binds_selector_and_context() {
        let descriptor = AcquisitionArtifactDescriptor::new(
            SourceReadRequest {
                source_id: SourceId::new("urn:ctxql:source:test").unwrap(),
                version: ContentHash::of_bytes(b"version"),
                selector: EvidenceSelector::Span(Utf8Span::new(2, 7).unwrap()),
                max_bytes: 99,
            },
            ContentHash::of_bytes(b"fragment"),
            ContentHash::of_bytes(b"artifact"),
            "evaluation_outcomes",
            ContentHash::of_bytes(b"context"),
        )
        .unwrap();
        let decoded =
            AcquisitionArtifactDescriptor::from_value(&descriptor.projection(), 99).unwrap();
        assert_eq!(decoded, descriptor);
    }

    #[test]
    fn artifact_descriptor_rejects_hash_only_shape() {
        let value = V::object([
            (
                "schema".into(),
                V::string("ctxql-acquisition-artifact-descriptor/v2"),
            ),
            (
                "artifact_root".into(),
                V::string(ContentHash::of_bytes(b"artifact").as_str()),
            ),
        ])
        .unwrap();
        assert!(AcquisitionArtifactDescriptor::from_value(&value, 99).is_err());
    }

    #[test]
    fn configured_and_unrestricted_policy_modes_are_distinct() {
        use cdb_backend_fluree::semantic_policy::SemanticPolicyMode;
        assert_ne!(
            SemanticPolicyMode::Configured,
            SemanticPolicyMode::Unrestricted
        );
    }
}
