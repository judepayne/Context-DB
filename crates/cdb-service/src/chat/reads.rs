use super::{
    contracts::*,
    direct_projection::{ChatGraphHost, DirectProjectionHost},
    state::ChatState,
};
use crate::{
    auth::{self, SessionLease},
    config::{BoundedFileRead, CredentialTable, InstanceConfig},
    graph_query::{AuthorizedQuery, GraphQueryDiagnostic, GraphQueryHost, GraphQueryLimits},
    graph_read_only::IsolatedGraphReadSnapshot,
    ontology_direct::DirectFlureeOntologyToolHost,
    sources::{AuthorizedSources, SourceStore},
};
use cdb_backend_fluree::{
    runs::{ExternalPublicationFence, Operation},
    FlureeBackend, FlureeSemanticLedger,
};
use cdb_core::{
    artifact::ArtifactRef,
    claim::ClaimObject,
    contracts::{GraphBackend, PolicyService, SemanticProjectionSource, SourceReader},
    evidence::Lineage,
    id::{ContentHash, Iri, PrincipalId, VersionId},
    snapshot::{ProjectionCheckpoint, SnapshotRef},
    CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use serde::de::DeserializeOwned;
use std::{
    collections::BTreeSet,
    future::Future,
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::{Duration, Instant},
};

struct ReadFence {
    lease: SessionLease,
    cancellation: Arc<AtomicBool>,
    deadline: Instant,
}
impl ExternalPublicationFence for ReadFence {
    fn check(&self) -> Result<()> {
        self.lease
            .check()
            .map_err(|_| Error::new(ErrorKind::Denied, "credential unavailable"))?;
        check_available(&self.cancellation, self.deadline)
    }
}

/// Standalone read composition. It owns no writer, coordinator, recovery or
/// recording service; every protected call reloads and leases the credential.
pub struct ChatReadResources {
    config: InstanceConfig,
    token: String,
    principal: PrincipalId,
    semantic: Arc<FlureeSemanticLedger>,
    control: Option<Arc<FlureeBackend>>,
    source_store: Arc<SourceStore>,
    ontology: Option<Arc<DirectFlureeOntologyToolHost>>,
    ontology_gate: Arc<tokio::sync::Semaphore>,
    call_gate: Arc<tokio::sync::Semaphore>,
    state: Mutex<ChatState>,
}

impl ChatReadResources {
    pub async fn open(config: InstanceConfig, token: String) -> Result<Arc<Self>> {
        config.validate_runtime()?;
        let chat = config
            .chat
            .as_ref()
            .ok_or_else(|| Error::invalid("chat configuration required"))?;
        let startup_deadline = Instant::now()
            + Duration::from_secs(
                chat.limits
                    .host_call_seconds
                    .min(config.limits.deadline_seconds) as u64,
            );
        let credential_file = config.credential_file.clone();
        let ttl = config.limits.session_ttl();
        let auth = bounded(
            startup_deadline,
            Arc::new(AtomicBool::new(false)),
            async move {
                let table =
                    tokio::task::spawn_blocking(move || CredentialTable::load(&credential_file))
                        .await
                        .map_err(|_| {
                            Error::new(ErrorKind::Backend, "credential startup failed")
                        })??;
                Ok(table.auth_store(ttl)?)
            },
        )
        .await?;
        let session = bounded(startup_deadline, Arc::new(AtomicBool::new(false)), async {
            auth.authenticate(&token)
                .await
                .map_err(|_| Error::new(ErrorKind::Denied, "credential unavailable"))
        })
        .await?;
        let principal = bounded(startup_deadline, Arc::new(AtomicBool::new(false)), async {
            auth.principal(&session)
                .await
                .map_err(|_| Error::new(ErrorKind::Denied, "credential unavailable"))
        })
        .await?;
        // Query is the only startup credential requirement. Source authorization
        // remains independent and is checked only when source bytes are read.
        bounded(startup_deadline, Arc::new(AtomicBool::new(false)), async {
            auth.lease(&session, auth::Operation::Query)
                .await
                .map(|_| ())
                .map_err(|_| Error::new(ErrorKind::Denied, "query credential unavailable"))
        })
        .await?;

        let (semantic_path, semantic_options) = config.semantic_binding()?;
        let semantic = Arc::new(
            bounded(
                startup_deadline,
                Arc::new(AtomicBool::new(false)),
                FlureeSemanticLedger::open_file(semantic_path, semantic_options),
            )
            .await?,
        );
        let control = Arc::new(
            bounded(startup_deadline, Arc::new(AtomicBool::new(false)), async {
                FlureeBackend::open(config.authority_options()?)
                    .await
                    .map_err(|_| Error::new(ErrorKind::Backend, "chat authority unavailable"))
            })
            .await?,
        );
        let source_store = Arc::new(SourceStore::open(
            config.source_root.clone(),
            config.limits.run_bytes,
        )?);
        let ontology = match &chat.ontology {
            Some(ontology) => {
                let receipt = ontology.bootstrap_path.join("bootstrap.json");
                let receipt_hash = ontology.receipt_hash.clone();
                let path = ontology.bootstrap_path.clone();
                Some(Arc::new(
                    bounded(
                        startup_deadline,
                        Arc::new(AtomicBool::new(false)),
                        async move {
                            tokio::task::spawn_blocking(move || {
                                let bytes =
                                    BoundedFileRead::new(64 * 1024, false)?.read(&receipt)?;
                                if ContentHash::of_bytes(&bytes).as_str() != receipt_hash {
                                    return Err(Error::invalid(
                                        "chat ontology receipt hash mismatch",
                                    ));
                                }
                                DirectFlureeOntologyToolHost::from_bootstrap_with_budget(
                                    &path,
                                    Arc::new(AtomicBool::new(false)),
                                    startup_deadline,
                                )
                                .map_err(|_| Error::invalid("chat ontology unavailable"))
                            })
                            .await
                            .map_err(|_| {
                                Error::new(ErrorKind::Backend, "ontology startup failed")
                            })?
                        },
                    )
                    .await?,
                ))
            }
            None => None,
        };
        let mut state_limits = chat.limits.clone();
        state_limits.max_response_bytes = state_limits
            .max_response_bytes
            .min(config.limits.max_body_bytes)
            .min(config.limits.run_bytes);
        state_limits.max_source_span_bytes = state_limits
            .max_source_span_bytes
            .min(config.limits.run_bytes);
        state_limits.max_source_bytes_per_turn = state_limits
            .max_source_bytes_per_turn
            .min(config.limits.run_bytes);
        let retain_control = !chat.unsafe_direct_projection;
        let resources = Arc::new(Self {
            state: Mutex::new(ChatState::new(state_limits)),
            config,
            token,
            principal,
            semantic,
            control: retain_control.then_some(control),
            source_store,
            ontology,
            ontology_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            call_gate: Arc::new(tokio::sync::Semaphore::new(1)),
        });
        // Preparing the selected host proves current Control Query permission and
        // exact publication of the configured config/profile before any model can
        // use the resources. The isolated copy is bounded by the startup deadline.
        let host = bounded(
            startup_deadline,
            Arc::new(AtomicBool::new(false)),
            resources.fresh_graph_host(startup_deadline, Arc::new(AtomicBool::new(false)), false),
        )
        .await?;
        let _ = host.approximate_explicit_labels();
        Ok(resources)
    }

    pub fn begin_turn(&self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .begin_turn();
    }

    pub fn clear_epoch(&self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear_epoch();
    }

    /// Last-turn queries already attempted; this does not access either ledger.
    pub fn last_queries(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queries()
    }

    /// Already-issued citation metadata only. Additional source bytes still need
    /// a fresh protected source-tool call, including after permission changes.
    pub fn citation_details(&self, token: &str) -> Option<serde_json::Value> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .citation(token)
    }

    async fn control_backend(&self) -> Result<Arc<FlureeBackend>> {
        if let Some(control) = &self.control {
            return Ok(control.clone());
        }
        // Unsafe chat releases native Control ownership too, allowing ordinary
        // writers to update both authorities between calls. Source/ontology
        // operations still open current Control and enforce their own policy.
        FlureeBackend::open(self.config.authority_options()?)
            .await
            .map(Arc::new)
            .map_err(|_| Error::new(ErrorKind::Backend, "chat authority unavailable"))
    }

    fn deadline(&self) -> Instant {
        Instant::now()
            + Duration::from_secs(
                self.chat()
                    .limits
                    .host_call_seconds
                    .min(self.config.limits.deadline_seconds) as u64,
            )
    }

    fn max_request_bytes(&self) -> usize {
        self.chat()
            .limits
            .max_request_bytes
            .min(self.config.limits.max_body_bytes)
    }

    fn max_response_bytes(&self) -> usize {
        self.chat()
            .limits
            .max_response_bytes
            .min(self.config.limits.max_body_bytes)
            .min(self.config.limits.run_bytes)
    }

    fn max_source_span_bytes(&self) -> usize {
        self.chat()
            .limits
            .max_source_span_bytes
            .min(self.config.limits.run_bytes)
    }

    async fn enter_call(
        &self,
        cancellation: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<tokio::sync::OwnedSemaphorePermit> {
        bounded(deadline, cancellation, async {
            self.call_gate
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Error::new(ErrorKind::Backend, "chat read queue unavailable"))
        })
        .await
    }

    async fn fresh_lease(
        &self,
        operation: auth::Operation,
        cancellation: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<SessionLease> {
        let credential_file = self.config.credential_file.clone();
        let ttl = self.config.limits.session_ttl();
        let auth = bounded(deadline, cancellation.clone(), async move {
            let table =
                tokio::task::spawn_blocking(move || CredentialTable::load(&credential_file))
                    .await
                    .map_err(|_| Error::new(ErrorKind::Backend, "credential read failed"))??;
            Ok(table.auth_store(ttl)?)
        })
        .await?;
        let session = bounded(deadline, cancellation.clone(), async {
            auth.authenticate(&self.token)
                .await
                .map_err(|_| Error::new(ErrorKind::Denied, "credential unavailable"))
        })
        .await?;
        let principal = bounded(deadline, cancellation.clone(), async {
            auth.principal(&session)
                .await
                .map_err(|_| Error::new(ErrorKind::Denied, "credential unavailable"))
        })
        .await?;
        if principal != self.principal {
            return Err(Error::new(
                ErrorKind::Denied,
                "credential principal changed",
            ));
        }
        bounded(deadline, cancellation, async {
            auth.lease(&session, operation)
                .await
                .map_err(|_| Error::new(ErrorKind::Denied, "credential operation unavailable"))
        })
        .await
    }

    fn chat(&self) -> &crate::config::ChatConfig {
        self.config.chat.as_ref().expect("validated chat config")
    }

    fn reserve_tool(&self, query: bool) -> Result<()> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .reserve_tool(query)
    }

    pub async fn capabilities(&self, cancellation: Arc<AtomicBool>) -> Result<ChatCapabilities> {
        self.reserve_tool(false)?;
        self.capabilities_reserved(cancellation).await
    }

    async fn capabilities_reserved(
        &self,
        cancellation: Arc<AtomicBool>,
    ) -> Result<ChatCapabilities> {
        let deadline = self.deadline();
        let _gate = self.enter_call(cancellation.clone(), deadline).await?;
        let epoch = self.state.lock().unwrap_or_else(|e| e.into_inner()).epoch();
        let lease = self
            .fresh_lease(auth::Operation::Query, cancellation.clone(), deadline)
            .await?;
        let host = self
            .fresh_graph_host(deadline, cancellation.clone(), false)
            .await?;
        let value = ChatCapabilities {
            schema: "ctxql.chat-capabilities/v1",
            graph_permissions: self.graph_permissions(),
            stored_predicate_fields: !self.chat().unsafe_direct_projection,
            restricted_compiler: true,
            approximate_explicit_labels: host.approximate_explicit_labels(),
            custom_predicates: false,
            inventory: self
                .chat()
                .profile
                .is_none()
                .then_some(super::inventory::SCHEMA),
            ontology: if self.ontology.is_some() {
                "verified_public"
            } else {
                "unavailable"
            },
            source_reads: "issued_exact_references_only",
            max_nodes: self.chat().limits.max_nodes,
            max_claims: self.chat().limits.max_claims,
            max_work: self.chat().limits.max_work.min(self.config.limits.max_work),
            max_response_bytes: self.max_response_bytes(),
        };
        let encoded = serde_json::to_vec(&value)
            .map_err(|_| Error::new(ErrorKind::Backend, "chat capability encoding"))?;
        let mut trial = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
        trial.reserve_response(encoded.len())?;
        let disclosed = bounded(
            deadline,
            cancellation.clone(),
            host.guarded_control_action(cancellation, deadline, move || async move { Ok(value) }),
        )
        .await?;
        lease
            .check()
            .map_err(|_| Error::new(ErrorKind::Denied, "credential unavailable"))?;
        self.commit_epoch(epoch, trial)?;
        Ok(disclosed)
    }

    pub async fn graph_query(
        &self,
        request: ChatQueryRequest,
        cancellation: Arc<AtomicBool>,
    ) -> Result<ChatQueryOutcome> {
        self.reserve_tool(true)?;
        self.graph_query_reserved(request, cancellation).await
    }

    async fn graph_query_reserved(
        &self,
        request: ChatQueryRequest,
        cancellation: Arc<AtomicBool>,
    ) -> Result<ChatQueryOutcome> {
        let deadline = self.deadline();
        let _gate = self.enter_call(cancellation.clone(), deadline).await?;
        let epoch = self.state.lock().unwrap_or_else(|e| e.into_inner()).epoch();
        if request.query.len() > self.max_request_bytes() {
            self.log_query_if_current(epoch, &request.query, "invalid")?;
            return Err(Error::limit());
        }
        let lease = self
            .fresh_lease(auth::Operation::Query, cancellation.clone(), deadline)
            .await?;
        let inventory = super::inventory::InventoryRequest::parse(&request.query)?;
        if let Some(inventory) = &inventory {
            let cursor = inventory.cursor_binding()?;
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .validate_inventory_cursor(cursor.as_deref())?;
        }
        let host = self
            .fresh_graph_host(deadline, cancellation.clone(), inventory.is_some())
            .await?;
        lease
            .check()
            .map_err(|_| Error::new(ErrorKind::Denied, "credential unavailable"))?;
        let result = if inventory.is_some() {
            bounded(
                deadline,
                cancellation.clone(),
                host.execute_inventory(cancellation.clone()),
            )
            .await?
        } else {
            bounded(
                deadline,
                cancellation.clone(),
                host.execute(
                    request.query.as_bytes(),
                    cancellation.clone(),
                    self.graph_limits(deadline),
                ),
            )
            .await?
        };
        let execution = match result {
            Ok(result) => result,
            Err(diagnostic) => {
                let public = match diagnostic {
                    GraphQueryDiagnostic::Incomplete => ChatDiagnostic::Incomplete,
                    GraphQueryDiagnostic::Capacity => ChatDiagnostic::Capacity,
                    GraphQueryDiagnostic::QueryTooBroad { cap } => ChatDiagnostic::TooBroad { cap },
                };
                let outcome = ChatQueryOutcome::Diagnostic(public);
                let bytes = serde_json::to_vec(&outcome)
                    .map_err(|_| Error::new(ErrorKind::Backend, "chat diagnostic encoding"))?;
                let mut trial = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
                trial.reserve_response(bytes.len())?;
                trial.log_query(&request.query, diagnostic_name(&outcome))?;
                self.commit_epoch(epoch, trial)?;
                return Ok(outcome);
            }
        };
        let supports = execution.dependencies.clone();
        let mut trial = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let staged = if let Some(inventory) = inventory {
            match super::inventory::project(inventory, execution) {
                Ok(projection) => {
                    let evidence = self.project_query(
                        &mut trial,
                        projection.execution.clone(),
                        &request.query,
                        true,
                    )?;
                    let evidence_bytes = serde_json::to_vec(&evidence)
                        .map_err(|_| Error::invalid("inventory evidence encoding"))?
                        .len();
                    trial.set_inventory_cursor(projection.cursor_binding()?)?;
                    let outcome = projection.finish(evidence);
                    let bytes = serde_json::to_vec(&outcome)
                        .map_err(|_| Error::invalid("inventory page encoding"))?;
                    if bytes.len() > self.max_response_bytes() {
                        return Err(Error::limit());
                    }
                    trial.reserve_response(bytes.len().saturating_sub(evidence_bytes))?;
                    outcome
                }
                Err(error) if error.kind == ErrorKind::Snapshot => {
                    trial.reserve_response(64)?;
                    trial.log_query(&request.query, "inventory_changed")?;
                    ChatQueryOutcome::Diagnostic(ChatDiagnostic::InventoryChanged)
                }
                Err(error) => return Err(error),
            }
        } else {
            ChatQueryOutcome::Complete(Box::new(self.project_query(
                &mut trial,
                execution,
                &request.query,
                false,
            )?))
        };
        let guarded = bounded(
            deadline,
            cancellation.clone(),
            host.guarded_disclosure_action(supports, cancellation, deadline, move || async move {
                Ok(staged)
            }),
        )
        .await?;
        lease
            .check()
            .map_err(|_| Error::new(ErrorKind::Denied, "credential unavailable"))?;
        self.commit_epoch(epoch, trial)?;
        Ok(guarded)
    }

    async fn fresh_graph_host(
        &self,
        deadline: Instant,
        cancellation: Arc<AtomicBool>,
        inventory: bool,
    ) -> Result<ChatGraphHost> {
        let chat = self.chat();
        let control = bounded(deadline, cancellation.clone(), self.control_backend()).await?;
        if chat.unsafe_direct_projection {
            let limits = if inventory {
                self.graph_limits(deadline).for_inventory()
            } else {
                self.graph_limits(deadline)
            };
            return bounded(
                deadline,
                cancellation.clone(),
                DirectProjectionHost::prepare(
                    &self.config,
                    &self.semantic,
                    control.clone(),
                    &self.principal,
                    limits,
                    cancellation,
                    deadline,
                ),
            )
            .await;
        }
        let (path, options) = self.config.semantic_binding()?;
        let binding = bounded(deadline, cancellation.clone(), async {
            ProjectionCheckpoint::new(
                SemanticProjectionSource::head(self.semantic.as_ref()).await?,
                VersionId::new("ctxql-semantic-rdf/v1")?,
                VersionId::new("live")?,
                Iri::new("urn:ctxql:semantic-projection:v1")?,
            )
        })
        .await?;
        let isolated = Arc::new(
            bounded(
                deadline,
                cancellation.clone(),
                IsolatedGraphReadSnapshot::copy_from(
                    self.semantic.as_ref(),
                    path,
                    options,
                    &self.config.projection,
                    binding,
                ),
            )
            .await?,
        );
        let profile = match (&chat.profile_selector, &chat.profile) {
            (Some(selector), Some(reference)) => {
                Some((selector.clone(), reference.artifact_ref()?))
            }
            (None, None) => None,
            _ => return Err(Error::invalid("chat profile binding")),
        };
        bounded(
            deadline,
            cancellation,
            GraphQueryHost::prepare_read_only(
                self.semantic.clone(),
                isolated,
                control.clone(),
                self.principal.clone(),
                "https://ns.flur.ee/db#view".into(),
                chat.query_config.artifact_ref()?,
                profile,
                if inventory {
                    self.graph_limits(deadline).for_inventory()
                } else {
                    self.graph_limits(deadline)
                },
            ),
        )
        .await
        .map(ChatGraphHost::Enforced)
    }

    fn graph_permissions(&self) -> &'static str {
        if self.chat().unsafe_direct_projection {
            "bypassed_unsafe_direct_projection"
        } else {
            "enforced"
        }
    }

    fn graph_limits(&self, deadline: Instant) -> GraphQueryLimits {
        let limits = &self.chat().limits;
        GraphQueryLimits {
            max_nodes: limits.max_nodes,
            max_claims: limits.max_claims,
            max_response_bytes: self.max_response_bytes(),
            max_work: limits.max_work.min(self.config.limits.max_work),
            timeout: deadline.saturating_duration_since(Instant::now()),
        }
    }

    fn project_query(
        &self,
        trial: &mut ChatState,
        execution: AuthorizedQuery,
        query: &str,
        compact: bool,
    ) -> Result<ChatQueryResult> {
        let claims = execution.response.field("claims")?.as_array()?;
        let snapshot = snapshot_binding(&execution.snapshot);
        let mut identities = BTreeSet::new();
        let mut projected_claims = Vec::with_capacity(claims.len());
        let mut source_descriptors = Vec::new();
        for value in claims {
            let meta = value.field("meta")?;
            let claim_id = meta.field("claim_id")?.as_str()?.to_owned();
            let subject = meta.field("subject_id")?.as_str()?.to_owned();
            identities.insert(subject.clone());
            let object = match ClaimObject::from_value(meta.field("object_id")?)? {
                ClaimObject::Entity(id) => {
                    identities.insert(id.as_str().to_owned());
                    ChatObject::Entity {
                        iri: id.as_str().to_owned(),
                    }
                }
                ClaimObject::Literal(literal) => ChatObject::Literal {
                    value: value_json(literal.value())?,
                    datatype: literal.datatype().as_str().to_owned(),
                    language: literal.language().map(str::to_owned),
                },
            };
            let metadata = value_json(meta)?;
            let metadata_binding = serde_json::to_vec(&metadata)
                .map_err(|_| Error::new(ErrorKind::Backend, "claim metadata encoding"))?;
            let binding = format!(
                "{}\0{}\0{}\0{}\0{}\0{}",
                snapshot.backend,
                snapshot.authority,
                snapshot.graph,
                snapshot.revision,
                snapshot.receipt,
                claim_id
            )
            .into_bytes();
            let citation = trial.issue_claim(binding, metadata_binding)?;
            let mut sources = Vec::new();
            if let Some(lineage) = meta.as_object()?.get("lineage") {
                for reference in Lineage::from_value(lineage)?.sources() {
                    let resolvable = reference.version().is_some()
                        && reference.selector().is_some()
                        && reference.content_hash().is_some();
                    let source_citation = if resolvable {
                        let token = trial.issue_source(reference.clone())?;
                        sources.push(token.clone());
                        Some(token)
                    } else {
                        None
                    };
                    if !compact {
                        source_descriptors.push(ChatSourceDescriptor {
                            citation: source_citation,
                            claim_citation: citation.clone(),
                            reference: value_json(&reference.projection())?,
                            resolvable,
                        });
                    }
                }
            }
            projected_claims.push(ChatClaim {
                citation,
                claim_id,
                subject,
                predicate: meta.field("relation")?.as_str()?.to_owned(),
                object,
                metadata: if compact {
                    serde_json::json!({
                        "lifecycle_state":metadata.get("lifecycle_state"),
                        "confidence":metadata.get("confidence"),
                        "grounding_level":metadata.get("grounding_level"),
                    })
                } else {
                    metadata
                },
                sources,
            });
        }
        if let Some(paths) = execution.response.as_object()?.get("paths") {
            for path in paths.as_array()? {
                for node in path.field("node_ids")?.as_array()? {
                    identities.insert(node.as_str()?.to_owned());
                }
            }
        }
        let nodes = identities
            .into_iter()
            .map(|iri| {
                let labels = execution.labels.get(&iri).cloned().unwrap_or_default();
                ChatNode {
                    display_label: labels
                        .first()
                        .map(|label| label.value.clone())
                        .unwrap_or_else(|| iri.clone()),
                    labels: labels
                        .into_iter()
                        .map(|label| ChatLabel { value: label.value })
                        .collect(),
                    iri,
                }
            })
            .collect();
        let (result_id, evicted_result_id) = trial.issue_result();
        let paths = value_json(
            execution
                .response
                .as_object()?
                .get("paths")
                .unwrap_or(&V::Array(Vec::new())),
        )?;
        let diagnostics = value_json(
            execution
                .response
                .as_object()?
                .get("diagnostics")
                .unwrap_or(&V::Object(Default::default())),
        )?;
        let result = ChatQueryResult {
            schema: "ctxql.chat-query-result/v1",
            graph_permissions: self.graph_permissions(),
            result_id: result_id.clone(),
            snapshot,
            query_config: artifact_binding(&execution.query_config),
            profile_selector: execution
                .profile
                .as_ref()
                .map(|(selector, _)| selector.clone()),
            profile: execution
                .profile
                .as_ref()
                .map(|(_, reference)| artifact_binding(reference)),
            complete: true,
            nodes,
            claims: projected_claims,
            paths,
            diagnostics,
            source_references: source_descriptors,
            evicted_result_id,
        };
        let bytes = serde_json::to_vec(&result)
            .map_err(|_| Error::new(ErrorKind::Backend, "chat graph encoding"))?;
        trial.reserve_response(bytes.len())?;
        trial.retain_graph(result_id, bytes)?;
        let outcome = serde_json::to_string(&serde_json::json!({
            "status":"complete", "result_id":result.result_id, "snapshot":result.snapshot,
        }))
        .map_err(|_| Error::invalid("query outcome encoding"))?;
        trial.log_query(query, &outcome)?;
        Ok(result)
    }

    pub async fn source(
        &self,
        request: ChatSourceRequest,
        cancellation: Arc<AtomicBool>,
    ) -> Result<ChatSourceOutcome> {
        self.reserve_tool(false)?;
        self.source_reserved(request, cancellation).await
    }

    async fn source_reserved(
        &self,
        request: ChatSourceRequest,
        cancellation: Arc<AtomicBool>,
    ) -> Result<ChatSourceOutcome> {
        let deadline = self.deadline();
        let _gate = self.enter_call(cancellation.clone(), deadline).await?;
        let epoch = self.state.lock().unwrap_or_else(|e| e.into_inner()).epoch();
        let reference = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .source(&request.reference)?;
        let max_bytes = request.max_bytes.unwrap_or(self.max_source_span_bytes());
        if max_bytes == 0 || max_bytes > self.max_source_span_bytes() {
            return Err(Error::limit());
        }
        let lease = self
            .fresh_lease(auth::Operation::Read, cancellation.clone(), deadline)
            .await?;
        let control = bounded(deadline, cancellation.clone(), self.control_backend()).await?;
        let native = bounded(deadline, cancellation.clone(), async {
            control
                .issue_principal(self.principal.clone())
                .await
                .map_err(|_| Error::new(ErrorKind::Denied, "Control principal unavailable"))
        })
        .await?;
        let context = bounded(deadline, cancellation.clone(), control.current(&native)).await?;
        control.require_operation(&context, Operation::Read)?;
        let capture = bounded(
            deadline,
            cancellation.clone(),
            GraphBackend::head(control.as_ref()),
        )
        .await?;
        let sources = Arc::new(AuthorizedSources::new(
            control.clone(),
            control.clone(),
            Arc::new(native.clone()),
            self.source_store.clone(),
        ));
        sources.bind_snapshot(&capture)?;
        let read = match bounded(
            deadline,
            cancellation.clone(),
            sources.read_reference(&reference, max_bytes),
        )
        .await
        {
            Ok(read) => read,
            Err(error) if error.kind == ErrorKind::Limit => {
                let outcome = ChatSourceOutcome::Diagnostic(ChatDiagnostic::SourceTooLarge);
                let bytes = serde_json::to_vec(&outcome)
                    .map_err(|_| Error::invalid("source diagnostic"))?;
                let mut trial = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
                trial.reserve_response(bytes.len())?;
                let (send, receive) = tokio::sync::oneshot::channel();
                bounded(
                    deadline,
                    cancellation.clone(),
                    control.clone().guarded_owned_release(
                        native,
                        context,
                        Operation::Read,
                        None,
                        Box::new(ReadFence {
                            lease,
                            cancellation,
                            deadline,
                        }),
                        move || {
                            send.send(outcome).map_err(|_| {
                                Error::new(ErrorKind::Backend, "chat source diagnostic sink")
                            })
                        },
                    ),
                )
                .await?;
                let outcome = bounded(deadline, Arc::new(AtomicBool::new(false)), async {
                    receive.await.map_err(|_| {
                        Error::new(ErrorKind::Backend, "chat source diagnostic unavailable")
                    })
                })
                .await?;
                self.commit_epoch(epoch, trial)?;
                return Ok(outcome);
            }
            Err(error) => return Err(error),
        };
        let text = std::str::from_utf8(read.bytes())
            .map_err(|_| Error::invalid("source encoding"))?
            .to_owned();
        let mut trial = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
        trial.reserve_source_bytes(text.len())?;
        let result = ChatSourceResult {
            schema: "ctxql.chat-source-result/v1",
            citation: request.reference,
            reference: value_json(&reference.projection())?,
            content: text,
        };
        let encoded = serde_json::to_vec(&result)
            .map_err(|_| Error::new(ErrorKind::Backend, "chat source encoding"))?;
        trial.reserve_response(encoded.len())?;
        let (send, receive) = tokio::sync::oneshot::channel();
        bounded(
            deadline,
            cancellation.clone(),
            control.clone().guarded_owned_release(
                native,
                context,
                Operation::Read,
                None,
                Box::new(ReadFence {
                    lease,
                    cancellation,
                    deadline,
                }),
                move || {
                    send.send(result)
                        .map_err(|_| Error::new(ErrorKind::Backend, "chat source sink"))
                },
            ),
        )
        .await?;
        let result = bounded(deadline, Arc::new(AtomicBool::new(false)), async {
            receive
                .await
                .map_err(|_| Error::new(ErrorKind::Backend, "chat source unavailable"))
        })
        .await?;
        self.commit_epoch(epoch, trial)?;
        Ok(ChatSourceOutcome::Complete(result))
    }

    pub async fn ontology(
        &self,
        request: ChatOntologyRequest,
        cancellation: Arc<AtomicBool>,
    ) -> Result<V> {
        self.reserve_tool(false)?;
        self.ontology_reserved(request, cancellation).await
    }

    async fn ontology_reserved(
        &self,
        request: ChatOntologyRequest,
        cancellation: Arc<AtomicBool>,
    ) -> Result<V> {
        let deadline = self.deadline();
        let _gate = self.enter_call(cancellation.clone(), deadline).await?;
        let epoch = self.state.lock().unwrap_or_else(|e| e.into_inner()).epoch();
        let lease = self
            .fresh_lease(auth::Operation::Query, cancellation.clone(), deadline)
            .await?;
        let control = bounded(deadline, cancellation.clone(), self.control_backend()).await?;
        let native = bounded(deadline, cancellation.clone(), async {
            control
                .issue_principal(self.principal.clone())
                .await
                .map_err(|_| Error::new(ErrorKind::Denied, "Control principal unavailable"))
        })
        .await?;
        let context = bounded(deadline, cancellation.clone(), control.current(&native)).await?;
        control.require_operation(&context, Operation::Query)?;
        let Some(host) = self.ontology.clone() else {
            let value = V::Object(std::collections::BTreeMap::from([
                ("schema".into(), V::string("ctxql.chat-ontology-result/v1")),
                ("status".into(), V::string("ontology_unavailable")),
            ]));
            let bytes = value.canonical_bytes(Limits::default())?;
            let mut trial = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
            trial.reserve_response(bytes.len())?;
            let (send, receive) = tokio::sync::oneshot::channel();
            bounded(
                deadline,
                cancellation.clone(),
                control.clone().guarded_owned_release(
                    native,
                    context,
                    Operation::Query,
                    None,
                    Box::new(ReadFence {
                        lease,
                        cancellation,
                        deadline,
                    }),
                    move || {
                        send.send(value).map_err(|_| {
                            Error::new(ErrorKind::Backend, "chat ontology status sink")
                        })
                    },
                ),
            )
            .await?;
            let value = bounded(deadline, Arc::new(AtomicBool::new(false)), async {
                receive
                    .await
                    .map_err(|_| Error::new(ErrorKind::Backend, "chat ontology status unavailable"))
            })
            .await?;
            self.commit_epoch(epoch, trial)?;
            return Ok(value);
        };
        let permit = bounded(deadline, cancellation.clone(), async {
            self.ontology_gate
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Error::new(ErrorKind::Backend, "ontology queue unavailable"))
        })
        .await?;
        let json = serde_json::to_value(request).map_err(|_| Error::invalid("ontology request"))?;
        let native_cancellation = cancellation.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            host.lookup_with_budget(&json, native_cancellation, deadline)
                .map_err(|_| Error::new(ErrorKind::Denied, "ontology lookup unavailable"))
        });
        let value = bounded(deadline, cancellation.clone(), async {
            result
                .await
                .map_err(|_| Error::new(ErrorKind::Backend, "ontology lookup task failed"))?
        })
        .await?;
        lease
            .check()
            .map_err(|_| Error::new(ErrorKind::Denied, "credential unavailable"))?;
        let fresh = bounded(deadline, cancellation.clone(), control.current(&native)).await?;
        control.require_operation(&fresh, Operation::Query)?;
        let bytes = serde_json::to_vec(&value).map_err(|_| Error::invalid("ontology response"))?;
        let mut trial = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
        trial.reserve_response(bytes.len())?;
        let (send, receive) = tokio::sync::oneshot::channel();
        bounded(
            deadline,
            cancellation.clone(),
            control.clone().guarded_owned_release(
                native,
                context,
                Operation::Query,
                None,
                Box::new(ReadFence {
                    lease,
                    cancellation,
                    deadline,
                }),
                move || {
                    send.send(value)
                        .map_err(|_| Error::new(ErrorKind::Backend, "chat ontology sink"))
                },
            ),
        )
        .await?;
        let value = bounded(deadline, Arc::new(AtomicBool::new(false)), async {
            receive
                .await
                .map_err(|_| Error::new(ErrorKind::Backend, "chat ontology unavailable"))
        })
        .await?;
        self.commit_epoch(epoch, trial)?;
        V::parse(
            &serde_json::to_vec(&value).map_err(|_| Error::invalid("ontology response"))?,
            Limits::default(),
        )
    }

    /// Closed Rust-side dispatcher. Parsing uses CanonicalValue first so duplicate
    /// object keys are rejected rather than silently accepted by serde_json.
    pub async fn dispatch_tool(
        &self,
        tool: &str,
        request: &[u8],
        cancellation: Arc<AtomicBool>,
    ) -> Result<serde_json::Value> {
        // One non-refundable reservation for every invocation, before any parsing
        // or response work. Exhaustion is terminal even for malformed requests.
        self.reserve_tool(tool == "ctxql_graph_query")?;
        if request.len() > self.max_request_bytes() {
            return self.sanitized_error(Error::limit(), &cancellation);
        }
        match tool {
            "ctxql_capabilities" => {
                if let Err(error) = Self::parse_request::<EmptyRequest>(request) {
                    return self.sanitized_error(error, &cancellation);
                }
                match self.capabilities_reserved(cancellation.clone()).await {
                    Ok(value) => serde_json::to_value(value)
                        .map_err(|_| Error::invalid("capability response")),
                    Err(error) => self.sanitized_error(error, &cancellation),
                }
            }
            "ctxql_graph_query" => {
                let value: ChatQueryRequest = match Self::parse_request(request) {
                    Ok(value) => value,
                    Err(error) => return self.sanitized_error(error, &cancellation),
                };
                let exact_query = value.query.clone();
                match self.graph_query_reserved(value, cancellation.clone()).await {
                    Ok(value) => {
                        serde_json::to_value(value).map_err(|_| Error::invalid("query response"))
                    }
                    Err(error) => {
                        let outcome = sanitized_diagnostic(&error, &cancellation);
                        let _ = self
                            .state
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .log_query(&exact_query, diagnostic_label(&outcome));
                        self.sanitized_value(outcome)
                    }
                }
            }
            "ctxql_ontology" => {
                let value: ChatOntologyRequest = match Self::parse_request(request) {
                    Ok(value) => value,
                    Err(error) => return self.sanitized_error(error, &cancellation),
                };
                match self.ontology_reserved(value, cancellation.clone()).await {
                    Ok(value) => value_json(&value),
                    Err(error) => self.sanitized_error(error, &cancellation),
                }
            }
            "ctxql_source" => {
                let value: ChatSourceRequest = match Self::parse_request(request) {
                    Ok(value) => value,
                    Err(error) => return self.sanitized_error(error, &cancellation),
                };
                match self.source_reserved(value, cancellation.clone()).await {
                    Ok(value) => {
                        serde_json::to_value(value).map_err(|_| Error::invalid("source response"))
                    }
                    Err(error) => self.sanitized_error(error, &cancellation),
                }
            }
            _ => self.sanitized_error(
                Error::new(ErrorKind::Denied, "chat tool unavailable"),
                &cancellation,
            ),
        }
    }

    fn parse_request<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        let canonical = V::parse(bytes, Limits::default())?.canonical_bytes(Limits::default())?;
        serde_json::from_slice(&canonical).map_err(|_| Error::invalid("invalid chat tool request"))
    }

    fn sanitized_error(
        &self,
        error: Error,
        cancellation: &AtomicBool,
    ) -> Result<serde_json::Value> {
        self.sanitized_value(sanitized_diagnostic(&error, cancellation))
    }

    fn sanitized_value(&self, diagnostic: ChatDiagnostic) -> Result<serde_json::Value> {
        let value = serde_json::to_value(diagnostic)
            .map_err(|_| Error::new(ErrorKind::Backend, "chat diagnostic encoding"))?;
        let bytes = serde_json::to_vec(&value)
            .map_err(|_| Error::new(ErrorKind::Backend, "chat diagnostic encoding"))?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .reserve_response(bytes.len())?;
        Ok(value)
    }

    fn commit_epoch(&self, epoch: u64, trial: ChatState) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.epoch() != epoch || state.revision() != trial.revision() {
            return Err(Error::new(ErrorKind::Denied, "chat state changed"));
        }
        *state = trial;
        Ok(())
    }

    fn log_query_if_current(&self, epoch: u64, query: &str, outcome: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.epoch() != epoch {
            return Err(Error::new(ErrorKind::Denied, "chat epoch changed"));
        }
        state.log_query(query, outcome)
    }
}

async fn bounded<T, F>(deadline: Instant, cancellation: Arc<AtomicBool>, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    check_available(&cancellation, deadline)?;
    tokio::select! {
        value = future => value,
        _ = wait_cancelled(cancellation.clone(), deadline) => {
            if cancellation.load(std::sync::atomic::Ordering::Acquire) {
                Err(Error::new(ErrorKind::Deadline, "chat read cancelled"))
            } else {
                Err(Error::new(ErrorKind::Deadline, "chat read deadline"))
            }
        }
    }
}

pub(super) fn check_available(cancellation: &AtomicBool, deadline: Instant) -> Result<()> {
    if cancellation.load(std::sync::atomic::Ordering::Acquire) {
        Err(Error::new(ErrorKind::Deadline, "chat read cancelled"))
    } else if Instant::now() >= deadline {
        Err(Error::new(ErrorKind::Deadline, "chat read deadline"))
    } else {
        Ok(())
    }
}

async fn wait_cancelled(cancellation: Arc<AtomicBool>, deadline: Instant) {
    loop {
        if cancellation.load(std::sync::atomic::Ordering::Acquire) || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn sanitized_diagnostic(error: &Error, cancellation: &AtomicBool) -> ChatDiagnostic {
    match error.kind {
        ErrorKind::Denied | ErrorKind::PolicyChanged => ChatDiagnostic::Denied,
        ErrorKind::Deadline if cancellation.load(std::sync::atomic::Ordering::Acquire) => {
            ChatDiagnostic::Cancelled
        }
        ErrorKind::Deadline => ChatDiagnostic::Timeout,
        ErrorKind::Limit if error.message == "execution work-unit limit" => {
            ChatDiagnostic::CapacityAt {
                stage: "internal_work",
            }
        }
        ErrorKind::Limit if error.message == "execution retained-byte limit" => {
            ChatDiagnostic::CapacityAt {
                stage: "internal_retained_bytes",
            }
        }
        ErrorKind::Limit | ErrorKind::Range | ErrorKind::Arithmetic => ChatDiagnostic::Capacity,
        ErrorKind::Invalid => ChatDiagnostic::Invalid,
        ErrorKind::Unsupported
        | ErrorKind::NotFound
        | ErrorKind::Conflict
        | ErrorKind::Snapshot
        | ErrorKind::Backend => ChatDiagnostic::Unavailable,
    }
}

fn diagnostic_label(diagnostic: &ChatDiagnostic) -> &'static str {
    match diagnostic {
        ChatDiagnostic::Incomplete => "incomplete",
        ChatDiagnostic::TooBroad { .. } => "too_broad",
        ChatDiagnostic::Capacity | ChatDiagnostic::CapacityAt { .. } => "capacity",
        ChatDiagnostic::Timeout => "timeout",
        ChatDiagnostic::Cancelled => "cancelled",
        ChatDiagnostic::Denied => "denied",
        ChatDiagnostic::Invalid => "invalid",
        ChatDiagnostic::Unavailable => "unavailable",
        ChatDiagnostic::SourceTooLarge => "source_too_large",
        ChatDiagnostic::InventoryChanged => "inventory_changed",
    }
}

fn diagnostic_name(outcome: &ChatQueryOutcome) -> &'static str {
    match outcome {
        ChatQueryOutcome::Complete(_) => "complete",
        ChatQueryOutcome::Inventory(_) => "inventory_page",
        ChatQueryOutcome::Diagnostic(ChatDiagnostic::InventoryChanged) => "inventory_changed",
        ChatQueryOutcome::Diagnostic(ChatDiagnostic::Incomplete) => "incomplete",
        ChatQueryOutcome::Diagnostic(ChatDiagnostic::TooBroad { .. }) => "too_broad",
        ChatQueryOutcome::Diagnostic(
            ChatDiagnostic::Capacity | ChatDiagnostic::CapacityAt { .. },
        ) => "capacity",
        ChatQueryOutcome::Diagnostic(ChatDiagnostic::Timeout) => "timeout",
        ChatQueryOutcome::Diagnostic(ChatDiagnostic::Cancelled) => "cancelled",
        ChatQueryOutcome::Diagnostic(ChatDiagnostic::Denied) => "denied",
        ChatQueryOutcome::Diagnostic(ChatDiagnostic::Invalid) => "invalid",
        ChatQueryOutcome::Diagnostic(ChatDiagnostic::Unavailable) => "unavailable",
        ChatQueryOutcome::Diagnostic(ChatDiagnostic::SourceTooLarge) => "source_too_large",
    }
}

pub(super) fn value_json(value: &V) -> Result<serde_json::Value> {
    serde_json::from_slice(&value.canonical_bytes(Limits::default())?)
        .map_err(|_| Error::invalid("chat canonical value encoding"))
}

pub(super) fn artifact_binding(reference: &ArtifactRef) -> ArtifactBinding {
    ArtifactBinding {
        iri: reference.iri().as_str().to_owned(),
        version: reference.version().as_str().to_owned(),
        hash: reference.hash().as_str().to_owned(),
    }
}

pub(super) fn snapshot_binding(snapshot: &SnapshotRef) -> SnapshotBinding {
    SnapshotBinding {
        backend: snapshot.backend().as_str().to_owned(),
        authority: snapshot.pin().authority().as_str().to_owned(),
        graph: snapshot.pin().graph().as_str().to_owned(),
        revision: snapshot.pin().revision().as_str().to_owned(),
        receipt: snapshot.pin().receipt().as_str().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
    include!("inventory_tests.rs");
}

#[cfg(test)]
mod paid_quality {
    include!("paid_quality.rs");
}
