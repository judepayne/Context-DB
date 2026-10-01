//! Serialized document workspace with query work staged outside the state lock.

use crate::{
    graph_context::{GazetteerContext, GraphContextManifest},
    graph_query::{GraphQueryDiagnostic, GraphQueryHost, GraphQueryLimits},
    graph_workspace::{
        ApplyRequest, ApplyResult, CheckResponse, DocumentContext, Handle, ViewKind, ViewResponse,
        Workspace, WorkspaceLimits,
    },
};
use cdb_core::{id::ContentHash, CanonicalValue, Error, ErrorKind, Limits, Result};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

const ACTIVE: u8 = 0;
const COMPLETED: u8 = 1;
const CANCELLED: u8 = 2;
const EXHAUSTED: u8 = 3;
const AUTHORITY_INVALIDATED: u8 = 4;

#[derive(Clone, Debug, Serialize)]
pub(crate) enum SessionQueryResult {
    Graph {
        handle: Handle,
        snapshot: String,
        node_count: usize,
        claim_count: usize,
        complete: bool,
        overview: String,
    },
    Diagnostic(GraphQueryDiagnostic),
}

#[derive(Clone)]
struct SessionState {
    workspace: Workspace,
    context: GraphContextManifest,
    graph_payload_roots: BTreeMap<Handle, ContentHash>,
}

#[derive(Clone)]
struct SessionDocumentContext {
    evidence: Arc<BTreeSet<String>>,
    cancelled: Arc<AtomicBool>,
}
impl DocumentContext for SessionDocumentContext {
    fn owns_evidence(&self, handle: &str) -> bool {
        self.evidence.contains(handle)
    }
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub(crate) struct GraphSession {
    issuer: String,
    session_id: String,
    query: Arc<GraphQueryHost>,
    state: Mutex<SessionState>,
    action_gate: tokio::sync::Mutex<()>,
    document: SessionDocumentContext,
    status: AtomicU8,
    cancellation: Arc<AtomicBool>,
    deadline: Instant,
}

impl GraphSession {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        issuer: String,
        session_id: String,
        attempt_id: String,
        source_version: String,
        source_range_root: String,
        evidence: BTreeSet<String>,
        query: Arc<GraphQueryHost>,
        workspace_limits: WorkspaceLimits,
        deadline: Instant,
    ) -> Result<Arc<Self>> {
        Self::new_with_gazetteer(
            issuer,
            session_id,
            attempt_id,
            source_version,
            source_range_root,
            evidence,
            None,
            query,
            workspace_limits,
            deadline,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_gazetteer(
        issuer: String,
        session_id: String,
        attempt_id: String,
        source_version: String,
        source_range_root: String,
        evidence: BTreeSet<String>,
        gazetteer: Option<GazetteerContext>,
        query: Arc<GraphQueryHost>,
        workspace_limits: WorkspaceLimits,
        deadline: Instant,
    ) -> Result<Arc<Self>> {
        let workspace =
            Workspace::new(&issuer, &session_id, workspace_limits).map_err(map_workspace)?;
        let mut context = GraphContextManifest::new(
            issuer.clone(),
            session_id.clone(),
            attempt_id,
            source_version,
            source_range_root,
            query.snapshot_binding(),
        );
        if let Some(gazetteer) = gazetteer {
            context.retain_gazetteer(gazetteer)?;
        }
        let cancellation = Arc::new(AtomicBool::new(false));
        Ok(Arc::new(Self {
            issuer,
            session_id,
            query,
            state: Mutex::new(SessionState {
                workspace,
                context,
                graph_payload_roots: BTreeMap::new(),
            }),
            action_gate: tokio::sync::Mutex::new(()),
            document: SessionDocumentContext {
                evidence: Arc::new(evidence),
                cancelled: cancellation.clone(),
            },
            status: AtomicU8::new(ACTIVE),
            cancellation,
            deadline,
        }))
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    pub(crate) fn query_host(&self) -> Arc<GraphQueryHost> {
        self.query.clone()
    }

    fn check_active(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            self.cancel();
        }
        match self.status.load(Ordering::Acquire) {
            ACTIVE => Ok(()),
            CANCELLED => Err(Error::new(ErrorKind::Deadline, "graph session cancelled")),
            AUTHORITY_INVALIDATED => {
                Err(Error::new(ErrorKind::Denied, "graph session unavailable"))
            }
            EXHAUSTED => Err(Error::limit()),
            COMPLETED => Err(Error::new(ErrorKind::Conflict, "graph session completed")),
            _ => Err(Error::new(ErrorKind::Backend, "graph session state")),
        }
    }

    fn invalidate_authority(&self) {
        self.cancellation.store(true, Ordering::Release);
        self.status.store(AUTHORITY_INVALIDATED, Ordering::Release);
    }

    fn account_error_response(&self, error: &Error) -> Result<()> {
        let response_bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "ctxql-graph-tool-error/v1",
            "status": "error",
            "code": error.public_code(),
        }))
        .map_err(|_| Error::new(ErrorKind::Backend, "graph error response encoding"))?
        .len();
        self.state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Backend, "graph session lock"))?
            .workspace
            .finish_call_bytes(response_bytes)
            .map_err(map_workspace)
    }

    fn account_and_map_error(&self, error: Error) -> Error {
        match self.account_error_response(&error) {
            Ok(()) => self.map_operation_error(error),
            Err(accounting) => self.map_operation_error(accounting),
        }
    }

    fn map_operation_error(&self, error: Error) -> Error {
        if error.kind == ErrorKind::Limit {
            self.cancellation.store(true, Ordering::Release);
            self.status.store(EXHAUSTED, Ordering::Release);
        } else if matches!(error.kind, ErrorKind::Denied | ErrorKind::PolicyChanged) {
            self.invalidate_authority();
        }
        error
    }

    fn begin_call(&self, request_bytes: usize, graph_query: bool) -> Result<u64> {
        self.check_active()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Backend, "graph session lock"))?;
        state
            .workspace
            .begin_call(request_bytes, graph_query)
            .map_err(map_workspace)
            .map_err(|error| self.map_operation_error(error))?;
        let context_bytes = state.context.retained_bytes()?;
        state
            .workspace
            .ensure_context_bytes(context_bytes)
            .map_err(map_workspace)
            .map_err(|error| self.map_operation_error(error))?;
        Ok(state.workspace.revision())
    }

    fn dependencies(&self) -> Result<BTreeSet<String>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Backend, "graph session lock"))?
            .context
            .disclosed()
            .clone())
    }

    async fn guarded_state_action<T, F>(self: &Arc<Self>, action: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut SessionState) -> Result<T> + Send + 'static,
    {
        self.check_active()?;
        let dependencies = self.dependencies()?;
        let session = self.clone();
        let result = self
            .query
            .guarded_disclosure_action(
                dependencies,
                self.cancellation.clone(),
                self.deadline,
                move || async move {
                    session.check_active()?;
                    let mut state = session
                        .state
                        .lock()
                        .map_err(|_| Error::new(ErrorKind::Backend, "graph session lock"))?;
                    action(&mut state)
                },
            )
            .await;
        result.map_err(|error| self.account_and_map_error(error))
    }

    pub(crate) async fn query(
        self: &Arc<Self>,
        inline: &[u8],
        mut limits: GraphQueryLimits,
    ) -> Result<SessionQueryResult> {
        let _action = self.action_gate.lock().await;
        let revision = self.begin_call(inline.len(), true)?;
        self.guarded_state_action(|_| Ok(())).await?;
        limits.timeout = limits
            .timeout
            .min(self.deadline.saturating_duration_since(Instant::now()));
        let result = self
            .query
            .query(
                &self.issuer,
                &self.session_id,
                inline,
                self.cancellation.clone(),
                limits,
            )
            .await;
        let result = match result {
            Ok(result) => result,
            Err(error) => return Err(self.account_and_map_error(error)),
        };
        let authorized = match result {
            Ok(graph) => graph,
            Err(diagnostic) => {
                let response = SessionQueryResult::Diagnostic(diagnostic);
                let bytes = serde_json::to_vec(&response)
                    .map_err(|_| Error::new(ErrorKind::Backend, "query diagnostic encoding"))?
                    .len();
                self.guarded_state_action(move |state| {
                    state
                        .workspace
                        .finish_call_bytes(bytes)
                        .map_err(map_workspace)?;
                    Ok(())
                })
                .await?;
                return Ok(response);
            }
        };
        let node_count = authorized.graph.nodes.len();
        let claim_count = authorized.graph.claims.len();
        let encoded_graph = serde_json::to_vec(&authorized.graph)
            .map_err(|_| Error::new(ErrorKind::Backend, "graph result encoding"))?;
        let encoded_graph = CanonicalValue::parse(&encoded_graph, Limits::default())?
            .canonical_bytes(Limits::default())?;
        let graph_bytes = encoded_graph.len();
        let graph_payload_root = ContentHash::of_bytes(&encoded_graph);
        let session = self.clone();
        let mut disclosure_dependencies = self.dependencies()?;
        disclosure_dependencies.extend(authorized.dependencies.iter().cloned());
        let result =
            self.query
                .guarded_disclosure_action(
                    disclosure_dependencies,
                    self.cancellation.clone(),
                    self.deadline,
                    move || async move {
                        let mut state = session
                            .state
                            .lock()
                            .map_err(|_| Error::new(ErrorKind::Backend, "graph session lock"))?;
                        if state.workspace.revision() != revision {
                            return Err(Error::new(
                                ErrorKind::Conflict,
                                "workspace changed during query",
                            ));
                        }
                        let mut staged = state.clone();
                        let handle = staged
                            .workspace
                            .register_graph(authorized.graph)
                            .map_err(map_workspace)?;
                        staged
                            .context
                            .retain_graph(&handle.0, authorized.dependencies)?;
                        staged
                            .graph_payload_roots
                            .insert(handle.clone(), graph_payload_root);
                        let context_bytes = staged.context.retained_bytes()?;
                        staged
                            .workspace
                            .ensure_context_bytes(context_bytes)
                            .map_err(map_workspace)?;
                        staged
                            .workspace
                            .finish_call_bytes(graph_bytes)
                            .map_err(map_workspace)?;
                        let issued = staged.workspace.issued_graph(&handle).ok_or_else(|| {
                            Error::new(ErrorKind::Backend, "issued graph missing")
                        })?;
                        let snapshot = issued.snapshot.clone();
                        let mut overview = format!(
                            "COMPLETE GRAPH {} / {} nodes / {} claims\n",
                            handle.0, node_count, claim_count
                        );
                        for node in issued.nodes.iter().take(8) {
                            overview.push_str(&format!(
                                "NODE {}: {} [{}]\n",
                                node.key, node.label, node.canonical_iri
                            ));
                        }
                        let omitted = node_count.saturating_sub(8);
                        if omitted != 0 {
                            overview.push_str(&format!(
                                "VIEW ONLY: {omitted} nodes omitted from overview\n"
                            ));
                        }
                        *state = staged;
                        Ok(SessionQueryResult::Graph {
                            handle,
                            snapshot,
                            node_count,
                            claim_count,
                            complete: true,
                            overview,
                        })
                    },
                )
                .await;
        result.map_err(|error| self.account_and_map_error(error))
    }

    pub(crate) async fn import_graph(
        self: &Arc<Self>,
        handle: &Handle,
    ) -> Result<BTreeMap<String, Handle>> {
        let _action = self.action_gate.lock().await;
        let request_bytes = serde_json::to_vec(handle)
            .map_err(|_| Error::invalid("import request encoding"))?
            .len();
        self.begin_call(request_bytes, false)?;
        let handle = handle.clone();
        self.guarded_state_action(move |state| {
            let mut staged = state.clone();
            let result = staged
                .workspace
                .import_graph(&handle)
                .map_err(map_workspace)?;
            let bytes = serde_json::to_vec(&result)
                .map_err(|_| Error::invalid("import response encoding"))?
                .len();
            staged
                .workspace
                .finish_call_bytes(bytes)
                .map_err(map_workspace)?;
            *state = staged;
            Ok(result)
        })
        .await
    }

    pub(crate) async fn release_graph(self: &Arc<Self>, handle: &Handle) -> Result<()> {
        let _action = self.action_gate.lock().await;
        let request_bytes = serde_json::to_vec(handle)
            .map_err(|_| Error::invalid("release request encoding"))?
            .len();
        self.begin_call(request_bytes, false)?;
        let handle = handle.clone();
        self.guarded_state_action(move |state| {
            let mut staged = state.clone();
            staged
                .workspace
                .release_graph(&handle)
                .map_err(map_workspace)?;
            staged.graph_payload_roots.remove(&handle);
            staged
                .workspace
                .finish_call_bytes(2)
                .map_err(map_workspace)?;
            *state = staged;
            Ok(())
        })
        .await
    }

    pub(crate) async fn apply(self: &Arc<Self>, request: ApplyRequest) -> Result<ApplyResult> {
        let _action = self.action_gate.lock().await;
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|_| Error::invalid("apply request encoding"))?
            .len();
        self.begin_call(request_bytes, false)?;
        let document = self.document.clone();
        self.guarded_state_action(move |state| {
            let mut staged = state.clone();
            let result = staged
                .workspace
                .apply_preaccounted(request, &document)
                .map_err(map_workspace)?;
            let context_bytes = staged.context.retained_bytes()?;
            staged
                .workspace
                .ensure_context_bytes(context_bytes)
                .map_err(map_workspace)?;
            *state = staged;
            Ok(result)
        })
        .await
    }

    pub(crate) async fn view(
        self: &Arc<Self>,
        kind: ViewKind,
        max_bytes: Option<usize>,
    ) -> Result<ViewResponse> {
        let _action = self.action_gate.lock().await;
        let request_bytes = serde_json::to_vec(&(kind.clone(), max_bytes))
            .map_err(|_| Error::invalid("view request encoding"))?
            .len();
        self.begin_call(request_bytes, false)?;
        self.guarded_state_action(move |state| {
            let mut staged = state.clone();
            let response = staged
                .workspace
                .view(kind, max_bytes)
                .map_err(map_workspace)?;
            let bytes = serde_json::to_vec(&response)
                .map_err(|_| Error::invalid("view response encoding"))?
                .len();
            staged
                .workspace
                .finish_call_bytes(bytes)
                .map_err(map_workspace)?;
            *state = staged;
            Ok(response)
        })
        .await
    }

    pub(crate) async fn inspect(
        self: &Arc<Self>,
        handle: Handle,
        max_bytes: Option<usize>,
    ) -> Result<ViewResponse> {
        self.view(ViewKind::Neighbourhood { centre: handle }, max_bytes)
            .await
    }

    pub(crate) async fn check(self: &Arc<Self>) -> Result<CheckResponse> {
        let _action = self.action_gate.lock().await;
        self.begin_call(2, false)?;
        self.guarded_state_action(move |state| {
            let mut staged = state.clone();
            let response = staged.workspace.check().map_err(map_workspace)?;
            let bytes = serde_json::to_vec(&response)
                .map_err(|_| Error::invalid("check response encoding"))?
                .len();
            staged
                .workspace
                .finish_call_bytes(bytes)
                .map_err(map_workspace)?;
            *state = staged;
            Ok(response)
        })
        .await
    }

    pub(crate) fn capture_state(&self) -> Result<(u64, CanonicalValue, GraphContextManifest)> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Backend, "graph session lock"))?;
        Ok((
            state.workspace.revision(),
            state.workspace.capture_projection()?,
            state.context.clone(),
        ))
    }

    pub(crate) fn graph_dependencies(&self, handle: &Handle) -> Result<BTreeSet<String>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Backend, "graph session lock"))?
            .context
            .graph_dependencies(&handle.0)
            .cloned()
            .unwrap_or_default())
    }

    pub(crate) fn graph_payload_root(&self, handle: &Handle) -> Result<Option<ContentHash>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Backend, "graph session lock"))?
            .graph_payload_roots
            .get(handle)
            .cloned())
    }

    pub(crate) fn graph_payload(&self, handle: &Handle) -> Result<Option<Vec<u8>>> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Backend, "graph session lock"))?;
        state
            .workspace
            .issued_graph(handle)
            .map(|graph| {
                let bytes = serde_json::to_vec(graph)
                    .map_err(|_| Error::new(ErrorKind::Backend, "graph payload encoding"))?;
                CanonicalValue::parse(&bytes, Limits::default())?.canonical_bytes(Limits::default())
            })
            .transpose()
    }

    pub(crate) fn graph_payloads(&self) -> Result<BTreeMap<String, serde_json::Value>> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Backend, "graph session lock"))?;
        let mut payloads = BTreeMap::new();
        for (handle, root) in &state.graph_payload_roots {
            let issued = state
                .workspace
                .issued_graph(handle)
                .ok_or_else(|| Error::new(ErrorKind::Backend, "graph payload missing"))?;
            let value = serde_json::to_value(issued)
                .map_err(|_| Error::new(ErrorKind::Backend, "graph payload encoding"))?;
            if payloads.insert(root.as_str().to_owned(), value).is_some() {
                return Err(Error::new(ErrorKind::Conflict, "graph payload root reused"));
            }
        }
        Ok(payloads)
    }

    pub(crate) fn workspace_root(&self) -> Result<ContentHash> {
        let (_, value, _) = self.capture_state()?;
        Ok(ContentHash::of_bytes(
            &value.canonical_bytes(Limits::default())?,
        ))
    }

    pub(crate) async fn authorize_final_release(self: &Arc<Self>) -> Result<BTreeSet<String>> {
        let _action = self.action_gate.lock().await;
        self.check_active()?;
        let dependencies = self.dependencies()?;
        let released = dependencies.clone();
        self.query
            .guarded_disclosure_action(
                dependencies,
                self.cancellation.clone(),
                self.deadline,
                move || async move { Ok(released) },
            )
            .await
            .map_err(|error| self.map_operation_error(error))
    }

    /// Hold current Control authority while the supplied admission callback
    /// performs its own exact dependency check under the Semantic writer fence.
    pub(crate) async fn guarded_final_action<T, F, Fut>(self: &Arc<Self>, action: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(BTreeSet<String>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        let _serial = self.action_gate.lock().await;
        let dependencies = self.dependencies()?;
        let callback_dependencies = dependencies.clone();
        self.query
            .guarded_control_action(self.cancellation.clone(), self.deadline, move || {
                action(callback_dependencies)
            })
            .await
            .map_err(|error| self.map_operation_error(error))
    }

    pub(crate) fn cancel(&self) {
        self.cancellation.store(true, Ordering::Release);
        let _ =
            self.status
                .compare_exchange(ACTIVE, CANCELLED, Ordering::AcqRel, Ordering::Acquire);
    }

    pub(crate) fn complete(&self) -> Result<()> {
        self.check_active()?;
        self.status
            .compare_exchange(ACTIVE, COMPLETED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::new(ErrorKind::Conflict, "graph session terminal"))?;
        Ok(())
    }
}

fn map_workspace(error: crate::graph_workspace::Error) -> Error {
    match error {
        crate::graph_workspace::Error::Cancelled => {
            Error::new(ErrorKind::Deadline, error.to_string())
        }
        crate::graph_workspace::Error::Limit(_) => Error::new(ErrorKind::Limit, error.to_string()),
        crate::graph_workspace::Error::ForeignHandle
        | crate::graph_workspace::Error::ForeignEvidence => {
            Error::new(ErrorKind::Denied, "foreign graph session handle")
        }
        crate::graph_workspace::Error::RevisionConflict { .. }
        | crate::graph_workspace::Error::IdempotencyConflict
        | crate::graph_workspace::Error::Conflict(_)
        | crate::graph_workspace::Error::DependencyPinned(_) => {
            Error::new(ErrorKind::Conflict, error.to_string())
        }
        _ => Error::new(ErrorKind::Invalid, error.to_string()),
    }
}
