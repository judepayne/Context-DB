//! Real broker authorization bridge: service session lease first, then the native
//! execution-authorization gate. No authority guard is held over provider latency.
use super::{
    dispatch::Attempt,
    permissions::{AuthorizationAction, AuthorizationFuture, GuardedEnqueue, TrustedAuthorizer},
};
use crate::auth::{AuthSession, AuthStore, Operation as SessionOperation, SessionLease};
use cdb_backend_fluree::{
    execution_authorization::{
        ExactInvocationRequirement, ExecutionAuthorization, ExecutionFence,
        RecordedReplayAuthorization,
    },
    runs::ExternalPublicationFence,
    FlureeBackend,
};
use cdb_core::{CanonicalValue, Error, ErrorKind, Result};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Mutex;

fn denied() -> Error {
    Error::new(ErrorKind::Denied, "native broker authorization denied")
}

struct BrokerFence {
    lease: SessionLease,
    cancelled: Arc<AtomicBool>,
    deadline: std::time::Instant,
}
impl ExternalPublicationFence for BrokerFence {
    fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::SeqCst) || std::time::Instant::now() >= self.deadline {
            return Err(denied());
        }
        self.lease.check().map_err(|_| denied())
    }
}
impl ExecutionFence for BrokerFence {
    fn check_disclosure(&self) -> Result<()> {
        self.check()
    }
}

enum BrokerAuthority {
    Query(ExecutionAuthorization),
    Replay(Box<RecordedReplayAuthorization>),
}

/// Trusted per-run bridge. Construction binds one authenticated session to one
/// privately captured native execution and its owner. Clones are intentionally not
/// exposed; all footprint extension/release operations are serialized here.
pub struct NativeBrokerAuthorizer {
    backend: Arc<FlureeBackend>,
    auth: AuthStore,
    session: AuthSession,
    session_id: String,
    request_id: String,
    authority: BrokerAuthority,
    cancelled: Arc<AtomicBool>,
    coordination: Arc<Mutex<()>>,
    recording: Option<Arc<super::authorization_log::AuthorizationLog>>,
    operation: SessionOperation,
    deadline: std::time::Instant,
}

impl NativeBrokerAuthorizer {
    pub async fn new(
        backend: Arc<FlureeBackend>,
        auth: AuthStore,
        session: AuthSession,
        session_id: String,
        request_id: String,
        execution: ExecutionAuthorization,
    ) -> Result<Self> {
        if execution.operation() != cdb_backend_fluree::runs::Operation::Query {
            return Err(denied());
        }
        Self::build(
            backend,
            auth,
            session,
            session_id,
            request_id,
            BrokerAuthority::Query(execution),
            SessionOperation::Query,
        )
        .await
    }

    pub async fn new_replay(
        backend: Arc<FlureeBackend>,
        auth: AuthStore,
        session: AuthSession,
        session_id: String,
        request_id: String,
        replay: &RecordedReplayAuthorization,
    ) -> Result<Self> {
        if replay.operation() != cdb_backend_fluree::runs::Operation::Replay
            || replay.run().id().as_str() != request_id
        {
            return Err(denied());
        }
        Self::build(
            backend,
            auth,
            session,
            session_id,
            request_id,
            BrokerAuthority::Replay(Box::new(replay.clone())),
            SessionOperation::Replay,
        )
        .await
    }

    async fn build(
        backend: Arc<FlureeBackend>,
        auth: AuthStore,
        session: AuthSession,
        session_id: String,
        request_id: String,
        authority: BrokerAuthority,
        operation: SessionOperation,
    ) -> Result<Self> {
        let principal = auth.principal(&session).await.map_err(|_| denied())?;
        let (expected_principal, expected_run) = match &authority {
            BrokerAuthority::Query(execution) => (execution.principal_id(), execution.run_id()),
            BrokerAuthority::Replay(replay) => (replay.principal(), replay.run().id()),
        };
        if &principal != expected_principal || expected_run.as_str() != request_id {
            return Err(denied());
        }
        let deadline = auth
            .lease(&session, operation)
            .await
            .map_err(|_| denied())?
            .deadline()
            .map_err(|_| denied())?;
        Ok(Self {
            backend,
            auth,
            session,
            session_id,
            request_id,
            authority,
            cancelled: Arc::new(AtomicBool::new(false)),
            coordination: Arc::new(Mutex::new(())),
            recording: None,
            operation,
            deadline,
        })
    }

    pub fn with_recording(
        mut self,
        recording: Arc<super::authorization_log::AuthorizationLog>,
    ) -> Self {
        self.recording = Some(recording);
        self
    }
    pub(crate) fn coordination(&self) -> Arc<Mutex<()>> {
        self.coordination.clone()
    }
    async fn guarded<T: Send + 'static, F: FnOnce() -> Result<T> + Send + 'static>(
        &self,
        action: AuthorizationAction<'_>,
        kind: &str,
        callback: F,
    ) -> Result<T> {
        let lease = self.lease().await?;
        let _coordination = self.coordination.lock().await;
        let callback_id = cdb_core::id::ResourceId::new(action.logical_id)?;
        let footprint = self.action_footprint(&action, &callback_id)?;
        let id = if action
            .logical_id
            .starts_with("urn:ctxql:function-callback:v1:")
        {
            cdb_core::recording_v3::function_action_id(&callback_id, action.attempt, kind)?
        } else {
            let identity = CanonicalValue::Array(vec![
                CanonicalValue::string(action.logical_id),
                CanonicalValue::integer(action.attempt as u64),
                CanonicalValue::string(kind),
            ]);
            let hash = cdb_core::id::ContentHash::of_bytes(
                &identity.canonical_bytes(cdb_core::Limits::default())?,
            );
            cdb_core::id::ResourceId::new(format!("urn:ctxql:release:{}", hash.as_str()))?
        };
        let data_snapshot = match &self.authority {
            BrokerAuthority::Query(execution) => execution.data_snapshot(),
            BrokerAuthority::Replay(replay) => replay.data_snapshot(),
        };
        let reservation = self
            .recording
            .as_ref()
            .map(|log| log.reserve(id, &footprint, data_snapshot))
            .transpose()?;
        let fence = Box::new(BrokerFence {
            lease,
            cancelled: self.cancelled.clone(),
            deadline: self.deadline,
        });
        let (value, receipt) = match &self.authority {
            BrokerAuthority::Query(execution) => {
                self.backend
                    .clone()
                    .guarded_execution_action_checked(execution.clone(), footprint, fence, callback)
                    .await?
            }
            BrokerAuthority::Replay(replay) => {
                self.backend
                    .clone()
                    .guarded_recorded_replay_action_checked(
                        replay,
                        &callback_id,
                        footprint,
                        fence,
                        callback,
                    )
                    .await?
            }
        };
        if let (Some(log), Some(reservation)) = (&self.recording, reservation) {
            log.append(reservation, receipt)?;
        }
        Ok(value)
    }
    /// Bind the controller's shorter deadline and shared cancellation signal.
    pub fn with_request_controls(
        mut self,
        deadline: std::time::Instant,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        self.deadline = self.deadline.min(deadline);
        self.cancelled = cancelled;
        self
    }

    /// Request cancellation is checked by every queued/retry/result fence.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn check_identity(&self, action: &AuthorizationAction<'_>) -> Result<()> {
        if action.session_id != self.session_id
            || action.request_id != self.request_id
            || action.logical_id.is_empty()
        {
            return Err(denied());
        }
        Ok(())
    }

    fn action_footprint(
        &self,
        action: &AuthorizationAction<'_>,
        callback_id: &cdb_core::id::ResourceId,
    ) -> Result<cdb_backend_fluree::execution_authorization::ReleaseFootprint> {
        self.check_identity(action)?;
        let view = cdb_core::id::Iri::http("https://ns.flur.ee/db#view")?;
        let mut facts = action.fact_dependencies.to_vec();
        facts.extend(
            action
                .argument_dependencies
                .iter()
                .chain(action.state_dependencies.iter())
                .chain(action.scope_dependencies.iter())
                .map(|resource| (resource.clone(), view.clone())),
        );
        let invocation = ExactInvocationRequirement::new(
            action.manifest.artifact().clone(),
            action.provider.clone(),
        );
        match &self.authority {
            BrokerAuthority::Query(execution) => {
                self.backend
                    .action_footprint(execution, facts, vec![invocation])
            }
            BrokerAuthority::Replay(replay) => {
                replay.action_footprint(&self.backend, callback_id, facts, invocation)
            }
        }
    }

    async fn lease(&self) -> Result<SessionLease> {
        // This await is deliberately before entry into the backend authority gate.
        self.auth
            .lease(&self.session, self.operation)
            .await
            .map_err(|_| denied())
    }
}

impl TrustedAuthorizer for NativeBrokerAuthorizer {
    fn deadline(&self) -> Option<std::time::Instant> {
        Some(self.deadline)
    }
    fn cancellation(&self) -> Option<Arc<AtomicBool>> {
        Some(self.cancelled.clone())
    }
    fn authorize_and_enqueue<'a>(
        &'a self,
        action: AuthorizationAction<'a>,
        enqueue: Box<dyn GuardedEnqueue>,
    ) -> AuthorizationFuture<'a, Attempt> {
        Box::pin(async move {
            self.guarded(action, "enqueue", move || enqueue.enqueue())
                .await
        })
    }

    fn authorize_result<'a>(
        &'a self,
        action: AuthorizationAction<'a>,
        _result: &'a CanonicalValue,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move { self.guarded(action, "consume", || Ok(())).await })
    }
}
