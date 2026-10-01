use super::dispatch::Attempt;
use cdb_core::{
    function_manifest::ExternalFunctionManifest,
    id::{Iri, ResourceId},
    CanonicalValue, Result,
};
use std::{future::Future, pin::Pin};

pub type AuthorizationFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Complete controller-supplied identity and cumulative dependency footprint.
/// Constructing this DTO is not authorization; only a trusted implementation of
/// [`TrustedAuthorizer`] can release it. Later lazy controller dependencies must be
/// added before calling this boundary and coordinated with any in-flight release.
#[derive(Clone, Debug)]
pub struct AuthorizationAction<'a> {
    pub session_id: &'a str,
    pub request_id: &'a str,
    pub logical_id: &'a str,
    pub attempt: u8,
    pub manifest: &'a ExternalFunctionManifest,
    pub provider: &'a ResourceId,
    pub argument_dependencies: &'a [ResourceId],
    pub state_dependencies: &'a [ResourceId],
    pub fact_dependencies: &'a [(ResourceId, Iri)],
    pub scope_dependencies: &'a [ResourceId],
}

/// One-shot local submission invoked while the authority implementation holds its guard.
pub trait GuardedEnqueue: Send {
    fn enqueue(self: Box<Self>) -> Result<Attempt>;
}
impl<F> GuardedEnqueue for F
where
    F: FnOnce() -> Result<Attempt> + Send,
{
    fn enqueue(self: Box<Self>) -> Result<Attempt> {
        (*self)()
    }
}

/// There is deliberately no allow-all implementation. Production composition must provide
/// the backend-issued current/session/disclosure check at the actual guarded enqueue, and a
/// fresh check before the returned value is consumed.
pub trait TrustedAuthorizer: Send + Sync {
    /// Operational ceilings; these do not replace fresh guarded authorization.
    fn deadline(&self) -> Option<std::time::Instant> {
        None
    }
    fn cancellation(&self) -> Option<std::sync::Arc<std::sync::atomic::AtomicBool>> {
        None
    }
    fn authorize_and_enqueue<'a>(
        &'a self,
        action: AuthorizationAction<'a>,
        enqueue: Box<dyn GuardedEnqueue>,
    ) -> AuthorizationFuture<'a, Attempt>;
    fn authorize_result<'a>(
        &'a self,
        action: AuthorizationAction<'a>,
        result: &'a CanonicalValue,
    ) -> AuthorizationFuture<'a, ()>;
}
