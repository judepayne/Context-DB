use cdb_core::{
    function_manifest::ExternalFunctionManifest, CanonicalValue, Error, ErrorKind, Result,
};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{sync::Notify, time::Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    Status,
    Transport,
    Deadline,
    Malformed,
    Oversize,
    Exhausted,
    Unavailable,
}
#[derive(Clone, Debug)]
pub struct AttemptFailure {
    pub class: FailureClass,
    pub retryable: bool,
}
impl AttemptFailure {
    pub fn error(&self) -> Error {
        let kind = match self.class {
            FailureClass::Deadline => ErrorKind::Deadline,
            FailureClass::Oversize => ErrorKind::Limit,
            _ => ErrorKind::Backend,
        };
        Error::new(
            kind,
            match self.class {
                FailureClass::Status => "function provider status failure",
                FailureClass::Transport => "function provider transport failure",
                FailureClass::Deadline => "function call deadline",
                FailureClass::Malformed => "malformed function provider response",
                FailureClass::Oversize => "function provider response limit",
                FailureClass::Exhausted => "function provider retries exhausted",
                FailureClass::Unavailable => "function provider unavailable",
            },
        )
    }
}
pub type AttemptOutcome = std::result::Result<CanonicalValue, AttemptFailure>;
pub struct Attempt(pub(crate) Pin<Box<dyn Future<Output = AttemptOutcome> + Send + 'static>>);
impl Attempt {
    pub async fn finish(self) -> AttemptOutcome {
        self.0.await
    }
}

/// Cooperative cancellation for transports. Dropping a waiting caller can stop local
/// HTTP work, but cannot recall bytes already transmitted or interrupt native code.
#[derive(Clone, Debug, Default)]
pub struct Cancellation {
    inner: Arc<CancellationInner>,
}
#[derive(Debug, Default)]
struct CancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
    flag: Option<Arc<AtomicBool>>,
}
impl Cancellation {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn from_flag(flag: Arc<AtomicBool>) -> Self {
        Self {
            inner: Arc::new(CancellationInner {
                flag: Some(flag),
                ..Default::default()
            }),
        }
    }
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
            || self
                .inner
                .flag
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Acquire))
    }
    pub async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            if self.inner.flag.is_some() {
                tokio::select! { _ = notified => {}, _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => {} }
            } else {
                notified.await;
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct PhysicalRequest {
    pub logical_id: String,
    pub attempt: u8,
    pub input: CanonicalValue,
    pub max_result_bytes: usize,
    /// Absolute deadline shared by retries and response-body reads.
    pub deadline: Instant,
    pub cancellation: Cancellation,
    /// Closed protocol metadata derived only from the registered exact manifest.
    pub manifest_binding: CanonicalValue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionClass {
    HttpService,
    CpuBlocking,
    Accelerator,
}

/// Registered adapters accept only already-bound manifests and operational requests.
/// They have no graph/source access and cannot choose an endpoint/model from input.
pub trait Adapter: Send + Sync {
    fn class(&self) -> ExecutionClass;
    fn build_identity(&self) -> &str;
    fn supports(&self, manifest: &ExternalFunctionManifest) -> bool;
    fn enqueue(&self, request: PhysicalRequest) -> Result<Attempt>;
    fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}
