use super::dispatch::{
    Adapter, Attempt, AttemptFailure, ExecutionClass, FailureClass, PhysicalRequest,
};
use cdb_core::{
    function_manifest::{Batching, ExternalFunctionManifest},
    id::ContentHash,
    CanonicalValue, Error, Result,
};
use std::{
    collections::BTreeMap,
    sync::{
        mpsc::{self, SyncSender},
        Arc, Mutex,
    },
    thread::JoinHandle,
};
use tokio::sync::oneshot;

pub type NativeFunction = Arc<dyn Fn(CanonicalValue) -> Result<CanonicalValue> + Send + Sync>;
struct Work {
    request: PhysicalRequest,
    completion: oneshot::Sender<super::dispatch::AttemptOutcome>,
}
pub(crate) struct NativePool {
    sender: Mutex<Option<SyncSender<Work>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}
impl NativePool {
    pub(crate) fn new(
        workers: usize,
        queue: usize,
        name: &str,
        function: NativeFunction,
    ) -> Result<Self> {
        if workers == 0 || queue == 0 {
            return Err(Error::limit());
        }
        let (tx, rx) = mpsc::sync_channel::<Work>(queue);
        let rx = Arc::new(Mutex::new(rx));
        let mut joins = Vec::new();
        for index in 0..workers {
            let rx = rx.clone();
            let f = function.clone();
            joins.push(
                std::thread::Builder::new()
                    .name(format!("{name}-{index}"))
                    .spawn(move || loop {
                        let work = rx.lock().unwrap_or_else(|e| e.into_inner()).recv();
                        let Ok(work) = work else { break };
                        let result = f(work.request.input).map_err(|_| AttemptFailure {
                            class: FailureClass::Transport,
                            retryable: false,
                        });
                        let _ = work.completion.send(result);
                    })
                    .map_err(|_| Error::invalid("native adapter worker start failed"))?,
            )
        }
        Ok(Self {
            sender: Mutex::new(Some(tx)),
            workers: Mutex::new(joins),
        })
    }
    pub(crate) fn enqueue(&self, request: PhysicalRequest) -> Result<Attempt> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .ok_or_else(|| Error::invalid("native adapter stopped"))?
            .try_send(Work {
                request,
                completion: tx,
            })
            .map_err(|_| Error::limit())?;
        Ok(Attempt(Box::pin(async move {
            rx.await.unwrap_or({
                Err(AttemptFailure {
                    class: FailureClass::Unavailable,
                    retryable: false,
                })
            })
        })))
    }
    pub(crate) fn shutdown(&self) -> Result<()> {
        self.sender.lock().unwrap_or_else(|e| e.into_inner()).take();
        let mut failed = false;
        for join in self
            .workers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            // One panicked worker must not detach the remaining live native calls.
            failed |= join.join().is_err();
        }
        if failed {
            Err(Error::invalid("native adapter worker failed"))
        } else {
            Ok(())
        }
    }
}

pub struct RegisteredCpuAdapter {
    build: String,
    implementation: String,
    version: String,
    implementation_build: ContentHash,
    pool: NativePool,
}
impl RegisteredCpuAdapter {
    pub fn new(
        workers: usize,
        queue: usize,
        implementation: String,
        version: String,
        implementation_build: ContentHash,
        function: NativeFunction,
    ) -> Result<Self> {
        Ok(Self {
            build: "ctxql-registered-cpu/v1".into(),
            implementation,
            version,
            implementation_build,
            pool: NativePool::new(workers, queue, "ctxql-function-cpu", function)?,
        })
    }
}
impl Adapter for RegisteredCpuAdapter {
    fn class(&self) -> ExecutionClass {
        ExecutionClass::CpuBlocking
    }
    fn build_identity(&self) -> &str {
        &self.build
    }
    fn supports(&self, m: &ExternalFunctionManifest) -> bool {
        let i = m.implementation();
        i.implementation.as_str() == self.implementation
            && i.version.as_str() == self.version
            && i.build == self.implementation_build
            && i.model.is_none()
            && m.semantic_parameters()
                .as_object()
                .is_ok_and(BTreeMap::is_empty)
            && m.batching() == Batching::None
    }
    fn enqueue(&self, r: PhysicalRequest) -> Result<Attempt> {
        self.pool.enqueue(r)
    }
    fn shutdown(&self) -> Result<()> {
        self.pool.shutdown()
    }
}
impl Drop for RegisteredCpuAdapter {
    fn drop(&mut self) {
        let _ = self.pool.shutdown();
    }
}

#[cfg(test)]
mod lifetime_tests {
    use super::*;
    use std::time::Duration;
    fn request() -> PhysicalRequest {
        PhysicalRequest {
            logical_id: "lifetime-test".into(),
            attempt: 1,
            input: CanonicalValue::Null,
            max_result_bytes: 1024,
            deadline: tokio::time::Instant::now() + Duration::from_secs(3),
            cancellation: super::super::dispatch::Cancellation::new(),
            manifest_binding: CanonicalValue::Object(BTreeMap::new()),
        }
    }
    #[test]
    fn shutdown_joins_remaining_native_calls_after_one_worker_panics() {
        let (started_tx, started_rx) = mpsc::sync_channel(2);
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let function: NativeFunction = Arc::new(move |_| {
            let first = std::thread::current().name().unwrap().ends_with("-0");
            started_tx.send(first).unwrap();
            assert!(!first, "intentional native worker failure");
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            Ok(CanonicalValue::Null)
        });
        let pool = Arc::new(NativePool::new(2, 2, "join-failure-test", function).unwrap());
        let _first = pool.enqueue(request()).unwrap();
        let _second = pool.enqueue(request()).unwrap();
        let a = started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let b = started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_ne!(a, b);
        let other = pool.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let join = std::thread::spawn(move || {
            done_tx.send(other.shutdown()).unwrap();
        });
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(
            pool.enqueue(request()).is_err(),
            "shutdown must close admission before joining"
        );
        release_tx.send(()).unwrap();
        assert!(done_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .is_err());
        join.join().unwrap();
    }
    #[test]
    fn dropping_attempt_does_not_release_a_running_native_worker() {
        let (started_tx, started_rx) = mpsc::sync_channel(2);
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let function: NativeFunction = Arc::new(move |_| {
            started_tx.send(()).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            Ok(CanonicalValue::Null)
        });
        let pool = NativePool::new(1, 1, "retained-slot-test", function).unwrap();
        let running = pool.enqueue(request()).unwrap();
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        drop(running);
        let _queued = pool.enqueue(request()).unwrap();
        assert!(
            pool.enqueue(request()).is_err(),
            "native queue must remain bounded while abandoned work runs"
        );
        release_tx.send(()).unwrap();
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        release_tx.send(()).unwrap();
        pool.shutdown().unwrap();
    }
}
