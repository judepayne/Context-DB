//! Bounded dedicated threads for native predicate execution.
use super::{classify_program, NativePredicateExecutor};
use cdb_core::{CanonicalValue, Error, Result};
use cdb_engine::{
    predicates::{EvaluationLimits, FunctionCallback, Outcome, PredicateExecutor, Program},
    values::Value,
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobClass {
    LocalOnly,
    CallCapable,
}

#[derive(Clone, Copy, Debug)]
pub struct PoolLimits {
    pub local_workers: usize,
    pub call_workers: usize,
    pub max_jobs: usize,
    pub max_bytes: usize,
}
impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            local_workers: 1,
            call_workers: 2,
            max_jobs: 64,
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

struct Admission {
    jobs: usize,
    bytes: usize,
}
struct Reservation {
    bytes: usize,
    admission: Arc<Mutex<Admission>>,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        admission.jobs -= 1;
        admission.bytes -= self.bytes;
    }
}

/// Keeps native pending bytes/count charged after completion until ordered reduction consumes it.
pub struct RetainedOutcome {
    outcome: Outcome,
    _reservation: Reservation,
}
impl RetainedOutcome {
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }
    pub fn into_outcome(self) -> Outcome {
        self.outcome
    }
}

struct Job {
    program: Program,
    state: CanonicalValue,
    bindings: BTreeMap<String, Value>,
    host: Arc<dyn FunctionCallback>,
    limits: EvaluationLimits,
    reservation: Option<Reservation>,
    completion: mpsc::Sender<Result<RetainedOutcome>>,
}

struct LocalHost(Arc<dyn FunctionCallback>);
impl FunctionCallback for LocalHost {
    fn check_interrupted(&self) -> Result<()> {
        self.0.check_interrupted()
    }
    fn call(&self, _: &str, _: &[Value]) -> Result<Value> {
        Err(Error::invalid(
            "unexpected callback on local-only predicate worker",
        ))
    }
}

/// Owns two bounded queues and joins every native worker during drop.
pub struct NativePredicatePool {
    local: Mutex<Option<SyncSender<Job>>>,
    callable: Mutex<Option<SyncSender<Job>>>,
    admission: Arc<Mutex<Admission>>,
    limits: PoolLimits,
    stopping: AtomicBool,
    workers: Mutex<Vec<JoinHandle<()>>>,
}
impl NativePredicatePool {
    pub fn new(limits: PoolLimits) -> Result<Self> {
        if limits.local_workers == 0
            || limits.call_workers == 0
            || limits.max_jobs == 0
            || limits.max_bytes == 0
        {
            return Err(Error::limit());
        }
        let admission = Arc::new(Mutex::new(Admission { jobs: 0, bytes: 0 }));
        let (local_tx, local_rx) = mpsc::sync_channel(limits.max_jobs);
        let (call_tx, call_rx) = mpsc::sync_channel(limits.max_jobs);
        let mut workers = Vec::new();
        spawn_workers(
            &mut workers,
            "ctxql-predicate-local",
            limits.local_workers,
            local_rx,
            true,
        )?;
        spawn_workers(
            &mut workers,
            "ctxql-predicate-call",
            limits.call_workers,
            call_rx,
            false,
        )?;
        Ok(Self {
            local: Mutex::new(Some(local_tx)),
            callable: Mutex::new(Some(call_tx)),
            admission,
            limits,
            stopping: AtomicBool::new(false),
            workers: Mutex::new(workers),
        })
    }

    pub fn evaluate(
        &self,
        program: Program,
        state: CanonicalValue,
        bindings: BTreeMap<String, Value>,
        host: Arc<dyn FunctionCallback>,
        limits: EvaluationLimits,
    ) -> Result<Outcome> {
        self.evaluate_retained(program, state, bindings, host, limits)
            .map(RetainedOutcome::into_outcome)
    }

    pub fn evaluate_retained(
        &self,
        program: Program,
        state: CanonicalValue,
        bindings: BTreeMap<String, Value>,
        host: Arc<dyn FunctionCallback>,
        limits: EvaluationLimits,
    ) -> Result<RetainedOutcome> {
        self.evaluate_retained_charged(program, state, bindings, host, limits, 0)
    }

    pub(crate) fn evaluate_retained_charged(
        &self,
        program: Program,
        state: CanonicalValue,
        bindings: BTreeMap<String, Value>,
        host: Arc<dyn FunctionCallback>,
        limits: EvaluationLimits,
        retained_capacity: usize,
    ) -> Result<RetainedOutcome> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(Error::invalid("predicate pool is draining"));
        }
        let class = classify_program(
            &program,
            &bindings.keys().cloned().collect::<Vec<_>>(),
            limits,
        )?;
        let bytes = super::job_bytes(&program, &state, &bindings)?
            .checked_add(retained_capacity)
            .ok_or_else(Error::limit)?;
        {
            let mut admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
            let jobs = admission.jobs.checked_add(1).ok_or_else(Error::limit)?;
            let total = admission
                .bytes
                .checked_add(bytes)
                .ok_or_else(Error::limit)?;
            if jobs > self.limits.max_jobs || total > self.limits.max_bytes {
                return Err(Error::limit());
            }
            admission.jobs = jobs;
            admission.bytes = total;
        }
        let (tx, rx) = mpsc::channel();
        let job = Job {
            program,
            state,
            bindings,
            host,
            limits,
            reservation: Some(Reservation {
                bytes,
                admission: self.admission.clone(),
            }),
            completion: tx,
        };
        let send = |sender: &Mutex<Option<SyncSender<Job>>>| {
            let sender = sender.lock().unwrap_or_else(|e| e.into_inner());
            sender
                .as_ref()
                .ok_or_else(|| Error::invalid("predicate pool is draining"))?
                .try_send(job)
                .map_err(|e| match e {
                    mpsc::TrySendError::Full(_) => Error::limit(),
                    mpsc::TrySendError::Disconnected(_) => Error::invalid("predicate pool stopped"),
                })
        };
        match class {
            JobClass::LocalOnly => send(&self.local)?,
            JobClass::CallCapable => send(&self.callable)?,
        }
        rx.recv()
            .map_err(|_| Error::invalid("predicate worker stopped"))?
    }

    /// Stop admission and join all queued/running native evaluations.
    pub fn shutdown(&self) {
        // Repeated/concurrent callers must also wait for the join owner.
        self.stopping.store(true, Ordering::Release);
        self.local.lock().unwrap_or_else(|e| e.into_inner()).take();
        self.callable
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        for worker in self
            .workers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            let _ = worker.join();
        }
    }
}
impl Drop for NativePredicatePool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn spawn_workers(
    out: &mut Vec<JoinHandle<()>>,
    name: &str,
    count: usize,
    receiver: Receiver<Job>,
    local: bool,
) -> Result<()> {
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..count {
        let receiver = receiver.clone();
        let worker = thread::Builder::new()
            .name(format!("{name}-{index}"))
            .spawn(move || loop {
                let job = {
                    let rx = receiver.lock().unwrap_or_else(|e| e.into_inner());
                    rx.recv()
                };
                let Ok(mut job) = job else { break };
                let host = if local {
                    Arc::new(LocalHost(job.host.clone())) as Arc<dyn FunctionCallback>
                } else {
                    job.host.clone()
                };
                let result = NativePredicateExecutor
                    .evaluate(&job.program, &job.state, &job.bindings, host, job.limits)
                    .map(|outcome| RetainedOutcome {
                        outcome,
                        _reservation: job.reservation.take().expect("job reservation"),
                    });
                let _ = job.completion.send(result);
            })
            .map_err(|e| Error::invalid(format!("predicate worker start: {e}")))?;
        out.push(worker);
    }
    Ok(())
}
