//! Trusted runtime bridge from owned native Rhai workers to the asynchronous broker.
pub mod controller;
pub mod effects;
use crate::{
    broker::{
        dispatch::Cancellation, permissions::TrustedAuthorizer, startup::ExecutorSettings, Broker,
        Invocation,
    },
    predicates::{
        canonical_value, job_bytes,
        pool::{NativePredicatePool, PoolLimits, RetainedOutcome},
    },
};
use cdb_core::{
    artifact::ArtifactRef,
    function_manifest::Batching,
    id::{Iri, ResourceId},
    CanonicalValue, Error, ErrorKind, Result,
};
use cdb_engine::{
    execution::controller::DependencyFootprint,
    predicates::{EvaluationLimits, FunctionCallback, Outcome, Program},
    values::Value,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
    task::{Context, Poll},
};

/// Exact semantic configuration route. A script name has one explicit provider;
/// runtime construction never searches for a compatible substitute.
#[derive(Clone, Debug)]
pub struct FunctionBinding {
    pub script_name: String,
    pub function_name: String,
    pub function_version: String,
    pub manifest: ArtifactRef,
    pub provider: String,
    pub deterministic: bool,
    pub order_independent: bool,
    pub retry_safe: bool,
    pub batching: Batching,
}

#[derive(Clone, Debug, Default)]
pub struct DependencyExtension {
    pub graph: Vec<ResourceId>,
    pub state: Vec<ResourceId>,
    pub facts: Vec<(ResourceId, Iri)>,
    pub scopes: Vec<ResourceId>,
}

#[derive(Default)]
struct Dependencies {
    graph: BTreeSet<ResourceId>,
    state: BTreeSet<ResourceId>,
    facts: BTreeSet<(ResourceId, Iri)>,
    scopes: BTreeSet<ResourceId>,
    bytes: usize,
}
struct RequestUse {
    pending: usize,
    bytes: usize,
}
struct RequestInner {
    broker: Arc<Broker>,
    authorizer: Arc<dyn TrustedAuthorizer>,
    session_id: String,
    request_id: String,
    bindings: BTreeMap<String, FunctionBinding>,
    dependencies: Mutex<Dependencies>,
    usage: Mutex<RequestUse>,
    max_pending: usize,
    max_pending_bytes: usize,
    max_dependency_bytes: usize,
    cancelled: Arc<AtomicBool>,
    next_lane: AtomicU64,
}
impl Drop for RequestInner {
    fn drop(&mut self) {
        // Normal completion must not mark the caller's shared cancellation flag.
        // Explicit request-owner drop/shutdown calls `RuntimeRequest::cancel` first.
        self.broker.finish_request(&self.request_id);
    }
}

#[derive(Clone)]
pub struct RuntimeRequest(Arc<RequestInner>);
impl RuntimeRequest {
    /// Extend only from trusted controller observations. The real native authorizer
    /// evaluates the cumulative snapshot at each enqueue/result boundary.
    pub fn extend_dependencies(&self, extension: DependencyExtension) -> Result<()> {
        if self.0.cancelled.load(Ordering::SeqCst) {
            return Err(cancelled());
        }
        let mut dependencies = self
            .0
            .dependencies
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut candidate = Dependencies {
            graph: dependencies.graph.clone(),
            state: dependencies.state.clone(),
            facts: dependencies.facts.clone(),
            scopes: dependencies.scopes.clone(),
            bytes: dependencies.bytes,
        };
        for resource in extension.graph {
            insert_resource(&mut candidate.graph, resource, &mut candidate.bytes)?;
        }
        for resource in extension.state {
            insert_resource(&mut candidate.state, resource, &mut candidate.bytes)?;
        }
        for resource in extension.scopes {
            insert_resource(&mut candidate.scopes, resource, &mut candidate.bytes)?;
        }
        for (resource, property) in extension.facts {
            if candidate.facts.insert((resource.clone(), property.clone())) {
                candidate.bytes = candidate
                    .bytes
                    .checked_add(resource.as_str().len())
                    .and_then(|n| n.checked_add(property.as_str().len()))
                    .ok_or_else(Error::limit)?;
            }
        }
        let count = candidate
            .graph
            .len()
            .checked_add(candidate.state.len())
            .and_then(|n| n.checked_add(candidate.facts.len()))
            .and_then(|n| n.checked_add(candidate.scopes.len()))
            .ok_or_else(Error::limit)?;
        if count > 4096 || candidate.bytes > self.0.max_dependency_bytes {
            return Err(Error::limit());
        }
        *dependencies = candidate;
        Ok(())
    }

    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
    }
}

fn insert_resource(
    set: &mut BTreeSet<ResourceId>,
    resource: ResourceId,
    bytes: &mut usize,
) -> Result<()> {
    if set.insert(resource.clone()) {
        *bytes = bytes
            .checked_add(resource.as_str().len())
            .ok_or_else(Error::limit)?;
    }
    Ok(())
}

struct RequestReservation {
    _shared: crate::broker::limits::LogicalAdmission,
    request: Arc<RequestInner>,
    bytes: usize,
}
impl Drop for RequestReservation {
    fn drop(&mut self) {
        let mut usage = self.request.usage.lock().unwrap_or_else(|e| e.into_inner());
        usage.pending -= 1;
        usage.bytes -= self.bytes;
    }
}

/// Completed native result. Pool and per-request bytes/count remain charged until
/// the deterministic controller consumes or drops this value.
pub struct RuntimeResult {
    native: RetainedOutcome,
    _request: RequestReservation,
}
impl RuntimeResult {
    pub fn outcome(&self) -> &Outcome {
        self.native.outcome()
    }
    pub fn into_outcome(self) -> Outcome {
        self.native.into_outcome()
    }
}

pub struct NativeEvaluation {
    task: tokio::task::JoinHandle<Result<RuntimeResult>>,
    cancelled: Arc<AtomicBool>,
    completed: bool,
}
impl Future for NativeEvaluation {
    type Output = Result<RuntimeResult>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.task).poll(cx) {
            Poll::Ready(Ok(value)) => {
                self.completed = true;
                Poll::Ready(value)
            }
            Poll::Ready(Err(_)) => {
                self.completed = true;
                Poll::Ready(Err(Error::new(
                    ErrorKind::Backend,
                    "native predicate task failed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Drop for NativeEvaluation {
    fn drop(&mut self) {
        if !self.completed {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        // Deliberately do not abort: the blocking task/native owner lives to return.
    }
}

pub struct NativeRuntime {
    broker: Arc<Broker>,
    pool: Arc<NativePredicatePool>,
    handle: tokio::runtime::Handle,
    executor: ExecutorSettings,
    evaluation_limits: EvaluationLimits,
    stopping: AtomicBool,
    requests: Mutex<Vec<Weak<RequestInner>>>,
}
impl NativeRuntime {
    /// The controller, not a worker-arrival counter, assigns recorded identities.
    pub fn recorded_host(
        &self,
        request: &RuntimeRequest,
        lane: cdb_core::recording_v3::LaneIdentityV3,
        ledger: effects::EffectLedger,
        counts: Arc<Mutex<BTreeMap<String, u64>>>,
        argument_dependencies: DependencyFootprint,
        state_dependencies: DependencyFootprint,
    ) -> Arc<dyn FunctionCallback> {
        Arc::new(RequestCallback {
            request: request.0.clone(),
            handle: self.handle.clone(),
            result_bytes: Mutex::new(0),
            max_result_bytes: self.evaluation_limits.max_result_bytes,
            job_dependencies: Some(JobDependencies {
                arguments: argument_dependencies,
                state: state_dependencies,
            }),
            recording: Some(RecordingCallback {
                lane,
                ledger,
                ordinal: AtomicU64::new(0),
                counts,
            }),
        })
    }
    pub(crate) fn broker(&self) -> &Broker {
        &self.broker
    }
    pub(crate) fn evaluation_limits(&self) -> EvaluationLimits {
        self.evaluation_limits
    }
    /// Must be called inside the service Tokio runtime; callbacks use this captured
    /// handle only after execution has reached a dedicated native pool worker.
    pub fn new(broker: Broker, executor: ExecutorSettings) -> Result<Self> {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| Error::invalid("native runtime requires an active Tokio runtime"))?;
        let broker = Arc::new(broker);
        let broker_limits = broker.settings().limits;
        let pool = NativePredicatePool::new(PoolLimits {
            local_workers: executor.local_workers,
            call_workers: executor.rhai_workers,
            // Count and byte controls are distinct. Never size a channel by a
            // byte budget (the default would allocate 64 million queue slots).
            max_jobs: executor.per_request_pending.min(4096),
            max_bytes: executor.global_pending_bytes,
        })?;
        let max_calls = usize::try_from(broker_limits.max_logical_calls).unwrap_or(usize::MAX);
        let evaluation_limits = EvaluationLimits {
            max_source_bytes: executor.script_max_ast_bytes,
            max_operations: executor.script_max_operations,
            max_depth: executor.script_max_recursion,
            max_state_bytes: executor.max_state_bytes,
            max_value_nodes: executor.script_max_container_items,
            max_collection_len: executor.script_max_container_items,
            max_calls,
            max_argument_bytes: broker_limits.max_argument_bytes,
            max_result_bytes: broker_limits.max_result_bytes,
        };
        Ok(Self {
            broker,
            pool: Arc::new(pool),
            handle,
            executor,
            evaluation_limits,
            stopping: AtomicBool::new(false),
            requests: Mutex::new(Vec::new()),
        })
    }

    pub fn request(
        &self,
        session_id: String,
        request_id: String,
        bindings: Vec<FunctionBinding>,
        authorizer: Arc<dyn TrustedAuthorizer>,
    ) -> Result<RuntimeRequest> {
        if self.stopping.load(Ordering::Acquire) || session_id.is_empty() || request_id.is_empty() {
            return Err(Error::invalid("native runtime is not admitting requests"));
        }
        let mut exact = BTreeMap::new();
        for binding in bindings {
            if binding.script_name.is_empty()
                || binding.script_name != binding.function_name
                || exact.contains_key(&binding.script_name)
            {
                return Err(Error::invalid("ambiguous or substituted function route"));
            }
            let (manifest, _) = self.broker.registry().resolve(
                &binding.function_name,
                &binding.function_version,
                &binding.provider,
            )?;
            if manifest.name().as_str() != binding.function_name
                || manifest.version().as_str() != binding.function_version
                || manifest.artifact() != &binding.manifest
                || manifest.deterministic() != binding.deterministic
                || manifest.order_independent() != binding.order_independent
                || manifest.retry_safe() != binding.retry_safe
                || manifest.batching() != binding.batching
            {
                return Err(Error::invalid("semantic function binding mismatch"));
            }
            exact.insert(binding.script_name.clone(), binding);
        }
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        requests.retain(|request| request.strong_count() != 0);
        if requests
            .iter()
            .filter_map(Weak::upgrade)
            .any(|r| r.request_id == request_id)
        {
            return Err(Error::new(
                ErrorKind::Conflict,
                "request identity already active",
            ));
        }
        if requests.len() >= 4096 || self.stopping.load(Ordering::Acquire) {
            return Err(Error::limit());
        }
        let cancelled = authorizer
            .cancellation()
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        let inner = Arc::new(RequestInner {
            broker: self.broker.clone(),
            authorizer,
            session_id,
            request_id,
            bindings: exact,
            dependencies: Mutex::new(Dependencies::default()),
            usage: Mutex::new(RequestUse {
                pending: 0,
                bytes: 0,
            }),
            max_pending: self.executor.per_request_pending,
            max_pending_bytes: self.executor.per_request_pending_bytes,
            max_dependency_bytes: self.executor.max_state_bytes,
            cancelled,
            next_lane: AtomicU64::new(0),
        });
        requests.push(Arc::downgrade(&inner));
        Ok(RuntimeRequest(inner))
    }

    pub fn evaluate(
        &self,
        request: &RuntimeRequest,
        program: Program,
        state: CanonicalValue,
        bindings: BTreeMap<String, Value>,
    ) -> Result<NativeEvaluation> {
        self.evaluate_with_host(request, program, state, bindings, None)
    }
    pub(crate) fn evaluate_with_host(
        &self,
        request: &RuntimeRequest,
        program: Program,
        state: CanonicalValue,
        bindings: BTreeMap<String, Value>,
        host: Option<Arc<dyn FunctionCallback>>,
    ) -> Result<NativeEvaluation> {
        if self.stopping.load(Ordering::Acquire) || request.0.cancelled.load(Ordering::SeqCst) {
            return Err(cancelled());
        }
        let retained_capacity = self
            .evaluation_limits
            .max_state_bytes
            .checked_add(self.evaluation_limits.max_result_bytes)
            .ok_or_else(Error::limit)?;
        let bytes = job_bytes(&program, &state, &bindings)?
            .checked_add(retained_capacity)
            .ok_or_else(Error::limit)?;
        let shared = self
            .broker
            .reserve_evaluation(&request.0.request_id, bytes)?;
        let reservation = {
            let mut usage = request.0.usage.lock().unwrap_or_else(|e| e.into_inner());
            let pending = usage.pending.checked_add(1).ok_or_else(Error::limit)?;
            let total = usage.bytes.checked_add(bytes).ok_or_else(Error::limit)?;
            if pending > request.0.max_pending || total > request.0.max_pending_bytes {
                return Err(Error::limit());
            }
            usage.pending = pending;
            usage.bytes = total;
            RequestReservation {
                _shared: shared,
                request: request.0.clone(),
                bytes,
            }
        };
        let request = request.0.clone();
        let cancelled = request.cancelled.clone();
        let host = host.unwrap_or_else(|| {
            Arc::new(RequestCallback {
                request: request.clone(),
                handle: self.handle.clone(),
                result_bytes: Mutex::new(0),
                max_result_bytes: self.evaluation_limits.max_result_bytes,
                job_dependencies: None,
                recording: None,
            })
        });
        let pool = self.pool.clone();
        let limits = self.evaluation_limits;
        let task = tokio::task::spawn_blocking(move || {
            let native = pool
                .evaluate_retained_charged(
                    program,
                    state,
                    bindings,
                    host,
                    limits,
                    retained_capacity,
                )
                .inspect_err(|_| {
                    request.cancelled.store(true, Ordering::SeqCst);
                })?;
            Ok(RuntimeResult {
                native,
                _request: reservation,
            })
        });
        Ok(NativeEvaluation {
            task,
            cancelled,
            completed: false,
        })
    }

    /// Stop admission, cancel requests, drain native Rhai/adapter callers, then stop broker.
    /// The parent may shut down projection/authority only after this returns.
    pub async fn shutdown(&self) -> Result<()> {
        self.stopping.store(true, Ordering::Release);
        for request in self
            .requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
        {
            request.cancelled.store(true, Ordering::SeqCst);
            self.broker.finish_request(&request.request_id);
        }
        let pool = self.pool.clone();
        let pool_result = tokio::task::spawn_blocking(move || pool.shutdown())
            .await
            .map_err(|_| Error::new(ErrorKind::Backend, "native pool shutdown failed"));
        let broker_result = self.broker.shutdown().await;
        pool_result.and(broker_result)
    }
}

struct RecordingCallback {
    lane: cdb_core::recording_v3::LaneIdentityV3,
    ledger: effects::EffectLedger,
    ordinal: AtomicU64,
    counts: Arc<Mutex<BTreeMap<String, u64>>>,
}
struct JobDependencies {
    arguments: DependencyFootprint,
    state: DependencyFootprint,
}
struct RequestCallback {
    request: Arc<RequestInner>,
    handle: tokio::runtime::Handle,
    result_bytes: Mutex<usize>,
    max_result_bytes: usize,
    job_dependencies: Option<JobDependencies>,
    recording: Option<RecordingCallback>,
}
impl FunctionCallback for RequestCallback {
    fn check_interrupted(&self) -> Result<()> {
        if self.request.cancelled.load(Ordering::SeqCst)
            || self
                .request
                .authorizer
                .deadline()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return Err(cancelled());
        }
        Ok(())
    }

    fn call(&self, name: &str, arguments: &[Value]) -> Result<Value> {
        self.check_interrupted()?;
        let route = self
            .request
            .bindings
            .get(name)
            .ok_or_else(|| Error::invalid("function has no exact startup route"))?;
        let input = CanonicalValue::Array(
            arguments
                .iter()
                .map(canonical_value)
                .collect::<Result<Vec<_>>>()?,
        );
        let dependencies = self
            .request
            .dependencies
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut argument_dependencies = dependencies.graph.clone();
        let mut state_dependencies = dependencies.state.clone();
        let mut fact_dependencies = dependencies.facts.clone();
        let mut scope_dependencies = dependencies.scopes.clone();
        if let Some(job) = &self.job_dependencies {
            argument_dependencies.extend(job.arguments.resources().cloned());
            state_dependencies.extend(job.state.resources().cloned());
            fact_dependencies.extend(job.arguments.facts().cloned());
            fact_dependencies.extend(job.state.facts().cloned());
            scope_dependencies.extend(job.arguments.scopes().cloned());
            scope_dependencies.extend(job.state.scopes().cloned());
        }
        let dependency_count = argument_dependencies
            .len()
            .checked_add(state_dependencies.len())
            .and_then(|n| n.checked_add(fact_dependencies.len()))
            .and_then(|n| n.checked_add(scope_dependencies.len()))
            .ok_or_else(Error::limit)?;
        let dependency_bytes = argument_dependencies
            .iter()
            .chain(&state_dependencies)
            .chain(&scope_dependencies)
            .try_fold(0usize, |n, resource| {
                n.checked_add(resource.as_str().len())
                    .ok_or_else(Error::limit)
            })?;
        let dependency_bytes =
            fact_dependencies
                .iter()
                .try_fold(dependency_bytes, |n, (resource, property)| {
                    n.checked_add(resource.as_str().len())
                        .and_then(|n| n.checked_add(property.as_str().len()))
                        .ok_or_else(Error::limit)
                })?;
        if dependency_count > 4096 || dependency_bytes > self.request.max_dependency_bytes {
            return Err(Error::limit());
        }
        drop(dependencies);
        let (lane, logical_id, effect) = if let Some(recording) = &self.recording {
            let ordinal = recording
                .ordinal
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
                .map_err(|_| Error::limit())?;
            let id = recording.lane;
            let effect =
                recording
                    .ledger
                    .begin(id, ordinal, name, &input, self.max_result_bytes)?;
            let callback = cdb_core::recording_v3::function_callback_id(
                &id,
                ordinal,
                cdb_core::Limits::default(),
            )?;
            (id.evaluation, callback.as_str().to_owned(), Some(effect))
        } else {
            let lane = self
                .request
                .next_lane
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
                .map_err(|_| Error::limit())?;
            (lane, format!("{}:{lane}", self.request.request_id), None)
        };
        let invocation = Invocation {
            session_id: self.request.session_id.clone(),
            request_id: self.request.request_id.clone(),
            logical_id,
            lane,
            function_name: route.function_name.clone(),
            function_version: route.function_version.clone(),
            provider: route.provider.clone(),
            argument_dependencies: argument_dependencies.into_iter().collect(),
            state_dependencies: state_dependencies.into_iter().collect(),
            fact_dependencies: fact_dependencies.into_iter().collect(),
            scope_dependencies: scope_dependencies.into_iter().collect(),
            input,
        };
        let deadline = self
            .request
            .authorizer
            .deadline()
            .map(tokio::time::Instant::from_std);
        let cancellation = Cancellation::from_flag(self.request.cancelled.clone());
        let value = self
            .handle
            .block_on(async {
                self.request
                    .broker
                    .invoke_with_controls(
                        invocation,
                        self.request.authorizer.clone(),
                        deadline,
                        cancellation,
                    )
                    .await?
                    .consume_retained(self.request.authorizer.as_ref())
                    .await
            })
            .inspect_err(|_| {
                self.request.cancelled.store(true, Ordering::SeqCst);
            })?;
        self.check_interrupted()?;
        let crate::broker::ConsumedBrokerResult { value, owner } = value;
        if let Some(effect) = effect {
            effect.complete_owned(&value, Box::new(owner))?;
            let recording = self.recording.as_ref().expect("recording host");
            let mut counts = recording.counts.lock().unwrap_or_else(|e| e.into_inner());
            let count = counts.entry(name.to_owned()).or_default();
            *count = count.checked_add(1).ok_or_else(Error::limit)?;
        }
        // Conservatively retain all model ingress for this evaluation, even if
        // the script discards a value. The job reserved this capacity up front.
        let bytes = value.canonical_bytes(cdb_core::Limits::default())?.len();
        let mut used = self.result_bytes.lock().unwrap_or_else(|e| e.into_inner());
        *used = used.checked_add(bytes).ok_or_else(Error::limit)?;
        if *used > self.max_result_bytes {
            return Err(Error::limit());
        }
        Value::from_json(&value)
    }
}

fn cancelled() -> Error {
    Error::new(ErrorKind::Deadline, "native request cancelled or expired")
}
