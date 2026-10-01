use cdb_backend_fluree::{
    execution_authorization::{exact_invocation_role, ExactInvocationRequirement},
    policy::PolicyState,
    runs::Operation as BackendOperation,
    AuthorityOptions, FlureeBackend,
};
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    function_manifest::{Batching, ExternalFunctionManifest},
    id::{
        AuthorityId, BackendId, ContentHash, GraphId, IdempotencyKey, Iri, PrincipalId, ResourceId,
        RunId, VersionId,
    },
    CanonicalValue as V, Error, ErrorKind, Limits,
};
use cdb_engine::{
    execution::controller::DependencyFootprint,
    predicates::{EvaluationLimits, PredicateExecutor, Program},
};
use cdb_service::{
    auth::{provision, AuthStore, Capabilities, Operation as SessionOperation},
    broker::{
        cpu::RegisteredCpuAdapter,
        limits::{BrokerLimits, ResourceLimits},
        native_authorization::NativeBrokerAuthorizer,
        permissions::{
            AuthorizationAction, AuthorizationFuture, GuardedEnqueue, TrustedAuthorizer,
        },
        registry::{ProviderRegistration, Registry},
        startup::ExecutorSettings,
        Broker, BrokerSettings,
    },
    predicates::NativePredicateExecutor,
    runtime::{
        effects::{EffectLedger, EffectLimits},
        FunctionBinding, NativeRuntime,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    time::Duration,
};

const BUILD: &str = "sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f";
const BYTES: &[u8] = br#"{"schema":"ctxql-external-function/v1","name":"pick-last","version":"1","implementation":{"implementation":"urn:test:native","version":"1","build":"sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f","model":null},"input_schema":{"type":"array","items":{"type":"number"},"max_items":4},"output_schema":{"type":"number"},"semantic_parameters":{},"capabilities":[],"declarations":{"deterministic":true,"order_independent":true,"retry_safe":true,"batching":"none"}}"#;

fn manifest() -> ExternalFunctionManifest {
    let reference = ArtifactRef::new(
        Iri::new("urn:test:pick-last-manifest").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(BYTES),
    );
    let artifact = PublishedArtifact::new(reference, BYTES.to_vec(), Limits::default()).unwrap();
    ExternalFunctionManifest::from_published(&artifact, Limits::default()).unwrap()
}

struct FreshAuthorizer {
    enqueue: AtomicUsize,
    consume: AtomicUsize,
}
impl TrustedAuthorizer for FreshAuthorizer {
    fn authorize_and_enqueue<'a>(
        &'a self,
        _: AuthorizationAction<'a>,
        enqueue: Box<dyn GuardedEnqueue>,
    ) -> AuthorizationFuture<'a, cdb_service::broker::dispatch::Attempt> {
        Box::pin(async move {
            self.enqueue.fetch_add(1, Ordering::SeqCst);
            enqueue.enqueue()
        })
    }
    fn authorize_result<'a>(
        &'a self,
        _: AuthorizationAction<'a>,
        _: &'a V,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.consume.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

fn runtime(pending: usize) -> (NativeRuntime, FunctionBinding, Arc<FreshAuthorizer>) {
    runtime_with(
        pending,
        4 * 1024 * 1024,
        BrokerLimits::default().max_logical_calls,
        Arc::new(|input| {
            let values = input.as_array()?;
            values
                .last()
                .cloned()
                .ok_or_else(|| Error::invalid("empty positional arguments"))
        }),
    )
}

fn runtime_with(
    pending: usize,
    pending_bytes: usize,
    max_logical_calls: u64,
    function: Arc<dyn Fn(V) -> Result<V, Error> + Send + Sync>,
) -> (NativeRuntime, FunctionBinding, Arc<FreshAuthorizer>) {
    let manifest = manifest();
    let artifact = manifest.artifact().clone();
    let adapter = Arc::new(
        RegisteredCpuAdapter::new(
            1,
            4,
            "urn:test:native".into(),
            "1".into(),
            ContentHash::parse(BUILD).unwrap(),
            function,
        )
        .unwrap(),
    );
    let resources = ResourceLimits {
        max_in_flight: 2,
        max_queued_bytes: pending_bytes,
        requests_per_second: u32::MAX,
        burst_requests: u32::try_from(max_logical_calls.min(u64::from(u32::MAX))).unwrap(),
    };
    let provider = ProviderRegistration {
        id: ResourceId::new("provider").unwrap(),
        destination: ResourceId::new("destination").unwrap(),
        group: ResourceId::new("group").unwrap(),
        limits: resources,
        allowed_manifests: BTreeSet::from([ProviderRegistration::binding(&artifact)]),
        adapter,
    };
    let registry = Registry::new(vec![manifest], vec![provider]).unwrap();
    let limits = BrokerLimits {
        per_request_pending: pending,
        per_request_bytes: pending_bytes,
        max_logical_calls,
        global: resources,
        ..Default::default()
    };
    let broker = Broker::new(
        registry,
        BrokerSettings {
            enabled: true,
            limits,
            groups: BTreeMap::from([("group".into(), resources)]),
        },
        &BTreeMap::from([("provider".into(), resources)]),
    )
    .unwrap();
    let executor = ExecutorSettings {
        rhai_workers: 1,
        local_workers: 1,
        global_pending_bytes: pending_bytes,
        per_request_pending: pending,
        per_request_pending_bytes: pending_bytes,
        max_state_bytes: 64 * 1024,
        script_max_operations: max_logical_calls
            .saturating_mul(32)
            .clamp(100_000, 1_000_000_000),
        script_max_recursion: 32,
        script_max_ast_bytes: 16 * 1024,
        script_max_container_items: 4096,
    };
    let binding = FunctionBinding {
        script_name: "pick-last".into(),
        function_name: "pick-last".into(),
        function_version: "1".into(),
        manifest: artifact,
        provider: "provider".into(),
        deterministic: true,
        order_independent: true,
        retry_safe: true,
        batching: Batching::None,
    };
    let authorizer = Arc::new(FreshAuthorizer {
        enqueue: AtomicUsize::new(0),
        consume: AtomicUsize::new(0),
    });
    (
        NativeRuntime::new(broker, executor).unwrap(),
        binding,
        authorizer,
    )
}

fn program(keep: &str) -> Program {
    Program {
        init: BTreeMap::new(),
        lets: BTreeMap::new(),
        next: BTreeMap::new(),
        keep: keep.into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_and_recording_execute_a_hundred_thousand_bounded_logical_calls() {
    let calls = 100_000u64;
    let (runtime, binding, authorizer) = runtime_with(
        4,
        4 * 1024 * 1024,
        calls,
        Arc::new(|input| {
            input
                .as_array()?
                .last()
                .cloned()
                .ok_or_else(|| Error::invalid("empty positional arguments"))
        }),
    );
    let request = runtime
        .request(
            "scale-session".into(),
            "scale-request".into(),
            vec![binding],
            authorizer.clone(),
        )
        .unwrap();
    let lane = cdb_core::recording_v3::LaneIdentityV3 {
        phase: cdb_core::recording_v3::LanePhaseV3::Walk,
        evaluation: 0,
        predicate: 0,
        attempt: 0,
        ordinal: 0,
    };
    let ledger = EffectLedger::new(
        EffectLimits {
            max_groups: 1,
            max_calls: calls,
            max_pending_bytes: 4 * 1024 * 1024,
            head_bytes: 2 * 1024 * 1024,
            values: Limits::default(),
        },
        vec![(
            Arc::new(manifest()),
            ResourceId::new("destination").unwrap(),
        )],
    )
    .unwrap();
    ledger.open_group(lane.into()).unwrap();
    let counts = Arc::new(Mutex::new(BTreeMap::new()));
    let host = runtime.recorded_host(
        &request,
        lane,
        ledger.clone(),
        counts.clone(),
        DependencyFootprint::default(),
        DependencyFootprint::default(),
    );
    let outcome = tokio::task::spawn_blocking(move || {
        NativePredicateExecutor.evaluate(
            &program(
                r#"let value = 0; for n in 0..100000 { value = fn:external("pick-last", n); } value == 99999"#,
            ),
            &V::Object(BTreeMap::new()),
            &BTreeMap::new(),
            host,
            EvaluationLimits {
                max_operations: 100_000_000,
                max_calls: calls as usize,
                ..EvaluationLimits::default()
            },
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert!(outcome.keep);
    ledger.close_group(lane.into()).unwrap();
    let completed = ledger.finish().unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].count, calls);
    let vectors = V::parse(
        include_bytes!("../../../fixtures/conformance/p5/independent-vectors.json"),
        Limits::default(),
    )
    .unwrap();
    let scale = vectors.field("broker_recording_scale").unwrap();
    assert_eq!(
        completed[0].manifest.artifact().hash().as_str(),
        scale.field("manifest_sha256").unwrap().as_str().unwrap()
    );
    assert_eq!(
        completed[0].input_root.as_str(),
        scale.field("input_root").unwrap().as_str().unwrap()
    );
    assert_eq!(
        completed[0].output_root.as_str(),
        scale.field("output_root").unwrap().as_str().unwrap()
    );
    assert_eq!(
        counts.lock().unwrap().get("pick-last").copied(),
        Some(calls)
    );
    assert_eq!(authorizer.enqueue.load(Ordering::SeqCst), calls as usize);
    assert_eq!(authorizer.consume.load(Ordering::SeqCst), calls as usize);
    drop(request);
    runtime.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_repeated_rhai_calls_use_registered_native_and_fresh_consumption() {
    let (runtime, binding, authorizer) = runtime(4);
    let request = runtime
        .request(
            "session".into(),
            "request".into(),
            vec![binding],
            authorizer.clone(),
        )
        .unwrap();
    let result = runtime
        .evaluate(
            &request,
            program(
                r#"fn nested(x) { fn:external("pick-last", x, fn:external("pick-last", x + 1)) } nested(1) == 2"#,
            ),
            V::Object(BTreeMap::new()),
            BTreeMap::new(),
        )
        .unwrap()
        .await
        .unwrap();
    assert!(result.outcome().keep);
    assert_eq!(authorizer.enqueue.load(Ordering::SeqCst), 2);
    assert_eq!(authorizer.consume.load(Ordering::SeqCst), 2);
    drop(result);
    runtime.shutdown().await.unwrap();
}

async fn native_authorizer() -> (tempfile::TempDir, Arc<NativeBrokerAuthorizer>) {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(
        FlureeBackend::create(AuthorityOptions::new(
            dir.path().join("db"),
            "runs:main".into(),
            BackendId::new("fluree").unwrap(),
            AuthorityId::new("owner").unwrap(),
            GraphId::new("graph").unwrap(),
        ))
        .await
        .unwrap(),
    );
    backend.bootstrap_governance().await.unwrap();
    let exact = ExactInvocationRequirement::new(
        manifest().artifact().clone(),
        ResourceId::new("destination").unwrap(),
    );
    let mut state = PolicyState::deny_all().unwrap();
    state.principals.insert(
        PrincipalId::new("alice").unwrap(),
        (
            true,
            BTreeSet::from([
                Iri::http(BackendOperation::Query.role()).unwrap(),
                Iri::http(BackendOperation::Read.role()).unwrap(),
                exact_invocation_role(&exact).unwrap(),
            ]),
        ),
    );
    backend
        .set_policy_state(&IdempotencyKey::new("policy").unwrap(), &state)
        .await
        .unwrap();
    let (token, record) = provision(
        PrincipalId::new("alice").unwrap(),
        None,
        Capabilities::only(&[SessionOperation::Query]),
    )
    .unwrap();
    let auth = AuthStore::new(vec![record], Duration::from_secs(5)).unwrap();
    let token = token.into_string();
    let session = auth.authenticate(&token).await.unwrap();
    let principal = backend
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let execution = backend
        .capture_execution(
            principal,
            backend.head().await.unwrap(),
            cdb_core::Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
            RunId::new("request").unwrap(),
            ContentHash::of_bytes(b"runtime-plan"),
            BackendOperation::Query,
        )
        .await
        .unwrap();
    let authorizer = NativeBrokerAuthorizer::new(
        backend,
        auth,
        session,
        "session".into(),
        "request".into(),
        execution,
    )
    .await
    .unwrap();
    (dir, Arc::new(authorizer))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_native_route_uses_real_current_authorization_on_enqueue_and_consumption() {
    let (runtime, binding, _) = runtime(4);
    let (_authority_owner, authorizer) = native_authorizer().await;
    let request = runtime
        .request(
            "session".into(),
            "request".into(),
            vec![binding],
            authorizer,
        )
        .unwrap();
    let result = runtime
        .evaluate(
            &request,
            program(
                r#"fn nested(x) { fn:external("pick-last", x, fn:external("pick-last", x + 1)) } nested(1) == 2"#,
            ),
            V::Object(BTreeMap::new()),
            BTreeMap::new(),
        )
        .unwrap()
        .await
        .unwrap();
    assert!(result.outcome().keep);
    drop(result);
    runtime.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_route_rejects_substitution_and_completed_output_retains_budget() {
    let (runtime, mut binding, authorizer) = runtime(1);
    binding.deterministic = false;
    assert!(runtime
        .request(
            "session".into(),
            "bad".into(),
            vec![binding.clone()],
            authorizer.clone(),
        )
        .is_err());
    binding.deterministic = true;
    let request = runtime
        .request(
            "session".into(),
            "request".into(),
            vec![binding],
            authorizer,
        )
        .unwrap();
    let first = runtime
        .evaluate(
            &request,
            program("true"),
            V::Object(BTreeMap::new()),
            BTreeMap::new(),
        )
        .unwrap()
        .await
        .unwrap();
    assert!(runtime
        .evaluate(
            &request,
            program("true"),
            V::Object(BTreeMap::new()),
            BTreeMap::new(),
        )
        .is_err());
    drop(first);
    let second = runtime
        .evaluate(
            &request,
            program("true"),
            V::Object(BTreeMap::new()),
            BTreeMap::new(),
        )
        .unwrap()
        .await
        .unwrap();
    assert!(second.outcome().keep);
    drop(second);
    runtime.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_live_request_id_does_not_finish_the_original_request() {
    let (runtime, binding, authorizer) = runtime(2);
    let request = runtime
        .request(
            "session".into(),
            "request".into(),
            vec![binding.clone()],
            authorizer.clone(),
        )
        .unwrap();
    let duplicate = runtime.request(
        "other-session".into(),
        "request".into(),
        vec![binding],
        authorizer.clone(),
    );
    assert_eq!(duplicate.err().unwrap().kind, ErrorKind::Conflict);

    let result = runtime
        .evaluate(
            &request,
            program(r#"fn:external("pick-last", 1) == 1"#),
            V::Object(BTreeMap::new()),
            BTreeMap::new(),
        )
        .unwrap()
        .await
        .unwrap();
    assert!(result.outcome().keep);
    assert_eq!(authorizer.enqueue.load(Ordering::SeqCst), 1);
    drop(result);
    runtime.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluation_and_broker_call_share_pending_without_double_counting_logical_calls() {
    let (runtime, binding, authorizer) = runtime_with(
        2,
        4 * 1024 * 1024,
        1,
        Arc::new(|input| Ok(input.as_array()?.last().cloned().unwrap())),
    );
    let request = runtime
        .request(
            "session".into(),
            "request".into(),
            vec![binding],
            authorizer.clone(),
        )
        .unwrap();

    let result = runtime
        .evaluate(
            &request,
            program(r#"fn:external("pick-last", 1) == 1"#),
            V::Object(BTreeMap::new()),
            BTreeMap::new(),
        )
        .unwrap()
        .await
        .unwrap();
    assert!(result.outcome().keep);
    assert_eq!(authorizer.enqueue.load(Ordering::SeqCst), 1);
    drop(result);
    runtime.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_evaluations_share_per_request_and_global_byte_admission() {
    let budget = 2 * 1024 * 1024;
    let (runtime, binding, authorizer) = runtime_with(
        4,
        budget,
        BrokerLimits::default().max_logical_calls,
        Arc::new(|input| Ok(input.as_array()?.last().cloned().unwrap())),
    );
    let first_request = runtime
        .request(
            "session".into(),
            "first".into(),
            vec![binding.clone()],
            authorizer.clone(),
        )
        .unwrap();
    let second_request = runtime
        .request("session".into(), "second".into(), vec![binding], authorizer)
        .unwrap();

    let held = runtime
        .evaluate(
            &first_request,
            program("true"),
            V::Object(BTreeMap::new()),
            BTreeMap::new(),
        )
        .unwrap()
        .await
        .unwrap();
    assert_eq!(
        runtime
            .evaluate(
                &first_request,
                program("true"),
                V::Object(BTreeMap::new()),
                BTreeMap::new(),
            )
            .err()
            .unwrap()
            .kind,
        ErrorKind::Limit
    );
    assert_eq!(
        runtime
            .evaluate(
                &second_request,
                program("true"),
                V::Object(BTreeMap::new()),
                BTreeMap::new(),
            )
            .err()
            .unwrap()
            .kind,
        ErrorKind::Limit
    );

    drop(held);
    let admitted = runtime
        .evaluate(
            &second_request,
            program("true"),
            V::Object(BTreeMap::new()),
            BTreeMap::new(),
        )
        .unwrap()
        .await
        .unwrap();
    drop(admitted);
    runtime.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_request_shutdown_waits_for_physical_native_completion() {
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    let (runtime, binding, authorizer) = runtime_with(
        2,
        4 * 1024 * 1024,
        BrokerLimits::default().max_logical_calls,
        Arc::new(move |input| {
            entered_tx
                .send(())
                .map_err(|_| Error::invalid("test entry barrier closed"))?;
            release_rx
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| Error::invalid("test release barrier timed out"))?;
            Ok(input.as_array()?.last().cloned().unwrap())
        }),
    );
    let runtime = Arc::new(runtime);
    let request = runtime
        .request(
            "session".into(),
            "request".into(),
            vec![binding],
            authorizer,
        )
        .unwrap();
    let evaluation = runtime
        .evaluate(
            &request,
            program(r#"fn:external("pick-last", 1) == 1"#),
            V::Object(BTreeMap::new()),
            BTreeMap::new(),
        )
        .unwrap();
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("native adapter did not enter");

    request.cancel();
    drop(evaluation);
    let shutdown_runtime = runtime.clone();
    let mut shutdown = tokio::spawn(async move { shutdown_runtime.shutdown().await });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut shutdown)
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), shutdown)
        .await
        .expect("shutdown did not drain physical native work")
        .unwrap()
        .unwrap();
}
