//! Authenticated native graph/function query, durable retry, restart, and actual HTTP replay.
use cdb_backend_fluree::{
    execution_authorization::{exact_invocation_role, ExactInvocationRequirement},
    policy::PolicyState,
    runs::Operation,
    AuthorityOptions, FlureeBackend,
};
use cdb_core::{
    admission::{AdmissionBatch, DependencyRecord, Fact, FactTerm, ResourceChange, ResourceKind},
    artifact::{ArtifactRef, PublishedArtifact},
    claim::{CandidateClaim, TypedLiteral},
    id::*,
    snapshot::ProjectionCheckpoint,
    CanonicalValue as V, ErrorKind, Limits,
};
use cdb_projection_redb::{GenerationOptions, RedbProjection};
use cdb_service::{
    auth::{provision, AuthStore, Capabilities, Operation as AuthOperation},
    broker::{
        cpu::RegisteredCpuAdapter,
        startup::{AdapterCatalog, NativeCapacity},
    },
    config::InstanceConfig,
    service::PreparationRequest,
    Service,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

async fn http_call(service: Arc<Service>, token: &str, value: serde_json::Value) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(cdb_service::http::serve(service, listener, receiver));
    let body = serde_json::to_vec(&value).unwrap();
    let request = format!(
        "POST /v1/operation HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = std::str::from_utf8(&response[..split]).unwrap();
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    response[split + 4..].to_vec()
}
const BUILD: &str = "sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f";
const MANIFEST: &[u8] = br#"{"schema":"ctxql-external-function/v1","name":"pick-last","version":"1","implementation":{"implementation":"urn:test:native","version":"1","build":"sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f","model":null},"input_schema":{"type":"array","items":{"type":"number"},"max_items":4},"output_schema":{"type":"number"},"semantic_parameters":{},"capabilities":[],"declarations":{"deterministic":true,"order_independent":true,"retry_safe":true,"batching":"none"}}"#;
fn artifact(id: &str, bytes: Vec<u8>) -> PublishedArtifact {
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new(id).unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(&bytes),
        ),
        bytes,
        Limits::default(),
    )
    .unwrap()
}
#[test]
fn service_owns_exact_function_session_and_current_invocation_checks() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap();
    let manifest = artifact("urn:test:manifest", MANIFEST.to_vec());
    let mut config = V::parse(
        include_bytes!("../../../fixtures/conformance/p2/config.json"),
        Limits::default(),
    )
    .unwrap();
    if let V::Object(ref mut fields) = config {
        if let V::Object(ref mut runtime) = fields.get_mut("runtime").unwrap() {
            runtime.insert(
                "predicate_numeric".into(),
                V::string("ctxql-predicate-numeric/v2"),
            );
        }
        fields.insert(
            "external_functions".into(),
            V::Object(BTreeMap::from([(
                "pick-last".into(),
                V::Object(BTreeMap::from([
                    ("version".into(), V::string("1")),
                    ("manifest_uri".into(), V::string("urn:test:manifest")),
                    (
                        "manifest_hash".into(),
                        V::string(manifest.reference().hash().as_str()),
                    ),
                    ("deterministic".into(), V::Bool(true)),
                ])),
            )])),
        );
    }
    let config = artifact(
        "urn:test:config",
        config.canonical_bytes(Limits::default()).unwrap(),
    );
    let query = artifact("urn:test:query", br#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1},"walk":{"predicates":[{"init":{"n":1},"keep":"fn:external(\"pick-last\", state.n + 1) == 2"}]}}"#.to_vec());
    let backend = Arc::new(
        FlureeBackend::create(AuthorityOptions::new(
            path.join("authority"),
            "functions:main".into(),
            BackendId::new("functions").unwrap(),
            AuthorityId::new("functions").unwrap(),
            GraphId::new("functions").unwrap(),
        ))
        .await
        .unwrap(),
    );
    backend.bootstrap_governance().await.unwrap();
    let entity = |id: &str, label: &str| {
        ResourceChange::Add(
            DependencyRecord::new(
                "ctxql-resource/v1",
                ResourceId::new(id).unwrap(),
                ResourceKind::Label,
                vec![
                    Fact::new(
                        cdb_engine::execution::property_iri("entity").unwrap(),
                        FactTerm::Literal(
                            TypedLiteral::new(
                                Iri::http("http://www.w3.org/2001/XMLSchema#boolean").unwrap(),
                                V::Bool(true),
                                None,
                            )
                            .unwrap(),
                        ),
                    ),
                    Fact::new(
                        cdb_engine::execution::property_iri("label").unwrap(),
                        FactTerm::Literal(
                            TypedLiteral::new(
                                Iri::http("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                                V::string(label),
                                None,
                            )
                            .unwrap(),
                        ),
                    ),
                ],
            )
            .unwrap(),
        )
    };
    let claim = CandidateClaim::from_value(
        &V::parse(
            br#"{"claim_id":"urn:test:claim-ab","subject_id":"urn:test:A","relation":"urn:test:edge","object_id":"urn:test:B","relation_type":"urn:test:Relation","subject_type":"urn:test:Entity","object_type":"urn:test:Entity","claim_type":"urn:test:Assertion","confidence":1,"grounding_level":"claim_only"}"#,
            Limits::default(),
        )
        .unwrap(),
    )
    .unwrap();
    backend
        .admit(
            &IdempotencyKey::new("artifacts").unwrap(),
            &AdmissionBatch::new(
                vec![claim],
                vec![],
                vec![entity("urn:test:A", "A"), entity("urn:test:B", "B")],
                vec![manifest.clone(), config.clone(), query.clone()],
                V::Object(BTreeMap::new()),
                Limits::default(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let mut state = PolicyState::deny_all().unwrap();
    state.policy = cdb_core::policy::PolicySet::parse(br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{"@id":"https://functions.test/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://functions.test/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}]}"#, Limits::default()).unwrap();
    let principal = PrincipalId::new("alice").unwrap();
    state.principals.insert(
        principal.clone(),
        (
            true,
            [
                Iri::new("https://functions.test/Reader").unwrap(),
                Iri::new(Operation::Query.role()).unwrap(),
                Iri::new(Operation::Read.role()).unwrap(),
                Iri::new(Operation::Replay.role()).unwrap(),
            ]
            .into(),
        ),
    );
    backend
        .set_policy_state(&IdempotencyKey::new("policy").unwrap(), &state)
        .await
        .unwrap();
    let projection = Arc::new(
        RedbProjection::create(
            path.join("projection"),
            ProjectionCheckpoint::new(
                backend.head().await.unwrap(),
                VersionId::new("ctxql-projection/v1").unwrap(),
                VersionId::new("live").unwrap(),
                Iri::new("urn:p3:raw").unwrap(),
            )
            .unwrap(),
            GenerationOptions::default(),
        )
        .await
        .unwrap(),
    );
    let capabilities = Capabilities::only(&[
        AuthOperation::Query,
        AuthOperation::Read,
        AuthOperation::Replay,
    ]);
    let (token, credential) = provision(principal.clone(), None, capabilities).unwrap();
    let (restart_token, restart_credential) =
        provision(principal.clone(), None, capabilities).unwrap();
    let (divergent_token, divergent_credential) =
        provision(principal.clone(), None, capabilities).unwrap();
    let token = token.into_string();
    let restart_token = restart_token.into_string();
    let divergent_token = divergent_token.into_string();
    let auth = AuthStore::new(vec![credential], Duration::from_secs(30)).unwrap();
    std::fs::create_dir(path.join("sources")).unwrap();
    std::fs::write(path.join("manifest.json"), MANIFEST).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path.join("sources"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::fs::set_permissions(
            path.join("manifest.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let instance_text = format!(
            r#"schema="ctxql-instance/v2"
projection="projection"
credential-file="injected"
source-root="sources"
[authority]
path="authority"
ledger="functions:main"
backend="functions"
authority="functions"
graph="functions"
[broker]
enabled=true
rhai_workers=1
local_workers=1
[broker.groups.shared]
[broker.manifests.pick]
iri="urn:test:manifest"
version="1"
hash="{}"
file="manifest.json"
[broker.providers.native]
class="cpu_blocking"
adapter="test-native"
destination="urn:test:destination"
group="shared"
allowed_manifests=["pick"]
implementation="urn:test:native"
implementation_version="1"
implementation_build="{BUILD}"
workers=1
internal_threads=1
[broker.providers.native.resources]
max_in_flight=1
"#,
            manifest.reference().hash().as_str()
        );
    let instance = InstanceConfig::parse(&instance_text, &path.join("node.toml")).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let make_catalog = |diverge: bool| {
        let observed = calls.clone();
        let adapter = Arc::new(
            RegisteredCpuAdapter::new(
                1,
                4,
                "urn:test:native".into(),
                "1".into(),
                ContentHash::parse(BUILD).unwrap(),
                Arc::new(move |input| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    let value = input.as_array()?.last().unwrap().clone();
                    if diverge {
                        Ok(V::Number(cdb_core::ExactNumber::from_u64(3)))
                    } else {
                        Ok(value)
                    }
                }),
            )
            .unwrap(),
        );
        let mut catalog = AdapterCatalog::default();
        catalog
            .register(
                "test-native",
                adapter,
                NativeCapacity {
                    workers: 1,
                    internal_threads: 1,
                    device_memory_bytes: None,
                    max_batch: None,
                    test_only: false,
                },
            )
            .unwrap();
        catalog
    };
    let catalog = make_catalog(false);
    let service =
        Service::attach_with_adapters(instance, backend.clone(), projection.clone(), auth, &catalog)
            .await
            .unwrap();
    let request = |id| PreparationRequest {
        run_id: RunId::new(id).unwrap(),
        query: query.reference().clone(),
        config: Some(config.reference().clone()),
        profile: None,
    };
    let cancel = || Arc::new(AtomicBool::new(false));
    let original = service
        .prepare_execution(&token, request("original"), cancel())
        .await
        .unwrap();
    let role = exact_invocation_role(&ExactInvocationRequirement::new(
        manifest.reference().clone(),
        ResourceId::new("urn:test:destination").unwrap(),
    ))
    .unwrap();
    state
        .principals
        .get_mut(&principal)
        .unwrap()
        .1
        .insert(role.clone());
    backend
        .set_policy_state(&IdempotencyKey::new("grant").unwrap(), &state)
        .await
        .unwrap();
    let initial = || {
        V::Object(BTreeMap::from([(
            "n".into(),
            V::Number(cdb_core::ExactNumber::from_u64(1)),
        )]))
    };
    assert_eq!(
        original
            .evaluate_predicate(false, 0, initial(), BTreeMap::new())
            .unwrap()
            .await
            .err()
            .unwrap()
            .kind,
        ErrorKind::Denied
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(original);
    let allowed = service
        .prepare_execution(&token, request("allowed"), cancel())
        .await
        .unwrap();
    assert!(
        allowed
            .evaluate_predicate(false, 0, initial(), BTreeMap::new())
            .unwrap()
            .await
            .unwrap()
            .outcome()
            .keep
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    state
        .principals
        .get_mut(&principal)
        .unwrap()
        .1
        .remove(&role);
    backend
        .set_policy_state(&IdempotencyKey::new("revoke").unwrap(), &state)
        .await
        .unwrap();
    assert_eq!(
        allowed
            .evaluate_predicate(false, 0, initial(), BTreeMap::new())
            .unwrap()
            .await
            .err()
            .unwrap()
            .kind,
        ErrorKind::Denied
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(allowed);
    state
        .principals
        .get_mut(&principal)
        .unwrap()
        .1
        .insert(role);
    backend
        .set_policy_state(&IdempotencyKey::new("regrant").unwrap(), &state)
        .await
        .unwrap();

    let recorded = service
        .prepare_execution(&token, request("recorded"), cancel())
        .await
        .unwrap();
    let committed = recorded
        .execute_recorded_v3_portable(ContentHash::of_bytes(b"recorded-operation"))
        .await
        .unwrap();
    assert_eq!(
        committed.run.projection().field("schema").unwrap().as_str().unwrap(),
        "ctxql-recorded-run/v3"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        committed.run.replay().data().snapshot,
        recorded.capture().snapshot
    );
    let replay_projection = committed.run.replay().projection();
    let evidence = replay_projection
        .field("release_evidence")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(evidence.len(), 3, "enqueue, consumption, and precommit checks");
    let action_ids = evidence
        .iter()
        .map(|entry| entry.field("action").unwrap().as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(action_ids.len(), evidence.len());
    for action in &evidence[..2] {
        assert_eq!(
            action
                .field("requirements")
                .unwrap()
                .field("invocations")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    let mut missing_consumption = committed.run.projection();
    let V::Object(run_fields) = &mut missing_consumption else {
        unreachable!()
    };
    let V::Object(replay_fields) = run_fields.get_mut("replay").unwrap() else {
        unreachable!()
    };
    let V::Array(release) = replay_fields.get_mut("release_evidence").unwrap() else {
        unreachable!()
    };
    release.remove(1);
    assert!(cdb_core::recording_v3::RunEnvelopeV3::from_value(
        &missing_consumption,
        Limits::default(),
    )
    .is_err());

    let reference_json = |reference: &ArtifactRef| {
        serde_json::from_slice::<serde_json::Value>(
            &reference.projection().canonical_bytes(Limits::default()).unwrap(),
        )
        .unwrap()
    };
    let public_query = serde_json::json!({
        "schema":"ctxql-service/v1",
        "op":"query",
        "run_id":"public-v3",
        "query":reference_json(query.reference()),
        "config":reference_json(config.reference()),
        "execution":"native_v3"
    });
    http_call(service.clone(), &token, public_query.clone()).await;
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let before_retry = calls.load(Ordering::SeqCst);
    http_call(service.clone(), &token, public_query).await;
    assert_eq!(calls.load(Ordering::SeqCst), before_retry);
    drop(recorded);
    drop(committed);
    service.shutdown().await.unwrap();
    drop(service);
    let restart_auth =
        AuthStore::new(vec![restart_credential], Duration::from_secs(30)).unwrap();
    let restart_instance =
        InstanceConfig::parse(&instance_text, &path.join("node.toml")).unwrap();
    let restart_catalog = make_catalog(false);
    let service = Service::attach_with_adapters(
        restart_instance,
        backend.clone(),
        projection.clone(),
        restart_auth,
        &restart_catalog,
    )
    .await
    .unwrap();
    let replay = http_call(
        service.clone(),
        &restart_token,
        serde_json::json!({
            "schema":"ctxql-service/v1",
            "op":"replay",
            "run_id":"public-v3"
        }),
    )
    .await;
    let replay: serde_json::Value = serde_json::from_slice(&replay).unwrap();
    assert_eq!(replay["response"]["graph"], "reproduced");
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    service.shutdown().await.unwrap();
    drop(service);

    let divergent_auth =
        AuthStore::new(vec![divergent_credential], Duration::from_secs(30)).unwrap();
    let divergent_instance =
        InstanceConfig::parse(&instance_text, &path.join("node.toml")).unwrap();
    let divergent_catalog = make_catalog(true);
    let service = Service::attach_with_adapters(
        divergent_instance,
        backend,
        projection,
        divergent_auth,
        &divergent_catalog,
    )
    .await
    .unwrap();
    let replay = http_call(
        service.clone(),
        &divergent_token,
        serde_json::json!({
            "schema":"ctxql-service/v1",
            "op":"replay",
            "run_id":"public-v3"
        }),
    )
    .await;
    let replay: serde_json::Value = serde_json::from_slice(&replay).unwrap();
    assert_eq!(replay["response"]["graph"], "diverged");
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    service.shutdown().await.unwrap();
                });
        })
        .unwrap()
        .join()
        .unwrap();
}
