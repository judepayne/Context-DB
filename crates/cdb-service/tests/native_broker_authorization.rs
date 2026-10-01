//! Native broker authorization acceptance: real AuthStore lease, Fluree authority,
//! and loopback HTTP. This is not complete v3 query/replay acceptance.
use cdb_backend_fluree::{
    execution_authorization::{exact_invocation_role, ExactInvocationRequirement},
    policy::PolicyState,
    runs::Operation as BackendOperation,
    AuthorityOptions, FlureeBackend,
};
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    function_manifest::ExternalFunctionManifest,
    id::*,
    recording::REQUIRED_SCOPES,
    CanonicalValue as V, ErrorKind, Limits,
};
use cdb_service::{
    auth::{provision, AuthStore, Capabilities, Operation as SessionOperation},
    broker::{
        http::HttpJsonAdapter,
        limits::{BrokerLimits, ResourceLimits},
        native_authorization::NativeBrokerAuthorizer,
        registry::{ProviderRegistration, Registry},
        Broker, BrokerSettings, Invocation,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
    task::JoinHandle,
    time::{sleep, timeout},
};

const BUILD_HASH: &str = "sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f";
const MANIFEST_BYTES: &[u8] = br#"{"schema":"ctxql-external-function/v1","name":"test-function","version":"1","implementation":{"implementation":"urn:test:http-json","version":"1","build":"sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f","model":null},"input_schema":{"type":"string"},"output_schema":{"type":"number"},"semantic_parameters":{},"capabilities":[],"declarations":{"deterministic":true,"order_independent":true,"retry_safe":true,"batching":"none"}}"#;
const DESTINATION: &str = "destination-1";

struct Server {
    endpoint: String,
    count: Arc<AtomicUsize>,
    first_seen: Arc<Notify>,
    release_first: Arc<Notify>,
    task: JoinHandle<()>,
}
impl Server {
    async fn start(statuses: Vec<u16>, pause_first: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/invoke", listener.local_addr().unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        let captured = count.clone();
        let first_seen = Arc::new(Notify::new());
        let seen = first_seen.clone();
        let release_first = Arc::new(Notify::new());
        let release = release_first.clone();
        let task = tokio::spawn(async move {
            for (index, status) in statuses.into_iter().enumerate() {
                let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept())
                    .await
                    .expect("bounded accept")
                    .unwrap();
                let mut wire = Vec::new();
                loop {
                    let mut chunk = [0; 1024];
                    let n = timeout(Duration::from_secs(2), stream.read(&mut chunk))
                        .await
                        .expect("bounded read")
                        .unwrap();
                    assert_ne!(n, 0);
                    wire.extend_from_slice(&chunk[..n]);
                    if wire.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                captured.fetch_add(1, Ordering::SeqCst);
                if index == 0 {
                    seen.notify_one();
                    if pause_first {
                        timeout(Duration::from_secs(2), release.notified())
                            .await
                            .expect("bounded response barrier");
                    }
                }
                let header_end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                let length = std::str::from_utf8(&wire[..header_end])
                    .unwrap()
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                assert!(length < 1024 * 1024);
                while wire.len() < header_end + length {
                    let mut chunk = [0; 4096];
                    let n = timeout(Duration::from_secs(2), stream.read(&mut chunk))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_ne!(n, 0);
                    wire.extend_from_slice(&chunk[..n]);
                }
                let request: serde_json::Value =
                    serde_json::from_slice(&wire[header_end..header_end + length]).unwrap();
                let body = if status == 200 {
                    serde_json::to_vec(&serde_json::json!({"schema":"ctxql-function-http/v1","output":7,"manifest":request["manifest"]})).unwrap()
                } else {
                    b"unavailable".to_vec()
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            endpoint,
            count,
            first_seen,
            release_first,
            task,
        }
    }
    async fn finish(self) -> usize {
        timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap();
        self.count.load(Ordering::SeqCst)
    }
}

fn manifest() -> ExternalFunctionManifest {
    let reference = ArtifactRef::new(
        Iri::new("urn:test:exact-manifest").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(MANIFEST_BYTES),
    );
    let artifact =
        PublishedArtifact::new(reference, MANIFEST_BYTES.to_vec(), Limits::default()).unwrap();
    ExternalFunctionManifest::from_published(&artifact, Limits::default()).unwrap()
}
fn broker(endpoint: &str) -> Broker {
    let manifest = manifest();
    let adapter = Arc::new(
        HttpJsonAdapter::new(
            endpoint,
            true,
            None,
            4,
            "urn:test:http-json".into(),
            "1".into(),
            ContentHash::parse(BUILD_HASH).unwrap(),
        )
        .unwrap(),
    );
    let resource_limits = ResourceLimits {
        max_in_flight: 2,
        max_queued_bytes: 2 * 1024 * 1024,
        requests_per_second: 1_000,
        burst_requests: 10,
    };
    let provider = ProviderRegistration {
        id: ResourceId::new("provider-1").unwrap(),
        destination: ResourceId::new(DESTINATION).unwrap(),
        group: ResourceId::new("group-1").unwrap(),
        limits: resource_limits,
        allowed_manifests: BTreeSet::from([ProviderRegistration::binding(manifest.artifact())]),
        adapter,
    };
    let registry = Registry::new(vec![manifest], vec![provider]).unwrap();
    let limits = BrokerLimits {
        call_timeout_ms: 1_000,
        ..Default::default()
    };
    Broker::new(
        registry,
        BrokerSettings {
            enabled: true,
            limits,
            groups: BTreeMap::from([("group-1".into(), resource_limits)]),
        },
        &BTreeMap::from([("provider-1".into(), resource_limits)]),
    )
    .unwrap()
}
fn invocation() -> Invocation {
    Invocation {
        session_id: "session-1".into(),
        request_id: "request-1".into(),
        logical_id: "logical-1".into(),
        lane: 0,
        function_name: "test-function".into(),
        function_version: "1".into(),
        provider: "provider-1".into(),
        argument_dependencies: vec![ResourceId::new(REQUIRED_SCOPES[0]).unwrap()],
        state_dependencies: vec![ResourceId::new(REQUIRED_SCOPES[3]).unwrap()],
        fact_dependencies: vec![(
            ResourceId::new(REQUIRED_SCOPES[1]).unwrap(),
            Iri::http("https://ns.flur.ee/db#view").unwrap(),
        )],
        scope_dependencies: vec![ResourceId::new(REQUIRED_SCOPES[2]).unwrap()],
        input: V::String("hello".into()),
    }
}
struct NativeFixture {
    _dir: tempfile::TempDir,
    backend: Arc<FlureeBackend>,
    auth: AuthStore,
    token: String,
}
impl NativeFixture {
    async fn new(grant_invocation: bool, ttl: Duration) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let options = AuthorityOptions::new(
            dir.path().join("db"),
            "runs:main".into(),
            BackendId::new("fluree").unwrap(),
            AuthorityId::new("owner").unwrap(),
            GraphId::new("graph").unwrap(),
        );
        let backend = Arc::new(FlureeBackend::create(options).await.unwrap());
        backend.bootstrap_governance().await.unwrap();
        let mut roles = BTreeSet::from([
            Iri::http(BackendOperation::Query.role()).unwrap(),
            Iri::http(BackendOperation::Read.role()).unwrap(),
            Iri::http(BackendOperation::Replay.role()).unwrap(),
        ]);
        if grant_invocation {
            roles.insert(
                exact_invocation_role(&ExactInvocationRequirement::new(
                    manifest().artifact().clone(),
                    ResourceId::new(DESTINATION).unwrap(),
                ))
                .unwrap(),
            );
        }
        let principal = PrincipalId::new("alice").unwrap();
        let mut state = PolicyState::deny_all().unwrap();
        state.principals.insert(principal.clone(), (true, roles));
        state.policy = cdb_core::policy::PolicySet::parse(
            br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{"@id":"https://test.example/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}]}"#,
            Limits::default(),
        ).unwrap();
        backend
            .set_policy_state(&IdempotencyKey::new("policy").unwrap(), &state)
            .await
            .unwrap();
        let (token, record) = provision(
            principal,
            None,
            Capabilities::only(&[SessionOperation::Query]),
        )
        .unwrap();
        let auth = AuthStore::new(vec![record], ttl).unwrap();
        Self {
            _dir: dir,
            backend,
            auth,
            token: token.into_string(),
        }
    }
    async fn authorizer(&self) -> Arc<NativeBrokerAuthorizer> {
        let session = self.auth.authenticate(&self.token).await.unwrap();
        let principal = self
            .backend
            .issue_principal(PrincipalId::new("alice").unwrap())
            .await
            .unwrap();
        let execution = self
            .backend
            .capture_execution(
                principal,
                self.backend.head().await.unwrap(),
                cdb_core::Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
                RunId::new("request-1").unwrap(),
                ContentHash::of_bytes(b"plan"),
                BackendOperation::Query,
            )
            .await
            .unwrap();
        Arc::new(
            NativeBrokerAuthorizer::new(
                self.backend.clone(),
                self.auth.clone(),
                session,
                "session-1".into(),
                "request-1".into(),
                execution,
            )
            .await
            .unwrap(),
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generic_broker_authorizer_rejects_replay_execution_without_capability() {
    let fixture = NativeFixture::new(true, Duration::from_secs(2)).await;
    let session = fixture.auth.authenticate(&fixture.token).await.unwrap();
    let principal = fixture
        .backend
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let execution = fixture
        .backend
        .capture_execution(
            principal,
            fixture.backend.head().await.unwrap(),
            cdb_core::Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
            RunId::new("request-1").unwrap(),
            ContentHash::of_bytes(b"plan"),
            BackendOperation::Replay,
        )
        .await
        .unwrap();
    let result = NativeBrokerAuthorizer::new(
        fixture.backend.clone(),
        fixture.auth.clone(),
        session,
        "session-1".into(),
        "request-1".into(),
        execution,
    )
    .await;
    assert!(matches!(result, Err(error) if error.kind == ErrorKind::Denied));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readable_without_exact_invocation_never_reaches_http() {
    let server = Server::start(vec![], false).await;
    let fixture = NativeFixture::new(false, Duration::from_secs(2)).await;
    let authorizer = fixture.authorizer().await;
    let error = match broker(&server.endpoint)
        .invoke(invocation(), authorizer)
        .await
    {
        Ok(_) => panic!("read-only principal reached broker"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Denied);
    assert_eq!(server.finish().await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_grant_allows_one_request_and_fresh_result_consumption() {
    let server = Server::start(vec![200], false).await;
    let fixture = NativeFixture::new(true, Duration::from_secs(2)).await;
    let authorizer = fixture.authorizer().await;
    let value = broker(&server.endpoint)
        .invoke(invocation(), authorizer.clone())
        .await
        .unwrap()
        .consume(authorizer.as_ref())
        .await
        .unwrap();
    assert_eq!(value, V::parse(b"7", Limits::default()).unwrap());
    assert_eq!(server.finish().await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_during_retry_prevents_the_next_http_request() {
    let server = Server::start(vec![503], true).await;
    let fixture = NativeFixture::new(true, Duration::from_secs(2)).await;
    let authorizer = fixture.authorizer().await;
    let broker = broker(&server.endpoint);
    let call = tokio::spawn(async move { broker.invoke(invocation(), authorizer).await });
    timeout(Duration::from_secs(2), server.first_seen.notified())
        .await
        .unwrap();
    let mut state = fixture.backend.policy_state().await.unwrap();
    state
        .principals
        .get_mut(&PrincipalId::new("alice").unwrap())
        .unwrap()
        .1
        .remove(
            &exact_invocation_role(&ExactInvocationRequirement::new(
                manifest().artifact().clone(),
                ResourceId::new(DESTINATION).unwrap(),
            ))
            .unwrap(),
        );
    fixture
        .backend
        .set_policy_state(&IdempotencyKey::new("revoke").unwrap(), &state)
        .await
        .unwrap();
    server.release_first.notify_one();
    let error = match call.await.unwrap() {
        Ok(_) => panic!("revoked retry reached broker"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Denied);
    assert_eq!(server.finish().await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_or_expired_session_prevents_result_consumption() {
    let server = Server::start(vec![200], false).await;
    let fixture = NativeFixture::new(true, Duration::from_millis(200)).await;
    let authorizer = fixture.authorizer().await;
    let result = broker(&server.endpoint)
        .invoke(invocation(), authorizer.clone())
        .await
        .unwrap();
    authorizer.cancel();
    assert_eq!(
        result.consume(authorizer.as_ref()).await.unwrap_err().kind,
        ErrorKind::Denied
    );
    assert_eq!(server.finish().await, 1);

    let server = Server::start(vec![200], false).await;
    let fixture = NativeFixture::new(true, Duration::from_millis(200)).await;
    let authorizer = fixture.authorizer().await;
    let result = broker(&server.endpoint)
        .invoke(invocation(), authorizer.clone())
        .await
        .unwrap();
    sleep(Duration::from_millis(250)).await;
    assert_eq!(
        result.consume(authorizer.as_ref()).await.unwrap_err().kind,
        ErrorKind::Denied
    );
    assert_eq!(server.finish().await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_callbacks_on_one_execution_are_serialized_not_denied_busy() {
    let server = Server::start(vec![200, 200], false).await;
    let fixture = NativeFixture::new(true, Duration::from_secs(2)).await;
    let authorizer = fixture.authorizer().await;
    let broker = Arc::new(broker(&server.endpoint));
    let first = tokio::spawn({
        let broker = broker.clone();
        let authorizer = authorizer.clone();
        async move { broker.invoke(invocation(), authorizer).await }
    });
    let second = tokio::spawn({
        let broker = broker.clone();
        let authorizer = authorizer.clone();
        async move { broker.invoke(invocation(), authorizer).await }
    });
    let first = first.await.unwrap().unwrap();
    let second = second.await.unwrap().unwrap();
    first.consume(authorizer.as_ref()).await.unwrap();
    second.consume(authorizer.as_ref()).await.unwrap();
    assert_eq!(server.finish().await, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_authority_commit_does_not_repeat_request_or_change_original_pin() {
    let server = Server::start(vec![200], false).await;
    let fixture = NativeFixture::new(true, Duration::from_secs(2)).await;
    let authorizer = fixture.authorizer().await;
    let result = broker(&server.endpoint)
        .invoke(invocation(), authorizer.clone())
        .await
        .unwrap();
    let state = fixture.backend.policy_state().await.unwrap();
    fixture
        .backend
        .set_policy_state(&IdempotencyKey::new("unrelated").unwrap(), &state)
        .await
        .unwrap();
    assert_eq!(
        result.consume(authorizer.as_ref()).await.unwrap(),
        V::parse(b"7", Limits::default()).unwrap()
    );
    assert_eq!(server.finish().await, 1);
}
