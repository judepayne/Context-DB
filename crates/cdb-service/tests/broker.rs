//! Actual loopback HTTP transport + broker tests with a test-only authorizer.
//! These are not native `Service`/`SessionLease` acceptance tests.
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    function_manifest::ExternalFunctionManifest,
    id::{ContentHash, Iri, ResourceId, VersionId},
    CanonicalValue as V, Error, ErrorKind, Limits,
};
use cdb_service::broker::{
    http::HttpJsonAdapter,
    limits::{BrokerLimits, ResourceLimits},
    permissions::{AuthorizationAction, AuthorizationFuture, GuardedEnqueue, TrustedAuthorizer},
    registry::{ProviderRegistration, Registry},
    Broker, BrokerSettings, Invocation,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
    task::JoinHandle,
    time::timeout,
};

const BUILD_HASH: &str = "sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f";
const MANIFEST_BYTES: &[u8] = br#"{"schema":"ctxql-external-function/v1","name":"test-function","version":"1","implementation":{"implementation":"urn:test:http-json","version":"1","build":"sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f","model":null},"input_schema":{"type":"string"},"output_schema":{"type":"number"},"semantic_parameters":{},"capabilities":[],"declarations":{"deterministic":true,"order_independent":true,"retry_safe":true,"batching":"none"}}"#;

struct LoopbackServer {
    endpoint: String,
    requests: Arc<Mutex<Vec<V>>>,
    first_seen: Arc<Notify>,
    release_first: Arc<Notify>,
    task: JoinHandle<()>,
}

impl LoopbackServer {
    async fn start(statuses: Vec<u16>, pause_first: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/invoke", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let first_seen = Arc::new(Notify::new());
        let seen = first_seen.clone();
        let release_first = Arc::new(Notify::new());
        let release = release_first.clone();
        let task = tokio::spawn(async move {
            for (index, status) in statuses.into_iter().enumerate() {
                let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept())
                    .await
                    .expect("bounded server accept")
                    .unwrap();
                let mut wire = Vec::new();
                let header_end = loop {
                    let mut chunk = [0_u8; 1024];
                    let n = timeout(Duration::from_secs(2), stream.read(&mut chunk))
                        .await
                        .expect("bounded request read")
                        .unwrap();
                    assert_ne!(n, 0, "request ended before headers");
                    wire.extend_from_slice(&chunk[..n]);
                    if let Some(position) = wire.windows(4).position(|w| w == b"\r\n\r\n") {
                        break position + 4;
                    }
                    assert!(wire.len() < 16 * 1024, "request headers too large");
                };
                let headers = std::str::from_utf8(&wire[..header_end]).unwrap();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .expect("request content-length");
                while wire.len() - header_end < content_length {
                    let mut chunk = [0_u8; 1024];
                    let n = timeout(Duration::from_secs(2), stream.read(&mut chunk))
                        .await
                        .expect("bounded request body read")
                        .unwrap();
                    assert_ne!(n, 0, "request ended before body");
                    wire.extend_from_slice(&chunk[..n]);
                }
                let request_value = V::parse(
                    &wire[header_end..header_end + content_length],
                    Limits::default(),
                )
                .unwrap();
                captured.lock().unwrap().push(request_value.clone());
                if index == 0 {
                    seen.notify_one();
                    if pause_first {
                        timeout(Duration::from_secs(2), release.notified())
                            .await
                            .expect("bounded first-response barrier");
                    }
                }
                let body = if status == 200 {
                    let mut response = BTreeMap::new();
                    response.insert(
                        "manifest".into(),
                        request_value.field("manifest").unwrap().clone(),
                    );
                    response.insert("output".into(), V::parse(b"7", Limits::default()).unwrap());
                    response.insert("schema".into(), V::String("ctxql-function-http/v1".into()));
                    V::Object(response)
                        .canonical_bytes(Limits::default())
                        .unwrap()
                } else {
                    b"unavailable".to_vec()
                };
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Service Unavailable"
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            endpoint,
            requests,
            first_seen,
            release_first,
            task,
        }
    }

    async fn finish(self) -> Vec<V> {
        timeout(Duration::from_secs(3), self.task)
            .await
            .expect("bounded server completion")
            .unwrap();
        Arc::try_unwrap(self.requests)
            .unwrap_or_else(|_| panic!("request capture still shared"))
            .into_inner()
            .unwrap()
    }
}

/// Test-only authorization seam for actual transport tests; it is deliberately not a
/// production or native `Service`/`SessionLease` authorizer.
struct ActualTransportTestAuthorizer {
    exact_manifest: Vec<u8>,
    revoked: AtomicBool,
    dispatch_checks: Mutex<Vec<u8>>,
    result_checks: AtomicUsize,
}

impl ActualTransportTestAuthorizer {
    fn new() -> Self {
        Self {
            exact_manifest: MANIFEST_BYTES.to_vec(),
            revoked: AtomicBool::new(false),
            dispatch_checks: Mutex::new(Vec::new()),
            result_checks: AtomicUsize::new(0),
        }
    }

    fn verify(&self, action: &AuthorizationAction<'_>) {
        assert_eq!(action.session_id, "session-1");
        assert_eq!(action.request_id, "request-1");
        assert_eq!(action.logical_id, "logical-1");
        assert_eq!(action.provider.as_str(), "destination-1");
        assert_eq!(action.manifest.exact_bytes(), self.exact_manifest);
    }
}

impl TrustedAuthorizer for ActualTransportTestAuthorizer {
    fn authorize_and_enqueue<'a>(
        &'a self,
        action: AuthorizationAction<'a>,
        enqueue: Box<dyn GuardedEnqueue>,
    ) -> AuthorizationFuture<'a, cdb_service::broker::dispatch::Attempt> {
        Box::pin(async move {
            self.verify(&action);
            self.dispatch_checks.lock().unwrap().push(action.attempt);
            if self.revoked.load(Ordering::SeqCst) {
                return Err(Error::new(ErrorKind::Denied, "test authority revoked"));
            }
            enqueue.enqueue()
        })
    }

    fn authorize_result<'a>(
        &'a self,
        action: AuthorizationAction<'a>,
        result: &'a V,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.verify(&action);
            if self.revoked.load(Ordering::SeqCst) {
                return Err(Error::new(ErrorKind::Denied, "test authority revoked"));
            }
            assert_eq!(result, &V::parse(b"7", Limits::default()).unwrap());
            self.result_checks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

fn broker(endpoint: &str) -> Broker {
    let artifact_ref = ArtifactRef::new(
        Iri::new("urn:test:exact-manifest").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(MANIFEST_BYTES),
    );
    let artifact =
        PublishedArtifact::new(artifact_ref, MANIFEST_BYTES.to_vec(), Limits::default()).unwrap();
    let manifest = ExternalFunctionManifest::from_published(&artifact, Limits::default()).unwrap();
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
        destination: ResourceId::new("destination-1").unwrap(),
        group: ResourceId::new("group-1").unwrap(),
        limits: resource_limits,
        allowed_manifests: BTreeSet::from([ProviderRegistration::binding(manifest.artifact())]),
        adapter,
    };
    let registry = Registry::new(vec![manifest], vec![provider]).unwrap();
    let limits = BrokerLimits {
        call_timeout_ms: 1_000,
        ..BrokerLimits::default()
    };
    let settings = BrokerSettings {
        enabled: true,
        limits,
        groups: BTreeMap::from([("group-1".into(), resource_limits)]),
    };
    Broker::new(
        registry,
        settings,
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
        argument_dependencies: vec![ResourceId::new("argument-1").unwrap()],
        state_dependencies: vec![],
        fact_dependencies: vec![],
        scope_dependencies: vec![],
        input: V::String("hello".into()),
    }
}

#[tokio::test]
async fn loopback_http_delivers_value_with_exact_manifest_binding_and_consumption() {
    let server = LoopbackServer::start(vec![200], false).await;
    let broker = broker(&server.endpoint);
    let authorizer = Arc::new(ActualTransportTestAuthorizer::new());

    let result = timeout(
        Duration::from_secs(3),
        broker.invoke(invocation(), authorizer.clone()),
    )
    .await
    .expect("bounded invocation")
    .unwrap()
    .consume(authorizer.as_ref())
    .await
    .unwrap();

    assert_eq!(result, V::parse(b"7", Limits::default()).unwrap());
    assert_eq!(*authorizer.dispatch_checks.lock().unwrap(), vec![1]);
    assert_eq!(authorizer.result_checks.load(Ordering::SeqCst), 1);
    let requests = server.finish().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].field("input").unwrap().as_str().unwrap(),
        "hello"
    );
    assert_eq!(
        requests[0]
            .field("call")
            .unwrap()
            .field("logical_id")
            .unwrap()
            .as_str()
            .unwrap(),
        "logical-1"
    );
}

#[tokio::test]
async fn retryable_503_retries_one_logical_invocation_with_authorization_each_attempt() {
    let server = LoopbackServer::start(vec![503, 200], false).await;
    let broker = broker(&server.endpoint);
    let authorizer = Arc::new(ActualTransportTestAuthorizer::new());

    let value = timeout(
        Duration::from_secs(3),
        broker.invoke(invocation(), authorizer.clone()),
    )
    .await
    .expect("bounded invocation")
    .unwrap()
    .consume(authorizer.as_ref())
    .await
    .unwrap();

    assert_eq!(value, V::parse(b"7", Limits::default()).unwrap());
    assert_eq!(*authorizer.dispatch_checks.lock().unwrap(), vec![1, 2]);
    assert_eq!(authorizer.result_checks.load(Ordering::SeqCst), 1);
    let requests = server.finish().await;
    assert_eq!(requests.len(), 2);
    for (index, request) in requests.iter().enumerate() {
        let call = request.field("call").unwrap();
        assert_eq!(
            call.field("logical_id").unwrap().as_str().unwrap(),
            "logical-1"
        );
        assert_eq!(
            call.field("attempt")
                .unwrap()
                .as_number()
                .unwrap()
                .to_u64()
                .unwrap(),
            (index + 1) as u64
        );
    }
}

#[tokio::test]
async fn revocation_during_retry_backoff_denies_second_dispatch() {
    let server = LoopbackServer::start(vec![503], true).await;
    let broker = Arc::new(broker(&server.endpoint));
    let authorizer = Arc::new(ActualTransportTestAuthorizer::new());
    let call = tokio::spawn({
        let broker = broker.clone();
        let authorizer = authorizer.clone();
        async move { broker.invoke(invocation(), authorizer).await }
    });

    timeout(Duration::from_secs(2), server.first_seen.notified())
        .await
        .expect("bounded first-request notification");
    authorizer.revoked.store(true, Ordering::SeqCst);
    server.release_first.notify_one();

    let error = match timeout(Duration::from_secs(3), call)
        .await
        .expect("bounded invocation")
        .unwrap()
    {
        Ok(_) => panic!("revoked retry unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Denied);
    assert_eq!(*authorizer.dispatch_checks.lock().unwrap(), vec![1, 2]);
    assert_eq!(authorizer.result_checks.load(Ordering::SeqCst), 0);
    assert_eq!(
        server.finish().await.len(),
        1,
        "only the first request reached HTTP"
    );
}
