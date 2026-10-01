//! Public-library and real-loopback parity for dual-ledger instance v3.
mod common_p5_5;

use cdb_backend_fluree::{
    runs::{Operation, ProtectedRun},
    FlureeBackend,
};
use cdb_core::{
    contracts::PolicyService,
    id::{ContentHash, PrincipalId, RunId},
    CanonicalValue, ErrorKind, Limits,
};
use cdb_service::{config::InstanceConfig, Service};
use common_p5_5::{instance_config, read_semantic_head, write_trusted_semantic_fixture};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    path::Path,
    sync::{atomic::AtomicBool, Arc},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

const CONFIG: &str = include_str!("../../../fixtures/conformance/p2/config.json");
const QUERY: &str = r#"{"about":[{"from":["missing"],"match":"exact"}],"bounds":{"max_depth":1}}"#;
const MAPPED_QUERY: &str = r#"{"about":[{"from":["http://example.org/alice"],"match":"exact"}],"bounds":{"max_depth":1},"walk":{"predicates":[["meta:ext:stored","contains","urn:value:stored"],["meta:ext:reasoned","contains","urn:value:stored"],["meta:ext:computed","=",1],{"name":"custom-bound-computed","bind":{"mapped":"meta:ext:computed"},"keep":"true"}]}}"#;
const RESOLVER_IRI: &str = "urn:resolver:semantic-count";
const RESOLVER: &str = "ctxql-local-count/v1";

fn mapped_config() -> String {
    json!({
        "name": "semantic-mapped-public",
        "version": "1",
        "runtime": {
            "candidate_order": ["depth asc", "confidence desc", "transaction_time desc", "claim_id asc"],
            "path_ranking": ["shorter_path", "higher_accumulated_confidence", "better_grounding", "newer_claims", "claim_id_tiebreak"],
            "cycle_policy": "no_repeated_claim",
            "predicate_numeric": "ctxql-predicate-numeric/v2"
        },
        "fields": {
            "meta:ext:stored": {"source":"stored_predicate", "iri":"urn:p:stored"},
            "meta:ext:reasoned": {"source":"reasoned", "iri":"urn:p:reasoned"},
            "meta:ext:computed": {
                "source":"computed",
                "iri":"urn:p:reasoned",
                "resolver": reference(RESOLVER_IRI, RESOLVER)
            }
        },
        "external_functions": {}
    })
    .to_string()
}

fn config(root: &Path) -> InstanceConfig {
    InstanceConfig::parse(&instance_config(root), &root.join("cdb.toml")).unwrap()
}

fn reference(iri: &str, content: &str) -> Value {
    json!({"iri":iri,"version":"1","hash":ContentHash::of_bytes(content.as_bytes()).as_str()})
}

fn operation(
    run_id: &str,
    query_iri: &str,
    query_text: &str,
    config_iri: &str,
    config_text: &str,
) -> Value {
    json!({
        "schema":"ctxql-service/v1", "op":"query", "run_id":run_id,
        "query":reference(query_iri, query_text),
        "config":reference(config_iri, config_text),
        "execution":"native_v3"
    })
}

fn query(run_id: &str) -> Value {
    operation(
        run_id,
        "https://test/v3-query",
        QUERY,
        "https://test/v3-config",
        CONFIG,
    )
}

async fn dispatch(service: &Arc<Service>, token: &str, value: &Value) -> cdb_core::Result<Value> {
    let bytes = service
        .dispatch(
            token,
            &serde_json::to_vec(value).unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await?;
    let canonical = CanonicalValue::parse(&bytes, Limits::default())?;
    serde_json::from_slice(&canonical.canonical_bytes(Limits::default())?)
        .map_err(|_| cdb_core::Error::invalid("test response"))
}

async fn publish(service: &Arc<Service>, token: &str, iri: &str, content: &str) {
    dispatch(
        service,
        token,
        &json!({
            "schema":"ctxql-service/v1", "op":"publish",
            "artifact":reference(iri, content), "content":content
        }),
    )
    .await
    .unwrap();
}

struct Server {
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<cdb_core::Result<()>>,
}

impl Server {
    async fn start(service: Arc<Service>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(cdb_service::http::serve(service, listener, receiver));
        Self { addr, stop, task }
    }

    async fn stop(self) {
        self.stop.send(true).unwrap();
        self.task.await.unwrap().unwrap();
    }
}

async fn http_call(addr: SocketAddr, token: &str, value: &Value) -> (u16, Value) {
    let body = value.to_string();
    let wire = format!(
        "POST /v1/operation HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(wire.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let wire = String::from_utf8(bytes).unwrap();
    let (head, body) = wire.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap())
}

#[tokio::test]
async fn v3_library_and_http_preserve_dual_stores_v4_and_public_errors() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let semantic_head = write_trusted_semantic_fixture(&root).await;
    std::fs::write(root.join("cdb.toml"), instance_config(&root)).unwrap();

    Service::initialize(
        config(&root),
        PrincipalId::new("owner").unwrap(),
        root.join("owner.secret"),
    )
    .await
    .unwrap();
    assert!(root.join("semantic").exists());
    assert!(root.join("control").exists());
    assert_ne!(root.join("semantic"), root.join("control"));
    assert_eq!(read_semantic_head(&root).await, semantic_head);

    let token = std::fs::read_to_string(root.join("owner.secret")).unwrap();
    let service = Service::open(config(&root)).await.unwrap();
    publish(&service, &token, "https://test/v3-config", CONFIG).await;
    publish(&service, &token, "https://test/v3-query", QUERY).await;

    let first = dispatch(&service, &token, &query("v3-public-run"))
        .await
        .unwrap();
    let retry = dispatch(&service, &token, &query("v3-public-run"))
        .await
        .unwrap();
    assert_eq!(retry["response"], first["response"]);
    let mut conflict = query("v3-public-run");
    conflict["consistency"] = json!("exact");
    let library_error = dispatch(&service, &token, &conflict).await.unwrap_err();
    assert_eq!(
        library_error.public_json(),
        r#"{"error":"preparation_failed"}"#
    );

    service.shutdown().await.unwrap();
    drop(service);
    {
        let backend = FlureeBackend::open(config(&root).authority_options().unwrap())
            .await
            .unwrap();
        let principal = backend
            .issue_principal(PrincipalId::new("owner").unwrap())
            .await
            .unwrap();
        let context = backend.current(&principal).await.unwrap();
        let stored = backend
            .guarded_find_versioned_run(
                &principal,
                &context,
                &RunId::new("v3-public-run").unwrap(),
                Operation::Read,
            )
            .await
            .unwrap();
        assert!(matches!(stored, Some(ProtectedRun::V5(_))));
    }
    let restarted = Service::open(config(&root)).await.unwrap();
    let replay = dispatch(
        &restarted,
        &token,
        &json!({
            "schema":"ctxql-service/v1", "op":"replay", "run_id":"v3-public-run"
        }),
    )
    .await
    .unwrap();
    assert_eq!(replay["response"]["graph"], "reproduced");

    let server = Server::start(restarted.clone()).await;
    let (status, http_retry) = http_call(server.addr, &token, &query("v3-public-run")).await;
    assert_eq!(status, 200);
    assert_eq!(http_retry["response"], first["response"]);
    let (status, http_error) = http_call(server.addr, &token, &conflict).await;
    assert_eq!(status, 400);
    assert_eq!(http_error, json!({"error":"preparation_failed"}));
    let (status, http_replay) = http_call(
        server.addr,
        &token,
        &json!({
            "schema":"ctxql-service/v1", "op":"replay", "run_id":"v3-public-run"
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(http_replay["response"]["graph"], "reproduced");
    server.stop().await;
    restarted.shutdown().await.unwrap();
    drop(restarted);

    assert_eq!(read_semantic_head(&root).await, semantic_head);
}

#[tokio::test]
async fn archival_configured_semantic_mapping_is_decodable_but_not_executable() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    write_trusted_semantic_fixture(&root).await;
    std::fs::write(root.join("cdb.toml"), instance_config(&root)).unwrap();
    Service::initialize(
        config(&root),
        PrincipalId::new("owner").unwrap(),
        root.join("owner.secret"),
    )
    .await
    .unwrap();

    let token = std::fs::read_to_string(root.join("owner.secret")).unwrap();
    let mapped_config = mapped_config();
    let mapped = operation(
        "semantic-mapped-run",
        "https://test/semantic-mapped-query",
        MAPPED_QUERY,
        "https://test/semantic-mapped-config",
        &mapped_config,
    );
    let service = Service::open(config(&root)).await.unwrap();
    publish(
        &service,
        &token,
        "https://test/semantic-mapped-config",
        &mapped_config,
    )
    .await;
    publish(
        &service,
        &token,
        "https://test/semantic-mapped-query",
        MAPPED_QUERY,
    )
    .await;
    publish(&service, &token, RESOLVER_IRI, RESOLVER).await;

    let error = dispatch(&service, &token, &mapped)
        .await
        .expect_err("archival 603974f semantic preparation must not execute as current");
    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        cdb_backend_fluree::backend_identity::HISTORICAL_EXECUTOR_UNAVAILABLE
    );
    service.shutdown().await.unwrap();
}
