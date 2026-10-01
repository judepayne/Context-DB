use cdb_core::{id::PrincipalId, CanonicalValue as V, ErrorKind, Limits};
use cdb_service::{config::InstanceConfig, Service};
use std::sync::{atomic::AtomicBool, Arc};
fn config(root: &std::path::Path) -> InstanceConfig {
    InstanceConfig::parse(
        &format!(
            r#"schema="ctxql-instance/v1"
projection="projection"
credential-file="credentials.json"
source-root="sources"
[authority]
path="authority"
ledger="service-smoke:main"
backend="smoke"
authority="smoke-authority"
graph="smoke-graph"
[default-config]
iri="https://test/config"
version="1"
hash="{}"
"#,
            cdb_core::id::ContentHash::of_bytes(include_bytes!(
                "../../../fixtures/conformance/p2/config.json"
            ))
            .as_str()
        ),
        &root.join("cdb.toml"),
    )
    .unwrap()
}
async fn call(s: &Arc<Service>, token: &str, v: serde_json::Value) -> cdb_core::Result<Vec<u8>> {
    s.dispatch(
        token,
        &serde_json::to_vec(&v).unwrap(),
        Arc::new(AtomicBool::new(false)),
    )
    .await
}
async fn publish(
    s: &Arc<Service>,
    token: &str,
    iri: &str,
    content: &str,
) -> cdb_core::Result<Vec<u8>> {
    call(s,token,serde_json::json!({"schema":"ctxql-service/v1","op":"publish","artifact":{"iri":iri,"version":"1","hash":cdb_core::id::ContentHash::of_bytes(content.as_bytes()).as_str()},"content":content})).await
}
#[tokio::test]
async fn initialize_auth_publish_record_restart_replay() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let owner = root.join("owner.secret");
    Service::initialize(
        config(&root),
        PrincipalId::new("owner").unwrap(),
        owner.clone(),
    )
    .await
    .unwrap();
    let token = std::fs::read_to_string(owner).unwrap();
    let reader = root.join("reader.secret");
    Service::provision(
        config(&root),
        PrincipalId::new("reader").unwrap(),
        reader.clone(),
        false,
    )
    .await
    .unwrap();
    let reader = std::fs::read_to_string(reader).unwrap();
    let s = Service::open(config(&root)).await.unwrap();
    assert_eq!(
        s.dispatch("bad", b"malformed", Arc::new(AtomicBool::new(false)))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
    call(
        &s,
        &token,
        serde_json::json!({"schema":"ctxql-service/v1","op":"status"}),
    )
    .await
    .unwrap();
    assert_eq!(
        publish(&s, &reader, "https://test/query", "{}")
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
    publish(
        &s,
        &token,
        "https://test/config",
        include_str!("../../../fixtures/conformance/p2/config.json"),
    )
    .await
    .unwrap();
    let query = r#"{"about":[{"from":["missing"],"match":"exact"}],"bounds":{"max_depth":1}}"#;
    publish(&s, &token, "https://test/query", query)
        .await
        .unwrap();
    let req = serde_json::json!({"schema":"ctxql-service/v1","op":"query","run_id":"smoke-run","query":{"iri":"https://test/query","version":"1","hash":cdb_core::id::ContentHash::of_bytes(query.as_bytes()).as_str()}});
    let first = call(&s, &token, req.clone()).await.unwrap();
    let value = V::parse(&first, Limits::default()).unwrap();
    assert_eq!(
        value.field("run_id").unwrap().as_str().unwrap(),
        "smoke-run"
    );
    call(&s, &token, req).await.unwrap();

    let profile = "PROFILE\nNAME native/profile\nRETURN\n  paths = false\n";
    publish(&s, &token, "https://test/profile", profile)
        .await
        .unwrap();
    let text_query = "QUERY\nUSE PROFILE native/profile\nABOUT\n  FROM missing MATCH exact\nBOUNDS\n  max_depth = 1\nWALK outgoing\n  WHERE\n    meta:confidence >= 0.5\n";
    publish(&s, &token, "https://test/text-query", text_query)
        .await
        .unwrap();
    let text_request = serde_json::json!({
        "schema":"ctxql-service/v1", "op":"query", "run_id":"text-run",
        "query":{"iri":"https://test/text-query","version":"1","hash":cdb_core::id::ContentHash::of_bytes(text_query.as_bytes()).as_str()},
        "profile":{"selector":"native/profile","artifact":{"iri":"https://test/profile","version":"1","hash":cdb_core::id::ContentHash::of_bytes(profile.as_bytes()).as_str()}}
    });
    call(&s, &token, text_request).await.unwrap();
    let rejected = serde_json::json!({
        "schema":"ctxql-service/v1", "op":"query", "run_id":"text-name-rejected",
        "query":{"iri":"https://test/text-query","version":"1","hash":cdb_core::id::ContentHash::of_bytes(text_query.as_bytes()).as_str()},
        "profile":{"selector":"different/profile","artifact":{"iri":"https://test/profile","version":"1","hash":cdb_core::id::ContentHash::of_bytes(profile.as_bytes()).as_str()}}
    });
    assert_eq!(
        call(&s, &token, rejected).await.unwrap_err().kind,
        ErrorKind::Invalid
    );
    s.shutdown().await.unwrap();
    drop(s);
    let s = Service::open(config(&root)).await.unwrap();
    let replay = call(
        &s,
        &token,
        serde_json::json!({"schema":"ctxql-service/v1","op":"replay","run_id":"smoke-run"}),
    )
    .await
    .unwrap();
    let v = V::parse(&replay, Limits::default()).unwrap();
    assert_eq!(
        v.field("response")
            .unwrap()
            .field("graph")
            .unwrap()
            .as_str()
            .unwrap(),
        "reproduced"
    );
    let replay = call(
        &s,
        &token,
        serde_json::json!({"schema":"ctxql-service/v1","op":"replay","run_id":"text-run"}),
    )
    .await
    .unwrap();
    assert_eq!(
        V::parse(&replay, Limits::default())
            .unwrap()
            .field("response")
            .unwrap()
            .field("graph")
            .unwrap()
            .as_str()
            .unwrap(),
        "reproduced"
    );
    s.shutdown().await.unwrap();
}
