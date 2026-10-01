//! Actual service construction boundary, not merely the TOML loader.
use cdb_core::{id::PrincipalId, ErrorKind};
use cdb_service::{config::InstanceConfig, Service};
use std::sync::{atomic::AtomicBool, Arc};

fn config(root: &std::path::Path) -> InstanceConfig {
    InstanceConfig::parse(
        r#"schema="ctxql-instance/v2"
projection="projection"
credential-file="credentials.json"
source-root="sources"
[authority]
path="authority"
ledger="startup-service:main"
backend="startup-service"
authority="startup-authority"
graph="startup-graph"
[limits]
deadline_seconds=3600
session_ttl_seconds=86400
"#,
        &root.join("node.toml"),
    )
    .unwrap()
}
#[tokio::test]
async fn v2_lifetimes_reach_the_real_service_and_restart_without_reset() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let secret = root.join("owner.secret");
    Service::initialize(
        config(&root),
        PrincipalId::new("owner").unwrap(),
        secret.clone(),
    )
    .await
    .unwrap();
    let token = std::fs::read_to_string(secret).unwrap();
    for _ in 0..2 {
        let service = Service::open(config(&root)).await.unwrap();
        assert_eq!(service.config().limits.session_ttl_seconds, 86400);
        assert_eq!(service.executor_settings().max_state_bytes, 65536);
        service
            .dispatch(
                &token,
                br#"{"schema":"ctxql-service/v1","op":"status"}"#,
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .dispatch("bad", b"not JSON", Arc::new(AtomicBool::new(false)))
                .await
                .unwrap_err()
                .kind,
            ErrorKind::Denied
        );
        service.shutdown().await.unwrap();
        assert!(service
            .dispatch(
                &token,
                br#"{"schema":"ctxql-service/v1","op":"status"}"#,
                Arc::new(AtomicBool::new(false))
            )
            .await
            .is_err());
        drop(service);
    }
}
#[tokio::test]
async fn v3_initializes_control_around_an_existing_read_only_semantic_ledger() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let semantic_writer =
        fluree_db_api::FlureeBuilder::file(root.join("semantic").to_string_lossy().into_owned())
            .without_indexing()
            .build()
            .unwrap();
    let semantic = semantic_writer
        .create_ledger("semantic:main")
        .await
        .unwrap();
    let config_graph = fluree_db_core::graph_registry::config_graph_iri("semantic:main");
    let fixture = format!(
        r#"@prefix ctxql: <https://ctxql.example/semantic-rdf/v1/> .
GRAPH <{config_graph}> {{
  <urn:config> ctxql:governedDataGraph <urn:claims>, <urn:data> ;
    ctxql:claimGraph <urn:claims> ;
    ctxql:infrastructureGraph <urn:schema> .
}}
GRAPH <urn:claims> {{ <urn:claim-placeholder> <urn:unused> <urn:value> . }}
GRAPH <urn:data> {{ <urn:subject> <urn:predicate> <urn:object> . }}
GRAPH <urn:schema> {{ <urn:schema> <urn:unused> <urn:value> . }}"#
    );
    let semantic = semantic_writer
        .stage_owned(semantic)
        .upsert_turtle(&fixture)
        .execute()
        .await
        .unwrap()
        .ledger;
    let before_t = semantic.t();
    let before_cid = semantic.head_commit_id.clone();
    drop(semantic_writer);

    let config_text = r#"schema="ctxql-instance/v3"
projection="projection"
credential-file="credentials.json"
source-root="sources"
[semantic]
path="semantic"
ledger="semantic:main"
backend="semantic"
authority="semantic-authority"
graph="semantic-graph"
[control]
path="control"
ledger="control:main"
backend="control"
authority="control-authority"
graph="control-graph"
[limits]
deadline_seconds=3600
session_ttl_seconds=86400
"#;
    let config = || InstanceConfig::parse(config_text, &root.join("node.toml")).unwrap();
    Service::initialize(
        config(),
        PrincipalId::new("owner").unwrap(),
        root.join("secret"),
    )
    .await
    .unwrap();
    assert!(root.join("control").exists());

    let service = Service::open(config()).await.unwrap();
    service.shutdown().await.unwrap();

    let reader =
        fluree_db_api::FlureeBuilder::file(root.join("semantic").to_string_lossy().into_owned())
            .without_indexing()
            .build()
            .unwrap();
    let after = reader.ledger("semantic:main").await.unwrap();
    assert_eq!(after.t(), before_t);
    assert_eq!(after.head_commit_id, before_cid);
}

#[tokio::test]
async fn service_revalidates_mutated_schema_before_authority_creation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let mut v1 = config(&root);
    v1.schema = "ctxql-instance/v1".into();
    assert!(
        Service::initialize(v1, PrincipalId::new("owner").unwrap(), root.join("secret"))
            .await
            .is_err()
    );
    assert!(!root.join("authority").exists());
}
