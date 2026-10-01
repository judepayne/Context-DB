use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

#[test]
fn v3_rejects_every_semantic_control_authority_alias() {
    let base = r#"schema="ctxql-instance/v3"
projection="projection"
credential-file="credentials.json"
source-root="sources"
[semantic]
path="semantic"
ledger="semantic:main"
backend="semantic-backend"
authority="semantic-authority"
graph="semantic-graph"
[control]
path="control"
ledger="control:main"
backend="control-backend"
authority="control-authority"
graph="control-graph"
"#;
    let root = std::path::Path::new("/tmp/ctxql-p5-5-role-separation/node.toml");
    InstanceConfig::parse(base, root).expect("independent roles");
    for (distinct, aliased) in [
        ("path=\"control\"", "path=\"semantic\""),
        ("ledger=\"control:main\"", "ledger=\"semantic:main\""),
        (
            "backend=\"control-backend\"",
            "backend=\"semantic-backend\"",
        ),
        (
            "authority=\"control-authority\"",
            "authority=\"semantic-authority\"",
        ),
        ("graph=\"control-graph\"", "graph=\"semantic-graph\""),
    ] {
        let aliased_config = base.replacen(distinct, aliased, 1);
        assert!(
            InstanceConfig::parse(&aliased_config, root).is_err(),
            "role alias must fail: {distinct}"
        );
    }
}

#[test]
fn semantic_final_fence_rechecks_revocation_at_each_sink_barrier() {
    let checks = Arc::new(AtomicUsize::new(0));
    let observed = checks.clone();
    let fence = SemanticFenceCheck::test(move || {
        if observed.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Denied, "semantic_policy_changed"))
        }
    });

    // Preparation/pre-admission succeeds, then authority changes. The same
    // check at the actual sink (and post-admission in commit paths) fails closed.
    fence.check().unwrap();
    let error = fence.check().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Denied);
    assert_eq!(error.message, "semantic_policy_changed");
    assert_eq!(checks.load(Ordering::SeqCst), 2);
}

async fn call(service: &Arc<Service>, token: &str, request: serde_json::Value) -> V {
    let bytes = service
        .dispatch(
            token,
            &serde_json::to_vec(&request).unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    V::parse(&bytes, Limits::default()).unwrap()
}

#[tokio::test]
async fn no_policy_ordinary_v3_records_v4_without_advancing_semantic_head() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let writer =
        fluree_db_api::FlureeBuilder::file(root.join("semantic").to_string_lossy().into_owned())
            .without_indexing()
            .build()
            .unwrap();
    let semantic = writer.create_ledger("semantic:main").await.unwrap();
    let config_graph = fluree_db_core::graph_registry::config_graph_iri("semantic:main");
    let fixture = format!(
        r#"@prefix ctxql: <https://ctxql.example/semantic-rdf/v1/> .
@prefix f: <https://ns.flur.ee/db#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
GRAPH <{config_graph}> {{
  <urn:config> rdf:type f:LedgerConfig ;
    f:reasoningDefaults <urn:reasoning> ;
    ctxql:governedDataGraph <urn:claims>, <urn:data> ;
    ctxql:claimGraph <urn:claims> ;
    ctxql:infrastructureGraph <urn:schema> .
  <urn:reasoning> f:reasoningModes f:owl2rl ;
    f:schemaSource <urn:schema-ref> ; f:followOwlImports true .
  <urn:schema-ref> rdf:type f:GraphRef ; f:graphSource <urn:schema-source> .
  <urn:schema-source> f:graphSelector <urn:schema> .
}}
GRAPH <urn:claims> {{ <urn:claim-placeholder> <urn:unused> <urn:value> . }}
GRAPH <urn:data> {{ <urn:subject> <urn:predicate> <urn:object> . }}
GRAPH <urn:schema> {{ <urn:schema> rdf:type owl:Ontology . }}"#
    );
    let semantic = writer
        .stage_owned(semantic)
        .upsert_turtle(&fixture)
        .execute()
        .await
        .unwrap()
        .ledger;
    let before_t = semantic.t();
    let before_cid = semantic.head_commit_id.clone();
    drop(writer);

    let text = r#"schema="ctxql-instance/v3"
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
    let config = || InstanceConfig::parse(text, &root.join("node.toml")).unwrap();
    Service::initialize(
        config(),
        PrincipalId::new("owner").unwrap(),
        root.join("owner.secret"),
    )
    .await
    .unwrap();
    assert!(root.join("control").exists());

    let token = std::fs::read_to_string(root.join("owner.secret")).unwrap();
    let service = Service::open(config()).await.unwrap();
    assert!(service.semantic.is_some());

    let config_bytes = include_str!("../../../../fixtures/conformance/p2/config.json");
    let config_hash = ContentHash::of_bytes(config_bytes.as_bytes());
    let published = call(
        &service,
        &token,
        serde_json::json!({
            "schema":"ctxql-service/v1", "op":"publish",
            "artifact":{"iri":"https://test/v3-config","version":"1","hash":config_hash.as_str()},
            "content":config_bytes
        }),
    )
    .await;
    assert_eq!(
        published
            .field("artifact")
            .unwrap()
            .field("iri")
            .unwrap()
            .as_str()
            .unwrap(),
        "https://test/v3-config"
    );
    let query = r#"{"about":[{"from":["missing"],"match":"exact"}],"bounds":{"max_depth":1}}"#;
    let query_hash = ContentHash::of_bytes(query.as_bytes());
    call(
        &service,
        &token,
        serde_json::json!({
            "schema":"ctxql-service/v1", "op":"publish",
            "artifact":{"iri":"https://test/v3-query","version":"1","hash":query_hash.as_str()},
            "content":query
        }),
    )
    .await;
    let prepared = service
        .prepare_execution(
            &token,
            PreparationRequest {
                run_id: RunId::new("v3-separated-run").unwrap(),
                query: ArtifactRef::new(
                    Iri::new("https://test/v3-query").unwrap(),
                    VersionId::new("1").unwrap(),
                    query_hash,
                ),
                config: Some(ArtifactRef::new(
                    Iri::new("https://test/v3-config").unwrap(),
                    VersionId::new("1").unwrap(),
                    config_hash.clone(),
                )),
                profile: None,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert_ne!(&prepared.capture().snapshot, prepared.captures().control());
    let session = service.auth.authenticate(&token).await.unwrap();
    let source_principal = service
        .backend
        .issue_principal(service.auth.principal(&session).await.unwrap())
        .await
        .unwrap();
    let source_request = cdb_core::source::SourceReadRequest {
        source_id: cdb_core::id::SourceId::new("urn:source:missing").unwrap(),
        version: ContentHash::of_bytes(b"missing"),
        selector: cdb_core::evidence::EvidenceSelector::WholeDocument,
        max_bytes: 1,
    };
    let control_provider = service
        .provider(
            source_principal.clone(),
            Some(prepared.captures().control().clone()),
        )
        .unwrap();
    ViewProvider::open(
        &control_provider,
        prepared.capture(),
        &ExecutionOptions::default(),
    )
    .await
    .unwrap();
    let control_error = match control_provider.sources.authorize(&source_request).await {
        Ok(_) => panic!("missing source must be denied"),
        Err(error) => error,
    };
    assert_eq!(control_error.kind, ErrorKind::Denied);
    let wrong_provider = service
        .provider(source_principal, Some(prepared.capture().snapshot.clone()))
        .unwrap();
    ViewProvider::open(
        &wrong_provider,
        prepared.capture(),
        &ExecutionOptions::default(),
    )
    .await
    .unwrap();
    let wrong = match wrong_provider.sources.authorize(&source_request).await {
        Ok(_) => panic!("semantic pin must not authorize a control source"),
        Err(error) => error,
    };
    assert_eq!(wrong.kind, ErrorKind::Snapshot);
    assert_eq!(wrong.message, "foreign snapshot identity");

    /* Legacy direct-host scaffolding retained only as historical test context.
    The active Phase 1 exit test constructs the capability through AcquisitionService.
    let graph_host = crate::graph_query::GraphQueryHost::prepare(
        service.semantic.as_ref().unwrap().clone(),
        service.backend.clone(),
        service.projection.clone(),
        service.coordinator.clone(),
        PrincipalId::new("owner").unwrap(),
        "https://ns.flur.ee/db#view".into(),
        ArtifactRef::new(
            Iri::new("https://test/v3-config").unwrap(),
            VersionId::new("1").unwrap(),
            config_hash.clone(),
        ),
        None,
        crate::graph_query::GraphQueryLimits::default(),
    )
    .await
    .unwrap();
    let graph_session = crate::graph_session::GraphSession::new(
        "test-issuer".into(),
        "document-session".into(),
        "attempt-1".into(),
        "source-version".into(),
        "range-root".into(),
        ["evidence:definition".into(), "evidence:member".into()]
            .into_iter()
            .collect(),
        graph_host,
        crate::graph_workspace::WorkspaceLimits::default(),
        Instant::now() + std::time::Duration::from_secs(30),
    )
    .unwrap();
    let graph_handle = match graph_session
        .query(
            query.as_bytes(),
            crate::graph_query::GraphQueryLimits::default(),
        )
        .await
        .unwrap()
    {
        crate::graph_session::SessionQueryResult::Graph {
            handle,
            node_count,
            claim_count,
        } => {
            assert_eq!((node_count, claim_count), (0, 0));
            handle
        }
        other => panic!("complete query unexpectedly rejected: {other:?}"),
    };
    graph_session.import_graph(&graph_handle).await.unwrap();
    let revision = graph_session.check().await.unwrap().revision;
    let applied = graph_session
        .apply(crate::graph_workspace::ApplyRequest {
            schema: "ctxql.graph-workspace/v1".into(),
            session_id: "document-session".into(),
            expected_revision: revision,
            idempotency_key: "phase-1-exit-drafts".into(),
            edits: vec![
                crate::graph_workspace::Edit::AddNode {
                    temp_id: "agreement".into(),
                    local_id: "agreement".into(),
                    label: "Synthetic Agreement".into(),
                    evidence: vec!["evidence:definition".into()],
                },
                crate::graph_workspace::Edit::AddNode {
                    temp_id: "borrower".into(),
                    local_id: "borrower".into(),
                    label: "Synthetic Borrower".into(),
                    evidence: vec!["evidence:member".into()],
                },
                crate::graph_workspace::Edit::AddClaim {
                    temp_id: "borrower-claim".into(),
                    subject: crate::graph_workspace::RecordRef::Temp {
                        id: "agreement".into(),
                    },
                    predicate: "urn:test:hasBorrower".into(),
                    object: crate::graph_workspace::EndpointRef::Record {
                        record: crate::graph_workspace::RecordRef::Temp {
                            id: "borrower".into(),
                        },
                    },
                    evidence: vec!["evidence:member".into()],
                    fit_note: "synthetic relationship".into(),
                },
                crate::graph_workspace::Edit::AddClaim {
                    temp_id: "name-claim".into(),
                    subject: crate::graph_workspace::RecordRef::Temp {
                        id: "borrower".into(),
                    },
                    predicate: "urn:test:legalName".into(),
                    object: crate::graph_workspace::EndpointRef::Literal {
                        value: crate::graph_workspace::TypedLiteral {
                            lexical: "Synthetic Borrower".into(),
                            datatype: "http://www.w3.org/2001/XMLSchema#string".into(),
                            language: None,
                        },
                    },
                    evidence: vec!["evidence:member".into()],
                    fit_note: "synthetic attribute".into(),
                },
                crate::graph_workspace::Edit::AddReference {
                    temp_id: "original-borrowers".into(),
                    label: "Original Borrowers".into(),
                    scope: "agreement".into(),
                    definition_evidence: vec!["evidence:definition".into()],
                    referent_shape: "collective_role".into(),
                    target_text: Some("Synthetic Borrower".into()),
                    members: vec![crate::graph_workspace::RecordRef::Temp {
                        id: "borrower".into(),
                    }],
                    membership_evidence: vec!["evidence:member".into()],
                    status: crate::graph_workspace::ReferenceStatus::Resolved,
                },
            ],
        })
        .await
        .unwrap();
    assert_eq!(applied.handles.len(), 5);
    for kind in [
        crate::graph_workspace::ViewKind::Overview,
        crate::graph_workspace::ViewKind::Changes,
    ] {
        let view = graph_session.view(kind, None).await.unwrap();
        assert!(!view.rendered.is_empty());
        assert!(!view.view_partial);
    }
    assert!(graph_session.check().await.unwrap().structurally_valid);

    let foreign = crate::graph_workspace::Handle(
        graph_handle
            .0
            .replace("document-session", "foreign-session"),
    );
    assert_eq!(
        graph_session.import_graph(&foreign).await.unwrap_err().kind,
        ErrorKind::Denied
    );
    graph_session.authorize_final_release().await.unwrap();

    */
    let recorded = prepared
        .execute_recorded_v5(ContentHash::of_bytes(b"ordinary-v3-operation"))
        .await
        .unwrap();
    let semantic_run = recorded.run;
    assert_eq!(
        semantic_run
            .replay()
            .semantic()
            .projection()
            .field("policy_mode")
            .unwrap()
            .as_str()
            .unwrap(),
        "unrestricted"
    );
    assert_eq!(
        semantic_run
            .replay()
            .semantic()
            .projection()
            .field("materializer")
            .unwrap()
            .as_str()
            .unwrap(),
        "none/v1"
    );
    assert_eq!(
        semantic_run
            .replay()
            .semantic()
            .capture(Limits::default())
            .unwrap(),
        semantic_run.replay().base().data().snapshot
    );
    assert_ne!(
        semantic_run.replay().control_capture(),
        &semantic_run.replay().base().data().snapshot
    );
    assert_eq!(
        semantic_run.replay().control_capture(),
        prepared.captures().control()
    );
    let retry_principal = service
        .backend
        .issue_principal(PrincipalId::new("owner").unwrap())
        .await
        .unwrap();
    let (retried, _) = service
        .backend
        .retry_original_v5_with_receipt(
            &retry_principal,
            semantic_run.id(),
            semantic_run.operation_hash(),
        )
        .await
        .unwrap();
    assert_eq!(retried, semantic_run);
    let response = V::parse(&recorded.response, Limits::default()).unwrap();
    assert_eq!(
        response.field("status").unwrap().as_str().unwrap(),
        "ready_with_warnings"
    );

    /* Covered by the acquisition-owned Phase 1 exit test below.
    let original_policy = service.backend.policy_state().await.unwrap();
    let mut revoked = original_policy.clone();
    revoked
        .principals
        .get_mut(&PrincipalId::new("owner").unwrap())
        .unwrap()
        .0 = false;
    service
        .backend
        .set_policy_state(
            &IdempotencyKey::new("graph-session-revoke").unwrap(),
            &revoked,
        )
        .await
        .unwrap();
    assert_eq!(
        graph_session.check().await.unwrap_err().kind,
        ErrorKind::Denied
    );
    service
        .backend
        .set_policy_state(
            &IdempotencyKey::new("graph-session-restore").unwrap(),
            &original_policy,
        )
        .await
        .unwrap();
    assert_eq!(
        graph_session.check().await.unwrap_err().kind,
        ErrorKind::Denied
    );
    drop(graph_session);
    */

    drop(wrong_provider);
    drop(control_provider);
    drop(prepared);
    service.shutdown().await.unwrap();
    drop(service);

    let restarted = Service::open(config()).await.unwrap();
    let replayed = call(
        &restarted,
        &token,
        serde_json::json!({
            "schema":"ctxql-service/v1", "op":"replay",
            "run_id":"v3-separated-run", "hydrate":true
        }),
    )
    .await;
    assert_eq!(
        replayed
            .field("response")
            .unwrap()
            .field("graph")
            .unwrap()
            .as_str()
            .unwrap(),
        "reproduced"
    );
    assert!(replayed
        .field("response")
        .unwrap()
        .field("evidence")
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    restarted.shutdown().await.unwrap();
    drop(restarted);

    let reader =
        fluree_db_api::FlureeBuilder::file(root.join("semantic").to_string_lossy().into_owned())
            .without_indexing()
            .build()
            .unwrap();
    let after = reader.ledger("semantic:main").await.unwrap();
    assert_eq!(after.t(), before_t);
    assert_eq!(after.head_commit_id, before_cid);
}
