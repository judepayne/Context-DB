use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    contracts::{GraphBackend, SemanticProjectionSource},
    id::{ContentHash, Iri, VersionId},
    Limits,
};
use cdb_service::{
    acquisition_v2_fixture::AcquisitionV2Fixture,
    chat::{
        ChatOntologyRequest, ChatQueryOutcome, ChatQueryRequest, ChatReadResources,
        ChatSourceRequest,
    },
    config::{ArtifactReference, ChatConfig, ChatLimits},
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
    Service,
};
use std::sync::{atomic::AtomicBool, Arc};

async fn publish_config(service: &Arc<Service>, token: &str) -> ArtifactRef {
    let content = include_bytes!("../../../fixtures/conformance/graph-workspace/config.json");
    let reference = ArtifactRef::new(
        Iri::new("urn:ctxql:chat-native-config").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(content),
    );
    let published =
        PublishedArtifact::new(reference.clone(), content.to_vec(), Limits::default()).unwrap();
    let artifact: serde_json::Value = serde_json::from_slice(
        &published
            .reference()
            .projection()
            .canonical_bytes(Limits::default())
            .unwrap(),
    )
    .unwrap();
    service
        .dispatch(
            token,
            &serde_json::to_vec(&serde_json::json!({
                "schema":"ctxql-service/v1",
                "op":"publish",
                "artifact":artifact,
                "content":String::from_utf8(published.content().to_vec()).unwrap()
            }))
            .unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    reference
}

#[tokio::test]
#[ignore = "run exactly through the serial native-test wrapper"]
async fn standalone_v3_reads_graph_and_rich_source_without_writes_or_acquisition() {
    standalone_reads(false).await;
}

#[tokio::test]
#[ignore = "run exactly through the serial native-test wrapper"]
async fn unsafe_projection_keeps_source_and_credential_checks() {
    standalone_reads(true).await;
}

async fn standalone_reads(unsafe_direct_projection: bool) {
    std::env::set_var("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key");
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let document = fixture
        .write_document(
            "chat-agreement.txt",
            b"Orion is a written agreement under which Acme Ltd borrows GBP 1000.\nOrion was executed on 2022-12-06.\nOrion agreement date: 2022-12-06.\n",
        )
        .unwrap();
    fixture
        .set_pi_response(include_str!(
            "../../../fixtures/conformance/p6/ontology-guided/a2-proposals-v2.json"
        ))
        .unwrap();
    let report = ingest(
        fixture.config().unwrap(),
        SourceTarget::LocalFile(document),
        IngestMode::Admit(IngestWait::Projected),
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        None,
        cdb_provider_pi::cancel::CancellationToken::default(),
    )
    .await
    .unwrap();
    let report = serde_json::to_value(report).unwrap();
    let admitted = report["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap();
    let subject = admitted
        .iter()
        .find(|claim| claim["relation"] == "urn:ctxql:a2:executedOn")
        .unwrap()["subject_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let other_subject = admitted
        .iter()
        .find_map(|claim| {
            claim["subject_id"]
                .as_str()
                .filter(|candidate| *candidate != subject)
        })
        .unwrap()
        .to_owned();

    let token = std::fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let service = Service::open(fixture.config().unwrap()).await.unwrap();
    let query_config = publish_config(&service, &token).await;
    service.shutdown().await.unwrap();
    drop(service);

    let make_config = || {
        let mut config = fixture.config().unwrap();
        let acquisition = config.acquisition.take().unwrap();
        config.schema = "ctxql-instance/v3".into();
        let chat_limits = ChatLimits {
            max_claims: 4,
            ..ChatLimits::default()
        };
        config.chat = Some(ChatConfig {
            unsafe_direct_projection,
            pi_command: acquisition.pi_command,
            pi_bundle: acquisition.pi_bundle,
            pi_session_log_dir: None,
            chat_model: cdb_provider_pi::MODEL.into(),
            thinking: cdb_provider_pi::THINKING.into(),
            query_config: ArtifactReference {
                iri: query_config.iri().as_str().into(),
                version: query_config.version().as_str().into(),
                hash: query_config.hash().as_str().into(),
            },
            profile_selector: None,
            profile: None,
            ontology: None,
            limits: chat_limits,
        });
        config.validate_runtime().unwrap();
        config
    };
    let config = make_config();
    assert!(config.acquisition.is_none());

    let (semantic_path, semantic_options) = config.semantic_binding().unwrap();
    let semantic =
        cdb_backend_fluree::FlureeSemanticLedger::open_file(semantic_path, semantic_options)
            .await
            .unwrap();
    let control = cdb_backend_fluree::FlureeBackend::open(config.authority_options().unwrap())
        .await
        .unwrap();
    let semantic_before = SemanticProjectionSource::head(&semantic).await.unwrap();
    let control_before = GraphBackend::head(&control).await.unwrap();
    drop(semantic);
    drop(control);

    let reads = ChatReadResources::open(config, token.clone())
        .await
        .unwrap();
    reads.begin_turn();
    let ontology = reads
        .ontology(
            ChatOntologyRequest {
                operation: "describe".into(),
                query: "urn:unused".into(),
                limit: None,
                kind: None,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    let ontology: serde_json::Value = serde_json::from_slice(
        &ontology
            .canonical_bytes(cdb_core::Limits::default())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ontology["status"], "ontology_unavailable");
    let query = serde_json::json!({
        "about":[{"from":[subject],"match":"exact"}],
        "bounds":{"max_depth":1,"seed_limit":1,"fanout_limit":16,"max_claims":32,"path_limit":16}
    });
    let outcome = reads
        .graph_query(
            ChatQueryRequest {
                query: query.to_string(),
            },
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    let ChatQueryOutcome::Complete(result) = outcome else {
        panic!("expected complete graph")
    };
    assert!(result.complete);
    assert!(!result.claims.is_empty());
    assert!(result.claims.iter().any(|claim| match &claim.object {
        cdb_service::chat::ChatObject::Literal { datatype, .. } =>
            datatype == "http://www.w3.org/2001/XMLSchema#date",
        _ => false,
    }));
    let source = result
        .source_references
        .iter()
        .find(|source| source.resolvable && source.reference["selectors"]["line"].is_object())
        .expect("rich line-witness source reference");
    let evidence = reads
        .source(
            ChatSourceRequest {
                reference: source.citation.clone().unwrap(),
                max_bytes: None,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    let evidence = serde_json::to_value(evidence).unwrap();
    assert!(!evidence["content"].as_str().unwrap().is_empty());

    let too_broad = reads
        .graph_query(
            ChatQueryRequest {
                query: serde_json::json!({
                    "about":[{"from":[subject, other_subject],"match":"exact"}],
                    "bounds":{"max_depth":1,"seed_limit":2,"fanout_limit":16,"max_claims":32,"path_limit":16}
                })
                .to_string(),
            },
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert!(matches!(too_broad, ChatQueryOutcome::Diagnostic(_)));
    let diagnostic = serde_json::to_value(too_broad).unwrap();
    assert!(diagnostic.get("result_id").is_none());

    // Removing only Read leaves Query usable but denies a fresh source call.
    let credential_path = fixture.root().join("credentials.json");
    let mut credentials: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&credential_path).unwrap()).unwrap();
    credentials["entries"][0]["capabilities"] = serde_json::json!(["query"]);
    std::fs::write(&credential_path, serde_json::to_vec(&credentials).unwrap()).unwrap();
    reads
        .capabilities(Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    let denied_source = reads
        .source(
            ChatSourceRequest {
                reference: source.citation.clone().unwrap(),
                max_bytes: None,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap_err();
    assert_eq!(denied_source.kind, cdb_core::ErrorKind::Denied);
    drop(reads);

    // Query-only credentials are sufficient at startup; source Read remains
    // independently denied on the previously issued exact reference.
    let query_only_reads = ChatReadResources::open(make_config(), token.clone())
        .await
        .unwrap();
    query_only_reads
        .capabilities(Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();

    credentials["entries"][0]["enabled"] = serde_json::Value::Bool(false);
    std::fs::write(&credential_path, serde_json::to_vec(&credentials).unwrap()).unwrap();
    let denied_credential = query_only_reads
        .capabilities(Arc::new(AtomicBool::new(false)))
        .await
        .unwrap_err();
    assert_eq!(denied_credential.kind, cdb_core::ErrorKind::Denied);
    drop(query_only_reads);

    let config = fixture.config().unwrap();
    let (semantic_path, semantic_options) = config.semantic_binding().unwrap();
    let semantic =
        cdb_backend_fluree::FlureeSemanticLedger::open_file(semantic_path, semantic_options)
            .await
            .unwrap();
    let control = cdb_backend_fluree::FlureeBackend::open(config.authority_options().unwrap())
        .await
        .unwrap();
    assert_eq!(
        SemanticProjectionSource::head(&semantic).await.unwrap(),
        semantic_before
    );
    assert_eq!(GraphBackend::head(&control).await.unwrap(), control_before);
    std::env::remove_var("OPENROUTER_API_KEY");
}
