use cdb_backend_fluree::{
    official_bootstrap::{
        ACQUISITION_V2_FIXTURE_CLAIMS_GRAPH, ACQUISITION_V2_FIXTURE_DATA_GRAPH,
        ACQUISITION_V2_FIXTURE_LEDGER, ACQUISITION_V2_FIXTURE_REVIEW_GRAPH,
    },
    FlureeSemanticLedger,
};
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    contracts::SemanticProjectionSource,
    id::{ContentHash, Iri, RunId, VersionId},
    ErrorKind, Limits,
};
use cdb_provider_pi::cancel::CancellationToken;
use cdb_service::{
    acquisition_v2_fixture::AcquisitionV2Fixture,
    config::{
        AcquisitionEntitySource, AcquisitionGraphWorkspaceConfig, ArtifactReference, InstanceConfig,
    },
    ingest::{ingest, IngestMode, OntologyMode},
    service::PreparationRequest,
    source_target::SourceTarget,
    Service,
};
use cdb_source_store::SourceObjectReader;
use std::sync::{atomic::AtomicBool, Arc};

#[tokio::test]
async fn fresh_4_2_1_fixture_opens_current_catalog_and_independent_service_stores() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let receipt = fixture.bootstrap_receipt();
    assert_eq!(receipt.ledger, ACQUISITION_V2_FIXTURE_LEDGER);
    assert_eq!(receipt.t, 1);
    assert_eq!(receipt.reasoning_mode, "none");
    assert_eq!(receipt.review_graph, ACQUISITION_V2_FIXTURE_REVIEW_GRAPH);

    assert!(
        fixture
            .config()
            .unwrap()
            .acquisition
            .unwrap()
            .ontology_ledger_path
            .is_none(),
        "ontology-v2 fixture must use its captured Semantic vocabulary"
    );

    let catalog = fixture.reload_catalog().await.unwrap();
    assert_eq!(
        catalog.identity().profile_identity(),
        cdb_core::recording_v5::CURRENT_ACQUISITION_PROFILE_ID
    );
    assert_eq!(catalog.identity(), fixture.catalog_identity());
    let terms = catalog
        .terms()
        .map(|term| term.iri().as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for term in [
        "urn:ctxql:a2:Agreement",
        "urn:ctxql:a2:CreditAgreement",
        "urn:ctxql:a2:WrittenContract",
        "urn:ctxql:a2:Borrower",
        "urn:ctxql:a2:hasBorrower",
        "urn:ctxql:a2:executedOn",
        "urn:ctxql:a2:effectiveOn",
        "http://www.w3.org/2001/XMLSchema#date",
    ] {
        assert!(terms.contains(term), "missing catalog term {term}");
    }

    for path in ["semantic", "control", "projection", "sources"] {
        assert!(
            fixture.root().join(path).exists(),
            "missing fresh {path} store"
        );
    }
    assert_ne!(
        fixture.root().join("semantic"),
        fixture.root().join("control")
    );
    assert_eq!(fixture.pi_invocations().unwrap(), 0);
}

fn enable_graph_workspace(config: &mut InstanceConfig) {
    let acquisition = config.acquisition.as_mut().unwrap();
    acquisition.window.mode = "off".into();
    acquisition.graph_workspace = Some(AcquisitionGraphWorkspaceConfig {
        query_config: None,
        profile_selector: None,
        profile: None,
        query_timeout_seconds: 10,
        max_nodes: 50,
        max_claims: 100,
        max_live_graphs: 3,
        max_tool_calls: 40,
        max_graph_queries: 12,
        max_request_bytes: 32 * 1024,
        max_response_bytes: 64 * 1024,
        max_aggregate_bytes: 1024 * 1024,
        max_state_bytes: 2 * 1024 * 1024,
        max_context_bytes: 512 * 1024,
        reserved_final_output_bytes: 64 * 1024,
        reserved_tool_result_bytes: 256 * 1024,
    });
}

fn enable_identity_source(config: &mut InstanceConfig, approved_agreement: &str) {
    let acquisition = config.acquisition.as_mut().unwrap();
    acquisition.approved_entity_iris = vec![approved_agreement.to_owned()];
    acquisition.entity_source = Some(AcquisitionEntitySource {
        graphs: vec![
            ACQUISITION_V2_FIXTURE_CLAIMS_GRAPH.to_owned(),
            ACQUISITION_V2_FIXTURE_DATA_GRAPH.to_owned(),
        ],
        classes: vec!["urn:ctxql:a2:CreditAgreement".into()],
        identifying_predicates: vec!["urn:ctxql:a2:hasBorrower".into()],
    });
}

#[test]
fn graph_workspace_full_document_uses_real_socket_and_replays_offline() {
    let evidence = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let status = std::process::Command::new(executable)
        .args([
            "--ignored",
            "--exact",
            "acquisition_v2_graph_workspace_child",
            "--test-threads=1",
        ])
        .env("RUST_MIN_STACK", "33554432")
        .env("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key")
        .env("CDB_A2_EVIDENCE_DIR", evidence.path())
        .status()
        .unwrap();
    assert!(status.success(), "serial graph-workspace child failed");
}

#[tokio::test]
#[ignore = "run only through the serial environment wrapper"]
async fn acquisition_v2_graph_workspace_child() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let document = fixture
        .write_document(
            "graph-agreement.txt",
            b"Orion identifies as urn:ctxql:a2:CreditAgreement and names approved borrower Acme Ltd as urn:ctxql:a2:Borrower.\nNew Party LLC is also a borrower.\nOrion was executed on 2022-12-06.\nOriginal Borrowers means Acme Ltd and New Party LLC, the parties listed in Schedule 1.\n",
        )
        .unwrap();
    fixture
        .set_pi_response(include_str!(
            "../../../fixtures/conformance/p6/ontology-guided/a2-proposals-v2.json"
        ))
        .unwrap();
    let seed_document = fixture
        .write_document(
            "graph-context-seed.txt",
            b"Orion is a written agreement under which Acme Ltd borrows GBP 1000.\nOrion was executed on 2022-12-06.\nOrion agreement date: 2022-12-06.\n",
        )
        .unwrap();
    let seed = ingest(
        fixture.config().unwrap(),
        SourceTarget::LocalFile(seed_document),
        IngestMode::Admit(cdb_service::ingest::IngestWait::Projected),
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        None,
        CancellationToken::default(),
    )
    .await
    .unwrap();
    let seed = serde_json::to_value(seed).unwrap();
    let relation = seed["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|claim| claim["relation"] == "urn:ctxql:a2:hasBorrower")
        .unwrap();
    let approved_agreement = relation["subject_id"].as_str().unwrap();
    let readable_unapproved_party = relation["object_id"].as_str().unwrap();
    std::fs::write(
        &document,
        format!(
            "Orion identifies its borrower as {readable_unapproved_party}. Orion identifies as urn:ctxql:a2:CreditAgreement and names approved borrower Acme Ltd as urn:ctxql:a2:Borrower.\nNew Party LLC is also a borrower.\nOrion was executed on 2022-12-06.\nOriginal Borrowers means Acme Ltd and New Party LLC, the parties listed in Schedule 1.\n"
        ),
    )
    .unwrap();
    fixture
        .set_identity_pi_response(approved_agreement, readable_unapproved_party)
        .unwrap();
    std::fs::write(fixture.root().join("graph-query.json"), serde_json::to_vec(&serde_json::json!({
        "about":[{"from":[approved_agreement],"match":"exact"}],
        "bounds":{"max_depth":1,"seed_limit":4,"fanout_limit":20,"max_claims":30,"path_limit":30},
        "walk":{"direction":"outgoing","predicates":[["meta:relation","=","urn:ctxql:a2:hasBorrower"]]}
    })).unwrap()).unwrap();
    let token = std::fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let publisher = Service::open(fixture.config().unwrap()).await.unwrap();
    let query_config: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/graph-workspace/config.json"
    ))
    .unwrap();
    let query_config = publish_artifact(
        &publisher,
        &token,
        "urn:ctxql:graph-workspace-config",
        query_config,
    )
    .await;
    publisher.shutdown().await.unwrap();
    drop(publisher);
    let mut config = fixture.config().unwrap();
    config.default_config = Some(ArtifactReference {
        iri: query_config.iri().as_str().to_owned(),
        version: query_config.version().as_str().to_owned(),
        hash: query_config.hash().as_str().to_owned(),
    });
    enable_graph_workspace(&mut config);
    enable_identity_source(&mut config, approved_agreement);
    let capture_file = std::path::PathBuf::from(std::env::var("CDB_A2_EVIDENCE_DIR").unwrap())
        .join("graph-capture.json");
    let report = ingest(
        config,
        SourceTarget::LocalFile(document.clone()),
        IngestMode::Admit(cdb_service::ingest::IngestWait::Admitted),
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        Some(capture_file.display().to_string()),
        CancellationToken::default(),
    )
    .await
    .unwrap();
    let report = serde_json::to_value(report).unwrap();
    assert_eq!(fixture.pi_invocations().unwrap(), 2);
    let retained: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&capture_file).unwrap()).unwrap();
    assert_eq!(
        retained["graph"]["workspace"]["limits"]["max_aggregate_bytes"],
        256 * 1024
    );
    assert_eq!(
        retained["graph"]["capability"]["max_aggregate_bytes"],
        256 * 1024
    );
    let transcript = retained["graph"]["transcript_leaves"].as_array().unwrap();
    assert_eq!(transcript.len(), 7);
    let recoverable = transcript
        .iter()
        .find(|leaf| leaf["result_kind"] == "error")
        .expect("recoverable revision conflict was not captured");
    let recoverable_response: serde_json::Value =
        serde_json::from_str(recoverable["response"].as_str().unwrap()).unwrap();
    assert_eq!(
        recoverable_response,
        serde_json::json!({
            "schema":"ctxql-graph-tool-error/v1",
            "status":"error",
            "code":"preparation_failed"
        })
    );
    assert_eq!(retained["graph"]["workspace"]["revision"], 3);
    assert_eq!(retained["graph"]["workspace"]["counters"]["tool_calls"], 7);
    let captured_counters = retained["graph"]["workspace"]["counters"].clone();
    let capture_bytes_before_replay = std::fs::read(&capture_file).unwrap();
    let checker = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/check_acquisition_capture_v2.py");
    let checked = std::process::Command::new("python3")
        .arg(checker)
        .arg(&capture_file)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert_eq!(report["admitted_claim_count"], 6);
    let admitted = report["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap();
    let borrower_objects = admitted
        .iter()
        .filter(|claim| claim["relation"] == "urn:ctxql:a2:hasBorrower")
        .map(|claim| claim["object_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        admitted
            .iter()
            .filter(|claim| claim["relation"] == "urn:ctxql:a2:hasBorrower")
            .all(|claim| claim["subject_id"].as_str() == Some(approved_agreement)),
        "approved known agreement was not reused"
    );
    assert!(
        !borrower_objects.contains(readable_unapproved_party),
        "readable unapproved party identity was reused"
    );
    assert_eq!(
        borrower_objects.len(),
        2,
        "collective reference became a third borrower"
    );
    assert!(
        admitted.iter().any(|claim| {
            claim["relation"] == "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
                && claim["object_id"] == "urn:ctxql:a2:Borrower"
                && claim["subject_id"].as_str() != Some(readable_unapproved_party)
        }),
        "readable unapproved party identity was reused"
    );
    let job = cdb_core::id::JobId::new(report["documents"][0]["job_id"].as_str().unwrap()).unwrap();
    let mut access_config = fixture.config().unwrap();
    access_config.default_config = Some(ArtifactReference {
        iri: query_config.iri().as_str().to_owned(),
        version: query_config.version().as_str().to_owned(),
        hash: query_config.hash().as_str().to_owned(),
    });
    enable_graph_workspace(&mut access_config);
    enable_identity_source(&mut access_config, approved_agreement);
    let access = cdb_service::acquisition_inspection::AuthorizedAcquisition::open_authenticated(
        access_config,
        &token,
        cdb_backend_fluree::runs::Operation::Read,
        cdb_service::auth::Operation::Read,
    )
    .await
    .unwrap();
    let inspected = access.inspect(&token, job.clone()).await.unwrap();
    let artifacts = inspected.field("artifacts").unwrap().as_array().unwrap();
    assert!(!artifacts.is_empty());
    assert!(artifacts.iter().all(|value| {
        value.field("schema").unwrap().as_str().unwrap()
            == "ctxql-acquisition-artifact-descriptor/v3"
    }));
    let descriptor = artifacts.first().unwrap();
    access
        .read_artifact(&token, job.clone(), descriptor)
        .await
        .unwrap();
    let capture_root = ContentHash::parse(
        artifacts
            .iter()
            .find(|value| {
                value.field("artifact_kind").unwrap().as_str().unwrap() == "provider_graph_capture"
            })
            .unwrap()
            .field("artifact_root")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let before = fixture.pi_invocations().unwrap();
    let queries_before_replay = fixture.graph_query_invocations();
    assert!(queries_before_replay > 0);
    access
        .replay_ephemeral(
            &token,
            capture_root.clone(),
            OntologyMode::Hard,
            cdb_service::config::AcquisitionAssertionPolicy::Accepted,
        )
        .await
        .unwrap();
    assert_eq!(fixture.pi_invocations().unwrap(), before);
    assert_eq!(
        fixture.graph_query_invocations(),
        queries_before_replay,
        "replay executed a live graph search"
    );
    let retained_after_replay: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&capture_file).unwrap()).unwrap();
    assert_eq!(
        retained_after_replay["graph"]["workspace"]["counters"], captured_counters,
        "offline replay changed captured workspace counters"
    );
    assert_eq!(
        std::fs::read(&capture_file).unwrap(),
        capture_bytes_before_replay,
        "offline replay rewrote the capture"
    );
    let observer_config = fixture.config().unwrap();
    let (observer_path, observer_options) = observer_config.semantic_binding().unwrap();
    let observer = FlureeSemanticLedger::open_file(observer_path, observer_options)
        .await
        .unwrap();
    let replay_head = SemanticProjectionSource::head(&observer).await.unwrap();
    access
        .replay(
            &token,
            capture_root.clone(),
            OntologyMode::Hard,
            cdb_service::config::AcquisitionAssertionPolicy::Accepted,
            cdb_service::ingest::IngestWait::Admitted,
        )
        .await
        .unwrap();
    assert_eq!(
        SemanticProjectionSource::head(&observer).await.unwrap(),
        replay_head,
        "durable replay duplicated an exact existing admission"
    );
    assert_eq!(fixture.pi_invocations().unwrap(), before);
    assert_eq!(fixture.graph_query_invocations(), queries_before_replay);
    drop(observer);
    access.shutdown().await.unwrap();
    drop(access);
    let work_before = tree_content(fixture.root().join("control/acquisition-work-v2"));
    let sources_before = tree_content(fixture.root().join("sources"));
    let mut extract_config = fixture.config().unwrap();
    extract_config.default_config = Some(ArtifactReference {
        iri: query_config.iri().as_str().to_owned(),
        version: query_config.version().as_str().to_owned(),
        hash: query_config.hash().as_str().to_owned(),
    });
    enable_graph_workspace(&mut extract_config);
    enable_identity_source(&mut extract_config, approved_agreement);
    let extracted = ingest(
        extract_config,
        SourceTarget::LocalFile(document),
        IngestMode::ExtractOnly,
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        None,
        CancellationToken::default(),
    )
    .await
    .unwrap();
    let extracted = serde_json::to_value(extracted).unwrap();
    assert_eq!(extracted["admitted_claim_count"], 0);
    assert_eq!(fixture.pi_invocations().unwrap(), before + 1);
    assert_eq!(
        tree_content(fixture.root().join("control/acquisition-work-v2")),
        work_before
    );
    assert_eq!(tree_content(fixture.root().join("sources")), sources_before);

    let semantic_config = fixture.config().unwrap();
    let (semantic_path, semantic_options) = semantic_config.semantic_binding().unwrap();
    let semantic = FlureeSemanticLedger::open_file(semantic_path, semantic_options)
        .await
        .unwrap();
    let committed_business_head = SemanticProjectionSource::head(&semantic).await.unwrap();
    let graph_revoker = Service::open(fixture.config().unwrap()).await.unwrap();
    fixture
        .set_graph_query_access(&graph_revoker, false)
        .await
        .unwrap();
    graph_revoker.shutdown().await.unwrap();
    drop(graph_revoker);
    let mut graph_revoked_config = fixture.config().unwrap();
    graph_revoked_config.default_config = Some(ArtifactReference {
        iri: query_config.iri().as_str().to_owned(),
        version: query_config.version().as_str().to_owned(),
        hash: query_config.hash().as_str().to_owned(),
    });
    enable_graph_workspace(&mut graph_revoked_config);
    enable_identity_source(&mut graph_revoked_config, approved_agreement);
    let denied_graph =
        cdb_service::acquisition_inspection::AuthorizedAcquisition::open_authenticated(
            graph_revoked_config,
            &token,
            cdb_backend_fluree::runs::Operation::Read,
            cdb_service::auth::Operation::Read,
        )
        .await
        .unwrap();
    for error in [
        denied_graph.inspect(&token, job.clone()).await.unwrap_err(),
        denied_graph
            .read_artifact(&token, job.clone(), descriptor)
            .await
            .unwrap_err(),
        denied_graph
            .replay_ephemeral(
                &token,
                capture_root.clone(),
                OntologyMode::Hard,
                cdb_service::config::AcquisitionAssertionPolicy::Accepted,
            )
            .await
            .unwrap_err(),
        denied_graph
            .resume(
                &token,
                job.clone(),
                cdb_service::acquisition::WaitPoint::Admitted,
            )
            .await
            .unwrap_err(),
    ] {
        assert_eq!(error.kind, ErrorKind::Denied);
    }
    denied_graph.shutdown().await.unwrap();
    drop(denied_graph);
    assert_eq!(
        SemanticProjectionSource::head(&semantic).await.unwrap(),
        committed_business_head
    );
    assert_eq!(fixture.pi_invocations().unwrap(), before + 1);
    let restore_graph = Service::open(fixture.config().unwrap()).await.unwrap();
    fixture
        .set_graph_query_access(&restore_graph, true)
        .await
        .unwrap();
    restore_graph.shutdown().await.unwrap();
    drop(restore_graph);
    let revoker = Service::open(fixture.config().unwrap()).await.unwrap();
    fixture.revoke_source_access(&revoker).await.unwrap();
    revoker.shutdown().await.unwrap();
    drop(revoker);

    let mut revoked_config = fixture.config().unwrap();
    revoked_config.default_config = Some(ArtifactReference {
        iri: query_config.iri().as_str().to_owned(),
        version: query_config.version().as_str().to_owned(),
        hash: query_config.hash().as_str().to_owned(),
    });
    enable_graph_workspace(&mut revoked_config);
    enable_identity_source(&mut revoked_config, approved_agreement);
    let revoked = cdb_service::acquisition_inspection::AuthorizedAcquisition::open_authenticated(
        revoked_config,
        &token,
        cdb_backend_fluree::runs::Operation::Read,
        cdb_service::auth::Operation::Read,
    )
    .await
    .unwrap();
    for error in [
        revoked.inspect(&token, job.clone()).await.unwrap_err(),
        revoked
            .read_artifact(&token, job, descriptor)
            .await
            .unwrap_err(),
        revoked
            .replay_ephemeral(
                &token,
                capture_root,
                OntologyMode::Hard,
                cdb_service::config::AcquisitionAssertionPolicy::Accepted,
            )
            .await
            .unwrap_err(),
    ] {
        assert_eq!(error.kind, ErrorKind::Denied, "unexpected error: {error:?}");
    }
    assert_eq!(
        fixture.pi_invocations().unwrap(),
        before + 1,
        "revoked graph-backed replay called Pi"
    );
    assert_eq!(
        SemanticProjectionSource::head(&semantic).await.unwrap(),
        committed_business_head,
        "source revocation or denied graph-backed operations changed committed business"
    );
    revoked.shutdown().await.unwrap();
}

fn tree_content(
    root: std::path::PathBuf,
) -> std::collections::BTreeMap<std::path::PathBuf, ContentHash> {
    fn visit(
        root: &std::path::Path,
        path: &std::path::Path,
        result: &mut std::collections::BTreeMap<std::path::PathBuf, ContentHash>,
    ) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    ContentHash::of_bytes(&std::fs::read(&path).unwrap()),
                );
            }
        }
    }
    let mut result = std::collections::BTreeMap::new();
    visit(&root, &root, &mut result);
    result
}

#[test]
fn foreground_v2_uses_captured_semantic_vocabulary_and_prompt_ranges() {
    let evidence = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let status = std::process::Command::new(executable)
        .args([
            "--ignored",
            "--exact",
            "acquisition_v2_foreground_child",
            "--test-threads=1",
        ])
        .env("RUST_MIN_STACK", "33554432")
        .env("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key")
        .env("CDB_A2_EVIDENCE_DIR", evidence.path())
        .status()
        .unwrap();
    assert!(status.success(), "serial acquisition-v2 child failed");
}

#[tokio::test]
#[ignore = "run only through the serial environment wrapper"]
async fn acquisition_v2_foreground_child() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let document = fixture
        .write_document(
            "agreement.txt",
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
        SourceTarget::LocalFile(document.clone()),
        IngestMode::Admit(cdb_service::ingest::IngestWait::Admitted),
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        None,
        CancellationToken::default(),
    )
    .await
    .unwrap();
    let report = serde_json::to_value(report).unwrap();
    assert_eq!(report["candidate_count"], 9);
    assert_eq!(report["mapped_candidate_count"], 5);
    assert_eq!(report["unmapped_candidate_count"], 4);
    assert_eq!(report["rejected_candidate_count"], 0);
    assert_eq!(fixture.pi_invocations().unwrap(), 1);
    assert_eq!(report["admitted_claim_count"], 5);
    assert_eq!(report["documents"][0]["review_record_count"], 9);
    assert_eq!(
        report["documents"][0]["review_receipts"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let claims = report["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap();
    assert_eq!(claims.len(), 5);
    fn component<'a>(claim: &&'a serde_json::Value) -> Option<&'a str> {
        claim["ext"]["ctxql.acquisition.v2/component_ref"].as_str()
    }
    let executed = claims
        .iter()
        .find(|claim| component(claim) == Some("attribute:host/attribute/0"))
        .expect("executed-on date claim");
    assert_eq!(executed["relation"], "urn:ctxql:a2:executedOn");
    assert_eq!(
        executed["object_id"]["datatype"],
        "http://www.w3.org/2001/XMLSchema#date"
    );
    assert_eq!(executed["object_id"]["value"], "2022-12-06");
    let relation = claims
        .iter()
        .find(|claim| component(claim) == Some("relation:host/relation/0"))
        .expect("borrower relation claim");
    assert_eq!(relation["relation"], "urn:ctxql:a2:hasBorrower");
    let classification = &relation["ext"]["ctxql.acquisition.classification/v2"];
    assert_eq!(classification["subject"]["status"], "classified");
    assert_eq!(
        classification["subject"]["classes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        classification["object"]["classes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(classification["subject"]["classes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|class| class["origin"] == "extracted"));
    let agreement_id = relation["subject_id"].as_str().unwrap();
    let borrower_id = relation["object_id"].as_str().unwrap();
    assert_ne!(agreement_id, borrower_id);
    assert_eq!(
        claims
            .iter()
            .filter(|claim| claim["subject_id"] == agreement_id)
            .count(),
        4,
        "two agreement types, date, and borrower edge reuse one identity"
    );
    assert_eq!(
        claims
            .iter()
            .filter(|claim| claim["subject_id"] == borrower_id)
            .count(),
        1,
        "borrower classification reuses the relation object identity"
    );

    let outcome_root = report["documents"][0]["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|artifact| artifact["kind"] == "evaluation_outcomes")
        .and_then(|artifact| artifact["root"].as_str())
        .unwrap();
    let outcomes = SourceObjectReader::open(
        fixture.root().join("sources").canonicalize().unwrap(),
        2 * 1024 * 1024,
    )
    .unwrap()
    .read_object(&ContentHash::parse(outcome_root).unwrap())
    .unwrap();
    let outcomes: serde_json::Value = serde_json::from_slice(&outcomes).unwrap();
    assert_eq!(outcomes["schema"], "ctxql-extraction-outcomes/v3");
    assert_eq!(outcomes["response_protocol"], "ctxql-extraction-text/v1");
    assert_eq!(outcomes["outcomes"].as_array().unwrap().len(), 9);
    let outcome_for = |candidate_index: u64| {
        outcomes["outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outcome| outcome["candidate_index"].as_u64() == Some(candidate_index))
            .unwrap()
    };
    let repaired_relation = outcome_for(8);
    assert_eq!(repaired_relation["vocabulary"], "repaired");
    assert_eq!(repaired_relation["assertion"], "direct");
    let unknown = outcome_for(6);
    assert_eq!(unknown["vocabulary"], "rejected");
    assert_eq!(unknown["reason"], "unknown_predicate");
    assert!(unknown["original"]
        .as_str()
        .unwrap()
        .contains("urn:ctxql:a2:agreementDate"));
    let uncertain = outcome_for(7);
    assert_eq!(uncertain["vocabulary"], "valid");
    assert_eq!(uncertain["semantic_fit"], "uncertain");
    assert_eq!(uncertain["assertion"], "withheld");
    assert_eq!(uncertain["reason"], "semantic_fit_uncertain");
    assert!(uncertain["original"]
        .as_str()
        .unwrap()
        .contains("Possible interpretation only"));
    assert!(claims
        .iter()
        .all(|claim| claim["relation"] != "urn:ctxql:a2:agreementDate"
            && claim["relation"] != "urn:ctxql:a2:effectiveOn"));

    std::env::remove_var("OPENROUTER_API_KEY");
    fixture.set_pi_response("provider disabled").unwrap();
    let repeat = ingest(
        fixture.config().unwrap(),
        SourceTarget::LocalFile(document),
        IngestMode::Admit(cdb_service::ingest::IngestWait::Admitted),
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        None,
        CancellationToken::default(),
    )
    .await
    .unwrap();
    let repeat = serde_json::to_value(repeat).unwrap();
    assert_eq!(
        repeat["documents"][0]["admissions"],
        report["documents"][0]["admissions"]
    );
    assert_eq!(repeat["admitted_claim_count"], 5);
    assert_eq!(repeat["documents"][0]["review_record_count"], 9);
    assert_eq!(fixture.pi_invocations().unwrap(), 1);
    assert_eq!(
        report["documents"][0]["ontology_lookup"]["mode"],
        "semantic-prepared/v1"
    );

    let token = std::fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let access = cdb_service::acquisition_inspection::AuthorizedAcquisition::open_authenticated(
        fixture.config().unwrap(),
        &token,
        cdb_backend_fluree::runs::Operation::Read,
        cdb_service::auth::Operation::Read,
    )
    .await
    .unwrap();
    let job = cdb_core::id::JobId::new(report["documents"][0]["job_id"].as_str().unwrap()).unwrap();
    assert!(access
        .inspect("invalid credential", job.clone())
        .await
        .is_err());
    let inspected = access.inspect(&token, job.clone()).await.unwrap();
    assert!(!inspected
        .field("reviews")
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    let descriptor = inspected
        .field("artifacts")
        .unwrap()
        .as_array()
        .unwrap()
        .first()
        .unwrap();
    let artifact = access
        .read_artifact(&token, job.clone(), descriptor)
        .await
        .unwrap();
    assert!(!artifact
        .field("content")
        .unwrap()
        .as_str()
        .unwrap()
        .is_empty());
    let resumed = access
        .resume(&token, job, cdb_service::acquisition::WaitPoint::Admitted)
        .await
        .unwrap();
    assert_eq!(
        resumed.field("result_available").unwrap(),
        &cdb_core::CanonicalValue::Bool(true)
    );
    access.shutdown().await.unwrap();
    drop(access);
    run_business_query_and_v5_replay(&fixture, agreement_id, claims).await;
}

async fn run_business_query_and_v5_replay(
    fixture: &AcquisitionV2Fixture,
    agreement_id: &str,
    admitted_claims: &[serde_json::Value],
) {
    let token = std::fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let service = Service::open(fixture.config().unwrap()).await.unwrap();
    let query = serde_json::json!({
        "about": [{"from": [agreement_id], "match": "exact"}],
        "bounds": {"max_depth": 2},
        "return": {"claims": true, "paths": true, "evidence": true, "explain": false}
    });
    let execution_config: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/conformance/p2/config.json")).unwrap();
    let query = publish_artifact(&service, &token, "urn:ctxql:a2:business-query", query).await;
    let execution_config = publish_artifact(
        &service,
        &token,
        "urn:ctxql:a2:execution-config",
        execution_config,
    )
    .await;

    let prepared = service
        .prepare_execution(
            &token,
            PreparationRequest {
                run_id: RunId::new("acquisition-v2-business-query").unwrap(),
                query,
                config: Some(execution_config),
                profile: None,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    assert!(
        prepared.is_semantic(),
        "business query must use Semantic preparation"
    );
    let recorded = prepared
        .execute_recorded_v5(ContentHash::of_bytes(b"acquisition-v2-business-query/v1"))
        .await
        .unwrap();
    assert_eq!(
        recorded
            .run
            .projection()
            .field("schema")
            .unwrap()
            .as_str()
            .unwrap(),
        "ctxql-recorded-run/v5"
    );
    let response: serde_json::Value = serde_json::from_slice(&recorded.response).unwrap();
    let returned = response["claims"].as_array().unwrap();
    let expected_ids = admitted_claims
        .iter()
        .map(|claim| claim["claim_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    let returned_ids = returned
        .iter()
        .map(|claim| claim["meta"]["claim_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        returned_ids, expected_ids,
        "CTXQL must traverse all admitted5 claims"
    );
    let date = returned
        .iter()
        .find(|claim| claim["meta"]["relation"] == "urn:ctxql:a2:executedOn")
        .expect("CTXQL typed date claim");
    assert_eq!(
        date["meta"]["object_id"]["datatype"],
        "http://www.w3.org/2001/XMLSchema#date"
    );
    assert_eq!(date["meta"]["object_id"]["value"], "2022-12-06");
    assert!(returned.iter().all(|claim| {
        claim["meta"]["relation"] != "urn:ctxql:a2:agreementDate"
            && claim["meta"]["relation"] != "urn:ctxql:a2:effectiveOn"
    }));
    assert!(returned.iter().all(|claim| {
        claim["meta"]["lineage"]["sources"]
            .as_array()
            .is_some_and(|sources| {
                !sources.is_empty()
                    && sources.iter().all(|source| {
                        source["source_id"]
                            .as_str()
                            .is_some_and(|id| id.starts_with("urn:ctxql:source:"))
                            && source["selectors"]["utf8"].is_object()
                    })
            })
    }));
    let evidence = response["evidence"].as_array().expect("hydrated evidence");
    assert!(!evidence.is_empty());
    assert!(evidence.iter().all(|item| {
        item["status"] == "verified"
            && item["content"]
                .as_str()
                .is_some_and(|content| !content.is_empty())
    }));
    assert_eq!(response["status"], response["graph_status"]);
    drop(recorded);
    drop(prepared);
    service.shutdown().await.unwrap();
    drop(service);

    let restarted = Service::open(fixture.config().unwrap()).await.unwrap();
    let replay = restarted
        .dispatch(
            &token,
            &serde_json::to_vec(&serde_json::json!({
                "schema": "ctxql-service/v1",
                "op": "replay",
                "run_id": "acquisition-v2-business-query",
                "hydrate": true
            }))
            .unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    let replay: serde_json::Value = serde_json::from_slice(&replay).unwrap();
    assert_eq!(replay["response"]["graph"], "reproduced");
    assert_eq!(
        replay["response"]["response_hash"],
        response["response_hash"]
    );
    assert!(replay["response"]["evidence"].as_array().is_some_and(
        |items| !items.is_empty() && items.iter().all(|item| item["status"] == "verified")
    ));

    fixture.revoke_source_access(&restarted).await.unwrap();
    let denied = restarted
        .dispatch(
            &token,
            &serde_json::to_vec(&serde_json::json!({
                "schema": "ctxql-service/v1",
                "op": "replay",
                "run_id": "acquisition-v2-business-query",
                "hydrate": true
            }))
            .unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.kind, cdb_core::ErrorKind::Denied);
    restarted.shutdown().await.unwrap();
}

async fn publish_artifact(
    service: &Arc<Service>,
    token: &str,
    iri: &str,
    value: serde_json::Value,
) -> ArtifactRef {
    let content = serde_json::to_vec(&value).unwrap();
    let reference = ArtifactRef::new(
        Iri::new(iri).unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(&content),
    );
    let published = PublishedArtifact::new(reference.clone(), content, Limits::default()).unwrap();
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
                "schema": "ctxql-service/v1",
                "op": "publish",
                "artifact": artifact,
                "content": String::from_utf8(published.content().to_vec()).unwrap()
            }))
            .unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    reference
}

#[tokio::test]
async fn fixtures_never_reuse_semantic_or_control_history() {
    let first = AcquisitionV2Fixture::create().await.unwrap();
    let second = AcquisitionV2Fixture::create().await.unwrap();
    assert_ne!(first.root(), second.root());
    assert_eq!(first.bootstrap_receipt().t, 1);
    assert_eq!(second.bootstrap_receipt().t, 1);
    assert!(!first.bootstrap_receipt().cid.is_empty());
    assert!(!second.bootstrap_receipt().cid.is_empty());
    assert!(!first
        .root()
        .join("control/p6-acquisition-control-v1.jsonl")
        .exists());
    assert!(!second
        .root()
        .join("control/p6-acquisition-control-v1.jsonl")
        .exists());
}
