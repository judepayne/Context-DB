use cdb_backend_fluree::{
    official_bootstrap::ACQUISITION_V2_FIXTURE_PRINCIPAL, policy::PolicyState, runs::Operation,
    FlureeBackend, FlureeSemanticLedger,
};
use cdb_core::{
    admission::ExportRecord,
    contracts::{GraphBackend, SemanticProjectionSource},
    id::{ContentHash, IdempotencyKey, JobId},
    policy::PolicySet,
    ErrorKind, Limits,
};
use cdb_provider_pi::cancel::CancellationToken;
use cdb_service::{
    acquisition_inspection::AuthorizedAcquisition,
    acquisition_v2_fixture::AcquisitionV2Fixture,
    auth,
    config::AcquisitionAssertionPolicy,
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
    sources::{selector_records, AcquisitionArtifactDescriptor},
};

#[test]
fn originating_selector_revocation_blocks_all_stored_release_and_replay() {
    let evidence = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "originating_selector_revocation_child",
            "--test-threads=1",
        ])
        .env("RUST_MIN_STACK", "33554432")
        .env("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key")
        .env("CDB_A2_EVIDENCE_DIR", evidence.path())
        .status()
        .unwrap();
    assert!(status.success(), "serial source-revocation child failed");
}

#[tokio::test]
#[ignore = "run only through the serial environment wrapper"]
async fn originating_selector_revocation_child() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let document = fixture
        .write_document(
            "source-revocation.txt",
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
        IngestMode::Admit(IngestWait::Admitted),
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
    assert_eq!(fixture.pi_invocations().unwrap(), 1);
    let job = JobId::new(report["documents"][0]["job_id"].as_str().unwrap()).unwrap();
    let token = std::fs::read_to_string(fixture.root().join("owner.secret")).unwrap();

    let access = AuthorizedAcquisition::open_authenticated(
        fixture.config().unwrap(),
        &token,
        Operation::Replay,
        auth::Operation::Replay,
    )
    .await
    .unwrap();
    let inspection = access.inspect(&token, job.clone()).await.unwrap();
    let descriptor_value = inspection
        .field("artifacts")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|value| {
            value.field("artifact_kind").unwrap().as_str().unwrap() == "evaluation_outcomes"
        })
        .unwrap()
        .clone();
    access
        .read_artifact(&token, job.clone(), &descriptor_value)
        .await
        .unwrap();
    let capture_root = ContentHash::parse(
        descriptor_value
            .field("context_root")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let descriptor =
        AcquisitionArtifactDescriptor::from_value(&descriptor_value, 2 * 1024 * 1024).unwrap();
    let fragment = ContentHash::parse(
        descriptor_value
            .field("source_fragment_hash")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let selector_id = selector_records(descriptor.source(), &fragment)
        .unwrap()
        .into_iter()
        .filter_map(|record| match record {
            ExportRecord::Resource(record) => Some(record.id().as_str().to_owned()),
            _ => None,
        })
        .next_back()
        .expect("exact selector descriptor ID");
    access.shutdown().await.unwrap();
    drop(access);

    let semantic = open_semantic(&fixture).await;
    let before = SemanticProjectionSource::head(&semantic).await.unwrap();
    revoke_control_selector(&fixture, &selector_id).await;

    let revoked = AuthorizedAcquisition::open_authenticated(
        fixture.config().unwrap(),
        &token,
        Operation::Replay,
        auth::Operation::Replay,
    )
    .await
    .unwrap();
    for error in [
        revoked.inspect(&token, job.clone()).await.unwrap_err(),
        revoked
            .read_artifact(&token, job, &descriptor_value)
            .await
            .unwrap_err(),
        revoked
            .replay(
                &token,
                capture_root,
                OntologyMode::Soft,
                AcquisitionAssertionPolicy::EvidenceOnly,
                IngestWait::Admitted,
            )
            .await
            .unwrap_err(),
    ] {
        assert_eq!(error.kind, ErrorKind::Denied, "unexpected error: {error:?}");
    }
    assert_eq!(
        fixture.pi_invocations().unwrap(),
        1,
        "revoked replay called Pi"
    );
    let after = SemanticProjectionSource::head(&semantic).await.unwrap();
    assert_eq!(
        after, before,
        "a denied release/replay admitted new Semantic data"
    );
    revoked.shutdown().await.unwrap();
}

async fn open_semantic(fixture: &AcquisitionV2Fixture) -> FlureeSemanticLedger {
    let config = fixture.config().unwrap();
    let (path, options) = config.semantic_binding().unwrap();
    FlureeSemanticLedger::open_file(path, options)
        .await
        .unwrap()
}

async fn revoke_control_selector(fixture: &AcquisitionV2Fixture, selector_id: &str) {
    let config = fixture.config().unwrap();
    let backend = FlureeBackend::open(config.authority_options().unwrap())
        .await
        .unwrap();
    let mut state: PolicyState = backend.policy_state().await.unwrap();
    state.policy = PolicySet::parse(
        format!(
            r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{{"@id":"https://ctxql.example/test/source-allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceReader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}},{{"@id":"https://ctxql.example/test/selector-revoked","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceReader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#onSubject":{selector_id:?},"https://ns.flur.ee/db#allow":false}}]}}"#
        )
        .as_bytes(),
        Limits::default(),
    )
    .unwrap();
    let head = GraphBackend::head(&backend).await.unwrap();
    backend
        .set_policy_state(
            &IdempotencyKey::new(format!(
                "test-selector-revoke:{}:{}",
                head.pin().revision().as_str(),
                &ContentHash::of_bytes(selector_id.as_bytes()).as_str()[7..]
            ))
            .unwrap(),
            &state,
        )
        .await
        .unwrap();
    assert!(state
        .principals
        .contains_key(&cdb_core::id::PrincipalId::new(ACQUISITION_V2_FIXTURE_PRINCIPAL).unwrap()));
}
