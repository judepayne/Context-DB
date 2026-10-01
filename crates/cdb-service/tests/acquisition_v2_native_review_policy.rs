use cdb_backend_fluree::{
    official_bootstrap::{
        ACQUISITION_V2_FIXTURE_ACTION, ACQUISITION_V2_FIXTURE_LEDGER,
        ACQUISITION_V2_FIXTURE_PRINCIPAL,
    },
    runs::Operation,
};
use cdb_core::{id::JobId, ErrorKind};
use cdb_provider_pi::cancel::CancellationToken;
use cdb_service::{
    acquisition::WaitPoint,
    acquisition_inspection::AuthorizedAcquisition,
    acquisition_v2_fixture::AcquisitionV2Fixture,
    auth,
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
};
use fluree_db_api::FlureeBuilder;

const POLICY_GRAPH: &str = "urn:ctxql:a2:policy";

#[test]
fn native_review_policy_guards_inspect_artifact_and_resume() {
    let evidence = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "native_review_policy_child",
            "--test-threads=1",
        ])
        .env("RUST_MIN_STACK", "33554432")
        .env("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key")
        .env("CDB_A2_EVIDENCE_DIR", evidence.path())
        .status()
        .unwrap();
    assert!(status.success(), "serial native-policy child failed");
}

#[tokio::test]
#[ignore = "run only through the serial environment wrapper"]
async fn native_review_policy_child() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    install_explicit_allow(fixture.root()).await;
    let document = fixture
        .write_document(
            "policy.txt",
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
    assert_eq!(report["documents"][0]["review_record_count"], 9);
    assert_eq!(report["admitted_claim_count"], 5);
    assert_eq!(fixture.pi_invocations().unwrap(), 1);

    let job = JobId::new(report["documents"][0]["job_id"].as_str().unwrap()).unwrap();
    let first_review_id = report["documents"][0]["review_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|receipt| receipt["review_ids"].as_array().unwrap())
        .next()
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let token = std::fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    use_view_action(&fixture);

    let allowed = AuthorizedAcquisition::open_authenticated(
        fixture.config().unwrap(),
        &token,
        Operation::Read,
        auth::Operation::Read,
    )
    .await
    .unwrap();
    let inspection = allowed.inspect(&token, job.clone()).await.unwrap();
    assert_eq!(
        inspection
            .field("reviews")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        18,
        "the admitted evaluation and result-review records are both released"
    );
    let descriptor = inspection.field("artifacts").unwrap().as_array().unwrap()[0].clone();
    let artifact = allowed
        .read_artifact(&token, job.clone(), &descriptor)
        .await
        .unwrap();
    assert!(!artifact
        .field("content")
        .unwrap()
        .as_str()
        .unwrap()
        .is_empty());
    assert_eq!(
        allowed
            .resume(&token, job.clone(), WaitPoint::Admitted)
            .await
            .unwrap()
            .field("result_available")
            .unwrap(),
        &cdb_core::CanonicalValue::Bool(true)
    );
    allowed.shutdown().await.unwrap();
    drop(allowed);

    revoke_review(fixture.root(), &first_review_id).await;
    let revoked = AuthorizedAcquisition::open_authenticated(
        fixture.config().unwrap(),
        &token,
        Operation::Read,
        auth::Operation::Read,
    )
    .await
    .unwrap();
    for denied in [
        revoked.inspect(&token, job.clone()).await.unwrap_err(),
        revoked
            .read_artifact(&token, job.clone(), &descriptor)
            .await
            .unwrap_err(),
        revoked
            .resume(&token, job, WaitPoint::Admitted)
            .await
            .unwrap_err(),
    ] {
        assert_eq!(denied.kind, ErrorKind::Denied);
        assert_eq!(denied.message, "acquisition access denied");
    }
    revoked.shutdown().await.unwrap();
}

async fn install_explicit_allow(root: &std::path::Path) {
    transact(
        root,
        &format!(
            r#"@prefix f: <https://ns.flur.ee/db#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
GRAPH <{POLICY_GRAPH}> {{
  <{ACQUISITION_V2_FIXTURE_PRINCIPAL}> f:policyClass <urn:ctxql:a2:PublicPolicy> .
  <urn:ctxql:a2:explicit-review-allow> rdf:type f:AccessPolicy, <urn:ctxql:a2:PublicPolicy> ;
    f:action f:view ; f:allow true .
}}"#
        ),
    )
    .await;
}

async fn revoke_review(root: &std::path::Path, review_id: &str) {
    transact(
        root,
        &format!(
            r#"@prefix f: <https://ns.flur.ee/db#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
GRAPH <{POLICY_GRAPH}> {{
  <urn:ctxql:a2:revoked-review> rdf:type f:AccessPolicy, <urn:ctxql:a2:PublicPolicy> ;
    f:action f:view ; f:onSubject <{review_id}> ; f:allow false .
}}"#
        ),
    )
    .await;
}

fn use_view_action(fixture: &AcquisitionV2Fixture) {
    let config = std::fs::read_to_string(fixture.config_path()).unwrap();
    let configured = format!("action = \"{ACQUISITION_V2_FIXTURE_ACTION}\"");
    assert_eq!(config.matches(&configured).count(), 1);
    std::fs::write(
        fixture.config_path(),
        config.replace(&configured, "action = \"https://ns.flur.ee/db#view\""),
    )
    .unwrap();
}

async fn transact(root: &std::path::Path, turtle: &str) {
    let fluree = FlureeBuilder::file(root.join("semantic").to_string_lossy().into_owned())
        .without_indexing()
        .build()
        .unwrap();
    let ledger = fluree.ledger(ACQUISITION_V2_FIXTURE_LEDGER).await.unwrap();
    let committed = fluree
        .stage_owned(ledger)
        .upsert_turtle(turtle)
        .execute()
        .await
        .unwrap()
        .ledger;
    assert!(committed.t() > 1);
}
