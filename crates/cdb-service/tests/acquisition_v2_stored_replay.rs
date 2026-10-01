use cdb_backend_fluree::{
    official_bootstrap::{
        ACQUISITION_V2_FIXTURE_ACTION, ACQUISITION_V2_FIXTURE_LEDGER,
        ACQUISITION_V2_FIXTURE_PRINCIPAL,
    },
    runs::Operation,
};
use cdb_core::{
    id::{ContentHash, JobId},
    ErrorKind,
};
use cdb_provider_pi::cancel::CancellationToken;
use cdb_service::{
    acquisition_inspection::AuthorizedAcquisition,
    acquisition_v2_fixture::AcquisitionV2Fixture,
    auth,
    config::AcquisitionAssertionPolicy,
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
};
use fluree_db_api::FlureeBuilder;

const POLICY_GRAPH: &str = "urn:ctxql:a2:policy";

#[test]
fn stored_capture_replay_is_provider_free_and_policy_revocable() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "stored_capture_replay_child",
            "--test-threads=1",
        ])
        .env("RUST_MIN_STACK", "33554432")
        .env("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key")
        .status()
        .unwrap();
    assert!(status.success(), "serial stored-replay child failed");
}

#[tokio::test]
#[ignore = "run only through the serial environment wrapper"]
async fn stored_capture_replay_child() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let document = fixture.write_document(
        "stored-replay.txt",
        b"Orion is a written agreement under which Acme Ltd borrows GBP 1000.\nOrion was executed on 2022-12-06.\nOrion agreement date: 2022-12-06.\n",
    ).unwrap();
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
    install_explicit_allow(fixture.root()).await;
    use_view_action(&fixture);
    replace_live_bundle_with_empty_directory(&fixture);
    let access = AuthorizedAcquisition::open_authenticated(
        fixture.config().unwrap(),
        &token,
        Operation::Replay,
        auth::Operation::Replay,
    )
    .await
    .unwrap();
    let inspection = access.inspect(&token, job).await.unwrap();
    let review_id = inspection.field("reviews").unwrap().as_array().unwrap()[0]
        .field("review_id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
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
    let capture_root = ContentHash::parse(
        descriptor_value
            .field("context_root")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let replayed = access
        .replay(
            &token,
            capture_root.clone(),
            OntologyMode::Soft,
            AcquisitionAssertionPolicy::EvidenceOnly,
            IngestWait::Admitted,
        )
        .await
        .unwrap();
    assert_eq!(
        replayed.field("capture_root").unwrap().as_str().unwrap(),
        capture_root.as_str()
    );
    assert_eq!(
        fixture.pi_invocations().unwrap(),
        1,
        "replay called the provider"
    );
    let invalid = access
        .replay(
            &token,
            ContentHash::of_bytes(b"not registered"),
            OntologyMode::Hard,
            AcquisitionAssertionPolicy::Accepted,
            IngestWait::Admitted,
        )
        .await
        .unwrap_err();
    assert_eq!(invalid.kind, ErrorKind::Denied);
    access.shutdown().await.unwrap();
    drop(access);

    deny_subject(fixture.root(), &review_id).await;
    let revoked = AuthorizedAcquisition::open_authenticated(
        fixture.config().unwrap(),
        &token,
        Operation::Replay,
        auth::Operation::Replay,
    )
    .await
    .unwrap();
    let error = revoked
        .replay(
            &token,
            capture_root,
            OntologyMode::Hard,
            AcquisitionAssertionPolicy::EvidenceOnly,
            IngestWait::Admitted,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.kind,
        ErrorKind::Denied,
        "unexpected replay error: {error:?}"
    );
    assert_eq!(fixture.pi_invocations().unwrap(), 1);
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
  <urn:ctxql:a2:stored-replay-allow> rdf:type f:AccessPolicy, <urn:ctxql:a2:PublicPolicy> ;
    f:action f:view ; f:allow true .
}}"#
        ),
    )
    .await;
}

async fn deny_subject(root: &std::path::Path, subject: &str) {
    transact(
        root,
        &format!(
            r#"@prefix f: <https://ns.flur.ee/db#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
GRAPH <{POLICY_GRAPH}> {{
  <urn:ctxql:a2:stored-replay-deny> rdf:type f:AccessPolicy, <urn:ctxql:a2:PublicPolicy> ;
    f:action f:view ; f:onSubject <{subject}> ; f:allow false .
}}"#
        ),
    )
    .await;
}

fn use_view_action(fixture: &AcquisitionV2Fixture) {
    let config = std::fs::read_to_string(fixture.config_path()).unwrap();
    let configured = format!("action = \"{ACQUISITION_V2_FIXTURE_ACTION}\"");
    std::fs::write(
        fixture.config_path(),
        config.replace(&configured, "action = \"https://ns.flur.ee/db#view\""),
    )
    .unwrap();
}

fn replace_live_bundle_with_empty_directory(fixture: &AcquisitionV2Fixture) {
    let empty = fixture.root().join("empty-live-bundle");
    std::fs::create_dir(&empty).unwrap();
    let config = std::fs::read_to_string(fixture.config_path()).unwrap();
    let rewritten = config
        .lines()
        .map(|line| {
            if line.starts_with("pi-bundle = ") {
                format!("pi-bundle = {:?}", empty.to_string_lossy())
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(fixture.config_path(), format!("{rewritten}\n")).unwrap();
}

async fn transact(root: &std::path::Path, turtle: &str) {
    let fluree = FlureeBuilder::file(root.join("semantic").to_string_lossy().into_owned())
        .without_indexing()
        .build()
        .unwrap();
    let ledger = fluree.ledger(ACQUISITION_V2_FIXTURE_LEDGER).await.unwrap();
    fluree
        .stage_owned(ledger)
        .upsert_turtle(turtle)
        .execute()
        .await
        .unwrap();
}
