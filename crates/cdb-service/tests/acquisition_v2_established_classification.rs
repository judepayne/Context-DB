use cdb_backend_fluree::{
    official_bootstrap::{
        ACQUISITION_V2_FIXTURE_ACTION, ACQUISITION_V2_FIXTURE_DATA_GRAPH,
        ACQUISITION_V2_FIXTURE_LEDGER,
    },
    FlureeSemanticLedger,
};
use cdb_core::{
    admission::ExportRecord, contracts::SemanticProjectionSource, snapshot::PageSize,
    CanonicalValue, Limits,
};
use cdb_provider_pi::cancel::CancellationToken;
use cdb_service::{
    acquisition_v2_fixture::AcquisitionV2Fixture,
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
};
use fluree_db_api::FlureeBuilder;

const ENTITY: &str = "urn:ctxql:established:orion";
const CLASS: &str = "urn:ctxql:a2:CreditAgreement";
const IDENTIFIER: &str = "urn:ctxql:a2:registration";
const POLICY_GRAPH: &str = "urn:ctxql:a2:policy";

#[test]
fn established_class_support_is_frozen_and_revocation_does_not_leak() {
    let evidence = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "established_classification_child",
            "--test-threads=1",
        ])
        .env("RUST_MIN_STACK", "33554432")
        .env("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key")
        .env("CDB_A2_EVIDENCE_DIR", evidence.path())
        .status()
        .unwrap();
    assert!(status.success(), "serial established-class child failed");
}

#[tokio::test]
#[ignore = "run only through the serial environment wrapper"]
async fn established_classification_child() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    seed_established_entity(fixture.root()).await;
    configure_entity_source(&fixture);

    let first = run(
        &fixture,
        "first.txt",
        "Orion registration ORION-1 is a credit agreement.",
        &type_response(),
    )
    .await;
    let support = first["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|claim| claim["relation"] == "http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
        .expect("established entity type support");
    assert_eq!(support["subject_id"], ENTITY);
    assert_eq!(support["object_id"], CLASS);
    let support_id = support["claim_id"].as_str().unwrap().to_owned();

    let second = run(
        &fixture,
        "second.txt",
        "Orion registration ORION-1 has Acme Ltd as borrower.",
        &relation_response("Acme Ltd"),
    )
    .await;
    let established = relation_claim(&second);
    assert_eq!(established["subject_id"], ENTITY);
    assert_eq!(established["subject_type"], CLASS);
    let classes = established["ext"]["ctxql.acquisition.classification/v2"]["subject"]["classes"]
        .as_array()
        .unwrap();
    assert_eq!(classes.len(), 1);
    assert_eq!(classes[0]["iri"], CLASS);
    assert_eq!(classes[0]["origin"], "established");
    assert_eq!(classes[0]["reference"], support_id);
    let frozen_id = established["claim_id"].as_str().unwrap().to_owned();
    let frozen_bytes =
        CanonicalValue::parse(&serde_json::to_vec(established).unwrap(), Limits::default())
            .unwrap()
            .canonical_bytes(Limits::default())
            .unwrap();

    use_view_action(&fixture);
    revoke_support(fixture.root(), &support_id).await;
    let third = run(
        &fixture,
        "third.txt",
        "Orion registration ORION-1 has Beta Ltd as borrower.",
        &relation_response("Beta Ltd"),
    )
    .await;
    let after_revocation = relation_claim(&third);
    assert_eq!(
        after_revocation["subject_type"],
        cdb_core::classification::UNCLASSIFIED_ENTITY
    );
    assert!(
        after_revocation["ext"]["ctxql.acquisition.classification/v2"]["subject"]["classes"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let config = fixture.config().unwrap();
    let (path, options) = config.semantic_binding().unwrap();
    let ledger = FlureeSemanticLedger::open_file(path, options)
        .await
        .unwrap();
    let head = SemanticProjectionSource::head(&ledger).await.unwrap();
    let snapshot = SemanticProjectionSource::open_snapshot(&ledger, &head)
        .await
        .unwrap();
    let page = snapshot
        .export(None, PageSize::new(128).unwrap())
        .await
        .unwrap();
    let stored = page
        .items()
        .iter()
        .find_map(|record| match record {
            ExportRecord::Claim(record) if record.id().as_str() == frozen_id => {
                Some(record.candidate().projection())
            }
            _ => None,
        })
        .expect("prior relation remains stored after support revocation");
    assert_eq!(
        stored.canonical_bytes(Limits::default()).unwrap(),
        frozen_bytes,
        "current policy changes must not remint or rewrite the prior claim"
    );
}

async fn run(
    fixture: &AcquisitionV2Fixture,
    name: &str,
    text: &str,
    response: &str,
) -> serde_json::Value {
    fixture.set_pi_response(response).unwrap();
    let document = fixture.write_document(name, text.as_bytes()).unwrap();
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
    serde_json::to_value(report).unwrap()
}

fn relation_claim(report: &serde_json::Value) -> &serde_json::Value {
    report["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|claim| claim["relation"] == "urn:ctxql:a2:hasBorrower")
        .expect("admitted borrower relation")
}

fn type_response() -> String {
    serde_json::json!({
        "schema": "ctxql-extraction-proposals/v2", "no_claims": false,
        "entities": [{
            "id": "orion", "name": "Orion", "aliases": [], "known_entity": ENTITY,
            "evidence": [{"range": "{{LINE_RANGE_1}}", "quote": "Orion registration ORION-1", "occurrence": 0}],
            "classes": [{
                "id": "credit",
                "term": {"suggestions": [{"text": CLASS, "note": ""}], "selected": 0},
                "evidence": [{"range": "{{LINE_RANGE_1}}", "quote": "Orion registration ORION-1 is a credit agreement", "occurrence": 0}],
                "source_mode": "affirmative", "fit": "supported", "fit_note": ""
            }]
        }],
        "attributes": [], "relations": []
    }).to_string()
}

fn relation_response(party: &str) -> String {
    serde_json::json!({
        "schema": "ctxql-extraction-proposals/v2", "no_claims": false,
        "entities": [
            {
                "id": "orion", "name": "Orion", "aliases": [], "known_entity": ENTITY,
                "evidence": [{"range": "{{LINE_RANGE_1}}", "quote": "Orion registration ORION-1", "occurrence": 0}],
                "classes": []
            },
            {
                "id": "party", "name": party, "aliases": [], "known_entity": null,
                "evidence": [{"range": "{{LINE_RANGE_1}}", "quote": party, "occurrence": 0}],
                "classes": []
            }
        ],
        "attributes": [],
        "relations": [{
            "id": "borrower",
            "subject": {"kind": "local", "id": "orion"},
            "predicate": {"suggestions": [{"text": "urn:ctxql:a2:hasBorrower", "note": ""}], "selected": 0},
            "object": {"kind": "local", "id": "party"},
            "evidence": [{"range": "{{LINE_RANGE_1}}", "quote": format!("Orion registration ORION-1 has {party} as borrower."), "occurrence": 0}],
            "source_mode": "affirmative", "qualifiers": [], "fit": "supported", "fit_note": ""
        }]
    }).to_string()
}

fn configure_entity_source(fixture: &AcquisitionV2Fixture) {
    let config = std::fs::read_to_string(fixture.config_path()).unwrap();
    let marker = "[acquisition.window]";
    assert_eq!(config.matches(marker).count(), 1);
    let entity_source = format!(
        "approved-entity-iris = [\"{ENTITY}\"]\nentity-source = {{ graphs = [\"{ACQUISITION_V2_FIXTURE_DATA_GRAPH}\"], classes = [\"{CLASS}\"], identifying-predicates = [\"{IDENTIFIER}\"] }}\n"
    );
    std::fs::write(
        fixture.config_path(),
        config.replace(marker, &format!("{entity_source}{marker}")),
    )
    .unwrap();
}

async fn seed_established_entity(root: &std::path::Path) {
    transact(
        root,
        &format!(
            r#"@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix f: <https://ns.flur.ee/db#> .
GRAPH <{ACQUISITION_V2_FIXTURE_DATA_GRAPH}> {{
  <{ENTITY}> rdf:type <{CLASS}> ; rdfs:label "Orion" ; <{IDENTIFIER}> "ORION-1" .
}}
GRAPH <{POLICY_GRAPH}> {{
  <urn:ctxql:a2:explicit-view-allow> rdf:type f:AccessPolicy, <urn:ctxql:a2:PublicPolicy> ;
    f:action f:view ; f:allow true .
}}"#
        ),
    )
    .await;
}

async fn revoke_support(root: &std::path::Path, support_id: &str) {
    transact(
        root,
        &format!(
            r#"@prefix f: <https://ns.flur.ee/db#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
GRAPH <{POLICY_GRAPH}> {{
  <urn:ctxql:a2:revoke-class-support> rdf:type f:AccessPolicy, <urn:ctxql:a2:PublicPolicy> ;
    f:action f:view ; f:onSubject <{support_id}> ; f:allow false .
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
    fluree
        .stage_owned(ledger)
        .upsert_turtle(turtle)
        .execute()
        .await
        .unwrap();
}
