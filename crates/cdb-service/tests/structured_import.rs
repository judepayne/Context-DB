use cdb_backend_fluree::runs::Operation as ControlOperation;
use cdb_core::{CanonicalValue as V, Limits};
use cdb_service::{
    acquisition_inspection::AuthorizedAcquisition, acquisition_v2_fixture::AcquisitionV2Fixture,
    auth,
};

const ORGANIZATION: &str = "https://www.omg.org/spec/Commons/Organizations/Organization";
const HAS_MEMBER: &str = "https://www.omg.org/spec/Commons/Collections/hasMember";

fn request(dataset: &str, claim_count: usize) -> Vec<u8> {
    let entities = (0..=claim_count)
        .map(|index| {
            serde_json::json!({
                "id": format!("urn:test:{dataset}:organization:{index}"),
                "type": ORGANIZATION
            })
        })
        .collect::<Vec<_>>();
    let claims = (0..claim_count)
        .map(|index| {
            serde_json::json!({
                "id": format!("{dataset}-related-{index}"),
                "subject": format!("urn:test:{dataset}:organization:{index}"),
                "predicate": HAS_MEMBER,
                "object": {
                    "type": "iri",
                    "value": format!("urn:test:{dataset}:organization:{}", index + 1)
                },
                "evidence": [{
                    "source": format!("urn:test:{dataset}:source"),
                    "selector": {"contract": "ctxql-evidence/v1", "whole_document": true},
                    "note": "administrator curated"
                }]
            })
        })
        .collect::<Vec<_>>();
    let value = serde_json::json!({
        "schema": "ctxql-structured-claim-import/v1",
        "dataset": {"id": format!("urn:test:{dataset}"), "version": "1"},
        "sources": [{
            "id": format!("urn:test:{dataset}:source"),
            "kind": "ctxql.source.curated-dataset",
            "uri": format!("urn:test:{dataset}:registry"),
            "version": "1",
            "content_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }],
        "entities": entities,
        "claims": claims
    });
    V::parse(&serde_json::to_vec(&value).unwrap(), Limits::default())
        .unwrap()
        .canonical_bytes(Limits::default())
        .unwrap()
}

#[tokio::test]
#[ignore = "requires CDB_PARTY_BACKGROUND_ONTOLOGY exact native bootstrap"]
async fn generic_import_batches_multiple_datasets_and_is_restart_idempotent() {
    let ontology = std::env::var_os("CDB_PARTY_BACKGROUND_ONTOLOGY").expect("ontology bootstrap");
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let token = std::fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let configured = || {
        let mut config = fixture.config().unwrap();
        config.limits.max_body_bytes = 16 * 1024 * 1024;
        config.limits.run_bytes = 16 * 1024 * 1024;
        config.limits.deadline_seconds = 300;
        let acquisition = config.acquisition.as_mut().unwrap();
        acquisition.ontology_ledger_path = Some(ontology.clone().into());
        acquisition.control_journal_bytes = 64 * 1024 * 1024;
        acquisition.projection_timeout_seconds = 300;
        config
    };
    let large = request("curated-organizations", 65);
    let other = request("second-dataset", 2);

    let access = AuthorizedAcquisition::open_authenticated(
        configured(),
        &token,
        ControlOperation::Admin,
        auth::Operation::Admin,
    )
    .await
    .unwrap();
    assert!(access
        .import_structured_claims("not-an-admin-secret", &large)
        .await
        .is_err());
    let first = access
        .import_structured_claims(&token, &large)
        .await
        .unwrap();
    assert_eq!(
        first.field("schema").unwrap().as_str().unwrap(),
        "ctxql-structured-claim-import-result/v1"
    );
    assert_eq!(first.field("claim_count").unwrap().u64().unwrap(), 65);
    assert_eq!(
        first.field("admissions").unwrap().as_array().unwrap().len(),
        2,
        "65 claims must cross the 64-claim native admission boundary"
    );
    let second_dataset = access
        .import_structured_claims(&token, &other)
        .await
        .unwrap();
    assert_eq!(
        second_dataset.field("claim_count").unwrap().u64().unwrap(),
        2
    );
    assert_ne!(
        first.field("import_id").unwrap(),
        second_dataset.field("import_id").unwrap()
    );
    access.shutdown().await.unwrap();
    drop(access);

    let restarted = AuthorizedAcquisition::open_authenticated(
        configured(),
        &token,
        ControlOperation::Admin,
        auth::Operation::Admin,
    )
    .await
    .unwrap();
    let after_restart = restarted
        .import_structured_claims(&token, &large)
        .await
        .unwrap();
    assert_eq!(
        first, after_restart,
        "restart changed the committed receipt"
    );
    let other_after_restart = restarted
        .import_structured_claims(&token, &other)
        .await
        .unwrap();
    assert_eq!(second_dataset, other_after_restart);
    restarted.shutdown().await.unwrap();
}
