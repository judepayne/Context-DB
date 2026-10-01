use cdb_backend_fluree::{runs::Operation as ControlOperation, FlureeBackend};
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    id::{ContentHash, IdempotencyKey, Iri, PrincipalId, RunId, VersionId},
    CanonicalValue as V, Limits,
};
use cdb_service::{
    acquisition_inspection::AuthorizedAcquisition, acquisition_v2_fixture::AcquisitionV2Fixture,
    auth, service::PreparationRequest, Service,
};
use std::sync::{atomic::AtomicBool, Arc};

const PARTY: &str =
    "https://ctxql.org/ontology/party-background/party/p003-cobham-ultra-seniorco-s-a-r-l";
const ADDRESS: &str =
    "https://ctxql.org/ontology/party-background/address/p003-cobham-ultra-seniorco-s-a-r-l/1";
const HAS_COUNTRY: &str = "https://www.omg.org/spec/Commons/Locations/hasCountry";

#[tokio::test]
#[ignore = "requires CDB_PARTY_BACKGROUND_ONTOLOGY exact native bootstrap"]
async fn full_pinned_seed_is_restart_idempotent_queryable_and_requires_current_admin() {
    let ontology =
        std::env::var_os("CDB_PARTY_BACKGROUND_ONTOLOGY").expect("CDB_PARTY_BACKGROUND_ONTOLOGY");
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
    let seed = include_bytes!("../../../fixtures/quickstart/party-background/seed.json");

    let access = AuthorizedAcquisition::open_authenticated(
        configured(),
        &token,
        ControlOperation::Admin,
        auth::Operation::Admin,
    )
    .await
    .unwrap();
    let first = access.seed_party_background(&token, seed).await.unwrap();
    assert_eq!(
        first.field("schema").unwrap().as_str().unwrap(),
        "ctxql-party-background-seed-result/v1"
    );
    assert_eq!(first.field("entity_count").unwrap().u64().unwrap(), 186);
    assert_eq!(first.field("claim_count").unwrap().u64().unwrap(), 496);
    assert_ne!(
        first
            .field("projections")
            .unwrap()
            .as_array()
            .unwrap()
            .last()
            .unwrap(),
        &V::Null
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
    let after_restart = restarted.seed_party_background(&token, seed).await.unwrap();
    assert_eq!(
        first, after_restart,
        "restart changed the committed receipt"
    );
    let mut tampered = seed.to_vec();
    let position = tampered
        .windows(b"2026-09-27".len())
        .position(|window| window == b"2026-09-27")
        .unwrap();
    tampered[position] = b'X';
    assert!(restarted
        .seed_party_background(&token, &tampered)
        .await
        .is_err());
    assert!(restarted
        .seed_party_background("not-a-valid-admin-secret", seed)
        .await
        .is_err());
    restarted.shutdown().await.unwrap();
    drop(restarted);

    query_projected_party_graph(configured(), &token).await;

    let config = configured();
    let backend = FlureeBackend::open(config.authority_options().unwrap())
        .await
        .unwrap();
    let mut state = backend.policy_state().await.unwrap();
    let principal =
        PrincipalId::new(config.acquisition.as_ref().unwrap().principal.clone()).unwrap();
    let admin = Iri::new(ControlOperation::Admin.role()).unwrap();
    assert!(state
        .principals
        .get_mut(&principal)
        .unwrap()
        .1
        .remove(&admin));
    backend
        .set_policy_state(
            &IdempotencyKey::new("party-seed-revoke-admin").unwrap(),
            &state,
        )
        .await
        .unwrap();
    drop(backend);

    assert!(AuthorizedAcquisition::open_authenticated(
        configured(),
        &token,
        ControlOperation::Admin,
        auth::Operation::Admin,
    )
    .await
    .is_err());
}

async fn query_projected_party_graph(config: cdb_service::config::InstanceConfig, token: &str) {
    let service = Service::open(config).await.unwrap();
    let query = serde_json::json!({
        "about": [{"from": [ADDRESS], "match": "exact"}],
        "bounds": {"max_depth": 1, "seed_limit": 1},
        "return": {"claims": true, "paths": true, "evidence": false, "explain": false}
    });
    let execution_config: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/conformance/p2/config.json")).unwrap();
    let query = publish_artifact(&service, token, "urn:ctxql:party-seed-query", query).await;
    let execution_config = publish_artifact(
        &service,
        token,
        "urn:ctxql:party-seed-query-config",
        execution_config,
    )
    .await;
    let recorded = service
        .prepare_execution(
            token,
            PreparationRequest {
                run_id: RunId::new("party-background-seed-query").unwrap(),
                query,
                config: Some(execution_config),
                profile: None,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap()
        .execute_recorded_v5(ContentHash::of_bytes(b"party-background-seed-query/v1"))
        .await
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&recorded.response).unwrap();
    let claims = response["claims"].as_array().unwrap();
    assert!(
        !claims.is_empty(),
        "admitted graph was not projected/queryable"
    );
    assert!(
        claims.iter().any(|claim| {
            claim["meta"]["subject_id"] == ADDRESS && claim["meta"]["relation"] == HAS_COUNTRY
        }),
        "address-country fact missing: {response}"
    );
    assert!(!claims.iter().any(|claim| {
        claim["meta"]["subject_id"] == PARTY && claim["meta"]["relation"] == HAS_COUNTRY
    }));
    assert!(claims.iter().all(|claim| {
        claim["meta"]["lineage"]["sources"][0]["source_id"]
            == "urn:ctxql:source:curated-party-background-graph"
    }));
    service.shutdown().await.unwrap();
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
