//! Durable replay uses current grants but never broadens its original visible reads.
mod common_p4;
use cdb_core::{
    claim::ClaimObject, id::*, policy::PolicySet, CanonicalValue as V, ErrorKind, Limits,
};
use cdb_testkit::reference_fixture::{allow_policy, artifact, FixtureBuilder, CONFIG};
use common_p4::Fixture;
fn obj<const N: usize>(values: [(&str, V); N]) -> V {
    V::Object(values.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
#[tokio::test]
async fn native_restart_replay_freezes_new_grants_and_blocks_revoked_dependencies() {
    let mut state = cdb_backend_fluree::policy::PolicyState::deny_all().unwrap();
    let mut policy = allow_policy()
        .unwrap()
        .projection()
        .as_object()
        .unwrap()
        .clone();
    let mut rules = policy["policies"].as_array().unwrap().to_vec();
    rules.push(V::parse(br#"{"@id":"https://fixture.example/deny","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#onClass":"https://fixture.example/Secret"}"#,Limits::default()).unwrap());
    policy.insert("policies".into(), V::Array(rules));
    state.policy = PolicySet::from_value(&V::Object(policy)).unwrap();
    state.principals.insert(
        PrincipalId::new("reader").unwrap(),
        (
            true,
            [Iri::new("https://fixture.example/Reader").unwrap()].into(),
        ),
    );
    state.classes.insert(
        ResourceId::new("B").unwrap(),
        [Iri::new("https://fixture.example/Secret").unwrap()].into(),
    );
    let mut builder = FixtureBuilder::new();
    builder
        .entity("A", None)
        .unwrap()
        .entity("B", None)
        .unwrap()
        .edge(
            "ab",
            "A",
            ClaimObject::Entity(EntityId::new("B").unwrap()),
            "1",
        )
        .unwrap();
    let config = artifact("https://fixture.example/config", CONFIG.as_bytes()).unwrap();
    let query=artifact("https://fixture.example/current-query",br#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1},"return":{"explain":false}}"#).unwrap();
    builder.artifact(config.clone()).artifact(query.clone());
    let f = Fixture::new(builder, state, 1_000_000).await;
    let q = |run: &str| {
        obj([
            ("schema", V::string("ctxql-service/v1")),
            ("op", V::string("query")),
            ("run_id", V::string(run)),
            ("query", query.reference().projection()),
            ("config", config.reference().projection()),
        ])
    };
    let old = f.dispatch(&q("old")).await.unwrap();
    assert!(old
        .field("response")
        .unwrap()
        .field("paths")
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    let mut state = f.backend.policy_state().await.unwrap();
    state.classes.clear();
    f.backend
        .set_policy_state(&IdempotencyKey::new("grant-B").unwrap(), &state)
        .await
        .unwrap();
    let fresh = f.dispatch(&q("fresh")).await.unwrap();
    assert_eq!(
        fresh
            .field("response")
            .unwrap()
            .field("paths")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let f = f.reopen().await;
    let replay = || {
        obj([
            ("schema", V::string("ctxql-service/v1")),
            ("op", V::string("replay")),
            ("run_id", V::string("old")),
        ])
    };
    let result = f.dispatch(&replay()).await.unwrap();
    let report = result.field("response").unwrap();
    assert_eq!(report.field("graph").unwrap(), &V::string("reproduced"));
    assert_eq!(
        report.field("response_hash").unwrap(),
        old.field("response")
            .unwrap()
            .field("response_hash")
            .unwrap()
    );
    assert!(report
        .field("response")
        .unwrap()
        .field("paths")
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    println!("P4_CASE {{\"id\":\"P4-Q025\",\"outcome\":\"passed\"}}");
    let mut state = f.backend.policy_state().await.unwrap();
    state.classes.insert(
        ResourceId::new("A").unwrap(),
        [Iri::new("https://fixture.example/Secret").unwrap()].into(),
    );
    f.backend
        .set_policy_state(&IdempotencyKey::new("revoke-A").unwrap(), &state)
        .await
        .unwrap();
    assert_eq!(
        f.dispatch(&replay()).await.err().unwrap().kind,
        ErrorKind::Denied
    );
    f.shutdown().await;
    println!("P4_CASE {{\"id\":\"P4-Q026\",\"outcome\":\"passed\"}}");
}
