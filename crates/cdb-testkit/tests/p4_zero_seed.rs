//! Partner Review M1: pre-cap matches cannot be inferred from zero retained seeds.
mod common_p4;
use cdb_core::{id::*, CanonicalValue as V};
use cdb_testkit::reference_fixture::{allow_policy, artifact, FixtureBuilder, CONFIG};
use common_p4::Fixture;
fn obj<const N: usize>(items: [(&str, V); N]) -> V {
    V::Object(items.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
async fn zero_seed(matching: bool, explain: bool, number: usize) {
    let mut state = cdb_backend_fluree::policy::PolicyState::deny_all().unwrap();
    state.policy = allow_policy().unwrap();
    state.principals.insert(
        PrincipalId::new("reader").unwrap(),
        (
            true,
            [Iri::new("https://fixture.example/Reader").unwrap()].into(),
        ),
    );
    let config = artifact("https://fixture.example/config", CONFIG.as_bytes()).unwrap();
    let text = format!(
        r#"{{"about":[{{"from":["{}"],"match":"exact"}}],"bounds":{{"max_depth":1,"seed_limit":0}},"return":{{"explain":{explain}}}}}"#,
        if matching { "A" } else { "missing" }
    );
    let query = artifact("https://fixture.example/zero-seed", text.as_bytes()).unwrap();
    let mut builder = FixtureBuilder::new();
    builder
        .entity("A", None)
        .unwrap()
        .artifact(query.clone())
        .artifact(config.clone());
    let f = Fixture::new(builder, state, 1_000_000).await;
    let first = f
        .dispatch(&obj([
            ("schema", V::string("ctxql-service/v1")),
            ("op", V::string("query")),
            ("run_id", V::string("zero")),
            ("query", query.reference().projection()),
            ("config", config.reference().projection()),
        ]))
        .await
        .unwrap();
    let original = first.field("response").unwrap();
    assert!(original
        .field("paths")
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    let expected = if matching {
        "seed_limit"
    } else {
        "empty_landing"
    };
    let notices = original.field("notices").unwrap().as_array().unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].field("code").unwrap(), &V::string(expected));
    if explain {
        assert!(original
            .field("explain")
            .unwrap()
            .field("seeds")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
    } else {
        assert_eq!(original.field("explain").unwrap(), &V::Null);
    }
    let f = f.reopen().await;
    let replay = f
        .dispatch(&obj([
            ("schema", V::string("ctxql-service/v1")),
            ("op", V::string("replay")),
            ("run_id", V::string("zero")),
        ]))
        .await
        .unwrap();
    let report = replay.field("response").unwrap();
    assert_eq!(report.field("graph").unwrap(), &V::string("reproduced"));
    assert_eq!(
        report.field("response_hash").unwrap(),
        original.field("response_hash").unwrap()
    );
    assert_eq!(
        report.field("response").unwrap().field("notices").unwrap(),
        original.field("notices").unwrap()
    );
    assert_eq!(
        report.field("response").unwrap().field("explain").unwrap(),
        original.field("explain").unwrap()
    );
    assert!(report
        .field("response")
        .unwrap()
        .field("paths")
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    f.shutdown().await;
    println!("P4_CASE {{\"id\":\"P4-Q{number:03}\",\"outcome\":\"passed\"}}");
}
#[tokio::test]
async fn zero_seed_matching_without_explain_restarts_and_reproduces() {
    zero_seed(true, false, 28).await;
}
#[tokio::test]
async fn zero_seed_missing_without_explain_restarts_and_reproduces() {
    zero_seed(false, false, 29).await;
}
#[tokio::test]
async fn zero_seed_matching_with_explain_restarts_and_reproduces() {
    zero_seed(true, true, 30).await;
}
#[tokio::test]
async fn zero_seed_missing_with_explain_restarts_and_reproduces() {
    zero_seed(false, true, 31).await;
}
