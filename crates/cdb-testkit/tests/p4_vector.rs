//! Independent P2 canonical response bytes through authenticated native recording/restart replay.
mod common_p4;
use cdb_core::{
    canonical::{CanonicalProjection, Domain},
    claim::ClaimObject,
    id::*,
    CanonicalValue as V, Limits,
};
use cdb_testkit::reference_fixture::{allow_policy, artifact, FixtureBuilder, CONFIG};
use common_p4::Fixture;
fn obj<const N: usize>(items: [(&str, V); N]) -> V {
    V::Object(items.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn state() -> cdb_backend_fluree::policy::PolicyState {
    let mut state = cdb_backend_fluree::policy::PolicyState::deny_all().unwrap();
    state.policy = allow_policy().unwrap();
    state.principals.insert(
        PrincipalId::new("reader").unwrap(),
        (
            true,
            [Iri::new("https://fixture.example/Reader").unwrap()].into(),
        ),
    );
    state
}
#[tokio::test]
async fn independent_response_bytes_survive_recording_and_restart() {
    let vectors = V::parse(
        include_bytes!("../../../fixtures/conformance/p2/bytes-v1.json"),
        Limits::default(),
    )
    .unwrap();
    let vector = &vectors.field("vectors").unwrap().as_array().unwrap()[0];
    let expected_bytes = vector
        .field("canonical_utf8")
        .unwrap()
        .as_str()
        .unwrap()
        .as_bytes();
    let expected = V::parse(expected_bytes, Limits::default()).unwrap();
    let literal = expected
        .field("payload")
        .unwrap()
        .field("paths")
        .unwrap()
        .as_array()
        .unwrap()[0]
        .field("endpoints")
        .unwrap()
        .as_array()
        .unwrap()[1]
        .clone();
    let mut builder = FixtureBuilder::new();
    builder
        .entity("s", None)
        .unwrap()
        .edge(
            "lit",
            "s",
            ClaimObject::from_value(&literal).unwrap(),
            "0.125",
        )
        .unwrap();
    let config = artifact("https://fixture.example/config", CONFIG.as_bytes()).unwrap();
    let query = artifact("https://fixture.example/vector-query",br#"{"about":[{"from":["s"],"match":"exact"}],"bounds":{"max_depth":3},"return":{"claims":false,"paths":true,"evidence":false,"explain":false}}"#).unwrap();
    builder.artifact(config.clone()).artifact(query.clone());
    let f = Fixture::new(builder, state(), 1_000_000).await;
    let request = obj([
        ("schema", V::string("ctxql-service/v1")),
        ("op", V::string("query")),
        ("run_id", V::string("vector")),
        ("query", query.reference().projection()),
        ("config", config.reference().projection()),
    ]);
    let result = f.dispatch(&request).await.unwrap();
    let response = result.field("response").unwrap();
    assert_eq!(
        response.field("response_hash").unwrap(),
        vector.field("sha256").unwrap()
    );
    let mut payload = response.as_object().unwrap().clone();
    for key in ["status", "response_hash", "plan_hash", "consistency"] {
        payload.remove(key);
    }
    assert_eq!(
        CanonicalProjection::from_payload(Domain::Response, V::Object(payload))
            .unwrap()
            .bytes(Limits::default())
            .unwrap(),
        expected_bytes
    );
    let f = f.reopen().await;
    let replay = f
        .dispatch(&obj([
            ("schema", V::string("ctxql-service/v1")),
            ("op", V::string("replay")),
            ("run_id", V::string("vector")),
        ]))
        .await
        .unwrap();
    let replay = replay.field("response").unwrap();
    assert_eq!(replay.field("graph").unwrap(), &V::string("reproduced"));
    assert_eq!(
        replay.field("response_hash").unwrap(),
        vector.field("sha256").unwrap()
    );
    assert_eq!(
        CanonicalProjection::from_payload(
            Domain::Response,
            replay.field("response").unwrap().clone()
        )
        .unwrap()
        .bytes(Limits::default())
        .unwrap(),
        expected_bytes
    );
    f.shutdown().await;
    println!("P4_CASE {{\"id\":\"P4-Q023\",\"outcome\":\"passed\"}}");
}
#[tokio::test]
async fn published_profile_binding_cannot_be_supplied_by_client_alias() {
    let config = artifact("https://fixture.example/config", CONFIG.as_bytes()).unwrap();
    let query = artifact(
        "https://fixture.example/profile-query",
        br#"{"profile":"wanted","about":[{"from":["A"],"match":"exact"}]}"#,
    )
    .unwrap();
    let wrong = artifact(
        "https://fixture.example/wrong-profile",
        br#"{"name":"other","bounds":{"max_depth":1}}"#,
    )
    .unwrap();
    let right = artifact(
        "https://fixture.example/right-profile",
        br#"{"name":"wanted","bounds":{"max_depth":1}}"#,
    )
    .unwrap();
    let mut builder = FixtureBuilder::new();
    builder.entity("A", None).unwrap();
    for a in [&config, &query, &wrong, &right] {
        builder.artifact(a.clone());
    }
    let f = Fixture::new(builder, state(), 1_000_000).await;
    let request = |run: &str, profile: &cdb_core::artifact::PublishedArtifact| {
        obj([
            ("schema", V::string("ctxql-service/v1")),
            ("op", V::string("query")),
            ("run_id", V::string(run)),
            ("query", query.reference().projection()),
            ("config", config.reference().projection()),
            (
                "profile",
                obj([
                    ("selector", V::string("wanted")),
                    ("artifact", profile.reference().projection()),
                ]),
            ),
        ])
    };
    let before = f.backend.head().await.unwrap();
    assert_eq!(
        f.dispatch(&request("wrong", &wrong))
            .await
            .err()
            .unwrap()
            .kind,
        cdb_core::ErrorKind::Invalid
    );
    assert_eq!(f.backend.head().await.unwrap(), before);
    f.dispatch(&request("right", &right)).await.unwrap();
    let f = f.reopen().await;
    let replay = f
        .dispatch(&obj([
            ("schema", V::string("ctxql-service/v1")),
            ("op", V::string("replay")),
            ("run_id", V::string("right")),
        ]))
        .await
        .unwrap();
    assert_eq!(
        replay.field("response").unwrap().field("graph").unwrap(),
        &V::string("reproduced")
    );
    f.shutdown().await;
    println!("P4_CASE {{\"id\":\"P4-Q024\",\"outcome\":\"passed\"}}");
}
