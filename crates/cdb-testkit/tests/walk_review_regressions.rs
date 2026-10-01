//! End-to-end regressions for Partner Review M1 (path values) and M2 (short circuit).
use cdb_core::{claim::CandidateClaim, CanonicalValue as V, Limits, Result};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::{execute, ExecutionOptions},
    options::CompileOptions,
};
use cdb_testkit::reference_fixture::{artifact, FixtureBuilder, ReferenceFixture, CONFIG};

fn value(s: &str) -> V {
    V::parse(s.as_bytes(), Limits::default()).unwrap()
}
async fn fixture(edges: &[(&str, &str, &str, &str, &str)], cycle: &str) -> ReferenceFixture {
    let mut builder = FixtureBuilder::new();
    for id in ["s", "u", "t"] {
        builder.entity(id, None).unwrap();
    }
    for (id, from, to, confidence, ext) in edges {
        builder.claim(CandidateClaim::from_value(&value(&format!(r#"{{"claim_id":"{id}","subject_id":"{from}","object_id":"{to}","confidence":{confidence},"ext":{ext},"relation":"https://fixture.example/edge","relation_type":"https://fixture.example/Relation","subject_type":"https://fixture.example/Entity","object_type":"https://fixture.example/Entity","claim_type":"https://fixture.example/Assertion","grounding_level":"claim_only"}}"#))).unwrap()).unwrap();
    }
    let mut config = value(CONFIG).as_object().unwrap().clone();
    let mut runtime = config["runtime"].as_object().unwrap().clone();
    runtime.insert("cycle_policy".into(), V::string(cycle));
    config.insert("runtime".into(), V::Object(runtime));
    let config = artifact(
        "https://fixture.example/review-config",
        &V::Object(config)
            .canonical_bytes(Limits::default())
            .unwrap(),
    )
    .unwrap();
    builder.artifact(config.clone());
    let mut fixture = builder.build().await.unwrap();
    fixture.config = config;
    fixture
}
async fn run(fixture: &ReferenceFixture, predicates: &str) -> Result<V> {
    let query = format!(
        r#"{{"about":[{{"from":["s"],"match":"exact"}}],"bounds":{{"max_depth":3}},"walk":{{"predicates":{predicates}}}}}"#
    );
    let draft = compile(
        QuerySource::inline(query.as_bytes()),
        None,
        &fixture.config,
        CompileOptions::default(),
    )?;
    let mut bytes = vec![];
    let result = execute(
        draft,
        &fixture.backend,
        &fixture.backend,
        &fixture.principal,
        fixture,
        ExecutionOptions::default(),
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await;
    if let Err(e) = result {
        assert!(bytes.is_empty(), "failed query released bytes");
        return Err(e);
    }
    let response = V::parse(&bytes, Limits::default())?;
    Ok(V::Array(
        response
            .field("paths")?
            .as_array()?
            .iter()
            .map(|p| p.field("claim_ids").unwrap().clone())
            .collect(),
    ))
}
#[tokio::test]
async fn path_string_contains_is_element_not_substring_and_includes_ancestors() {
    let f = fixture(
        &[("c1", "s", "u", "0.9", "{}"), ("c2", "u", "t", "0.8", "{}")],
        "no_repeated_claim",
    )
    .await;
    assert_eq!(
        run(&f, r#"[["path.meta:claim_id","contains","c"]]"#)
            .await
            .unwrap(),
        value("[]")
    );
    assert_eq!(
        run(&f, r#"[["path.meta:claim_id","contains","c1"]]"#)
            .await
            .unwrap(),
        value(r#"[["c1"],["c1","c2"]]"#)
    );
}
#[tokio::test]
async fn numeric_path_contains_uses_the_prospective_list() {
    let f = fixture(
        &[("c1", "s", "u", "0.9", "{}"), ("c2", "u", "t", "0.8", "{}")],
        "no_repeated_claim",
    )
    .await;
    assert_eq!(
        run(&f, r#"[["path.meta:confidence","contains",0.9]]"#)
            .await
            .unwrap(),
        value(r#"[["c1"],["c1","c2"]]"#)
    );
}
#[tokio::test]
async fn prospective_path_preserves_internal_missing_values() {
    let f = fixture(
        &[
            ("c1", "s", "u", "1", r#"{"x":1}"#),
            ("c2", "u", "t", "1", "{}"),
        ],
        "no_repeated_claim",
    )
    .await;
    assert_eq!(
        run(&f, r#"[["path.meta:ext:x","contains",1]]"#)
            .await
            .unwrap(),
        value(r#"[["c1"],["c1","c2"]]"#)
    );
}
#[tokio::test]
async fn rejected_walk_does_not_evaluate_unreachable_dynamic_error() {
    let f = fixture(
        &[("c1", "s", "u", "0.2", r#"{"x":"text"}"#)],
        "no_repeated_claim",
    )
    .await;
    assert_eq!(
        run(&f, r#"[["meta:confidence",">=",0.5],["meta:ext:x",">",1]]"#)
            .await
            .unwrap(),
        value("[]")
    );
    // Merged order remains observable: the same type error is real when reached first.
    assert!(
        run(&f, r#"[["meta:ext:x",">",1],["meta:confidence",">=",0.5]]"#)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn cycle_rejection_skips_walk_predicates() {
    let f = fixture(
        &[("c1", "s", "s", "1", r#"{"x":"text"}"#)],
        "no_repeated_node",
    )
    .await;
    assert_eq!(
        run(&f, r#"[["meta:ext:x",">",1]]"#).await.unwrap(),
        value("[]")
    );
}
#[tokio::test]
async fn evaluated_path_predicate_still_checks_late_list_types() {
    let f = fixture(
        &[
            ("c1", "s", "u", "1", r#"{"x":1}"#),
            ("c2", "u", "t", "1", r#"{"x":"text"}"#),
        ],
        "no_repeated_claim",
    )
    .await;
    // The second list is [1, "text"]. Its early match cannot conceal the late type error.
    assert!(run(&f, r#"[["path.meta:ext:x","contains",1]]"#)
        .await
        .is_err());
}
