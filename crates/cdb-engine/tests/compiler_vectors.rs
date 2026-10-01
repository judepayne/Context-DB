//! Expected normalized data is hand-authored from execution-v1, not captured engine output.
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    id::{ContentHash, Iri, VersionId},
    CanonicalValue as V, Limits, Timestamp,
};
use cdb_engine::{
    compiler::{compile, QuerySource, SelectedProfile},
    options::CompileOptions,
};
const CONFIG: &str = r#"{"name":"fixture","version":"1","runtime":{"candidate_order":["depth asc","confidence desc","transaction_time desc","claim_id asc"],"path_ranking":["shorter_path","higher_accumulated_confidence","better_grounding","newer_claims","claim_id_tiebreak"],"cycle_policy":"no_repeated_claim"},"fields":{},"external_functions":{}}"#;
fn published(name: &str, bytes: &str) -> PublishedArtifact {
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new(format!("urn:{name}")).unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(bytes.as_bytes()),
        ),
        bytes.as_bytes().to_vec(),
        Limits::default(),
    )
    .unwrap()
}
#[test]
fn independent_complete_plan_bytes() {
    let c = published("config", CONFIG);
    let q = br#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":2}}"#;
    let p = compile(QuerySource::inline(q), None, &c, CompileOptions::default())
        .unwrap()
        .finalize(Timestamp::parse("2026-03-31T00:00:00Z").unwrap())
        .unwrap();
    let expected = format!(
        r#"{{"domain":"ctxql.plan","version":"ctxql-canonical/v1","payload":{{"query":{{"about":[{{"from":["A"],"to":null,"match":"exact"}}],"bounds":{{"max_depth":2,"seed_limit":2,"fanout_limit":4,"max_claims":16,"path_limit":8,"as_of":"2026-03-31T00:00:00.000Z"}},"walk":{{"direction":"outgoing","predicates":[]}},"filter":{{"predicates":[]}},"return":{{"claims":true,"paths":true,"evidence":false,"explain":false}}}},"artifacts":{{"query":null,"profile":null,"config":{{"iri":"urn:config","version":"1","hash":"{}"}}}},"config":{CONFIG},"as_of":"2026-03-31T00:00:00.000Z"}}}}"#,
        ContentHash::of_bytes(CONFIG.as_bytes()).as_str()
    );
    let expected = V::parse(expected.as_bytes(), Limits::default())
        .unwrap()
        .canonical_bytes(Limits::default())
        .unwrap();
    assert_eq!(
        p.projection().canonical().bytes(Limits::default()).unwrap(),
        expected
    );
    assert_eq!(p.hash(), &ContentHash::of_bytes(&expected));
}
#[test]
fn recursive_objects_arrays_false_and_default_override() {
    let config = CONFIG.replace(
        "\"fields\":{}",
        r#""defaults":{"seed_limit":7,"fanout_limit":6,"max_claims":5,"path_limit":4},"fields":{}"#,
    );
    let profile = published(
        "profile",
        r#"{"name":"p","bounds":{"max_depth":2,"seed_limit":3,"custom":{"a":1,"b":2,"list":[1,2]}},"return":{"claims":true,"paths":false,"evidence":true}}"#,
    );
    let q = br#"{"profile":"p","about":[{"from":["A"],"to":["B"],"match":"exact"},{"from":["C"],"match":"exact"}],"bounds":{"seed_limit":0,"custom":{"a":null,"list":[]}},"return":{"claims":false,"evidence":false}}"#;
    let plan = compile(
        QuerySource::inline(q),
        Some(SelectedProfile {
            selector: "p",
            artifact: &profile,
        }),
        &published("config", &config),
        CompileOptions::default(),
    )
    .unwrap()
    .finalize(Timestamp::parse("2026-03-31T00:00:00Z").unwrap())
    .unwrap();
    assert_eq!(plan.caps().seed_limit, 0);
    assert_eq!(plan.caps().fanout_limit, 6);
    assert!(!plan.selection().claims);
    assert!(!plan.selection().paths);
    assert!(!plan.selection().evidence);
    assert_eq!(plan.blocks().len(), 2);
    assert_eq!(plan.blocks()[0].to().unwrap(), ["B"]);
    let custom = plan
        .projection()
        .canonical()
        .payload()
        .field("query")
        .unwrap()
        .field("bounds")
        .unwrap()
        .field("custom")
        .unwrap();
    assert_eq!(
        custom,
        &V::parse(br#"{"a":null,"b":2,"list":[]}"#, Limits::default()).unwrap()
    );
}
#[test]
fn profile_missing_chaining_and_empty_anchor_errors() {
    let config = published("config", CONFIG);
    let q = br#"{"profile":"p","about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1}}"#;
    assert!(compile(
        QuerySource::inline(q),
        None,
        &config,
        CompileOptions::default()
    )
    .is_err());
    let p = published("profile", r#"{"profile":"p"}"#);
    assert!(compile(
        QuerySource::inline(q),
        Some(SelectedProfile {
            selector: "p",
            artifact: &p
        }),
        &config,
        CompileOptions::default()
    )
    .is_err());
    for about in [
        "[]",
        r#"[{"from":[],"match":"exact"}]"#,
        r#"[{"from":["A"],"to":[],"match":"exact"}]"#,
        r#"[{"from":["A"],"to":null,"match":"exact"}]"#,
    ] {
        let q = format!(r#"{{"about":{about},"bounds":{{"max_depth":1}}}}"#);
        assert!(compile(
            QuerySource::inline(q.as_bytes()),
            None,
            &config,
            CompileOptions::default()
        )
        .is_err());
    }
}
