//! P4 loader subslice only; these tests do not certify recorded execution.
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    canonical::{CanonicalProjection, Domain},
    id::{ContentHash, Iri, VersionId},
    CanonicalValue as V, ErrorKind, Limits, Timestamp,
};
use cdb_engine::{
    compiler::{compile, ExecutablePlan, QuerySource},
    load_recorded_plan,
    options::CompileOptions,
};
use cdb_testkit::reference_fixture::FixtureBuilder;

async fn plan(published: bool) -> ExecutablePlan {
    let f = FixtureBuilder::new().build().await.unwrap();
    let bytes = br#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":2,"seed_limit":7,"fanout_limit":9},"walk":{"predicates":[["meta:confidence",">=",0.5]]}}"#.to_vec();
    let artifact = PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new("https://e/query").unwrap(),
            VersionId::new("v1").unwrap(),
            ContentHash::of_bytes(&bytes),
        ),
        bytes,
        Limits::default(),
    )
    .unwrap();
    compile(
        if published {
            QuerySource::published(&artifact)
        } else {
            QuerySource::inline(artifact.content())
        },
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap()
    .finalize(Timestamp::parse("2026-04-01T00:00:00Z").unwrap())
    .unwrap()
}
fn load(c: &CanonicalProjection) -> cdb_core::Result<ExecutablePlan> {
    load_recorded_plan(
        &c.bytes(Limits::default())?,
        &c.hash(Limits::default())?,
        vec![],
        Limits::default(),
    )
}
fn set(v: &mut V, path: &[&str], value: V) {
    let V::Object(o) = v else { panic!("object") };
    if path.len() == 1 {
        o.insert(path[0].into(), value);
    } else {
        set(o.get_mut(path[0]).unwrap(), &path[1..], value);
    }
}
#[tokio::test]
async fn stored_plan_restores_typed_semantics_without_defaults() {
    let p = plan(true).await;
    let restored = load(p.projection().canonical()).unwrap();
    assert_eq!(restored.hash(), p.hash());
    assert_eq!(restored.caps(), p.caps());
    assert_eq!(restored.caps().seed_limit, 7);
    assert_eq!(restored.walk_predicates(), p.walk_predicates());
    assert_eq!(restored.blocks(), p.blocks());
    assert_eq!(restored.as_of(), p.as_of());
}
#[tokio::test]
async fn wrong_expected_plan_hash_fails() {
    let p = plan(true).await;
    assert!(load_recorded_plan(
        &p.projection().canonical().bytes(Limits::default()).unwrap(),
        &ContentHash::of_bytes(b"wrong"),
        vec![],
        Limits::default()
    )
    .is_err());
}
#[tokio::test]
async fn inline_plan_is_not_recordable() {
    assert!(load(plan(false).await.projection().canonical()).is_err());
}
#[tokio::test]
async fn stored_plan_does_not_substitute_resolved_bound_strings() {
    let p = plan(true).await;
    let mut value = p.projection().canonical().payload().clone();
    set(
        &mut value,
        &["query", "walk", "predicates"],
        V::parse(
            br#"[["meta:ext:note","=","bound:literal"]]"#,
            Limits::default(),
        )
        .unwrap(),
    );
    let c = CanonicalProjection::from_payload(Domain::Plan, value).unwrap();
    assert!(load(&c).is_ok());
}
#[tokio::test]
async fn malformed_named_triple_fails_without_panicking() {
    let p = plan(true).await;
    let mut value = p.projection().canonical().payload().clone();
    set(
        &mut value,
        &["query", "walk", "predicates"],
        V::parse(
            br#"[{"name":"bad","where":["meta:confidence"]}]"#,
            Limits::default(),
        )
        .unwrap(),
    );
    let c = CanonicalProjection::from_payload(Domain::Plan, value).unwrap();
    assert!(load(&c).is_err());
}
#[tokio::test]
async fn unsupported_ordering_is_not_a_replayable_plan() {
    let p = plan(true).await;
    let mut value = p.projection().canonical().payload().clone();
    set(
        &mut value,
        &["config", "runtime", "candidate_order"],
        V::Array(vec![V::string("other")]),
    );
    let c = CanonicalProjection::from_payload(Domain::Plan, value).unwrap();
    assert_eq!(load(&c).unwrap_err().kind, ErrorKind::Unsupported);
}
#[tokio::test]
async fn stored_plan_requires_all_original_caps() {
    let p = plan(true).await;
    let mut value = p.projection().canonical().envelope();
    let V::Object(root) = &mut value else {
        unreachable!()
    };
    let V::Object(payload) = root.get_mut("payload").unwrap() else {
        unreachable!()
    };
    let V::Object(query) = payload.get_mut("query").unwrap() else {
        unreachable!()
    };
    let V::Object(bounds) = query.get_mut("bounds").unwrap() else {
        unreachable!()
    };
    bounds.remove("seed_limit");
    assert!(load_recorded_plan(
        &value.canonical_bytes(Limits::default()).unwrap(),
        p.hash(),
        vec![],
        Limits::default()
    )
    .is_err());
}
