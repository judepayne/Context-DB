//! Real native recording retains selector grants; replay hydration never reuses cached bytes.
mod common_p4;
use cdb_core::{
    admission::ExportRecord,
    claim::CandidateClaim,
    evidence::{EvidenceSelector, Utf8Span},
    id::*,
    policy::PolicySet,
    source::SourceReadRequest,
    CanonicalValue as V, ErrorKind, Limits,
};
use cdb_service::sources::{selector_records, SourceStore};
use cdb_testkit::reference_fixture::{allow_policy, artifact, FixtureBuilder, CONFIG};
use common_p4::Fixture;
fn obj<const N: usize>(v: [(&str, V); N]) -> V {
    V::Object(v.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
#[tokio::test]
async fn native_graph_replay_does_not_require_external_bytes_but_requires_selector_grants() {
    let text = "Aé🙂\n漢Z";
    let source = SourceReadRequest {
        source_id: SourceId::new("document-source").unwrap(),
        version: ContentHash::of_bytes(text.as_bytes()),
        selector: EvidenceSelector::Span(Utf8Span::new(3, 11).unwrap()),
        max_bytes: 32,
    };
    let selectors = obj([
        ("contract", V::string("ctxql-evidence/v1")),
        (
            "utf8",
            obj([("start", V::integer(3)), ("end", V::integer(11))]),
        ),
    ]);
    let lineage = obj([
        ("schema", V::string("ctxql.lineage.v1")),
        (
            "sources",
            V::Array(vec![obj([
                ("source_id", V::string(source.source_id.as_str())),
                ("kind", V::string("document")),
                ("version", V::string(source.version.as_str())),
                (
                    "content_hash",
                    V::string(ContentHash::of_bytes("🙂\n漢".as_bytes()).as_str()),
                ),
                ("selectors", selectors),
            ])]),
        ),
    ]);
    let mut claim=V::parse(br#"{"claim_id":"ab","subject_id":"A","relation":"https://fixture.example/edge","object_id":"B","relation_type":"https://fixture.example/Relation","subject_type":"https://fixture.example/Entity","object_type":"https://fixture.example/Entity","claim_type":"https://fixture.example/Assertion","confidence":1,"grounding_level":"source_spans_available"}"#,Limits::default()).unwrap().as_object().unwrap().clone();
    claim.insert("lineage".into(), lineage);
    let mut builder = FixtureBuilder::new();
    builder
        .entity("A", None)
        .unwrap()
        .entity("B", None)
        .unwrap()
        .claim(CandidateClaim::from_value(&V::Object(claim)).unwrap())
        .unwrap();
    let records = selector_records(&source, &ContentHash::of_bytes("🙂\n漢".as_bytes())).unwrap();
    for record in &records {
        let ExportRecord::Resource(record) = record else {
            unreachable!()
        };
        builder.resource(record.clone());
    }
    let config = artifact("https://fixture.example/config", CONFIG.as_bytes()).unwrap();
    let query=artifact("https://fixture.example/evidence-query",br#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1},"return":{"claims":false,"evidence":true,"explain":false}}"#).unwrap();
    builder.artifact(config.clone()).artifact(query.clone());
    let mut state = cdb_backend_fluree::policy::PolicyState::deny_all().unwrap();
    state.policy = allow_policy().unwrap();
    state.principals.insert(
        PrincipalId::new("reader").unwrap(),
        (
            true,
            [Iri::new("https://fixture.example/Reader").unwrap()].into(),
        ),
    );
    let f = Fixture::new(builder, state, 1_000_000).await;
    let root = f.root.path().canonicalize().unwrap().join("sources");
    SourceStore::open(root.clone(), 1024)
        .unwrap()
        .put(text.as_bytes())
        .unwrap();
    let result = f
        .dispatch(&obj([
            ("schema", V::string("ctxql-service/v1")),
            ("op", V::string("query")),
            ("run_id", V::string("evidence")),
            ("query", query.reference().projection()),
            ("config", config.reference().projection()),
        ]))
        .await
        .unwrap();
    let original = result.field("response").unwrap();
    let evidence = &original.field("evidence").unwrap().as_array().unwrap()[0];
    assert_eq!(evidence.field("status").unwrap(), &V::string("verified"));
    assert_eq!(evidence.field("content").unwrap(), &V::string("🙂\n漢"));
    let f = f.reopen().await;
    let replay = |hydrate: bool| {
        obj([
            ("schema", V::string("ctxql-service/v1")),
            ("op", V::string("replay")),
            ("run_id", V::string("evidence")),
            ("hydrate", V::Bool(hydrate)),
        ])
    };
    let hydrated = f.dispatch(&replay(true)).await.unwrap();
    assert_eq!(
        hydrated
            .field("response")
            .unwrap()
            .field("evidence")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .field("content")
            .unwrap(),
        &V::string("🙂\n漢")
    );
    println!("P4_CASE {{\"id\":\"P4-S011\",\"outcome\":\"passed\"}}");
    let path = root.join(&source.version.as_str()[7..]);
    std::fs::rename(&path, path.with_extension("retained-away")).unwrap();
    let graph = f.dispatch(&replay(false)).await.unwrap();
    let graph = graph.field("response").unwrap();
    assert_eq!(graph.field("graph").unwrap(), &V::string("reproduced"));
    assert_eq!(
        graph.field("response_hash").unwrap(),
        original.field("response_hash").unwrap()
    );
    assert!(!graph.as_object().unwrap().contains_key("evidence"));
    let hydrated = f.dispatch(&replay(true)).await.unwrap();
    let hydrated = hydrated.field("response").unwrap();
    assert_eq!(hydrated.field("graph").unwrap(), &V::string("reproduced"));
    let e = &hydrated.field("evidence").unwrap().as_array().unwrap()[0];
    assert_eq!(e.field("status").unwrap(), &V::string("unavailable"));
    assert_eq!(e.field("content").unwrap(), &V::Null);
    println!("P4_CASE {{\"id\":\"P4-S012\",\"outcome\":\"passed\"}}");
    let mut state = f.backend.policy_state().await.unwrap();
    let ExportRecord::Resource(selector) = &records[2] else {
        unreachable!()
    };
    state.classes.insert(
        selector.id().clone(),
        [Iri::new("https://fixture.example/Secret").unwrap()].into(),
    );
    let mut policy = state.policy.projection().as_object().unwrap().clone();
    let mut rules = policy["policies"].as_array().unwrap().to_vec();
    rules.push(V::parse(br#"{"@id":"https://fixture.example/deny-selector","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#onClass":"https://fixture.example/Secret"}"#,Limits::default()).unwrap());
    policy.insert("policies".into(), V::Array(rules));
    state.policy = PolicySet::from_value(&V::Object(policy)).unwrap();
    f.backend
        .set_policy_state(&IdempotencyKey::new("revoke-selector").unwrap(), &state)
        .await
        .unwrap();
    let graph = f.dispatch(&replay(false)).await.unwrap();
    assert_eq!(
        graph.field("response").unwrap().field("graph").unwrap(),
        &V::string("reproduced")
    );
    assert_eq!(
        f.dispatch(&replay(true)).await.unwrap_err().kind,
        ErrorKind::Denied
    );
    f.shutdown().await;
    println!("P4_CASE {{\"id\":\"P4-S013\",\"outcome\":\"passed\"}}");
}
