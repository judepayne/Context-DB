//! Independent, hand-authored case expectations; tagged results are checked by CI.
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    id::{ContentHash, Iri, VersionId},
    CanonicalValue as V, Limits, Timestamp,
};
use cdb_engine::{
    compiler::{compile, QuerySource, SelectedProfile},
    options::CompileOptions,
};

fn parse(bytes: &[u8]) -> V {
    V::parse(bytes, Limits::default()).unwrap()
}
fn published(name: &str, bytes: Vec<u8>) -> PublishedArtifact {
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new(format!("ctxql:{name}")).unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(&bytes),
        ),
        bytes,
        Limits::default(),
    )
    .unwrap()
}
fn passed(id: &str) {
    println!("P2_CASE {{\"id\":\"{id}\",\"outcome\":\"passed\"}}");
}
#[tokio::test]
async fn independent_response_bytes() {
    use cdb_core::{
        canonical::{CanonicalProjection, Domain},
        claim::ClaimObject,
    };
    use cdb_engine::execution::{execute, ExecutionOptions};
    use cdb_testkit::reference_fixture::FixtureBuilder;
    let vectors = parse(include_bytes!(
        "../../../fixtures/conformance/p2/bytes-v1.json"
    ));
    let vector = &vectors.field("vectors").unwrap().as_array().unwrap()[0];
    let expected = parse(
        vector
            .field("canonical_utf8")
            .unwrap()
            .as_str()
            .unwrap()
            .as_bytes(),
    );
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
    builder.entity("s", None).unwrap();
    builder
        .edge(
            "lit",
            "s",
            ClaimObject::from_value(&literal).unwrap(),
            "0.125",
        )
        .unwrap();
    let fixture = builder.build().await.unwrap();
    let draft = compile(QuerySource::inline(br#"{"about":[{"from":["s"],"match":"exact"}],"bounds":{"max_depth":3},"return":{"claims":false,"paths":true,"evidence":false,"explain":false}}"#), None, &fixture.config, CompileOptions::default()).unwrap();
    let mut bytes = Vec::new();
    execute(
        draft,
        &fixture.backend,
        &fixture.backend,
        &fixture.principal,
        &fixture,
        ExecutionOptions::default(),
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await
    .unwrap();
    let response = parse(&bytes);
    assert_eq!(
        response.field("response_hash").unwrap(),
        vector.field("sha256").unwrap()
    );
    let mut payload = response.as_object().unwrap().clone();
    for key in ["status", "response_hash", "plan_hash"] {
        payload.remove(key);
    }
    let canonical =
        CanonicalProjection::from_payload(Domain::Response, V::Object(payload)).unwrap();
    assert_eq!(
        canonical.bytes(Limits::default()).unwrap(),
        vector
            .field("canonical_utf8")
            .unwrap()
            .as_str()
            .unwrap()
            .as_bytes()
    );
    passed("P2-H001");
}

#[tokio::test]
async fn execution_cases() {
    let corpus = parse(include_bytes!(
        "../../../fixtures/conformance/p2/execution-cases.json"
    ));
    let mut failures = Vec::new();
    for case in corpus.field("cases").unwrap().as_array().unwrap() {
        let id = case.field("id").unwrap().as_str().unwrap();
        let graph = corpus
            .field("graphs")
            .unwrap()
            .field(case.field("graph").unwrap().as_str().unwrap())
            .unwrap()
            .clone();
        // Isolate assertions so a defect in one case does not skip the rest of the corpus.
        if let Err(error) = tokio::spawn(execution_case(case.clone(), graph)).await {
            failures.push(format!("{id}: {error}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

async fn execution_case(case: V, graph: V) {
    use cdb_core::{claim::ClaimObject, id::ResourceId, policy::PolicySet};
    use cdb_engine::execution::{execute, ExecutionOptions};
    use cdb_testkit::reference_fixture::{allow_policy, artifact, FixtureBuilder};

    let id = case.field("id").unwrap().as_str().unwrap();
    let mut builder = FixtureBuilder::new();
    for (entity, label) in graph.field("entities").unwrap().as_object().unwrap() {
        builder
            .entity(
                entity,
                if matches!(label, V::Null) {
                    None
                } else {
                    Some(label.as_str().unwrap())
                },
            )
            .unwrap();
    }
    for edge in graph.field("edges").unwrap().as_array().unwrap() {
        let confidence = edge
            .field("confidence")
            .unwrap()
            .as_number()
            .unwrap()
            .token();
        builder
            .edge(
                edge.field("id").unwrap().as_str().unwrap(),
                edge.field("from").unwrap().as_str().unwrap(),
                ClaimObject::from_value(edge.field("to").unwrap()).unwrap(),
                &confidence,
            )
            .unwrap();
    }
    let mut config = parse(include_bytes!(
        "../../../fixtures/conformance/p2/config.json"
    ))
    .as_object()
    .unwrap()
    .clone();
    if let Some(cycle) = case.as_object().unwrap().get("cycle") {
        let mut runtime = config.get("runtime").unwrap().as_object().unwrap().clone();
        runtime.insert("cycle_policy".into(), cycle.clone());
        config.insert("runtime".into(), V::Object(runtime));
    }
    let config = artifact(
        "https://fixture.example/p2-config",
        &V::Object(config)
            .canonical_bytes(Limits::default())
            .unwrap(),
    )
    .unwrap();
    builder.artifact(config.clone());
    let fixture = builder.build().await.unwrap();
    if let Some(denied) = case.as_object().unwrap().get("denied") {
        let class = Iri::new("https://fixture.example/P2Denied").unwrap();
        for resource in denied.as_array().unwrap() {
            fixture
                .backend
                .set_classes(
                    ResourceId::new(resource.as_str().unwrap()).unwrap(),
                    [class.clone()].into(),
                )
                .unwrap();
        }
        let mut policy = allow_policy()
            .unwrap()
            .projection()
            .as_object()
            .unwrap()
            .clone();
        let mut rules = policy.get("policies").unwrap().as_array().unwrap().to_vec();
        rules.push(parse(br#"{"@id":"https://fixture.example/p2-deny","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#onClass":"https://fixture.example/P2Denied"}"#));
        policy.insert("policies".into(), V::Array(rules));
        fixture
            .backend
            .set_policy(PolicySet::from_value(&V::Object(policy)).unwrap())
            .unwrap();
    }
    let query = case
        .field("query")
        .unwrap()
        .canonical_bytes(Limits::default())
        .unwrap();
    let draft = compile(
        QuerySource::inline(&query),
        None,
        &config,
        CompileOptions::default(),
    )
    .unwrap_or_else(|e| panic!("{id}: compile: {e}"));
    let mut options = ExecutionOptions::default();
    if let Some(work) = case.as_object().unwrap().get("max_work") {
        options.max_work = usize::try_from(work.u64().unwrap()).unwrap();
    }
    let mut bytes = Vec::new();
    let result = execute(
        draft,
        &fixture.backend,
        &fixture.backend,
        &fixture.principal,
        &fixture,
        options,
        &mut |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        },
    )
    .await;
    let expected = case.field("expected").unwrap();
    if let Some(kind) = expected.as_object().unwrap().get("error") {
        assert!(bytes.is_empty(), "{id}: error released sink bytes");
        let error = result.expect_err(&format!("{id}: expected execution error"));
        assert_eq!(format!("{:?}", error.kind), kind.as_str().unwrap(), "{id}");
    } else {
        result.unwrap_or_else(|e| panic!("{id}: execute: {e}"));
        let response = parse(&bytes);
        let paths = response.field("paths").unwrap().as_array().unwrap();
        let column = |key: &str| {
            V::Array(
                paths
                    .iter()
                    .map(|p| p.field(key).unwrap().clone())
                    .collect(),
            )
        };
        assert_eq!(
            &column("claim_ids"),
            expected.field("paths").unwrap(),
            "{id}: ordered claims"
        );
        if let Some(nodes) = expected.as_object().unwrap().get("nodes") {
            assert_eq!(&column("node_ids"), nodes, "{id}: ordered nodes");
        }
        let blocks = expected
            .as_object()
            .unwrap()
            .get("blocks")
            .cloned()
            .unwrap_or_else(|| V::Array(vec![V::integer(0); paths.len()]));
        assert_eq!(column("block_index"), blocks, "{id}: blocks");
        if let Some(terminal) = expected.as_object().unwrap().get("terminal_literal") {
            assert!(!paths.is_empty(), "{id}: terminal flag requires a path");
            for path in paths {
                let endpoint = path
                    .field("endpoints")
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .last()
                    .unwrap();
                assert_eq!(
                    V::Bool(endpoint.field("kind").unwrap().as_str().unwrap() == "literal"),
                    *terminal,
                    "{id}: terminal literal"
                );
            }
        }
    }
    passed(id);
}

#[test]
fn compiler_cases() {
    let cases = parse(include_bytes!(
        "../../../fixtures/conformance/p2/compiler-cases.json"
    ));
    let config = published(
        "config/fixture",
        include_bytes!("../../../fixtures/conformance/p2/config.json").to_vec(),
    );
    for case in cases.field("cases").unwrap().as_array().unwrap() {
        let id = case.field("id").unwrap().as_str().unwrap();
        let query = case.field("query").unwrap();
        let query_bytes = query.canonical_bytes(Limits::default()).unwrap();
        let profile = case
            .as_object()
            .unwrap()
            .get("profile")
            .map(|p| published("profile/p", p.canonical_bytes(Limits::default()).unwrap()));
        let selected = profile.as_ref().map(|p| SelectedProfile {
            selector: query.field("profile").unwrap().as_str().unwrap(),
            artifact: p,
        });
        let result = compile(
            QuerySource::inline(&query_bytes),
            selected,
            &config,
            CompileOptions::default(),
        );
        let expected = case.field("expected").unwrap();
        let outcome = expected.field("outcome").unwrap().as_str().unwrap();
        if outcome == "compiled" {
            let draft = result.unwrap_or_else(|e| panic!("{id}: {e}"));
            let cutoff = draft
                .requested_as_of()
                .unwrap_or(Timestamp::from_millis(0).unwrap());
            let plan = draft.finalize(cutoff).unwrap();
            assert_eq!(
                plan.caps().max_depth,
                expected.field("max_depth").unwrap().u64().unwrap(),
                "{id}"
            );
            assert_eq!(
                plan.walk_predicates().len() as u64,
                expected.field("walk").unwrap().u64().unwrap(),
                "{id}"
            );
            assert_eq!(
                plan.filter_predicates().len() as u64,
                expected.field("filter").unwrap().u64().unwrap(),
                "{id}"
            );
            if let Some(n) = expected.as_object().unwrap().get("notices") {
                assert_eq!(plan.notices().len() as u64, n.u64().unwrap(), "{id}");
            }
        } else {
            let error = result
                .err()
                .unwrap_or_else(|| panic!("{id}: expected {outcome}"));
            assert_eq!(format!("{:?}", error.kind), outcome, "{id}");
        }
        passed(id);
    }
}
