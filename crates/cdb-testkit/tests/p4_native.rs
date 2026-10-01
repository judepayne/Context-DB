//! P2's independent authored expectations, executed through real persisted adapters.
mod common_p4;
fn reader_policy() -> cdb_backend_fluree::policy::PolicyState {
    let mut state = cdb_backend_fluree::policy::PolicyState::deny_all().unwrap();
    state.policy = allow_policy().unwrap();
    state.principals.insert(
        cdb_core::id::PrincipalId::new("reader").unwrap(),
        (
            true,
            [Iri::new("https://fixture.example/Reader").unwrap()].into(),
        ),
    );
    state
}
use cdb_core::{
    claim::ClaimObject,
    id::{Iri, ResourceId},
    policy::PolicySet,
    CanonicalValue as V, Limits,
};
use cdb_testkit::reference_fixture::{allow_policy, artifact, FixtureBuilder};
use common_p4::Fixture;
fn parse(bytes: &[u8]) -> V {
    V::parse(bytes, Limits::default()).unwrap()
}
fn passed(n: usize) {
    println!("P4_CASE {{\"id\":\"P4-Q{n:03}\",\"outcome\":\"passed\"}}");
}
#[tokio::test]
async fn execution_cases() {
    let corpus = parse(include_bytes!(
        "../../../fixtures/conformance/p2/execution-cases.json"
    ));
    let mut failures = Vec::new();
    for (n, case) in corpus
        .field("cases")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let graph = corpus
            .field("graphs")
            .unwrap()
            .field(case.field("graph").unwrap().as_str().unwrap())
            .unwrap()
            .clone();
        if let Err(e) = tokio::spawn(execution_case(n + 1, case.clone(), graph)).await {
            failures.push(format!("{}: {e}", n + 1));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
async fn execution_case(n: usize, case: V, graph: V) {
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
        builder
            .edge(
                edge.field("id").unwrap().as_str().unwrap(),
                edge.field("from").unwrap().as_str().unwrap(),
                ClaimObject::from_value(edge.field("to").unwrap()).unwrap(),
                &edge
                    .field("confidence")
                    .unwrap()
                    .as_number()
                    .unwrap()
                    .token(),
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
    let mut state = reader_policy();
    if let Some(denied) = case.as_object().unwrap().get("denied") {
        let class = Iri::new("https://fixture.example/P2Denied").unwrap();
        for resource in denied.as_array().unwrap() {
            state.classes.insert(
                ResourceId::new(resource.as_str().unwrap()).unwrap(),
                [class.clone()].into(),
            );
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
        state.policy = PolicySet::from_value(&V::Object(policy)).unwrap();
    }
    let query = artifact(
        "https://fixture.example/p4-query",
        &case
            .field("query")
            .unwrap()
            .canonical_bytes(Limits::default())
            .unwrap(),
    )
    .unwrap();
    builder.artifact(query.clone());
    let work = case
        .as_object()
        .unwrap()
        .get("max_work")
        .map(|v| v.u64().unwrap() as usize)
        .unwrap_or(1_000_000);
    let fixture = Fixture::new(builder, state, work).await;
    let request = V::Object(
        [
            ("schema".into(), V::string("ctxql-service/v1")),
            ("op".into(), V::string("query")),
            ("run_id".into(), V::string(format!("p4-{n}"))),
            ("query".into(), query.reference().projection()),
            ("config".into(), config.reference().projection()),
        ]
        .into(),
    );
    let before = fixture.backend.head().await.unwrap();
    let result = fixture.dispatch(&request).await;
    let lookup = |op: &str| {
        V::Object(
            [
                ("schema".into(), V::string("ctxql-service/v1")),
                ("op".into(), V::string(op)),
                ("run_id".into(), V::string(format!("p4-{n}"))),
            ]
            .into(),
        )
    };
    let expected = case.field("expected").unwrap();
    if let Some(kind) = expected.as_object().unwrap().get("error") {
        assert_eq!(
            before,
            fixture.backend.head().await.unwrap(),
            "{id}: error committed output"
        );
        assert!(
            fixture.dispatch(&lookup("run")).await.is_err(),
            "{id}: error wrote a run"
        );
        let error = result.expect_err(&format!("{id}: expected execution error"));
        assert_eq!(format!("{:?}", error.kind), kind.as_str().unwrap(), "{id}");
        fixture.shutdown().await;
    } else {
        let wire = result.unwrap_or_else(|e| panic!("{id}: execute: {e}"));
        let response = wire.field("response").unwrap().clone();
        let summary = fixture.dispatch(&lookup("run")).await.unwrap();
        assert_eq!(
            summary
                .field("response")
                .unwrap()
                .field("response_hash")
                .unwrap(),
            response.field("response_hash").unwrap()
        );
        let fixture = fixture.reopen().await;
        assert_eq!(summary, fixture.dispatch(&lookup("run")).await.unwrap());
        let replay = fixture.dispatch(&lookup("replay")).await.unwrap();
        let replay = replay.field("response").unwrap();
        assert_eq!(
            replay.field("graph").unwrap().as_str().unwrap(),
            "reproduced",
            "{id}"
        );
        assert_eq!(
            replay.field("response_hash").unwrap(),
            response.field("response_hash").unwrap()
        );
        for key in ["paths", "notices"] {
            assert_eq!(
                replay.field("response").unwrap().field(key).unwrap(),
                response.field(key).unwrap(),
                "{id}: {key}"
            );
        }
        fixture.shutdown().await;
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
    passed(n);
}
