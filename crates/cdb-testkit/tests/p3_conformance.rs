//! P2's independent authored expectations, executed through real persisted adapters.
mod common_p3;
use cdb_core::{
    claim::ClaimObject,
    id::{Iri, ResourceId},
    policy::PolicySet,
    CanonicalValue as V, Limits,
};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::{execute, ExecutionOptions},
    options::CompileOptions,
};
use cdb_testkit::reference_fixture::{allow_policy, artifact, FixtureBuilder};
use common_p3::{reader_policy, NativeFixture};
fn parse(bytes: &[u8]) -> V {
    V::parse(bytes, Limits::default()).unwrap()
}
fn passed(n: usize) {
    println!("P3_CASE {{\"id\":\"P3-Q{n:03}\",\"outcome\":\"passed\"}}");
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
    let fixture = NativeFixture::new(builder, state, 1000).await;
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
        fixture.backend.as_ref(),
        fixture.backend.as_ref(),
        &fixture.principal,
        &fixture.provider,
        options,
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await;
    // Stop worker even if the independent assertions below fail.
    fixture.shutdown().await;
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
    passed(n);
}
#[tokio::test]
async fn live_bus_and_held_history() {
    use cdb_core::{
        contracts::{ProjectionStore, RawQueryView},
        id::{ClaimId, IdempotencyKey},
    };
    use cdb_projection_redb::CoordinatorStatus;
    use std::time::Duration;
    use tokio::time::{timeout, Instant};
    let mut builder = FixtureBuilder::new();
    builder
        .entity("s", None)
        .unwrap()
        .entity("t", None)
        .unwrap()
        .edge(
            "a",
            "s",
            ClaimObject::from_value(&V::string("t")).unwrap(),
            "0.8",
        )
        .unwrap();
    let fixture = NativeFixture::new(builder, reader_policy(), 1).await;
    let query = br#"{"about":[{"from":["s"],"match":"exact"}],"bounds":{"max_depth":1},"return":{"claims":false,"paths":true,"evidence":false,"explain":false}}"#;
    let mut initial = Vec::new();
    let draft = compile(
        QuerySource::inline(query),
        None,
        &fixture.config,
        CompileOptions::default(),
    )
    .unwrap();
    execute(
        draft,
        fixture.backend.as_ref(),
        fixture.backend.as_ref(),
        &fixture.principal,
        &fixture.provider,
        ExecutionOptions::default(),
        &mut |b| {
            initial.extend_from_slice(b);
            Ok(())
        },
    )
    .await
    .unwrap();
    let pin = fixture.backend.head().await.unwrap();
    let held = fixture
        .coordinator
        .wait_exact(&pin, Instant::now() + Duration::from_secs(60))
        .await
        .unwrap();
    fixture.advance();
    let mut later = FixtureBuilder::new();
    later
        .edge(
            "b",
            "s",
            ClaimObject::from_value(&V::string("t")).unwrap(),
            "0.9",
        )
        .unwrap();
    let mut status = fixture.coordinator.status();
    let authored = later.into_batch().unwrap();
    // FixtureBuilder includes the initial config; this second admission adds only its new claim.
    let batch = cdb_core::admission::AdmissionBatch::new(
        authored.claims().to_vec(),
        vec![],
        vec![],
        vec![],
        V::Object(Default::default()),
        Limits::default(),
    )
    .unwrap();
    let receipt = fixture
        .backend
        .admit(&IdempotencyKey::new("later").unwrap(), &batch)
        .await
        .unwrap();
    // No wait command/reconcile/manual fold triggers this advancement: observe the real bus worker.
    timeout(Duration::from_secs(60), async {
        loop {
            if matches!(&*status.borrow_and_update(), CoordinatorStatus::Ready(cp) if cp.snapshot() == receipt.snapshot()) { break; }
            status.changed().await.unwrap();
        }
    }).await.unwrap();
    let live = fixture
        .coordinator
        .wait_exact(receipt.snapshot(), Instant::now() + Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(
        fixture
            .store
            .checkpoint()
            .await
            .unwrap()
            .unwrap()
            .snapshot(),
        receipt.snapshot()
    );
    assert!(live.claim(&ClaimId::new("b").unwrap()).unwrap().is_some());
    assert_eq!(held.identity(), &pin);
    assert!(held.claim(&ClaimId::new("a").unwrap()).unwrap().is_some());
    assert!(held.claim(&ClaimId::new("b").unwrap()).unwrap().is_none());
    let historical = fixture
        .coordinator
        .wait_exact(&pin, Instant::now() + Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(historical.identity(), &pin);
    assert!(historical
        .claim(&ClaimId::new("b").unwrap())
        .unwrap()
        .is_none());
    // Historical cutoff query after the write retains the initial authored result.
    let past = br#"{"about":[{"from":["s"],"match":"exact"}],"bounds":{"max_depth":1,"as_of":"2026-04-01T00:00:00.001Z"},"return":{"claims":false,"paths":true,"evidence":false,"explain":false}}"#;
    let draft = compile(
        QuerySource::inline(past),
        None,
        &fixture.config,
        CompileOptions::default(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    execute(
        draft,
        fixture.backend.as_ref(),
        fixture.backend.as_ref(),
        &fixture.principal,
        &fixture.provider,
        ExecutionOptions::default(),
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(
        parse(&bytes).field("paths").unwrap(),
        parse(&initial).field("paths").unwrap()
    );
    drop((held, historical, live, status));
    fixture.shutdown().await;
}
#[tokio::test]
async fn independent_response_bytes() {
    use cdb_core::canonical::{CanonicalProjection, Domain};
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
    let fixture = NativeFixture::new(builder, reader_policy(), 1000).await;
    let draft = compile(QuerySource::inline(br#"{"about":[{"from":["s"],"match":"exact"}],"bounds":{"max_depth":3},"return":{"claims":false,"paths":true,"evidence":false,"explain":false}}"#), None, &fixture.config, CompileOptions::default()).unwrap();
    let mut bytes = Vec::new();
    let result = execute(
        draft,
        fixture.backend.as_ref(),
        fixture.backend.as_ref(),
        &fixture.principal,
        &fixture.provider,
        ExecutionOptions::default(),
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await;
    fixture.shutdown().await;
    result.unwrap();
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
    passed(23);
}
