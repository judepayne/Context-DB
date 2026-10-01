//! Independent C3d / active-plan D4–5 regression expectations, not engine goldens.
use cdb_core::{
    admission::*, claim::*, contracts::GraphBackend, id::*, policy::PolicySet, CanonicalValue as V,
    ExactNumber, Limits, Timestamp,
};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::{execute, property_iri, ExecutionOptions},
    options::CompileOptions,
};
use cdb_testkit::reference_fixture::{allow_policy, FixtureBuilder, ReferenceFixture};

const OLD: &str = "https://lifecycle/old";
const REPLACEMENT: &str = "https://lifecycle/replacement";
const EVENT: &str = "https://lifecycle/event";

fn base() -> FixtureBuilder {
    let mut b = FixtureBuilder::new();
    for label in ["A", "B", "X", "Y"] {
        b.entity(&format!("https://lifecycle/{label}"), Some(label))
            .unwrap();
    }
    // Replacement is deliberately disconnected from A, and has a different confidence.
    for (id, from, to, confidence) in [(OLD, "A", "B", "0.2"), (REPLACEMENT, "X", "Y", "0.9")] {
        b.edge(
            id,
            &format!("https://lifecycle/{from}"),
            ClaimObject::Entity(EntityId::new(format!("https://lifecycle/{to}")).unwrap()),
            confidence,
        )
        .unwrap();
    }
    b.resource(
        DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new(EVENT).unwrap(),
            ResourceKind::LifecycleEvent,
            vec![Fact::new(
                property_iri("event").unwrap(),
                FactTerm::Literal(
                    TypedLiteral::new(
                        Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                        V::string("withdrawal"),
                        None,
                    )
                    .unwrap(),
                ),
            )],
        )
        .unwrap(),
    );
    b
}

fn support(id: &str, relation: &str) -> LifecycleAssertion {
    let object = if relation == "retracted_by" {
        EVENT
    } else {
        REPLACEMENT
    };
    let object_type = if relation == "retracted_by" {
        "Event"
    } else {
        "Claim"
    };
    // Full immutable candidate metadata; transaction time is assigned only by admission.
    let json = format!(
        r#"{{"claim_id":"https://lifecycle/{id}","subject_id":"{OLD}","relation":"ctxql:{relation}","object_id":"{object}","relation_type":"https://lifecycle/Relation","subject_type":"https://lifecycle/Claim","object_type":"https://lifecycle/{object_type}","claim_type":"https://lifecycle/Assertion","confidence":0.7,"grounding_level":"claim_only","ext":{{"reason":"independent lifecycle test"}}}}"#
    );
    LifecycleAssertion::from_value(&V::parse(json.as_bytes(), Limits::default()).unwrap()).unwrap()
}

async fn admit(f: &ReferenceFixture, key: &str, supports: Vec<LifecycleAssertion>) -> Timestamp {
    let batch = AdmissionBatch::new(
        vec![],
        supports,
        vec![],
        vec![],
        V::Object(Default::default()),
        Limits::default(),
    )
    .unwrap();
    f.backend
        .admit(&IdempotencyKey::new(key).unwrap(), &batch)
        .await
        .unwrap()
        .transaction_time()
}

async fn run(f: &ReferenceFixture, cutoff: Option<Timestamp>, predicate: &str) -> V {
    let cutoff = cutoff
        .map(|t| format!(r#", "as_of":"{}""#, t.canonical()))
        .unwrap_or_default();
    let q = format!(
        r#"{{"about":[{{"from":["A"],"match":"exact"}}],"bounds":{{"max_depth":3{cutoff}}},"walk":{{"predicates":[{predicate}]}},"return":{{"explain":true}}}}"#
    );
    let draft = compile(
        QuerySource::inline(q.as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    let mut publications = 0;
    execute(
        draft,
        &f.backend,
        &f.backend,
        &f.principal,
        f,
        ExecutionOptions::default(),
        &mut |b| {
            publications += 1;
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(
        publications, 1,
        "response must use the guarded publication sink"
    );
    V::parse(&bytes, Limits::default()).unwrap()
}

fn paths(v: &V) -> Vec<Vec<&str>> {
    v.field("paths")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            p.field("claim_ids")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|id| id.as_str().unwrap())
                .collect()
        })
        .collect()
}

fn assert_state(v: &V, state: &str, supporting_ids: &[&str]) {
    assert_eq!(
        paths(v),
        vec![vec![OLD]],
        "lifecycle is metadata, not an implicit active-only gate"
    );
    let claims = v.field("claims").unwrap().as_array().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        claims[0]
            .field("meta")
            .unwrap()
            .field("lifecycle_state")
            .unwrap(),
        &V::string(state)
    );
    let entries = v
        .field("explain")
        .unwrap()
        .field("lifecycle")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.field("claim_id").unwrap(), &V::string(OLD));
    assert_eq!(
        entry.field("rule").unwrap(),
        &V::string("ctxql-execution/v1:lifecycle")
    );
    assert_eq!(entry.field("state").unwrap(), &V::string(state));
    assert_eq!(
        entry.field("supporting_ids").unwrap(),
        &V::Array(supporting_ids.iter().map(|s| V::string(*s)).collect())
    );
}

fn deny(f: &ReferenceFixture, target: &str) {
    let mut policy = allow_policy()
        .unwrap()
        .projection()
        .as_object()
        .unwrap()
        .clone();
    let mut rules = policy["policies"].as_array().unwrap().to_vec();
    let rule = format!(
        r#"{{"@id":"https://lifecycle/deny","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":false,"https://ns.flur.ee/db#onSubject":"{target}"}}"#
    );
    rules.push(V::parse(rule.as_bytes(), Limits::default()).unwrap());
    policy.insert("policies".into(), V::Array(rules));
    f.backend
        .set_policy(PolicySet::from_value(&V::Object(policy)).unwrap())
        .unwrap();
}

#[tokio::test]
async fn each_state_and_priority_are_metadata_not_implicit_filter() {
    // Reverse priority insertion ensures input order cannot establish the winner.
    for (relations, expected, ids) in [
        (vec![], "active", vec![]),
        (
            vec![("c", "contradicted_by")],
            "contradicted",
            vec!["https://lifecycle/c"],
        ),
        (
            vec![("s", "superseded_by"), ("c", "contradicted_by")],
            "superseded",
            vec!["https://lifecycle/s"],
        ),
        (
            vec![
                ("r", "retracted_by"),
                ("s", "superseded_by"),
                ("c", "contradicted_by"),
            ],
            "retracted",
            vec!["https://lifecycle/r"],
        ),
    ] {
        let mut b = base();
        for (id, relation) in relations {
            b.lifecycle(support(id, relation));
        }
        let f = b.build().await.unwrap();
        assert_state(&run(&f, None, "").await, expected, &ids);
        let predicate = format!(r#"["meta:lifecycle_state","=","{expected}"]"#);
        assert_state(&run(&f, None, &predicate).await, expected, &ids);
    }
}

#[tokio::test]
async fn equal_time_winning_support_uses_assertion_ids_not_event_id() {
    let mut b = base();
    // Same admission => equal transaction times; both assertions reference one distinct event.
    for id in ["z-retraction", "a-retraction"] {
        let s = support(id, "retracted_by");
        assert_eq!(
            s.reference(),
            &LifecycleReference::Event(ResourceId::new(EVENT).unwrap())
        );
        assert_ne!(s.id().as_str(), EVENT);
        b.lifecycle(s);
    }
    b.lifecycle(support("0-contradiction", "contradicted_by"));
    let f = b.build().await.unwrap();
    assert_state(
        &run(&f, None, "").await,
        "retracted",
        &[
            "https://lifecycle/a-retraction",
            "https://lifecycle/z-retraction",
        ],
    );
}

#[tokio::test]
async fn later_admission_cutoff_is_inclusive_and_priority_beats_recency() {
    let f = base().build().await.unwrap();
    let initial = f
        .backend
        .receipt(&IdempotencyKey::new("reference-initial").unwrap())
        .await
        .unwrap()
        .unwrap()
        .transaction_time();
    // The catalog remains unchanged: only immutable lifecycle claims are added later.
    let retracted = admit(&f, "retract", vec![support("r", "retracted_by")]).await;
    let contradicted = admit(
        &f,
        "contradict-later",
        vec![support("c", "contradicted_by")],
    )
    .await;
    assert!(initial < retracted && retracted < contradicted);
    assert_state(&run(&f, Some(initial), "").await, "active", &[]);
    assert_state(
        &run(&f, Some(retracted), "").await,
        "retracted",
        &["https://lifecycle/r"],
    );
    assert_state(
        &run(&f, Some(contradicted), "").await,
        "retracted",
        &["https://lifecycle/r"],
    );
}

#[tokio::test]
async fn winning_support_orders_newest_before_lexical_id() {
    let mut b = base();
    b.lifecycle(support("a-old", "retracted_by"));
    let f = b.build().await.unwrap();
    let later = admit(
        &f,
        "new-retractions",
        vec![
            support("z-new", "retracted_by"),
            support("y-new", "retracted_by"),
        ],
    )
    .await;
    assert_state(
        &run(&f, Some(later), "").await,
        "retracted",
        &[
            "https://lifecycle/y-new",
            "https://lifecycle/z-new",
            "https://lifecycle/a-old",
        ],
    );
}

#[tokio::test]
async fn denied_winning_lower_priority_or_event_dependency_poison_claim() {
    for target in ["https://lifecycle/r", "https://lifecycle/c", EVENT] {
        let mut b = base();
        b.lifecycle(support("r", "retracted_by"));
        b.lifecycle(support("c", "contradicted_by"));
        let f = b.build().await.unwrap();
        assert_state(
            &run(&f, None, "").await,
            "retracted",
            &["https://lifecycle/r"],
        );
        deny(&f, target);
        for predicate in ["", r#"["meta:lifecycle_state","=","active"]"#] {
            let v = run(&f, None, predicate).await;
            assert!(
                paths(&v).is_empty(),
                "denied {target} must not disappear into active state"
            );
            assert_eq!(v.field("claims").unwrap(), &V::Array(vec![]));
            assert_eq!(
                v.field("explain").unwrap().field("lifecycle").unwrap(),
                &V::Array(vec![])
            );
            let bytes = String::from_utf8(v.canonical_bytes(Limits::default()).unwrap()).unwrap();
            assert!(!bytes.contains(target), "denied dependency must not leak");
        }
    }
}

#[tokio::test]
async fn typed_replacement_reference_never_hops_or_transfers_confidence() {
    let mut b = base();
    let s = support("s", "superseded_by");
    assert_eq!(
        s.reference(),
        &LifecycleReference::Claim(ClaimId::new(REPLACEMENT).unwrap())
    );
    assert!(s.event().is_none());
    b.lifecycle(s);
    let f = b.build().await.unwrap();
    let v = run(&f, None, "").await;
    assert_state(&v, "superseded", &["https://lifecycle/s"]);
    let path = &v.field("paths").unwrap().as_array().unwrap()[0];
    assert_eq!(
        path.field("node_ids").unwrap(),
        &V::Array(vec![
            V::string("https://lifecycle/A"),
            V::string("https://lifecycle/B")
        ])
    );
    assert_eq!(
        path.field("scores")
            .unwrap()
            .field("accumulated_confidence")
            .unwrap()
            .as_number()
            .unwrap(),
        &ExactNumber::parse("0.2").unwrap()
    );
    assert_eq!(
        v.field("claims").unwrap().as_array().unwrap()[0]
            .field("meta")
            .unwrap()
            .field("confidence")
            .unwrap()
            .as_number()
            .unwrap(),
        &ExactNumber::parse("0.2").unwrap()
    );
    // A typed replacement is an interpretation dependency even though not traversed.
    deny(&f, REPLACEMENT);
    assert!(paths(&run(&f, None, "").await).is_empty());
}
