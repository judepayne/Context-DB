use cdb_core::{
    admission::*, claim::*, contracts::*, id::*, snapshot::*, CanonicalValue as V, Limits,
    Timestamp,
};
use cdb_testkit::{assertions::complete_export, memory::*, projection::*};

fn candidate(id: &str, subject: &str, relation: &str, object: &str) -> CandidateClaim {
    let mut v = V::parse(br#"{"claim_id":"c","subject_id":"s","object_id":"o","relation":"urn:rel","relation_type":"urn:LifecycleRelation","subject_type":"urn:Claim","object_type":"urn:Reference","claim_type":"urn:Assertion","confidence":0.81234567890123456789,"grounding_level":"source_lineage_available","lineage":{"schema":"ctxql.lineage.v1","sources":[{"source_id":"source-2","kind":"document","uri":"urn:evidence:second"},{"source_id":"source-1","kind":"document","uri":"urn:evidence:first"}]},"ext":{"author":"Zo\u00eb","note":[null,42]},"valid_time":"2020-01-01T00:00:00.000Z","source_observed_at":"2020-01-02T00:00:00.000Z"}"#, Limits::default()).unwrap().as_object().unwrap().clone();
    for (key, val) in [
        ("claim_id", id),
        ("subject_id", subject),
        ("relation", relation),
        ("object_id", object),
    ] {
        v.insert(key.into(), V::string(val));
    }
    CandidateClaim::from_value(&V::Object(v)).unwrap()
}
fn batch(
    claims: Vec<CandidateClaim>,
    lifecycle: Vec<LifecycleAssertion>,
    resources: Vec<ResourceChange>,
) -> AdmissionBatch {
    AdmissionBatch::new(
        claims,
        lifecycle,
        resources,
        vec![],
        V::object([]).unwrap(),
        Limits::default(),
    )
    .unwrap()
}
fn backend() -> MemoryBackend {
    MemoryBackend::new(
        BackendId::new("b").unwrap(),
        AuthorityId::new("b:review").unwrap(),
        GraphId::new("g").unwrap(),
        Timestamp::parse("2021-01-01T00:00:00.000Z").unwrap(),
        MemoryOptions::default(),
    )
    .unwrap()
}
fn cp(pin: &SnapshotRef, generation: &str) -> ProjectionCheckpoint {
    ProjectionCheckpoint::new(
        pin.clone(),
        VersionId::new("ctxql-projection/v1").unwrap(),
        VersionId::new(generation).unwrap(),
        Iri::new("urn:algorithm").unwrap(),
    )
    .unwrap()
}
async fn export(b: &MemoryBackend, pin: &SnapshotRef) -> CompleteExport {
    complete_export(b.open_snapshot(pin).await.unwrap().as_ref(), 1000)
        .await
        .unwrap()
}
fn event(id: &str, kind: ResourceKind) -> ResourceChange {
    ResourceChange::Add(
        DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new(id).unwrap(),
            kind,
            vec![Fact::new(
                Iri::new("urn:reason").unwrap(),
                FactTerm::Reference(ResourceId::new("withdrawal").unwrap()),
            )],
        )
        .unwrap(),
    )
}
async fn changes(b: &MemoryBackend, a: &SnapshotRef, c: &SnapshotRef) -> Vec<ChangeBatch> {
    let page = b
        .changes(a, c, None, PageSize::new(100).unwrap())
        .await
        .unwrap();
    assert!(page.complete());
    page.items().to_vec()
}
#[tokio::test]
async fn cached_ahead_reconciles_authoritative_history_without_rewinding_held_views() {
    let b = backend();
    let a = b.head().await.unwrap();
    let p = MemoryProjection::new(
        a.clone(),
        Iri::new("urn:algorithm").unwrap(),
        ProjectionOptions::default(),
    )
    .unwrap();
    p.build(&export(&b, &a).await, &cp(&a, "live"))
        .await
        .unwrap();
    let held_a = p.open_view(&a).await.unwrap();
    let receipt = b
        .admit(
            &IdempotencyKey::new("b").unwrap(),
            &batch(vec![candidate("c1", "s", "urn:r", "o")], vec![], vec![]),
        )
        .await
        .unwrap();
    let middle = receipt.snapshot().clone();
    p.build(&export(&b, &middle).await, &cp(&middle, "cached"))
        .await
        .unwrap();
    let held_b = p.open_view(&middle).await.unwrap();
    assert_eq!(p.checkpoint().await.unwrap(), Some(cp(&a, "live")));
    let end = b
        .admit(
            &IdempotencyKey::new("c").unwrap(),
            &batch(vec![candidate("c2", "s", "urn:r", "o")], vec![], vec![]),
        )
        .await
        .unwrap()
        .snapshot()
        .clone();
    let history = changes(&b, &a, &end).await;
    assert_eq!(history.len(), 2);
    p.set_write_fault(true);
    assert!(p.apply(&history[0], &cp(&middle, "live")).await.is_err());
    assert_eq!(p.checkpoint().await.unwrap(), Some(cp(&a, "live")));
    p.set_write_fault(false);
    for change in &history {
        p.apply(change, &cp(change.result(), "live")).await.unwrap();
    }
    assert_eq!(p.checkpoint().await.unwrap(), Some(cp(&end, "live")));
    assert!(held_a
        .claim(&ClaimId::new("c1").unwrap())
        .unwrap()
        .is_none());
    assert!(held_b
        .claim(&ClaimId::new("c1").unwrap())
        .unwrap()
        .is_some());
    assert!(held_b
        .claim(&ClaimId::new("c2").unwrap())
        .unwrap()
        .is_none());
    assert!(p
        .open_view(&end)
        .await
        .unwrap()
        .claim(&ClaimId::new("c2").unwrap())
        .unwrap()
        .is_some());
}
#[tokio::test]
async fn mismatched_cached_result_is_rejected_without_any_publication() {
    let b = backend();
    let a = b.head().await.unwrap();
    let middle = b
        .admit(
            &IdempotencyKey::new("b").unwrap(),
            &batch(vec![candidate("c1", "s", "urn:r", "o")], vec![], vec![]),
        )
        .await
        .unwrap()
        .snapshot()
        .clone();
    let p = MemoryProjection::new(
        a.clone(),
        Iri::new("urn:algorithm").unwrap(),
        ProjectionOptions::default(),
    )
    .unwrap();
    p.build(&export(&b, &a).await, &cp(&a, "live"))
        .await
        .unwrap();
    // A terminal export asserts completeness but deliberately omits the authoritative records.
    let wrong = CompleteExport::collect(
        middle.clone(),
        ResourceId::new("export").unwrap(),
        vec![Page::new(vec![], middle.clone(), None, PageSize::new(1).unwrap()).unwrap()],
        100,
    )
    .unwrap();
    p.build(&wrong, &cp(&middle, "cached")).await.unwrap();
    let held = p.open_view(&middle).await.unwrap();
    let change = changes(&b, &a, &middle).await.remove(0);
    assert!(p.apply(&change, &cp(&middle, "live")).await.is_err());
    assert!(p.apply(&change, &cp(&middle, "live")).await.is_err());
    assert_eq!(p.checkpoint().await.unwrap(), Some(cp(&a, "live")));
    assert!(held.claim(&ClaimId::new("c1").unwrap()).unwrap().is_none());
    assert!(p
        .open_view(&middle)
        .await
        .unwrap()
        .claim(&ClaimId::new("c1").unwrap())
        .unwrap()
        .is_none());
}
#[tokio::test]
async fn all_lifecycle_examples_preserve_full_claims_exact_history_and_catch_up() {
    let b = backend();
    let origin = b.head().await.unwrap();
    let initial = batch(
        vec![
            candidate("claim-1", "s", "urn:r", "o"),
            candidate("claim-9", "s", "urn:r", "o"),
            candidate("claim-8", "s", "urn:r", "o"),
        ],
        vec![],
        vec![event("retraction-event-7", ResourceKind::LifecycleEvent)],
    );
    let a = b
        .admit(&IdempotencyKey::new("initial").unwrap(), &initial)
        .await
        .unwrap()
        .snapshot()
        .clone();
    let p = MemoryProjection::new(
        origin,
        Iri::new("urn:algorithm").unwrap(),
        ProjectionOptions::default(),
    )
    .unwrap();
    p.build(&export(&b, &a).await, &cp(&a, "live"))
        .await
        .unwrap();
    let held = p.open_view(&a).await.unwrap();
    let mut expected = vec![];
    for (id, rel, reference) in [
        ("claim-2", "ctxql:superseded_by", "claim-9"),
        ("claim-3", "ctxql:retracted_by", "retraction-event-7"),
        ("claim-4", "ctxql:contradicted_by", "claim-8"),
    ] {
        let c = candidate(id, "claim-1", rel, reference);
        let assertion = LifecycleAssertion::new(c.clone()).unwrap();
        assert_eq!(assertion.candidate(), &c);
        assert_eq!(assertion.projection(), c.projection());
        let bytes = assertion
            .projection()
            .canonical_bytes(Limits::default())
            .unwrap();
        assert_eq!(
            LifecycleAssertion::from_value(&V::parse(&bytes, Limits::default()).unwrap()).unwrap(),
            assertion
        );
        match assertion.reference() {
            LifecycleReference::Claim(r) => assert_eq!(r.as_str(), reference),
            LifecycleReference::Event(r) => {
                assert_eq!(rel, "ctxql:retracted_by");
                assert_eq!(r.as_str(), reference);
            }
        }
        let payload = batch(vec![], vec![assertion.clone()], vec![]);
        let receipt = b
            .admit(&IdempotencyKey::new(id).unwrap(), &payload)
            .await
            .unwrap();
        assert_eq!(receipt.claim_ids(), &[ClaimId::new(id).unwrap()]);
        expected.push((assertion, receipt));
    }
    let end = b.head().await.unwrap();
    let history = changes(&b, &a, &end).await;
    assert_eq!(history.len(), 3);
    for (change, (assertion, receipt)) in history.iter().zip(&expected) {
        assert_eq!(change.result(), receipt.snapshot());
        assert!(change.changes().contains(&RecordChange::LifecycleAdded {
            assertion: assertion.clone(),
            transaction_time: receipt.transaction_time()
        }));
        p.apply(change, &cp(change.result(), "live")).await.unwrap();
        let exact = export(&b, receipt.snapshot()).await;
        let records: Vec<_> = exact
            .records()
            .iter()
            .filter(|r| r.identity_key() == resource_key(assertion.id().as_str()))
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].claim().unwrap(),
            AdmittedClaim::assign(assertion.candidate().clone(), receipt.transaction_time())
        );
    }
    let view = p.open_view(&end).await.unwrap();
    let lifecycle = view
        .lifecycle(
            &ClaimId::new("claim-1").unwrap(),
            PageSize::new(10).unwrap(),
            None,
        )
        .unwrap();
    assert_eq!(lifecycle.items().len(), 3);
    for (assertion, receipt) in expected {
        let admitted =
            AdmittedClaim::assign(assertion.candidate().clone(), receipt.transaction_time());
        assert_eq!(view.claim(assertion.id()).unwrap(), Some(admitted.clone()));
        assert!(view
            .incident(
                &EntityId::new("claim-1").unwrap(),
                Direction::Outgoing,
                PageSize::new(10).unwrap(),
                None
            )
            .unwrap()
            .items()
            .contains(&admitted));
        assert!(held.claim(assertion.id()).unwrap().is_none());
    }
    assert_eq!(
        export(&b, &a)
            .await
            .records()
            .iter()
            .filter(|r| matches!(r, ExportRecord::Lifecycle { .. }))
            .count(),
        0
    );
}
#[tokio::test]
async fn projection_rejects_unresolved_lifecycle_references_on_build_and_apply() {
    let b = backend();
    let a = b
        .admit(
            &IdempotencyKey::new("base").unwrap(),
            &batch(vec![candidate("target", "s", "urn:r", "o")], vec![], vec![]),
        )
        .await
        .unwrap()
        .snapshot()
        .clone();
    let end = b
        .admit(
            &IdempotencyKey::new("next").unwrap(),
            &batch(vec![], vec![], vec![]),
        )
        .await
        .unwrap()
        .snapshot()
        .clone();
    let base = export(&b, &a).await;
    for (rel, reference) in [
        ("ctxql:contradicted_by", "missing-claim"),
        ("ctxql:retracted_by", "missing-event"),
    ] {
        let assertion =
            LifecycleAssertion::new(candidate("assertion", "target", rel, reference)).unwrap();
        let time = Timestamp::from_millis(0).unwrap();
        let change = ChangeBatch::new(
            "ctxql-change/v1",
            a.clone(),
            end.clone(),
            vec![RecordChange::LifecycleAdded {
                assertion: assertion.clone(),
                transaction_time: time,
            }],
            Limits::default(),
        )
        .unwrap();
        let p = MemoryProjection::new(
            a.clone(),
            Iri::new("urn:algorithm").unwrap(),
            ProjectionOptions::default(),
        )
        .unwrap();
        p.build(&base, &cp(&a, "live")).await.unwrap();
        assert!(p.apply(&change, &cp(&end, "live")).await.is_err());
        assert_eq!(p.checkpoint().await.unwrap(), Some(cp(&a, "live")));
        assert!(p.open_view(&end).await.is_err());
        let mut records = base.records().to_vec();
        records.push(ExportRecord::Lifecycle {
            assertion,
            transaction_time: time,
        });
        let invalid = CompleteExport::collect(
            end.clone(),
            ResourceId::new("export").unwrap(),
            vec![Page::new(records, end.clone(), None, PageSize::new(100).unwrap()).unwrap()],
            100,
        )
        .unwrap();
        assert!(p.build(&invalid, &cp(&end, "cache")).await.is_err());
        assert_eq!(p.checkpoint().await.unwrap(), Some(cp(&a, "live")));
    }
}

#[tokio::test]
async fn invalid_claim_and_event_references_and_duplicate_representations_are_atomic() {
    let b = backend();
    b.admit(
        &IdempotencyKey::new("base").unwrap(),
        &batch(
            vec![
                candidate("target", "s", "urn:r", "o"),
                candidate("ordinary", "s", "urn:r", "o"),
            ],
            vec![],
            vec![event("not-event", ResourceKind::Ontology)],
        ),
    )
    .await
    .unwrap();
    let before = b.head().await.unwrap();
    for (rel, reference) in [
        ("ctxql:superseded_by", "absent"),
        ("ctxql:contradicted_by", "not-event"),
        ("ctxql:retracted_by", "ordinary"),
        ("ctxql:retracted_by", "not-event"),
        ("ctxql:retracted_by", "missing-event"),
    ] {
        let assertion =
            LifecycleAssertion::new(candidate("assertion", "target", rel, reference)).unwrap();
        assert!(b
            .admit(
                &IdempotencyKey::new(format!("{rel}-{reference}")).unwrap(),
                &batch(vec![], vec![assertion], vec![])
            )
            .await
            .is_err());
        assert_eq!(b.head().await.unwrap(), before);
    }
    for (id, target, rel, object) in [
        ("a", "a", "ctxql:retracted_by", "event"),
        ("a", "target", "ctxql:contradicted_by", "a"),
        ("a", "target", "ctxql:superseded_by", "target"),
        ("a", "target", "urn:unknown", "event"),
    ] {
        assert!(LifecycleAssertion::new(candidate(id, target, rel, object)).is_err());
    }
    let c = candidate("assertion", "target", "ctxql:retracted_by", "event");
    let l = LifecycleAssertion::new(c.clone()).unwrap();
    assert!(AdmissionBatch::new(
        vec![c.clone()],
        vec![],
        vec![],
        vec![],
        V::object([]).unwrap(),
        Limits::default()
    )
    .is_err());
    assert!(AdmissionBatch::new(
        vec![],
        vec![l.clone(), l],
        vec![],
        vec![],
        V::object([]).unwrap(),
        Limits::default()
    )
    .is_err());
    // Same-batch event is valid and immutable, not the lifecycle assertion's own ID.
    b.admit(
        &IdempotencyKey::new("valid").unwrap(),
        &batch(
            vec![],
            vec![LifecycleAssertion::new(c).unwrap()],
            vec![event("event", ResourceKind::LifecycleEvent)],
        ),
    )
    .await
    .unwrap();
    assert!(ResourceChange::RetractMutable {
        id: ResourceId::new("event").unwrap(),
        kind: ResourceKind::LifecycleEvent,
        previous: ContentHash::of_bytes(b"x")
    }
    .validate()
    .is_err());
}
