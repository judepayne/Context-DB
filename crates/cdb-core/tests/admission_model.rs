mod common;
use cdb_core::{admission::*, claim::*, id::*, snapshot::*, Limits, Timestamp};
use common::*;
use std::collections::BTreeSet;
fn lifecycle(id: &str, target: &str, event: &str) -> cdb_core::Result<LifecycleAssertion> {
    use cdb_core::CanonicalValue as V;
    let mut v = candidate(id).projection().as_object().unwrap().clone();
    v.insert("subject_id".into(), V::string(target));
    v.insert("object_id".into(), V::string(event));
    v.insert("relation".into(), V::string("ctxql:retracted_by"));
    LifecycleAssertion::from_value(&V::Object(v))
}
fn batch(ids: &[&str], limits: Limits) -> cdb_core::Result<AdmissionBatch> {
    AdmissionBatch::new(
        ids.iter().map(|i| candidate(i)).collect(),
        vec![],
        vec![],
        vec![],
        json("{}"),
        limits,
    )
}
#[test]
fn independent_claim_identity_and_ordered_payload() {
    let a = batch(&["a", "b"], Limits::default()).unwrap();
    let b = batch(&["b", "a"], Limits::default()).unwrap();
    assert_ne!(a.digest(), b.digest());
    assert!(batch(&["a", "a"], Limits::default()).is_err());
    a.validate_claim_references(&BTreeSet::new()).unwrap();
    assert!(a
        .validate_claim_references(&BTreeSet::from([ClaimId::new("a").unwrap()]))
        .is_err());
    assert!(batch(&["a"], Limits::new(1000, 64, 100, 10000, 1).unwrap()).is_err());
    assert_eq!(
        a.digest(),
        batch(
            &["a", "b"],
            Limits::new(100000, 64, 10000, 100000, 100000).unwrap()
        )
        .unwrap()
        .digest()
    );
}
#[test]
fn normalized_origin_and_lifecycle_reference_validation() {
    let a = AdmissionBatch::new(
        vec![],
        vec![],
        vec![],
        vec![],
        json("{\"a\":1,\"b\":2}"),
        Limits::default(),
    )
    .unwrap();
    let b = AdmissionBatch::new(
        vec![],
        vec![],
        vec![],
        vec![],
        json("{\"b\":2.0,\"a\":1}"),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(a.digest(), b.digest());
    let l = lifecycle("assertion", "target", "event").unwrap();
    let b = AdmissionBatch::new(
        vec![],
        vec![l],
        vec![],
        vec![],
        json("{}"),
        Limits::default(),
    )
    .unwrap();
    assert!(b.validate_claim_references(&BTreeSet::new()).is_err());
    b.validate_claim_references(&BTreeSet::from([ClaimId::new("target").unwrap()]))
        .unwrap();
    assert!(lifecycle("a", "a", "event").is_err());
}
#[test]
fn complete_snapshot_identity_and_metadata_changes() {
    let a = pin("a");
    let b = pin("b");
    assert_ne!(a, b);
    assert_eq!(a.projection().as_object().unwrap().len(), 4);
    let batch = ChangeBatch::new(
        "ctxql-change/v1",
        a.clone(),
        b.clone(),
        vec![],
        Limits::default(),
    )
    .unwrap();
    assert!(batch.changes().is_empty());
    let cp = ProjectionCheckpoint::new(
        b.clone(),
        VersionId::new("ctxql-projection/v1").unwrap(),
        VersionId::new("generation1").unwrap(),
        Iri::new("ctxql:projection/v1").unwrap(),
    )
    .unwrap();
    assert_eq!(cp.snapshot(), &b);
    assert!(ChangeBatch::new("bad", a, b, vec![], Limits::default()).is_err());
}
#[test]
fn page_completion_and_cursor_reuse_fail() {
    let snap = pin("a");
    let stream = ResourceId::new("export").unwrap();
    let c = PageCursor::new(snap.clone(), stream.clone(), VersionId::new("one").unwrap());
    let size = PageSize::new(1).unwrap();
    let first = Page::new(vec![1], snap.clone(), Some(c.clone()), size).unwrap();
    let mut t = PageTracker::new(snap.clone(), stream.clone(), 5);
    t.accept(None, &first).unwrap();
    assert!(t.accept(Some(&c), &first).is_err());
    assert!(PageTracker::new(snap.clone(), stream.clone(), 5)
        .finish()
        .is_err());
    let mut t = PageTracker::new(snap.clone(), stream, 0);
    assert!(t.accept(None, &first).is_err());
    let end = Page::<u8>::new(vec![], snap, None, size).unwrap();
    t.accept(None, &end).unwrap();
    assert_eq!(t.finish().unwrap(), 0);
}
#[test]
fn receipt_time_is_not_source_time() {
    let b = batch(&["c"], Limits::default()).unwrap();
    let r = AdmissionReceipt::new(
        IdempotencyKey::new("key").unwrap(),
        b.digest().clone(),
        pin("a"),
        Timestamp::from_millis(-1).unwrap(),
        vec![ClaimId::new("c").unwrap()],
    )
    .unwrap();
    assert_eq!(r.payload(), b.digest());
    assert_eq!(r.transaction_time().millis(), -1);
}
