use cdb_core::{
    id::{
        AttemptId, AuthorityId, BackendId, BundleId, ContentHash, GraphId, JobId, ResourceId,
        VersionId,
    },
    review::{
        ReviewAdmissionReceipt, ReviewAssertionIntent, ReviewBundlePrepared, ReviewRecord,
        ReviewRecordId, ValidatedReviewBundle, VocabularyVerdict,
    },
    snapshot::{GraphPin, SnapshotRef},
    CanonicalValue, Limits, Timestamp,
};

fn capture() -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new("fluree:4.2.1").unwrap(),
        GraphPin::new(
            AuthorityId::new("authority").unwrap(),
            GraphId::new("urn:graph:semantic").unwrap(),
            VersionId::new("7").unwrap(),
            ResourceId::new("cid:seven").unwrap(),
        ),
    )
}

fn record() -> ReviewRecord {
    ReviewRecord::new(
        ReviewRecordId::new("urn:review:a2").unwrap(),
        "passage-1/attribute/a2",
        "source:document-06",
        ContentHash::of_bytes(b"outcome page"),
        VocabularyVerdict::Rejected,
        ReviewAssertionIntent::None,
        vec!["unknown_predicate".into()],
        vec!["urn:test:acq:agreementDate".into()],
        vec!["urn:test:acq:SuggestedClass".into()],
        vec![],
        vec![],
        vec![],
    )
    .unwrap()
}

#[test]
fn review_contracts_are_closed_canonical_roundtrips() {
    let limits = Limits::default();
    let record = record();
    assert_eq!(
        ReviewRecord::from_value(&record.projection()).unwrap(),
        record
    );

    let bundle = ValidatedReviewBundle::new(
        BundleId::new("review-bundle-1").unwrap(),
        "evaluation-1",
        "passage-1-review",
        AttemptId::new("attempt-1").unwrap(),
        capture(),
        vec![record.clone()],
        limits,
    )
    .unwrap();
    assert_eq!(
        ValidatedReviewBundle::from_value(&bundle.projection(), limits).unwrap(),
        bundle
    );

    let prepared = ReviewBundlePrepared::new(
        JobId::new("job-1").unwrap(),
        &bundle,
        Timestamp::parse("2026-09-21T12:00:00.000Z").unwrap(),
    );
    assert_eq!(
        ReviewBundlePrepared::from_value(&prepared.projection()).unwrap(),
        prepared
    );
    prepared.verify_bundle(&bundle).unwrap();

    let receipt = ReviewAdmissionReceipt::new(
        bundle.admission_key().clone(),
        bundle.descriptor_root().clone(),
        bundle.payload_root().clone(),
        bundle.canonical_review_root().clone(),
        ContentHash::of_bytes(b"stored review projection"),
        capture(),
        Timestamp::parse("2026-09-21T12:01:00.000Z").unwrap(),
        bundle.expected_review_ids(),
    )
    .unwrap();
    assert_eq!(
        ReviewAdmissionReceipt::from_value(&receipt.projection()).unwrap(),
        receipt
    );
    receipt.verify_prepared(&prepared).unwrap();

    let mut foreign = prepared.clone();
    foreign.payload_root = ContentHash::of_bytes(b"foreign payload");
    assert!(foreign.verify_bundle(&bundle).is_err());
    assert!(receipt.verify_prepared(&foreign).is_err());

    let mut open = record.projection().as_object().unwrap().clone();
    open.insert("unexpected".into(), CanonicalValue::Bool(true));
    assert!(ReviewRecord::from_value(&CanonicalValue::Object(open)).is_err());
}

#[test]
fn review_identity_and_nonempty_invariants_fail_closed() {
    assert!(ReviewRecordId::new("").is_err());
    assert!(ValidatedReviewBundle::new(
        BundleId::new("review-bundle-empty").unwrap(),
        "evaluation-1",
        "empty",
        AttemptId::new("attempt-1").unwrap(),
        capture(),
        vec![],
        Limits::default(),
    )
    .is_err());
    assert!(ReviewAdmissionReceipt::new(
        cdb_core::id::IdempotencyKey::new("review:key").unwrap(),
        ContentHash::of_bytes(b"descriptor"),
        ContentHash::of_bytes(b"payload"),
        ContentHash::of_bytes(b"decoded"),
        ContentHash::of_bytes(b"stored"),
        capture(),
        Timestamp::parse("2026-09-21T12:01:00.000Z").unwrap(),
        vec![],
    )
    .is_err());
}
