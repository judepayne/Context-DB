use cdb_backend_fluree::{AuthorityOptions, FlureeAcquisitionControl, FlureeControlLedger};
use cdb_core::acquisition::{AcquisitionControl, BundlePrepared};
use cdb_core::id::{
    AttemptId, AuthorityId, BackendId, BundleId, ClaimId, ContentHash, GraphId, IdempotencyKey,
    JobId, ResourceId, VersionId,
};
use cdb_core::review::{
    ReviewAdmissionReceipt, ReviewAssertionIntent, ReviewBundlePrepared, ReviewRecord,
    ReviewRecordId, ValidatedReviewBundle, VocabularyVerdict,
};
use cdb_core::semantic_admission::{ProjectionReceipt, SemanticAdmissionReceipt};
use cdb_core::snapshot::{GraphPin, SnapshotRef};
use cdb_core::{CanonicalValue as V, Limits, Timestamp};

fn options(path: std::path::PathBuf) -> AuthorityOptions {
    AuthorityOptions::new(
        path,
        "control:p6".into(),
        BackendId::new("control-backend").unwrap(),
        AuthorityId::new("control-authority").unwrap(),
        GraphId::new("control-graph").unwrap(),
    )
}

#[tokio::test]
async fn admission_receipt_survives_control_repository_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let control_path = dir.path().join("control");
    let control = FlureeControlLedger::create(options(control_path.clone()))
        .await
        .unwrap();
    let repository = FlureeAcquisitionControl::open(&control, 1024 * 1024).unwrap();
    let bundle = BundleId::new("bundle").unwrap();
    let snapshot = SnapshotRef::new(
        BackendId::new("semantic-backend").unwrap(),
        GraphPin::new(
            AuthorityId::new("semantic-authority").unwrap(),
            GraphId::new("semantic-graph").unwrap(),
            VersionId::new("2").unwrap(),
            ResourceId::new("cid").unwrap(),
        ),
    );
    let hash = |value| ContentHash::of_bytes(value);
    let prepared = BundlePrepared {
        job_id: JobId::new("job").unwrap(),
        attempt_id: AttemptId::new("attempt").unwrap(),
        bundle_id: bundle.clone(),
        admission_key: "p6:key".into(),
        descriptor_root: hash(b"descriptor"),
        payload_root: hash(b"payload"),
        canonical_claim_root: hash(b"decoded"),
        expected_claim_ids: vec![ClaimId::new("urn:claim:one").unwrap()],
        validation_capture: snapshot.clone(),
        source_selector_root: hash(b"selectors"),
        safe_counts: V::object([("claims".into(), V::integer(1))]).unwrap(),
        recorded_at: Timestamp::parse("2026-09-22T00:00:00.000Z").unwrap(),
    };
    repository.append_prepared(&prepared).await.unwrap();
    assert_eq!(
        repository.prepared_records().await.unwrap(),
        vec![prepared.clone()]
    );
    let review_bundle = ValidatedReviewBundle::new(
        BundleId::new("review-bundle").unwrap(),
        "evaluation",
        "logical-review",
        AttemptId::new("review-attempt").unwrap(),
        snapshot.clone(),
        vec![ReviewRecord::new(
            ReviewRecordId::new("urn:review:control").unwrap(),
            "component",
            "source",
            hash(b"artifact"),
            VocabularyVerdict::Rejected,
            ReviewAssertionIntent::None,
            vec!["unknown_predicate".into()],
            vec!["model predicate".into()],
            vec![],
            vec![],
            vec![],
            vec![],
        )
        .unwrap()],
        Limits::default(),
    )
    .unwrap();
    let review_prepared = ReviewBundlePrepared::new(
        JobId::new("review-job").unwrap(),
        &review_bundle,
        Timestamp::parse("2026-09-22T00:00:00.000Z").unwrap(),
    );
    repository
        .append_review_prepared(&review_prepared)
        .await
        .unwrap();
    repository
        .append_review_prepared(&review_prepared)
        .await
        .unwrap();
    assert_eq!(
        repository.review_prepared_records().await.unwrap(),
        vec![review_prepared.clone()]
    );
    let review_receipt = ReviewAdmissionReceipt::new(
        review_bundle.admission_key().clone(),
        review_bundle.descriptor_root().clone(),
        review_bundle.payload_root().clone(),
        review_bundle.canonical_review_root().clone(),
        hash(b"review stored"),
        snapshot.clone(),
        Timestamp::parse("2026-09-22T00:00:00.000Z").unwrap(),
        review_bundle.expected_review_ids(),
    )
    .unwrap();
    repository
        .append_review_admission(review_bundle.id(), &review_receipt)
        .await
        .unwrap();
    let receipt = SemanticAdmissionReceipt::new(
        IdempotencyKey::new("p6:key").unwrap(),
        hash(b"descriptor"),
        hash(b"payload"),
        hash(b"decoded"),
        hash(b"stored"),
        snapshot,
        Timestamp::parse("2026-09-22T00:00:00.000Z").unwrap(),
        vec![ClaimId::new("urn:claim:one").unwrap()],
    )
    .unwrap();
    repository
        .append_admission(&bundle, &receipt)
        .await
        .unwrap();
    let projection = ProjectionReceipt::new(
        IdempotencyKey::new("p6:key").unwrap(),
        receipt.snapshot().clone(),
        receipt.snapshot().clone(),
    )
    .unwrap();
    repository
        .append_projection(&bundle, &projection)
        .await
        .unwrap();
    let journal = control_path.join("p6-acquisition-control-v1.jsonl");
    let length = std::fs::metadata(&journal).unwrap().len();
    repository
        .append_projection(&bundle, &projection)
        .await
        .unwrap();
    assert_eq!(std::fs::metadata(&journal).unwrap().len(), length);
    drop(repository);

    let reopened = FlureeAcquisitionControl::open(&control, 1024 * 1024).unwrap();
    assert_eq!(
        reopened.prepared(&bundle).await.unwrap(),
        Some(prepared.clone())
    );
    assert_eq!(reopened.admission(&bundle).await.unwrap(), Some(receipt));
    assert_eq!(
        reopened.review_prepared(review_bundle.id()).await.unwrap(),
        Some(review_prepared.clone())
    );
    assert_eq!(
        reopened.review_prepared_records().await.unwrap(),
        vec![review_prepared]
    );
    assert_eq!(
        reopened.review_admission(review_bundle.id()).await.unwrap(),
        Some(review_receipt)
    );
    assert_eq!(reopened.prepared_records().await.unwrap(), vec![prepared]);
    reopened
        .append_projection(&bundle, &projection)
        .await
        .unwrap();
    assert_eq!(std::fs::metadata(&journal).unwrap().len(), length);
    let conflict = ProjectionReceipt::new(
        IdempotencyKey::new("p6:foreign").unwrap(),
        projection.projected().clone(),
        projection.projected().clone(),
    )
    .unwrap();
    assert!(reopened
        .append_projection(&bundle, &conflict)
        .await
        .is_err());
}
