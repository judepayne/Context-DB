mod common;
use cdb_core::{evidence::*, id::*, replay::*, source::*, CanonicalValue as V, Limits};
use common::*;
#[test]
fn graph_evidence_product_outcomes_stay_independent() {
    let report = ReplayReport {
        graph: ReplayVerdict::Reproduced,
        evidence: vec![EvidenceVerification {
            source_id: SourceId::new("s").unwrap(),
            version: None,
            fragment_id: None,
            outcome: VerificationOutcome::Missing,
        }],
        product: ProductOutcome::Failed,
    };
    assert_eq!(report.graph, ReplayVerdict::Reproduced);
    assert_eq!(
        ReplayVerdict::aggregate([ReplayVerdict::Reproduced, ReplayVerdict::NotReplayable])
            .unwrap(),
        ReplayVerdict::NotReplayable
    );
    assert_eq!(
        ReplayVerdict::aggregate([ReplayVerdict::ReproducedBestEffort, ReplayVerdict::Diverged])
            .unwrap(),
        ReplayVerdict::Diverged
    );
}
#[test]
fn external_identity_row_keys_and_path_rejection() {
    let identity = fixture("structured-claim")
        .field("payload")
        .unwrap()
        .clone();
    let s = ExternalSnapshot::from_value(identity.field("snapshot").unwrap()).unwrap();
    assert_eq!(s.projection(), *identity.field("snapshot").unwrap());
    let key = RowKey::from_value(identity.field("row_key").unwrap()).unwrap();
    assert_eq!(key.projection(), *identity.field("row_key").unwrap());
    let mut bad = s.projection();
    set(
        &mut bad,
        "files",
        json(
            r#"[{"path":"../escape","hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1}]"#,
        ),
    );
    assert!(ExternalSnapshot::from_value(&bad).is_err());
    assert!(RowKey::from_value(&V::Array(vec![V::Null])).is_err());
}
#[test]
fn footprint_is_data_and_requested_not_widened() {
    let used = vec![ReadDependency::SourceSelector {
        descriptor: ResourceId::new("span").unwrap(),
        source: SourceId::new("source").unwrap(),
        version: ContentHash::of_bytes(b"text"),
    }];
    let f = ReadFootprint::new("ctxql-read-footprint/v1", pin("a"), used.clone(), vec![]).unwrap();
    assert!(f.requested_selectors().is_empty());
    assert_eq!(f.used().len(), 1);
    assert!(ReadFootprint::new(
        "ctxql-read-footprint/v1",
        pin("a"),
        used,
        vec![ResourceId::new("whole").unwrap()]
    )
    .is_err());
}
#[test]
fn source_limits_and_extraction_atomic_validation() {
    assert!(SourceRead::new(
        SourceId::new("s").unwrap(),
        ContentHash::of_bytes(b"ab"),
        b"ab".to_vec(),
        1
    )
    .is_err());
    assert!(ExtractionResult::new(vec![candidate("a"), candidate("a")], json("{}"), 10).is_err());
    assert!(ExtractionResult::new(vec![candidate("a")], json("{}"), 0).is_err());
    let _ = Limits::default();
}
