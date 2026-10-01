use cdb_core::{
    contracts::{
        CapturedSnapshot, ExecutionCaptures, GraphBackend, GraphBackendProjectionSource,
        PreparedOntologyDescriptor, SemanticProjectionCapabilities, SemanticProjectionSource,
    },
    id::{AuthorityId, BackendId, ContentHash, GraphId, Iri, ResourceId, VersionId},
    snapshot::{GraphPin, HistoryAvailabilityEvidence, SemanticCapture, SnapshotRef},
    Timestamp,
};
use std::sync::Arc;

fn snapshot(revision: &str, receipt: &str) -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new("fluree-semantic").unwrap(),
        GraphPin::new(
            AuthorityId::new("fluree:tenant").unwrap(),
            GraphId::new("ledger:knowledge").unwrap(),
            VersionId::new(revision).unwrap(),
            ResourceId::new(receipt).unwrap(),
        ),
    )
}

#[test]
fn semantic_capture_has_one_canonical_snapshot_mapping() {
    let requested = Timestamp::parse("2026-09-16T12:00:00.000Z").unwrap();
    let capture = SemanticCapture::new(
        Some(requested),
        BackendId::new("fluree-semantic").unwrap(),
        AuthorityId::new("fluree:tenant").unwrap(),
        GraphId::new("ledger:knowledge").unwrap(),
        42,
        ResourceId::new("bafy-full-capture-cid").unwrap(),
        42,
        ResourceId::new("bafy-full-capture-cid").unwrap(),
    )
    .unwrap();

    assert_eq!(capture.requested_as_of(), Some(requested));
    assert_eq!(capture.ledger().as_str(), "ledger:knowledge");
    assert_eq!(capture.t(), 42);
    assert_eq!(capture.commit_cid().as_str(), "bafy-full-capture-cid");
    assert_eq!(capture.snapshot().pin().revision().as_str(), "42");
    assert_eq!(capture.snapshot().pin().receipt(), capture.commit_cid());
    assert_eq!(capture.history_availability().exact_t(), 42);
    assert_eq!(
        capture.history_availability().exact_commit_cid().as_str(),
        "bafy-full-capture-cid"
    );
    assert_eq!(
        capture
            .history_availability()
            .exact_capture()
            .pin()
            .revision(),
        &VersionId::new("42").unwrap()
    );
}

#[test]
fn execution_captures_keep_semantic_and_control_identities_distinct() {
    let semantic = CapturedSnapshot {
        as_of: Timestamp::parse("2026-09-16T12:00:00.000Z").unwrap(),
        snapshot: snapshot("42", "semantic-cid"),
    };
    let control = SnapshotRef::new(
        BackendId::new("fluree-control").unwrap(),
        GraphPin::new(
            AuthorityId::new("fluree:control").unwrap(),
            GraphId::new("ledger:control").unwrap(),
            VersionId::new("9").unwrap(),
            ResourceId::new("control-cid").unwrap(),
        ),
    );
    let captures = ExecutionCaptures::new(semantic.clone(), control.clone());
    assert_eq!(captures.semantic(), &semantic);
    assert_eq!(captures.control(), &control);
    assert_ne!(captures.semantic().snapshot, *captures.control());

    let legacy = ExecutionCaptures::legacy(semantic.clone());
    assert_eq!(legacy.semantic(), &semantic);
    assert_eq!(legacy.control(), &semantic.snapshot);
}

#[test]
fn semantic_capture_rejects_noncanonical_or_foreign_availability_proofs() {
    let noncanonical = snapshot("042", "capture-cid");
    let available = HistoryAvailabilityEvidence::new(snapshot("7", "history-cid")).unwrap();
    assert!(SemanticCapture::from_snapshot(None, noncanonical, available).is_err());

    let capture = snapshot("42", "capture-cid");
    let different_exact_point =
        HistoryAvailabilityEvidence::new(snapshot("41", "history-cid")).unwrap();
    assert!(SemanticCapture::from_snapshot(None, capture.clone(), different_exact_point).is_err());

    let too_new = HistoryAvailabilityEvidence::new(snapshot("43", "history-cid")).unwrap();
    assert!(SemanticCapture::from_snapshot(None, capture.clone(), too_new).is_err());

    let foreign = SnapshotRef::new(
        BackendId::new("other-backend").unwrap(),
        capture.pin().clone(),
    );
    let foreign_available = HistoryAvailabilityEvidence::new(foreign).unwrap();
    assert!(SemanticCapture::from_snapshot(None, capture, foreign_available).is_err());
}

struct ReadOnlySource;
impl SemanticProjectionSource for ReadOnlySource {
    fn capabilities(&self) -> cdb_core::Result<SemanticProjectionCapabilities> {
        Ok(SemanticProjectionCapabilities {
            exact_snapshots: true,
            ordered_changes: true,
            closed_cutoff: true,
            complete_exports: true,
            schema: VersionId::new("ctxql-semantic-rdf/v1").unwrap(),
            algorithm: Iri::new("urn:ctxql:semantic-projection:v1").unwrap(),
        })
    }
    fn head(&self) -> cdb_core::contracts::IoFuture<'_, SnapshotRef> {
        panic!("type boundary only")
    }
    fn capture(
        &self,
        _: Option<Timestamp>,
    ) -> cdb_core::contracts::IoFuture<'_, cdb_core::contracts::CapturedSnapshot> {
        panic!("type boundary only")
    }
    fn open_snapshot<'a>(
        &'a self,
        _: &'a SnapshotRef,
    ) -> cdb_core::contracts::IoFuture<'a, Arc<dyn cdb_core::contracts::SemanticProjectionSnapshot>>
    {
        panic!("type boundary only")
    }
    fn changes<'a>(
        &'a self,
        _: &'a SnapshotRef,
        _: &'a SnapshotRef,
        _: Option<&'a cdb_core::snapshot::PageCursor>,
        _: cdb_core::snapshot::PageSize,
    ) -> cdb_core::contracts::IoFuture<'a, cdb_core::snapshot::Page<cdb_core::admission::ChangeBatch>>
    {
        panic!("type boundary only")
    }
    fn subscribe(
        &self,
    ) -> cdb_core::contracts::IoFuture<'_, Box<dyn cdb_core::contracts::ChangeHintSource>> {
        panic!("type boundary only")
    }
}

#[allow(dead_code)]
fn legacy_graph_backend_adapter<B: GraphBackend + 'static>(
    backend: Arc<B>,
) -> Arc<dyn SemanticProjectionSource> {
    Arc::new(GraphBackendProjectionSource::new(
        backend,
        VersionId::new("ctxql-projection/v1").unwrap(),
        Iri::new("urn:raw").unwrap(),
    ))
}

#[test]
fn no_sandbox_descriptor_uses_explicit_none_identities() {
    let descriptor = PreparedOntologyDescriptor::no_sandbox(
        snapshot("42", "capture-cid"),
        ContentHash::of_bytes(b"premises"),
        ContentHash::of_bytes(b"manifest"),
        ContentHash::of_bytes(b"completeness"),
    )
    .unwrap();

    assert_eq!(descriptor.ontology_profile.as_str(), "none/v1");
    assert_eq!(descriptor.structural_mapping_algorithm.as_str(), "none/v1");
    assert_eq!(descriptor.materializer.as_str(), "none/v1");
    assert_eq!(descriptor.reasoner.as_str(), "none/v1");
    for root in [
        &descriptor.full_ontology_bundle_root,
        &descriptor.ontology_profile_result_root,
        &descriptor.reasoner_input_root,
        &descriptor.profile_limits_identity,
        &descriptor.materialization_limits_identity,
        &descriptor.reasoning_limits_identity,
        &descriptor.budget_identity,
        &descriptor.prepared_root,
        &descriptor.diagnostics_root,
    ] {
        assert!(root.as_str().starts_with("sha256:"));
    }
}

#[test]
fn semantic_projection_source_is_independently_read_only() {
    fn accepts_source(_: &dyn SemanticProjectionSource) {}

    let source = ReadOnlySource;
    accepts_source(&source);
    let capabilities = source.capabilities().unwrap();
    assert!(capabilities.exact_snapshots);
    assert!(capabilities.ordered_changes);
    assert!(capabilities.closed_cutoff);
    assert!(capabilities.complete_exports);
}
