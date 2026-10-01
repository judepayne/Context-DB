use cdb_backend_fluree::options::AuthorityOptions;
use cdb_backend_fluree::{FlureeControlLedger, FlureeSemanticLedger, SemanticLedgerOptions};
use cdb_core::{
    id::{AuthorityId, BackendId, GraphId, ResourceId, VersionId},
    snapshot::{GraphPin, SnapshotRef},
};
use fluree_db_api::{FlureeBuilder, LedgerState, Novelty};
use fluree_db_core::LedgerSnapshot;
use serde_json::json;
use std::sync::Arc;

fn semantic_options(ledger: &str) -> SemanticLedgerOptions {
    SemanticLedgerOptions {
        backend: BackendId::new("fluree:semantic-reader").unwrap(),
        authority: AuthorityId::new("fluree:shared-semantic").unwrap(),
        ledger: GraphId::new(ledger).unwrap(),
    }
}

#[tokio::test]
async fn semantic_reader_captures_without_advancing_the_source() {
    let fluree = Arc::new(FlureeBuilder::memory().build_memory());
    let ledger_id = "semantic:main";
    let genesis = LedgerState::new(LedgerSnapshot::genesis(ledger_id), Novelty::new(0));
    let state = fluree
        .stage_owned(genesis)
        .upsert_turtle("<urn:s> <urn:p> <urn:o> .")
        .execute()
        .await
        .unwrap()
        .ledger;
    let before_t = state.t();
    let before_cid = state.head_commit_id.clone();

    let reader = FlureeSemanticLedger::open(Arc::clone(&fluree), semantic_options(ledger_id))
        .await
        .unwrap();
    let capture = reader.capture_current(None).await.unwrap();
    reader.verify_unchanged(&capture).await.unwrap();
    let after = fluree.ledger(ledger_id).await.unwrap();

    assert_eq!(after.t(), before_t);
    assert_eq!(after.head_commit_id, before_cid);
    assert_eq!(capture.t(), u64::try_from(before_t).unwrap());
    assert_eq!(capture.ledger().as_str(), ledger_id);
}

#[tokio::test]
async fn file_reader_is_structurally_read_only_and_proves_exact_history() {
    let dir = tempfile::tempdir().unwrap();
    let ledger_id = "semantic-history:main";
    let expected_cid = {
        let writer = FlureeBuilder::file(dir.path().to_string_lossy().into_owned())
            .without_indexing()
            .build()
            .unwrap();
        let ledger = writer.create_ledger(ledger_id).await.unwrap();
        let committed = writer
            .insert(
                ledger,
                &json!({
                    "@context": {"ex": "http://example.org/"},
                    "@id": "ex:subject",
                    "ex:predicate": {"@id": "ex:object"}
                }),
            )
            .await
            .unwrap()
            .ledger;
        committed.head_commit_id.unwrap().to_string()
    };

    let reader = FlureeSemanticLedger::open_file(dir.path(), semantic_options(ledger_id))
        .await
        .unwrap();
    let before = reader.capture_current(None).await.unwrap();
    let expected = ResourceId::new(expected_cid).unwrap();
    let historical = reader.capture_at_t(1, Some(&expected), None).await.unwrap();
    assert_eq!(historical.t(), 1);
    assert_eq!(historical.commit_cid(), &expected);
    reader.verify_capture_available(&historical).await.unwrap();
    reader.verify_unchanged(&before).await.unwrap();
    let projected = reader
        .capture_projection_snapshot(historical.snapshot())
        .await
        .unwrap();
    assert_eq!(&projected.snapshot, historical.snapshot());

    let wrong =
        ResourceId::new("bafkreigh2akiscaildc5hlyr3l4m2zue5vifm6wl5pquhxtwlq5s4h4yhy").unwrap();
    let error = reader
        .capture_at_t(1, Some(&wrong), None)
        .await
        .unwrap_err();
    assert_eq!(error.kind, cdb_core::ErrorKind::Snapshot);
    assert_eq!(error.message, "semantic_snapshot_divergence");

    let wrong_pin = SnapshotRef::new(
        semantic_options(ledger_id).backend,
        GraphPin::new(
            semantic_options(ledger_id).authority,
            GraphId::new(ledger_id).unwrap(),
            VersionId::new("1").unwrap(),
            wrong,
        ),
    );
    let error = reader
        .capture_projection_snapshot(&wrong_pin)
        .await
        .unwrap_err();
    assert_eq!(error.kind, cdb_core::ErrorKind::Snapshot);
    assert_eq!(error.message, "semantic_snapshot_divergence");
}

#[tokio::test]
async fn control_wrapper_rejects_semantic_ledger_alias() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = "control:main";
    let options = AuthorityOptions::new(
        dir.path().join("control"),
        ledger.into(),
        BackendId::new("fluree:control").unwrap(),
        AuthorityId::new("control:authority").unwrap(),
        GraphId::new("control:graph").unwrap(),
    );
    let control = FlureeControlLedger::create(options).await.unwrap();
    assert!(control
        .reject_semantic_alias(&GraphId::new(ledger).unwrap())
        .is_err());
    control
        .reject_semantic_alias(&GraphId::new("semantic:main").unwrap())
        .unwrap();
}
