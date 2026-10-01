use cdb_backend_fluree::{FlureeSemanticLedger, SemanticLedgerOptions};
use cdb_core::id::{AuthorityId, BackendId, GraphId};
use fluree_db_api::FlureeBuilder;
use serde_json::json;

fn options(ledger: &str) -> SemanticLedgerOptions {
    SemanticLedgerOptions {
        backend: BackendId::new("fluree:p6-reader").unwrap(),
        authority: AuthorityId::new("fluree:p6-semantic").unwrap(),
        ledger: GraphId::new(ledger).unwrap(),
    }
}

#[tokio::test]
async fn file_backed_writer_and_read_only_reader_observe_only_committed_heads() {
    let dir = tempfile::tempdir().unwrap();
    let ledger_id = "p6-r2:main";
    let writer = FlureeBuilder::file(dir.path().to_string_lossy().into_owned())
        .without_indexing()
        .build()
        .unwrap();
    let genesis = writer.create_ledger(ledger_id).await.unwrap();
    let first = writer
        .insert(
            genesis,
            &json!({"@id": "urn:p6:s1", "urn:p6:p": {"@id": "urn:p6:o1"}}),
        )
        .await
        .unwrap()
        .ledger;
    assert_eq!(first.t(), 1);

    // Keep the writer alive while opening a structurally read-only nameservice.
    let reader = FlureeSemanticLedger::open_file(dir.path(), options(ledger_id))
        .await
        .unwrap();
    let before = reader.capture_current(None).await.unwrap();
    assert_eq!(before.t(), 1);

    let second = writer
        .insert(
            first,
            &json!({"@id": "urn:p6:s2", "urn:p6:p": {"@id": "urn:p6:o2"}}),
        )
        .await
        .unwrap()
        .ledger;
    assert_eq!(second.t(), 2);

    let after = reader.capture_current(None).await.unwrap();
    assert_eq!(after.t(), 2);
    assert_ne!(before.snapshot(), after.snapshot());
    reader.verify_capture_available(&before).await.unwrap();
    reader.verify_capture_available(&after).await.unwrap();
}
