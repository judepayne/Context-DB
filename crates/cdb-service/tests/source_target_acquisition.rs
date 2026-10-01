use cdb_core::ErrorKind;
use cdb_service::config::{AcquisitionAccessMode, AcquisitionConfig, AcquisitionWindowConfig};
use cdb_service::source_target::{
    acquire_source_target, acquire_source_target_outcomes, AcquiredDocumentOutcome, MediaKind,
    SourceLocator, SourceTarget,
};
use std::{collections::BTreeMap, fs, path::Path};
use tempfile::TempDir;

fn config(root: &Path, max_folder_entries: usize) -> AcquisitionConfig {
    AcquisitionConfig {
        access_mode: AcquisitionAccessMode::Direct,
        protocol: cdb_service::config::AcquisitionProtocol::LegacyV1,
        assertions: cdb_service::config::AcquisitionAssertionPolicy::Accepted,
        review_graph: None,
        approved_entity_iris: Vec::new(),
        entity_source: None,
        ontology_briefing: None,
        claims_graph: "urn:test:claims".into(),
        principal: "test".into(),
        action: "urn:test:acquire".into(),
        pi_command: root.join("pi"),
        pi_bundle: root.join("bundle"),
        pi_session_log_dir: None,
        extractor_model: "test".into(),
        thinking: "test".into(),
        batch_size: 2,
        max_source_bytes: 4096,
        max_document_bytes: 1024,
        max_folder_entries,
        provider_timeout_seconds: 1,
        projection_timeout_seconds: 1,
        control_journal_bytes: 1024,
        ontology_profile: "test".into(),
        ontology_catalog_root:
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
        ontology_ledger_path: None,
        window: AcquisitionWindowConfig {
            mode: "off".into(),
            target_bytes: 1,
            max_bytes: 1,
            overlap_bytes: 0,
        },
        graph_workspace: None,
        allowed_local_roots: vec![root.to_path_buf()],
        converters: BTreeMap::new(),
        url_adapters: BTreeMap::new(),
    }
}

#[tokio::test]
async fn folder_is_non_recursive_filtered_and_sorted() {
    let temp = TempDir::new().unwrap();
    let folder = temp.path().join("docs");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("z.txt"), b"z").unwrap();
    fs::write(folder.join("a.pdf"), b"a").unwrap();
    fs::write(folder.join("m.md"), b"m").unwrap();
    fs::write(folder.join("ignored.json"), b"ignored").unwrap();

    let documents = acquire_source_target(
        &config(temp.path(), 4),
        temp.path(),
        SourceTarget::LocalFolder("docs".into()),
    )
    .await
    .unwrap();

    let names: Vec<_> = documents
        .iter()
        .map(|document| match &document.locator {
            SourceLocator::Local(path) => path.file_name().unwrap().to_str().unwrap(),
            SourceLocator::Https(_) => panic!("unexpected URL locator"),
        })
        .collect();
    assert_eq!(names, ["a.pdf", "m.md", "z.txt"]);
    assert_eq!(documents[0].media_kind, MediaKind::Pdf);
}

#[tokio::test]
async fn query_credentials_are_rejected_before_adapter_or_provider_use() {
    let temp = TempDir::new().unwrap();
    let error = acquire_source_target(
        &config(temp.path(), 10),
        temp.path(),
        SourceTarget::HttpsUrl("https://example.test/doc.md?token=secret".into()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Invalid);
    assert!(!error.to_string().contains("secret"));
}

#[tokio::test]
async fn local_file_outside_allowed_root_is_denied() {
    let allowed = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let path = outside.path().join("outside.txt");
    fs::write(&path, b"secret").unwrap();

    let error = acquire_source_target(
        &config(allowed.path(), 10),
        allowed.path(),
        SourceTarget::LocalFile(path),
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind, ErrorKind::Denied);
}

#[cfg(unix)]
#[tokio::test]
async fn local_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("real.txt"), b"contents").unwrap();
    symlink(temp.path().join("real.txt"), temp.path().join("link.txt")).unwrap();

    let error = acquire_source_target(
        &config(temp.path(), 10),
        temp.path(),
        SourceTarget::LocalFile("link.txt".into()),
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind, ErrorKind::Invalid);
}

#[cfg(unix)]
#[tokio::test]
async fn local_path_with_symlinked_ancestor_is_rejected() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let real = temp.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("source.md"), b"contents").unwrap();
    symlink(&real, temp.path().join("alias")).unwrap();

    let error = acquire_source_target(
        &config(temp.path(), 10),
        temp.path(),
        SourceTarget::LocalFile("alias/source.md".into()),
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind, ErrorKind::Invalid);
}

#[cfg(unix)]
#[tokio::test]
async fn folder_reports_a_bad_document_without_hiding_good_siblings() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let folder = temp.path().join("docs");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("a.md"), b"good").unwrap();
    symlink(folder.join("a.md"), folder.join("b.md")).unwrap();

    let outcomes = acquire_source_target_outcomes(
        &config(temp.path(), 10),
        temp.path(),
        SourceTarget::LocalFolder("docs".into()),
    )
    .await
    .unwrap();
    assert!(matches!(outcomes[0], AcquiredDocumentOutcome::Acquired(_)));
    assert!(matches!(
        outcomes[1],
        AcquiredDocumentOutcome::Rejected { .. }
    ));
}

#[tokio::test]
async fn folder_entry_limit_counts_all_entries_before_filtering() {
    let temp = TempDir::new().unwrap();
    let folder = temp.path().join("docs");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("one.txt"), b"one").unwrap();
    fs::write(folder.join("ignored.bin"), b"two").unwrap();

    let error = acquire_source_target(
        &config(temp.path(), 1),
        temp.path(),
        SourceTarget::LocalFolder("docs".into()),
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind, ErrorKind::Limit);
}
