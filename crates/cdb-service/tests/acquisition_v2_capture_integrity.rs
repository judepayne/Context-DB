#[path = "support/wal_cleanup.rs"]
mod wal_cleanup;

use cdb_provider_pi::cancel::CancellationToken;
use cdb_service::{
    acquisition_v2_fixture::AcquisitionV2Fixture,
    ingest::{ingest, IngestMode, OntologyMode},
    source_target::SourceTarget,
};
use std::{collections::BTreeMap, fs, path::Path};

fn store_bytes(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn visit(root: &Path, path: &Path, output: &mut BTreeMap<String, Vec<u8>>) {
        if !path.exists() {
            return;
        }
        if path.is_dir() {
            output.insert(
                format!("{}/", path.strip_prefix(root).unwrap().to_string_lossy()),
                Vec::new(),
            );
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), output);
            }
        } else {
            output.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                cdb_core::id::ContentHash::of_bytes(&fs::read(path).unwrap())
                    .as_str()
                    .as_bytes()
                    .to_vec(),
            );
        }
    }
    let mut output = BTreeMap::new();
    for name in ["semantic", "control", "projection", "sources"] {
        visit(root, &root.join(name), &mut output);
    }
    output
}

#[test]
fn capture_integrity_and_no_write_extract_only() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "capture_integrity_child",
            "--test-threads=1",
        ])
        .env("OPENROUTER_API_KEY", "fake-only")
        .env("RUST_MIN_STACK", "33554432")
        .status()
        .unwrap();
    assert!(status.success());
}

#[tokio::test]
#[ignore = "executed by isolated child wrapper with fake credentials"]
async fn capture_integrity_child() {
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let document = fixture
        .write_document(
            "capture.txt",
            "Orion borrows £1000.\r\nNo additional claims.\n".as_bytes(),
        )
        .unwrap();
    let export = tempfile::tempdir().unwrap();
    let manifest = export.path().join("capture.json");
    // Bootstrap clients drain their WALs asynchronously on drop. Finish that
    // setup lifecycle before measuring the extract-only operation itself.
    wal_cleanup::wait_for_wal_cleanup(fixture.root(), std::time::Duration::from_secs(5)).await;
    let before = store_bytes(fixture.root());
    let report = ingest(
        fixture.config().unwrap(),
        SourceTarget::LocalFile(document.clone()),
        IngestMode::ExtractOnly,
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        Some(manifest.to_str().unwrap().to_owned()),
        CancellationToken::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        store_bytes(fixture.root()),
        before,
        "extract-only mutated durable stores"
    );
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["admitted_claim_count"], 0);
    let checker =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/check_acquisition_capture_v2.py");
    let checked = std::process::Command::new("python3")
        .arg(&checker)
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let retained: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let request: serde_json::Value =
        serde_json::from_str(retained["request"].as_str().unwrap()).unwrap();
    assert_eq!(request["response_protocol"], "ctxql-extraction-text/v1");
    assert_eq!(retained["response"], "NO_CLAIMS");
    for (mode, evidence_only) in [(OntologyMode::Soft, false), (OntologyMode::Hard, true)] {
        let mut config = fixture.config().unwrap();
        if evidence_only {
            config.acquisition.as_mut().unwrap().assertions =
                cdb_service::config::AcquisitionAssertionPolicy::EvidenceOnly;
        }
        ingest(
            config,
            SourceTarget::LocalFile(document.clone()),
            IngestMode::ExtractOnly,
            mode,
            2 * 1024 * 1024,
            None,
            Some(manifest.to_str().unwrap().to_owned()),
            None,
            CancellationToken::default(),
        )
        .await
        .expect("same capture must preserve coordinates across evaluation modes");
    }
    assert_eq!(
        fixture.pi_invocations().unwrap(),
        1,
        "mode comparison invoked provider"
    );
    let mut capture: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    capture["source_text"] = serde_json::json!("tampered source");
    let corrupt = export.path().join("corrupt.json");
    fs::write(&corrupt, serde_json::to_vec(&capture).unwrap()).unwrap();
    assert!(!std::process::Command::new("python3")
        .arg(&checker)
        .arg(corrupt)
        .output()
        .unwrap()
        .status
        .success());
    fixture.set_pi_response("not valid JSON").unwrap();
    let failed = ingest(
        fixture.config().unwrap(),
        SourceTarget::LocalFile(document),
        IngestMode::ExtractOnly,
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        None,
        CancellationToken::default(),
    )
    .await;
    let failed = serde_json::to_value(
        failed.expect("protocol failure should remain bounded diagnostic output"),
    )
    .unwrap();
    assert!(!failed["documents"][0]["errors"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(failed["admitted_claim_count"], 0);
    assert_eq!(
        store_bytes(fixture.root()),
        before,
        "failure path mutated durable stores"
    );
}
