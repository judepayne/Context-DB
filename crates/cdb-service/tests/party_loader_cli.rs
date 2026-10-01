//! Exercise the native party fixture loader with the pinned seed, not mocks.
use cdb_service::acquisition_v2_fixture::AcquisitionV2Fixture;
use std::path::{Path, PathBuf};

#[tokio::test]
#[ignore = "requires explicitly built fixture helper and CDB_PARTY_BACKGROUND_ONTOLOGY"]
async fn native_party_loader_admits_and_recovers_without_a_model() {
    let helper = std::env::var_os("CDB_PARTY_FIXTURE_BIN")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .unwrap_or_else(|| {
            panic!(
                "CDB_PARTY_FIXTURE_BIN must name an executable built with: cargo build --locked -p cdb-service --example load_party_fixture"
            )
        });
    let ontology =
        std::env::var("CDB_PARTY_BACKGROUND_ONTOLOGY").expect("CDB_PARTY_BACKGROUND_ONTOLOGY");
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let config = std::fs::read_to_string(fixture.config_path()).unwrap();
    assert_eq!(config.matches("control-journal-bytes = 1048576").count(), 1);
    let config = config
        .replace(
            "[limits]\n",
            "[limits]\nmax_body_bytes = 16777216\nrun_bytes = 16777216\n",
        )
        .replace("deadline_seconds = 30", "deadline_seconds = 300")
        .replace(
            "projection-timeout-seconds = 10",
            "projection-timeout-seconds = 300",
        )
        .replace(
            "control-journal-bytes = 1048576",
            "control-journal-bytes = 67108864",
        )
        .replace(
            "[acquisition]\n",
            &format!(
                "[acquisition]\nontology-ledger-path = {}\n",
                serde_json::to_string(&ontology).unwrap()
            ),
        );
    // Only the explicitly disposable fixture configuration is changed.
    std::fs::write(fixture.config_path(), config).unwrap();
    fixture
        .config()
        .expect("configuration must pass the real file loader");

    let config_path = fixture.config_path().to_owned();
    let token_path = fixture.root().join("owner.secret");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let request_path = root
        .join("fixtures/quickstart/party-background/seed.json")
        .canonicalize()
        .unwrap();
    let receipts = tokio::task::spawn_blocking(move || {
        (0..2)
            .map(|_| {
                let result = std::process::Command::new(&helper)
                    .arg("--config")
                    .arg(&config_path)
                    .arg("--token-file")
                    .arg(&token_path)
                    .arg("--request-file")
                    .arg(&request_path)
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    assert_eq!(
        receipts[0], receipts[1],
        "CLI restart duplicated or changed admission"
    );
    assert_eq!(receipts[0]["status"], "admitted");
    assert_eq!(receipts[0]["entity_count"], 186);
    assert_eq!(receipts[0]["claim_count"], 496);
    let projections = receipts[0]["projections"].as_array().unwrap();
    assert!(projections.last().unwrap().is_object());
    assert_eq!(fixture.pi_invocations().unwrap(), 0);
}
