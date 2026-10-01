use std::process::Command;

#[test]
fn ingestion_help_is_grouped_and_available_without_an_instance() {
    for flag in ["--help", "-h"] {
        let top = Command::new(env!("CARGO_BIN_EXE_cdb"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(top.status.success());
        let text = String::from_utf8(top.stdout).unwrap();
        assert!(text.contains("cdb ingest <start|inspect|artifact|resume|replay>"));
        assert!(!text.contains("acquisition"));
        assert!(!text.contains("seed"));

        let group = Command::new(env!("CARGO_BIN_EXE_cdb"))
            .args(["ingest", flag])
            .output()
            .unwrap();
        assert!(group.status.success());
        for subcommand in ["start", "inspect", "artifact", "resume", "replay"] {
            let help = Command::new(env!("CARGO_BIN_EXE_cdb"))
                .args(["ingest", subcommand, flag])
                .output()
                .unwrap();
            assert!(help.status.success(), "{subcommand} {flag}");
            assert!(help.stderr.is_empty());
            let text = String::from_utf8(help.stdout).unwrap();
            assert!(text.starts_with(&format!("cdb ingest {subcommand} ")));
            assert!(text.contains("--config"));
            if subcommand == "start" {
                for source in ["--file", "--folder", "--url"] {
                    assert!(text.contains(source));
                }
            } else {
                assert!(text.contains("--token-file"));
            }
        }
    }
    assert!(Command::new(env!("CARGO_BIN_EXE_cdb"))
        .arg("ingest")
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn old_command_names_and_seed_are_not_product_commands() {
    for args in [
        vec!["acquisition", "replay", "--help"],
        vec!["acquisition", "seed", "--help"],
        vec!["acquisition-inspect", "--help"],
        vec!["acquisition-artifact", "--help"],
        vec!["acquisition-resume", "--help"],
        vec!["ingest", "seed", "--help"],
        vec!["ingest", "--config", "/tmp/missing-cdb.toml"],
        vec!["ingest", "unknown"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_cdb"))
            .args(&args)
            .output()
            .unwrap();
        assert!(!result.status.success(), "unexpected success: {args:?}");
        assert!(result.stdout.is_empty());
    }
}

#[tokio::test]
async fn ingest_start_accepts_a_file_and_a_non_recursive_folder() {
    use cdb_service::acquisition_v2_fixture::AcquisitionV2Fixture;
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    fixture.set_pi_response("NO_CLAIMS").unwrap();
    let first = fixture
        .write_document("one.md", b"First document.")
        .unwrap();
    fixture
        .write_document("two.txt", b"Second document.")
        .unwrap();
    let folder = first.parent().unwrap().to_path_buf();
    let nested = folder.join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join("excluded.md"), b"Not a top-level document.").unwrap();
    let config = fixture.config_path().to_owned();
    tokio::task::spawn_blocking(move || {
        for (flag, path, count) in [("--file", first, 1), ("--folder", folder, 2)] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_cdb"));
            command
                .args(["ingest", "start"])
                // The fixture launches fake Pi; never depend on a developer's key.
                .env("OPENROUTER_API_KEY", "ctxql-hermetic-fake-provider-key")
                .env("CDB_DEBUG_ERRORS", "1");
            if flag == "--file" {
                command
                    .args(["--config"])
                    .arg(&config)
                    .env("CDB_CONFIG", "relative-invalid-config");
            } else {
                command.env("CDB_CONFIG", &config);
            }
            let result = command
                .arg(flag)
                .arg(path)
                .arg("--extract-only")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(report["mode"], "extract_only");
            assert_eq!(report["document_count"], count);
            assert_eq!(report["admitted_claim_count"], 0);
            assert_eq!(report["details_truncated"], false);
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.pi_invocations().unwrap(), 3);
}
