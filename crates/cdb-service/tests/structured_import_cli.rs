use cdb_core::{CanonicalValue as V, Limits};
use cdb_service::acquisition_v2_fixture::AcquisitionV2Fixture;
use std::process::{Command, Output};

fn invoke(config: &std::path::Path, token: &std::path::Path, input: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cdb"))
        .arg("import")
        .arg("--config")
        .arg(config)
        .arg("--token-file")
        .arg(token)
        .arg("--input")
        .arg(input)
        .output()
        .unwrap()
}

#[test]
fn structured_import_help_is_available_without_an_instance() {
    for flag in ["--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_cdb"))
            .args(["import", flag])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.starts_with("cdb import "));
        assert!(text.contains("ctxql-structured-claim-import/v1"));
        assert!(text.contains("--input"));
        assert!(text.contains("batches already committed"));
    }
}

#[tokio::test]
#[ignore = "requires CDB_PARTY_BACKGROUND_ONTOLOGY exact native bootstrap"]
async fn structured_import_cli_authenticates_and_resumes_after_restart() {
    let ontology = std::env::var("CDB_PARTY_BACKGROUND_ONTOLOGY").expect("ontology bootstrap");
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let config = std::fs::read_to_string(fixture.config_path()).unwrap();
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
    std::fs::write(fixture.config_path(), config).unwrap();
    fixture.config().unwrap();

    let request = serde_json::json!({
        "schema": "ctxql-structured-claim-import/v1",
        "dataset": {"id": "urn:test:cli-dataset", "version": "1"},
        "sources": [{
            "id": "urn:test:cli-source",
            "kind": "ctxql.source.curated-dataset",
            "uri": "urn:test:cli-registry",
            "version": "1",
            "content_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }],
        "entities": [
            {"id": "urn:test:cli:a", "type": "https://www.omg.org/spec/Commons/Organizations/Organization"},
            {"id": "urn:test:cli:b", "type": "https://www.omg.org/spec/Commons/Organizations/Organization"}
        ],
        "claims": [{
            "id": "cli-related",
            "subject": "urn:test:cli:a",
            "predicate": "https://www.omg.org/spec/Commons/Collections/hasMember",
            "object": {"type": "iri", "value": "urn:test:cli:b"},
            "evidence": [{
                "source": "urn:test:cli-source",
                "selector": {"contract": "ctxql-evidence/v1", "whole_document": true}
            }]
        }]
    });
    let input = fixture.root().join("structured-import.json");
    let canonical = V::parse(&serde_json::to_vec(&request).unwrap(), Limits::default())
        .unwrap()
        .canonical_bytes(Limits::default())
        .unwrap();
    std::fs::write(&input, canonical).unwrap();
    let wrong_token = fixture.root().join("wrong.secret");
    std::fs::write(&wrong_token, "not-an-admin-secret").unwrap();
    let owner_token = fixture.root().join("owner.secret");

    let denied = invoke(fixture.config_path(), &wrong_token, &input);
    assert!(!denied.status.success());
    assert!(String::from_utf8(denied.stderr).unwrap().contains("denied"));

    let first = invoke(fixture.config_path(), &owner_token, &input);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let restarted = invoke(fixture.config_path(), &owner_token, &input);
    assert!(
        restarted.status.success(),
        "{}",
        String::from_utf8_lossy(&restarted.stderr)
    );
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let restarted: serde_json::Value = serde_json::from_slice(&restarted.stdout).unwrap();
    assert_eq!(first, restarted);
    assert_eq!(first["schema"], "ctxql-structured-claim-import-result/v1");
    assert_eq!(first["claim_count"], 1);
}

#[test]
fn structured_import_rejects_relative_or_unknown_arguments_before_opening_state() {
    for args in [
        vec![
            "import",
            "--config",
            "relative.toml",
            "--token-file",
            "/tmp/token",
            "--input",
            "/tmp/input",
        ],
        vec!["import", "--unknown", "value"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_cdb"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "{\"error\":\"preparation_failed\"}\n"
        );
    }
}
