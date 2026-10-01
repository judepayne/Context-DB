#[path = "../../cdb-testkit/tests/common_p5_5/mod.rs"]
mod common_p5_5;

use cdb_core::{id::ContentHash, CanonicalValue as V, Limits};
use std::{
    path::Path,
    process::{Command, Output},
};
fn command(root: &Path, op: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cdb"))
        .arg(op)
        .arg("--config")
        .arg(root.join("cdb.toml"))
        .args(extra)
        .output()
        .unwrap()
}
fn call(root: &Path, op: &str, request: serde_json::Value) -> V {
    std::fs::write(
        root.join("request.json"),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let token = root.join("owner.secret");
    let file = root.join("request.json");
    let output = command(
        root,
        op,
        &[
            "--token-file",
            token.to_str().unwrap(),
            "--request-file",
            file.to_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "{op}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    V::parse(&output.stdout, Limits::default()).unwrap()
}
#[test]
fn cli_help_has_no_instance_or_authentication_side_effects() {
    let out = Command::new(env!("CARGO_BIN_EXE_cdb"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("cdb <"));
    println!("P4_CASE {{\"id\":\"P4-C001\",\"outcome\":\"passed\"}}");
}
#[test]
fn ingest_start_arguments_require_exactly_one_source_mode() {
    let help = Command::new(env!("CARGO_BIN_EXE_cdb"))
        .args(["ingest", "start", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.starts_with("cdb ingest"));
    assert!(help_text.contains("--extract-only"));
    assert!(help_text.contains("--ontology-mode hard|soft"));

    let reject = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_cdb"))
            .args(args)
            .output()
            .unwrap();
        assert!(!out.status.success(), "unexpected success: {args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("preparation_failed"));
    };
    reject(&["ingest", "start", "--config", "/tmp/missing-cdb.toml"]);
    reject(&[
        "ingest",
        "start",
        "--config",
        "/tmp/missing-cdb.toml",
        "--file",
        "a.md",
        "--folder",
        "docs",
    ]);
    reject(&[
        "ingest",
        "start",
        "--config",
        "relative.toml",
        "--file",
        "a.md",
    ]);
    reject(&[
        "ingest",
        "start",
        "--config",
        "/tmp/missing-cdb.toml",
        "--file",
        "a.md",
        "--file",
        "b.md",
    ]);
    reject(&[
        "ingest",
        "start",
        "--config",
        "/tmp/missing-cdb.toml",
        "--url",
    ]);
    reject(&[
        "ingest",
        "start",
        "--config",
        "/tmp/missing-cdb.toml",
        "--file",
        "a.md",
        "--wait",
        "later",
    ]);
    reject(&[
        "ingest",
        "start",
        "--config",
        "/tmp/missing-cdb.toml",
        "--file",
        "a.md",
        "--extract-only",
        "--wait",
        "admitted",
    ]);
    reject(&[
        "ingest",
        "start",
        "--config",
        "/tmp/missing-cdb.toml",
        "--file",
        "a.md",
        "--extract-only",
        "--extract-only",
    ]);
    reject(&[
        "ingest",
        "start",
        "--config",
        "/tmp/missing-cdb.toml",
        "--file",
        "a.md",
        "--ontology-mode",
        "lenient",
    ]);
    reject(&[
        "ingest",
        "start",
        "--config",
        "/tmp/missing-cdb.toml",
        "--file",
        "a.md",
        "--ontology-mode",
        "hard",
        "--ontology-mode",
        "soft",
    ]);
}

#[test]
fn ontology_bootstrap_arguments_and_create_new_output_fail_closed() {
    let reject = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_cdb"))
            .args(args)
            .output()
            .unwrap();
        assert!(!out.status.success(), "unexpected success: {args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("preparation_failed"));
    };
    reject(&[
        "ontology",
        "bootstrap",
        "--cache",
        "relative-cache",
        "--output",
        "relative-output",
    ]);
    reject(&["ontology", "bootstrap", "--cache"]);
    reject(&["ontology", "bootstrap", "--unknown", "/tmp/value"]);
    reject(&[
        "ontology",
        "bootstrap",
        "--cache",
        "/tmp/cache",
        "--output",
        "/tmp/output",
        "--scope",
        "all",
    ]);
    reject(&[
        "ontology",
        "bootstrap",
        "--cache",
        "/tmp/cache",
        "--output",
        "/tmp/output",
        "--scope",
        "agreements",
        "--scope",
        "commercial-loans",
    ]);
    reject(&[
        "ontology",
        "bootstrap",
        "--cache",
        "/tmp/cache",
        "--cache",
        "/tmp/other-cache",
        "--output",
        "/tmp/output",
    ]);

    let existing = tempfile::tempdir().unwrap();
    reject(&[
        "ontology",
        "bootstrap",
        "--cache",
        existing.path().to_str().unwrap(),
        "--output",
        existing.path().to_str().unwrap(),
    ]);
    reject(&[
        "ontology",
        "bootstrap",
        "--cache",
        existing.path().to_str().unwrap(),
        "--output",
        existing.path().to_str().unwrap(),
        "--scope",
        "commercial-loans",
    ]);
}

#[test]
fn cli_uses_the_same_authenticated_durable_service_across_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let cfg = include_str!("../../../fixtures/conformance/p2/config.json");
    std::fs::write(
        root.join("cdb.toml"),
        format!(
            r#"schema="ctxql-instance/v2"
projection="projection"
credential-file="credentials.json"
source-root="sources"
[authority]
path="authority"
ledger="cli-p4:main"
backend="cli"
authority="cli-authority"
graph="cli-graph"
[default-config]
iri="https://test/config"
version="1"
hash="{}"
"#,
            ContentHash::of_bytes(cfg.as_bytes()).as_str()
        ),
    )
    .unwrap();
    let secret = root.join("owner.secret");
    let init = command(
        &root,
        "init",
        &[
            "--principal",
            "owner",
            "--secret-file",
            secret.to_str().unwrap(),
        ],
    );
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(init.stdout.is_empty());
    for (iri, content) in [
        ("https://test/config", cfg),
        (
            "https://test/query",
            r#"{"about":[{"from":["missing"],"match":"exact"}],"bounds":{"max_depth":1},"return":{"explain":false}}"#,
        ),
    ] {
        call(
            &root,
            "publish",
            serde_json::json!({"schema":"ctxql-service/v1","op":"publish","artifact":{"iri":iri,"version":"1","hash":ContentHash::of_bytes(content.as_bytes()).as_str()},"content":content}),
        );
    }
    let query = r#"{"about":[{"from":["missing"],"match":"exact"}],"bounds":{"max_depth":1},"return":{"explain":false}}"#;
    let first = call(
        &root,
        "query",
        serde_json::json!({"schema":"ctxql-service/v1","op":"query","run_id":"cli-run","query":{"iri":"https://test/query","version":"1","hash":ContentHash::of_bytes(query.as_bytes()).as_str()},"execution":"native_v3"}),
    );
    let replay = call(
        &root,
        "replay",
        serde_json::json!({"schema":"ctxql-service/v1","op":"replay","run_id":"cli-run"}),
    );
    let replay = replay.field("response").unwrap();
    assert_eq!(replay.field("graph").unwrap(), &V::string("reproduced"));
    assert_eq!(
        replay.field("response_hash").unwrap(),
        first
            .field("response")
            .unwrap()
            .field("response_hash")
            .unwrap()
    );
    let status = command(&root, "status", &["--token-file", secret.to_str().unwrap()]);
    assert!(status.status.success());
    let environment_only = Command::new(env!("CARGO_BIN_EXE_cdb"))
        .arg("status")
        .env("CDB_CONFIG", root.join("cdb.toml"))
        .env("CDB_TOKEN_FILE", &secret)
        .output()
        .unwrap();
    assert!(environment_only.status.success());
    let mixed = Command::new(env!("CARGO_BIN_EXE_cdb"))
        .args(["status", "--config"])
        .arg(root.join("cdb.toml"))
        .env("CDB_TOKEN_FILE", &secret)
        .output()
        .unwrap();
    assert!(mixed.status.success());
    let explicit_precedence = Command::new(env!("CARGO_BIN_EXE_cdb"))
        .args(["status", "--config"])
        .arg(root.join("cdb.toml"))
        .args(["--token-file"])
        .arg(&secret)
        .env("CDB_CONFIG", "relative-invalid-config")
        .env("CDB_TOKEN_FILE", "relative-invalid-token")
        .output()
        .unwrap();
    assert!(explicit_precedence.status.success());
    let token = std::fs::read_to_string(secret).unwrap();
    assert!(!String::from_utf8_lossy(&status.stdout).contains(&token));
    println!("P4_CASE {{\"id\":\"P4-C002\",\"outcome\":\"passed\"}}");
}

#[test]
fn cli_v3_uses_read_only_semantic_and_durable_v4_across_processes() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let semantic_head = runtime.block_on(common_p5_5::write_trusted_semantic_fixture(&root));
    std::fs::write(root.join("cdb.toml"), common_p5_5::instance_config(&root)).unwrap();
    let config = include_str!("../../../fixtures/conformance/p2/config.json");
    let query = r#"{"about":[{"from":["missing"],"match":"exact"}],"bounds":{"max_depth":1}}"#;
    let secret = root.join("owner.secret");
    let init = command(
        &root,
        "init",
        &[
            "--principal",
            "owner",
            "--secret-file",
            secret.to_str().unwrap(),
        ],
    );
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    for (iri, content) in [
        ("https://test/v3-config", config),
        ("https://test/v3-query", query),
    ] {
        call(
            &root,
            "publish",
            serde_json::json!({
                "schema":"ctxql-service/v1", "op":"publish",
                "artifact":{"iri":iri,"version":"1","hash":ContentHash::of_bytes(content.as_bytes()).as_str()},
                "content":content
            }),
        );
    }
    let request = serde_json::json!({
        "schema":"ctxql-service/v1", "op":"query", "run_id":"cli-v3-run",
        "query":{"iri":"https://test/v3-query","version":"1","hash":ContentHash::of_bytes(query.as_bytes()).as_str()},
        "config":{"iri":"https://test/v3-config","version":"1","hash":ContentHash::of_bytes(config.as_bytes()).as_str()},
        "execution":"native_v3"
    });
    let first = call(&root, "query", request.clone());
    let retry = call(&root, "query", request);
    assert_eq!(
        retry.field("response").unwrap(),
        first.field("response").unwrap()
    );
    let replay = call(
        &root,
        "replay",
        serde_json::json!({"schema":"ctxql-service/v1","op":"replay","run_id":"cli-v3-run"}),
    );
    assert_eq!(
        replay.field("response").unwrap().field("graph").unwrap(),
        &V::string("reproduced")
    );

    let mut conflict = serde_json::json!({
        "schema":"ctxql-service/v1", "op":"query", "run_id":"cli-v3-run",
        "query":{"iri":"https://test/v3-query","version":"1","hash":ContentHash::of_bytes(query.as_bytes()).as_str()},
        "config":{"iri":"https://test/v3-config","version":"1","hash":ContentHash::of_bytes(config.as_bytes()).as_str()},
        "execution":"native_v3"
    });
    conflict["consistency"] = serde_json::json!("exact");
    std::fs::write(
        root.join("request.json"),
        serde_json::to_vec(&conflict).unwrap(),
    )
    .unwrap();
    let failed = command(
        &root,
        "query",
        &[
            "--token-file",
            secret.to_str().unwrap(),
            "--request-file",
            root.join("request.json").to_str().unwrap(),
        ],
    );
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&failed.stderr).trim(),
        r#"{"error":"preparation_failed"}"#
    );
    assert_eq!(
        runtime.block_on(common_p5_5::read_semantic_head(&root)),
        semantic_head
    );
}
