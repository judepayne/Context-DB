use std::{
    path::Path,
    process::{Command, Output},
};

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cdb"));
    command
        .env_remove("CDB_CONFIG")
        .env_remove("CDB_TOKEN_FILE")
        .env("CDB_DEBUG_ERRORS", "1");
    command
}

fn run(args: &[&str], config: Option<&Path>, token: Option<&Path>) -> Output {
    let mut command = binary();
    command.args(args);
    if let Some(path) = config {
        command.env("CDB_CONFIG", path);
    }
    if let Some(path) = token {
        command.env("CDB_TOKEN_FILE", path);
    }
    command.output().unwrap()
}

fn config(root: &Path) -> std::path::PathBuf {
    let path = root.join("cdb.toml");
    std::fs::write(
        &path,
        r#"schema = "ctxql-instance/v1"
projection = "projection"
credential-file = "credentials.json"
source-root = "sources"
[authority]
path = "authority"
ledger = "main"
backend = "urn:backend:test"
authority = "urn:authority:test"
graph = "urn:graph:test"
"#,
    )
    .unwrap();
    path
}

#[test]
fn explicit_historical_configuration_filename_remains_valid() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let current = config(&root);
    let historical = root.join("ctxql.toml");
    std::fs::rename(&current, &historical).unwrap();
    let original = std::fs::read(&historical).unwrap();
    let loaded = cdb_service::config::InstanceConfig::load(&historical).unwrap();
    assert_eq!(loaded.authority.unwrap().path, root.join("authority"));
    assert_eq!(std::fs::read(&historical).unwrap(), original);
    assert!(!current.exists());
}

#[test]
fn generic_paths_resolve_independently_and_explicit_values_win() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let config = config(&root);
    let token = root.join("token");
    std::fs::write(&token, b"secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let environment_only = run(&["status"], Some(&config), None);
    let stderr = String::from_utf8_lossy(&environment_only.stderr);
    assert!(!environment_only.status.success());
    assert!(stderr.contains("CDB_TOKEN_FILE"), "{stderr}");

    let mixed = run(
        &["status", "--token-file", "relative-token"],
        Some(&config),
        Some(&token),
    );
    let stderr = String::from_utf8_lossy(&mixed.stderr);
    assert!(!mixed.status.success());
    assert!(stderr.contains("--token-file/CDB_TOKEN_FILE"), "{stderr}");

    let precedence = run(
        &["status", "--config", "relative-config"],
        Some(&config),
        Some(&token),
    );
    let stderr = String::from_utf8_lossy(&precedence.stderr);
    assert!(!precedence.status.success());
    assert!(stderr.contains("--config/CDB_CONFIG"), "{stderr}");

    for args in [
        vec!["status", "--config"],
        vec!["status", "--token-file"],
        vec!["status", "--config", "/tmp/a", "--config", "/tmp/b"],
        vec!["status", "extra"],
    ] {
        assert!(!run(&args, None, None).status.success(), "{args:?}");
    }
}

#[test]
fn selected_token_routes_have_identical_private_file_checks() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let config = config(&root);
    let token = root.join("token");
    std::fs::write(&token, b"secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let explicit = run(
        &[
            "status",
            "--config",
            config.to_str().unwrap(),
            "--token-file",
            token.to_str().unwrap(),
        ],
        None,
        None,
    );
    let environment = run(&["status"], Some(&config), Some(&token));
    assert!(!explicit.status.success());
    assert!(!environment.status.success());
    assert!(String::from_utf8_lossy(&explicit.stderr).contains("kind: Denied"));
    assert!(String::from_utf8_lossy(&environment.stderr).contains("kind: Denied"));
}

#[test]
fn help_and_unrelated_commands_ignore_path_environment() {
    for args in [
        vec!["--help"],
        vec!["chat", "--help"],
        vec!["ingest", "--help"],
        vec!["ingest", "start", "--help"],
        vec!["ingest", "inspect", "--help"],
        vec!["ontology", "bootstrap", "--help"],
    ] {
        let output = run(
            &args,
            Some(Path::new("relative-invalid-config")),
            Some(Path::new("relative-invalid-token")),
        );
        if args == ["ontology", "bootstrap", "--help"] {
            // Ontology bootstrap has no dedicated help form, but path variables
            // remain irrelevant to its ordinary argument rejection.
            assert!(!output.status.success());
        } else {
            assert!(
                output.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn every_ingest_subcommand_accepts_environment_config_selection() {
    let missing = Path::new("/tmp/ctxql-environment-config-does-not-exist");
    let cases = [
        vec!["ingest", "start", "--file", "doc.md", "--extract-only"],
        vec!["ingest", "inspect", "--request-file", "/tmp/request.json"],
        vec!["ingest", "artifact", "--request-file", "/tmp/request.json"],
        vec!["ingest", "resume", "--request-file", "/tmp/request.json"],
        vec![
            "ingest",
            "replay",
            "--capture",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--ontology-mode",
            "hard",
            "--assertions",
            "accepted",
        ],
    ];
    for args in cases {
        let output = run(&args, Some(missing), Some(Path::new("/tmp/token")));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{args:?}");
        assert!(!stderr.contains("missing --config"), "{args:?}: {stderr}");
    }
}

#[test]
fn chat_rejects_duplicates_unknowns_and_redirected_io_without_startup() {
    assert!(run(&["chat", "--help"], None, None).status.success());
    for args in [
        vec!["chat"],
        vec!["chat", "--config", "/tmp/a", "--config", "/tmp/b"],
        vec!["chat", "--token-file"],
        vec!["chat", "--prompt", "question"],
        vec!["chat", "extra"],
    ] {
        assert!(!run(&args, None, None).status.success(), "{args:?}");
    }
}
