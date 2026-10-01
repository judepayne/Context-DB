#![cfg(unix)]

use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    contracts::{GraphBackend, SemanticProjectionSource},
    id::{ContentHash, Iri, VersionId},
    Limits,
};
use cdb_service::{
    acquisition_v2_fixture::AcquisitionV2Fixture,
    ingest::{ingest, IngestMode, IngestWait, OntologyMode},
    source_target::SourceTarget,
    Service,
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicBool, Arc},
};

fn source_inventory(root: &Path) -> BTreeMap<PathBuf, ContentHash> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, ContentHash>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                visit(root, &entry.path(), files);
            } else {
                assert!(kind.is_file());
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    ContentHash::of_bytes(&fs::read(entry.path()).unwrap()),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

async fn publish_query_config(service: &Arc<Service>, token: &str) -> ArtifactRef {
    let content = include_bytes!("../../../fixtures/conformance/graph-workspace/config.json");
    let reference = ArtifactRef::new(
        Iri::new("urn:ctxql:chat-pty-config").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(content),
    );
    let published =
        PublishedArtifact::new(reference.clone(), content.to_vec(), Limits::default()).unwrap();
    let artifact: serde_json::Value = serde_json::from_slice(
        &published
            .reference()
            .projection()
            .canonical_bytes(Limits::default())
            .unwrap(),
    )
    .unwrap();
    service
        .dispatch(
            token,
            &serde_json::to_vec(&serde_json::json!({
                "schema":"ctxql-service/v1",
                "op":"publish",
                "artifact":artifact,
                "content":String::from_utf8(published.content().to_vec()).unwrap()
            }))
            .unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    reference
}

fn write_chat_pi(path: &Path, subject: &str, audit: &Path) {
    let source = include_str!("chat_cli_fake_pi.py")
        .replace("{{SUBJECT}}", subject)
        .replace("{{AUDIT}}", &audit.display().to_string());
    fs::write(path, source).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).unwrap();
}

fn write_chat_config(
    fixture: &AcquisitionV2Fixture,
    pi: &Path,
    query_config: &ArtifactRef,
) -> PathBuf {
    let original = fs::read_to_string(fixture.config_path()).unwrap();
    let acquisition = original
        .find("[acquisition]\n")
        .expect("fixture acquisition section");
    let mut chat = original[..acquisition].replace(
        "schema = \"ctxql-instance/v4\"",
        "schema = \"ctxql-instance/v3\"",
    );
    chat.push_str(&format!(
        r#"[chat]
pi-command = {:?}
pi-bundle = {:?}
chat_model = "openrouter/deepseek/deepseek-v4.1-flash"
thinking = "high"
query-config = {{ iri = {:?}, version = {:?}, hash = {:?} }}
"#,
        pi.display().to_string(),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../assets/pi")
            .canonicalize()
            .unwrap()
            .display()
            .to_string(),
        query_config.iri().as_str(),
        query_config.version().as_str(),
        query_config.hash().as_str(),
    ));
    let path = fixture.root().join("chat-v3.toml");
    fs::write(&path, chat).unwrap();
    let loaded = cdb_service::config::InstanceConfig::load(&path).unwrap();
    assert!(loaded.acquisition.is_none(), "tested chat must be v3-only");
    loaded.validate_runtime().unwrap();
    path
}

/// Real terminal acceptance over freshly created native stores and the real
/// authorized Unix tool bridge. The Pi side is a test-owned deterministic RPC
/// process: it has only a synthetic credential and never contacts a provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run exactly through the serial native-test wrapper"]
async fn deterministic_fake_pi_native_terminal_acceptance() {
    if std::env::var_os("CDB_CHAT_PTY_CHILD").is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "deterministic_fake_pi_native_terminal_acceptance",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("CDB_CHAT_PTY_CHILD", "1")
            .env("OPENROUTER_API_KEY", "ctxql-hermetic-chat-only")
            .status()
            .unwrap();
        assert!(status.success(), "isolated native PTY child failed");
        return;
    }
    assert!(std::env::var("OPENROUTER_API_KEY").as_deref() == Ok("ctxql-hermetic-chat-only"));
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let document = fixture
        .write_document(
            "chat-pty-agreement.txt",
            b"Orion is a written agreement under which Acme Ltd borrows GBP 1000.\nOrion was executed on 2022-12-06.\nOrion agreement date: 2022-12-06.\n",
        )
        .unwrap();
    fixture
        .set_pi_response(include_str!(
            "../../../fixtures/conformance/p6/ontology-guided/a2-proposals-v2.json"
        ))
        .unwrap();
    let report = ingest(
        fixture.config().unwrap(),
        SourceTarget::LocalFile(document),
        IngestMode::Admit(IngestWait::Projected),
        OntologyMode::Hard,
        2 * 1024 * 1024,
        None,
        None,
        None,
        cdb_provider_pi::cancel::CancellationToken::default(),
    )
    .await
    .unwrap();
    let report = serde_json::to_value(report).unwrap();
    let subject = report["documents"][0]["admitted_claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|claim| claim["relation"] == "urn:ctxql:a2:executedOn")
        .unwrap()["subject_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let token_path = fixture.root().join("owner.secret");
    let token = fs::read_to_string(&token_path).unwrap();
    let service = Service::open(fixture.config().unwrap()).await.unwrap();
    let query_config = publish_query_config(&service, &token).await;
    service.shutdown().await.unwrap();
    drop(service);

    let audit = fixture.root().join("chat-pi-audit");
    fs::create_dir(&audit).unwrap();
    let pi = fixture.root().join("chat-fake-pi.py");
    write_chat_pi(&pi, &subject, &audit);
    let config_path = write_chat_config(&fixture, &pi, &query_config);
    let config = cdb_service::config::InstanceConfig::load(&config_path).unwrap();

    let (semantic_path, semantic_options) = config.semantic_binding().unwrap();
    let semantic =
        cdb_backend_fluree::FlureeSemanticLedger::open_file(semantic_path, semantic_options)
            .await
            .unwrap();
    let control = cdb_backend_fluree::FlureeBackend::open(config.authority_options().unwrap())
        .await
        .unwrap();
    let sources_before = source_inventory(&config.source_root);
    let semantic_before = SemanticProjectionSource::head(&semantic).await.unwrap();
    let control_before = GraphBackend::head(&control).await.unwrap();
    drop(semantic);
    drop(control);

    let helper = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/chat_pty.py");
    let status = Command::new("python3")
        .arg(helper)
        .arg(env!("CARGO_BIN_EXE_cdb"))
        .arg(&config_path)
        .arg(&token_path)
        .arg(&audit)
        .arg(&config.credential_file)
        .env_remove("CDB_CONFIG")
        .env_remove("CDB_TOKEN_FILE")
        .env("OPENROUTER_API_KEY", "ctxql-hermetic-chat-only")
        .status()
        .expect("run deterministic PTY helper");
    if !status.success() {
        let diagnostics = fs::read_dir(&audit)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("error-"))
            .map(|entry| fs::read_to_string(entry.path()).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");
        panic!("PTY helper failed; fake Pi diagnostics:\n{diagnostics}");
    }

    let semantic = cdb_backend_fluree::FlureeSemanticLedger::open_file(
        config.semantic_binding().unwrap().0,
        config.semantic_binding().unwrap().1,
    )
    .await
    .unwrap();
    let control = cdb_backend_fluree::FlureeBackend::open(config.authority_options().unwrap())
        .await
        .unwrap();
    assert_eq!(
        SemanticProjectionSource::head(&semantic).await.unwrap(),
        semantic_before,
        "chat must not advance the Semantic head"
    );
    assert_eq!(source_inventory(&config.source_root), sources_before);
    assert_eq!(
        GraphBackend::head(&control).await.unwrap(),
        control_before,
        "chat must not advance the Control head"
    );
}
