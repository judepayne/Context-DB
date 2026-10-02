use cdb_backend_fluree::{
    semantic_preparation::{prepare_current_authorized_view, ExtractionLimits},
    FlureeSemanticLedger,
};
use cdb_service::{acquisition::load_current_catalog, config::InstanceConfig};
use serde_json::Value;
use std::{fs, process::Command};

fn config(root: &std::path::Path) -> String {
    format!(
        r#"schema = "ctxql-instance/v4"
projection = "projection"
credential-file = "credentials.json"
source-root = "sources"
[semantic]
path = "semantic"
ledger = "generic-semantic:main"
backend = "fluree-db/4.2.1@82dbcec3e435d6ed1d45bc0ed929432323b6b201"
authority = "urn:example:authority:semantic"
graph = "https://example.test/graphs/schema"
[control]
path = "control"
ledger = "generic-control:main"
backend = "urn:example:backend:control"
authority = "urn:example:authority:control"
graph = "urn:example:graph:control"
[acquisition]
access-mode = "direct"
protocol = "ontology-v2"
assertions = "accepted"
claims-graph = "https://example.test/graphs/claims"
review-graph = "https://example.test/graphs/review"
principal = "did:example:generic-owner"
action = "https://ns.flur.ee/db#modify"
pi-command = "/usr/bin/false"
pi-bundle = "pi-bundle"
extractor_model = "openrouter/deepseek/deepseek-v4.1-flash"
thinking = "high"
batch-size = 2
max-source-bytes = 1048576
max-document-bytes = 524288
max-folder-entries = 100
provider-timeout-seconds = 120
projection-timeout-seconds = 30
control-journal-bytes = 1048576
ontology-profile = "ctxql-ontology-profile/fluree-4.2.1-82dbcec3e435d6ed1d45bc0ed929432323b6b201/v1-uncertified-acquisition"
ontology-catalog-root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
allowed-local-roots = ["{}"]
[acquisition.window]
mode = "auto"
target-bytes = 4096
max-bytes = 8192
overlap-bytes = 256
"#,
        root.join("documents").display()
    )
}

#[test]
fn generic_semantic_bootstrap_then_control_init_is_create_only() {
    let root = tempfile::tempdir().unwrap();
    let root_path = fs::canonicalize(root.path()).unwrap();
    let config_path = root_path.join("cdb.toml");
    fs::write(&config_path, config(&root_path)).unwrap();

    let bootstrap = Command::new(env!("CARGO_BIN_EXE_cdb"))
        .args(["semantic", "bootstrap", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(
        bootstrap.status.success(),
        "{}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    let receipt: Value = serde_json::from_slice(&bootstrap.stdout).unwrap();
    assert_eq!(receipt["schema"], "ctxql-fresh-semantic-bootstrap/v1");
    assert_eq!(receipt["principal"], "did:example:generic-owner");
    assert_eq!(receipt["default_allow"], false);
    assert_eq!(
        receipt["ontology_profile"],
        "ctxql-ontology-profile/fluree-4.2.1-82dbcec3e435d6ed1d45bc0ed929432323b6b201/v1-uncertified-acquisition"
    );
    assert_ne!(
        receipt["catalog_root"],
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let loaded = InstanceConfig::load(&config_path).unwrap();
    let catalog = runtime.block_on(load_current_catalog(&loaded)).unwrap();
    assert_eq!(
        receipt["catalog_root"],
        catalog.identity().catalog_root().as_str()
    );
    assert_eq!(
        receipt["ontology_profile"],
        catalog.identity().profile_identity()
    );
    let (semantic_path, semantic_options) = loaded.semantic_binding().unwrap();
    let semantic = runtime
        .block_on(FlureeSemanticLedger::open_file(
            semantic_path,
            semantic_options,
        ))
        .unwrap();
    let prepared = runtime
        .block_on(prepare_current_authorized_view(
            &semantic,
            "did:example:generic-owner",
            "https://ns.flur.ee/db#modify",
            ExtractionLimits::default(),
        ))
        .unwrap();
    assert!(prepared.authorized_claims.is_empty());
    assert_eq!(prepared.manifest.data_quads.len(), 1);
    assert_eq!(
        prepared
            .manifest
            .data_quads
            .iter()
            .next()
            .unwrap()
            .object
            .as_iri(),
        Some("http://www.w3.org/2004/03/trix/rdfg-1/Graph")
    );

    let secret = root_path.join("owner.secret");
    let init = Command::new(env!("CARGO_BIN_EXE_cdb"))
        .args(["init", "--config"])
        .arg(&config_path)
        .args(["--principal", "did:example:generic-owner", "--secret-file"])
        .arg(&secret)
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(root_path.join("semantic").is_dir());
    assert!(root_path.join("control").is_dir());
    assert!(secret.is_file());

    let marker = root_path.join("semantic").join("do-not-clobber");
    fs::write(&marker, b"keep").unwrap();
    let repeated = Command::new(env!("CARGO_BIN_EXE_cdb"))
        .args(["semantic", "bootstrap", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(!repeated.status.success());
    assert_eq!(fs::read(marker).unwrap(), b"keep");
}

#[test]
fn non_native_backend_is_rejected_before_store_creation() {
    let root = tempfile::tempdir().unwrap();
    let root_path = fs::canonicalize(root.path()).unwrap();
    let config_path = root_path.join("cdb.toml");
    let invalid = config(&root_path).replace(
        "backend = \"fluree-db/4.2.1@82dbcec3e435d6ed1d45bc0ed929432323b6b201\"",
        "backend = \"urn:example:backend:semantic\"",
    );
    fs::write(&config_path, invalid).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cdb"))
        .args(["semantic", "bootstrap", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!root_path.join("semantic").exists());
    assert!(!root_path.join("control").exists());
}

#[test]
fn legacy_acquisition_is_rejected_before_store_creation() {
    let root = tempfile::tempdir().unwrap();
    let root_path = fs::canonicalize(root.path()).unwrap();
    let config_path = root_path.join("cdb.toml");
    let legacy = config(&root_path)
        .replace("ontology-v2", "legacy-v1")
        .replace(
            cdb_core::recording_v5::CURRENT_ACQUISITION_PROFILE_ID,
            cdb_core::recording_v4::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID,
        );
    fs::write(&config_path, legacy).unwrap();
    cdb_service::config::InstanceConfig::load(&config_path).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cdb"))
        .args(["semantic", "bootstrap", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!root_path.join("semantic").exists());
    assert!(!root_path.join("control").exists());
}

#[test]
fn invalid_bootstrap_config_creates_no_stores() {
    let root = tempfile::tempdir().unwrap();
    let root_path = fs::canonicalize(root.path()).unwrap();
    let config_path = root_path.join("cdb.toml");
    let invalid = config(&root_path).replace(
        "principal = \"did:example:generic-owner\"",
        "principal = \"not an iri\"",
    );
    fs::write(&config_path, invalid).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cdb"))
        .args(["semantic", "bootstrap", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!root_path.join("semantic").exists());
    assert!(!root_path.join("control").exists());
    assert!(!root_path.join("projection").exists());
    assert!(!root_path.join("sources").exists());
}
