use cdb_core::{function_manifest::ExternalFunctionManifest, id::ContentHash, Error};
use cdb_service::{
    broker::{
        dispatch::{Adapter, Attempt, ExecutionClass, PhysicalRequest},
        startup::{AdapterCatalog, NativeCapacity, StartupError},
    },
    config::{CredentialEntry, CredentialTable, InstanceConfig},
};
use std::{path::Path, sync::Arc};

struct FixedAdapter {
    class: ExecutionClass,
    build: &'static str,
}
impl Adapter for FixedAdapter {
    fn class(&self) -> ExecutionClass {
        self.class
    }
    fn build_identity(&self) -> &str {
        self.build
    }
    fn supports(&self, _: &ExternalFunctionManifest) -> bool {
        true
    }
    fn enqueue(&self, _: PhysicalRequest) -> cdb_core::Result<Attempt> {
        Err(Error::invalid("test adapter does not execute"))
    }
}

const MANIFEST: &[u8] = br#"{"schema":"ctxql-external-function/v1","name":"test-function","version":"1","implementation":{"implementation":"urn:test:http-json","version":"1","build":"sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f","model":null},"input_schema":{"type":"string"},"output_schema":{"type":"number"},"semantic_parameters":{},"capabilities":[],"declarations":{"deterministic":true,"order_independent":true,"retry_safe":true,"batching":"none"}}"#;

fn base(hash: &str) -> String {
    format!(
        r#"schema = "ctxql-instance/v2"
projection = "projection"
credential-file = "credentials.json"
source-root = "sources"
[authority]
path = "authority"
ledger = "main"
backend = "urn:backend:test"
authority = "urn:authority:test"
graph = "urn:graph:test"
[limits]
deadline_seconds = 86400
session_ttl_seconds = 86400
[broker]
enabled = true
[broker.groups.shared]
max_in_flight = 8
max_queued_bytes = 1048576
requests_per_second = 100
burst_requests = 10
[broker.manifests.score]
iri = "urn:test:manifest"
version = "1"
hash = "{hash}"
file = "manifest.json"
[broker.providers.first]
class = "http_service"
adapter = "ctxql-http-json/v1"
destination = "urn:destination:test"
group = "shared"
allowed_manifests = ["score"]
endpoint = "http://127.0.0.1:9/invoke"
allow_loopback_plaintext = true
implementation = "urn:test:http-json"
implementation_version = "1"
implementation_build = "sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f"
[broker.providers.second]
class = "http_service"
adapter = "ctxql-http-json/v1"
destination = "urn:destination:test-two"
group = "shared"
allowed_manifests = ["score"]
endpoint = "http://localhost:9/invoke"
allow_loopback_plaintext = true
implementation = "urn:test:http-json"
implementation_version = "1"
implementation_build = "sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f"
"#,
        hash = hash
    )
}

#[cfg(unix)]
fn fixture() -> (tempfile::TempDir, String) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let credentials = CredentialTable {
        schema: "ctxql-credentials/v1".into(),
        entries: vec![CredentialEntry {
            digest: format!("sha256:{}", "a".repeat(64)),
            principal: "urn:principal:test".into(),
            enabled: true,
            expires_at: None,
            capabilities: vec!["query".into()],
        }],
    };
    credentials
        .write_new(&root.join("credentials.json"))
        .unwrap();
    std::fs::write(root.join("manifest.json"), MANIFEST).unwrap();
    std::fs::set_permissions(
        root.join("manifest.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let hash = ContentHash::of_bytes(MANIFEST).as_str().to_owned();
    let text = base(&hash);
    (dir, text)
}

#[cfg(unix)]
#[tokio::test]
async fn constructs_exact_http_registry_and_shared_group_bundle() {
    let (dir, text) = fixture();
    let root = dir.path().canonicalize().unwrap();
    let config = InstanceConfig::parse(&text, &root.join("instance.toml")).unwrap();
    let bundle = config.startup_bundle(&AdapterCatalog::default()).unwrap();
    assert_eq!(bundle.executor.rhai_workers, 32);
    assert_eq!(bundle.executor.local_workers, 2);
    assert_eq!(bundle.executor.max_state_bytes, 64 * 1024);
    assert_eq!(bundle.providers.len(), 2);
    assert_eq!(bundle.providers[0].group, "shared");
    assert_eq!(bundle.providers[1].group, "shared");
    assert!(bundle.providers.iter().all(|p| !p.test_only));
}

#[cfg(unix)]
#[tokio::test]
async fn v1_startup_preserves_broker_disabled_behavior() {
    let (dir, text) = fixture();
    let legacy = text
        .split("[broker]")
        .next()
        .unwrap()
        .replace("ctxql-instance/v2", "ctxql-instance/v1")
        .replace(
            "[limits]\ndeadline_seconds = 86400\nsession_ttl_seconds = 86400\n",
            "",
        );
    let root = dir.path().canonicalize().unwrap();
    let config = InstanceConfig::parse(&legacy, &root.join("instance.toml")).unwrap();
    let bundle = config.startup_bundle(&AdapterCatalog::default()).unwrap();
    assert!(bundle.providers.is_empty());
    assert_eq!(bundle.executor.rhai_workers, 32);
}

#[cfg(unix)]
#[tokio::test]
async fn exact_manifest_bytes_not_reserialization_are_pinned() {
    let (dir, text) = fixture();
    let root = dir.path().canonicalize().unwrap();
    std::fs::write(root.join("manifest.json"), [MANIFEST, b"\n"].concat()).unwrap();
    let config = InstanceConfig::parse(&text, &root.join("instance.toml")).unwrap();
    assert!(config.startup_bundle(&AdapterCatalog::default()).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_zero_overflow_and_unknown_references() {
    let (dir, text) = fixture();
    let root = dir.path().canonicalize().unwrap();
    let zero = text.replacen("max_in_flight = 8", "max_in_flight = 0", 1);
    let config = InstanceConfig::parse(&zero, &root.join("instance.toml")).unwrap();
    assert!(config.startup_bundle(&AdapterCatalog::default()).is_err());

    let missing = text.replacen("group = \"shared\"", "group = \"missing\"", 1);
    let config = InstanceConfig::parse(&missing, &root.join("instance.toml")).unwrap();
    let error = match config.startup_bundle(&AdapterCatalog::default()) {
        Err(error) => error,
        Ok(_) => panic!("unknown group accepted"),
    };
    assert!(matches!(
        error,
        StartupError::Invalid("provider references unknown group")
    ));

    let overflow = text.replace(
        "enabled = true",
        "enabled = true\nper_request_pending = 184467440737095516160",
    );
    assert!(InstanceConfig::parse(&overflow, &root.join("instance.toml")).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn reports_runtime_controls_that_current_dispatch_cannot_enforce() {
    let (dir, text) = fixture();
    let text = text.replace(
        "[broker.groups.shared]\n",
        "[broker.groups.shared]\ntokens_per_second = 1000\nburst_tokens = 1000\ntoken_accounting = \"provider_usage\"\n",
    );
    let root = dir.path().canonicalize().unwrap();
    let config = InstanceConfig::parse(&text, &root.join("instance.toml")).unwrap();
    let error = match config.startup_bundle(&AdapterCatalog::default()) {
        Err(error) => error,
        Ok(_) => panic!("unsupported token controls accepted"),
    };
    assert!(matches!(
        error,
        StartupError::UnsupportedControl(
            "token rates require dispatch token accounting capability"
        )
    ));
    assert!(error.to_string().contains("token accounting"));
}

#[cfg(unix)]
#[tokio::test]
async fn native_adapters_require_available_exact_capacity_and_test_label() {
    let (dir, mut text) = fixture();
    text.push_str(
        r#"[broker.providers.cpu]
class = "cpu_blocking"
adapter = "registered-cpu"
destination = "urn:destination:cpu"
group = "shared"
allowed_manifests = ["score"]
implementation = "urn:test:http-json"
implementation_version = "1"
implementation_build = "sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f"
workers = 2
internal_threads = 1
[broker.providers.device]
class = "accelerator"
adapter = "test-device"
destination = "urn:destination:device"
group = "shared"
allowed_manifests = ["score"]
implementation = "urn:test:http-json"
implementation_version = "1"
implementation_build = "sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f"
workers = 1
internal_threads = 1
device_memory_bytes = 1048576
max_batch = 4
"#,
    );
    let root = dir.path().canonicalize().unwrap();
    let config = InstanceConfig::parse(&text, &root.join("instance.toml")).unwrap();
    let missing = match config.startup_bundle(&AdapterCatalog::default()) {
        Err(error) => error,
        Ok(_) => panic!("unavailable native adapters accepted"),
    };
    assert!(matches!(
        missing,
        StartupError::UnsupportedControl("configured native adapter is not registered/available")
    ));

    let mut catalog = AdapterCatalog::default();
    catalog
        .register(
            "registered-cpu",
            Arc::new(FixedAdapter {
                class: ExecutionClass::CpuBlocking,
                build: "test-cpu-build",
            }),
            NativeCapacity {
                workers: 2,
                internal_threads: 1,
                device_memory_bytes: None,
                max_batch: None,
                test_only: false,
            },
        )
        .unwrap();
    catalog
        .register(
            "test-device",
            Arc::new(FixedAdapter {
                class: ExecutionClass::Accelerator,
                build: "ctxql-test-accelerator/v1-NOT-REAL-HARDWARE",
            }),
            NativeCapacity {
                workers: 1,
                internal_threads: 1,
                device_memory_bytes: Some(1024 * 1024),
                max_batch: Some(4),
                test_only: true,
            },
        )
        .unwrap();
    let bundle = config.startup_bundle(&catalog).unwrap();
    assert_eq!(bundle.providers.len(), 4);
    assert!(
        bundle
            .providers
            .iter()
            .find(|p| p.id == "device")
            .unwrap()
            .test_only
    );
}

#[test]
fn v1_rejects_broker_and_v2_is_closed_and_finite() {
    let old = r#"schema = "ctxql-instance/v1"
projection = "projection"
credential-file = "credentials.json"
source-root = "sources"
[authority]
path = "authority"
ledger = "main"
backend = "urn:backend:test"
authority = "urn:authority:test"
graph = "urn:graph:test"
[broker]
enabled = false
"#;
    assert!(InstanceConfig::parse(old, Path::new("/instance/config.toml")).is_err());
    let v2 = old.replace("ctxql-instance/v1", "ctxql-instance/v2");
    assert!(InstanceConfig::parse(
        &(v2.clone() + "unknown = 1\n"),
        Path::new("/instance/config.toml")
    )
    .is_err());
    assert!(InstanceConfig::parse(
        &v2.replace("enabled = false", "enabled = true\nrhai_workers = 0"),
        Path::new("/instance/config.toml")
    )
    .is_err());
}
