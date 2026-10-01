use cdb_backend_fluree::ontology_release::{
    inventory_external_root, validate_version_specific_https_url, verify_external_inventory,
    ArtifactClassification, ArtifactRole, CompleteInventory, EvidenceKind, InventoryEntry,
    RelativeSourcePath, ReleaseEvidence, ReleaseForm, SourceArtifactPin, SourceReleaseManifest,
    SourceVerificationLimits, ARTIFACT_CLASSIFICATION_POLICY, ONTOLOGY_RELEASE_UNAPPROVED,
};
use cdb_core::id::ContentHash;
use std::{collections::BTreeMap, fs};

fn path(value: &str) -> RelativeSourcePath {
    RelativeSourcePath::new(value).unwrap()
}
fn class(role: ArtifactRole, media: &str) -> ArtifactClassification {
    ArtifactClassification::new(role, media).unwrap()
}
fn entry(name: &str, bytes: &[u8], role: ArtifactRole, media: &str) -> InventoryEntry {
    InventoryEntry::new(
        path(name),
        ContentHash::of_bytes(bytes),
        bytes.len() as u64,
        class(role, media),
    )
    .unwrap()
}
fn synthetic_manifest(ontology: &[u8]) -> SourceReleaseManifest {
    let license = b"license";
    let notice = b"notice";
    let ontology_class = class(ArtifactRole::OntologyRdf, "application/rdf+xml");
    let inventory = CompleteInventory::new(vec![
        entry(
            "rdf/core.data",
            ontology,
            ArtifactRole::OntologyRdf,
            "application/rdf+xml",
        ),
        entry("LICENSE.txt", license, ArtifactRole::License, "text/plain"),
        entry("NOTICE.txt", notice, ArtifactRole::Notice, "text/plain"),
    ])
    .unwrap();
    let artifact = SourceArtifactPin::new(
        path("rdf/core.data"),
        "https://publisher.example/spec/1.0/core.rdf",
        "1.0",
        ContentHash::of_bytes(ontology),
        ontology.len() as u64,
        ontology_class,
    )
    .unwrap();
    SourceReleaseManifest::new(
        "Publisher",
        "Product",
        "1.0",
        ReleaseForm::SyntheticArtifacts,
        Some("v1.0".into()),
        Some("0123456789012345678901234567890123456789".into()),
        Some("1123456789012345678901234567890123456789".into()),
        Some("2026-09-18T12:00:00Z".into()),
        Some("publisher receipt".into()),
        vec![artifact],
        vec![
            ReleaseEvidence::license(path("LICENSE.txt"), ContentHash::of_bytes(license)),
            ReleaseEvidence::notice(path("NOTICE.txt"), ContentHash::of_bytes(notice)),
        ],
        inventory,
        Some("ctxql-safe-extraction/v1".into()),
        "publisher immutable release",
    )
    .unwrap()
}

#[test]
fn classified_release_has_stable_closed_counts_and_roots() {
    let first = synthetic_manifest(b"ontology");
    let second = synthetic_manifest(b"ontology");
    assert_eq!(first.id(), second.id());
    assert_eq!(first.root(), second.root());
    assert_eq!(
        first.inventory().classification_policy(),
        ARTIFACT_CLASSIFICATION_POLICY
    );
    assert_eq!(first.inventory().role_counts()["ontology_rdf"], 1);
    assert_eq!(first.inventory().role_counts()["license"], 1);
    assert_eq!(first.inventory().role_counts()["notice"], 1);
    assert!(first
        .inventory()
        .classification_root()
        .as_str()
        .starts_with("sha256:"));
    let bytes = first.canonical_json().unwrap();
    first.verify_canonical_json(&bytes).unwrap();
    let mut noncanonical = bytes.clone();
    noncanonical.push(b'\n');
    assert!(first.verify_canonical_json(&noncanonical).is_err());
}

#[test]
fn release_identity_and_manifest_root_bind_independent_fields() {
    let first = synthetic_manifest(b"first authoritative bytes");
    let second = synthetic_manifest(b"second authoritative bytes");
    assert_ne!(first.id(), second.id());
    assert_ne!(first.root(), second.root());
    let mut value: serde_json::Value =
        serde_json::from_slice(&first.canonical_json().unwrap()).unwrap();
    value["manifest_root"] =
        serde_json::Value::String(ContentHash::of_bytes(b"stale").as_str().into());
    let stale = serde_json::to_vec(&value).unwrap();
    assert!(first.verify_canonical_json(&stale).is_err());
}

#[test]
fn classification_is_closed_and_does_not_use_extensions() {
    assert!(ArtifactClassification::new(ArtifactRole::Other, "application/rdf+xml").is_err());
    assert!(ArtifactClassification::new(ArtifactRole::OntologyRdf, "text/plain").is_err());
    assert!(ArtifactClassification::new(ArtifactRole::Other, "Text/Plain").is_err());
    let deceptive = entry(
        "not-ontology.owl",
        b"plain",
        ArtifactRole::Other,
        "text/plain",
    );
    assert_eq!(deceptive.role(), ArtifactRole::Other);
}

#[test]
fn artifact_and_evidence_must_match_inventory_classification() {
    let ontology = b"ontology";
    let license = b"license";
    let notice = b"notice";
    let inventory = CompleteInventory::new(vec![
        entry(
            "core.bin",
            ontology,
            ArtifactRole::OntologyRdf,
            "application/rdf+xml",
        ),
        entry("LICENSE", license, ArtifactRole::Other, "text/plain"),
        entry("NOTICE", notice, ArtifactRole::Notice, "text/plain"),
    ])
    .unwrap();
    let artifact = SourceArtifactPin::new(
        path("core.bin"),
        "https://example.org/1.0/core.rdf",
        "1.0",
        ContentHash::of_bytes(ontology),
        ontology.len() as u64,
        class(ArtifactRole::OntologyRdf, "application/rdf+xml"),
    )
    .unwrap();
    let result = SourceReleaseManifest::new(
        "P",
        "X",
        "1.0",
        ReleaseForm::SyntheticArtifacts,
        None,
        None,
        None,
        None,
        None,
        vec![artifact],
        vec![
            ReleaseEvidence::license(path("LICENSE"), ContentHash::of_bytes(license)),
            ReleaseEvidence::notice(path("NOTICE"), ContentHash::of_bytes(notice)),
        ],
        inventory,
        None,
        "immutable",
    );
    assert!(result.is_err());
}

#[test]
fn exact_url_and_relative_path_policy_fail_closed() {
    for bad in [
        "http://publisher.example/spec/1.0/core.rdf",
        "https://publisher.example/spec/latest/core.rdf",
        "https://publisher.example/spec/1.0",
        "https://publisher.example/ontology/core",
        "https://publisher.example/spec/1.0/core.rdf?accept=xml",
    ] {
        assert_eq!(
            validate_version_specific_https_url(bad, "1.0")
                .unwrap_err()
                .reason_code(),
            ONTOLOGY_RELEASE_UNAPPROVED
        );
    }
    assert!(validate_version_specific_https_url(
        "https://publisher.example/spec/1.0/core.rdf",
        "1.0"
    )
    .is_ok());
    for bad in [
        "/absolute.rdf",
        "../escape.rdf",
        "a/../../escape",
        "a\\b.rdf",
        "a//b.rdf",
    ] {
        assert!(RelativeSourcePath::new(bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn external_inventory_requires_exact_classification_map_and_verifies_bytes() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("rdf")).unwrap();
    fs::write(root.path().join("rdf/core.data"), b"exact").unwrap();
    fs::write(root.path().join("LICENSE.txt"), b"terms").unwrap();
    let mut classes = BTreeMap::from([
        (
            path("rdf/core.data"),
            class(ArtifactRole::OntologyRdf, "application/rdf+xml"),
        ),
        (
            path("LICENSE.txt"),
            class(ArtifactRole::License, "text/plain"),
        ),
    ]);
    let inventory =
        inventory_external_root(root.path(), &classes, SourceVerificationLimits::default())
            .unwrap();
    verify_external_inventory(root.path(), &inventory, SourceVerificationLimits::default())
        .unwrap();
    classes.remove(&path("LICENSE.txt"));
    assert!(
        inventory_external_root(root.path(), &classes, SourceVerificationLimits::default())
            .is_err()
    );
    classes.insert(
        path("LICENSE.txt"),
        class(ArtifactRole::License, "text/plain"),
    );
    classes.insert(path("extra"), class(ArtifactRole::Other, "text/plain"));
    assert!(
        inventory_external_root(root.path(), &classes, SourceVerificationLimits::default())
            .is_err()
    );
    fs::write(root.path().join("rdf/core.data"), b"substitution").unwrap();
    assert!(verify_external_inventory(
        root.path(),
        &inventory,
        SourceVerificationLimits::default()
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn external_inventory_rejects_symlinks() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    symlink(outside.path(), root.path().join("linked.rdf")).unwrap();
    assert!(inventory_external_root(
        root.path(),
        &BTreeMap::new(),
        SourceVerificationLimits::default()
    )
    .is_err());
}

#[test]
fn evidence_kinds_are_closed() {
    assert_eq!(
        ReleaseEvidence::license(path("LICENSE"), ContentHash::of_bytes(b"license")).kind(),
        EvidenceKind::License
    );
}
