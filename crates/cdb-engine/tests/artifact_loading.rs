use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    id::{ContentHash, Iri, VersionId},
    ErrorKind, Limits,
};
use cdb_engine::artifacts::{read_json, ArtifactKind as K, ArtifactName, Catalog, CatalogOptions};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

fn limits() -> Limits {
    Limits::new(4096, 16, 256, 4096, 8192).unwrap()
}
fn options() -> CatalogOptions {
    CatalogOptions {
        limits: limits(),
        max_entries: 4,
        max_name_bytes: 64,
        max_retained_bytes: 8192,
    }
}
fn name(s: &str) -> ArtifactName {
    ArtifactName::new(s, 64).unwrap()
}
fn reference(bytes: &[u8], version: &str) -> ArtifactRef {
    ArtifactRef::new(
        Iri::new("urn:test:artifact").unwrap(),
        VersionId::new(version).unwrap(),
        ContentHash::of_bytes(bytes),
    )
}
fn published(bytes: &[u8], version: &str) -> PublishedArtifact {
    PublishedArtifact::new(reference(bytes, version), bytes.to_vec(), limits()).unwrap()
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "ctxql-artifact-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("exclusive test directory: {e}"),
            }
        }
    }
    fn put(&self, bytes: &[u8]) {
        fs::create_dir_all(self.0.join("queries/team")).unwrap();
        fs::write(self.0.join("queries/team/example.json"), bytes).unwrap();
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn names_reject_paths_and_escapes() {
    for invalid in [
        "",
        "/absolute",
        "../up",
        "a/../b",
        "a/./b",
        "a//b",
        "a/",
        "C:/root",
        "a\\b",
        "a\n",
        "%2e%2e/x",
        "a./x",
        "a /x",
    ] {
        assert!(ArtifactName::new(invalid, 64).is_err(), "{invalid:?}");
    }
    assert_eq!(name("team/example").as_str(), "team/example");
    assert_eq!(
        ArtifactName::new("long", 3).unwrap_err().kind,
        ErrorKind::Limit
    );
}

#[test]
fn immutable_exact_catalog() {
    let bytes = b" { \"large\" : 9007199254740993 }\n";
    let artifact = published(bytes, "v1");
    let catalog = Catalog::new(
        [
            (K::Query, name("n"), artifact.clone()),
            (K::Query, name("n"), artifact.clone()),
            (K::Profile, name("n"), artifact.clone()),
            (K::Config, name("n"), artifact.clone()),
        ],
        options(),
    )
    .unwrap();
    assert_eq!(catalog.len(), 3);
    assert!(!catalog.is_empty());
    assert_eq!(
        catalog
            .resolve(K::Query, &name("n"), artifact.reference())
            .unwrap()
            .content(),
        bytes
    );
    assert_eq!(
        catalog
            .resolve(K::Query, &name("absent"), artifact.reference())
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    for changed in [published(bytes, "v2"), published(b"{}", "v1")] {
        assert_eq!(
            catalog
                .resolve(K::Query, &name("n"), changed.reference())
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );
        assert_eq!(
            Catalog::new(
                [
                    (K::Query, name("n"), artifact.clone()),
                    (K::Query, name("n"), changed)
                ],
                options()
            )
            .unwrap_err()
            .kind,
            ErrorKind::Conflict
        );
    }
}

#[test]
fn catalog_budgets_are_enforced() {
    let entry = || (K::Query, name("name"), published(b"{}", "1"));
    let retained = Catalog::new([entry()], options()).unwrap().retained_bytes();
    let mut o = options();
    o.max_retained_bytes = retained;
    Catalog::new([entry()], o).unwrap();
    o.max_retained_bytes -= 1;
    assert_eq!(
        Catalog::new([entry()], o).unwrap_err().kind,
        ErrorKind::Limit
    );
    o = options();
    o.max_entries = 0;
    assert_eq!(
        Catalog::new([entry()], o).unwrap_err().kind,
        ErrorKind::Limit
    );
    o = options();
    o.max_name_bytes = 3;
    assert_eq!(
        Catalog::new([entry()], o).unwrap_err().kind,
        ErrorKind::Limit
    );
    o = options();
    o.limits = Limits::new(1, 16, 256, 4096, 8192).unwrap();
    assert_eq!(
        Catalog::new([entry()], o).unwrap_err().kind,
        ErrorKind::Limit
    );
    o = options();
    o.limits = Limits::new(4096, 16, 256, 1, 8192).unwrap();
    assert!(Catalog::new([entry(), entry()], o).is_err());
}

#[test]
fn explicit_root_exact_bytes_hash_missing_and_ceiling() {
    let temp = Temp::new();
    let bytes = b" {\"n\": 9007199254740993.0001}\n";
    temp.put(bytes);
    let expected = reference(bytes, "1");
    let read = read_json(
        &temp.0,
        K::Query,
        &name("team/example"),
        &expected,
        limits(),
    )
    .unwrap();
    assert_eq!(read.content(), bytes);
    assert!(read_json(
        &temp.0,
        K::Query,
        &name("team/example"),
        &reference(b"{}", "1"),
        limits()
    )
    .is_err());
    assert_eq!(
        read_json(&temp.0, K::Profile, &name("missing"), &expected, limits())
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    let small = Limits::new(bytes.len() - 1, 16, 256, 4096, 8192).unwrap();
    assert_eq!(
        read_json(&temp.0, K::Query, &name("team/example"), &expected, small)
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
}

#[test]
fn strict_json_in_catalog_and_files() {
    let temp = Temp::new();
    for bytes in [
        b"{\"a\":1,\"a\":2}".as_slice(),
        b"{/*comment*/}",
        b"NaN",
        b"Infinity",
        b"[1,]",
        b"\xff",
    ] {
        temp.put(bytes);
        assert!(read_json(
            &temp.0,
            K::Query,
            &name("team/example"),
            &reference(bytes, "1"),
            limits()
        )
        .is_err());
        assert!(Catalog::new([(K::Query, name("n"), published(bytes, "1"))], options()).is_err());
    }
}

#[cfg(unix)]
#[test]
fn symlink_escape_is_rejected_without_path_disclosure() {
    let root = Temp::new();
    let outside = Temp::new();
    fs::write(outside.0.join("secret.json"), b"{}").unwrap();
    fs::create_dir(root.0.join("queries")).unwrap();
    std::os::unix::fs::symlink(
        outside.0.join("secret.json"),
        root.0.join("queries/link.json"),
    )
    .unwrap();
    let error = read_json(
        &root.0,
        K::Query,
        &name("link"),
        &reference(b"{}", "1"),
        limits(),
    )
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Invalid);
    assert!(!error.to_string().contains(outside.0.to_str().unwrap()));
    assert!(!error.public_json().contains("secret"));
    std::os::unix::fs::symlink(&outside.0, root.0.join("profiles")).unwrap();
    assert!(read_json(
        &root.0,
        K::Profile,
        &name("secret"),
        &reference(b"{}", "1"),
        limits()
    )
    .is_err());
}
