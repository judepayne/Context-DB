//! Native executor provenance is a raw source/build commitment, not a semantic hash domain.
use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn collect(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn fingerprint(
    root: &Path,
    domain: &[u8],
    mut files: Vec<PathBuf>,
    variables: &[(String, String)],
) -> String {
    files.sort();
    files.dedup();
    let mut bytes = domain.to_vec();
    for file in files {
        println!("cargo:rerun-if-changed={}", file.display());
        let name = file
            .strip_prefix(root)
            .expect("workspace build input")
            .to_string_lossy();
        let content = fs::read(&file).expect("build input");
        for part in [name.as_bytes(), content.as_slice()] {
            bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
            bytes.extend_from_slice(part);
        }
    }
    for (key, value) in variables {
        for part in [key.as_bytes(), value.as_bytes()] {
            bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
            bytes.extend_from_slice(part);
        }
    }
    cdb_core::id::ContentHash::of_bytes(&bytes)
        .as_str()
        .to_owned()
}

fn main() {
    let service = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest"));
    let crates = service.parent().expect("crates directory");
    let root = crates.parent().expect("workspace root");
    let backend = crates.join("cdb-backend-fluree");
    let engine = crates.join("cdb-engine");
    let core = crates.join("cdb-core");
    let projection = crates.join("cdb-projection-redb");
    let manifests = vec![
        root.join("Cargo.lock"),
        root.join("Cargo.toml"),
        service.join("Cargo.toml"),
        backend.join("Cargo.toml"),
        engine.join("Cargo.toml"),
        core.join("Cargo.toml"),
        projection.join("Cargo.toml"),
        service.join("build.rs"),
    ];
    let mut variables: Vec<_> = env::vars()
        .filter(|(key, _)| key == "TARGET" || key.starts_with("CARGO_FEATURE_"))
        .collect();
    variables.sort();

    let mut executor_files = manifests.clone();
    for directory in [&service, &backend, &engine, &core, &projection] {
        collect(&directory.join("src"), &mut executor_files);
    }
    let executor = fingerprint(
        root,
        b"ctxql-native-executor-source-build/v1\0",
        executor_files,
        &variables,
    );

    println!("cargo:rustc-env=CDB_NATIVE_EXECUTOR_BUILD={executor}");
}
