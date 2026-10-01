//! Build provenance is a raw source commitment, not a CTXQL semantic hash domain.
use std::{
    env, fs,
    path::{Path, PathBuf},
};
fn collect(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            collect(&path, files);
        } else if path.extension().is_some_and(|s| s == "rs") {
            files.push(path);
        }
    }
}
fn main() {
    let engine = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest"));
    let root = engine.parent().unwrap().parent().unwrap();
    let core = engine.parent().unwrap().join("cdb-core");
    let mut files = vec![
        root.join("Cargo.lock"),
        root.join("Cargo.toml"),
        engine.join("Cargo.toml"),
        engine.join("build.rs"),
        core.join("Cargo.toml"),
    ];
    collect(&engine.join("src"), &mut files);
    collect(&core.join("src"), &mut files);
    files.sort();
    let mut bytes = b"ctxql-engine-source-build/v1\0".to_vec();
    for file in files {
        println!("cargo:rerun-if-changed={}", file.display());
        let name = file.strip_prefix(root).unwrap().to_string_lossy();
        let content = fs::read(&file).expect("build input");
        bytes.extend_from_slice(&(name.len() as u64).to_be_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&(content.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&content);
    }
    // Target and enabled package features are part of the execution build identity.
    let mut variables: Vec<_> = env::vars()
        .filter(|(k, _)| k == "TARGET" || k.starts_with("CARGO_FEATURE_"))
        .collect();
    variables.sort();
    for (key, value) in variables {
        for text in [key, value] {
            bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
            bytes.extend_from_slice(text.as_bytes());
        }
    }
    println!(
        "cargo:rustc-env=CDB_ENGINE_BUILD={}",
        cdb_core::id::ContentHash::of_bytes(&bytes).as_str()
    );
}
