use cdb_core::{id::ContentHash, ErrorKind};
use cdb_source_store::{ConverterManifest, Normalization, SourceObjectReader, SourceObjectWriter};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn private_root() -> tempfile::TempDir {
    let parent = std::env::temp_dir().canonicalize().unwrap();
    let root = tempfile::Builder::new()
        .prefix("ctxql-source-store-")
        .tempdir_in(parent)
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    root
}

fn path_for(root: &Path, id: &ContentHash) -> PathBuf {
    root.join(&id.as_str()[7..])
}

fn converter() -> ConverterManifest {
    ConverterManifest::new(
        ContentHash::of_bytes(b"converter executable"),
        "converter 1.0",
        vec!["--text".into(), "--utf8".into()],
        5_000,
        1_000_000,
        Normalization::None,
    )
    .unwrap()
}

#[test]
fn create_new_or_verify_and_current_layout() {
    let root = private_root();
    let writer = SourceObjectWriter::open(root.path().to_path_buf(), 1024).unwrap();
    let id = writer.put_object(b"same bytes").unwrap();
    assert_eq!(writer.put_object(b"same bytes").unwrap(), id);
    assert_eq!(fs::read(path_for(root.path(), &id)).unwrap(), b"same bytes");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path_for(root.path(), &id))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn existing_object_conflict_fails_closed() {
    let root = private_root();
    let expected = ContentHash::of_bytes(b"expected");
    let path = path_for(root.path(), &expected);
    fs::write(&path, b"hostile existing bytes").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let writer = SourceObjectWriter::open(root.path().to_path_buf(), 1024).unwrap();
    let error = writer.put_object(b"expected").unwrap_err();
    assert_eq!(error.kind, ErrorKind::Conflict);
}

#[test]
fn rehashed_read_detects_corruption() {
    let root = private_root();
    let writer = SourceObjectWriter::open(root.path().to_path_buf(), 1024).unwrap();
    let id = writer.put_object(b"original").unwrap();
    fs::write(path_for(root.path(), &id), b"corrupt!").unwrap();

    let reader = SourceObjectReader::open(root.path().to_path_buf(), 1024).unwrap();
    let error = reader.read_object(&id).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Invalid);
}

#[test]
fn read_and_write_limits_are_hard_bounds() {
    let root = private_root();
    let writer = SourceObjectWriter::open(root.path().to_path_buf(), 16).unwrap();
    assert_eq!(
        writer.put_object(&[0; 17]).unwrap_err().kind,
        ErrorKind::Limit
    );
    let id = writer.put_object(&[0; 16]).unwrap();

    let reader = SourceObjectReader::open(root.path().to_path_buf(), 15).unwrap();
    assert_eq!(reader.read_object(&id).unwrap_err().kind, ErrorKind::Limit);
}

#[cfg(unix)]
#[test]
fn symlink_root_is_rejected() {
    use std::os::unix::fs::symlink;
    let parent = private_root();
    let actual = parent.path().join("actual");
    fs::create_dir(&actual).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&actual, fs::Permissions::from_mode(0o700)).unwrap();
    let linked = parent.path().join("linked");
    symlink(&actual, &linked).unwrap();

    assert_eq!(
        SourceObjectReader::open(linked.clone(), 1024)
            .unwrap_err()
            .kind,
        ErrorKind::Invalid
    );
    assert_eq!(
        SourceObjectWriter::open(linked, 1024).unwrap_err().kind,
        ErrorKind::Invalid
    );
}

#[test]
fn manifests_and_restart_reads_preserve_derivation() {
    let root = private_root();
    let writer = SourceObjectWriter::open(root.path().to_path_buf(), 16_384).unwrap();
    let converter = converter();
    let converter_id = writer.put_converter_manifest(&converter).unwrap();
    let original = writer
        .put_original(
            b"# exact markdown\r\n",
            "text/markdown",
            ContentHash::of_bytes(b"bounded acquisition metadata"),
        )
        .unwrap();
    let text = writer
        .put_text(
            b"# exact markdown\r\n",
            original.manifest().clone(),
            converter_id.clone(),
        )
        .unwrap();
    drop(writer);

    let reader = SourceObjectReader::open(root.path().to_path_buf(), 16_384).unwrap();
    assert_eq!(
        reader.read_converter_manifest(&converter_id).unwrap(),
        converter
    );
    let original_manifest = reader.read_original_manifest(original.manifest()).unwrap();
    assert_eq!(original_manifest.object(), original.object());
    let text_manifest = reader.read_text_manifest(text.manifest()).unwrap();
    assert_eq!(text_manifest.version(), text.version());
    assert_eq!(text_manifest.original_manifest(), original.manifest());
    assert_eq!(text_manifest.converter_manifest(), &converter_id);
    assert_eq!(
        reader.read_text(&text_manifest).unwrap().as_bytes(),
        b"# exact markdown\r\n"
    );
}

#[test]
fn text_version_is_content_and_converter_bound() {
    let object = ContentHash::of_bytes(b"text");
    let converter = ContentHash::of_bytes(b"converter manifest");
    let first = cdb_source_store::TextRepresentationManifest::new(
        object.clone(),
        ContentHash::of_bytes(b"original one"),
        converter.clone(),
    )
    .unwrap();
    let second = cdb_source_store::TextRepresentationManifest::new(
        object,
        ContentHash::of_bytes(b"original two"),
        converter,
    )
    .unwrap();
    assert_eq!(first.version(), second.version());
    assert_ne!(first.id().unwrap(), second.id().unwrap());
}
