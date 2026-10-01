use crate::path::{backend, check_private_file, same_identity, Root};
use cdb_core::{id::ContentHash, Error, ErrorKind, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn read(root: &Root, id: &ContentHash, max_bytes: usize) -> Result<Vec<u8>> {
    let path = root.object_path(&id.as_str()[7..])?;
    let before = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::new(ErrorKind::NotFound, "source object not found"));
        }
        Err(_) => return Err(backend("source object metadata")),
    };
    check_private_file(&before)?;
    if before.len() > max_bytes as u64 {
        return Err(Error::limit());
    }

    let mut file = File::open(&path).map_err(|_| backend("source object open"))?;
    let opened = file
        .metadata()
        .map_err(|_| backend("source object metadata"))?;
    check_private_file(&opened)?;
    if !same_identity(&before, &opened) {
        return Err(Error::invalid("source object changed while opening"));
    }
    root.check()?;

    let mut bytes = Vec::new();
    (&mut file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| backend("source object read"))?;
    if bytes.len() > max_bytes {
        return Err(Error::limit());
    }

    let after = file
        .metadata()
        .map_err(|_| backend("source object metadata"))?;
    let named = fs::symlink_metadata(&path).map_err(|_| backend("source object metadata"))?;
    check_private_file(&after)?;
    if !same_identity(&opened, &after)
        || !same_identity(&after, &named)
        || after.len() != bytes.len() as u64
    {
        return Err(Error::invalid("source object changed while reading"));
    }
    root.check()?;
    if ContentHash::of_bytes(&bytes) != *id {
        return Err(Error::invalid("source object hash mismatch"));
    }
    Ok(bytes)
}

pub(crate) fn write(root: &Root, bytes: &[u8], max_bytes: usize) -> Result<ContentHash> {
    if bytes.len() > max_bytes {
        return Err(Error::limit());
    }
    let id = ContentHash::of_bytes(bytes);
    let path = root.object_path(&id.as_str()[7..])?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = root.directory().join(format!(
        ".ctxql-source-tmp-{}-{sequence}",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| backend("source object temporary creation"))?;
    let write_result = (|| {
        let opened = file
            .metadata()
            .map_err(|_| backend("source object metadata"))?;
        check_private_file(&opened)?;
        root.check()?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| backend("source object write"))?;
        let after = file
            .metadata()
            .map_err(|_| backend("source object metadata"))?;
        if !same_identity(&opened, &after) || after.len() != bytes.len() as u64 {
            return Err(Error::invalid("source object changed while writing"));
        }
        drop(file);
        match fs::hard_link(&temporary, &path) {
            Ok(()) => {
                fs::remove_file(&temporary)
                    .map_err(|_| backend("source object temporary cleanup"))?;
                let named =
                    fs::symlink_metadata(&path).map_err(|_| backend("source object metadata"))?;
                check_private_file(&named)?;
                if named.len() != bytes.len() as u64 {
                    return Err(Error::invalid("source object changed while publishing"));
                }
                File::open(root.directory())
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| backend("source-store directory sync"))?;
                root.check()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temporary)
                    .map_err(|_| backend("source object temporary cleanup"))?;
                match read(root, &id, max_bytes) {
                    Ok(existing) if existing == bytes => Ok(()),
                    _ => Err(Error::new(ErrorKind::Conflict, "source object conflict")),
                }
            }
            Err(_) => Err(backend("source object publication")),
        }
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result?;
    Ok(id)
}
