use cdb_core::{Error, ErrorKind, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Debug)]
pub(crate) struct Root {
    path: PathBuf,
    metadata: fs::Metadata,
}

impl Root {
    pub(crate) fn open(path: PathBuf) -> Result<Self> {
        if !path.is_absolute() {
            return Err(Error::invalid("source-store root must be absolute"));
        }
        if fs::canonicalize(&path).map_err(|_| backend("source-store root"))? != path {
            return Err(Error::invalid("source-store root must be canonical"));
        }
        check_directory_chain(&path)?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| backend("source-store root"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::invalid(
                "source-store root must be a non-symlink directory",
            ));
        }
        #[cfg(unix)]
        if metadata.mode() & 0o777 != 0o700 {
            return Err(Error::invalid("source-store root must have mode 0700"));
        }
        Ok(Self { path, metadata })
    }

    pub(crate) fn object_path(&self, digest: &str) -> Result<PathBuf> {
        if digest.len() != 64
            || !digest
                .as_bytes()
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(Error::invalid("invalid source-object digest"));
        }
        self.check()?;
        Ok(self.path.join(digest))
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.path
    }

    pub(crate) fn check(&self) -> Result<()> {
        if fs::canonicalize(&self.path).map_err(|_| backend("source-store root"))? != self.path {
            return Err(Error::invalid("source-store root changed"));
        }
        check_directory_chain(&self.path)?;
        let current = fs::symlink_metadata(&self.path).map_err(|_| backend("source-store root"))?;
        if !same_identity(&self.metadata, &current)
            || !current.is_dir()
            || current.file_type().is_symlink()
        {
            return Err(Error::invalid("source-store root changed"));
        }
        #[cfg(unix)]
        if current.mode() & 0o777 != 0o700 {
            return Err(Error::invalid("source-store root permissions changed"));
        }
        Ok(())
    }
}

fn check_directory_chain(path: &Path) -> Result<()> {
    for component in path.ancestors() {
        let metadata =
            fs::symlink_metadata(component).map_err(|_| backend("source-store root component"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::invalid("source-store root contains a symlink"));
        }
        #[cfg(unix)]
        if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
            return Err(Error::invalid("unsafe source-store root ancestor"));
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.file_type() == right.file_type()
        && left.uid() == right.uid()
}

#[cfg(not(unix))]
pub(crate) fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type() == right.file_type()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

pub(crate) fn check_private_file(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::invalid("source object is not a regular file"));
    }
    #[cfg(unix)]
    if metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
        return Err(Error::invalid(
            "source object permissions or links are unsafe",
        ));
    }
    Ok(())
}

pub(crate) fn backend(message: &'static str) -> Error {
    Error::new(ErrorKind::Backend, message)
}
