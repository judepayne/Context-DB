use crate::{
    manifest::{ConverterManifest, OriginalRepresentationManifest, TextRepresentationManifest},
    object,
    path::Root,
};
use cdb_core::{id::ContentHash, Error, Result};
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredOriginal {
    object: ContentHash,
    manifest: ContentHash,
}

impl StoredOriginal {
    pub fn object(&self) -> &ContentHash {
        &self.object
    }

    pub fn manifest(&self) -> &ContentHash {
        &self.manifest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredText {
    object: ContentHash,
    manifest: ContentHash,
    version: ContentHash,
}

impl StoredText {
    pub fn object(&self) -> &ContentHash {
        &self.object
    }

    pub fn manifest(&self) -> &ContentHash {
        &self.manifest
    }

    pub fn version(&self) -> &ContentHash {
        &self.version
    }
}

/// Write-only source-store capability. Existing objects are read internally only to
/// implement create-new-or-verify; no read operation is exposed to callers.
#[derive(Clone, Debug)]
pub struct SourceObjectWriter {
    root: Root,
    max_bytes: usize,
}

impl SourceObjectWriter {
    pub fn open(root: PathBuf, max_bytes: usize) -> Result<Self> {
        if max_bytes == 0 {
            return Err(Error::invalid("source-store write limit"));
        }
        Ok(Self {
            root: Root::open(root)?,
            max_bytes,
        })
    }

    /// Stores immutable bytes at `<root>/<lowercase sha256 hex>`.
    pub fn put_object(&self, bytes: &[u8]) -> Result<ContentHash> {
        object::write(&self.root, bytes, self.max_bytes)
    }

    pub fn put_converter_manifest(&self, manifest: &ConverterManifest) -> Result<ContentHash> {
        self.put_object(&manifest.canonical_bytes()?)
    }

    pub fn put_original(
        &self,
        bytes: &[u8],
        media_type: impl Into<String>,
        acquisition_metadata_root: ContentHash,
    ) -> Result<StoredOriginal> {
        let object = self.put_object(bytes)?;
        let representation = OriginalRepresentationManifest::new(
            object.clone(),
            media_type,
            acquisition_metadata_root,
        )?;
        let manifest = self.put_object(&representation.canonical_bytes()?)?;
        Ok(StoredOriginal { object, manifest })
    }

    pub fn put_text(
        &self,
        text: &[u8],
        original_manifest: ContentHash,
        converter_manifest: ContentHash,
    ) -> Result<StoredText> {
        if text.is_empty() || std::str::from_utf8(text).is_err() {
            return Err(Error::invalid(
                "text representation must be non-empty UTF-8",
            ));
        }
        // Derivation references must already be immutable, valid manifests in this store.
        OriginalRepresentationManifest::from_bytes(&object::read(
            &self.root,
            &original_manifest,
            self.max_bytes,
        )?)?;
        ConverterManifest::from_bytes(&object::read(
            &self.root,
            &converter_manifest,
            self.max_bytes,
        )?)?;

        let object = self.put_object(text)?;
        let representation =
            TextRepresentationManifest::new(object.clone(), original_manifest, converter_manifest)?;
        let version = representation.version().clone();
        let stored_version = self.put_object(&representation.version_bytes()?)?;
        if stored_version != version {
            return Err(Error::invalid("text version commitment mismatch"));
        }
        let manifest = self.put_object(&representation.canonical_bytes()?)?;
        Ok(StoredText {
            object,
            manifest,
            version,
        })
    }
}
