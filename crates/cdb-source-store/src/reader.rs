use crate::{
    manifest::{ConverterManifest, OriginalRepresentationManifest, TextRepresentationManifest},
    object,
    path::Root,
};
use cdb_core::{id::ContentHash, Error, Result};
use std::path::PathBuf;

/// Read-only source-store capability. It has no write or path-based operation.
#[derive(Clone, Debug)]
pub struct SourceObjectReader {
    root: Root,
    max_bytes: usize,
}

impl SourceObjectReader {
    pub fn open(root: PathBuf, max_bytes: usize) -> Result<Self> {
        if max_bytes == 0 {
            return Err(Error::invalid("source-store read limit"));
        }
        Ok(Self {
            root: Root::open(root)?,
            max_bytes,
        })
    }

    /// Reads at most the configured number of bytes and rehashes the complete object.
    pub fn read_object(&self, id: &ContentHash) -> Result<Vec<u8>> {
        object::read(&self.root, id, self.max_bytes)
    }

    pub fn read_converter_manifest(&self, id: &ContentHash) -> Result<ConverterManifest> {
        ConverterManifest::from_bytes(&self.read_object(id)?)
    }

    pub fn read_original_manifest(
        &self,
        id: &ContentHash,
    ) -> Result<OriginalRepresentationManifest> {
        OriginalRepresentationManifest::from_bytes(&self.read_object(id)?)
    }

    pub fn read_text_manifest(&self, id: &ContentHash) -> Result<TextRepresentationManifest> {
        TextRepresentationManifest::from_bytes(&self.read_object(id)?)
    }

    /// Resolves only the hash carried by the trusted manifest; no path enters this API.
    pub fn read_text(&self, manifest: &TextRepresentationManifest) -> Result<String> {
        let bytes = self.read_object(manifest.object())?;
        String::from_utf8(bytes).map_err(|_| Error::invalid("text representation UTF-8"))
    }
}
