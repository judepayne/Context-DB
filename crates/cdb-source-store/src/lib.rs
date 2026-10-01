//! Immutable, content-addressed source objects and representation manifests.
//!
//! Object paths are always derived from validated SHA-256 identities. Callers receive
//! distinct reader and writer capabilities and can never supply an object path.

mod manifest;
mod object;
mod path;
mod reader;
mod writer;

pub use manifest::{
    ConverterManifest, Normalization, OriginalRepresentationManifest, TextRepresentationManifest,
};
pub use reader::SourceObjectReader;
pub use writer::{SourceObjectWriter, StoredOriginal, StoredText};

impl cdb_core::acquisition::SourceObjectReader for SourceObjectReader {
    fn read<'a>(
        &'a self,
        hash: &'a cdb_core::id::ContentHash,
        max_bytes: usize,
    ) -> cdb_core::contracts::IoFuture<'a, cdb_core::acquisition::SourceObject> {
        Box::pin(async move {
            let bytes = self.read_object(hash)?;
            cdb_core::acquisition::SourceObject::new(hash.clone(), bytes, max_bytes)
        })
    }
}

impl cdb_core::acquisition::SourceObjectWriter for SourceObjectWriter {
    fn put<'a>(
        &'a self,
        bytes: &'a [u8],
        max_bytes: usize,
    ) -> cdb_core::contracts::IoFuture<'a, cdb_core::id::ContentHash> {
        Box::pin(async move {
            if bytes.len() > max_bytes {
                return Err(cdb_core::Error::limit());
            }
            self.put_object(bytes)
        })
    }
}
