//! Compile-time identity for the native executor.
//! This identifies installed code; it is not a published artifact or authority.
use cdb_core::{
    id::{ContentHash, ResourceId, VersionId},
    recording::RecordingEngine,
    Result,
};

pub const EXECUTOR_NAME: &str = "ctxql-native-executor";

pub fn build() -> Result<ContentHash> {
    ContentHash::parse(env!("CDB_NATIVE_EXECUTOR_BUILD"))
}

/// Exact executor identity stored separately from the portable engine identity.
pub fn executor() -> Result<RecordingEngine> {
    Ok(RecordingEngine {
        name: ResourceId::new(EXECUTOR_NAME)?,
        version: VersionId::new(env!("CARGO_PKG_VERSION"))?,
        build: build()?,
    })
}
