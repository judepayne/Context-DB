//! Truthful identity of the Fluree implementation linked into this crate.

pub use cdb_core::recording_v5::{BACKEND_ID, FLUREE_RELEASE, FLUREE_REVISION, REASONER_PREFIX};

/// The historical supported-subset profile was certified against `603974f`.
/// It remains decodable evidence, but is not executable by this backend.
pub const HISTORICAL_EXECUTOR_UNAVAILABLE: &str =
    "historical Fluree 603974f executor unavailable; archival decoding only";
