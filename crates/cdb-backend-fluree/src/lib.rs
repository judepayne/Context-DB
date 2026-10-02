//! Embedded managed Fluree authority (P3 implementation in progress).
#![forbid(unsafe_code)]

pub mod backend_identity;
pub mod native;
pub use native::{NativeLimits, NativeResult};
pub mod acquisition_catalog;
pub mod acquisition_control;
pub mod acquisition_writer;
mod authority;
#[cfg(test)]
mod authority_tests;
pub mod authorized_view;
mod backend;
pub mod control;
pub mod current_reasoning_profile;
mod exact_term;
pub mod executable_profile_v3;
pub mod execution_authorization;
pub mod fresh_semantic;
mod hints;
mod history;
mod journal;
#[cfg(test)]
mod native_tests;
pub mod official_bootstrap;
pub mod ontology_compatibility;
pub mod ontology_construct_audit;
pub mod ontology_conversion;
pub mod ontology_dependency_universe;
pub mod ontology_profile;
pub mod ontology_profile_load;
pub mod ontology_profile_v2;
pub mod ontology_profile_v3;
pub mod ontology_release;
#[cfg(test)]
mod review_h1_h2_tests;
mod snapshot;
pub use snapshot::{changes_stream, export_stream};
mod legacy_runs;
pub mod options;
pub mod policy;
pub mod reasoning_sandbox;
pub mod review_codec;
pub mod runs;
pub mod semantic;
pub mod semantic_codec;
pub mod semantic_policy;
pub mod semantic_preparation;
pub use acquisition_catalog::{CaptureEntityResolver, CertifiedOntologyCatalog};
pub use acquisition_control::FlureeAcquisitionControl;
pub use acquisition_writer::{FlureeSemanticWriter, SemanticWriterOptions};
pub use authority::{Authority, FlureeBackend};
pub use control::FlureeControlLedger;
pub use options::{AuthorityOptions, SystemClock, WallClock};
pub use semantic::{FlureeSemanticLedger, SemanticLedgerOptions};
