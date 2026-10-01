//! Explicitly selected in-memory CTXQL contract-test adapters, not production services.
//!
//! Trusted fixture principal handles cannot be provisioned from client JSON:
//! ```compile_fail
//! use cdb_testkit::memory::MemoryPrincipal;
//! let _: MemoryPrincipal = serde_json::from_str(r#"{"id":"admin"}"#).unwrap();
//! ```
//! Nor can a caller fabricate a source permission by constructing its fields:
//! ```compile_fail
//! use cdb_testkit::sources::SelectorAuthorization;
//! fn forge(request: cdb_core::source::SourceReadRequest) -> SelectorAuthorization {
//!     SelectorAuthorization { issuer: std::sync::Arc::new(()), request }
//! }
//! ```
pub mod assertions;
pub mod memory;
pub mod projection;
pub mod reference_fixture;
pub mod sources;
