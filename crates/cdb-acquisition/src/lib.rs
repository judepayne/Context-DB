//! Backend-neutral trusted-acquisition contracts and deterministic host logic.
//! Windows and provider candidates are transient; this crate persists neither.

pub mod candidates;
pub mod contracts;
pub mod coordinates;
pub mod coordinator;
pub mod document_entities;
pub mod eval;
pub mod lineage;
pub mod outcomes;
pub mod proposals;
pub mod source;
pub mod state;
pub mod validator;
pub mod windows;

pub use cdb_core::id::ContentHash;
