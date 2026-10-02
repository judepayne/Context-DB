//! Authenticated local composition layer; P4 integration in progress.
#![forbid(unsafe_code)]
pub mod acquisition;
mod acquisition_checkpoints;
pub mod acquisition_inspection;
pub mod acquisition_v2_fixture;
mod acquisition_work;
pub mod auth;
pub mod broker;
pub mod chat;
pub mod config;
pub mod entity_lookup;
#[allow(dead_code)]
mod graph_capture;
#[allow(dead_code)]
mod graph_context;
#[allow(dead_code)]
mod graph_query;
#[allow(dead_code)]
mod graph_read_only;
#[allow(dead_code)]
mod graph_session;
#[allow(dead_code, unused_imports)]
mod graph_workspace;
pub mod http;
pub mod ingest;
pub mod native_identity;
pub mod ontology_briefing;
mod ontology_direct;
mod ontology_mapping;
mod passage_context;
pub mod predicates;
pub mod runtime;
pub mod semantic_bootstrap;
mod semantic_vocabulary;
pub mod service;
pub mod source_target;
pub mod sources;
pub use service::Service;
