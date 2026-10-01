//! Isolated Pi transport and strict P6 provider-output parser.
//!
//! This crate intentionally contains no semantic admission authority. Model
//! output remains advisory until validated by the acquisition host.

pub mod advisory;
pub mod agent_bundle;
pub mod cancel;
pub mod chat_transport;
pub mod fact_blocks;
pub mod ontology_bridge;
pub mod parser;
pub mod proposal_protocol;
pub mod proposal_text;
pub mod provider;
mod session_logging;
pub use session_logging::SessionLogging;
pub mod transport;
pub mod usage;

pub const MODEL: &str = "openrouter/deepseek/deepseek-v4.1-flash";
/// Pi reports the provider-qualified selection without the provider transport prefix.
pub const RUNTIME_MODEL: &str = "deepseek/deepseek-v4.1-flash";
pub const THINKING: &str = "high";
