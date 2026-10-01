//! Durable derived redb projection (P3 implementation in progress).
#![forbid(unsafe_code)]
mod catalog;
pub mod provider;
pub use provider::RedbViewProvider;
pub mod coordinator;
pub use coordinator::{Coordinator, CoordinatorOptions, CoordinatorStatus};
pub mod database;
pub use database::{Database, DatabaseOptions, DatabaseView};
pub mod generations;
pub use generations::{GenerationOptions, GenerationView, RedbProjection};
pub mod observer;
pub use observer::RedbProjectionObserver;
