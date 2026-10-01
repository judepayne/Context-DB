//! Bounded, lossless JSON compilation and pure common-predicate semantics.
pub mod artifacts;
pub mod compiler;
pub use compiler::load_recorded_plan;
pub mod diagnostics;
pub mod execution;
pub mod frontend;
pub mod lexical;
pub mod options;
pub mod predicates;
pub mod values;
