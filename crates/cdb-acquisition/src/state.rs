//! Transient extraction failure classification.
//!
//! Durable job, bundle, prepared-admission, and receipt types are owned by
//! `cdb_core::acquisition` and `cdb_core::semantic_admission`; this module
//! intentionally does not define parallel persistence DTOs.

pub use cdb_core::acquisition::{AcquisitionFailureClass as FailureClass, BundleState, JobState};
use cdb_core::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure {
    pub class: FailureClass,
    code: String,
}
impl Failure {
    pub fn new(class: FailureClass, code: impl Into<String>) -> Result<Self> {
        let code = code.into();
        if code.is_empty()
            || code.len() > 128
            || !code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(Error::invalid("bounded content-free failure code required"));
        }
        Ok(Self { class, code })
    }
    pub fn code(&self) -> &str {
        &self.code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_core_state_machines_are_reexported() {
        assert!(JobState::Created.permits(JobState::Acquiring));
        assert!(!JobState::Completed.permits(JobState::Acquiring));
        assert!(BundleState::Prepared.permits(BundleState::AdmissionUnknown));
        assert!(!BundleState::Conflict.permits(BundleState::Prepared));
    }

    #[test]
    fn diagnostics_are_content_free_and_bounded() {
        assert!(Failure::new(FailureClass::Source, "root_escape").is_ok());
        assert!(Failure::new(FailureClass::Source, "source quote: secret").is_err());
    }
}
