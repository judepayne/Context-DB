use cdb_core::{Error, ErrorKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileNotice {
    IgnoredProfileAbout,
}
impl CompileNotice {
    pub fn code(self) -> &'static str {
        match self {
            Self::IgnoredProfileAbout => "ignored_profile_about",
        }
    }
}
pub(crate) fn unsupported(capability: &'static str) -> Error {
    Error::new(ErrorKind::Unsupported, capability)
}
/// Stable redacted code; internal Error messages must not cross a policy boundary.
pub fn public_code(error: &Error) -> &'static str {
    match error.kind {
        ErrorKind::Unsupported => "unsupported_capability",
        ErrorKind::Invalid | ErrorKind::Range | ErrorKind::Arithmetic => {
            "validation_or_evaluation_failed"
        }
        ErrorKind::Limit | ErrorKind::Deadline => "operational_exhaustion",
        _ => error.public_code(),
    }
}
