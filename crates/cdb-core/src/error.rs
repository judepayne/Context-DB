use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Invalid,
    Unsupported,
    Limit,
    Range,
    Arithmetic,
    NotFound,
    Conflict,
    Snapshot,
    Backend,
    Denied,
    PolicyChanged,
    Deadline,
}
/// Internal diagnostics: deliberately not Serialize. Never expose Display on a policy path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}
impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Invalid, message)
    }
    pub fn limit() -> Self {
        Self::new(ErrorKind::Limit, "operational budget exhausted")
    }
    pub fn public_code(&self) -> &'static str {
        match self.kind {
            ErrorKind::Denied => "access_denied",
            ErrorKind::PolicyChanged => "policy_changed",
            _ => "preparation_failed",
        }
    }
    pub fn public_json(&self) -> String {
        format!("{{\"error\":\"{}\"}}", self.public_code())
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}
impl std::error::Error for Error {}
