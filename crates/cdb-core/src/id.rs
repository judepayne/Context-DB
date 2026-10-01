use crate::{Error, Result};
use sha2::{Digest, Sha256};
fn identifier(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control) {
        return Err(Error::invalid(
            "nonempty control-free identifier <=4096 bytes required",
        ));
    }
    Ok(())
}
macro_rules! ids {($($name:ident),+)=>{$(#[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)] pub struct $name(String);impl $name{pub fn new(s:impl Into<String>)->Result<Self>{let s=s.into();identifier(&s)?;Ok(Self(s))}pub fn as_str(&self)->&str{&self.0}})+};}
ids!(
    ClaimId,
    EntityId,
    ResourceId,
    PrincipalId,
    AuthorityId,
    GraphId,
    BackendId,
    VersionId,
    RunId,
    JobId,
    DocumentId,
    ExtractionRunId,
    AttemptId,
    WindowId,
    BundleId,
    OperationId,
    IdempotencyKey,
    SourceId,
    FragmentId,
    InvocationId
);
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Iri(String);
impl Iri {
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        identifier(&s)?;
        if s.chars().any(|c| {
            c.is_whitespace() || matches!(c, '<' | '>' | '"' | '{' | '}' | '|' | '\\' | '^' | '`')
        }) {
            return Err(Error::invalid("forbidden IRI character"));
        }
        let b = s.as_bytes();
        for (i, c) in b.iter().enumerate() {
            if *c == b'%'
                && !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                    && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
            {
                return Err(Error::invalid("IRI percent escape"));
            }
        }
        let parsed = url::Url::parse(&s).map_err(|_| Error::invalid("absolute IRI required"))?;
        if matches!(parsed.scheme(), "http" | "https" | "ftp") {
            let rest = s
                .split_once(':')
                .ok_or_else(|| Error::invalid("IRI scheme"))?
                .1;
            if !rest.starts_with("//") || rest[2..].starts_with('/') || rest[2..].is_empty() {
                return Err(Error::invalid("IRI authority cannot require repair"));
            }
        }
        Ok(Self(s))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn http(s: impl Into<String>) -> Result<Self> {
        let iri = Self::new(s)?;
        let u = url::Url::parse(&iri.0).map_err(|_| Error::invalid("HTTP IRI"))?;
        if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
            return Err(Error::invalid("HTTP(S) IRI with host required"));
        }
        Ok(iri)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ContentHash(String);
impl ContentHash {
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.len() != 71
            || !s.starts_with("sha256:")
            || !s.as_bytes()[7..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(Error::invalid("sha256 lowercase digest required"));
        }
        Ok(Self(s))
    }
    /// Raw byte hash, not a canonical domain hash.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(format!("sha256:{:x}", Sha256::digest(bytes)))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
