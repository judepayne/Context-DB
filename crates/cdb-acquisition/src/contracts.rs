use crate::candidates::AdvisoryBundle;
use crate::state::Failure;
use crate::windows::{DocumentKind, Window, WindowConfig};
use cdb_core::id::{ContentHash, Iri};
use cdb_core::{CanonicalValue, Result};
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderWindow {
    pub document_id: String,
    pub window_id: String,
    pub locator: Iri,
    pub text_version: ContentHash,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderItemOutcome {
    Candidates(Vec<AdvisoryBundle>),
    NoClaims,
    Failed(Failure),
}

pub trait ExtractionProvider {
    /// Implementations must preserve request order and return one outcome per item.
    fn extract(&mut self, windows: &[ProviderWindow]) -> Result<Vec<ProviderItemOutcome>>;
}

pub trait DocumentConverter {
    fn convert(&self, original: &[u8], media_type: &str) -> Result<(String, ContentHash)>;
}
pub trait WindowPlanner {
    fn plan(&self, text: &str, kind: DocumentKind, config: &WindowConfig) -> Result<Vec<Window>>;
}
pub trait OntologyLookup {
    fn describe(&self, capture: &str, iri: &Iri) -> Result<Option<CanonicalValue>>;
}
pub trait EntityResolver {
    fn resolve(
        &self,
        capture: &str,
        text_version: &ContentHash,
        extraction_run: &str,
        local_key: &str,
        source_spelling: &str,
        proposed_type: &Iri,
    ) -> Result<Iri>;
}
pub trait BundleValidator {
    type ValidatedBundle;
    fn validate(&self, candidate: AdvisoryBundle) -> Result<Self::ValidatedBundle>;
}

pub trait CancellationCheckpoint {
    fn cancelled(&self) -> bool;
}

/// Non-serializable, issuer-bound authority marker. Cloning preserves the
/// unforgeable in-process issuer allocation rather than creating bearer data.
#[derive(Clone, Debug)]
pub struct IssuerHandle {
    issuer: Arc<()>,
    scope: String,
}
impl IssuerHandle {
    pub fn issue(scope: impl Into<String>) -> Self {
        Self {
            issuer: Arc::new(()),
            scope: scope.into(),
        }
    }
    pub fn same_issuer(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.issuer, &other.issuer)
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn issuer_handles_cannot_be_recreated_from_scope() {
        let a = IssuerHandle::issue("run");
        let clone = a.clone();
        let foreign = IssuerHandle::issue("run");
        assert!(a.same_issuer(&clone));
        assert!(!a.same_issuer(&foreign));
    }
}
