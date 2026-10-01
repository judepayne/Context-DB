//! Role-specific writable Control Ledger wrapper.
//! It preserves the existing `FlureeBackend`/`NativeStore` durability,
//! corruption, journal, idempotency, and recovery invariants unchanged.

use crate::{AuthorityOptions, FlureeBackend, NativeResult};
use cdb_core::id::GraphId;
use std::sync::Arc;

#[derive(Clone)]
pub struct FlureeControlLedger {
    inner: Arc<FlureeBackend>,
}

impl FlureeControlLedger {
    pub async fn create(options: AuthorityOptions) -> NativeResult<Self> {
        Ok(Self {
            inner: Arc::new(FlureeBackend::create(options).await?),
        })
    }

    pub async fn open(options: AuthorityOptions) -> NativeResult<Self> {
        Ok(Self {
            inner: Arc::new(FlureeBackend::open(options).await?),
        })
    }

    pub fn from_backend(inner: Arc<FlureeBackend>) -> Self {
        Self { inner }
    }

    /// Narrow escape hatch for existing control-only artifact/run/policy call
    /// sites during migration. Semantic code never receives this wrapper.
    pub fn backend(&self) -> &Arc<FlureeBackend> {
        &self.inner
    }

    pub fn reject_semantic_alias(&self, semantic_ledger: &GraphId) -> NativeResult<()> {
        if self.inner.options.ledger == semantic_ledger.as_str() {
            return Err("semantic and control ledger identities must differ".into());
        }
        Ok(())
    }
}
