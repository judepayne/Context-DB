//! Bounded operational check receipts. Never part of semantic function roots.
use cdb_backend_fluree::execution_authorization::{AuthorizationCheckReceipt, ReleaseFootprint};
use cdb_core::{
    id::ResourceId, recording_v3::ReleaseEvidenceV3, snapshot::SnapshotRef, CanonicalValue as V,
    Error, Limits, Result,
};
use std::sync::Mutex;

pub struct AuthorizationLog {
    limits: Limits,
    max_bytes: usize,
    max_actions: usize,
    state: Mutex<State>,
}
struct State {
    bytes: usize,
    entries: Vec<ReleaseEvidenceV3>,
}
pub struct ReceiptReservation {
    action: ResourceId,
    bytes: usize,
}
impl AuthorizationLog {
    pub fn new(limits: Limits, max_bytes: usize, max_actions: usize) -> Self {
        Self {
            limits,
            max_bytes,
            max_actions,
            state: Mutex::new(State {
                bytes: 0,
                entries: vec![],
            }),
        }
    }
    /// Caller holds per-execution coordination through reserve/check/append.
    /// Native heads retain authority/graph identifiers; reserve ample space beyond
    /// the original encoding for its generated revision/receipt identifiers.
    pub fn reserve(
        &self,
        action: ResourceId,
        footprint: &ReleaseFootprint,
        basis: &SnapshotRef,
    ) -> Result<ReceiptReservation> {
        let requirements = footprint.requirements(self.limits)?;
        let bytes = requirements
            .projection()
            .canonical_bytes(self.limits)?
            .len()
            .checked_add(
                cdb_core::record_codec::snapshot_value(basis)
                    .canonical_bytes(self.limits)?
                    .len(),
            )
            .and_then(|n| n.checked_add(action.as_str().len()))
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(Error::limit)?;
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.entries.len() >= self.max_actions
            || bytes > self.max_bytes.saturating_sub(state.bytes)
        {
            return Err(Error::limit());
        }
        Ok(ReceiptReservation { action, bytes })
    }
    pub fn append(
        &self,
        reservation: ReceiptReservation,
        receipt: AuthorizationCheckReceipt,
    ) -> Result<()> {
        let evidence = receipt.release_evidence(reservation.action, self.limits)?;
        let bytes = evidence.projection().canonical_bytes(self.limits)?.len();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if bytes > reservation.bytes
            || state.entries.len() >= self.max_actions
            || bytes > self.max_bytes.saturating_sub(state.bytes)
        {
            return Err(Error::limit());
        }
        state.bytes += bytes;
        state.entries.push(evidence);
        Ok(())
    }
    pub fn values(&self) -> Vec<V> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .iter()
            .map(ReleaseEvidenceV3::projection)
            .collect()
    }
}
