//! Validated finite preparation records, not an overlay executor or source connector.
use crate::{
    id::{ContentHash, SourceId},
    source::{ExternalSnapshot, NeutralRow, PreparationMode},
    CanonicalValue as V, Error, ErrorKind, Limits, Result, Timestamp,
};
use std::collections::BTreeSet;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSource {
    source_id: SourceId,
    mode: PreparationMode,
    snapshot: ExternalSnapshot,
    rows: Vec<NeutralRow>,
    observed_at: Timestamp,
    digest: ContentHash,
}
impl PreparedSource {
    pub fn new(
        source_id: SourceId,
        mode: PreparationMode,
        snapshot: ExternalSnapshot,
        rows: Vec<NeutralRow>,
        observed_at: Timestamp,
        historical_as_of: Option<Timestamp>,
        limits: Limits,
    ) -> Result<Self> {
        if mode == PreparationMode::Live && historical_as_of.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "unsupported_temporal_live_overlay",
            ));
        }
        if rows.len() > limits.values() {
            return Err(Error::limit());
        }
        let mut keys = BTreeSet::new();
        let mut wires = Vec::new();
        for row in &rows {
            let wire = row.projection();
            if wire.field("source_id")?.as_str()? != source_id.as_str()
                || wire.field("snapshot_ref")? != &snapshot.projection()
            {
                return Err(Error::invalid("prepared row source/snapshot mismatch"));
            }
            if !keys.insert(wire.field("row_key")?.canonical_bytes(limits)?) {
                return Err(Error::invalid("duplicate prepared row key"));
            }
            wires.push(wire);
        }
        let digest = ContentHash::of_bytes(&V::Array(wires).canonical_bytes(limits)?);
        Ok(Self {
            source_id,
            mode,
            snapshot,
            rows,
            observed_at,
            digest,
        })
    }
    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }
    pub fn mode(&self) -> PreparationMode {
        self.mode
    }
    pub fn snapshot(&self) -> &ExternalSnapshot {
        &self.snapshot
    }
    pub fn rows(&self) -> &[NeutralRow] {
        &self.rows
    }
    pub fn observed_at(&self) -> Timestamp {
        self.observed_at
    }
    pub fn digest(&self) -> &ContentHash {
        &self.digest
    }
}
