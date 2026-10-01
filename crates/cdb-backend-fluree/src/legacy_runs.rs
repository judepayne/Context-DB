//! Trusted host-only unsealed v1 summaries. Not exposed through service routes.
use crate::{backend::map, journal::decode, FlureeBackend};
use cdb_core::{
    admission::*,
    id::*,
    replay::{CoreSummaryKey, ExecutionRun},
    CanonicalValue as V, Error, ErrorKind, Result,
};
use std::sync::Arc;

impl FlureeBackend {
    async fn legacy_run_locked(&self, id: &RunId) -> Result<Option<ExecutionRun>> {
        let key = CoreSummaryKey::new(id.clone());
        let pin = self.native.head().await.map_err(map)?;
        let Some(raw) = self
            .keyed(&pin, "record", &resource_key(key.descriptor_id()?.as_str()))
            .await
            .map_err(map)?
        else {
            return Ok(None);
        };
        Ok(Some(key.from_record(
            &decode(&raw, self.options.codec_limits).map_err(map)?,
            self.options.codec_limits,
        )?))
    }
    pub(crate) async fn read_legacy_run(&self, id: &RunId) -> Result<Option<ExecutionRun>> {
        let _gate = self.mutation_gate.lock().await;
        self.legacy_run_locked(id).await
    }
    pub(crate) async fn record_legacy_run(&self, run: &ExecutionRun) -> Result<()> {
        let key = CoreSummaryKey::new(run.id().clone());
        let ExportRecord::Resource(record) = key.to_record(run, self.options.codec_limits)? else {
            unreachable!()
        };
        let batch = AdmissionBatch::new(
            vec![],
            vec![],
            vec![ResourceChange::Add(record)],
            vec![],
            V::object([])?,
            self.options.codec_limits,
        )?;
        let admission_key = IdempotencyKey::new(key.descriptor_id()?.as_str())?;
        let gate = Arc::new(self.mutation_gate.clone().lock_owned().await);
        if let Some(old) = self.legacy_run_locked(run.id()).await? {
            return if &old == run {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::Conflict,
                    "legacy run identity conflict",
                ))
            };
        }
        // Ordinary nonreserved immutable admission retains journal, clock/origin,
        // prospective bounds and cancellation-surviving owned gate semantics.
        self.admit_locked(&admission_key, &batch, false, gate)
            .await
            .map_err(map)?;
        Ok(())
    }
}
