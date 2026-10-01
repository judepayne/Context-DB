//! Exact local query preparation; stale selection remains an explicit engine decision.
use crate::{catalog::prepare_catalog, coordinator::Coordinator, generations::RedbProjection};
use cdb_core::{
    contracts::{CapturedSnapshot, IoFuture, ProjectionStore},
    snapshot::SnapshotRef,
    Error, Result,
};
use cdb_engine::execution::{ExecutionOptions, PreparedView, ViewProvider};
use std::{sync::Arc, time::Duration};

pub struct RedbViewProvider {
    coordinator: Arc<Coordinator>,
    store: Arc<RedbProjection>,
    wait_timeout: Duration,
}
impl RedbViewProvider {
    pub fn new(
        coordinator: Arc<Coordinator>,
        store: Arc<RedbProjection>,
        wait_timeout: Duration,
    ) -> Result<Self> {
        if wait_timeout.is_zero() {
            return Err(Error::invalid("projection wait timeout"));
        }
        Ok(Self {
            coordinator,
            store,
            wait_timeout,
        })
    }
}
impl ViewProvider for RedbViewProvider {
    fn propose_stale<'a>(
        &'a self,
        requested: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, Option<SnapshotRef>> {
        Box::pin(async move {
            options.check_interrupted()?;
            let checkpoint = self.store.checkpoint().await?;
            options.check_interrupted()?;
            // A checkpoint is a proposal, not proof. The engine validates the full
            // identity and retained ancestry; an ahead/foreign/corrupt proposal is
            // an error, never a silent exact or latest fallback.
            Ok(checkpoint
                .map(|cp| cp.snapshot().clone())
                .filter(|s| s != &requested.snapshot))
        })
    }
    fn open<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        Box::pin(async move {
            options.check_interrupted()?;
            let timeout = tokio::time::Instant::now()
                .checked_add(self.wait_timeout)
                .ok_or_else(Error::limit)?;
            let deadline = options
                .deadline
                .map(tokio::time::Instant::from_std)
                .map_or(timeout, |d| d.min(timeout));
            let view = self
                .coordinator
                .wait_exact(&captured.snapshot, deadline)
                .await?;
            options.check_interrupted()?;
            let snapshot = captured.snapshot.clone();
            let as_of = captured.as_of;
            let options_owned = options.clone();
            let catalog_view = view.clone();
            let catalog = tokio::task::spawn_blocking(move || {
                prepare_catalog(&snapshot, as_of, &options_owned, |size, cursor| {
                    catalog_view.scan(size, cursor)
                })
            })
            .await
            .map_err(|_| Error::new(cdb_core::ErrorKind::Backend, "catalog task failed"))??;
            options.check_interrupted()?;
            Ok(PreparedView {
                view,
                landing: Arc::new(catalog),
            })
        })
    }
}
