use crate::Coordinator;
use cdb_core::acquisition::ProjectionObserver;
use cdb_core::contracts::IoFuture;
use cdb_core::semantic_admission::{ProjectionReceipt, SemanticAdmissionReceipt};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;

#[derive(Clone)]
pub struct RedbProjectionObserver {
    coordinator: Arc<Coordinator>,
    timeout: Duration,
}
impl RedbProjectionObserver {
    pub fn new(coordinator: Arc<Coordinator>, timeout: Duration) -> cdb_core::Result<Self> {
        if timeout.is_zero() {
            return Err(cdb_core::Error::invalid("projection observer timeout"));
        }
        Ok(Self {
            coordinator,
            timeout,
        })
    }
}
impl ProjectionObserver for RedbProjectionObserver {
    fn wait_exact<'a>(
        &'a self,
        admission: &'a SemanticAdmissionReceipt,
    ) -> IoFuture<'a, ProjectionReceipt> {
        Box::pin(async move {
            let pin = admission.snapshot();
            self.coordinator
                .wait_exact(pin, Instant::now() + self.timeout)
                .await?;
            ProjectionReceipt::new(admission.admission_key().clone(), pin.clone(), pin.clone())
        })
    }
}
