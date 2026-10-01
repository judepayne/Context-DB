use crate::{history, native::NativeResult, snapshot::*, FlureeBackend};
use cdb_core::{
    admission::*, contracts::*, id::IdempotencyKey, snapshot::*, Error, ErrorKind, Timestamp,
};
use std::sync::Arc;
pub(crate) fn map(e: Box<dyn std::error::Error + Send + Sync>) -> Error {
    if let Some(e) = e.downcast_ref::<Error>() {
        return e.clone();
    }
    // Native boxed strings have no reliable taxonomy: do not guess from text.
    Error::new(ErrorKind::Backend, e.to_string())
}
impl FlureeBackend {
    pub(crate) async fn ensure_audited(&self, s: &SnapshotRef) -> NativeResult<()> {
        self.validate_snapshot(s).await?;
        let p = history::pin(s)?;
        let mut cache = self.audited.lock().await;
        if cache.as_ref().is_some_and(|c| c.pin == p) {
            return Ok(());
        }
        let base = cache.as_ref().filter(|c| c.pin.t < p.t).cloned();
        let verified = history::audit_from(&self.native, &self.options, &p, base).await?;
        if cache.as_ref().is_none_or(|c| c.pin.t <= p.t) {
            *cache = Some(verified);
        }
        Ok(())
    }
    pub(crate) async fn audit_snapshot(&self, s: &SnapshotRef) -> NativeResult<Vec<ChangeBatch>> {
        self.validate_snapshot(s).await?;
        history::audit(&self.native, &self.options, &history::pin(s)?).await
    }
}
impl GraphBackend for FlureeBackend {
    fn capabilities(&self) -> cdb_core::Result<BackendCapabilities> {
        Ok(BackendCapabilities {
            exact_snapshots: true,
            ordered_changes: true,
            atomic_admission: true,
            closed_cutoff: true,
            complete_exports: true,
        })
    }
    fn head(&self) -> IoFuture<'_, SnapshotRef> {
        Box::pin(async move {
            let s = FlureeBackend::head(self).await.map_err(map)?;

            Ok(s)
        })
    }
    fn admit<'a>(
        &'a self,
        key: &'a IdempotencyKey,
        batch: &'a AdmissionBatch,
    ) -> IoFuture<'a, AdmissionReceipt> {
        Box::pin(async move { FlureeBackend::admit(self, key, batch).await.map_err(map) })
    }
    fn receipt<'a>(&'a self, key: &'a IdempotencyKey) -> IoFuture<'a, Option<AdmissionReceipt>> {
        Box::pin(async move { FlureeBackend::receipt(self, key).await.map_err(map) })
    }
    fn capture(&self, t: Option<Timestamp>) -> IoFuture<'_, CapturedSnapshot> {
        Box::pin(async move { FlureeBackend::capture(self, t).await.map_err(map) })
    }
    fn open_snapshot<'a>(&'a self, s: &'a SnapshotRef) -> IoFuture<'a, Arc<dyn BackendSnapshot>> {
        Box::pin(async move {
            self.ensure_audited(s).await.map_err(map)?;
            Ok(Arc::new(ExactSnapshot {
                native: self.native.clone(),
                options: self.options.clone(),
                identity: s.clone(),
            }) as Arc<dyn BackendSnapshot>)
        })
    }
    fn changes<'a>(
        &'a self,
        after: &'a SnapshotRef,
        through: &'a SnapshotRef,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ChangeBatch>> {
        Box::pin(async move {
            self.validate_snapshot(after).await.map_err(map)?;
            let all = self.audit_snapshot(through).await.map_err(map)?;
            let a = history::pin(after).map_err(map)?.t;
            let b = history::pin(through).map_err(map)?.t;
            if a > b {
                return Err(Error::new(ErrorKind::Snapshot, "reversed history range"));
            }
            let items = all
                .into_iter()
                .filter(|b| {
                    b.result()
                        .pin()
                        .revision()
                        .as_str()
                        .parse::<i64>()
                        .is_ok_and(|t| t > a)
                })
                .collect::<Vec<_>>();
            page(&items, through, changes_stream(after), cursor, size)
        })
    }
    fn subscribe(&self) -> IoFuture<'_, Box<dyn ChangeHintSource>> {
        Box::pin(async move {
            Ok(Box::new(crate::hints::Hints::new(
                self.native.clone(),
                self.options.clone(),
            )) as Box<dyn ChangeHintSource>)
        })
    }
}

impl ArtifactRepository for FlureeBackend {
    fn publish<'a>(
        &'a self,
        artifact: &'a cdb_core::artifact::PublishedArtifact,
    ) -> IoFuture<'a, cdb_core::artifact::ArtifactRef> {
        Box::pin(async move {
            let batch = AdmissionBatch::new(
                vec![],
                vec![],
                vec![],
                vec![artifact.clone()],
                cdb_core::CanonicalValue::object([])?,
                self.options.codec_limits,
            )?;
            let key =
                IdempotencyKey::new(format!("artifact-publication:{}", batch.digest().as_str()))?;
            FlureeBackend::admit(self, &key, &batch)
                .await
                .map_err(map)?;
            Ok(artifact.reference().clone())
        })
    }
    fn lookup<'a>(
        &'a self,
        reference: &'a cdb_core::artifact::ArtifactRef,
    ) -> IoFuture<'a, Option<cdb_core::artifact::PublishedArtifact>> {
        Box::pin(async move {
            let pin = FlureeBackend::head(self).await.map_err(map)?;
            GraphBackend::open_snapshot(self, &pin)
                .await?
                .artifact(reference)
                .await
        })
    }
    fn record_run<'a>(&'a self, run: &'a cdb_core::replay::ExecutionRun) -> IoFuture<'a, ()> {
        Box::pin(async move { self.record_legacy_run(run).await })
    }
    fn run<'a>(
        &'a self,
        id: &'a cdb_core::id::RunId,
    ) -> IoFuture<'a, Option<cdb_core::replay::ExecutionRun>> {
        Box::pin(async move { self.read_legacy_run(id).await })
    }
    fn record_assembly<'a>(
        &'a self,
        _: &'a cdb_core::replay::AssemblyInvocation,
    ) -> IoFuture<'a, ()> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "assemblies not supported",
            ))
        })
    }
}
