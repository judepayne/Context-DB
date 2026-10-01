//! Event worker adapted (with the owner's authorization) from hmem-runtime
//! `fluree_ctx.rs::start_ctx_projector_worker`: subscribe, receive, fold, lag and
//! shutdown branches. Native events/local watermarks are replaced by neutral hints
//! and durable checkpoints; errors retry independently and lag never clears data.
use crate::{GenerationView, RedbProjection};
use cdb_core::{contracts::*, id::ResourceId, snapshot::*, Error, Result};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, oneshot, watch, Semaphore},
    task::JoinHandle,
    time::{timeout, Instant},
};

#[derive(Clone, Debug)]
pub struct CoordinatorOptions {
    pub repair_interval: Duration,
    pub retry_min: Duration,
    pub retry_max: Duration,
    pub operation_timeout: Duration,
    pub max_waiters: usize,
    pub max_pages: usize,
    pub max_records: usize,
    pub page_size: PageSize,
    pub export_stream: ResourceId,
    pub changes_stream: ResourceId,
}
impl Default for CoordinatorOptions {
    fn default() -> Self {
        Self {
            repair_interval: Duration::from_secs(30),
            retry_min: Duration::from_millis(100),
            retry_max: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(30),
            max_waiters: 64,
            max_pages: 10000,
            max_records: 1000000,
            page_size: PageSize::new(1000).unwrap(),
            export_stream: ResourceId::new("export").unwrap(),
            changes_stream: ResourceId::new("changes").unwrap(),
        }
    }
}
#[derive(Clone, Debug)]
pub enum CoordinatorStatus {
    Starting,
    Ready(ProjectionCheckpoint),
    Degraded(String),
    Stopped,
}
enum Command {
    Reconcile(oneshot::Sender<Result<()>>),
    Exact(
        SnapshotRef,
        Instant,
        oneshot::Sender<Result<Arc<GenerationView>>>,
    ),
}
/// One worker serializes live reconciliation and historical work. Dropping a wait
/// future cancels its queued request. Dropping the coordinator requests stop;
/// `shutdown` additionally joins the worker. Already-returned views stay valid.
pub struct Coordinator {
    commands: mpsc::Sender<Command>,
    stop: watch::Sender<bool>,
    status: watch::Receiver<CoordinatorStatus>,
    slots: Arc<Semaphore>,
    worker: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}
impl Coordinator {
    pub fn start<B: SemanticProjectionSource + 'static>(
        backend: Arc<B>,
        store: Arc<RedbProjection>,
        binding: ProjectionCheckpoint,
        options: CoordinatorOptions,
    ) -> Result<Self> {
        if options.max_waiters == 0
            || options.max_pages == 0
            || options.max_records == 0
            || options.retry_min.is_zero()
            || options.retry_max < options.retry_min
            || options.repair_interval.is_zero()
            || options.operation_timeout.is_zero()
        {
            return Err(Error::invalid("coordinator bounds"));
        }
        let caps = backend.capabilities()?;
        if !caps.exact_snapshots
            || !caps.complete_exports
            || &caps.schema != binding.schema()
            || &caps.algorithm != binding.algorithm()
        {
            return Err(Error::invalid("coordinator backend capabilities"));
        }
        let (commands, rx) = mpsc::channel(options.max_waiters);
        let (stop, stopped) = watch::channel(false);
        let (tx, status) = watch::channel(CoordinatorStatus::Starting);
        let slots = Arc::new(Semaphore::new(options.max_waiters));
        let worker = tokio::spawn(run(
            Work {
                backend,
                store,
                binding,
                options,
                ordered_changes: caps.ordered_changes,
            },
            rx,
            stopped,
            tx,
        ));
        Ok(Self {
            commands,
            stop,
            status,
            slots,
            worker: tokio::sync::Mutex::new(Some(worker)),
        })
    }
    pub fn status(&self) -> watch::Receiver<CoordinatorStatus> {
        self.status.clone()
    }
    /// Explicit repair pulse also provides a deterministic timer hook for tests.
    pub async fn reconcile(&self, deadline: Instant) -> Result<()> {
        if *self.stop.borrow() {
            return Err(Error::invalid("coordinator stopped"));
        }
        let _slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::limit())?;
        let (tx, rx) = oneshot::channel();
        self.commands
            .try_send(Command::Reconcile(tx))
            .map_err(|_| Error::invalid("coordinator stopped or queue full"))?;
        tokio::time::timeout_at(deadline, rx)
            .await
            .map_err(|_| Error::new(cdb_core::ErrorKind::Deadline, "coordinator deadline"))?
            .map_err(|_| Error::invalid("coordinator stopped"))?
    }
    /// Exact historical reconstruction is queued, never substituted by latest.
    pub async fn wait_exact(
        &self,
        pin: &SnapshotRef,
        deadline: Instant,
    ) -> Result<Arc<GenerationView>> {
        if *self.stop.borrow() {
            return Err(Error::invalid("coordinator stopped"));
        }
        let _slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::limit())?;
        let (tx, rx) = oneshot::channel();
        self.commands
            .try_send(Command::Exact(pin.clone(), deadline, tx))
            .map_err(|_| Error::invalid("coordinator stopped or queue full"))?;
        tokio::time::timeout_at(deadline, rx)
            .await
            .map_err(|_| Error::new(cdb_core::ErrorKind::Deadline, "coordinator deadline"))?
            .map_err(|_| Error::invalid("coordinator stopped"))?
    }
    pub async fn historical(
        &self,
        pin: &SnapshotRef,
        deadline: Instant,
    ) -> Result<Arc<GenerationView>> {
        self.wait_exact(pin, deadline).await
    }
    /// Request graceful stop without consuming shared handles.
    pub fn request_stop(&self) {
        let _ = self.stop.send(true);
    }
    pub async fn shutdown(self) -> Result<()> {
        self.shutdown_shared().await
    }
    /// Join through a shared service owner. Concurrent shutdown callers wait for the
    /// same completion; dropping a waiter does not detach or lose the join handle.
    pub async fn shutdown_shared(&self) -> Result<()> {
        self.request_stop();
        let mut worker = self.worker.lock().await;
        if let Some(handle) = worker.as_mut() {
            let result = handle.await;
            worker.take();
            result.map_err(|_| Error::invalid("coordinator worker panicked"))?;
        }
        Ok(())
    }
}
impl Drop for Coordinator {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

struct Work<B> {
    backend: Arc<B>,
    store: Arc<RedbProjection>,
    binding: ProjectionCheckpoint,
    options: CoordinatorOptions,
    ordered_changes: bool,
}
impl<B: SemanticProjectionSource> Work<B> {
    async fn io<T>(&self, future: IoFuture<'_, T>) -> Result<T> {
        timeout(self.options.operation_timeout, future)
            .await
            .unwrap_or_else(|_| {
                Err(Error::new(
                    cdb_core::ErrorKind::Deadline,
                    "backend operation deadline",
                ))
            })
    }
    fn checkpoint(&self, pin: &SnapshotRef) -> Result<ProjectionCheckpoint> {
        if !pin.same_authority(self.binding.snapshot()) {
            return Err(Error::invalid("coordinator foreign authority"));
        }
        ProjectionCheckpoint::new(
            pin.clone(),
            self.binding.schema().clone(),
            self.binding.generation().clone(),
            self.binding.algorithm().clone(),
        )
    }
    async fn export(&self, pin: &SnapshotRef) -> Result<CompleteExport> {
        let snapshot = self.io(self.backend.open_snapshot(pin)).await?;
        if snapshot.identity() != pin {
            return Err(Error::invalid("exact export identity"));
        }
        let mut tracker = None;
        let mut stream = self.options.export_stream.clone();
        let mut pages = Vec::new();
        let mut cursor = None;
        for _ in 0..self.options.max_pages {
            let page = self
                .io(snapshot.export(cursor.as_ref(), self.options.page_size))
                .await?;
            if page.items().len() > self.options.page_size.get() {
                return Err(Error::limit());
            }
            let current_tracker = tracker.get_or_insert_with(|| {
                stream = page
                    .next()
                    .map(|c| c.stream().clone())
                    .unwrap_or_else(|| stream.clone());
                PageTracker::new(pin.clone(), stream.clone(), self.options.max_records)
            });
            current_tracker.accept(cursor.as_ref(), &page)?;
            cursor = page.next().cloned();
            pages.push(page);
            if cursor.is_none() {
                tracker.take().expect("initialized tracker").finish()?;
                return CompleteExport::collect(
                    pin.clone(),
                    stream,
                    pages,
                    self.options.max_records,
                );
            }
        }
        Err(Error::limit())
    }
    async fn reconcile(&self) -> Result<()> {
        let target = self.io(self.backend.head()).await?;
        self.checkpoint(&target)?;
        let Some(mut cp) = self.store.checkpoint().await? else {
            let export = self.export(&target).await?;
            return self.store.build(&export, &self.checkpoint(&target)?).await;
        };
        if !cp.snapshot().same_authority(&target)
            || cp.schema() != self.binding.schema()
            || cp.algorithm() != self.binding.algorithm()
        {
            return Err(Error::invalid("coordinator checkpoint binding"));
        }
        if cp.snapshot() == &target {
            return Ok(());
        }
        if !self.ordered_changes {
            let export = self.export(&target).await?;
            return self
                .store
                .rebuild_live(&export, &self.checkpoint(&target)?)
                .await;
        }
        let after = cp.snapshot().clone();
        let mut cursor = None;
        let mut tracker = None;
        let mut records = 0usize;
        for _ in 0..self.options.max_pages {
            let page = self
                .io(self
                    .backend
                    .changes(&after, &target, cursor.as_ref(), self.options.page_size))
                .await?;
            if page.items().len() > self.options.page_size.get() {
                return Err(Error::limit());
            }
            tracker
                .get_or_insert_with(|| {
                    PageTracker::new(
                        target.clone(),
                        page.next()
                            .map(|c| c.stream().clone())
                            .unwrap_or_else(|| self.options.changes_stream.clone()),
                        self.options.max_records,
                    )
                })
                .accept(cursor.as_ref(), &page)?;
            for batch in page.items() {
                records = records
                    .checked_add(batch.changes().len())
                    .ok_or_else(Error::limit)?;
                if records > self.options.max_records {
                    return Err(Error::limit());
                }
                if batch.predecessor() != cp.snapshot()
                    || batch.result() == cp.snapshot()
                    || cp.snapshot() == &target
                {
                    return Err(Error::invalid("coordinator change progress"));
                }
                cp = self.checkpoint(batch.result())?;
                self.store.apply(batch, &cp).await?;
            }
            cursor = page.next().cloned();
            if cursor.is_none() {
                tracker.take().expect("initialized tracker").finish()?;
                return if cp.snapshot() == &target {
                    Ok(())
                } else {
                    Err(Error::invalid("incomplete change history"))
                };
            }
        }
        Err(Error::limit())
    }
    async fn exact(&self, pin: &SnapshotRef) -> Result<Arc<GenerationView>> {
        let cp = self.checkpoint(pin)?;
        if self.store.checkpoint().await?.is_none() {
            self.reconcile().await?;
        }
        // Do not reinterpret corruption/read errors as absence.
        if self.store.cached_snapshots().await?.contains(pin) {
            return self.store.open_generation(pin).await;
        }
        let export = self.export(pin).await?;
        // Evict only known, unheld cache generations; evict refuses the active DB.
        // Try build first so normally no cache entry is discarded.
        if let Err(first) = self.store.build(&export, &cp).await {
            if first.kind != cdb_core::ErrorKind::Limit {
                return Err(first);
            }
            let mut evicted = false;
            for cached in self.store.cached_snapshots().await? {
                if self.store.evict(&cached).await.is_ok() {
                    evicted = true;
                    break;
                }
            }
            if !evicted {
                return Err(first);
            }
            self.store.build(&export, &cp).await?;
        }
        self.store.open_generation(pin).await
    }
}
async fn run<B: SemanticProjectionSource + 'static>(
    work: Work<B>,
    mut commands: mpsc::Receiver<Command>,
    mut stop: watch::Receiver<bool>,
    status: watch::Sender<CoordinatorStatus>,
) {
    let mut source: Option<Box<dyn ChangeHintSource>> = None;
    let mut next = Instant::now();
    let mut backoff = work.options.retry_min;
    let mut retrying = false;
    loop {
        if *stop.borrow() {
            break;
        }
        let mut reply = None;
        let mut closed = false;
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = tokio::time::sleep_until(next) => {},
            command = commands.recv(), if source.is_some() => match command {
                None => break,
                Some(Command::Exact(pin, deadline, tx)) => {
                    if tx.is_closed() { continue; }
                    if deadline <= Instant::now() {
                        let _ = tx.send(Err(Error::new(cdb_core::ErrorKind::Deadline, "coordinator deadline")));
                        continue;
                    }
                    let end = deadline.min(Instant::now() + work.options.operation_timeout);
                    let mut delay = work.options.retry_min;
                    let result = loop {
                        let result = work.exact(&pin).await;
                        if result.is_ok() || Instant::now() >= end || tx.is_closed() || *stop.borrow() { break result; }
                        if let Err(error) = &result { let _ = status.send(CoordinatorStatus::Degraded(error.to_string())); }
                        tokio::select! {
                            _ = stop.changed() => break result,
                            _ = tokio::time::sleep_until(end.min(Instant::now() + delay)) => {}
                        }
                        delay = delay.saturating_mul(2).min(work.options.retry_max);
                    };
                    let result = if Instant::now() >= end {
                        Err(Error::new(cdb_core::ErrorKind::Deadline, "coordinator deadline"))
                    } else { result };
                    if !*stop.borrow() && !tx.is_closed() { let _ = tx.send(result); }
                    continue;
                }
                Some(Command::Reconcile(tx)) => { if tx.is_closed() { continue; } reply = Some(tx); }
            },
            hint = async { source.as_mut().unwrap().next().await }, if source.is_some() && !retrying => {
                match hint {
                    Ok(ChangeHint::Closed) | Err(_) => { source = None; closed = true; }
                    Ok(ChangeHint::Head(_)) | Ok(ChangeHint::Lagged) => {}
                }
            }
        }
        // Subscribe BEFORE every initial reconciliation, including retry after closure.
        let result = async {
            if source.is_none() {
                source = Some(work.io(work.backend.subscribe()).await?);
            }
            work.reconcile().await
        }
        .await;
        match &result {
            Ok(()) => {
                backoff = work.options.retry_min;
                retrying = false;
                next = Instant::now() + work.options.repair_interval;
                match work.store.checkpoint().await {
                    Ok(Some(cp)) => {
                        let _ = status.send(CoordinatorStatus::Ready(cp));
                    }
                    other => {
                        let _ = status.send(CoordinatorStatus::Degraded(format!(
                            "checkpoint publication: {other:?}"
                        )));
                    }
                }
                // Closed receivers that immediately close again must not spin.
                if closed {
                    retrying = true;
                    next = Instant::now() + backoff;
                    let _ = status.send(CoordinatorStatus::Degraded(
                        "hint receiver closed; resubscribed with cooldown".into(),
                    ));
                }
            }
            Err(error) => {
                let _ = status.send(CoordinatorStatus::Degraded(error.to_string()));
                retrying = true;
                next = Instant::now() + backoff;
                backoff = backoff.saturating_mul(2).min(work.options.retry_max);
            }
        }
        if !*stop.borrow() {
            if let Some(tx) = reply {
                let _ = tx.send(result);
            }
        }
    }
    commands.close();
    let _ = status.send(CoordinatorStatus::Stopped);
}
