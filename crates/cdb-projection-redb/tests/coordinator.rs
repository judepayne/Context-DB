use cdb_core::{admission::*, contracts::*, id::*, snapshot::*, Error, Limits, Timestamp};
use cdb_projection_redb::{
    Coordinator, CoordinatorOptions, CoordinatorStatus, GenerationOptions, RedbProjection,
};
use std::future::Future;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::time::Instant;
fn pin(r: usize) -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new("fake").unwrap(),
        GraphPin::new(
            AuthorityId::new("authority").unwrap(),
            GraphId::new("g").unwrap(),
            VersionId::new(r.to_string()).unwrap(),
            ResourceId::new(format!("receipt:{r}")).unwrap(),
        ),
    )
}
fn cp(r: usize) -> ProjectionCheckpoint {
    ProjectionCheckpoint::new(
        pin(r),
        VersionId::new("ctxql-projection/v1").unwrap(),
        VersionId::new("live").unwrap(),
        Iri::new("urn:raw").unwrap(),
    )
    .unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
struct Hints(mpsc::Receiver<ChangeHint>);
impl ChangeHintSource for Hints {
    fn next(&mut self) -> IoFuture<'_, ChangeHint> {
        Box::pin(async { Ok(self.0.recv().await.unwrap_or(ChangeHint::Closed)) })
    }
}
struct Fake {
    revision: AtomicUsize,
    subscribers: AtomicUsize,
    hints: Mutex<Vec<mpsc::Sender<ChangeHint>>>,
    fail_head: AtomicBool,
    fail_changes: AtomicBool,
    block_head: AtomicBool,
    ordered_changes: AtomicBool,
    entered: Notify,
    release: Semaphore,
}
impl Fake {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            revision: AtomicUsize::new(0),
            subscribers: AtomicUsize::new(0),
            hints: Mutex::new(vec![]),
            fail_head: AtomicBool::new(false),
            fail_changes: AtomicBool::new(false),
            block_head: AtomicBool::new(false),
            ordered_changes: AtomicBool::new(true),
            entered: Notify::new(),
            release: Semaphore::new(0),
        })
    }
    fn hint(&self, hint: ChangeHint) {
        self.hints
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .try_send(hint)
            .unwrap();
    }
}
struct Snapshot(SnapshotRef);
impl SemanticProjectionSnapshot for Snapshot {
    fn identity(&self) -> &SnapshotRef {
        &self.0
    }
    fn export<'a>(
        &'a self,
        _: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ExportRecord>> {
        Box::pin(async move { Page::new(vec![], self.0.clone(), None, size) })
    }
}
impl SemanticProjectionSource for Fake {
    fn capabilities(&self) -> cdb_core::Result<SemanticProjectionCapabilities> {
        Ok(SemanticProjectionCapabilities {
            exact_snapshots: true,
            ordered_changes: self.ordered_changes.load(Ordering::SeqCst),
            closed_cutoff: true,
            complete_exports: true,
            schema: cp(0).schema().clone(),
            algorithm: cp(0).algorithm().clone(),
        })
    }
    fn head(&self) -> IoFuture<'_, SnapshotRef> {
        Box::pin(async {
            assert!(
                self.subscribers.load(Ordering::SeqCst) > 0,
                "subscribe before head"
            );
            let captured = pin(self.revision.load(Ordering::SeqCst));
            if self.block_head.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.acquire().await.unwrap().forget();
            }
            if self.fail_head.swap(false, Ordering::SeqCst) {
                return Err(Error::invalid("injected head read"));
            }
            Ok(captured)
        })
    }
    fn capture(&self, requested: Option<Timestamp>) -> IoFuture<'_, CapturedSnapshot> {
        Box::pin(async move {
            let snapshot = pin(self.revision.load(Ordering::SeqCst));
            Ok(CapturedSnapshot {
                as_of: requested.unwrap_or(Timestamp::parse("2025-01-01T00:00:00Z")?),
                snapshot,
            })
        })
    }
    fn open_snapshot<'a>(
        &'a self,
        p: &'a SnapshotRef,
    ) -> IoFuture<'a, Arc<dyn SemanticProjectionSnapshot>> {
        Box::pin(async move {
            if !p.same_authority(&pin(0))
                || p.pin().revision().as_str().parse::<usize>().unwrap()
                    > self.revision.load(Ordering::SeqCst)
            {
                return Err(Error::invalid("unavailable"));
            }
            Ok(Arc::new(Snapshot(p.clone())) as Arc<dyn SemanticProjectionSnapshot>)
        })
    }
    fn changes<'a>(
        &'a self,
        after: &'a SnapshotRef,
        through: &'a SnapshotRef,
        _: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ChangeBatch>> {
        Box::pin(async move {
            if self.fail_changes.swap(false, Ordering::SeqCst) {
                return Err(Error::invalid("injected changes read"));
            }
            Page::new(
                vec![ChangeBatch::new(
                    "ctxql-change/v1",
                    after.clone(),
                    through.clone(),
                    vec![],
                    Limits::default(),
                )?],
                through.clone(),
                None,
                size,
            )
        })
    }
    fn subscribe(&self) -> IoFuture<'_, Box<dyn ChangeHintSource>> {
        Box::pin(async {
            let (tx, rx) = mpsc::channel(16);
            self.hints.lock().unwrap().push(tx);
            self.subscribers.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Hints(rx)) as Box<dyn ChangeHintSource>)
        })
    }
}
fn options() -> CoordinatorOptions {
    CoordinatorOptions {
        retry_min: Duration::from_millis(1),
        retry_max: Duration::from_millis(10),
        repair_interval: Duration::from_secs(3600),
        ..Default::default()
    }
}
async fn ready(c: &Coordinator, revision: usize) {
    let mut status = c.status();
    tokio::time::timeout_at(end(), async {
        loop {
            if matches!(&*status.borrow_and_update(), CoordinatorStatus::Ready(cp) if cp.snapshot() == &pin(revision)) { return; }
            status.changed().await.unwrap();
        }
    }).await.unwrap();
}
async fn setup(
    f: Arc<Fake>,
    o: CoordinatorOptions,
) -> (tempfile::TempDir, Arc<RedbProjection>, Coordinator) {
    let d = tempfile::tempdir().unwrap();
    let s = Arc::new(
        RedbProjection::create(
            d.path().join("projection"),
            cp(0),
            GenerationOptions::default(),
        )
        .await
        .unwrap(),
    );
    let c = Coordinator::start(f, s.clone(), cp(0), o).unwrap();
    (d, s, c)
}
#[tokio::test]
async fn startup_barrier_commit_and_historical_after_live_ahead() {
    let f = Fake::new();
    f.block_head.store(true, Ordering::SeqCst);
    let (_d, s, c) = setup(f.clone(), options()).await;
    f.entered.notified().await;
    assert_eq!(f.subscribers.load(Ordering::SeqCst), 1);
    f.revision.store(1, Ordering::SeqCst);
    f.hint(ChangeHint::Head(pin(1)));
    f.release.add_permits(1);
    ready(&c, 1).await;
    assert_eq!(s.checkpoint().await.unwrap().unwrap().snapshot(), &pin(1));
    let held = c.wait_exact(&pin(0), end()).await.unwrap();
    assert_eq!(held.checkpoint().snapshot(), &pin(0));
    c.shutdown().await.unwrap();
    assert_eq!(
        held.scan(PageSize::new(10).unwrap(), None)
            .unwrap()
            .snapshot(),
        &pin(0)
    );
}
#[tokio::test]
async fn lost_hint_repair_pulse_and_lag_are_durable() {
    let f = Fake::new();
    let (_d, s, c) = setup(f.clone(), options()).await;
    ready(&c, 0).await;
    let held = c.wait_exact(&pin(0), end()).await.unwrap();
    f.revision.store(1, Ordering::SeqCst);
    c.reconcile(end()).await.unwrap();
    ready(&c, 1).await;
    f.revision.store(2, Ordering::SeqCst);
    f.hint(ChangeHint::Lagged);
    ready(&c, 2).await;
    assert_eq!(held.checkpoint().snapshot(), &pin(0));
    assert_eq!(s.checkpoint().await.unwrap().unwrap().snapshot(), &pin(2));
    c.shutdown().await.unwrap();
}
#[tokio::test]
async fn source_without_ordered_changes_rebuilds_from_exact_export() {
    let f = Fake::new();
    f.ordered_changes.store(false, Ordering::SeqCst);
    let (_d, s, c) = setup(f.clone(), options()).await;
    ready(&c, 0).await;
    f.fail_changes.store(true, Ordering::SeqCst);
    f.revision.store(1, Ordering::SeqCst);
    c.reconcile(end()).await.unwrap();
    assert_eq!(s.checkpoint().await.unwrap().unwrap().snapshot(), &pin(1));
    assert!(f.fail_changes.load(Ordering::SeqCst));
    c.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_read_then_silence_retries_without_hint() {
    let f = Fake::new();
    let (_d, _s, c) = setup(f.clone(), options()).await;
    ready(&c, 0).await;
    f.revision.store(1, Ordering::SeqCst);
    f.fail_changes.store(true, Ordering::SeqCst);
    assert!(c.reconcile(end()).await.is_err());
    ready(&c, 1).await;
    c.shutdown().await.unwrap();
}
#[tokio::test]
async fn failed_initial_publication_then_silence_retries() {
    let f = Fake::new();
    f.block_head.store(true, Ordering::SeqCst);
    let (_d, s, c) = setup(f.clone(), options()).await;
    f.entered.notified().await;
    s.set_before_publish_fault(true);
    f.release.add_permits(1);
    let mut status = c.status();
    tokio::time::timeout_at(end(), async {
        loop {
            if matches!(&*status.borrow_and_update(), CoordinatorStatus::Degraded(_)) {
                break;
            }
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(s.checkpoint().await.unwrap().is_none());
    s.set_before_publish_fault(false);
    ready(&c, 0).await;
    c.shutdown().await.unwrap();
}
#[tokio::test]
async fn closed_receiver_resubscribes_and_receives_again() {
    let f = Fake::new();
    let (_d, _s, c) = setup(f.clone(), options()).await;
    ready(&c, 0).await;
    f.hint(ChangeHint::Closed);
    let mut status = c.status();
    tokio::time::timeout_at(end(), async {
        loop {
            if f.subscribers.load(Ordering::SeqCst) >= 2 {
                break;
            }
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    f.revision.store(1, Ordering::SeqCst);
    f.hint(ChangeHint::Head(pin(1)));
    ready(&c, 1).await;
    c.shutdown().await.unwrap();
}
#[tokio::test]
async fn bounded_waiters_deadline_cancellation_and_shutdown() {
    let f = Fake::new();
    f.block_head.store(true, Ordering::SeqCst);
    let mut o = options();
    o.max_waiters = 1;
    let (_d, _s, c) = setup(f.clone(), o).await;
    f.entered.notified().await;
    let p = pin(0);
    let mut first = Box::pin(c.wait_exact(&p, end()));
    // Poll until the request is queued while initial head is held at the barrier.
    assert!(
        std::future::poll_fn(|cx| match first.as_mut().poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Ready(true),
            _ => std::task::Poll::Ready(false),
        })
        .await
    );
    assert!(c.wait_exact(&p, end()).await.is_err());
    drop(first);
    assert!(c.wait_exact(&p, Instant::now()).await.is_err());
    f.release.add_permits(1);
    ready(&c, 0).await;
    let held = c.wait_exact(&p, end()).await.unwrap();
    let mut status = c.status();
    c.shutdown().await.unwrap();
    assert!(matches!(
        &*status.borrow_and_update(),
        CoordinatorStatus::Stopped
    ));
    assert_eq!(held.checkpoint().snapshot(), &p);
}

#[tokio::test]
async fn lost_hint_actual_periodic_timer_repairs() {
    let f = Fake::new();
    let mut o = options();
    o.repair_interval = Duration::from_millis(1);
    let (_d, _s, c) = setup(f.clone(), o).await;
    ready(&c, 0).await;
    f.revision.store(1, Ordering::SeqCst);
    // No event or explicit pulse: await durable publication, not a guessed sleep.
    ready(&c, 1).await;
    c.shutdown().await.unwrap();
}
#[tokio::test]
async fn shutdown_rejects_queued_waiter() {
    let f = Fake::new();
    f.block_head.store(true, Ordering::SeqCst);
    let (_d, _s, c) = setup(f.clone(), options()).await;
    f.entered.notified().await;
    let p = pin(0);
    let mut pending = Box::pin(c.wait_exact(&p, end()));
    std::future::poll_fn(|cx| {
        assert!(pending.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    c.request_stop();
    f.release.add_permits(1);
    assert!(pending.await.is_err());
    assert!(c.wait_exact(&p, end()).await.is_err());
    c.shutdown().await.unwrap();
}
