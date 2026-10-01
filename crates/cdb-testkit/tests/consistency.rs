use cdb_core::{
    contracts::*, id::*, policy::PolicySet, snapshot::*, CanonicalValue as V, Error, ErrorKind,
    Limits, Result,
};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::*,
    options::CompileOptions,
};
use cdb_testkit::reference_fixture::{artifact, FixtureBuilder, ReferenceFixture, CONFIG};
use std::sync::Mutex;

#[derive(Clone, Copy)]
enum Mode {
    Older,
    None,
    Mismatch,
    Future,
    Foreign,
    Error,
    Timeout,
}
struct Provider<'a> {
    fixture: &'a ReferenceFixture,
    old: SnapshotRef,
    mode: Mode,
    calls: Mutex<(usize, usize)>,
    requested: Mutex<Option<CapturedSnapshot>>,
}
impl ViewProvider for Provider<'_> {
    fn propose_stale<'a>(
        &'a self,
        requested: &'a CapturedSnapshot,
        _: &'a ExecutionOptions,
    ) -> IoFuture<'a, Option<SnapshotRef>> {
        Box::pin(async move {
            self.calls.lock().unwrap().0 += 1;
            *self.requested.lock().unwrap() = Some(requested.clone());
            Ok(match self.mode {
                Mode::None => None,
                Mode::Future => Some(self.fixture.backend.capture(None).await?.snapshot),
                Mode::Foreign => Some(SnapshotRef::new(
                    BackendId::new("foreign")?,
                    self.old.pin().clone(),
                )),
                _ => Some(self.old.clone()),
            })
        })
    }
    fn open<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        Box::pin(async move {
            self.calls.lock().unwrap().1 += 1;
            match self.mode {
                Mode::Error => return Err(Error::new(ErrorKind::Backend, "preparation failed")),
                Mode::Timeout => {
                    return Err(Error::new(ErrorKind::Deadline, "preparation timed out"))
                }
                _ => {}
            }
            let effective = CapturedSnapshot {
                as_of: captured.as_of,
                snapshot: if matches!(self.mode, Mode::Mismatch) {
                    self.old.clone()
                } else {
                    captured.snapshot.clone()
                },
            };
            self.fixture.open(&effective, options).await
        })
    }
}
async fn fixture() -> ReferenceFixture {
    let mut b = FixtureBuilder::new();
    b.entity("https://e/A", Some("A")).unwrap();
    b.build().await.unwrap()
}
async fn provider(f: &ReferenceFixture, mode: Mode) -> Provider<'_> {
    Provider {
        fixture: f,
        old: f.backend.head().await.unwrap(),
        mode,
        calls: Mutex::new((0, 0)),
        requested: Mutex::new(None),
    }
}
async fn run(
    p: &Provider<'_>,
    consistency: Option<Consistency>,
    options: ExecutionOptions,
) -> (Result<()>, Vec<u8>) {
    run_backend(p, &p.fixture.backend, consistency, options).await
}
async fn run_backend<B: GraphBackend>(
    p: &Provider<'_>,
    backend: &B,
    consistency: Option<Consistency>,
    options: ExecutionOptions,
) -> (Result<()>, Vec<u8>) {
    let f = p.fixture;
    let draft = compile(QuerySource::inline(br#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1},"return":{"explain":false}}"#), None, &f.config, CompileOptions::default()).unwrap();
    let mut bytes = vec![];
    let mut sink = |b: &[u8]| {
        bytes.extend_from_slice(b);
        Ok(())
    };
    let result = if let Some(c) = consistency {
        execute_with_consistency(
            draft,
            backend,
            &f.backend,
            &f.principal,
            p,
            c,
            options,
            &mut sink,
        )
        .await
    } else {
        execute(
            draft,
            backend,
            &f.backend,
            &f.principal,
            p,
            options,
            &mut sink,
        )
        .await
    };
    (result, bytes)
}
fn json(bytes: &[u8]) -> V {
    V::parse(bytes, Limits::default()).unwrap()
}

#[tokio::test]
async fn default_exact_rejects_old_open_without_proposing() {
    let f = fixture().await;
    let p = provider(&f, Mode::Mismatch).await;
    let (r, b) = run(&p, None, ExecutionOptions::default()).await;
    assert_eq!(r.unwrap_err().kind, ErrorKind::Snapshot);
    assert!(b.is_empty());
    assert_eq!(*p.calls.lock().unwrap(), (0, 1));
}
#[tokio::test]
async fn explicit_older_preserves_cutoff_and_reports_actual_without_explain() {
    let f = fixture().await;
    let p = provider(&f, Mode::Older).await;
    // Force multi-page authoritative ancestry (adapter-defined stream identifier).
    f.backend.capture(None).await.unwrap();
    let (r, b) = run(
        &p,
        Some(Consistency::AllowStale),
        ExecutionOptions {
            page_size: PageSize::new(1).unwrap(),
            ..Default::default()
        },
    )
    .await;
    r.unwrap();
    let v = json(&b);
    let c = v.field("consistency").unwrap();
    assert_eq!(c.field("stale").unwrap(), &V::Bool(true));
    assert_eq!(
        c.field("actual").unwrap().field("pin").unwrap(),
        &p.old.pin().projection()
    );
    assert_eq!(
        c.field("actual").unwrap().field("backend").unwrap(),
        &V::string(p.old.backend().as_str())
    );
    let requested = p.requested.lock().unwrap().clone().unwrap();
    assert_eq!(
        c.field("requested").unwrap().field("pin").unwrap(),
        &requested.snapshot.pin().projection()
    );
    assert_eq!(
        c.field("as_of").unwrap(),
        &V::string(requested.as_of.canonical())
    );
    assert_eq!(
        v.field("semantic_flags").unwrap(),
        &V::Array(vec![V::string("stale_snapshot")])
    );
    assert_eq!(
        v.field("status").unwrap(),
        &V::string("ready_with_warnings")
    );
}
#[tokio::test]
async fn none_means_exact_and_explicit_exact_does_not_propose() {
    let f = fixture().await;
    for c in [Consistency::Exact, Consistency::AllowStale] {
        let p = provider(&f, Mode::None).await;
        let (r, b) = run(&p, Some(c), ExecutionOptions::default()).await;
        r.unwrap();
        assert_eq!(
            json(&b)
                .field("consistency")
                .unwrap()
                .field("stale")
                .unwrap(),
            &V::Bool(false)
        );
        assert_eq!(
            p.calls.lock().unwrap().0,
            usize::from(c == Consistency::AllowStale)
        );
    }
}
#[tokio::test]
async fn future_foreign_and_disconnected_proposals_release_nothing() {
    let f = fixture().await;
    for mode in [Mode::Future, Mode::Foreign] {
        let p = provider(&f, mode).await;
        let (r, b) = run(
            &p,
            Some(Consistency::AllowStale),
            ExecutionOptions::default(),
        )
        .await;
        assert!(r.is_err());
        assert!(b.is_empty());
        assert_eq!(*p.calls.lock().unwrap(), (1, 0));
    }
    let p = provider(&f, Mode::Older).await;
    let (r, b) = run_backend(
        &p,
        &Disconnected(&f.backend),
        Some(Consistency::AllowStale),
        ExecutionOptions::default(),
    )
    .await;
    assert_eq!(r.unwrap_err().kind, ErrorKind::Snapshot);
    assert!(b.is_empty());
    assert_eq!(*p.calls.lock().unwrap(), (1, 0));
}
// Real authority operations, with deliberately disconnected terminal history.
struct Disconnected<'a>(&'a cdb_testkit::memory::MemoryBackend);
impl GraphBackend for Disconnected<'_> {
    fn capabilities(&self) -> Result<BackendCapabilities> {
        self.0.capabilities()
    }
    fn head(&self) -> IoFuture<'_, SnapshotRef> {
        self.0.head()
    }
    fn capture(&self, t: Option<cdb_core::Timestamp>) -> IoFuture<'_, CapturedSnapshot> {
        self.0.capture(t)
    }
    fn open_snapshot<'a>(
        &'a self,
        p: &'a SnapshotRef,
    ) -> IoFuture<'a, std::sync::Arc<dyn BackendSnapshot>> {
        self.0.open_snapshot(p)
    }
    fn admit<'a>(
        &'a self,
        k: &'a IdempotencyKey,
        b: &'a cdb_core::admission::AdmissionBatch,
    ) -> IoFuture<'a, cdb_core::admission::AdmissionReceipt> {
        self.0.admit(k, b)
    }
    fn receipt<'a>(
        &'a self,
        k: &'a IdempotencyKey,
    ) -> IoFuture<'a, Option<cdb_core::admission::AdmissionReceipt>> {
        self.0.receipt(k)
    }
    fn subscribe(&self) -> IoFuture<'_, Box<dyn ChangeHintSource>> {
        self.0.subscribe()
    }
    fn changes<'a>(
        &'a self,
        _: &'a SnapshotRef,
        through: &'a SnapshotRef,
        _: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<cdb_core::admission::ChangeBatch>> {
        Box::pin(async move { Page::new(vec![], through.clone(), None, size) })
    }
}
#[tokio::test]
async fn missing_actual_artifact_never_uses_latest() {
    let mut f = fixture().await;
    let old = f.backend.head().await.unwrap();
    f.config = artifact("https://fixture.example/new-config", CONFIG.as_bytes()).unwrap();
    ArtifactRepository::publish(&f.backend, &f.config)
        .await
        .unwrap();
    let mut p = provider(&f, Mode::Older).await;
    p.old = old;
    let (r, b) = run(
        &p,
        Some(Consistency::AllowStale),
        ExecutionOptions::default(),
    )
    .await;
    assert_eq!(r.unwrap_err().kind, ErrorKind::NotFound);
    assert!(b.is_empty());
    assert_eq!(*p.calls.lock().unwrap(), (1, 1));
}
#[tokio::test]
async fn current_revocation_applies_to_old_data() {
    let f = fixture().await;
    let p = provider(&f, Mode::Older).await;
    f.backend
        .set_policy(
            PolicySet::parse(
                br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[]}"#,
                Limits::default(),
            )
            .unwrap(),
        )
        .unwrap();
    let (r, b) = run(
        &p,
        Some(Consistency::AllowStale),
        ExecutionOptions::default(),
    )
    .await;
    assert_eq!(r.unwrap_err().kind, ErrorKind::Denied);
    assert!(b.is_empty());
}
#[tokio::test]
async fn preparation_errors_and_proof_budgets_never_fallback() {
    let f = fixture().await;
    for (mode, kind) in [
        (Mode::Error, ErrorKind::Backend),
        (Mode::Timeout, ErrorKind::Deadline),
    ] {
        let p = provider(&f, mode).await;
        let (r, b) = run(
            &p,
            Some(Consistency::AllowStale),
            ExecutionOptions::default(),
        )
        .await;
        assert_eq!(r.unwrap_err().kind, kind);
        assert!(b.is_empty());
        assert_eq!(*p.calls.lock().unwrap(), (1, 1));
    }
    let p = provider(&f, Mode::Older).await;
    let (r, b) = run(
        &p,
        Some(Consistency::AllowStale),
        ExecutionOptions {
            max_records: 0,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(r.unwrap_err().kind, ErrorKind::Limit);
    assert!(b.is_empty());
    assert_eq!(*p.calls.lock().unwrap(), (1, 0));
}
