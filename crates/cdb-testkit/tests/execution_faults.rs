//! Fault injection at the public raw-view boundary, using normally admitted fixture data.
use cdb_core::{
    admission::{DependencyRecord, ExportRecord},
    claim::AdmittedClaim,
    contracts::{CapturedSnapshot, Direction, IoFuture, RawQueryView},
    id::{BackendId, ClaimId, EntityId, ResourceId, VersionId},
    snapshot::{Page, PageCursor, PageSize, SnapshotRef},
    Error, ErrorKind, Result,
};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::{execute, ExecutionOptions, PreparedView, ViewProvider},
    options::CompileOptions,
};
use cdb_testkit::reference_fixture::{FixtureBuilder, ReferenceFixture};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Clone, Copy)]
enum Fault {
    Identity,
    Incident,
    Lifecycle,
    RepeatedCursor,
    PageSnapshot,
}
struct FaultProvider<'a> {
    fixture: &'a ReferenceFixture,
    fault: Fault,
    hits: Arc<AtomicUsize>,
}
struct FaultView {
    inner: Arc<dyn RawQueryView>,
    identity: SnapshotRef,
    fault: Fault,
    hits: Arc<AtomicUsize>,
}
fn other_backend(snapshot: &SnapshotRef) -> SnapshotRef {
    let other = SnapshotRef::new(
        BackendId::new("fault-backend").unwrap(),
        snapshot.pin().clone(),
    );
    // A projected pin comparison cannot detect this fault.
    assert_eq!(other.pin(), snapshot.pin());
    assert_ne!(&other, snapshot);
    other
}
impl ViewProvider for FaultProvider<'_> {
    fn open<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        Box::pin(async move {
            let prepared = self.fixture.open(captured, options).await?;
            let identity = if matches!(self.fault, Fault::Identity) {
                self.hits.fetch_add(1, Ordering::SeqCst);
                other_backend(&captured.snapshot)
            } else {
                captured.snapshot.clone()
            };
            Ok(PreparedView {
                view: Arc::new(FaultView {
                    inner: prepared.view,
                    identity,
                    fault: self.fault,
                    hits: self.hits.clone(),
                }),
                landing: prepared.landing,
            })
        })
    }
}
impl RawQueryView for FaultView {
    fn identity(&self) -> &SnapshotRef {
        &self.identity
    }
    fn claim(&self, id: &ClaimId) -> Result<Option<AdmittedClaim>> {
        self.inner.claim(id)
    }
    fn entity(&self, id: &EntityId) -> Result<Option<Vec<DependencyRecord>>> {
        self.inner.entity(id)
    }
    fn resource(&self, id: &ResourceId) -> Result<Option<DependencyRecord>> {
        self.inner.resource(id)
    }
    fn incident(
        &self,
        id: &EntityId,
        direction: Direction,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<AdmittedClaim>> {
        match self.fault {
            Fault::Incident => {
                self.hits.fetch_add(1, Ordering::SeqCst);
                Err(Error::new(
                    ErrorKind::Backend,
                    "injected incident read failure",
                ))
            }
            Fault::RepeatedCursor => {
                self.hits.fetch_add(1, Ordering::SeqCst);
                // Return a nonempty first page forever, including the same continuation.
                // Each page is individually valid; cumulative progress is not.
                let page = self.inner.incident(id, direction, size, None)?;
                assert!(!page.items().is_empty());
                Page::new(
                    page.into_items(),
                    self.identity.clone(),
                    Some(PageCursor::new(
                        self.identity.clone(),
                        ResourceId::new("incident-fault")?,
                        VersionId::new("stuck")?,
                    )),
                    size,
                )
            }
            Fault::PageSnapshot => {
                self.hits.fetch_add(1, Ordering::SeqCst);
                let page = self.inner.incident(id, direction, size, cursor)?;
                Page::new(page.into_items(), other_backend(&self.identity), None, size)
            }
            _ => self.inner.incident(id, direction, size, cursor),
        }
    }
    fn lifecycle(
        &self,
        id: &ClaimId,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<ExportRecord>> {
        if matches!(self.fault, Fault::Lifecycle) {
            self.hits.fetch_add(1, Ordering::SeqCst);
            Err(Error::new(
                ErrorKind::Backend,
                "injected lifecycle read failure",
            ))
        } else {
            self.inner.lifecycle(id, size, cursor)
        }
    }
}

async fn assert_fault(fault: Fault, kind: ErrorKind, expected_hits: usize) -> Error {
    let mut builder = FixtureBuilder::new();
    for name in ["A", "B", "C"] {
        builder
            .entity(&format!("https://e/{name}"), Some(name))
            .unwrap();
    }
    for (id, from, to) in [("ab", "A", "B"), ("bc", "B", "C")] {
        builder
            .edge(
                &format!("https://e/{id}"),
                &format!("https://e/{from}"),
                cdb_core::claim::ClaimObject::Entity(
                    EntityId::new(format!("https://e/{to}")).unwrap(),
                ),
                "1",
            )
            .unwrap();
    }
    let fixture = builder.build().await.unwrap();
    let draft = compile(
        QuerySource::inline(
            br#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":2}}"#,
        ),
        None,
        &fixture.config,
        CompileOptions::default(),
    )
    .unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let provider = FaultProvider {
        fixture: &fixture,
        fault,
        hits: hits.clone(),
    };
    let mut bytes = 0;
    let mut calls = 0;
    let error = execute(
        draft,
        &fixture.backend,
        &fixture.backend,
        &fixture.principal,
        &provider,
        ExecutionOptions::default(),
        &mut |buffer| {
            calls += 1;
            bytes += buffer.len();
            Ok(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, kind);
    assert_eq!(hits.load(Ordering::SeqCst), expected_hits);
    assert_eq!(calls, 0, "even an empty sink publication is forbidden");
    assert_eq!(bytes, 0);
    error
}

#[tokio::test]
async fn full_snapshot_mismatch_with_identical_graph_pin_releases_nothing() {
    assert_fault(Fault::Identity, ErrorKind::Snapshot, 1).await;
}
#[tokio::test]
async fn incident_read_error_propagates_without_publication() {
    let error = assert_fault(Fault::Incident, ErrorKind::Backend, 1).await;
    assert_eq!(error.message, "injected incident read failure");
}
#[tokio::test]
async fn lifecycle_read_error_propagates_without_publication() {
    let error = assert_fault(Fault::Lifecycle, ErrorKind::Backend, 1).await;
    assert_eq!(error.message, "injected lifecycle read failure");
}
#[tokio::test]
async fn repeated_nonprogressing_incident_cursor_releases_nothing() {
    assert_fault(Fault::RepeatedCursor, ErrorKind::Invalid, 2).await;
}
#[tokio::test]
async fn wrong_page_snapshot_with_identical_graph_pin_releases_nothing() {
    assert_fault(Fault::PageSnapshot, ErrorKind::Invalid, 1).await;
}
