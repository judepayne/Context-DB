use cdb_core::{
    admission::*, artifact::*, contracts::*, id::*, snapshot::*, Error, ErrorKind, Result,
    Timestamp,
};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::{
        capture_dual_execution, capture_execution, execute_dual_captured, ExecutionOptions,
    },
    options::CompileOptions,
};
use cdb_testkit::{memory::MemoryBackend, reference_fixture::*};
use std::sync::Arc;

fn control_pin() -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new("control").unwrap(),
        GraphPin::new(
            AuthorityId::new("control-authority").unwrap(),
            GraphId::new("control-ledger").unwrap(),
            VersionId::new("7").unwrap(),
            ResourceId::new("control-cid").unwrap(),
        ),
    )
}

struct ControlSnapshot {
    identity: SnapshotRef,
    inner: Arc<dyn BackendSnapshot>,
}
impl BackendSnapshot for ControlSnapshot {
    fn identity(&self) -> &SnapshotRef {
        &self.identity
    }
    fn resource<'a>(&'a self, id: &'a ResourceId) -> IoFuture<'a, Option<DependencyRecord>> {
        self.inner.resource(id)
    }
    fn export<'a>(
        &'a self,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ExportRecord>> {
        self.inner.export(cursor, size)
    }
    fn artifact<'a>(
        &'a self,
        reference: &'a ArtifactRef,
    ) -> IoFuture<'a, Option<PublishedArtifact>> {
        self.inner.artifact(reference)
    }
}

struct ControlBackend<'a> {
    inner: &'a MemoryBackend,
    semantic: SnapshotRef,
    control: SnapshotRef,
    return_wrong_identity: bool,
}
impl GraphBackend for ControlBackend<'_> {
    fn capabilities(&self) -> Result<BackendCapabilities> {
        self.inner.capabilities()
    }
    fn head(&self) -> IoFuture<'_, SnapshotRef> {
        Box::pin(async move { Ok(self.control.clone()) })
    }
    fn admit<'a>(
        &'a self,
        key: &'a IdempotencyKey,
        batch: &'a AdmissionBatch,
    ) -> IoFuture<'a, AdmissionReceipt> {
        self.inner.admit(key, batch)
    }
    fn receipt<'a>(&'a self, key: &'a IdempotencyKey) -> IoFuture<'a, Option<AdmissionReceipt>> {
        self.inner.receipt(key)
    }
    fn capture(&self, requested: Option<Timestamp>) -> IoFuture<'_, CapturedSnapshot> {
        Box::pin(async move {
            Ok(CapturedSnapshot {
                as_of: requested.unwrap_or(Timestamp::parse("2025-01-01T00:00:00Z")?),
                snapshot: self.control.clone(),
            })
        })
    }
    fn open_snapshot<'a>(&'a self, pin: &'a SnapshotRef) -> IoFuture<'a, Arc<dyn BackendSnapshot>> {
        Box::pin(async move {
            if pin != &self.control {
                return Err(Error::new(ErrorKind::Snapshot, "wrong control capture"));
            }
            let inner = self.inner.open_snapshot(&self.semantic).await?;
            Ok(Arc::new(ControlSnapshot {
                identity: if self.return_wrong_identity {
                    self.semantic.clone()
                } else {
                    self.control.clone()
                },
                inner,
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
        self.inner.changes(after, through, cursor, size)
    }
    fn subscribe(&self) -> IoFuture<'_, Box<dyn ChangeHintSource>> {
        self.inner.subscribe()
    }
}

struct FixedSemanticProvider<'a> {
    fixture: &'a ReferenceFixture,
    actual: CapturedSnapshot,
}
impl cdb_engine::execution::ViewProvider for FixedSemanticProvider<'_> {
    fn open<'a>(
        &'a self,
        _captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, cdb_engine::execution::PreparedView> {
        cdb_engine::execution::ViewProvider::open(self.fixture, &self.actual, options)
    }
}

async fn fixture() -> ReferenceFixture {
    let mut builder = FixtureBuilder::new();
    builder.entity("A", Some("A")).unwrap();
    builder.build().await.unwrap()
}

fn draft(fixture: &ReferenceFixture) -> cdb_engine::compiler::ValidatedDraft {
    compile(
        QuerySource::inline(
            br#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":0}}"#,
        ),
        None,
        &fixture.config,
        CompileOptions::default(),
    )
    .unwrap()
}

#[tokio::test]
async fn dual_capture_uses_semantic_view_and_control_artifact_identity() {
    let fixture = fixture().await;
    let semantic = capture_execution(&fixture.backend, draft(&fixture).requested_as_of())
        .await
        .unwrap();
    let control = ControlBackend {
        inner: &fixture.backend,
        semantic: semantic.snapshot().snapshot.clone(),
        control: control_pin(),
        return_wrong_identity: false,
    };
    let capture = capture_dual_execution(semantic.snapshot().clone(), control.control.clone());
    let mut bytes = Vec::new();
    execute_dual_captured(
        draft(&fixture),
        &control,
        &fixture.backend,
        &fixture.principal,
        &capture,
        &fixture,
        ExecutionOptions::default(),
        &mut |part| {
            bytes.extend_from_slice(part);
            Ok(())
        },
    )
    .await
    .unwrap();
    assert!(!bytes.is_empty());
    assert_ne!(
        capture.captures().semantic().snapshot,
        *capture.captures().control()
    );
}

#[tokio::test]
async fn dual_capture_rejects_wrong_semantic_snapshot_identity() {
    let fixture = fixture().await;
    let actual = capture_execution(&fixture.backend, draft(&fixture).requested_as_of())
        .await
        .unwrap()
        .snapshot()
        .clone();
    let control = ControlBackend {
        inner: &fixture.backend,
        semantic: actual.snapshot.clone(),
        control: control_pin(),
        return_wrong_identity: false,
    };
    let mut wrong = actual.clone();
    wrong.snapshot = SnapshotRef::new(
        BackendId::new("semantic-wrong").unwrap(),
        wrong.snapshot.pin().clone(),
    );
    let capture = capture_dual_execution(wrong, control.control.clone());
    let error = execute_dual_captured(
        draft(&fixture),
        &control,
        &fixture.backend,
        &fixture.principal,
        &capture,
        &FixedSemanticProvider {
            fixture: &fixture,
            actual,
        },
        ExecutionOptions::default(),
        &mut |_| Ok(()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Snapshot);
    assert!(error.to_string().contains("exact view required"));
}

#[tokio::test]
async fn dual_capture_rejects_wrong_control_snapshot_identity() {
    let fixture = fixture().await;
    let semantic = capture_execution(&fixture.backend, draft(&fixture).requested_as_of())
        .await
        .unwrap();
    let control = ControlBackend {
        inner: &fixture.backend,
        semantic: semantic.snapshot().snapshot.clone(),
        control: control_pin(),
        return_wrong_identity: true,
    };
    let capture = capture_dual_execution(semantic.snapshot().clone(), control.control.clone());
    let error = execute_dual_captured(
        draft(&fixture),
        &control,
        &fixture.backend,
        &fixture.principal,
        &capture,
        &fixture,
        ExecutionOptions::default(),
        &mut |_| Ok(()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Snapshot);
    assert!(error.to_string().contains("control artifact snapshot"));
}

#[tokio::test]
async fn legacy_capture_still_uses_one_snapshot_for_both_roles() {
    let fixture = fixture().await;
    let capture = capture_execution(&fixture.backend, draft(&fixture).requested_as_of())
        .await
        .unwrap();
    assert_eq!(capture.snapshot(), capture.captures().semantic());
    assert_eq!(&capture.snapshot().snapshot, capture.captures().control());
}
