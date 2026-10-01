//! Partner Review H3: complete artifact identities at adapter and executor boundaries.
mod common_p3;
use cdb_backend_fluree::FlureeBackend;
use cdb_core::{
    admission::*, artifact::*, contracts::*, id::*, snapshot::*, CanonicalValue as V, Limits,
    Timestamp,
};
use cdb_engine::{
    compiler::{compile, QuerySource},
    execution::{execute, ExecutionOptions},
    options::CompileOptions,
};
use cdb_testkit::reference_fixture::FixtureBuilder;
use std::sync::Arc;
struct WrongArtifact<'a> {
    inner: &'a FlureeBackend,
    artifact: PublishedArtifact,
}
struct WrongSnapshot {
    inner: Arc<dyn BackendSnapshot>,
    artifact: PublishedArtifact,
}
impl BackendSnapshot for WrongSnapshot {
    fn identity(&self) -> &SnapshotRef {
        self.inner.identity()
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
    fn artifact<'a>(&'a self, _: &'a ArtifactRef) -> IoFuture<'a, Option<PublishedArtifact>> {
        Box::pin(async { Ok(Some(self.artifact.clone())) })
    }
}
impl GraphBackend for WrongArtifact<'_> {
    fn capabilities(&self) -> cdb_core::Result<BackendCapabilities> {
        self.inner.capabilities()
    }
    fn head(&self) -> IoFuture<'_, SnapshotRef> {
        GraphBackend::head(self.inner)
    }
    fn admit<'a>(
        &'a self,
        key: &'a IdempotencyKey,
        batch: &'a AdmissionBatch,
    ) -> IoFuture<'a, AdmissionReceipt> {
        GraphBackend::admit(self.inner, key, batch)
    }
    fn receipt<'a>(&'a self, key: &'a IdempotencyKey) -> IoFuture<'a, Option<AdmissionReceipt>> {
        GraphBackend::receipt(self.inner, key)
    }
    fn capture(&self, time: Option<Timestamp>) -> IoFuture<'_, CapturedSnapshot> {
        GraphBackend::capture(self.inner, time)
    }
    fn open_snapshot<'a>(&'a self, pin: &'a SnapshotRef) -> IoFuture<'a, Arc<dyn BackendSnapshot>> {
        Box::pin(async move {
            Ok(Arc::new(WrongSnapshot {
                inner: self.inner.open_snapshot(pin).await?,
                artifact: self.artifact.clone(),
            }) as Arc<dyn BackendSnapshot>)
        })
    }
    fn changes<'a>(
        &'a self,
        a: &'a SnapshotRef,
        b: &'a SnapshotRef,
        c: Option<&'a PageCursor>,
        s: PageSize,
    ) -> IoFuture<'a, Page<ChangeBatch>> {
        self.inner.changes(a, b, c, s)
    }
    fn subscribe(&self) -> IoFuture<'_, Box<dyn ChangeHintSource>> {
        self.inner.subscribe()
    }
}
#[tokio::test]
async fn complete_artifact_hash_mismatch_is_rejected_by_lookup_and_execution() {
    let mut builder = FixtureBuilder::new();
    builder.entity("s", None).unwrap();
    let f = common_p3::NativeFixture::new(builder, common_p3::reader_policy(), 1).await;
    let mut value = V::parse(f.config.content(), Limits::default())
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    value.insert("name".into(), V::string("unpublished-config"));
    let bytes = V::Object(value).canonical_bytes(Limits::default()).unwrap();
    let wrong = PublishedArtifact::new(
        ArtifactRef::new(
            f.config.reference().iri().clone(),
            f.config.reference().version().clone(),
            ContentHash::of_bytes(&bytes),
        ),
        bytes,
        Limits::default(),
    )
    .unwrap();
    let pin = f.backend.head().await.unwrap();
    let snapshot = f.backend.open_snapshot(&pin).await.unwrap();
    assert_eq!(
        snapshot.artifact(f.config.reference()).await.unwrap(),
        Some(f.config.clone())
    );
    assert_eq!(
        snapshot.artifact(wrong.reference()).await.unwrap_err().kind,
        cdb_core::ErrorKind::Conflict
    );
    assert_eq!(
        ArtifactRepository::lookup(f.backend.as_ref(), wrong.reference())
            .await
            .unwrap_err()
            .kind,
        cdb_core::ErrorKind::Conflict
    );
    let query = br#"{"about":[{"from":["s"],"match":"exact"}],"bounds":{"max_depth":1}}"#;
    let mut output = vec![];
    let draft = compile(
        QuerySource::inline(query),
        None,
        &wrong,
        CompileOptions::default(),
    )
    .unwrap();
    let error = execute(
        draft,
        f.backend.as_ref(),
        f.backend.as_ref(),
        &f.principal,
        &f.provider,
        ExecutionOptions::default(),
        &mut |b| {
            output.extend_from_slice(b);
            Ok(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, cdb_core::ErrorKind::Conflict);
    assert!(output.is_empty());
    // Even a faulty adapter returning the wrong object cannot satisfy presence-only validation.
    f.advance();
    let liar = WrongArtifact {
        inner: f.backend.as_ref(),
        artifact: f.config.clone(),
    };
    let draft = compile(
        QuerySource::inline(query),
        None,
        &wrong,
        CompileOptions::default(),
    )
    .unwrap();
    let error = execute(
        draft,
        &liar,
        f.backend.as_ref(),
        &f.principal,
        &f.provider,
        ExecutionOptions::default(),
        &mut |b| {
            output.extend_from_slice(b);
            Ok(())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, cdb_core::ErrorKind::Snapshot);
    assert!(output.is_empty());
    drop(liar);
    drop(snapshot);
    f.shutdown().await;
}
