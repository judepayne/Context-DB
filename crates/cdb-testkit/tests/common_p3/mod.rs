//! Disposable real-authority fixture shared by native integration tests.
use cdb_backend_fluree::{
    policy::{FlureePrincipal, PolicyState},
    AuthorityOptions, FlureeBackend, NativeResult, WallClock,
};
use cdb_core::{
    contracts::GraphBackendProjectionSource, id::*, snapshot::ProjectionCheckpoint, Timestamp,
};
use cdb_projection_redb::{
    Coordinator, CoordinatorOptions, GenerationOptions, RedbProjection, RedbViewProvider,
};
use cdb_testkit::reference_fixture::{allow_policy, artifact, FixtureBuilder, CONFIG};
use std::{
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc,
    },
    time::Duration,
};

pub struct FixedClock(AtomicI64);
impl WallClock for FixedClock {
    fn now(&self) -> NativeResult<Timestamp> {
        Ok(Timestamp::from_millis(self.0.load(Ordering::SeqCst))?)
    }
}
pub struct NativeFixture {
    pub backend: Arc<FlureeBackend>,
    pub principal: FlureePrincipal,
    pub config: cdb_core::artifact::PublishedArtifact,
    pub provider: RedbViewProvider,
    pub coordinator: Arc<Coordinator>,
    pub store: Arc<RedbProjection>,
    pub clock: Arc<FixedClock>,
    root: tempfile::TempDir,
}
impl NativeFixture {
    pub async fn new(builder: FixtureBuilder, state: PolicyState, page_size: usize) -> Self {
        let root = tempfile::tempdir().unwrap();
        let clock = Arc::new(FixedClock(AtomicI64::new(
            Timestamp::parse("2026-04-01T00:00:00Z").unwrap().millis(),
        )));
        let mut options = AuthorityOptions::new(
            root.path().join("authority"),
            "p3-conformance:main".into(),
            BackendId::new("p3").unwrap(),
            AuthorityId::new("p3-authority").unwrap(),
            GraphId::new("p3-graph").unwrap(),
        );
        options.clock = clock.clone();
        let backend = Arc::new(FlureeBackend::create(options).await.unwrap());
        backend
            .admit(
                &IdempotencyKey::new("fixture").unwrap(),
                &builder.into_batch().unwrap(),
            )
            .await
            .unwrap();
        clock.0.fetch_add(1, Ordering::SeqCst);
        backend
            .set_policy_state(&IdempotencyKey::new("policy").unwrap(), &state)
            .await
            .unwrap();
        let principal = backend
            .issue_principal(PrincipalId::new("reader").unwrap())
            .await
            .unwrap();
        let binding = ProjectionCheckpoint::new(
            backend.head().await.unwrap(),
            VersionId::new("ctxql-projection/v1").unwrap(),
            VersionId::new("live").unwrap(),
            Iri::new("urn:p3:raw").unwrap(),
        )
        .unwrap();
        let store = Arc::new(
            RedbProjection::create(
                root.path().join("projection"),
                binding.clone(),
                GenerationOptions::default(),
            )
            .await
            .unwrap(),
        );
        let projection_source = Arc::new(GraphBackendProjectionSource::new(
            backend.clone(),
            binding.schema().clone(),
            binding.algorithm().clone(),
        ));
        let coordinator = Arc::new(
            Coordinator::start(
                projection_source,
                store.clone(),
                binding,
                CoordinatorOptions {
                    page_size: cdb_core::snapshot::PageSize::new(page_size).unwrap(),
                    repair_interval: Duration::from_secs(3600),
                    ..CoordinatorOptions::default()
                },
            )
            .unwrap(),
        );
        let provider =
            RedbViewProvider::new(coordinator.clone(), store.clone(), Duration::from_secs(60))
                .unwrap();
        Self {
            backend,
            principal,
            config: artifact("https://fixture.example/config", CONFIG.as_bytes()).unwrap(),
            provider,
            coordinator,
            store,
            clock,
            root,
        }
    }
    pub fn advance(&self) {
        self.clock.0.fetch_add(1, Ordering::SeqCst);
    }
    pub async fn shutdown(self) {
        let Self {
            provider,
            coordinator,
            store,
            backend,
            root,
            ..
        } = self;
        drop(provider);
        Arc::try_unwrap(coordinator)
            .ok()
            .expect("provider released coordinator")
            .shutdown()
            .await
            .unwrap();
        drop(store);
        drop(backend);
        drop(root);
    }
}
pub fn reader_policy() -> PolicyState {
    let mut state = PolicyState::deny_all().unwrap();
    state.policy = allow_policy().unwrap();
    state.principals.insert(
        PrincipalId::new("reader").unwrap(),
        (
            true,
            [Iri::new("https://fixture.example/Reader").unwrap()].into(),
        ),
    );
    state
}
