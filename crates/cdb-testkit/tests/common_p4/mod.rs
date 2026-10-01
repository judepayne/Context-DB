use cdb_backend_fluree::{
    policy::PolicyState, AuthorityOptions, FlureeBackend, NativeResult, WallClock,
};
use cdb_core::{id::*, snapshot::ProjectionCheckpoint, Timestamp};
use cdb_projection_redb::{GenerationOptions, RedbProjection};
use cdb_service::{
    auth::{AuthStore, Capabilities, CredentialRecord, Operation},
    config::{AuthorityConfig, InstanceConfig, InstanceRole, ServiceLimits},
    Service,
};
use cdb_testkit::reference_fixture::FixtureBuilder;
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
pub struct FixedClock;
impl WallClock for FixedClock {
    fn now(&self) -> NativeResult<Timestamp> {
        Ok(Timestamp::parse("2026-04-01T00:00:00.001Z")?)
    }
}
pub struct Fixture {
    pub root: tempfile::TempDir,
    pub backend: Arc<FlureeBackend>,
    pub service: Arc<Service>,
    pub token: String,
}
impl Fixture {
    pub fn config(root: &std::path::Path, work: usize) -> InstanceConfig {
        InstanceConfig {
            schema: "ctxql-instance/v1".into(),
            role: InstanceRole::Replayable,
            authority: Some(AuthorityConfig {
                path: root.join("authority"),
                ledger: "p4-corpus:main".into(),
                backend: "p4".into(),
                authority: "p4-authority".into(),
                graph: "p4-graph".into(),
            }),
            semantic: None,
            control: None,
            projection: root.join("projection"),
            credential_file: root.join("credentials"),
            source_root: root.join("sources"),
            bind: "127.0.0.1:8080".parse().unwrap(),
            default_config: None,
            broker: None,
            acquisition: None,
            chat: None,
            limits: ServiceLimits {
                max_work: work,
                deadline_seconds: 120,
                ..Default::default()
            },
        }
    }
    fn options(root: &std::path::Path) -> AuthorityOptions {
        let mut o = Self::config(root, 1_000_000).authority_options().unwrap();
        o.clock = Arc::new(FixedClock);
        o
    }
    fn auth(token: &str) -> AuthStore {
        AuthStore::new(
            vec![CredentialRecord::new(
                ContentHash::of_bytes(token.as_bytes()).as_str(),
                PrincipalId::new("reader").unwrap(),
                true,
                None,
                Capabilities::only(&[Operation::Query, Operation::Read, Operation::Replay]),
            )
            .unwrap()],
            Duration::from_secs(300),
        )
        .unwrap()
    }
    fn binding(pin: cdb_core::snapshot::SnapshotRef) -> ProjectionCheckpoint {
        ProjectionCheckpoint::new(
            pin,
            VersionId::new("ctxql-projection/v1").unwrap(),
            VersionId::new("live").unwrap(),
            Iri::new("urn:p3:raw").unwrap(),
        )
        .unwrap()
    }
    pub async fn new(builder: FixtureBuilder, mut state: PolicyState, work: usize) -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(root.path()).unwrap();
        std::fs::create_dir(path.join("sources")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path.join("sources"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let backend = Arc::new(FlureeBackend::create(Self::options(&path)).await.unwrap());
        backend
            .admit(
                &IdempotencyKey::new("fixture").unwrap(),
                &builder.into_batch().unwrap(),
            )
            .await
            .unwrap();
        backend.bootstrap_governance().await.unwrap();
        for op in [
            cdb_backend_fluree::runs::Operation::Query,
            cdb_backend_fluree::runs::Operation::Read,
            cdb_backend_fluree::runs::Operation::Replay,
        ] {
            state
                .principals
                .get_mut(&PrincipalId::new("reader").unwrap())
                .unwrap()
                .1
                .insert(Iri::new(op.role()).unwrap());
        }
        backend
            .set_policy_state(&IdempotencyKey::new("policy").unwrap(), &state)
            .await
            .unwrap();
        let store = Arc::new(
            RedbProjection::create(
                path.join("projection"),
                Self::binding(backend.head().await.unwrap()),
                GenerationOptions::default(),
            )
            .await
            .unwrap(),
        );
        let token = format!("ctxql1_{}", "a".repeat(64));
        let service = Service::attach(
            Self::config(&path, work),
            backend.clone(),
            store,
            Self::auth(&token),
        )
        .await
        .unwrap();
        Self {
            root,
            backend,
            service,
            token,
        }
    }
    pub async fn dispatch(
        &self,
        request: &cdb_core::CanonicalValue,
    ) -> cdb_core::Result<cdb_core::CanonicalValue> {
        let bytes = self
            .service
            .dispatch(
                &self.token,
                &request.canonical_bytes(cdb_core::Limits::default())?,
                Arc::new(AtomicBool::new(false)),
            )
            .await?;
        cdb_core::CanonicalValue::parse(&bytes, cdb_core::Limits::default())
    }
    pub async fn reopen(self) -> Self {
        let Self {
            root,
            backend,
            service,
            token,
        } = self;
        service.shutdown().await.unwrap();
        drop(service);
        assert_eq!(Arc::strong_count(&backend), 1);
        drop(backend);
        let path = std::fs::canonicalize(root.path()).unwrap();
        let backend = Arc::new(FlureeBackend::open(Self::options(&path)).await.unwrap());
        let store = Arc::new(
            RedbProjection::open(
                path.join("projection"),
                Self::binding(backend.head().await.unwrap()),
                GenerationOptions::default(),
            )
            .await
            .unwrap(),
        );
        let service = Service::attach(
            Self::config(&path, 1_000_000),
            backend.clone(),
            store,
            Self::auth(&token),
        )
        .await
        .unwrap();
        Self {
            root,
            backend,
            service,
            token,
        }
    }
    pub async fn shutdown(self) {
        self.service.shutdown().await.unwrap();
    }
}
