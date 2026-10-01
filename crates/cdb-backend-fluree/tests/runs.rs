use cdb_backend_fluree::{
    policy::PolicyState,
    runs::{ExternalPublicationFence, Operation},
    AuthorityOptions, FlureeBackend,
};
use cdb_core::{
    artifact::ArtifactRef, canonical::CanonicalProjection, contracts::PolicyService, id::*,
    recording::*, CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[path = "../../cdb-core/tests/common/mod.rs"]
mod common;
use common::fixture;
fn input(snapshot: cdb_core::snapshot::SnapshotRef) -> ReplayDataInput {
    let l = Limits::default();
    let mut p = fixture("plan");
    let V::Object(root) = &mut p else {
        unreachable!()
    };
    let V::Object(payload) = root.get_mut("payload").unwrap() else {
        unreachable!()
    };
    let V::Object(a) = payload.get_mut("artifacts").unwrap() else {
        unreachable!()
    };
    a.insert("query".into(), a["config"].clone());
    let plan = CanonicalProjection::read(&p.canonical_bytes(l).unwrap(), l).unwrap();
    let config = ArtifactRef::from_value(
        plan.payload()
            .field("artifacts")
            .unwrap()
            .field("config")
            .unwrap(),
    )
    .unwrap();
    ReplayDataInput {
        snapshot: snapshot.clone(),
        requested_snapshot: snapshot.clone(),
        as_of: cdb_core::Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
        stale: false,
        // Independent Python hashlib over the existing vector with query=config binding.
        plan_hash: ContentHash::parse(
            "sha256:c62caf74fbecd39100be7fa9fbcbcea7f9c0bb84815814c125fcfc61bc9fe5a3",
        )
        .unwrap(),
        plan,
        response: CanonicalProjection::read(&fixture("response").canonical_bytes(l).unwrap(), l)
            .unwrap(),
        response_hash: ContentHash::parse(
            "sha256:17489b4f791a43e0a36b1af79ea9eacd60e7ecbfda760516503be24ca0dba55a",
        )
        .unwrap(),
        query: config.clone(),
        config,
        profile: None,
        engine: RecordingEngine {
            name: ResourceId::new("engine").unwrap(),
            version: VersionId::new("1").unwrap(),
            build: ContentHash::of_bytes(b"engine"),
        },
        replay_abi: VersionId::new("native/v1").unwrap(),
        landings: vec![],
        catalog: vec![],
        policy: vec![],
        reads: vec![],
        scopes: REQUIRED_SCOPES
            .iter()
            .map(|s| ResourceId::new(*s).unwrap())
            .collect(),
        functions: vec![],
    }
}

fn options(path: &std::path::Path) -> AuthorityOptions {
    AuthorityOptions::new(
        path.join("db"),
        "runs:main".into(),
        BackendId::new("fluree").unwrap(),
        AuthorityId::new("owner").unwrap(),
        GraphId::new("graph").unwrap(),
    )
}
async fn setup() -> (tempfile::TempDir, Arc<FlureeBackend>) {
    let dir = tempfile::tempdir().unwrap();
    let b = Arc::new(FlureeBackend::create(options(dir.path())).await.unwrap());
    b.bootstrap_governance().await.unwrap();
    let mut state = PolicyState::deny_all().unwrap();
    let roles = [Operation::Query, Operation::Read]
        .into_iter()
        .map(|o| Iri::http(o.role()).unwrap())
        .collect();
    state
        .principals
        .insert(PrincipalId::new("alice").unwrap(), (true, roles));
    state.principals.insert(
        PrincipalId::new("bob").unwrap(),
        (
            true,
            [Operation::Read]
                .into_iter()
                .map(|o| Iri::http(o.role()).unwrap())
                .collect(),
        ),
    );
    state.policy = cdb_core::policy::PolicySet::parse(br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{"@id":"https://test.example/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}]}"#, Limits::default()).unwrap();
    b.set_policy_state(&IdempotencyKey::new("policy").unwrap(), &state)
        .await
        .unwrap();
    (dir, b)
}
async fn envelope(b: &FlureeBackend) -> RunEnvelope {
    RunEnvelope::new(
        RunId::new("r1").unwrap(),
        PrincipalId::new("alice").unwrap(),
        ContentHash::of_bytes(b"operation"),
        ReplayData::new(input(b.head().await.unwrap()), Limits::default()).unwrap(),
        Limits::default(),
    )
    .unwrap()
}
struct Fence(Arc<AtomicBool>);
impl ExternalPublicationFence for Fence {
    fn check(&self) -> Result<()> {
        if self.0.load(Ordering::SeqCst) {
            Err(Error::new(ErrorKind::Denied, "cancelled"))
        } else {
            Ok(())
        }
    }
}
async fn commit(
    b: Arc<FlureeBackend>,
    r: RunEnvelope,
    fail: bool,
) -> Result<cdb_core::snapshot::SnapshotRef> {
    let p = b
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let c = b.current(&p).await.unwrap();
    b.guarded_owned_commit_record(
        p,
        c,
        r,
        Box::new(Fence(Arc::new(AtomicBool::new(false)))),
        move |_, _| {
            if fail {
                Err(Error::new(ErrorKind::Backend, "sink failed"))
            } else {
                Ok(())
            }
        },
    )
    .await
}
#[tokio::test]
async fn recording_reopen_hash_and_retry() {
    let (dir, b) = setup().await;
    let r = envelope(&b).await;
    let receipt = commit(b.clone(), r.clone(), false).await.unwrap();
    assert_eq!(commit(b.clone(), r.clone(), false).await.unwrap(), receipt);
    drop(b);
    let b = FlureeBackend::open(options(dir.path())).await.unwrap();
    let p = b.issue_principal(r.owner().clone()).await.unwrap();
    let got = b
        .guarded_run(&p, &b.current(&p).await.unwrap(), r.id())
        .await
        .unwrap();
    assert_eq!(
        got.integrity_hash(Limits::default()).unwrap(),
        r.integrity_hash(Limits::default()).unwrap()
    );
}
#[tokio::test]
async fn changed_retry_conflicts() {
    let (_d, b) = setup().await;
    let r = envelope(&b).await;
    commit(b.clone(), r.clone(), false).await.unwrap();
    let changed = RunEnvelope::new(
        r.id().clone(),
        r.owner().clone(),
        ContentHash::of_bytes(b"changed"),
        r.replay().clone(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        commit(b, changed, false).await.unwrap_err().kind,
        ErrorKind::Conflict
    );
}
#[tokio::test]
async fn another_reader_cannot_read_owner_run() {
    let (_d, b) = setup().await;
    let r = envelope(&b).await;
    commit(b.clone(), r.clone(), false).await.unwrap();
    let p = b
        .issue_principal(PrincipalId::new("bob").unwrap())
        .await
        .unwrap();
    assert_eq!(
        b.guarded_run(&p, &b.current(&p).await.unwrap(), r.id())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
}
#[tokio::test]
async fn sink_failure_leaves_recoverable_run() {
    let (_d, b) = setup().await;
    let r = envelope(&b).await;
    assert!(commit(b.clone(), r.clone(), true).await.is_err());
    let p = b.issue_principal(r.owner().clone()).await.unwrap();
    assert_eq!(
        b.guarded_run(&p, &b.current(&p).await.unwrap(), r.id())
            .await
            .unwrap(),
        r
    );
}
#[tokio::test]
async fn cancellation_precommit_has_no_write_or_sink() {
    let (_d, b) = setup().await;
    let r = envelope(&b).await;
    let before = b.head().await.unwrap();
    let p = b.issue_principal(r.owner().clone()).await.unwrap();
    let c = b.current(&p).await.unwrap();
    assert!(b
        .clone()
        .guarded_owned_commit_record(
            p,
            c,
            r,
            Box::new(Fence(Arc::new(AtomicBool::new(true)))),
            |_, _| panic!("sink")
        )
        .await
        .is_err());
    assert_eq!(b.head().await.unwrap(), before);
}
#[tokio::test]
async fn positive_missing_dependency_denies_but_negative_does_not() {
    let (_d, b) = setup().await;
    let r = envelope(&b).await;
    let mut i = r.replay().data().clone();
    i.policy.push(PolicyObservation {
        resource: ResourceId::new("missing").unwrap(),
        predicate: None,
        allowed: true,
    });
    let make = |i| {
        RunEnvelope::new(
            r.id().clone(),
            r.owner().clone(),
            r.operation_hash().clone(),
            ReplayData::new(i, Limits::default()).unwrap(),
            Limits::default(),
        )
        .unwrap()
    };
    let before = b.head().await.unwrap();
    assert_eq!(
        commit(b.clone(), make(i.clone()), false)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
    assert_eq!(before, b.head().await.unwrap());
    i.policy[0].allowed = false;
    commit(b, make(i), false).await.unwrap();
}
#[tokio::test]
async fn governance_idempotent_and_no_credential_grants() {
    let (_d, b) = setup().await;
    let before = b.head().await.unwrap();
    b.bootstrap_governance().await.unwrap();
    assert_eq!(before, b.head().await.unwrap());
    let p = b
        .issue_principal(PrincipalId::new("bob").unwrap())
        .await
        .unwrap();
    let c = b.current(&p).await.unwrap();
    assert!(b.operation_allowed(&c, Operation::Read).unwrap());
    assert!(!b.operation_allowed(&c, Operation::Publish).unwrap());
}
