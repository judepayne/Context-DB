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
async fn payload_predicate_denial_blocks_stored_run_and_retry() {
    let (_d, b) = setup().await;
    let r = envelope(&b).await;
    commit(b.clone(), r.clone(), false).await.unwrap();
    let mut state = PolicyState::deny_all().unwrap();
    state.principals.insert(
        r.owner().clone(),
        (
            true,
            [Operation::Query, Operation::Read]
                .into_iter()
                .map(|o| Iri::http(o.role()).unwrap())
                .collect(),
        ),
    );
    let json = format!(
        r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{{"@id":"https://test.example/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}},{{"@id":"https://test.example/deny","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#onProperty":"{}","https://ns.flur.ee/db#allow":false}}]}}"#,
        RUN_PAYLOAD
    );
    state.policy = cdb_core::policy::PolicySet::parse(json.as_bytes(), Limits::default()).unwrap();
    b.set_policy_state(&IdempotencyKey::new("deny-payload").unwrap(), &state)
        .await
        .unwrap();
    let p = b.issue_principal(r.owner().clone()).await.unwrap();
    let c = b.current(&p).await.unwrap();
    assert_eq!(
        b.guarded_run(&p, &c, r.id()).await.unwrap_err().kind,
        ErrorKind::Denied
    );
    assert_eq!(
        commit(b.clone(), r, false).await.unwrap_err().kind,
        ErrorKind::Denied
    );
}
#[tokio::test]
async fn reader_cannot_publish_or_advance_head() {
    let (_d, b) = setup().await;
    let before = b.head().await.unwrap();
    let p = b
        .issue_principal(PrincipalId::new("bob").unwrap())
        .await
        .unwrap();
    let c = b.current(&p).await.unwrap();
    let artifact = cdb_core::artifact::PublishedArtifact::new(
        ArtifactRef::new(
            Iri::http("https://test.example/new").unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(b"new"),
        ),
        b"new".to_vec(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        b.clone()
            .guarded_owned_publish(
                p,
                c,
                artifact,
                Box::new(Fence(Arc::new(AtomicBool::new(false)))),
                |_, _| panic!("sink")
            )
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
    assert_eq!(before, b.head().await.unwrap());
}
#[tokio::test]
async fn retry_sink_uses_durable_envelope_not_candidate() {
    let (_d, b) = setup().await;
    let old = envelope(&b).await;
    commit(b.clone(), old.clone(), false).await.unwrap();
    let candidate = envelope(&b).await;
    assert_ne!(old, candidate);
    let p = b.issue_principal(old.owner().clone()).await.unwrap();
    let c = b.current(&p).await.unwrap();
    b.guarded_owned_commit_record(
        p,
        c,
        candidate,
        Box::new(Fence(Arc::new(AtomicBool::new(false)))),
        move |stored, _| {
            assert_eq!(stored, &old);
            Ok(())
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn publisher_can_publish_prospective_resource() {
    let (_d, b) = setup().await;
    let mut state = PolicyState::deny_all().unwrap();
    state.principals.insert(
        PrincipalId::new("alice").unwrap(),
        (
            true,
            [Operation::Publish]
                .into_iter()
                .map(|o| Iri::http(o.role()).unwrap())
                .collect(),
        ),
    );
    state.policy = cdb_core::policy::PolicySet::parse(br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{"@id":"https://test.example/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/servicePublish"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}]}"#, Limits::default()).unwrap();
    b.set_policy_state(&IdempotencyKey::new("publisher").unwrap(), &state)
        .await
        .unwrap();
    let p = b
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let c = b.current(&p).await.unwrap();
    let artifact = cdb_core::artifact::PublishedArtifact::new(
        ArtifactRef::new(
            Iri::http("https://test.example/new").unwrap(),
            VersionId::new("1").unwrap(),
            ContentHash::of_bytes(b"new"),
        ),
        b"new".to_vec(),
        Limits::default(),
    )
    .unwrap();
    let expected = artifact.reference().clone();
    let got = b
        .clone()
        .guarded_owned_publish(
            p,
            c,
            artifact,
            Box::new(Fence(Arc::new(AtomicBool::new(false)))),
            |_, _| Ok(()),
        )
        .await
        .unwrap();
    assert_eq!(got, expected);
}

#[tokio::test]
async fn enqueue_is_not_retroactively_failed_by_cancellation() {
    let (_d, b) = setup().await;
    let run = envelope(&b).await;
    let p = b.issue_principal(run.owner().clone()).await.unwrap();
    let c = b.current(&p).await.unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let in_sink = cancelled.clone();
    b.guarded_owned_commit_record(p, c, run, Box::new(Fence(cancelled)), move |_, _| {
        in_sink.store(true, Ordering::SeqCst);
        Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn lookup_operations_and_cancelled_release_are_guarded() {
    let (_d, b) = setup().await;
    let run = envelope(&b).await;
    let p = b.issue_principal(run.owner().clone()).await.unwrap();
    let c = b.current(&p).await.unwrap();
    assert!(b
        .guarded_find_run(&p, &c, run.id(), Operation::Query)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        b.guarded_run_for(&p, &c, run.id(), Operation::Read)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
    commit(b.clone(), run.clone(), false).await.unwrap();
    let c = b.current(&p).await.unwrap();
    assert_eq!(
        b.guarded_run_for(&p, &c, run.id(), Operation::Query)
            .await
            .unwrap(),
        run
    );
    assert_eq!(
        b.guarded_run_for(&p, &c, run.id(), Operation::Replay)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Denied
    );
    assert_eq!(
        b.guarded_owned_release(
            p,
            c,
            Operation::Read,
            Some(run),
            Box::new(Fence(Arc::new(AtomicBool::new(true)))),
            || panic!("cancelled sink")
        )
        .await
        .unwrap_err()
        .kind,
        ErrorKind::Denied
    );
}
