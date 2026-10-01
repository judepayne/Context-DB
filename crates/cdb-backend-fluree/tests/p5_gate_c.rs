//! P5 Gate C characterization, not a concurrency fix or a P5 egress implementation.
//! Prepared envelopes are trusted test data: no Rhai/engine execution is claimed.
use cdb_backend_fluree::{
    policy::PolicyState,
    runs::{ExternalPublicationFence, Operation},
    AuthorityOptions, FlureeBackend,
};
use cdb_core::{
    admission::{AdmissionBatch, DependencyRecord, Fact, FactTerm, ResourceChange, ResourceKind},
    artifact::ArtifactRef,
    canonical::CanonicalProjection,
    contracts::{GraphBackend, PolicyService},
    id::*,
    recording::*,
    snapshot::SnapshotRef,
    CanonicalValue as V, ErrorKind, Limits, Result,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Condvar, Mutex,
};
use tokio::sync::{oneshot, Notify};
#[path = "../../cdb-core/tests/common/mod.rs"]
mod common;

// Same independently hashed v2 fixture binding as run_service_gates.rs.
fn envelope(snapshot: SnapshotRef, id: &str, owner: &str) -> RunEnvelope {
    let limits = Limits::default();
    let mut value = common::fixture("plan");
    let V::Object(root) = &mut value else {
        unreachable!()
    };
    let V::Object(payload) = root.get_mut("payload").unwrap() else {
        unreachable!()
    };
    let V::Object(artifacts) = payload.get_mut("artifacts").unwrap() else {
        unreachable!()
    };
    artifacts.insert("query".into(), artifacts["config"].clone());
    let plan = CanonicalProjection::read(&value.canonical_bytes(limits).unwrap(), limits).unwrap();
    let config = ArtifactRef::from_value(
        plan.payload()
            .field("artifacts")
            .unwrap()
            .field("config")
            .unwrap(),
    )
    .unwrap();
    let data = ReplayData::new(
        ReplayDataInput {
            snapshot: snapshot.clone(),
            requested_snapshot: snapshot,
            as_of: cdb_core::Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
            stale: false,
            plan_hash: ContentHash::parse(
                "sha256:c62caf74fbecd39100be7fa9fbcbcea7f9c0bb84815814c125fcfc61bc9fe5a3",
            )
            .unwrap(),
            plan,
            response: CanonicalProjection::read(
                &common::fixture("response").canonical_bytes(limits).unwrap(),
                limits,
            )
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
        },
        limits,
    )
    .unwrap();
    RunEnvelope::new(
        RunId::new(id).unwrap(),
        PrincipalId::new(owner).unwrap(),
        ContentHash::of_bytes(id.as_bytes()),
        data,
        limits,
    )
    .unwrap()
}
fn policy(allow: bool) -> cdb_core::policy::PolicySet {
    cdb_core::policy::PolicySet::parse(format!(r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{{"@id":"https://gate.example/view","@type":["https://ns.flur.ee/db#AccessPolicy","https://ctxql.org/roles/serviceRead"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":{allow}}}]}}"#).as_bytes(), Limits::default()).unwrap()
}
fn batch(id: &str) -> AdmissionBatch {
    AdmissionBatch::new(
        vec![],
        vec![],
        vec![ResourceChange::Add(
            DependencyRecord::new(
                "ctxql-resource/v1",
                ResourceId::new(id).unwrap(),
                ResourceKind::Identity,
                vec![Fact::new(
                    Iri::new("urn:gate:kind").unwrap(),
                    FactTerm::Reference(ResourceId::new("urn:gate:entity").unwrap()),
                )],
            )
            .unwrap(),
        )],
        vec![],
        V::object([]).unwrap(),
        Limits::default(),
    )
    .unwrap()
}
async fn setup() -> (tempfile::TempDir, Arc<FlureeBackend>, PolicyState) {
    let dir = tempfile::tempdir().unwrap();
    let options = AuthorityOptions::new(
        dir.path().join("db"),
        "gate-c:main".into(),
        BackendId::new("fluree").unwrap(),
        AuthorityId::new("owner").unwrap(),
        GraphId::new("graph").unwrap(),
    );
    let b = Arc::new(FlureeBackend::create(options).await.unwrap());
    b.bootstrap_governance().await.unwrap();
    let mut state = PolicyState::deny_all().unwrap();
    state.policy = policy(true);
    for name in ["alice", "bob"] {
        state.principals.insert(
            PrincipalId::new(name).unwrap(),
            (
                true,
                [Operation::Query, Operation::Read]
                    .into_iter()
                    .map(|o| Iri::http(o.role()).unwrap())
                    .collect(),
            ),
        );
    }
    b.set_policy_state(&IdempotencyKey::new("initial-policy").unwrap(), &state)
        .await
        .unwrap();
    b.admit(&IdempotencyKey::new("seed").unwrap(), &batch("seed"))
        .await
        .unwrap();
    (dir, b, state)
}
struct OpenFence;
impl ExternalPublicationFence for OpenFence {
    fn check(&self) -> Result<()> {
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
enum Mutation {
    PeerRun,
    UnrelatedData,
    Policy,
    Disable,
}

async fn characterize(mutation: Mutation) {
    let (_dir, b, mut state) = setup().await;
    let original_pin = b.head().await.unwrap();
    let old_view = GraphBackend::open_snapshot(b.as_ref(), &original_pin)
        .await
        .unwrap();
    let seed = ResourceId::new("seed").unwrap();
    let before = old_view.resource(&seed).await.unwrap();
    assert!(before.is_some());
    let p = b
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let context = b.current(&p).await.unwrap();
    let fresh_alice = p.clone();
    assert!(b.resource_allowed(&context, &seed).unwrap());
    let run_a = envelope(original_pin.clone(), "run-a", "alice");
    let sinks = Arc::new(AtomicUsize::new(0));
    let (ready_tx, ready_rx) = oneshot::channel();
    let (resume_tx, resume_rx) = oneshot::channel();
    let paused = {
        let b = b.clone();
        let sinks = sinks.clone();
        let seed = seed.clone();
        tokio::spawn(async move {
            // A's permission context and candidate envelope exist before B can mutate.
            ready_tx.send(()).unwrap();
            resume_rx.await.unwrap();
            let read = b.resource_allowed(&context, &seed).unwrap_err().kind;
            let released = sinks.clone();
            let release = b
                .clone()
                .guarded_owned_release(
                    p.clone(),
                    context.clone(),
                    Operation::Read,
                    None,
                    Box::new(OpenFence),
                    move || {
                        released.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .await
                .unwrap_err()
                .kind;
            let committed = sinks.clone();
            let commit = b
                .guarded_owned_commit_record(p, context, run_a, Box::new(OpenFence), move |_, _| {
                    committed.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
                .unwrap_err()
                .kind;
            (read, release, commit)
        })
    };
    ready_rx.await.unwrap();
    match mutation {
        Mutation::PeerRun => {
            let peer = b
                .issue_principal(PrincipalId::new("bob").unwrap())
                .await
                .unwrap();
            let fresh = b.current(&peer).await.unwrap();
            b.clone()
                .guarded_owned_commit_record(
                    peer,
                    fresh,
                    envelope(original_pin.clone(), "run-b", "bob"),
                    Box::new(OpenFence),
                    |_, _| Ok(()),
                )
                .await
                .unwrap();
        }
        Mutation::UnrelatedData => {
            b.admit(
                &IdempotencyKey::new("unrelated").unwrap(),
                &batch("unrelated"),
            )
            .await
            .unwrap();
        }
        Mutation::Policy => {
            state.policy = policy(false);
            b.set_policy_state(&IdempotencyKey::new("deny-view").unwrap(), &state)
                .await
                .unwrap();
        }
        Mutation::Disable => {
            state
                .principals
                .get_mut(&PrincipalId::new("alice").unwrap())
                .unwrap()
                .0 = false;
            b.set_policy_state(&IdempotencyKey::new("disable-alice").unwrap(), &state)
                .await
                .unwrap();
        }
    }
    assert_eq!(b.policy_state().await.unwrap(), state);
    let after_mutation = b.head().await.unwrap();
    assert_ne!(original_pin, after_mutation);
    resume_tx.send(()).unwrap();
    let (read, release, commit) = paused.await.unwrap();
    assert_eq!(read, ErrorKind::PolicyChanged, "{mutation:?}");
    let guarded = if matches!(mutation, Mutation::Disable) {
        ErrorKind::Denied
    } else {
        ErrorKind::PolicyChanged
    };
    assert_eq!(release, guarded, "{mutation:?}");
    assert_eq!(commit, guarded, "{mutation:?}");
    assert_eq!(sinks.load(Ordering::SeqCst), 0);
    assert_eq!(
        b.head().await.unwrap(),
        after_mutation,
        "stale A must not commit"
    );
    assert_eq!(old_view.identity(), &original_pin);
    assert_eq!(old_view.resource(&seed).await.unwrap(), before);

    // An enabled observer can establish A's absence through the actual protected lookup.
    let observer = b
        .issue_principal(PrincipalId::new("bob").unwrap())
        .await
        .unwrap();
    let fresh = b.current(&observer).await.unwrap();
    assert!(b
        .guarded_find_run(
            &observer,
            &fresh,
            &RunId::new("run-a").unwrap(),
            Operation::Query
        )
        .await
        .unwrap()
        .is_none());
    if matches!(mutation, Mutation::PeerRun) {
        let stored = b
            .guarded_run(&observer, &fresh, &RunId::new("run-b").unwrap())
            .await
            .unwrap();
        assert_eq!(stored.replay().data().snapshot, original_pin);
    }
    if matches!(mutation, Mutation::Disable) {
        assert_eq!(
            b.current(&fresh_alice).await.err().unwrap().kind,
            ErrorKind::Denied
        );
    } else {
        let alice = fresh_alice;
        let fresh = b.current(&alice).await.unwrap();
        assert_eq!(
            b.resource_allowed(&fresh, &seed).unwrap(),
            !matches!(mutation, Mutation::Policy)
        );
        if !matches!(mutation, Mutation::Policy) {
            let released = sinks.clone();
            b.clone()
                .guarded_owned_release(
                    alice,
                    fresh,
                    Operation::Read,
                    None,
                    Box::new(OpenFence),
                    move || {
                        released.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .await
                .unwrap();
            assert_eq!(sinks.load(Ordering::SeqCst), 1);
        }
    }
}
// These probes compose several large unoptimized SDK futures. Reserve a bounded
// test stack explicitly instead of requiring a process-wide RUST_MIN_STACK override.
fn native_test<F: std::future::Future<Output = ()>>(make: impl FnOnce() -> F + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(make());
        })
        .unwrap()
        .join()
        .unwrap();
}
#[test]
fn peer_run_commit_invalidates_prepared_context_without_policy_change() {
    native_test(|| characterize(Mutation::PeerRun));
}
#[test]
fn unrelated_data_commit_invalidates_prepared_context_without_policy_change() {
    native_test(|| characterize(Mutation::UnrelatedData));
}
#[test]
fn actual_policy_change_invalidates_old_context_and_changes_fresh_decision() {
    native_test(|| characterize(Mutation::Policy));
}
#[test]
fn principal_disable_denies_guarded_release_and_record() {
    native_test(|| characterize(Mutation::Disable));
}

struct PausedFence {
    entered: Arc<Notify>,
    release: Arc<(Mutex<bool>, Condvar)>,
    dropped: Option<oneshot::Sender<()>>,
    first: AtomicBool,
}
impl ExternalPublicationFence for PausedFence {
    fn check(&self) -> Result<()> {
        if !self.first.swap(true, Ordering::SeqCst) {
            self.entered.notify_one();
            let (lock, condition) = &*self.release;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = condition.wait(open).unwrap();
            }
        }
        Ok(())
    }
}
impl Drop for PausedFence {
    fn drop(&mut self) {
        if let Some(sender) = self.dropped.take() {
            let _ = sender.send(());
        }
    }
}
#[test]
fn aborting_waiter_preserves_owned_commit_and_fence_until_completion() {
    native_test(owned_commit_probe);
}
async fn owned_commit_probe() {
    let (_dir, b, _) = setup().await;
    let p = b
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let c = b.current(&p).await.unwrap();
    let run = envelope(b.head().await.unwrap(), "owned", "alice");
    let entered = Arc::new(Notify::new());
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (dropped, mut dropped_rx) = oneshot::channel();
    let (sink, sink_rx) = oneshot::channel();
    let fence = PausedFence {
        entered: entered.clone(),
        release: release.clone(),
        dropped: Some(dropped),
        first: AtomicBool::new(false),
    };
    let owner = b.clone();
    let caller = tokio::spawn(async move {
        owner
            .guarded_owned_commit_record(p, c, run, Box::new(fence), move |_, _| {
                sink.send(()).unwrap();
                Ok(())
            })
            .await
    });
    // Public fence pauses the owned operation at entry, NOT inside the SDK commit.
    entered.notified().await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(matches!(
        dropped_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    *release.0.lock().unwrap() = true;
    release.1.notify_all();
    sink_rx.await.unwrap();
    dropped_rx.await.unwrap();
    let p = b
        .issue_principal(PrincipalId::new("alice").unwrap())
        .await
        .unwrap();
    let c = b.current(&p).await.unwrap();
    assert_eq!(
        b.guarded_run(&p, &c, &RunId::new("owned").unwrap())
            .await
            .unwrap()
            .id()
            .as_str(),
        "owned"
    );
}
