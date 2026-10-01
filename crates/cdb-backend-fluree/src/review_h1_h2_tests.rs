use crate::{
    native::*,
    policy::PolicyState,
    runs::{ExternalPublicationFence, Operation},
    AuthorityOptions, FlureeBackend,
};
use cdb_core::{admission::*, contracts::PolicyService, id::*, CanonicalValue, Error, ErrorKind};
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::Poll,
};

fn options(path: &std::path::Path) -> AuthorityOptions {
    AuthorityOptions::new(
        path.join("db"),
        "review:main".into(),
        BackendId::new("b").unwrap(),
        AuthorityId::new("a").unwrap(),
        GraphId::new("g").unwrap(),
    )
}
fn key(s: &str) -> IdempotencyKey {
    IdempotencyKey::new(s).unwrap()
}
fn is_limit<T>(r: NativeResult<T>) {
    let e = r.err().expect("must reject before commit");
    assert_eq!(
        e.downcast_ref::<Error>().map(|e| e.kind),
        Some(ErrorKind::Limit),
        "{e}"
    );
}
struct OpenFence;
impl ExternalPublicationFence for OpenFence {
    fn check(&self) -> cdb_core::Result<()> {
        Ok(())
    }
}

fn empty_batch() -> NativeResult<AdmissionBatch> {
    Ok(AdmissionBatch::new(
        vec![],
        vec![],
        vec![],
        vec![],
        CanonicalValue::object([])?,
        Default::default(),
    )?)
}

#[tokio::test]
async fn query_action_holds_revocation_gate_through_publication() -> NativeResult<()> {
    let tmp = tempfile::tempdir()?;
    let b = Arc::new(FlureeBackend::create(options(tmp.path())).await?);
    let id = PrincipalId::new("query-user")?;
    let mut state = PolicyState::deny_all()?;
    state.principals.insert(
        id.clone(),
        (
            true,
            BTreeSet::from([cdb_core::id::Iri::new(Operation::Query.role())?]),
        ),
    );
    b.set_policy_state(&key("query-enable"), &state).await?;
    let principal = b.issue_principal(id).await?;
    let context = b.current(&principal).await?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let published = Arc::new(AtomicBool::new(false));
    let action_backend = b.clone();
    let action_entered = entered.clone();
    let action_release = release.clone();
    let action_published = published.clone();
    let action = tokio::spawn(async move {
        action_backend
            .guarded_owned_query_action(
                principal,
                context,
                Box::new(OpenFence),
                move || async move {
                    action_entered.notify_one();
                    action_release.notified().await;
                    action_published.store(true, Ordering::Release);
                    Ok(())
                },
            )
            .await
    });
    entered.notified().await;
    let revoker = b.clone();
    let revoke = tokio::spawn(async move {
        revoker
            .set_policy_state(&key("query-revoke"), &PolicyState::deny_all()?)
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), async {
            while !revoke.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_err()
    );
    assert!(!published.load(Ordering::Acquire));
    release.notify_one();
    action.await.unwrap()?;
    assert!(published.load(Ordering::Acquire));
    revoke.await.unwrap()?;
    Ok(())
}

#[tokio::test]
async fn canceled_revocation_keeps_publish_fenced_and_publishes_epoch() -> NativeResult<()> {
    let tmp = tempfile::tempdir()?;
    let b = Arc::new(FlureeBackend::create(options(tmp.path())).await?);
    let id = PrincipalId::new("alice")?;
    let mut state = PolicyState::deny_all()?;
    state.principals.insert(id.clone(), (true, BTreeSet::new()));
    b.set_policy_state(&key("enable"), &state).await?;
    let principal = b.issue_principal(id).await?;
    let context = b.current(&principal).await?;
    let before = b.policy_epoch.load(Ordering::Acquire);
    let (entered, release) = b.native.pause_commit().await;
    let writer = b.clone();
    let task = tokio::spawn(async move {
        writer
            .set_policy_state(&key("revoke"), &PolicyState::deny_all()?)
            .await
    });
    entered.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(b.policy_epoch.load(Ordering::Acquire), before);
    let mut calls = 0;
    let mut sink = || {
        calls += 1;
        Ok(())
    };
    let mut publish = b.publish(&principal, &context, &mut sink);
    std::future::poll_fn(|cx| {
        assert!(
            publish.as_mut().poll(cx).is_pending(),
            "orphan write released policy fence"
        );
        Poll::Ready(())
    })
    .await;
    release.notify_one();
    assert_eq!(publish.await.unwrap_err().kind, ErrorKind::PolicyChanged);
    assert_eq!(calls, 0);
    assert_eq!(b.policy_epoch.load(Ordering::Acquire), before + 1);
    let retry = b
        .set_policy_state(&key("revoke"), &PolicyState::deny_all()?)
        .await?;
    assert_eq!(retry.snapshot(), &b.head().await?);
    Ok(())
}

#[tokio::test]
async fn canceled_capture_and_admission_finish_epoch_before_releasing_gate() -> NativeResult<()> {
    let tmp = tempfile::tempdir()?;
    let b = Arc::new(FlureeBackend::create(options(tmp.path())).await?);
    for capture in [true, false] {
        let before = b.policy_epoch.load(Ordering::Acquire);
        let (entered, release) = b.native.pause_commit().await;
        let writer = b.clone();
        let task = tokio::spawn(async move {
            if capture {
                writer.capture(None).await.map(|_| ())
            } else {
                writer
                    .admit(&key("admit"), &empty_batch()?)
                    .await
                    .map(|_| ())
            }
        });
        entered.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(b.mutation_gate.try_lock().is_err());
        release.notify_one();
        b.head().await?;
        assert_eq!(b.policy_epoch.load(Ordering::Acquire), before + 1);
    }
    assert!(b.receipt(&key("admit")).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn cumulative_rows_reject_before_commit_and_restart_is_readable() -> NativeResult<()> {
    let tmp = tempfile::tempdir()?;
    let mut o = options(tmp.path());
    o.native_limits.max_records = 5;
    let b = FlureeBackend::create(o.clone()).await?;
    b.capture(None).await?; // cumulative work = 2 + 3 = 5, not just current rows
    let old = b.head().await?;
    is_limit(b.capture(None).await);
    is_limit(b.admit(&key("rejected"), &empty_batch()?).await);
    is_limit(
        b.set_policy_state(&key("policy"), &PolicyState::deny_all()?)
            .await,
    );
    assert_eq!(b.head().await?, old);
    assert!(b.receipt(&key("rejected")).await?.is_none());
    drop(b);
    let reopened = FlureeBackend::open(o).await?;
    assert_eq!(reopened.head().await?, old);
    is_limit(reopened.capture(None).await);
    assert_eq!(reopened.head().await?, old);
    Ok(())
}

#[tokio::test]
async fn image_byte_ceiling_preserves_receipt_and_reopen() -> NativeResult<()> {
    let probe = tempfile::tempdir()?;
    let b = FlureeBackend::create(options(probe.path())).await?;
    b.admit(&key("accepted"), &empty_batch()?).await?;
    let rows = b.native.read_records(&b.native.head().await?, None).await?;
    let cap = image_result_bytes(rows.iter())?;
    drop(b);
    let tmp = tempfile::tempdir()?;
    let mut o = options(tmp.path());
    o.native_limits.max_result_bytes = cap;
    let b = FlureeBackend::create(o.clone()).await?;
    let receipt = b.admit(&key("accepted"), &empty_batch()?).await?;
    let old = b.head().await?;
    is_limit(b.capture(None).await);
    assert_eq!(b.receipt(&key("accepted")).await?, Some(receipt.clone()));
    drop(b);
    let b = FlureeBackend::open(o).await?;
    assert_eq!(b.head().await?, old);
    assert_eq!(b.admit(&key("accepted"), &empty_batch()?).await?, receipt);
    is_limit(b.capture(None).await);
    Ok(())
}

#[tokio::test]
async fn bootstrap_budget_is_checked_before_authority_commit() -> NativeResult<()> {
    let tmp = tempfile::tempdir()?;
    let mut o = options(tmp.path());
    o.native_limits.max_records = 1;
    is_limit(FlureeBackend::create(o.clone()).await);
    let n = NativeStore::open(
        o.path,
        o.ledger,
        OpenMode::OpenExisting,
        NativeLimits::default(),
    )
    .await?;
    assert_eq!(n.head().await?.t, 1);
    Ok(())
}
