use cdb_core::id::{ContentHash, PrincipalId};
use cdb_service::auth::*;
use std::time::{Duration, SystemTime};

fn principal() -> PrincipalId {
    PrincipalId::new("principal:alice").unwrap()
}
fn setup(expiry: Option<SystemTime>, caps: Capabilities, ttl: Duration) -> (String, AuthStore) {
    let (secret, record) = provision(principal(), expiry, caps).unwrap();
    (
        secret.into_string(),
        AuthStore::new(vec![record], ttl).unwrap(),
    )
}
fn record(token: &str, enabled: bool) -> CredentialRecord {
    CredentialRecord::new(
        ContentHash::of_bytes(token.as_bytes()).as_str(),
        principal(),
        enabled,
        None,
        Capabilities::all(),
    )
    .unwrap()
}

#[tokio::test]
async fn strict_tokens_and_unknown_are_uniformly_denied() {
    let (token, store) = setup(None, Capabilities::all(), MAX_SESSION_TTL);
    assert_eq!(token.len(), 71);
    let session = store.authenticate(&token).await.unwrap();
    assert_eq!(
        store
            .lease(&session, Operation::Query)
            .await
            .unwrap()
            .principal(),
        &principal()
    );
    for bad in [
        String::new(),
        format!(" {token}"),
        token.to_uppercase(),
        format!("{token}\n"),
        format!("ctxql1_{}", "0".repeat(64)),
        "x".repeat(100_000),
    ] {
        assert!(matches!(store.authenticate(&bad).await, Err(Denied)));
    }
    assert_eq!(Denied.to_string(), "denied");
}

#[tokio::test]
async fn duplicate_disabled_and_table_bounds_fail_closed() {
    let token = format!("ctxql1_{}", "1".repeat(64));
    assert!(AuthStore::new(
        vec![record(&token, true), record(&token, false)],
        MAX_SESSION_TTL
    )
    .is_err());
    assert!(AuthStore::new(vec![], MAX_SESSION_TTL).is_err());
    assert!(AuthStore::new(
        (0..=MAX_CREDENTIALS)
            .map(|_| record(&token, true))
            .collect(),
        MAX_SESSION_TTL
    )
    .is_err());
    assert!(AuthStore::new(vec![record(&token, true)], Duration::ZERO).is_err());
    assert!(AuthStore::new(
        vec![record(&token, true)],
        MAX_SESSION_TTL + Duration::from_secs(1)
    )
    .is_err());
    let store = AuthStore::new(vec![record(&token, false)], MAX_SESSION_TTL).unwrap();
    assert!(matches!(store.authenticate(&token).await, Err(Denied)));
    assert!(
        CredentialRecord::new("sha256:ABC", principal(), true, None, Capabilities::all()).is_err()
    );
}

#[tokio::test]
async fn v2_maximum_lifetime_is_real_and_credential_expiry_still_wins() {
    let token = format!("ctxql1_{}", "2".repeat(64));
    let store = AuthStore::new(vec![record(&token, true)], Duration::from_secs(86_400));
    assert!(store.is_ok());
    assert!(AuthStore::new(vec![record(&token, true)], Duration::from_secs(86_401),).is_err());

    let (expired, store) = setup(
        Some(SystemTime::now() - Duration::from_millis(1)),
        Capabilities::all(),
        Duration::from_secs(86_400),
    );
    assert!(matches!(store.authenticate(&expired).await, Err(Denied)));
}

#[tokio::test]
async fn expiry_is_checked_at_authentication_and_final_publication() {
    let (token, store) = setup(
        Some(SystemTime::now() - Duration::from_secs(1)),
        Capabilities::all(),
        MAX_SESSION_TTL,
    );
    assert!(matches!(store.authenticate(&token).await, Err(Denied)));
    let (token, store) = setup(
        Some(SystemTime::now() + Duration::from_millis(150)),
        Capabilities::all(),
        MAX_SESSION_TTL,
    );
    let session = store.authenticate(&token).await.unwrap();
    let lease = store.lease(&session, Operation::Read).await.unwrap();
    tokio::time::sleep(Duration::from_millis(180)).await;
    assert_eq!(lease.check(), Err(Denied));
}

#[tokio::test]
async fn held_session_and_lease_have_bounded_monotonic_ttl() {
    let (token, store) = setup(None, Capabilities::all(), Duration::from_millis(50));
    let session = store.authenticate(&token).await.unwrap();
    let lease = store.lease(&session, Operation::Replay).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(lease.check(), Err(Denied));
    assert!(matches!(
        store.lease(&session, Operation::Read).await,
        Err(Denied)
    ));
}

#[tokio::test]
async fn foreign_issuer_rejected_even_with_identical_credentials() {
    let (token, store) = setup(None, Capabilities::all(), MAX_SESSION_TTL);
    let other = AuthStore::new(vec![record(&token, true)], MAX_SESSION_TTL).unwrap();
    let session = store.authenticate(&token).await.unwrap();
    assert!(matches!(
        other.lease(&session, Operation::Query).await,
        Err(Denied)
    ));
    assert!(store
        .clone()
        .lease(&session, Operation::Query)
        .await
        .is_ok());
}

#[tokio::test]
async fn capabilities_only_narrow_operations() {
    let (token, store) = setup(
        None,
        Capabilities::only(&[Operation::Query, Operation::Read, Operation::Replay]),
        MAX_SESSION_TTL,
    );
    let session = store.authenticate(&token).await.unwrap();
    for operation in [Operation::Query, Operation::Read, Operation::Replay] {
        assert!(store.lease(&session, operation).await.is_ok());
    }
    for operation in [Operation::Publish, Operation::Admin] {
        assert!(matches!(
            store.lease(&session, operation).await,
            Err(Denied)
        ));
    }
}

#[tokio::test]
async fn shutdown_stops_admission_then_waits_for_owned_lease() {
    let (token, store) = setup(None, Capabilities::all(), MAX_SESSION_TTL);
    let session = store.authenticate(&token).await.unwrap();
    let lease = store.lease(&session, Operation::Query).await.unwrap();
    store.stop_admitting();
    let copy = store.clone();
    let shutdown = tokio::spawn(async move { copy.shutdown().await });
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    assert!(matches!(store.authenticate(&token).await, Err(Denied)));
    assert!(matches!(
        store.lease(&session, Operation::Query).await,
        Err(Denied)
    ));
    assert_eq!(lease.check(), Err(Denied));
    drop(lease);
    shutdown.await.unwrap();
    assert!(matches!(store.authenticate(&token).await, Err(Denied)));
}

#[tokio::test]
async fn cancelled_request_does_not_drop_detached_recording_lease() {
    fn send_static<T: Send + 'static>() {}
    send_static::<SessionLease>();
    let (token, store) = setup(None, Capabilities::all(), MAX_SESSION_TTL);
    let session = store.authenticate(&token).await.unwrap();
    let lease = store.lease(&session, Operation::Query).await.unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let request = tokio::spawn(async move {
        let detached = tokio::spawn(async move {
            let _ = release_rx.await;
            assert_eq!(lease.check(), Err(Denied));
            drop(lease);
        });
        ready_tx.send(detached).unwrap();
        std::future::pending::<()>().await;
    });
    let detached = ready_rx.await.unwrap();
    request.abort();
    let _ = request.await;
    store.stop_admitting();
    let shutdown = tokio::spawn(async move { store.shutdown().await });
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    release_tx.send(()).unwrap();
    detached.await.unwrap();
    shutdown.await.unwrap();
}
