use crate::native::*;
use fluree_db_nameservice::NameServiceEvent;

#[tokio::test(flavor = "current_thread")]
async fn native_ownership_exact_payload_history_and_event() -> NativeResult<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("authority");
    let ledger = "native-proof:main".to_string();
    assert!(NativeStore::open(
        path.clone(),
        ledger.clone(),
        OpenMode::OpenExisting,
        NativeLimits::default()
    )
    .await
    .is_err());
    assert!(!path.exists());
    let store = NativeStore::open(
        path.clone(),
        ledger.clone(),
        OpenMode::CreateNew,
        NativeLimits::default(),
    )
    .await?;
    let genesis = store.head().await?;
    assert_eq!(genesis.t, 1);
    assert!(store.read_records(&genesis, None).await?.is_empty());
    assert!(NativeStore::open(
        path.clone(),
        ledger.clone(),
        OpenMode::CreateNew,
        NativeLimits::default()
    )
    .await
    .is_err());
    assert!(NativeStore::open(
        path.clone(),
        ledger.clone(),
        OpenMode::OpenExisting,
        NativeLimits::default()
    )
    .await
    .is_err());
    let a = NativeRecord { kind: "claim:東京".into(), key: "a:/%\"\\é".into(), hash: "opaque-hash-A".into(), payload: "{\"large\":900719925474099312345678901234567890,\"decimal\":1.000000000000000000000001,\"unicode\":\"café 東京 🦀\"}".into() };
    let mut events = store.event_receiver();
    let pin_a = store.commit(&genesis, vec![], vec![a.clone()]).await?;
    assert_eq!(pin_a.t, 2);
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let event = events.recv().await.unwrap();
            if let NameServiceEvent::LedgerCommitPublished {
                ledger_id,
                commit_id,
                commit_t,
            } = event
            {
                if ledger_id == ledger {
                    break (commit_id.to_string(), commit_t);
                }
            }
        }
    })
    .await?;
    assert_eq!(event, (pin_a.cid.clone(), pin_a.t));
    assert_eq!(store.read_records(&pin_a, None).await?, vec![a.clone()]);
    let mut b = a.clone();
    b.payload = "replacement".into();
    b.hash = "opaque-hash-B".into();
    let pin_b = store
        .commit(&pin_a, vec![a.clone()], vec![b.clone()])
        .await?;
    assert_eq!(store.head().await?, pin_b);
    assert!(store.commit(&pin_a, vec![], vec![b.clone()]).await.is_err());
    assert_eq!(
        store
            .read_records(&pin_a, Some((a.kind.clone(), a.key.clone())))
            .await?,
        vec![a.clone()]
    );
    assert_eq!(store.read_records(&pin_b, None).await?, vec![b.clone()]);
    let bad = NativePin {
        t: pin_a.t,
        cid: pin_b.cid.clone(),
    };
    assert!(store.validate_pin(&bad).await.is_err());
    assert!(store.read_records(&bad, None).await.is_err());
    drop(store); // Must not panic when dropping owned runtime inside a reactor.
    let reopened = NativeStore::open(
        path.clone(),
        ledger.clone(),
        OpenMode::OpenExisting,
        NativeLimits::default(),
    )
    .await?;
    assert_eq!(reopened.head().await?, pin_b);
    assert_eq!(reopened.read_records(&pin_a, None).await?, vec![a]);
    assert_eq!(reopened.read_records(&pin_b, None).await?, vec![b]);
    drop(reopened);
    assert!(
        NativeStore::open(path, ledger, OpenMode::CreateNew, NativeLimits::default())
            .await
            .is_err()
    );
    assert_ne!(record_iri("a:b", "c"), record_iri("a", "b:c"));
    assert_ne!(record_iri("a", "%00"), record_iri("a", "\0"));
    Ok(())
}

#[tokio::test]
async fn native_limits_fail_without_partial_commit() -> NativeResult<()> {
    let temp = tempfile::tempdir()?;
    let limits = NativeLimits {
        max_transaction_bytes: 32,
        ..NativeLimits::default()
    };
    let store = NativeStore::open(
        temp.path().join("authority"),
        "limits:main".into(),
        OpenMode::CreateNew,
        limits,
    )
    .await?;
    let pin = store.head().await?;
    let record = NativeRecord {
        kind: "claim".into(),
        key: "a".into(),
        hash: "hash".into(),
        payload: "x".repeat(100),
    };
    assert!(store.commit(&pin, vec![], vec![record]).await.is_err());
    assert_eq!(store.head().await?, pin);
    Ok(())
}
