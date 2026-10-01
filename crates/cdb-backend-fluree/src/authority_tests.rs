use crate::{
    native::{NativeLimits, NativeResult, NativeStore, OpenMode},
    *,
};
use cdb_core::{
    admission::*, claim::*, id::*, snapshot::*, CanonicalValue as V, Limits, Timestamp,
};
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};
struct Clock(AtomicI64);
impl WallClock for Clock {
    fn now(&self) -> NativeResult<Timestamp> {
        Ok(Timestamp::from_millis(self.0.load(Ordering::SeqCst))?)
    }
}
fn setup() -> NativeResult<(tempfile::TempDir, AuthorityOptions, Arc<Clock>)> {
    let tmp = tempfile::tempdir()?;
    let clock = Arc::new(Clock(AtomicI64::new(-100)));
    let mut o = AuthorityOptions::new(
        tmp.path().join("db"),
        "authority:main".into(),
        BackendId::new("fluree")?,
        AuthorityId::new("owner")?,
        GraphId::new("graph")?,
    );
    o.clock = clock.clone();
    Ok((tmp, o, clock))
}
fn batch(resources: Vec<ResourceChange>, origin: &str) -> NativeResult<AdmissionBatch> {
    Ok(AdmissionBatch::new(
        vec![],
        vec![],
        resources,
        vec![],
        V::parse(origin.as_bytes(), Limits::default())?,
        Limits::default(),
    )?)
}
fn key(s: &str) -> IdempotencyKey {
    IdempotencyKey::new(s).unwrap()
}
fn resource(id: &str, kind: ResourceKind, s: &str) -> NativeResult<DependencyRecord> {
    Ok(DependencyRecord::new(
        "ctxql-resource/v1",
        ResourceId::new(id)?,
        kind,
        vec![Fact::new(
            Iri::new("urn:label")?,
            FactTerm::Literal(TypedLiteral::new(
                Iri::new("http://www.w3.org/2001/XMLSchema#string")?,
                V::string(s),
                None,
            )?),
        )],
    )?)
}
fn candidate(id: &str) -> CandidateClaim {
    let text = format!(
        r#"{{"claim_id":"{id}","subject_id":"subject","relation":"urn:rel","object_id":{{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#decimal","value":9007199254740993.00001,"language":null}},"relation_type":"urn:rt","subject_type":"urn:st","object_type":"urn:ot","claim_type":"urn:ct","confidence":0.75,"grounding_level":"claim_only"}}"#
    );
    CandidateClaim::from_value(&V::parse(text.as_bytes(), Limits::default()).unwrap()).unwrap()
}
#[tokio::test]
async fn retry_original_after_reopen_and_later_commit() -> NativeResult<()> {
    let (_tmp, o, _) = setup()?;
    let s = Authority::create(o.clone()).await?;
    let b = batch(vec![], r#"{"a":1,"b":2}"#)?;
    let r = s.admit(&key("key"), &b).await?;
    s.capture(None).await?;
    drop(s); // Deliberately discard acknowledgement at caller boundary; no bypass hook.
    let s = Authority::open(o).await?;
    let p = s.head().await?;
    assert_eq!(
        s.admit(&key("key"), &batch(vec![], r#"{"b":2.0,"a":1}"#)?)
            .await?,
        r
    );
    assert!(s
        .admit(&key("key"), &batch(vec![], r#"{"a":3}"#)?)
        .await
        .is_err());
    assert_eq!(s.head().await?, p);
    Ok(())
}
#[tokio::test]
async fn idle_capture_preepoch_and_rollback() -> NativeResult<()> {
    let (_tmp, o, c) = setup()?;
    let s = Authority::create(o).await?;
    let a = s.capture(None).await?;
    assert_eq!(a.as_of.millis(), -100);
    let b = s.capture(None).await?;
    assert_ne!(a.snapshot, b.snapshot);
    c.0.store(-500, Ordering::SeqCst);
    let r = s.admit(&key("a"), &batch(vec![], "{}")?).await?;
    assert_eq!(r.transaction_time().millis(), -99);
    let p = s.head().await?;
    assert!(s.capture(Some(Timestamp::from_millis(0)?)).await.is_err());
    assert_eq!(p, s.head().await?);
    Ok(())
}
#[tokio::test]
async fn persisted_identity_relocation_and_full_pin() -> NativeResult<()> {
    let (tmp, o, _) = setup()?;
    let s = Authority::create(o.clone()).await?;
    let pin = s.head().await?;
    drop(s);
    let mut wrong = o.clone();
    wrong.authority = AuthorityId::new("wrong")?;
    assert!(Authority::open(wrong).await.is_err());
    let mut moved = o.clone();
    moved.path = tmp.path().join("moved");
    std::fs::rename(&o.path, &moved.path)?;
    let s = Authority::open(moved).await?;
    assert_eq!(s.head().await?, pin);
    let foreign = SnapshotRef::new(BackendId::new("foreign")?, pin.pin().clone());
    assert!(s.validate_snapshot(&foreign).await.is_err());
    s.validate_snapshot(&pin).await?;
    Ok(())
}
#[tokio::test]
async fn mutable_previous_hash_atomic_and_origins() -> NativeResult<()> {
    let (_tmp, o, _) = setup()?;
    let s = Authority::create(o.clone()).await?;
    let a = resource("label", ResourceKind::Label, "A")?;
    let b = resource("label", ResourceKind::Label, "B")?;
    s.admit(
        &key("a"),
        &batch(vec![ResourceChange::Add(a.clone())], "{}")?,
    )
    .await?;
    let p = s.head().await?;
    assert!(s
        .admit(
            &key("bad"),
            &batch(
                vec![ResourceChange::ReplaceMutable {
                    previous: ContentHash::of_bytes(b"bad"),
                    record: b.clone()
                }],
                "{}"
            )?
        )
        .await
        .is_err());
    assert_eq!(p, s.head().await?);
    assert!(s.receipt(&key("bad")).await?.is_none());
    let hash = ContentHash::of_bytes(&a.projection().canonical_bytes(Limits::default())?);
    s.admit(
        &key("b"),
        &batch(
            vec![ResourceChange::ReplaceMutable {
                previous: hash,
                record: b.clone(),
            }],
            "{}",
        )?,
    )
    .await?;
    let hash = ContentHash::of_bytes(&b.projection().canonical_bytes(Limits::default())?);
    s.admit(
        &key("return"),
        &batch(
            vec![ResourceChange::ReplaceMutable {
                previous: hash,
                record: a,
            }],
            "{}",
        )?,
    )
    .await?;
    drop(s);
    let n = NativeStore::open(
        o.path,
        o.ledger,
        OpenMode::OpenExisting,
        NativeLimits::default(),
    )
    .await?;
    let records = n.read_records(&n.head().await?, None).await?;
    let origins = records
        .iter()
        .filter(|r| r.kind == "record")
        .map(|r| {
            cdb_core::record_codec::decode_record(r.payload.as_bytes(), Limits::default()).unwrap()
        })
        .filter_map(|r| {
            if let ExportRecord::Resource(r) = r {
                cdb_core::storage_origin::RecordOrigin::from_resource(&r, Limits::default())
                    .unwrap()
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(origins.len(), 3);
    assert_eq!(origins.iter().map(|o| o.sequence()).max(), Some(5));
    Ok(())
}
#[tokio::test]
async fn immutable_and_reserved_fail_without_partial() -> NativeResult<()> {
    let (_tmp, o, _) = setup()?;
    let s = Authority::create(o).await?;
    let r = resource("immutable", ResourceKind::SourceDescriptor, "x")?;
    let b = batch(vec![ResourceChange::Add(r)], "{}")?;
    s.admit(&key("a"), &b).await?;
    let p = s.head().await?;
    assert!(s.admit(&key("b"), &b).await.is_err());
    let reserved = resource(
        &format!("{}spoof", cdb_core::storage_origin::INTERNAL_PREFIX),
        ResourceKind::SourceDescriptor,
        "x",
    )?;
    assert!(s
        .admit(
            &key("spoof"),
            &batch(vec![ResourceChange::Add(reserved)], "{}")?
        )
        .await
        .is_err());
    assert_eq!(p, s.head().await?);
    Ok(())
}
#[tokio::test]
async fn lifecycle_staged_typed_references() -> NativeResult<()> {
    let (_tmp, o, _) = setup()?;
    let s = Authority::create(o).await?;
    let V::Object(mut v) = candidate("life").projection() else {
        unreachable!()
    };
    v.insert("subject_id".into(), V::string("target"));
    v.insert("object_id".into(), V::string("event"));
    v.insert("relation".into(), V::string("ctxql:retracted_by"));
    let l = LifecycleAssertion::from_value(&V::Object(v))?;
    let make = |kind| {
        AdmissionBatch::new(
            vec![candidate("target")],
            vec![l.clone()],
            vec![ResourceChange::Add(
                resource("event", kind, "event").unwrap(),
            )],
            vec![],
            V::Object(Default::default()),
            Limits::default(),
        )
    };
    let p = s.head().await?;
    assert!(s
        .admit(&key("bad"), &make(ResourceKind::Label)?)
        .await
        .is_err());
    assert_eq!(s.head().await?, p);
    s.admit(&key("ok"), &make(ResourceKind::LifecycleEvent)?)
        .await?;
    Ok(())
}
#[tokio::test]
async fn artifact_versions_exact_bytes_and_clock_overflow() -> NativeResult<()> {
    use cdb_core::artifact::{ArtifactRef, PublishedArtifact};
    let (_tmp, o, clock) = setup()?;
    let s = Authority::create(o.clone()).await?;
    let artifact = |version: &str, bytes: Vec<u8>| -> NativeResult<PublishedArtifact> {
        Ok(PublishedArtifact::new(
            ArtifactRef::new(
                Iri::new("urn:artifact")?,
                VersionId::new(version)?,
                ContentHash::of_bytes(&bytes),
            ),
            bytes,
            Limits::default(),
        )?)
    };
    let a = artifact("1", vec![0, 255, 128, 10])?;
    let make = |a| {
        AdmissionBatch::new(
            vec![],
            vec![],
            vec![],
            vec![a],
            V::Object(Default::default()),
            Limits::default(),
        )
    };
    s.admit(&key("a"), &make(a.clone())?).await?;
    assert!(s
        .admit(&key("conflict"), &make(artifact("1", vec![1])?)?)
        .await
        .is_err());
    s.admit(&key("v2"), &make(artifact("2", vec![1])?)?).await?;
    clock.0.store(
        Timestamp::parse("9999-12-31T23:59:59.999Z")?.millis(),
        Ordering::SeqCst,
    );
    s.capture(None).await?;
    let pin = s.head().await?;
    assert!(s
        .admit(&key("overflow"), &batch(vec![], "{}")?)
        .await
        .is_err());
    assert_eq!(s.head().await?, pin);
    drop(s);
    let n = NativeStore::open(
        o.path,
        o.ledger,
        OpenMode::OpenExisting,
        NativeLimits::default(),
    )
    .await?;
    let rows = n
        .read_records(
            &n.head().await?,
            Some(("record".into(), artifact_key(a.reference()))),
        )
        .await?;
    assert_eq!(
        cdb_core::record_codec::decode_record(rows[0].payload.as_bytes(), Limits::default())?,
        ExportRecord::Artifact(a)
    );
    Ok(())
}
#[tokio::test]
async fn bootstrap_only_never_adopted_and_bounds() -> NativeResult<()> {
    let (_tmp, o, _) = setup()?;
    let n = NativeStore::open(
        o.path.clone(),
        o.ledger.clone(),
        OpenMode::CreateNew,
        NativeLimits::default(),
    )
    .await?;
    drop(n);
    assert!(Authority::open(o).await.is_err());
    let (_tmp, mut o, _) = setup()?;
    o.max_history_commits = 2;
    let s = Authority::create(o).await?;
    let p = s.head().await?;
    assert!(s.capture(None).await.is_err());
    assert_eq!(p, s.head().await?);
    Ok(())
}

// Deliberately bypass owner admission only inside the private-kernel unit boundary.
async fn corrupt(case: &str) -> NativeResult<()> {
    use crate::journal::{control, value};
    let (_tmp, o, _clock) = setup()?;
    let b = FlureeBackend::create(o.clone()).await?;
    let p = b.native.head().await?;
    let old = b.keyed(&p, "control", "owner").await?.unwrap();
    let mut owner = value(&old)?;
    owner["t"] = serde_json::json!("3");
    owner["closed"] = serde_json::json!("1970-01-01T00:00:00.000Z");
    let mut j = serde_json::json!({"schema":"ctxql-authority/v1","t":"3","predecessor_t":"2","predecessor_cid":p.cid,"operation":"capture","time":"1970-01-01T00:00:00.000Z","key":"","payload":"","digest":"","claims":[],"changes":[]});
    match case {
        "predecessor" => j["predecessor_cid"] = serde_json::json!("wrong"),
        "clock" => owner["last"] = serde_json::json!("1970-01-01T00:00:00.000Z"),
        "closure" => owner["closed"] = serde_json::json!(""),
        "payload" => j["payload"] = serde_json::json!("tamper"),
        "operation" => j["operation"] = serde_json::json!("raw"),
        _ => {}
    }
    let mut insert = vec![
        control("control", "owner", owner)?,
        control("journal", "3", j)?,
    ];
    if case == "gap" {
        insert.pop();
    }
    if case == "extra" {
        insert.push(control(
            "control",
            "extra",
            serde_json::json!({"schema":"ctxql-authority/v1"}),
        )?);
    }
    if case == "mirror" {
        insert[0].hash = "wrong".into();
    }
    b.native.commit(&p, vec![old], insert).await?;
    assert!(b.head().await.is_err(), "{case}");
    assert!(b.capture(None).await.is_err(), "{case}");
    drop(b);
    assert!(FlureeBackend::open(o).await.is_err(), "{case}");
    Ok(())
}
#[tokio::test]
async fn journal_gap_fails() -> NativeResult<()> {
    corrupt("gap").await
}
#[tokio::test]
async fn predecessor_tamper_fails() -> NativeResult<()> {
    corrupt("predecessor").await
}
#[tokio::test]
async fn capture_last_tamper_fails() -> NativeResult<()> {
    corrupt("clock").await
}
#[tokio::test]
async fn capture_closed_tamper_fails() -> NativeResult<()> {
    corrupt("closure").await
}
#[tokio::test]
async fn control_payload_tamper_fails() -> NativeResult<()> {
    corrupt("payload").await
}
#[tokio::test]
async fn unmanaged_operation_fails() -> NativeResult<()> {
    corrupt("operation").await
}
#[tokio::test]
async fn extra_record_fails() -> NativeResult<()> {
    corrupt("extra").await
}
#[tokio::test]
async fn owner_hash_mirror_fails() -> NativeResult<()> {
    corrupt("mirror").await
}

#[tokio::test]
async fn artifact_repository_exact_retry_and_absent_legacy_run() -> NativeResult<()> {
    use cdb_core::{artifact::*, contracts::ArtifactRepository};
    let (_tmp, o, _) = setup()?;
    let b = FlureeBackend::create(o).await?;
    let bytes = vec![0, 255, 10];
    let a = PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new("urn:artifact")?,
            VersionId::new("1")?,
            ContentHash::of_bytes(&bytes),
        ),
        bytes,
        Limits::default(),
    )?;
    assert_eq!(ArtifactRepository::publish(&b, &a).await?, *a.reference());
    let pin = b.head().await?;
    ArtifactRepository::publish(&b, &a).await?;
    assert_eq!(b.head().await?, pin);
    assert_eq!(
        ArtifactRepository::lookup(&b, a.reference()).await?,
        Some(a)
    );
    assert_eq!(
        ArtifactRepository::run(&b, &RunId::new("run")?).await?,
        None
    );
    Ok(())
}
