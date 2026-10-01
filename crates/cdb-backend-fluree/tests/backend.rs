use cdb_backend_fluree::*;
use cdb_core::{admission::*, contracts::*, id::*, snapshot::*, CanonicalValue, Limits};
fn options(p: &std::path::Path) -> AuthorityOptions {
    AuthorityOptions::new(
        p.join("db"),
        "backend:main".into(),
        BackendId::new("fluree").unwrap(),
        AuthorityId::new("owner").unwrap(),
        GraphId::new("g").unwrap(),
    )
}
fn batch() -> AdmissionBatch {
    AdmissionBatch::new(
        vec![],
        vec![],
        vec![ResourceChange::Add(
            DependencyRecord::new(
                "ctxql-resource/v1",
                ResourceId::new("r").unwrap(),
                ResourceKind::Identity,
                vec![Fact::new(
                    Iri::new("urn:type").unwrap(),
                    FactTerm::Reference(ResourceId::new("urn:entity").unwrap()),
                )],
            )
            .unwrap(),
        )],
        vec![],
        CanonicalValue::parse(b"{}", Limits::default()).unwrap(),
        Limits::default(),
    )
    .unwrap()
}
#[tokio::test]
async fn pinned_export_changes_and_capture() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let t = tempfile::tempdir()?;
    let b = FlureeBackend::create(options(t.path())).await?;
    let first = GraphBackend::head(&b).await?;
    let old = GraphBackend::open_snapshot(&b, &first).await?;
    let r = GraphBackend::admit(&b, &IdempotencyKey::new("one")?, &batch()).await?;
    let end = GraphBackend::capture(&b, None).await?.snapshot;
    assert!(old.resource(&ResourceId::new("r")?).await?.is_none());
    let now = GraphBackend::open_snapshot(&b, &end).await?;
    assert!(now.resource(&ResourceId::new("r")?).await?.is_some());
    let mut tracker = PageTracker::new(end.clone(), export_stream(), 10);
    let mut cursor = None;
    let mut records = vec![];
    loop {
        let p = now.export(cursor.as_ref(), PageSize::new(1)?).await?;
        tracker.accept(cursor.as_ref(), &p)?;
        cursor = p.next().cloned();
        records.extend(p.into_items());
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(tracker.finish()?, 2);
    assert_eq!(records.len(), 2);
    let p = GraphBackend::changes(&b, &first, &end, None, PageSize::new(1)?).await?;
    assert_eq!(p.items()[0].result(), r.snapshot());
    assert_eq!(p.items()[0].changes().len(), 2);
    let q = GraphBackend::changes(&b, &first, &end, p.next(), PageSize::new(1)?).await?;
    assert!(q.complete());
    assert!(q.items()[0].changes().is_empty());
    drop(b);
    assert!(now.resource(&ResourceId::new("r")?).await?.is_some());
    Ok(())
}
#[tokio::test]
async fn empty_range_validates_full_endpoint(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let t = tempfile::tempdir()?;
    let b = FlureeBackend::create(options(t.path())).await?;
    let s = b.head().await?;
    assert!(GraphBackend::changes(&b, &s, &s, None, PageSize::new(1)?)
        .await?
        .complete());
    let bad = SnapshotRef::new(
        s.backend().clone(),
        GraphPin::new(
            s.pin().authority().clone(),
            s.pin().graph().clone(),
            s.pin().revision().clone(),
            ResourceId::new("bad-cid")?,
        ),
    );
    assert_eq!(
        GraphBackend::changes(&b, &bad, &bad, None, PageSize::new(1)?)
            .await
            .unwrap_err()
            .kind,
        cdb_core::ErrorKind::Snapshot
    );
    for revision in ["not-a-number", "999999"] {
        let invalid = SnapshotRef::new(
            s.backend().clone(),
            GraphPin::new(
                s.pin().authority().clone(),
                s.pin().graph().clone(),
                VersionId::new(revision)?,
                s.pin().receipt().clone(),
            ),
        );
        assert_eq!(
            GraphBackend::changes(&b, &invalid, &invalid, None, PageSize::new(1)?)
                .await
                .unwrap_err()
                .kind,
            cdb_core::ErrorKind::Snapshot
        );
    }
    Ok(())
}
#[tokio::test]
async fn real_bus_head_is_exact() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let t = tempfile::tempdir()?;
    let b = FlureeBackend::create(options(t.path())).await?;
    let mut hints = GraphBackend::subscribe(&b).await?;
    let end = b.capture(None).await?.snapshot;
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), hints.next()).await??,
        ChangeHint::Head(end)
    );
    Ok(())
}
