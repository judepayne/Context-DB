//! Reusable adapter assertions for small deterministic P1/P3 fixtures.
//! These helpers deliberately panic on contract violations like ordinary tests.
use cdb_core::claim::ClaimObject;
use cdb_core::{admission::*, contracts::*, id::*, snapshot::*, Error, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

fn unique_records(records: &[ExportRecord]) -> BTreeMap<String, ExportRecord> {
    let mut result = BTreeMap::new();
    for record in records {
        assert!(
            result
                .insert(record.identity_key(), record.clone())
                .is_none(),
            "duplicate export identity"
        );
    }
    result
}

// Discover adapter-specific stream spelling, then validate every page and completion.
fn track<T>(
    tracker: &mut Option<PageTracker>,
    pin: &SnapshotRef,
    cursor: Option<&PageCursor>,
    page: &Page<T>,
    max: usize,
) -> Result<()> {
    if tracker.is_none() {
        let stream = page
            .next()
            .map(|c| c.stream().clone())
            .unwrap_or(ResourceId::new("terminal")?);
        *tracker = Some(PageTracker::new(pin.clone(), stream, max));
    }
    tracker.as_mut().unwrap().accept(cursor, page)
}

fn collect_view<T>(
    pin: &SnapshotRef,
    max: usize,
    mut fetch: impl FnMut(Option<&PageCursor>) -> Result<Page<T>>,
) -> Result<Vec<T>> {
    let mut tracker = None;
    let mut cursor = None;
    let mut items = Vec::new();
    loop {
        let page = fetch(cursor.as_ref())?;
        track(&mut tracker, pin, cursor.as_ref(), &page, max)?;
        cursor = page.next().cloned();
        items.extend(page.into_items());
        if cursor.is_none() {
            break;
        }
    }
    tracker.unwrap().finish()?;
    Ok(items)
}

/// Collect with cumulative limits and explicit completion; no fixed adapter cursor spelling.
pub async fn complete_export(
    snapshot: &dyn BackendSnapshot,
    max_records: usize,
) -> Result<CompleteExport> {
    let size = PageSize::new(1)?;
    let mut pages = Vec::new();
    let mut cursor = None;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..=max_records {
        let page = snapshot.export(cursor.as_ref(), size).await?;
        let done = page.complete();
        cursor = page.next().cloned();
        if let Some(c) = &cursor {
            if !seen.insert(c.position().clone()) {
                return Err(Error::invalid("nonprogressing export"));
            }
        }
        pages.push(page);
        if done {
            let stream = pages
                .iter()
                .find_map(|p| p.next().map(|c| c.stream().clone()))
                .unwrap_or(ResourceId::new("terminal")?);
            let export =
                CompleteExport::collect(snapshot.identity().clone(), stream, pages, max_records)?;
            unique_records(export.records());
            return Ok(export);
        }
    }
    Err(Error::limit())
}

/// End-to-end backend → complete export → incremental projection contract.
/// The caller owns backend initialization, clock/fault controls and valid fixture batches.
pub async fn assert_backend_projection<B: GraphBackend, P: ProjectionStore>(
    backend: &B,
    projection: &P,
    batches: &[(IdempotencyKey, AdmissionBatch)],
    generation: VersionId,
    algorithm: Iri,
    max_records: usize,
) -> Result<()> {
    let mut head = backend.head().await?;
    let origin = backend.open_snapshot(&head).await?;
    let export = complete_export(origin.as_ref(), max_records).await?;
    let checkpoint = |pin| {
        ProjectionCheckpoint::new(
            pin,
            VersionId::new("ctxql-projection/v1")?,
            generation.clone(),
            algorithm.clone(),
        )
    };
    projection
        .build(&export, &checkpoint(head.clone())?)
        .await?;
    let mut held: Vec<(Arc<dyn RawQueryView>, CompleteExport)> =
        vec![(projection.open_view(&head).await?, export)];
    for (key, batch) in batches {
        let receipt = backend.admit(key, batch).await?;
        assert_eq!(backend.admit(key, batch).await?, receipt);
        assert_eq!(backend.receipt(key).await?, Some(receipt.clone()));
        let through = receipt.snapshot();
        let mut cursor = None;
        let mut tracker = None;
        let mut predecessor = head.clone();
        let mut revisions = BTreeSet::from([head.clone()]);
        loop {
            let page = backend
                .changes(&head, through, cursor.as_ref(), PageSize::new(1)?)
                .await?;
            track(&mut tracker, through, cursor.as_ref(), &page, max_records)?;
            for change in page.items() {
                assert_eq!(change.predecessor(), &predecessor);
                assert!(
                    revisions.insert(change.result().clone()),
                    "repeated change revision"
                );
                predecessor = change.result().clone();
                let cp = checkpoint(change.result().clone())?;
                projection.apply(change, &cp).await?;
                projection.apply(change, &cp).await?;
            }
            cursor = page.next().cloned();
            if page.complete() {
                break;
            }
        }
        assert!(tracker.unwrap().finish()? > 0);
        assert_eq!(&predecessor, through);
        assert_eq!(projection.checkpoint().await?.unwrap().snapshot(), through);
        head = through.clone();
        let snapshot = backend.open_snapshot(&head).await?;
        held.push((
            projection.open_view(&head).await?,
            complete_export(snapshot.as_ref(), max_records).await?,
        ));
    }
    // RawQueryView has no global scan: compare the union of fixture-known IDs,
    // including future-only IDs against every older held view.
    let mut ids = BTreeSet::new();
    for (_, export) in &held {
        for record in export.records() {
            if let Some(c) = record.claim() {
                ids.insert(c.id().as_str().to_owned());
                ids.insert(c.candidate().subject().as_str().to_owned());
                if let ClaimObject::Entity(e) = c.candidate().object() {
                    ids.insert(e.as_str().to_owned());
                }
            }
            if let ExportRecord::Resource(r) = record {
                ids.insert(r.id().as_str().to_owned());
            }
        }
    }
    for (view, export) in held {
        assert_eq!(view.identity(), export.snapshot());
        let snapshot = backend.open_snapshot(export.snapshot()).await?;
        let records = unique_records(export.records());
        for id in &ids {
            let expected = records.get(&resource_key(id));
            assert_eq!(
                view.claim(&ClaimId::new(id)?)?,
                expected.and_then(ExportRecord::claim)
            );
            let resource = expected.and_then(|r| match r {
                ExportRecord::Resource(r) => Some(r.clone()),
                _ => None,
            });
            assert_eq!(view.resource(&ResourceId::new(id)?)?, resource);
            let entity = EntityId::new(id)?;
            for direction in [Direction::Outgoing, Direction::Incoming, Direction::Both] {
                let expected: BTreeMap<_, _> = export.records().iter().filter_map(ExportRecord::claim).filter(|c| {
                    let outgoing = c.candidate().subject() == &entity;
                    let incoming = matches!(c.candidate().object(), ClaimObject::Entity(e) if e == &entity);
                    match direction { Direction::Outgoing => outgoing, Direction::Incoming => incoming, Direction::Both => outgoing || incoming }
                }).map(|c| (c.id().clone(), c)).collect();
                let actual = collect_view(view.identity(), max_records, |cursor| {
                    view.incident(&entity, direction, PageSize::new(1)?, cursor)
                })?;
                let mut indexed = BTreeMap::new();
                for c in actual {
                    assert!(
                        indexed.insert(c.id().clone(), c).is_none(),
                        "duplicate incident identity"
                    );
                }
                assert_eq!(indexed, expected);
            }
            let target = ClaimId::new(id)?;
            let expected: Vec<_> = export.records().iter().filter(|r| matches!(r, ExportRecord::Lifecycle { assertion, .. } if assertion.target() == &target)).cloned().collect();
            let actual = collect_view(view.identity(), max_records, |cursor| {
                view.lifecycle(&target, PageSize::new(1)?, cursor)
            })?;
            assert_eq!(unique_records(&actual), unique_records(&expected));
        }
        for r in export.records() {
            match r {
                ExportRecord::Claim(c) => assert_eq!(view.claim(c.id())?, Some(*c.clone())),
                ExportRecord::Resource(r) => assert_eq!(view.resource(r.id())?, Some(r.clone())),
                ExportRecord::Lifecycle { assertion, .. } => {
                    assert_eq!(view.claim(assertion.id())?, r.claim());
                }
                ExportRecord::Artifact(a) => {
                    assert_eq!(snapshot.artifact(a.reference()).await?, Some(a.clone()))
                }
            }
        }
    }
    Ok(())
}
