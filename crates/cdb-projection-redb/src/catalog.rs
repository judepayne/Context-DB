//! Exact-pin temporal catalog from immutable managed record-image provenance.
use cdb_core::{
    admission::{ExportRecord, FactTerm},
    id::{EntityId, ResourceId},
    snapshot::{Page, PageCursor, PageSize, PageTracker, SnapshotRef},
    storage_origin::RecordOrigin,
    CanonicalValue, Error, Result, Timestamp,
};
use cdb_engine::execution::{property_iri, ExecutionOptions, LandingCatalog, LandingEntry};
use std::collections::BTreeMap;

pub struct Catalog {
    snapshot: SnapshotRef,
    entries: Vec<LandingEntry>,
}
impl LandingCatalog for Catalog {
    fn identity(&self) -> &SnapshotRef {
        &self.snapshot
    }
    fn entries(&self) -> &[LandingEntry] {
        &self.entries
    }
}
/// Two bounded scans of the SAME immutable transaction: select the latest origin
/// by sequence first, then validate the current image before applying the cutoff.
/// In particular A -> B -> A cannot select the first matching A hash.
pub fn prepare_catalog(
    snapshot: &SnapshotRef,
    as_of: Timestamp,
    options: &ExecutionOptions,
    mut scan: impl FnMut(PageSize, Option<&PageCursor>) -> Result<Page<ExportRecord>>,
) -> Result<Catalog> {
    let mut origins = BTreeMap::<String, RecordOrigin>::new();
    let mut work = 0usize;
    let mut bytes = 0usize;
    let mut entries = vec![];
    let entity = property_iri("entity")?;
    let label = property_iri("label")?;
    for pass in 0..2 {
        let mut cursor = None;
        let mut tracker = None;
        loop {
            options.check_interrupted()?;
            work = work.checked_add(1).ok_or_else(Error::limit)?;
            if work > options.max_work {
                return Err(Error::limit());
            }
            let page = scan(options.page_size, cursor.as_ref())?;
            if page.items().len() > options.page_size.get() {
                return Err(Error::limit());
            }
            let current_tracker = tracker.get_or_insert_with(|| {
                PageTracker::new(
                    snapshot.clone(),
                    page.next()
                        .map(|c| c.stream().clone())
                        .unwrap_or_else(|| ResourceId::new("catalog-terminal").expect("constant")),
                    options.max_records,
                )
            });
            current_tracker.accept(cursor.as_ref(), &page)?;
            for record in page.items() {
                options.check_interrupted()?;
                work = work.checked_add(1).ok_or_else(Error::limit)?;
                bytes = bytes
                    .checked_add(
                        cdb_core::record_codec::encode_record(record, options.limits)?.len(),
                    )
                    .ok_or_else(Error::limit)?;
                if work > options.max_work || bytes > options.max_retained_bytes {
                    return Err(Error::limit());
                }
                let ExportRecord::Resource(resource) = record else {
                    continue;
                };
                if pass == 0 {
                    if let Some(origin) = RecordOrigin::from_resource(resource, options.limits)? {
                        match origins.get(origin.key()) {
                            Some(old) if old.sequence() == origin.sequence() => {
                                return Err(Error::invalid("duplicate origin sequence"));
                            }
                            Some(old) if old.sequence() > origin.sequence() => (),
                            _ => {
                                origins.insert(origin.key().to_owned(), origin);
                            }
                        }
                    }
                    continue;
                }
                let entity_facts: Vec<_> = resource
                    .facts()
                    .iter()
                    .filter(|f| f.predicate() == &entity)
                    .collect();
                if entity_facts.is_empty() {
                    continue;
                }
                if entity_facts.len() != 1
                    || !matches!(entity_facts[0].term(), FactTerm::Literal(l) if l.value() == &CanonicalValue::Bool(true))
                {
                    return Err(Error::invalid("entity marker"));
                }
                let origin = origins
                    .get(&record.identity_key())
                    .ok_or_else(|| Error::invalid("missing entity image origin"))?;
                if origin.removed() || !origin.matches(record, options.limits)? {
                    return Err(Error::invalid("entity image provenance mismatch"));
                }
                if origin.time() > as_of {
                    continue;
                }
                let id = EntityId::new(resource.id().as_str())?;
                let dependencies = vec![resource.id().clone(), origin.id()?];
                entries.push(LandingEntry {
                    id: id.clone(),
                    label: None,
                    dependencies: dependencies.clone(),
                });
                for fact in resource.facts().iter().filter(|f| f.predicate() == &label) {
                    let FactTerm::Literal(l) = fact.term() else {
                        return Err(Error::invalid("label literal"));
                    };
                    entries.push(LandingEntry {
                        id: id.clone(),
                        label: Some(l.value().as_str()?.into()),
                        dependencies: dependencies.clone(),
                    });
                    if entries.len() > options.max_records {
                        return Err(Error::limit());
                    }
                }
                if entries.len() > options.max_records {
                    return Err(Error::limit());
                }
            }
            cursor = page.next().cloned();
            if cursor.is_none() {
                tracker.take().expect("initialized tracker").finish()?;
                break;
            }
        }
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id).then(a.label.cmp(&b.label)));
    Ok(Catalog {
        snapshot: snapshot.clone(),
        entries,
    })
}
