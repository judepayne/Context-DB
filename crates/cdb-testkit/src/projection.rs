//! Bounded disposable projection. Limits count retained generations (no eviction).
use cdb_core::{
    admission::*, claim::*, contracts::*, id::*, snapshot::*, Error, ErrorKind, Limits, Result,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

#[derive(Clone, Copy, Debug)]
pub struct ProjectionOptions {
    pub max_records: usize,
    pub max_bytes: usize,
    pub max_history: usize,
}
impl Default for ProjectionOptions {
    fn default() -> Self {
        Self {
            max_records: 1000,
            max_bytes: 8 * 1024 * 1024,
            max_history: 100,
        }
    }
}
#[derive(Default)]
struct State {
    checkpoint: Option<ProjectionCheckpoint>,
    views: BTreeMap<SnapshotRef, Arc<View>>,
    batches: BTreeMap<SnapshotRef, (ChangeBatch, ProjectionCheckpoint)>,
    checkpoints: BTreeMap<SnapshotRef, ProjectionCheckpoint>,
}
pub struct MemoryProjection {
    origin: SnapshotRef,
    algorithm: Iri,
    options: ProjectionOptions,
    state: Mutex<State>,
    read_fault: Arc<AtomicBool>,
    write_fault: AtomicBool,
}
fn fail(message: &str) -> Error {
    Error::new(ErrorKind::Conflict, message)
}
impl MemoryProjection {
    pub fn new(origin: SnapshotRef, algorithm: Iri, options: ProjectionOptions) -> Result<Self> {
        if options.max_records == 0 || options.max_bytes == 0 || options.max_history == 0 {
            return Err(Error::limit());
        }
        Ok(Self {
            origin,
            algorithm,
            options,
            state: Mutex::new(State::default()),
            read_fault: Arc::new(AtomicBool::new(false)),
            write_fault: AtomicBool::new(false),
        })
    }
    pub fn set_read_fault(&self, enabled: bool) {
        self.read_fault.store(enabled, Ordering::SeqCst);
    }
    pub fn set_write_fault(&self, enabled: bool) {
        self.write_fault.store(enabled, Ordering::SeqCst);
    }
    fn check(&self, cp: &ProjectionCheckpoint, pin: &SnapshotRef) -> Result<()> {
        if cp.snapshot() != pin
            || !self.origin.same_authority(pin)
            || cp.algorithm() != &self.algorithm
            || cp.schema().as_str() != "ctxql-projection/v1"
        {
            return Err(fail("projection identity"));
        }
        Ok(())
    }
    fn stage(&self, pin: &SnapshotRef, records: BTreeMap<String, ExportRecord>) -> Result<View> {
        if records.len() > self.options.max_records {
            return Err(Error::limit());
        }
        let mut bytes = 0usize;
        for r in records.values() {
            let change = match r {
                ExportRecord::Claim(c) => RecordChange::ClaimAdded(c.clone()),
                ExportRecord::Lifecycle {
                    assertion,
                    transaction_time,
                } => RecordChange::LifecycleAdded {
                    assertion: assertion.clone(),
                    transaction_time: *transaction_time,
                },
                ExportRecord::Resource(r) => RecordChange::Resource(ResourceChange::Add(r.clone())),
                ExportRecord::Artifact(a) => RecordChange::ArtifactAdded(a.clone()),
            };
            bytes = bytes
                .checked_add(
                    change
                        .projection()
                        .canonical_bytes(Limits::default())?
                        .len(),
                )
                .ok_or_else(Error::limit)?;
            if let ExportRecord::Claim(c) = r {
                if c.candidate().is_lifecycle_assertion() {
                    return Err(fail("lifecycle claim requires validated wrapper"));
                }
            }
            if let ExportRecord::Artifact(a) = r {
                bytes = bytes
                    .checked_add(a.content().len())
                    .ok_or_else(Error::limit)?;
            }
            if bytes > self.options.max_bytes {
                return Err(Error::limit());
            }
            if let ExportRecord::Lifecycle { assertion, .. } = r {
                for id in std::iter::once(assertion.target()).chain(assertion.referenced_claim()) {
                    if !matches!(
                        records.get(&resource_key(id.as_str())),
                        Some(ExportRecord::Claim(_) | ExportRecord::Lifecycle { .. })
                    ) {
                        return Err(fail("unknown lifecycle claim"));
                    }
                }
                if let Some(event) = assertion.event() {
                    if !matches!(records.get(&resource_key(event.as_str())),
                        Some(ExportRecord::Resource(r)) if r.kind() == ResourceKind::LifecycleEvent)
                    {
                        return Err(fail("unknown lifecycle event"));
                    }
                }
            }
        }
        Ok(View {
            pin: pin.clone(),
            records,
            fault: self.read_fault.clone(),
        })
    }
    fn writable(&self) -> Result<()> {
        if self.write_fault.load(Ordering::SeqCst) {
            Err(fail("injected projection write fault"))
        } else {
            Ok(())
        }
    }
}
fn insert(records: &mut BTreeMap<String, ExportRecord>, r: ExportRecord) -> Result<()> {
    let id = r.identity_key();
    if records.contains_key(&id) {
        return Err(fail("duplicate record identity"));
    }
    records.insert(id, r);
    Ok(())
}
impl ProjectionStore for MemoryProjection {
    fn checkpoint(&self) -> IoFuture<'_, Option<ProjectionCheckpoint>> {
        Box::pin(async {
            if self.read_fault.load(Ordering::SeqCst) {
                return Err(fail("injected read fault"));
            }
            Ok(self
                .state
                .lock()
                .map_err(|_| fail("poisoned projection"))?
                .checkpoint
                .clone())
        })
    }
    fn build<'a>(
        &'a self,
        export: &'a CompleteExport,
        cp: &'a ProjectionCheckpoint,
    ) -> IoFuture<'a, ()> {
        Box::pin(async move {
            self.check(cp, export.snapshot())?;
            let mut records = BTreeMap::new();
            for r in export.records() {
                insert(&mut records, r.clone())?;
            }
            let view = self.stage(export.snapshot(), records)?;
            let mut s = self.state.lock().map_err(|_| fail("poisoned projection"))?;
            if let Some(old) = s.views.get(export.snapshot()) {
                if old.records != view.records || s.checkpoints.get(export.snapshot()) != Some(cp) {
                    return Err(fail("inconsistent rebuild"));
                }
                return Ok(());
            }
            if s.checkpoints
                .values()
                .any(|old| old.generation() == cp.generation())
            {
                return Err(fail("generation already bound"));
            }
            if s.views.len() >= self.options.max_history {
                return Err(Error::limit());
            }
            self.writable()?;
            s.views.insert(export.snapshot().clone(), Arc::new(view));
            s.checkpoints.insert(export.snapshot().clone(), cp.clone());
            // Only initial construction establishes the live cursor. Later builds cache
            // exact historical generations; arbitrary opaque revisions cannot be ordered.
            if s.checkpoint.is_none() {
                s.checkpoint = Some(cp.clone());
            }
            Ok(())
        })
    }
    fn apply<'a>(
        &'a self,
        batch: &'a ChangeBatch,
        cp: &'a ProjectionCheckpoint,
    ) -> IoFuture<'a, ()> {
        Box::pin(async move {
            self.check(cp, batch.result())?;
            let mut s = self.state.lock().map_err(|_| fail("poisoned projection"))?;
            if let Some((old, checkpoint)) = s.batches.get(batch.result()) {
                return if old == batch && checkpoint == cp {
                    Ok(())
                } else {
                    Err(fail("changed duplicate"))
                };
            }
            let previous = s
                .checkpoint
                .as_ref()
                .ok_or_else(|| fail("build required"))?;
            if previous.snapshot() != batch.predecessor()
                || previous.generation() != cp.generation()
            {
                return Err(fail("projection predecessor/generation"));
            }
            if !s.views.contains_key(batch.result()) && s.views.len() >= self.options.max_history {
                return Err(Error::limit());
            }
            let mut records = s
                .views
                .get(batch.predecessor())
                .ok_or_else(|| fail("missing predecessor"))?
                .records
                .clone();
            let mut touched = BTreeSet::new();
            for c in batch.changes() {
                let key = match c {
                    RecordChange::ClaimAdded(c) => resource_key(c.id().as_str()),
                    RecordChange::LifecycleAdded { assertion, .. } => {
                        resource_key(assertion.id().as_str())
                    }
                    RecordChange::ArtifactAdded(a) => artifact_key(a.reference()),
                    RecordChange::Resource(
                        ResourceChange::Add(r) | ResourceChange::ReplaceMutable { record: r, .. },
                    ) => resource_key(r.id().as_str()),
                    RecordChange::Resource(ResourceChange::RetractMutable { id, .. }) => {
                        resource_key(id.as_str())
                    }
                };
                if !touched.insert(key) {
                    return Err(fail("duplicate change"));
                }
            }
            for c in batch.changes() {
                let record = match c {
                    RecordChange::ClaimAdded(c) => ExportRecord::Claim(c.clone()),
                    RecordChange::LifecycleAdded {
                        assertion,
                        transaction_time,
                    } => ExportRecord::Lifecycle {
                        assertion: assertion.clone(),
                        transaction_time: *transaction_time,
                    },
                    RecordChange::ArtifactAdded(a) => ExportRecord::Artifact(a.clone()),
                    RecordChange::Resource(change) => {
                        change.validate()?;
                        match change {
                            ResourceChange::Add(r) => ExportRecord::Resource(r.clone()),
                            ResourceChange::ReplaceMutable { previous, record } => {
                                check_previous(&records, record.id(), record.kind(), previous)?;
                                records.remove(&resource_key(record.id().as_str()));
                                ExportRecord::Resource(record.clone())
                            }
                            ResourceChange::RetractMutable { id, kind, previous } => {
                                check_previous(&records, id, *kind, previous)?;
                                records.remove(&resource_key(id.as_str()));
                                continue;
                            }
                        }
                    }
                };
                insert(&mut records, record)?;
            }
            let view = self.stage(batch.result(), records)?;
            if let Some(cached) = s.views.get(batch.result()) {
                if cached.records != view.records {
                    return Err(fail("cached result differs from authoritative changes"));
                }
            }
            self.writable()?;
            s.views.insert(batch.result().clone(), Arc::new(view));
            s.checkpoints.insert(batch.result().clone(), cp.clone());
            s.batches
                .insert(batch.result().clone(), (batch.clone(), cp.clone()));
            s.checkpoint = Some(cp.clone());
            Ok(())
        })
    }
    fn open_view<'a>(&'a self, pin: &'a SnapshotRef) -> IoFuture<'a, Arc<dyn RawQueryView>> {
        Box::pin(async move {
            if self.read_fault.load(Ordering::SeqCst) {
                return Err(fail("injected read fault"));
            }
            let s = self.state.lock().map_err(|_| fail("poisoned projection"))?;
            let view = s
                .views
                .get(pin)
                .ok_or_else(|| Error::new(ErrorKind::Snapshot, "unknown exact projection"))?
                .clone();
            Ok(view as Arc<dyn RawQueryView>)
        })
    }
}
fn check_previous(
    records: &BTreeMap<String, ExportRecord>,
    id: &ResourceId,
    kind: ResourceKind,
    hash: &ContentHash,
) -> Result<()> {
    match records.get(&resource_key(id.as_str())) {
        Some(ExportRecord::Resource(r))
            if r.kind() == kind
                && &ContentHash::of_bytes(&r.projection().canonical_bytes(Limits::default())?)
                    == hash =>
        {
            Ok(())
        }
        _ => Err(fail("resource previous mismatch")),
    }
}
struct View {
    pin: SnapshotRef,
    records: BTreeMap<String, ExportRecord>,
    fault: Arc<AtomicBool>,
}
impl View {
    fn readable(&self) -> Result<()> {
        if self.fault.load(Ordering::SeqCst) {
            Err(fail("injected projection read fault"))
        } else {
            Ok(())
        }
    }
    fn page<T: Clone>(
        &self,
        items: Vec<T>,
        stream: String,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<T>> {
        self.readable()?;
        let stream = ResourceId::new(stream)?;
        let start = match cursor {
            None => 0,
            Some(c) => {
                if c.snapshot() != &self.pin || c.stream() != &stream {
                    return Err(fail("cursor binding"));
                }
                let n = c
                    .position()
                    .as_str()
                    .parse::<usize>()
                    .map_err(|_| fail("cursor position"))?;
                if n == 0 || n >= items.len() || n.to_string() != c.position().as_str() {
                    return Err(fail("cursor range"));
                }
                n
            }
        };
        let end = start.saturating_add(size.get()).min(items.len());
        let next = if end < items.len() {
            Some(PageCursor::new(
                self.pin.clone(),
                stream,
                VersionId::new(end.to_string())?,
            ))
        } else {
            None
        };
        Page::new(items[start..end].to_vec(), self.pin.clone(), next, size)
    }
}
impl RawQueryView for View {
    fn identity(&self) -> &SnapshotRef {
        &self.pin
    }
    fn claim(&self, id: &ClaimId) -> Result<Option<AdmittedClaim>> {
        self.readable()?;
        Ok(self
            .records
            .get(&resource_key(id.as_str()))
            .and_then(ExportRecord::claim))
    }
    fn entity(&self, id: &EntityId) -> Result<Option<Vec<DependencyRecord>>> {
        self.readable()?;
        Ok(self
            .resource(&ResourceId::new(id.as_str())?)?
            .map(|r| vec![r]))
    }
    fn resource(&self, id: &ResourceId) -> Result<Option<DependencyRecord>> {
        self.readable()?;
        Ok(match self.records.get(&resource_key(id.as_str())) {
            Some(ExportRecord::Resource(r)) => Some(r.clone()),
            _ => None,
        })
    }
    fn incident(
        &self,
        id: &EntityId,
        direction: Direction,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<AdmittedClaim>> {
        self.readable()?;
        let items = self
            .records
            .values()
            .filter_map(|r| {
                let c = r.claim()?;
                let out = c.candidate().subject() == id;
                let incoming = matches!(c.candidate().object(), ClaimObject::Entity(e) if e == id);
                if match direction {
                    Direction::Outgoing => out,
                    Direction::Incoming => incoming,
                    Direction::Both => out || incoming,
                } {
                    Some(c)
                } else {
                    None
                }
            })
            .collect();
        self.page(
            items,
            format!(
                "incident:{direction:?}:{}",
                ContentHash::of_bytes(id.as_str().as_bytes()).as_str()
            ),
            size,
            cursor,
        )
    }
    fn lifecycle(
        &self,
        id: &ClaimId,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<ExportRecord>> {
        self.readable()?;
        let items = self.records.values().filter(|r| matches!(r, ExportRecord::Lifecycle { assertion, .. } if assertion.target() == id)).cloned().collect();
        self.page(
            items,
            format!(
                "lifecycle:{}",
                ContentHash::of_bytes(id.as_str().as_bytes()).as_str()
            ),
            size,
            cursor,
        )
    }
}
