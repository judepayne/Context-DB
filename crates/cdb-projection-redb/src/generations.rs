//! Durable generation ownership; reuses the D1 hmem-derived transaction kernel.
use crate::{Database, DatabaseOptions, DatabaseView};
use cdb_core::{
    admission::*, claim::*, contracts::*, id::*, record_codec::*, snapshot::*, CanonicalValue,
    Error, ErrorKind, Result,
};
use fs2::FileExt;
use redb::{ReadableTable, TableDefinition};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
const OWNED: TableDefinition<u64, u8> = TableDefinition::new("owned-slots-v1");
const ENTRIES: TableDefinition<u64, u8> = TableDefinition::new("generations-v1");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("catalog-v1");
fn err(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Backend, format!("generations: {e}"))
}
fn conflict(s: &str) -> Error {
    Error::new(ErrorKind::Conflict, s)
}
#[derive(Clone, Copy, Debug)]
pub struct GenerationOptions {
    pub database: DatabaseOptions,
    pub max_generations: usize,
}
impl Default for GenerationOptions {
    fn default() -> Self {
        Self {
            database: DatabaseOptions::default(),
            max_generations: 8,
        }
    }
}
struct Generation {
    db: Database,
}
struct State {
    catalog: redb::Database,
    active: Option<u64>,
    generations: BTreeMap<u64, Arc<Generation>>,
}
struct Inner {
    state: Mutex<State>,
    dir: PathBuf,
    binding: ProjectionCheckpoint,
    options: GenerationOptions,
    fault: AtomicBool,
    apply_fault: AtomicBool,
    _lock: File,
}
#[derive(Clone)]
pub struct RedbProjection {
    inner: Arc<Inner>,
}
/// The owned transaction and generation/owner leases keep old databases and directory lock alive.
pub struct GenerationView {
    view: DatabaseView,
    _generation: Arc<Generation>,
    _owner: Arc<Inner>,
}
fn safe_file(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)
        .map_err(err)?
        .file_type()
        .is_file()
    {
        Ok(())
    } else {
        Err(conflict("not a regular managed file"))
    }
}
fn binding(a: &ProjectionCheckpoint, b: &ProjectionCheckpoint) -> Result<()> {
    if a.snapshot().same_authority(b.snapshot())
        && a.schema() == b.schema()
        && a.algorithm() == b.algorithm()
    {
        Ok(())
    } else {
        Err(conflict("foreign projection binding"))
    }
}
impl RedbProjection {
    /// Directory must not exist. Binding specifies authority/schema/algorithm, not a stale live pin.
    pub async fn create(
        path: impl AsRef<Path>,
        binding: ProjectionCheckpoint,
        options: GenerationOptions,
    ) -> Result<Self> {
        let path = path.as_ref().to_owned();
        tokio::task::spawn_blocking(move || Self::init(path, binding, options, true, true))
            .await
            .map_err(err)?
    }
    pub async fn open(
        path: impl AsRef<Path>,
        binding: ProjectionCheckpoint,
        options: GenerationOptions,
    ) -> Result<Self> {
        let path = path.as_ref().to_owned();
        tokio::task::spawn_blocking(move || Self::init(path, binding, options, false, true))
            .await
            .map_err(err)?
    }
    /// Open the active completed generation from an existing store as one
    /// independently owned native read snapshot.
    pub async fn open_latest_existing(
        path: impl AsRef<Path>,
        binding: ProjectionCheckpoint,
        options: GenerationOptions,
    ) -> Result<Arc<GenerationView>> {
        let path = path.as_ref().to_owned();
        tokio::task::spawn_blocking(move || {
            let projection = Self::init(path, binding, options, false, false)?;
            Self::open_latest(projection.inner)
        })
        .await
        .map_err(err)?
    }
    /// Open the completed semantic generation with the greatest Fluree
    /// transaction revision. This does not change which generation is active.
    pub async fn open_latest_semantic_existing(
        path: impl AsRef<Path>,
        binding: ProjectionCheckpoint,
        options: GenerationOptions,
    ) -> Result<Arc<GenerationView>> {
        let path = path.as_ref().to_owned();
        tokio::task::spawn_blocking(move || {
            let projection = Self::init(path, binding, options, false, false)?;
            Self::open_latest_semantic(projection.inner)
        })
        .await
        .map_err(err)?
    }
    fn init(
        dir: PathBuf,
        expected: ProjectionCheckpoint,
        options: GenerationOptions,
        create: bool,
        cleanup_orphans: bool,
    ) -> Result<Self> {
        if options.max_generations == 0 || options.max_generations > 1024 {
            return Err(Error::limit());
        }
        if create {
            fs::create_dir(&dir).map_err(err)?;
        }
        if !fs::symlink_metadata(&dir)
            .map_err(err)?
            .file_type()
            .is_dir()
        {
            return Err(conflict("not a directory"));
        }
        let lockpath = dir.join("owner.lock");
        if !create {
            safe_file(&lockpath)?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create)
            .open(lockpath)
            .map_err(err)?;
        lock.try_lock_exclusive().map_err(err)?;
        let path = dir.join("catalog.redb");
        let catalog = if create {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(err)?;
            redb::Database::builder().create_file(file).map_err(err)?
        } else {
            safe_file(&path)?;
            redb::Database::open(&path).map_err(err)?
        };
        if create {
            let mut t = catalog.begin_write().map_err(err)?;
            t.set_durability(redb::Durability::Immediate);
            {
                t.open_table(OWNED).map_err(err)?;
                t.open_table(ENTRIES).map_err(err)?;
                let mut m = t.open_table(META).map_err(err)?;
                m.insert(
                    "binding",
                    checkpoint_value(&expected)
                        .canonical_bytes(options.database.codec)?
                        .as_slice(),
                )
                .map_err(err)?;
                m.insert(
                    "slots",
                    (options.max_generations as u64).to_be_bytes().as_slice(),
                )
                .map_err(err)?;
            }
            t.commit().map_err(err)?;
            File::open(&dir).map_err(err)?.sync_all().map_err(err)?;
        }
        let t = catalog.begin_read().map_err(err)?;
        let m = t.open_table(META).map_err(err)?;
        let saved = checkpoint_from_value(
            &CanonicalValue::parse(
                m.get("binding")
                    .map_err(err)?
                    .ok_or_else(|| conflict("missing binding"))?
                    .value(),
                options.database.codec,
            )?,
            options.database.codec,
        )?;
        binding(&saved, &expected)?;
        if m.get("slots")
            .map_err(err)?
            .ok_or_else(|| conflict("missing slots"))?
            .value()
            != (options.max_generations as u64).to_be_bytes()
        {
            return Err(conflict("generation capacity differs"));
        }
        let entries = t.open_table(ENTRIES).map_err(err)?;
        let mut generations = BTreeMap::new();
        let mut active = None;
        for entry in entries.iter().map_err(err)? {
            let (id, kind) = entry.map_err(err)?;
            let id = id.value();
            if id > options.max_generations as u64 || kind.value() > 1 {
                return Err(conflict("catalog entry"));
            }
            if kind.value() == 1 && active.replace(id).is_some() {
                return Err(conflict("multiple live generations"));
            }
            let path = dir.join(format!("generation-{id}.redb"));
            safe_file(&path)?;
            let db = Database::open_existing(&path, options.database)?;
            binding(&saved, &db.checkpoint()?)?;
            generations.insert(id, Arc::new(Generation { db }));
        }
        if generations.len() > options.max_generations {
            return Err(Error::limit());
        }
        if !generations.is_empty() && active.is_none() {
            return Err(conflict("catalog has no live generation"));
        }
        let owned = t.open_table(OWNED).map_err(err)?;
        let mut slots = Vec::new();
        for entry in owned.iter().map_err(err)? {
            let (id, _) = entry.map_err(err)?;
            if id.value() > options.max_generations as u64 {
                return Err(conflict("unknown owned slot"));
            }
            slots.push(id.value());
        }
        if generations.keys().any(|id| !slots.contains(id)) {
            return Err(conflict("unowned catalog generation"));
        }
        drop(owned);
        drop(entries);
        drop(m);
        drop(t);
        // Only normal owner initialization cleans durably reserved staging slots.
        // Snapshot-only opens must not perform application-level recovery or cleanup.
        if cleanup_orphans {
            for id in slots {
                let p = dir.join(format!("generation-{id}.redb"));
                if !generations.contains_key(&id) && p.try_exists().map_err(err)? {
                    safe_file(&p)?;
                    fs::remove_file(p).map_err(err)?;
                }
            }
        }
        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    catalog,
                    active,
                    generations,
                }),
                dir,
                binding: saved,
                options,
                fault: AtomicBool::new(false),
                apply_fault: AtomicBool::new(false),
                _lock: lock,
            }),
        })
    }
    fn open_latest(inner: Arc<Inner>) -> Result<Arc<GenerationView>> {
        let state = inner.state.lock().map_err(err)?;
        let active = state.active.ok_or_else(|| conflict("unbuilt projection"))?;
        let generation = state
            .generations
            .get(&active)
            .ok_or_else(|| conflict("missing live generation"))?
            .clone();
        Self::open_generation_view(&inner, state, generation)
    }
    fn open_latest_semantic(inner: Arc<Inner>) -> Result<Arc<GenerationView>> {
        if inner.binding.schema().as_str() != "ctxql-semantic-rdf/v1"
            || inner.binding.algorithm().as_str() != "urn:ctxql:semantic-projection:v1"
        {
            return Err(conflict("not a semantic projection binding"));
        }
        let state = inner.state.lock().map_err(err)?;
        let mut latest: Option<(u64, ResourceId, Arc<Generation>)> = None;
        let mut latest_receipt_ambiguous = false;
        for generation in state.generations.values() {
            let checkpoint = generation.db.checkpoint()?;
            binding(&inner.binding, &checkpoint)?;
            let revision = checkpoint.snapshot().pin().revision().as_str();
            let t = revision
                .parse::<u64>()
                .map_err(|_| conflict("invalid semantic transaction revision"))?;
            if t == 0 || t.to_string() != revision {
                return Err(conflict("invalid semantic transaction revision"));
            }
            let receipt = checkpoint.snapshot().pin().receipt();
            match &latest {
                Some((latest_t, latest_receipt, _)) if t == *latest_t => {
                    latest_receipt_ambiguous |= receipt != latest_receipt;
                }
                Some((latest_t, _, _)) if t < *latest_t => {}
                _ => {
                    latest = Some((t, receipt.clone(), generation.clone()));
                    latest_receipt_ambiguous = false;
                }
            }
        }
        if latest_receipt_ambiguous {
            return Err(conflict(
                "ambiguous semantic receipts at latest transaction",
            ));
        }
        let generation = latest
            .map(|(_, _, generation)| generation)
            .ok_or_else(|| conflict("unbuilt projection"))?;
        Self::open_generation_view(&inner, state, generation)
    }
    fn open_generation_view(
        inner: &Arc<Inner>,
        state: std::sync::MutexGuard<'_, State>,
        generation: Arc<Generation>,
    ) -> Result<Arc<GenerationView>> {
        let pin = generation.db.checkpoint()?.snapshot().clone();
        let view = generation.db.open_view(&pin)?;
        drop(state);
        Ok(Arc::new(GenerationView {
            view,
            _generation: generation,
            _owner: inner.clone(),
        }))
    }
    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Inner, &mut State) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut s = inner.state.lock().map_err(err)?;
            f(&inner, &mut s)
        })
        .await
        .map_err(err)?
    }
    /// Trusted deterministic rollback probe; does not wake the coordinator.
    pub fn set_before_apply_fault(&self, enabled: bool) {
        self.inner.apply_fault.store(enabled, Ordering::SeqCst);
    }
    pub fn set_before_publish_fault(&self, enabled: bool) {
        self.inner.fault.store(enabled, Ordering::SeqCst);
    }
    pub async fn cached_snapshots(&self) -> Result<Vec<SnapshotRef>> {
        self.run(|_, s| {
            s.generations
                .values()
                .map(|g| Ok(g.db.checkpoint()?.snapshot().clone()))
                .collect()
        })
        .await
    }
    pub async fn open_generation(&self, pin: &SnapshotRef) -> Result<Arc<GenerationView>> {
        let pin = pin.clone();
        let owner = self.inner.clone();
        self.run(move |_, s| {
            for g in s.generations.values() {
                if g.db.checkpoint()?.snapshot() == &pin {
                    return Ok(Arc::new(GenerationView {
                        view: g.db.open_view(&pin)?,
                        _generation: g.clone(),
                        _owner: owner,
                    }));
                }
            }
            Err(Error::new(
                ErrorKind::Snapshot,
                "exact generation unavailable",
            ))
        })
        .await
    }
    pub async fn rebuild_live(
        &self,
        export: &CompleteExport,
        cp: &ProjectionCheckpoint,
    ) -> Result<()> {
        let export = export.clone();
        let cp = cp.clone();
        self.run(move |i, s| materialize(i, s, &export, &cp, true, || {}))
            .await
    }
    /// Trusted fixture-only barrier after durable stage/reservation and before publication.
    /// Runs under the owner mutex: callback must be bounded, non-reentrant, and
    /// must not call this projection. No callback is installed on production calls.
    #[doc(hidden)]
    pub async fn rebuild_live_with_before_publish_probe(
        &self,
        export: &CompleteExport,
        cp: &ProjectionCheckpoint,
        probe: impl FnOnce() + Send + 'static,
    ) -> Result<()> {
        let export = export.clone();
        let cp = cp.clone();
        self.run(move |i, s| materialize(i, s, &export, &cp, true, probe))
            .await
    }
    /// Trusted fixture-only barrier inside the live write transaction before commit.
    /// Callback runs under the owner mutex and must be bounded and non-reentrant.
    #[doc(hidden)]
    pub async fn apply_with_before_commit_probe(
        &self,
        batch: &ChangeBatch,
        cp: &ProjectionCheckpoint,
        probe: impl FnOnce() + Send + 'static,
    ) -> Result<()> {
        let batch = batch.clone();
        let cp = cp.clone();
        self.run(move |i, s| {
            binding(&i.binding, &cp)?;
            let active = s.active.ok_or_else(|| conflict("unbuilt projection"))?;
            let live = &s.generations[&active].db;
            let old = live.checkpoint()?;
            // Exceptional ahead-cache path only: D1 validates a full staged image before live mutation.
            if old.snapshot() != cp.snapshot() {
                for (id, g) in &s.generations {
                    if *id != active && g.db.checkpoint()?.snapshot() == cp.snapshot() {
                        let image = export(live, i.options.database)?;
                        let (slot, staged) = stage(i, s, &image, &old)?;
                        let result = (|| {
                            staged.apply(&batch, &cp)?;
                            let expected = export(&staged, i.options.database)?;
                            let cached = export(&g.db, i.options.database)?;
                            if expected.records() != cached.records() {
                                return Err(conflict("cached target image mismatch"));
                            }
                            Ok(())
                        })();
                        drop(staged);
                        fs::remove_file(i.path(slot)).map_err(err)?;
                        result?;
                    }
                }
            }
            live.set_before_commit_fault(i.apply_fault.load(Ordering::SeqCst));
            live.apply_with_before_commit_probe(&batch, &cp, probe)
        })
        .await
    }
    /// Refuses held cache generations. Retry after releasing views; never unlinks held DBs.
    pub async fn evict(&self, pin: &SnapshotRef) -> Result<()> {
        let pin = pin.clone();
        self.run(move |i, s| {
            let mut found = None;
            for (id, g) in &s.generations {
                if g.db.checkpoint()?.snapshot() == &pin && s.active != Some(*id) {
                    found = Some(*id);
                    break;
                }
            }
            let id = found.ok_or_else(|| conflict("not cached or active"))?;
            if s.active == Some(id) || Arc::strong_count(&s.generations[&id]) != 1 {
                return Err(conflict("active or held generation"));
            }
            publish(i, s, None, Some(id))?;
            s.generations.remove(&id);
            fs::remove_file(i.path(id)).map_err(err)
        })
        .await
    }
}
impl Inner {
    fn path(&self, id: u64) -> PathBuf {
        self.dir.join(format!("generation-{id}.redb"))
    }
}
fn publish(i: &Inner, s: &mut State, add: Option<(u64, bool)>, remove: Option<u64>) -> Result<()> {
    if i.fault.load(Ordering::SeqCst) {
        return Err(conflict("injected before catalog publication"));
    }
    let mut t = s.catalog.begin_write().map_err(err)?;
    t.set_durability(redb::Durability::Immediate);
    {
        let mut e = t.open_table(ENTRIES).map_err(err)?;
        if let Some(id) = remove {
            e.remove(id).map_err(err)?;
        }
        if let Some((id, live)) = add {
            if live {
                if let Some(old) = s.active {
                    e.insert(old, 0).map_err(err)?;
                }
            }
            e.insert(id, if live { 1 } else { 0 }).map_err(err)?;
        }
    }
    t.commit().map_err(err)
}
fn stage(
    i: &Inner,
    s: &State,
    export: &CompleteExport,
    cp: &ProjectionCheckpoint,
) -> Result<(u64, Database)> {
    let id = (0..=i.options.max_generations as u64)
        .find(|id| !s.generations.contains_key(id))
        .ok_or_else(Error::limit)?;
    let path = i.path(id);
    let txn = s.catalog.begin_read().map_err(err)?;
    let owned = txn
        .open_table(OWNED)
        .map_err(err)?
        .get(id)
        .map_err(err)?
        .is_some();
    drop(txn);
    if path.try_exists().map_err(err)? {
        if !owned {
            return Err(conflict("unowned staging path"));
        }
        safe_file(&path)?;
        fs::remove_file(&path).map_err(err)?;
    }
    let mut txn = s.catalog.begin_write().map_err(err)?;
    txn.set_durability(redb::Durability::Immediate);
    {
        txn.open_table(OWNED)
            .map_err(err)?
            .insert(id, 0)
            .map_err(err)?;
    }
    txn.commit().map_err(err)?;
    match Database::create(&path, export, cp, i.options.database) {
        Ok(db) => {
            File::open(&i.dir).map_err(err)?.sync_all().map_err(err)?;
            Ok((id, db))
        }
        Err(e) => {
            let _ = fs::remove_file(path);
            Err(e)
        }
    }
}
fn materialize(
    i: &Inner,
    s: &mut State,
    export: &CompleteExport,
    cp: &ProjectionCheckpoint,
    live: bool,
    before_publish: impl FnOnce(),
) -> Result<()> {
    binding(&i.binding, cp)?;
    if export.snapshot() != cp.snapshot() {
        return Err(conflict("export checkpoint"));
    }
    if s.generations.len() >= i.options.max_generations {
        return Err(Error::limit());
    }
    let (id, db) = stage(i, s, export, cp)?;
    let check = (|| {
        for g in s.generations.values() {
            if g.db.checkpoint()?.snapshot() == cp.snapshot() {
                if self::export(&db, i.options.database)?.records()
                    != self::export(&g.db, i.options.database)?.records()
                {
                    return Err(conflict("existing snapshot image mismatch"));
                }
                if !live {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    })();
    match check {
        Ok(false) => {}
        result => {
            drop(db);
            fs::remove_file(i.path(id)).map_err(err)?;
            return result.map(|_| ());
        }
    }
    before_publish();
    if let Err(e) = publish(i, s, Some((id, live)), None) {
        drop(db);
        let _ = fs::remove_file(i.path(id));
        return Err(e);
    }
    s.generations.insert(id, Arc::new(Generation { db }));
    if live {
        s.active = Some(id);
    }
    Ok(())
}
fn export(db: &Database, o: DatabaseOptions) -> Result<CompleteExport> {
    let cp = db.checkpoint()?;
    let view = db.open_view(cp.snapshot())?;
    let mut pages = Vec::new();
    let mut cursor = None;
    loop {
        let p = view.scan(PageSize::new(o.max_page_records)?, cursor.as_ref())?;
        cursor = p.next().cloned();
        pages.push(p);
        if cursor.is_none() {
            break;
        }
    }
    CompleteExport::collect(
        cp.snapshot().clone(),
        ResourceId::new("redb-v1:scan")?,
        pages,
        o.max_records,
    )
}
impl ProjectionStore for RedbProjection {
    fn checkpoint(&self) -> IoFuture<'_, Option<ProjectionCheckpoint>> {
        Box::pin(self.run(|_, s| {
            s.active
                .map(|id| s.generations[&id].db.checkpoint())
                .transpose()
        }))
    }
    fn build<'a>(
        &'a self,
        export: &'a CompleteExport,
        cp: &'a ProjectionCheckpoint,
    ) -> IoFuture<'a, ()> {
        let export = export.clone();
        let cp = cp.clone();
        Box::pin(self.run(move |i, s| materialize(i, s, &export, &cp, s.active.is_none(), || {})))
    }
    fn apply<'a>(
        &'a self,
        batch: &'a ChangeBatch,
        cp: &'a ProjectionCheckpoint,
    ) -> IoFuture<'a, ()> {
        Box::pin(self.apply_with_before_commit_probe(batch, cp, || {}))
    }
    fn open_view<'a>(&'a self, pin: &'a SnapshotRef) -> IoFuture<'a, Arc<dyn RawQueryView>> {
        Box::pin(async move { Ok(self.open_generation(pin).await? as Arc<dyn RawQueryView>) })
    }
}
impl GenerationView {
    pub fn checkpoint(&self) -> &ProjectionCheckpoint {
        self.view.checkpoint()
    }
    pub fn scan(&self, size: PageSize, cursor: Option<&PageCursor>) -> Result<Page<ExportRecord>> {
        self.view.scan(size, cursor)
    }
}
impl RawQueryView for GenerationView {
    fn identity(&self) -> &SnapshotRef {
        self.view.identity()
    }
    fn claim(&self, id: &ClaimId) -> Result<Option<AdmittedClaim>> {
        self.view.claim(id)
    }
    fn entity(&self, id: &EntityId) -> Result<Option<Vec<DependencyRecord>>> {
        self.view.entity(id)
    }
    fn resource(&self, id: &ResourceId) -> Result<Option<DependencyRecord>> {
        self.view.resource(id)
    }
    fn incident(
        &self,
        id: &EntityId,
        d: Direction,
        size: PageSize,
        c: Option<&PageCursor>,
    ) -> Result<Page<AdmittedClaim>> {
        self.view.incident(id, d, size, c)
    }
    fn lifecycle(
        &self,
        id: &ClaimId,
        size: PageSize,
        c: Option<&PageCursor>,
    ) -> Result<Page<ExportRecord>> {
        self.view.lifecycle(id, size, c)
    }
}
