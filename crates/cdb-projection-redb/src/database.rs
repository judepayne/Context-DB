//! Single-generation, synchronous trusted-local storage kernel.
//! Transaction/table-guard scaffolding adapted with owner permission from hmem
//! redb_graph.rs: RedbGraphRuntime::{write_delta,reader} and RedbReader.
//! Unlike that source, opening never resets, and every storage/decode error propagates.
use cdb_core::{
    admission::*, claim::*, contracts::*, id::*, record_codec::*, snapshot::*, CanonicalValue as V,
    Error, ErrorKind, Limits, Result,
};
use redb::{ReadTransaction, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::{
    collections::BTreeSet,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};
const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("records-v1");
const INDEX: TableDefinition<&str, &str> = TableDefinition::new("indexes-v1");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("kernel-v1");
const HEADER: &[u8] = b"ctxql-redb-kernel/v1";
fn storage(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Backend, format!("redb: {e}"))
}
fn conflict(s: &str) -> Error {
    Error::new(ErrorKind::Conflict, s)
}
#[derive(Clone, Copy, Debug)]
pub struct DatabaseOptions {
    pub max_records: usize,
    pub max_bytes: usize,
    pub max_batch_records: usize,
    pub max_batch_bytes: usize,
    pub max_page_records: usize,
    pub codec: Limits,
}
impl Default for DatabaseOptions {
    fn default() -> Self {
        Self {
            max_records: 100_000,
            max_bytes: 128 * 1024 * 1024,
            max_batch_records: 10_000,
            max_batch_bytes: 16 * 1024 * 1024,
            max_page_records: 1000,
            codec: Limits::default(),
        }
    }
}
impl DatabaseOptions {
    fn validate(self) -> Result<Self> {
        if self.max_records == 0
            || self.max_bytes == 0
            || self.max_batch_records == 0
            || self.max_batch_bytes == 0
            || self.max_page_records == 0
        {
            return Err(Error::limit());
        }
        Ok(self)
    }
}
pub struct Database {
    db: redb::Database,
    options: DatabaseOptions,
    before_commit_fault: AtomicBool,
}
pub struct DatabaseView {
    txn: ReadTransaction,
    checkpoint: ProjectionCheckpoint,
    options: DatabaseOptions,
}
fn cp_bytes(cp: &ProjectionCheckpoint, o: DatabaseOptions) -> Result<Vec<u8>> {
    checkpoint_value(cp).canonical_bytes(o.codec)
}
fn load_cp(
    t: &impl ReadableTable<&'static str, &'static [u8]>,
    o: DatabaseOptions,
) -> Result<ProjectionCheckpoint> {
    if t.get("header")
        .map_err(storage)?
        .ok_or_else(|| conflict("missing kernel header"))?
        .value()
        != HEADER
    {
        return Err(conflict("unknown kernel header"));
    }
    let g = t
        .get("checkpoint")
        .map_err(storage)?
        .ok_or_else(|| conflict("missing checkpoint"))?;
    checkpoint_from_value(&V::parse(g.value(), o.codec)?, o.codec)
}
fn binding(old: &ProjectionCheckpoint, new: &ProjectionCheckpoint) -> Result<()> {
    if !old.snapshot().same_authority(new.snapshot())
        || old.schema() != new.schema()
        || old.algorithm() != new.algorithm()
        || old.generation() != new.generation()
    {
        return Err(conflict("kernel checkpoint binding"));
    }
    Ok(())
}
fn decode(key: &str, bytes: &[u8], o: DatabaseOptions) -> Result<ExportRecord> {
    let r = decode_record(bytes, o.codec)?;
    if r.identity_key() != key {
        return Err(conflict("record key/payload mismatch"));
    }
    Ok(r)
}
fn get(
    t: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
    o: DatabaseOptions,
) -> Result<Option<ExportRecord>> {
    t.get(key)
        .map_err(storage)?
        .map(|g| decode(key, g.value(), o))
        .transpose()
}
fn hex(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        write!(out, "{b:02x}").expect("string write");
    }
    out
}
fn prefix(kind: &str, id: &str) -> String {
    format!("{kind}:{}:", hex(id))
}
fn indexes(r: &ExportRecord) -> Vec<String> {
    let mut p = BTreeSet::new();
    if let Some(c) = r.claim() {
        let c = c.candidate();
        p.insert(prefix("out", c.subject().as_str()));
        p.insert(prefix("both", c.subject().as_str()));
        if let ClaimObject::Entity(e) = c.object() {
            p.insert(prefix("in", e.as_str()));
            p.insert(prefix("both", e.as_str()));
        }
    }
    if let ExportRecord::Lifecycle { assertion, .. } = r {
        p.insert(prefix("life", assertion.target().as_str()));
    }
    p.into_iter()
        .map(|p| format!("{p}{}", hex(&r.identity_key())))
        .collect()
}
fn references(
    t: &impl ReadableTable<&'static str, &'static [u8]>,
    r: &ExportRecord,
    o: DatabaseOptions,
) -> Result<()> {
    if matches!(r,ExportRecord::Claim(c) if c.candidate().is_lifecycle_assertion()) {
        return Err(conflict("lifecycle wrapper required"));
    }
    if let ExportRecord::Lifecycle { assertion, .. } = r {
        for id in std::iter::once(assertion.target()).chain(assertion.referenced_claim()) {
            if !matches!(
                get(t, &resource_key(id.as_str()), o)?,
                Some(ExportRecord::Claim(_) | ExportRecord::Lifecycle { .. })
            ) {
                return Err(conflict("unknown lifecycle claim"));
            }
        }
        if let Some(e) = assertion.event() {
            if !matches!(get(t,&resource_key(e.as_str()),o)?,Some(ExportRecord::Resource(r)) if r.kind()==ResourceKind::LifecycleEvent)
            {
                return Err(conflict("unknown lifecycle event"));
            }
        }
    }
    Ok(())
}
fn number(t: &impl ReadableTable<&'static str, &'static [u8]>, key: &str) -> Result<usize> {
    let g = t
        .get(key)
        .map_err(storage)?
        .ok_or_else(|| conflict("missing counter"))?;
    let b: [u8; 8] = g
        .value()
        .try_into()
        .map_err(|_| conflict("counter bytes"))?;
    usize::try_from(u64::from_be_bytes(b)).map_err(|_| Error::limit())
}
impl Database {
    /// Creates only a new file. A failed bootstrap leaves an unpublished file; never reset it.
    pub fn create(
        path: &Path,
        export: &CompleteExport,
        cp: &ProjectionCheckpoint,
        options: DatabaseOptions,
    ) -> Result<Self> {
        let options = options.validate()?;
        if export.snapshot() != cp.snapshot() {
            return Err(conflict("export checkpoint"));
        }
        if export.records().len() > options.max_records {
            return Err(Error::limit());
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(storage)?;
        let db = redb::Database::builder()
            .create_file(file)
            .map_err(storage)?;
        let kernel = Self {
            db,
            options,
            before_commit_fault: AtomicBool::new(false),
        };
        // Adapted hmem write_delta: one write txn, multiple scoped table guards, one commit.
        let mut txn = kernel.db.begin_write().map_err(storage)?;
        txn.set_durability(redb::Durability::Immediate);
        {
            let mut records = txn.open_table(RECORDS).map_err(storage)?;
            let mut index = txn.open_table(INDEX).map_err(storage)?;
            let mut meta = txn.open_table(META).map_err(storage)?;
            let mut bytes = 0usize;
            for r in export.records() {
                let key = r.identity_key();
                if records.get(key.as_str()).map_err(storage)?.is_some() {
                    return Err(conflict("duplicate export identity"));
                }
                let data = encode_record(r, options.codec)?;
                bytes = bytes.checked_add(data.len()).ok_or_else(Error::limit)?;
                if bytes > options.max_bytes {
                    return Err(Error::limit());
                }
                records
                    .insert(key.as_str(), data.as_slice())
                    .map_err(storage)?;
                for k in indexes(r) {
                    index.insert(k.as_str(), key.as_str()).map_err(storage)?;
                }
            }
            for r in export.records() {
                references(&records, r, options)?;
            }
            meta.insert("header", HEADER).map_err(storage)?;
            meta.insert("checkpoint", cp_bytes(cp, options)?.as_slice())
                .map_err(storage)?;
            meta.insert(
                "count",
                (export.records().len() as u64).to_be_bytes().as_slice(),
            )
            .map_err(storage)?;
            meta.insert("bytes", (bytes as u64).to_be_bytes().as_slice())
                .map_err(storage)?;
        }
        txn.commit().map_err(storage)?;
        Ok(kernel)
    }
    /// Reopen only a recognized generation at the full expected current checkpoint.
    pub fn open(
        path: &Path,
        expected: &ProjectionCheckpoint,
        options: DatabaseOptions,
    ) -> Result<Self> {
        let kernel = Self::open_existing(path, options)?;
        if kernel.checkpoint()? != *expected {
            return Err(conflict("open checkpoint mismatch"));
        }
        Ok(kernel)
    }
    /// Discover the validated durable checkpoint, never a catalog checkpoint copy.
    pub fn open_existing(path: &Path, options: DatabaseOptions) -> Result<Self> {
        let kernel = Self {
            db: redb::Database::open(path).map_err(storage)?,
            options: options.validate()?,
            before_commit_fault: AtomicBool::new(false),
        };
        kernel.checkpoint()?;
        let txn = kernel.db.begin_read().map_err(storage)?;
        let meta = txn.open_table(META).map_err(storage)?;
        if number(&meta, "count")? > options.max_records
            || number(&meta, "bytes")? > options.max_bytes
        {
            return Err(Error::limit());
        }
        if txn
            .open_table(RECORDS)
            .map_err(storage)?
            .len()
            .map_err(storage)?
            != number(&meta, "count")? as u64
        {
            return Err(conflict("record count mismatch"));
        }
        txn.open_table(INDEX).map_err(storage)?;
        drop(meta);
        drop(txn);
        Ok(kernel)
    }
    pub fn checkpoint(&self) -> Result<ProjectionCheckpoint> {
        let txn = self.db.begin_read().map_err(storage)?;
        load_cp(&txn.open_table(META).map_err(storage)?, self.options)
    }
    /// Deterministic pre-commit rollback probe; no data is committed while enabled.
    pub fn set_before_commit_fault(&self, enabled: bool) {
        self.before_commit_fault.store(enabled, Ordering::SeqCst);
    }
    pub fn apply(&self, batch: &ChangeBatch, cp: &ProjectionCheckpoint) -> Result<()> {
        self.apply_with_before_commit_probe(batch, cp, || {})
    }
    /// Trusted fixture instrumentation, invoked once after writes and before native commit.
    /// The transaction remains live. Callback must be bounded and non-reentrant; it
    /// must not call this database. Production callers should use `apply`.
    #[doc(hidden)]
    pub fn apply_with_before_commit_probe(
        &self,
        batch: &ChangeBatch,
        cp: &ProjectionCheckpoint,
        probe: impl FnOnce(),
    ) -> Result<()> {
        let o = self.options;
        if batch.changes().len() > o.max_batch_records {
            return Err(Error::limit());
        }
        if cp.snapshot() != batch.result() {
            return Err(conflict("batch checkpoint"));
        }
        let mut work = 0usize;
        for c in batch.changes() {
            work = work
                .checked_add(encode_change(c, o.codec)?.len())
                .ok_or_else(Error::limit)?;
            if work > o.max_batch_bytes {
                return Err(Error::limit());
            }
        }
        let mut txn = self.db.begin_write().map_err(storage)?;
        txn.set_durability(redb::Durability::Immediate);
        {
            let mut meta = txn.open_table(META).map_err(storage)?;
            let old = load_cp(&meta, o)?;
            binding(&old, cp)?;
            if old == *cp {
                return if meta
                    .get("digest")
                    .map_err(storage)?
                    .is_some_and(|g| g.value() == batch.digest().as_str().as_bytes())
                {
                    Ok(())
                } else {
                    Err(conflict("changed duplicate"))
                };
            }
            if old.snapshot() != batch.predecessor() {
                return Err(conflict("predecessor gap"));
            }
            let mut records = txn.open_table(RECORDS).map_err(storage)?;
            let mut index = txn.open_table(INDEX).map_err(storage)?;
            let mut count = number(&meta, "count")?;
            let mut bytes = number(&meta, "bytes")?;
            let mut staged = Vec::new();
            let mut touched = BTreeSet::new();
            for c in batch.changes() {
                let mut previous = None;
                let r = match c {
                    RecordChange::ClaimAdded(c) => Some(ExportRecord::Claim(c.clone())),
                    RecordChange::LifecycleAdded {
                        assertion,
                        transaction_time,
                    } => Some(ExportRecord::Lifecycle {
                        assertion: assertion.clone(),
                        transaction_time: *transaction_time,
                    }),
                    RecordChange::ArtifactAdded(a) => Some(ExportRecord::Artifact(a.clone())),
                    RecordChange::Resource(change) => {
                        change.validate()?;
                        match change {
                            ResourceChange::Add(r) => Some(ExportRecord::Resource(r.clone())),
                            ResourceChange::ReplaceMutable {
                                previous: hash,
                                record,
                            } => {
                                previous = Some((record.id(), record.kind(), hash));
                                Some(ExportRecord::Resource(record.clone()))
                            }
                            ResourceChange::RetractMutable {
                                id,
                                kind,
                                previous: hash,
                            } => {
                                previous = Some((id, *kind, hash));
                                None
                            }
                        }
                    }
                };
                let key = if let Some(r) = &r {
                    r.identity_key()
                } else {
                    resource_key(previous.expect("retraction").0.as_str())
                };
                if !touched.insert(key.clone()) {
                    return Err(conflict("duplicate change"));
                }
                if let Some((_, kind, hash)) = previous {
                    match get(&records, &key, o)? {
                        Some(ExportRecord::Resource(old))
                            if old.kind() == kind
                                && ContentHash::of_bytes(
                                    &old.projection().canonical_bytes(o.codec)?,
                                ) == *hash => {}
                        _ => return Err(conflict("mutable previous hash/kind")),
                    }
                    let removed = records
                        .remove(key.as_str())
                        .map_err(storage)?
                        .ok_or_else(|| conflict("missing mutable"))?;
                    bytes = bytes
                        .checked_sub(removed.value().len())
                        .ok_or_else(|| conflict("counter underflow"))?;
                    count = count
                        .checked_sub(1)
                        .ok_or_else(|| conflict("counter underflow"))?;
                } else if get(&records, &key, o)?.is_some() {
                    return Err(conflict("occupied immutable/add identity"));
                }
                if let Some(r) = r {
                    let data = encode_record(&r, o.codec)?;
                    bytes = bytes.checked_add(data.len()).ok_or_else(Error::limit)?;
                    count = count.checked_add(1).ok_or_else(Error::limit)?;
                    if bytes > o.max_bytes || count > o.max_records {
                        return Err(Error::limit());
                    }
                    records
                        .insert(key.as_str(), data.as_slice())
                        .map_err(storage)?;
                    for k in indexes(&r) {
                        index.insert(k.as_str(), key.as_str()).map_err(storage)?;
                    }
                    staged.push(r);
                }
            }
            for r in &staged {
                references(&records, r, o)?;
            }
            meta.insert("checkpoint", cp_bytes(cp, o)?.as_slice())
                .map_err(storage)?;
            meta.insert("digest", batch.digest().as_str().as_bytes())
                .map_err(storage)?;
            meta.insert("count", (count as u64).to_be_bytes().as_slice())
                .map_err(storage)?;
            meta.insert("bytes", (bytes as u64).to_be_bytes().as_slice())
                .map_err(storage)?;
        }
        probe();
        if self.before_commit_fault.load(Ordering::SeqCst) {
            return Err(conflict("injected before commit"));
        }
        txn.commit().map_err(storage)
    }
    /// Owned ReadTransaction ported from hmem reader/RedbReader; pin checked INSIDE it.
    pub fn open_view(&self, pin: &SnapshotRef) -> Result<DatabaseView> {
        let txn = self.db.begin_read().map_err(storage)?;
        let checkpoint = load_cp(&txn.open_table(META).map_err(storage)?, self.options)?;
        if checkpoint.snapshot() != pin {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "exact generation unavailable",
            ));
        }
        Ok(DatabaseView {
            txn,
            checkpoint,
            options: self.options,
        })
    }
}
impl DatabaseView {
    pub fn checkpoint(&self) -> &ProjectionCheckpoint {
        &self.checkpoint
    }
    fn record(&self, key: &str) -> Result<Option<ExportRecord>> {
        get(
            &self.txn.open_table(RECORDS).map_err(storage)?,
            key,
            self.options,
        )
    }
    /// Bounded ordered record scan, for later catalog/rebuild wrappers.
    pub fn scan(&self, size: PageSize, cursor: Option<&PageCursor>) -> Result<Page<ExportRecord>> {
        self.page(None, size, cursor)
    }
    fn page(
        &self,
        prefix: Option<String>,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<ExportRecord>> {
        if size.get() > self.options.max_page_records {
            return Err(Error::limit());
        }
        let stream = ResourceId::new(format!("redb-v1:{}", prefix.as_deref().unwrap_or("scan")))?;
        let start = cursor.map(|c| c.position().as_str());
        if let Some(c) = cursor {
            if c.snapshot() != self.identity() || c.stream() != &stream {
                return Err(conflict("cursor binding"));
            }
        }
        let mut items = Vec::new();
        let mut last = None;
        let mut more = false;
        let mut bytes = 0usize;
        let records = self.txn.open_table(RECORDS).map_err(storage)?;
        if let Some(p) = prefix {
            let index = self.txn.open_table(INDEX).map_err(storage)?;
            if let Some(s) = start {
                if !s.starts_with(&p) || index.get(s).map_err(storage)?.is_none() {
                    return Err(conflict("cursor position"));
                }
            }
            let upper = format!("{p}~");
            let lower = start.unwrap_or(&p);
            for entry in index.range(lower..upper.as_str()).map_err(storage)? {
                let (k, v) = entry.map_err(storage)?;
                if Some(k.value()) == start {
                    continue;
                }
                if items.len() == size.get() {
                    more = true;
                    break;
                }
                let r = get(&records, v.value(), self.options)?
                    .ok_or_else(|| conflict("dangling index"))?;
                if !indexes(&r).iter().any(|i| i == k.value()) {
                    return Err(conflict("index mismatch"));
                }
                bytes = bytes
                    .checked_add(encode_record(&r, self.options.codec)?.len())
                    .ok_or_else(Error::limit)?;
                if bytes > self.options.max_batch_bytes {
                    return Err(Error::limit());
                }
                items.push(r);
                last = Some(k.value().to_string());
            }
        } else {
            if let Some(s) = start {
                if records.get(s).map_err(storage)?.is_none() {
                    return Err(conflict("cursor position"));
                }
            }
            for entry in records.range(start.unwrap_or("")..).map_err(storage)? {
                let (k, v) = entry.map_err(storage)?;
                if Some(k.value()) == start {
                    continue;
                }
                if items.len() == size.get() {
                    more = true;
                    break;
                }
                bytes = bytes
                    .checked_add(v.value().len())
                    .ok_or_else(Error::limit)?;
                if bytes > self.options.max_batch_bytes {
                    return Err(Error::limit());
                }
                items.push(decode(k.value(), v.value(), self.options)?);
                last = Some(k.value().to_string());
            }
        }
        if start.is_some() && items.is_empty() {
            return Err(conflict("terminal cursor"));
        }
        let next = if more {
            Some(PageCursor::new(
                self.identity().clone(),
                stream,
                VersionId::new(last.ok_or_else(|| conflict("no progress"))?)?,
            ))
        } else {
            None
        };
        Page::new(items, self.identity().clone(), next, size)
    }
}
impl RawQueryView for DatabaseView {
    fn identity(&self) -> &SnapshotRef {
        self.checkpoint.snapshot()
    }
    fn claim(&self, id: &ClaimId) -> Result<Option<AdmittedClaim>> {
        Ok(self
            .record(&resource_key(id.as_str()))?
            .and_then(|r| r.claim()))
    }
    fn resource(&self, id: &ResourceId) -> Result<Option<DependencyRecord>> {
        Ok(match self.record(&resource_key(id.as_str()))? {
            Some(ExportRecord::Resource(r)) => Some(r),
            _ => None,
        })
    }
    fn entity(&self, id: &EntityId) -> Result<Option<Vec<DependencyRecord>>> {
        Ok(self
            .resource(&ResourceId::new(id.as_str())?)?
            .map(|r| vec![r]))
    }
    fn incident(
        &self,
        id: &EntityId,
        direction: Direction,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<AdmittedClaim>> {
        let p = self.page(
            Some(prefix(
                match direction {
                    Direction::Outgoing => "out",
                    Direction::Incoming => "in",
                    Direction::Both => "both",
                },
                id.as_str(),
            )),
            size,
            cursor,
        )?;
        let next = p.next().cloned();
        let items = p
            .into_items()
            .into_iter()
            .map(|r| r.claim().ok_or_else(|| conflict("nonclaim adjacency")))
            .collect::<Result<Vec<_>>>()?;
        Page::new(items, self.identity().clone(), next, size)
    }
    fn lifecycle(
        &self,
        id: &ClaimId,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<ExportRecord>> {
        self.page(Some(prefix("life", id.as_str())), size, cursor)
    }
}
