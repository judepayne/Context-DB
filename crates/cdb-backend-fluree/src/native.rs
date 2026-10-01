//! Trusted native storage kernel; not an admission or authorization API.
//!
//! Copied/adapted with the owner's explicit authorization from hmem
//! crates/hmem-runtime/src/fluree_ctx.rs: FlureeBridge::{new,run,event_receiver},
//! Drop, FlureeCtxLedger::open lock/builder, reified builders/read-back.
//! Source SHA256: 30f266195e6d29f3261e2fe041cd0c8c17ab791b54d56636b60570a581e9224b.
//! Blocking reply channels become async oneshots; reset/republish is NOT copied.
use fluree_db_api::{Fluree, FlureeBuilder, LedgerState, Novelty, TimeSpec};
use fluree_db_core::LedgerSnapshot;
use fluree_db_nameservice::{NameServiceEvent, SubscriptionScope};
use fs2::FileExt;
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

pub type NativeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const NS: &str = "urn:ctxql:native:v1:";
const CONTROL: &str = "urn:ctxql:native:genesis";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativePin {
    pub t: i64,
    pub cid: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeRecord {
    pub kind: String,
    pub key: String,
    pub hash: String,
    pub payload: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenMode {
    CreateNew,
    OpenExisting,
}
#[derive(Debug, Clone)]
pub struct NativeLimits {
    pub max_transaction_bytes: usize,
    pub max_query_bytes: usize,
    pub max_result_bytes: usize,
    pub max_records: usize,
    pub query_timeout_ms: u64,
}
impl Default for NativeLimits {
    fn default() -> Self {
        Self {
            max_transaction_bytes: 4 * 1024 * 1024,
            max_query_bytes: 64 * 1024,
            max_result_bytes: 16 * 1024 * 1024,
            max_records: 10_000,
            query_timeout_ms: 30_000,
        }
    }
}

struct FlureeBridge {
    runtime: Option<tokio::runtime::Runtime>,
}
impl FlureeBridge {
    fn new() -> NativeResult<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("ctxql-fluree")
            .enable_all()
            .build()?;
        Ok(Self {
            runtime: Some(runtime),
        })
    }
    fn run<T, F>(
        &self,
        fut: F,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NativeResult<T>> + Send + '_>>
    where
        T: Send + 'static,
        F: std::future::Future<Output = NativeResult<T>> + Send + 'static,
    {
        Box::pin(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.runtime
                .as_ref()
                .expect("runtime present until drop")
                .handle()
                .spawn(async move {
                    let _ = tx.send(fut.await);
                });
            rx.await
                .map_err(|_| "fluree task dropped before completion")?
        })
    }
    fn event_receiver(
        &self,
        fluree: &Arc<Fluree>,
    ) -> tokio::sync::broadcast::Receiver<NameServiceEvent> {
        fluree
            .event_bus()
            .subscribe(SubscriptionScope::All)
            .receiver
    }
}
impl Drop for FlureeBridge {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}
struct Owned {
    fluree: Arc<Fluree>,
    ledger: String,
    gate: tokio::sync::Mutex<()>,
    #[cfg(test)]
    commit_barrier:
        tokio::sync::Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    // Last field; tasks retain this owner even after caller cancellation/drop.
    _storage_lock: std::fs::File,
}
#[derive(Clone)]
pub(crate) struct NativeStore {
    owner: Arc<Owned>,
    bridge: Arc<FlureeBridge>,
    limits: NativeLimits,
}

impl NativeStore {
    pub async fn open(
        path: PathBuf,
        ledger: String,
        mode: OpenMode,
        limits: NativeLimits,
    ) -> NativeResult<Self> {
        if ledger.is_empty() || !ledger.contains(':') || ledger.len() > 1024 {
            return Err("explicit canonical ledger:branch required".into());
        }
        if limits.max_records == 0
            || limits.max_records > 1_000_000
            || limits.query_timeout_ms == 0
            || limits.max_transaction_bytes == 0
            || limits.max_query_bytes == 0
            || limits.max_result_bytes == 0
        {
            return Err("invalid native limits".into());
        }
        // Filesystem work does not occupy the calling reactor.
        let (path, storage_lock) = tokio::task::spawn_blocking(move || -> NativeResult<_> {
            match mode {
                OpenMode::CreateNew => std::fs::create_dir(&path)?,
                OpenMode::OpenExisting => {
                    if !path.is_dir() {
                        return Err("missing native directory".into());
                    }
                }
            }
            let path = path.canonicalize()?;
            let storage_lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(path.join("owner.lock"))?;
            storage_lock.try_lock_exclusive()?;
            Ok((path, storage_lock))
        })
        .await??;
        let bridge = Arc::new(FlureeBridge::new()?);
        let owner = bridge
            .run(async move {
                let fluree = Arc::new(
                    FlureeBuilder::file(path.to_str().ok_or("non-UTF8 storage path")?)
                        // Incremental indexing in the pinned SDK corrupts historical
                        // retractions. Admission below bounds novelty instead.
                        .without_indexing()
                        .with_novelty_thresholds(usize::MAX - 1, usize::MAX)
                        .build()?,
                );
                if mode == OpenMode::CreateNew {
                    fluree
                        .insert(
                            LedgerState::new(LedgerSnapshot::genesis(&ledger), Novelty::new(0)),
                            &json!({"@id":CONTROL, format!("{NS}schema"):"native-v1"}),
                        )
                        .await?;
                } else {
                    fluree.ledger(&ledger).await?;
                }
                Ok(Arc::new(Owned {
                    fluree,
                    ledger,
                    gate: tokio::sync::Mutex::new(()),
                    #[cfg(test)]
                    commit_barrier: tokio::sync::Mutex::new(None),
                    _storage_lock: storage_lock,
                }))
            })
            .await?;
        let store = Self {
            owner,
            bridge,
            limits,
        };
        if mode == OpenMode::OpenExisting {
            // Authority open validates the bounded durable RAW image before
            // repairing derived indexes; do not trust the old index here.
            return Ok(store);
        }
        let pin = store.head().await?;
        let o = store.owner.clone();
        store
            .bridge
            .run(async move {
                let q = format!("SELECT ?v WHERE {{ <{CONTROL}> <{NS}schema> ?v }} LIMIT 2");
                let rows = o
                    .fluree
                    .graph_at(&o.ledger, TimeSpec::AtT(pin.t))
                    .query()
                    .sparql(&q)
                    .execute_formatted()
                    .await?;
                let rows = bindings(&rows)?;
                if rows.len() != 1 || cell(&rows[0], "v")? != "native-v1" {
                    return Err("missing/unknown native schema; repair required".into());
                }
                Ok(())
            })
            .await?;
        Ok(store)
    }
    #[cfg(test)]
    pub(crate) async fn pause_commit(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let pair = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        *self.owner.commit_barrier.lock().await = Some(pair.clone());
        pair
    }
    pub fn ledger_id(&self) -> &str {
        &self.owner.ledger
    }
    pub fn event_receiver(&self) -> tokio::sync::broadcast::Receiver<NameServiceEvent> {
        self.bridge.event_receiver(&self.owner.fluree)
    }
    pub async fn head(&self) -> NativeResult<NativePin> {
        let o = self.owner.clone();
        self.bridge.run(async move { head(&o).await }).await
    }
    pub(crate) async fn pin_at(&self, t: i64) -> NativeResult<NativePin> {
        let o = self.owner.clone();
        self.bridge
            .run(async move {
                let c = o.fluree.graph(&o.ledger).commit_t(t).execute().await?;
                if c.t != t {
                    return Err("native t mismatch".into());
                }
                Ok(NativePin { t, cid: c.id })
            })
            .await
    }
    /// Detect incomplete mirrors and extra physical triples, including unknown subjects.
    pub(crate) async fn audit_physical(&self, pin: &NativePin, records: usize) -> NativeResult<()> {
        let o = self.owner.clone();
        let pin = pin.clone();
        let cap = self.limits.max_result_bytes;
        let timeout = self.limits.query_timeout_ms;
        self.bridge
            .run(async move {
                validate(&o, &pin).await?;
                let q = "SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }";
                let v = tokio::time::timeout(std::time::Duration::from_millis(timeout), async {
                    o.fluree
                        .graph_at(&o.ledger, TimeSpec::AtT(pin.t))
                        .query()
                        .sparql(q)
                        .execute_formatted()
                        .await
                })
                .await
                .map_err(|_| "native COUNT timeout")??;
                if serde_json::to_vec(&v)?.len() > cap {
                    return Err("result bytes exceeded".into());
                }
                let rows = bindings(&v)?;
                if rows.len() != 1
                    || cell(&rows[0], "n")?.parse::<usize>()?
                        != records
                            .checked_mul(4)
                            .and_then(|n| n.checked_add(1))
                            .ok_or("record count overflow")?
                {
                    return Err("unmanaged/incomplete physical records".into());
                }
                Ok(())
            })
            .await
    }
    /// Replay durable commits without consulting the potentially broken index.
    /// Only the fixed native string-mirror schema is accepted, including COUNT's
    /// equivalent physical completeness check on the current image.
    pub(crate) async fn raw_records(&self, pin: &NativePin) -> NativeResult<Vec<NativeRecord>> {
        let o = self.owner.clone();
        let pin = pin.clone();
        let limits = self.limits.clone();
        self.bridge
            .run(async move {
                tokio::time::timeout(
                    std::time::Duration::from_millis(limits.query_timeout_ms),
                    async {
                        validate(&o, &pin).await?;
                        let mut image = BTreeSet::new();
                        let (mut bytes, mut flakes) = (0usize, 0usize);
                        let byte_cap = limits
                            .max_result_bytes
                            .checked_mul(16)
                            .ok_or("raw budget overflow")?;
                        let flake_cap = limits
                            .max_records
                            .checked_mul(8)
                            .and_then(|n| n.checked_add(1))
                            .ok_or("raw budget overflow")?;
                        for t in 1..=pin.t {
                            let c = o.fluree.graph(&o.ledger).commit_t(t).execute().await?;
                            bytes = bytes.checked_add(c.size).ok_or("raw bytes overflow")?;
                            flakes = flakes
                                .checked_add(c.flakes.len())
                                .ok_or("raw rows overflow")?;
                            if bytes > byte_cap || flakes > flake_cap {
                                return Err(cdb_core::Error::limit().into());
                            }
                            let expand = |s: &str| {
                                s.split_once(':')
                                    .and_then(|(prefix, tail)| {
                                        c.context.get(prefix).map(|base| format!("{base}{tail}"))
                                    })
                                    .unwrap_or_else(|| s.to_owned())
                            };
                            for f in &c.flakes {
                                if f.lang.is_some()
                                    || f.i.is_some()
                                    || f.graph.is_some()
                                    || expand(&f.dt) != "http://www.w3.org/2001/XMLSchema#string"
                                {
                                    return Err("unmanaged raw triple datatype/metadata".into());
                                }
                                let value = serde_json::to_value(&f.o)?;
                                let value =
                                    value.as_str().ok_or("non-string raw mirror")?.to_owned();
                                let row = (expand(&f.s), expand(&f.p), value);
                                if f.op {
                                    image.insert(row);
                                } else {
                                    image.remove(&row);
                                }
                            }
                        }
                        if !image.remove(&(
                            CONTROL.into(),
                            format!("{NS}schema"),
                            "native-v1".into(),
                        )) {
                            return Err("missing native schema".into());
                        }
                        let mut subjects = std::collections::BTreeMap::<
                            String,
                            std::collections::BTreeMap<String, String>,
                        >::new();
                        for (s, p, v) in image {
                            if subjects.entry(s).or_default().insert(p, v).is_some() {
                                return Err("multiple raw mirror values".into());
                            }
                        }
                        if subjects.len() > limits.max_records {
                            return Err(cdb_core::Error::limit().into());
                        }
                        let mut records = Vec::new();
                        for (s, mut fields) in subjects {
                            let mut field = |name| {
                                fields
                                    .remove(&format!("{NS}{name}"))
                                    .ok_or("missing raw mirror")
                            };
                            let r = NativeRecord {
                                kind: field("kind")?,
                                key: field("key")?,
                                hash: field("hash")?,
                                payload: field("payload")?,
                            };
                            if !fields.is_empty() || s != record_iri(&r.kind, &r.key) {
                                return Err("unmanaged raw triples".into());
                            }
                            records.push(r);
                        }
                        if image_result_bytes(records.iter())? > limits.max_result_bytes {
                            return Err(cdb_core::Error::limit().into());
                        }
                        Ok(records)
                    },
                )
                .await
                .map_err(|_| "native raw replay deadline exceeded")?
            })
            .await
    }
    /// Rebuild only derived indexes; caller must validate raw authority first.
    pub(crate) async fn repair_index(&self) -> NativeResult<()> {
        let o = self.owner.clone();
        let bridge = self.bridge.clone();
        let limits = self.limits.clone();
        self.bridge
            .run(async move {
                let _bridge = bridge;
                let _guard = o.gate.lock().await;
                let before = head(&o).await?;
                tokio::time::timeout(
                    std::time::Duration::from_millis(limits.query_timeout_ms),
                    async {
                        // Bound durable ancestry before asking the full builder to load it.
                        // A decoded commit is materialized by the SDK before its size can
                        // be checked; these are cooperative limits, not an RSS sandbox.
                        let byte_cap = limits
                            .max_result_bytes
                            .checked_mul(16)
                            .ok_or("repair byte budget overflow")?;
                        let flake_cap = limits
                            .max_records
                            .checked_mul(8)
                            .and_then(|n| n.checked_add(1))
                            .ok_or("repair row budget overflow")?;
                        let (mut bytes, mut flakes) = (0usize, 0usize);
                        for t in 1..=before.t {
                            let c = o.fluree.graph(&o.ledger).commit_t(t).execute().await?;
                            bytes = bytes.checked_add(c.size).ok_or("repair bytes overflow")?;
                            flakes = flakes
                                .checked_add(c.asserts)
                                .and_then(|n| n.checked_add(c.retracts))
                                .ok_or("repair rows overflow")?;
                            if bytes > byte_cap || flakes > flake_cap {
                                return Err::<(), Box<dyn std::error::Error + Send + Sync>>(
                                    cdb_core::Error::limit().into(),
                                );
                            }
                        }
                        let mut options = fluree_db_api::ReindexOptions::default();
                        let config = options.indexer_config.get_or_insert_with(Default::default);
                        config.incremental_enabled = false;
                        // Do not spawn unowned asynchronous GC beyond this owner gate.
                        config.gc_max_old_indexes = u32::MAX;
                        config.run_budget_bytes =
                            limits.max_result_bytes.clamp(1024 * 1024, 64 * 1024 * 1024);
                        Box::pin(o.fluree.reindex(&o.ledger, options)).await?;
                        // Equal-t replacement does not invalidate the SDK's loaded
                        // LedgerState. Drop that derived cache before any exact query.
                        o.fluree.disconnect_ledger(&o.ledger).await;
                        Ok(())
                    },
                )
                .await
                .map_err(|_| "native full reindex deadline exceeded")??;
                if head(&o).await? != before {
                    return Err("full reindex changed durable head".into());
                }
                Ok(())
            })
            .await
    }
    pub async fn validate_pin(&self, pin: &NativePin) -> NativeResult<()> {
        let o = self.owner.clone();
        let pin = pin.clone();
        self.bridge
            .run(async move { validate(&o, &pin).await })
            .await
    }
    /// Trusted exact-image deletion/insertion, one native transaction. Higher layer
    /// validates content hashes, immutability, identity, journal and all policy.
    #[cfg(test)]
    pub async fn commit(
        &self,
        expected: &NativePin,
        delete: Vec<NativeRecord>,
        insert: Vec<NativeRecord>,
    ) -> NativeResult<NativePin> {
        self.commit_owned(expected, delete, insert, None).await
    }
    /// The detached native task owns the authority fence through epoch publication.
    pub(crate) async fn commit_owned(
        &self,
        expected: &NativePin,
        delete: Vec<NativeRecord>,
        insert: Vec<NativeRecord>,
        completion: Option<(
            Arc<tokio::sync::OwnedMutexGuard<()>>,
            Arc<std::sync::atomic::AtomicI64>,
        )>,
    ) -> NativeResult<NativePin> {
        if delete.len().saturating_add(insert.len()) > self.limits.max_records
            || (delete.is_empty() && insert.is_empty())
        {
            return Err("invalid transaction record count".into());
        }
        let mut seen = BTreeSet::new();
        for records in [&delete, &insert] {
            seen.clear();
            for r in records {
                if !seen.insert((&r.kind, &r.key)) {
                    return Err("duplicate transaction identity".into());
                }
            }
        }
        let tx = json!({"delete":delete.iter().map(resource).collect::<Vec<_>>(), "insert":insert.iter().map(resource).collect::<Vec<_>>()});
        if serde_json::to_vec(&tx)?.len() > self.limits.max_transaction_bytes {
            return Err(cdb_core::Error::limit().into());
        }
        // Explicit finite novelty budget, checked before entering the SDK's
        // transaction/backpressure path. Include conservative incoming flake
        // overhead (four triples per record, both retractions and assertions).
        let novelty_cap = self
            .limits
            .max_result_bytes
            .checked_mul(16)
            .and_then(|n| n.checked_add(self.limits.max_records.checked_mul(4096)?))
            .ok_or("novelty budget overflow")?;
        let incoming = serde_json::to_vec(&tx)?
            .len()
            .checked_mul(32)
            .and_then(|n| n.checked_add((delete.len() + insert.len()).checked_mul(4096)?))
            .ok_or("novelty estimate overflow")?;
        let o = self.owner.clone();
        let expected = expected.clone();
        let bridge = self.bridge.clone();
        self.bridge
            .run(async move {
                let _bridge = bridge;
                let _guard = o.gate.lock().await;
                #[cfg(test)]
                if let Some((entered, release)) = o.commit_barrier.lock().await.take() {
                    entered.notify_one();
                    release.notified().await;
                }
                if head(&o).await? != expected {
                    return Err("native predecessor conflict".into());
                }
                if o.fluree
                    .ledger(&o.ledger)
                    .await?
                    .novelty_size()
                    .checked_add(incoming)
                    .is_none_or(|n| n > novelty_cap)
                {
                    return Err(cdb_core::Error::limit().into());
                }
                o.fluree
                    .graph(&o.ledger)
                    .transact()
                    .update(&tx)
                    .commit()
                    .await?;
                // Even a subsequent receipt/head read failure must invalidate old contexts.
                if let Some((_, epoch)) = &completion {
                    epoch.store(expected.t + 1, std::sync::atomic::Ordering::Release);
                }
                let result = head(&o).await;
                drop(completion);
                result
            })
            .await
    }
    pub async fn read_records(
        &self,
        pin: &NativePin,
        key: Option<(String, String)>,
    ) -> NativeResult<Vec<NativeRecord>> {
        let mut out = Vec::new();
        let mut bytes = 0usize;
        loop {
            // Keep the SDK-sized page future out of every caller's async frame.
            let page = Box::pin(self.read_record_page(pin, key.clone(), out.len())).await?;
            let done = page.len() < 128 || key.is_some();
            if page.len() > self.limits.max_records.saturating_sub(out.len()) {
                return Err(cdb_core::Error::limit().into());
            }
            let size = image_result_bytes(page.iter())?;
            bytes = bytes.checked_add(size).ok_or_else(cdb_core::Error::limit)?;
            if bytes > self.limits.max_result_bytes {
                return Err(cdb_core::Error::limit().into());
            }
            out.extend(page);
            if done {
                break;
            }
        }
        out.sort_by(|a, b| (&a.kind, &a.key).cmp(&(&b.kind, &b.key)));
        if out
            .windows(2)
            .any(|w| (&w[0].kind, &w[0].key) == (&w[1].kind, &w[1].key))
        {
            return Err("duplicate native record mirrors across pages".into());
        }
        Ok(out)
    }
    pub(crate) async fn read_record_page(
        &self,
        pin: &NativePin,
        key: Option<(String, String)>,
        offset: usize,
    ) -> NativeResult<Vec<NativeRecord>> {
        let subject = key
            .as_ref()
            .map(|(k, v)| format!("<{}>", record_iri(k, v)))
            .unwrap_or("?s".into());
        let q = format!(
            "SELECT ?s ?kind ?key ?hash ?payload WHERE {{ {subject} <{NS}kind> ?kind ; <{NS}key> ?key ; <{NS}hash> ?hash ; <{NS}payload> ?payload }} ORDER BY ?s LIMIT 128 OFFSET {offset}"
        );
        if q.len() > self.limits.max_query_bytes {
            return Err("query bytes exceeded".into());
        }
        let o = self.owner.clone();
        let pin = pin.clone();
        let limits = self.limits.clone();
        self.bridge
            .run(async move {
                tokio::time::timeout(
                    std::time::Duration::from_millis(limits.query_timeout_ms),
                    async {
                        validate(&o, &pin).await?;
                        let value = o
                            .fluree
                            .graph_at(&o.ledger, TimeSpec::AtT(pin.t))
                            .query()
                            .sparql(&q)
                            .execute_formatted()
                            .await?;
                        if serde_json::to_vec(&value)?.len() > limits.max_result_bytes {
                            return Err("result bytes exceeded".into());
                        }
                        let rows = bindings(&value)?;
                        if rows.len() > limits.max_records {
                            return Err("result records exceeded".into());
                        }
                        let mut out = Vec::with_capacity(rows.len());
                        let mut seen = BTreeSet::new();
                        for row in rows {
                            let record = NativeRecord {
                                kind: cell(row, "kind")?,
                                key: cell(row, "key")?,
                                hash: cell(row, "hash")?,
                                payload: cell(row, "payload")?,
                            };
                            if (key.is_none()
                                && cell(row, "s")? != record_iri(&record.kind, &record.key))
                                || key.as_ref().is_some_and(|k| {
                                    k != &(record.kind.clone(), record.key.clone())
                                })
                                || !seen.insert((record.kind.clone(), record.key.clone()))
                            {
                                return Err("invalid native record mirrors".into());
                            }
                            out.push(record);
                        }
                        #[cfg(test)]
                        if key.is_none() {
                            assert_eq!(
                                image_result_bytes(out.iter())?,
                                serde_json::to_vec(&value)?.len()
                            );
                        }
                        out.sort_by(|a, b| (&a.kind, &a.key).cmp(&(&b.kind, &b.key)));
                        Ok(out)
                    },
                )
                .await
                .map_err(|_| "native query timeout")?
            })
            .await
    }
}
async fn head(o: &Owned) -> NativeResult<NativePin> {
    // LedgerState::t includes novelty, unlike snapshot.t (index high-water).
    let t = o.fluree.ledger(&o.ledger).await?.t();
    if t < 1 {
        return Err("native genesis is not bootstrapped".into());
    }
    let commit = o.fluree.graph(&o.ledger).commit_t(t).execute().await?;
    Ok(NativePin { t, cid: commit.id })
}
async fn validate(o: &Owned, pin: &NativePin) -> NativeResult<()> {
    if pin.t < 1 {
        return Err("invalid native t".into());
    }
    let commit = o.fluree.graph(&o.ledger).commit_t(pin.t).execute().await?;
    if commit.t != pin.t || commit.id != pin.cid {
        return Err(
            cdb_core::Error::new(cdb_core::ErrorKind::Snapshot, "native CID/t mismatch").into(),
        );
    }
    Ok(())
}
fn hex(text: &str) -> String {
    text.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn record_iri(kind: &str, key: &str) -> String {
    format!("{NS}record:{}:{}", hex(kind), hex(key))
}
fn resource(r: &NativeRecord) -> Value {
    json!({"@id":record_iri(&r.kind,&r.key), format!("{NS}kind"):r.kind, format!("{NS}key"):r.key, format!("{NS}hash"):r.hash, format!("{NS}payload"):r.payload})
}
/// Exact serialized size of the fixed unkeyed SPARQL string-mirror query.
/// Sum rows without allocating a second full image serialization.
pub(crate) fn image_result_bytes<'a>(
    records: impl IntoIterator<Item = &'a NativeRecord>,
) -> NativeResult<usize> {
    let mut bytes = serde_json::to_vec(
        &json!({"head":{"vars":["hash","key","kind","payload","s"]},"results":{"bindings":[]}}),
    )?
    .len();
    for (i, r) in records.into_iter().enumerate() {
        let row = json!({
            "s":{"type":"uri","value":record_iri(&r.kind, &r.key)},
            "kind":{"type":"literal","value":r.kind},
            "key":{"type":"literal","value":r.key},
            "hash":{"type":"literal","value":r.hash},
            "payload":{"type":"literal","value":r.payload}
        });
        bytes = bytes
            .checked_add(serde_json::to_vec(&row)?.len() + usize::from(i > 0))
            .ok_or("image size overflow")?;
    }
    Ok(bytes)
}
fn bindings(value: &Value) -> NativeResult<&Vec<Value>> {
    value
        .get("results")
        .and_then(|r| r.get("bindings"))
        .and_then(Value::as_array)
        .ok_or_else(|| "malformed native query result".into())
}
fn cell(row: &Value, key: &str) -> NativeResult<String> {
    row.get(key)
        .and_then(|c| c.get("value"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "missing native string mirror".into())
}

#[cfg(test)]
mod corruption_tests {
    use super::*;
    // Upstream incremental-index history regression: unlike a full reindex,
    // background indexing can surface future retracted hash/payload triples at
    // genesis. Native owners disable that path; COUNT remains mandatory.
    #[tokio::test]
    async fn repeated_replacements_preserve_physical_history() -> NativeResult<()> {
        let tmp = tempfile::tempdir()?;
        let n = NativeStore::open(
            tmp.path().join("db"),
            "history:main".into(),
            OpenMode::CreateNew,
            NativeLimits::default(),
        )
        .await?;
        let original = NativeRecord {
            kind: "policy".into(),
            key: "current".into(),
            hash: "original".into(),
            payload: "allow".into(),
        };
        let mut control = NativeRecord {
            kind: "control".into(),
            key: "owner".into(),
            hash: "0".into(),
            payload: "0".into(),
        };
        let genesis = n.head().await?;
        let mut initial = vec![original.clone(), control.clone()];
        for i in 0..40 {
            initial.push(NativeRecord {
                kind: "record".into(),
                key: format!("filler-{i}"),
                hash: format!("filler-{i}"),
                payload: "x".repeat(10000),
            });
        }
        let mut pin = n.commit(&genesis, vec![], initial).await?;
        let saved = pin.clone();
        let mut images = vec![
            (genesis.clone(), Vec::new()),
            (saved.clone(), n.read_records(&saved, None).await?),
        ];
        let o = n.owner.clone();
        n.bridge
            .run(async move {
                o.fluree
                    .reindex(&o.ledger, fluree_db_api::ReindexOptions::default())
                    .await?;
                Ok(())
            })
            .await?;
        for i in 0..5 {
            let changed = NativeRecord {
                hash: format!("deny-{i}"),
                payload: format!("deny-{i}"),
                ..original.clone()
            };
            let next = NativeRecord {
                hash: format!("{}", i * 2 + 1),
                payload: format!("{}", i * 2 + 1),
                ..control.clone()
            };
            pin = n
                .commit(
                    &pin,
                    vec![original.clone(), control.clone()],
                    vec![changed.clone(), next.clone()],
                )
                .await?;
            images.push((pin.clone(), n.read_records(&pin, None).await?));
            control = next;
            let next = NativeRecord {
                hash: format!("{}", i * 2 + 2),
                payload: format!("{}", i * 2 + 2),
                ..control.clone()
            };
            pin = n
                .commit(
                    &pin,
                    vec![changed, control],
                    vec![original.clone(), next.clone()],
                )
                .await?;
            images.push((pin.clone(), n.read_records(&pin, None).await?));
            control = next;
            // Give an accidentally enabled incremental indexer time to publish.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            for p in [&genesis, &saved, &pin] {
                let o = n.owner.clone();
                let p = p.clone();
                n.bridge
                    .run(async move {
                        eprintln!(
                            "iteration={i} requested_t={} index_t={}",
                            p.t,
                            o.fluree.index_status(&o.ledger).await?.index_t
                        );
                        for q in [
                            "SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }",
                            "SELECT ?s ?p ?o WHERE { ?s ?p ?o } LIMIT 170",
                        ] {
                            let v = o
                                .fluree
                                .graph_at(&o.ledger, TimeSpec::AtT(p.t))
                                .query()
                                .sparql(q)
                                .execute_formatted()
                                .await?;
                            if q.contains("COUNT") {
                                eprintln!(
                                    "iteration={i} t={} physical_count={}",
                                    p.t,
                                    cell(&bindings(&v)?[0], "n")?
                                );
                            } else {
                                eprintln!(
                                    "iteration={i} t={} physical_scan_rows={}",
                                    p.t,
                                    bindings(&v)?.len()
                                );
                            }
                        }
                        Ok(())
                    })
                    .await?;
            }
            assert_eq!(n.read_records(&saved, None).await?.len(), 42);
            n.audit_physical(&genesis, 0).await?;
            n.audit_physical(&saved, 42).await?;
            n.audit_physical(&pin, 42).await?;
        }
        drop(n);
        let n = NativeStore::open(
            tmp.path().join("db"),
            "history:main".into(),
            OpenMode::OpenExisting,
            NativeLimits::default(),
        )
        .await?;
        for (p, image) in &images {
            assert_eq!(&n.read_records(p, None).await?, image);
            n.audit_physical(p, image.len()).await?;
        }
        let before = n.head().await?;
        n.repair_index().await?;
        assert_eq!(n.head().await?, before);
        for (p, image) in &images {
            assert_eq!(&n.read_records(p, None).await?, image);
            n.audit_physical(p, image.len()).await?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn novelty_budget_rejects_before_sdk_backpressure() -> NativeResult<()> {
        let tmp = tempfile::tempdir()?;
        let n = NativeStore::open(
            tmp.path().join("bounded"),
            "bounded:main".into(),
            OpenMode::CreateNew,
            NativeLimits {
                max_result_bytes: 512,
                max_records: 1,
                ..NativeLimits::default()
            },
        )
        .await?;
        let before = n.head().await?;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            n.commit(
                &before,
                vec![],
                vec![NativeRecord {
                    kind: "record".into(),
                    key: "large".into(),
                    hash: "hash".into(),
                    payload: "x".repeat(1000),
                }],
            ),
        )
        .await?;
        assert!(result.is_err());
        assert_eq!(n.head().await?, before);
        n.audit_physical(&before, 0).await?;
        Ok(())
    }
    #[tokio::test]
    async fn explicit_open_repairs_legacy_incremental_index() -> NativeResult<()> {
        use crate::{authority::FlureeBackend, options::AuthorityOptions};
        use cdb_core::id::{AuthorityId, BackendId, GraphId};
        let tmp = tempfile::tempdir()?;
        let options = AuthorityOptions::new(
            tmp.path().join("legacy"),
            "legacy:main".into(),
            BackendId::new("legacy")?,
            AuthorityId::new("owner")?,
            GraphId::new("graph")?,
        );
        let authority = Box::pin(FlureeBackend::create(options.clone())).await?;
        authority.native.repair_index().await?;
        let genesis = authority.native.pin_at(1).await?;
        let mut images = vec![(genesis, Vec::new())];
        for _ in 0..8 {
            authority.capture(None).await?;
            let p = authority.native.head().await?;
            images.push((p.clone(), authority.native.read_records(&p, None).await?));
        }
        let before = authority.native.head().await?;
        drop(authority);
        // Simulate an old owner publishing the pinned SDK's incremental index.
        // It is completely stopped before any new native owner opens the store.
        let path = options.path.clone();
        let bridge = FlureeBridge::new()?;
        bridge
            .run(async move {
                let f = FlureeBuilder::file(path.to_str().ok_or("path")?).build()?;
                f.ledger("legacy:main").await?;
                f.trigger_index(
                    "legacy:main",
                    fluree_db_api::TriggerIndexOptions::default().with_timeout(30_000),
                )
                .await?;
                Ok(())
            })
            .await?;
        drop(bridge);
        fn files(path: &std::path::Path) -> NativeResult<Vec<(PathBuf, Vec<u8>)>> {
            let mut out = Vec::new();
            for e in std::fs::read_dir(path)? {
                let p = e?.path();
                if p.is_dir() {
                    out.extend(files(&p)?);
                } else {
                    out.push((p.clone(), std::fs::read(p)?));
                }
            }
            out.sort();
            Ok(out)
        }
        let durable = files(&options.path)?;
        let mut wrong = options.clone();
        wrong.authority = AuthorityId::new("wrong-owner")?;
        assert!(Box::pin(FlureeBackend::open(wrong)).await.is_err());
        assert_eq!(
            files(&options.path)?,
            durable,
            "wrong authority mutated storage"
        );
        let authority = Box::pin(FlureeBackend::open(options.clone())).await?;
        assert_eq!(authority.native.head().await?, before);
        for (p, image) in &images {
            assert_eq!(&authority.native.read_records(p, None).await?, image);
            authority.native.audit_physical(p, image.len()).await?;
        }
        drop(authority);
        let authority = Box::pin(FlureeBackend::open(options)).await?;
        assert_eq!(authority.native.head().await?, before);
        for (p, image) in images {
            assert_eq!(authority.native.read_records(&p, None).await?, image);
            authority.native.audit_physical(&p, image.len()).await?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn raw_unmanaged_and_incomplete_rdf_fail_count() -> NativeResult<()> {
        for incomplete in [false, true] {
            let tmp = tempfile::tempdir()?;
            let n = NativeStore::open(
                tmp.path().join("db"),
                "raw:main".into(),
                OpenMode::CreateNew,
                NativeLimits::default(),
            )
            .await?;
            let o = n.owner.clone();
            n.bridge
                .run(async move {
                    let tx = if incomplete {
                        json!({"@id":record_iri("record","x"),format!("{NS}kind"):"record"})
                    } else {
                        json!({"@id":"urn:raw", "urn:property":"unmanaged"})
                    };
                    o.fluree
                        .graph(&o.ledger)
                        .transact()
                        .insert(&tx)
                        .commit()
                        .await?;
                    Ok(())
                })
                .await?;
            let p = n.head().await?;
            assert!(n.read_records(&p, None).await?.is_empty());
            assert!(n.audit_physical(&p, 0).await.is_err());
            let raw = || {
                let o = n.owner.clone();
                n.bridge.run(async move {
                    Ok(o.fluree
                        .graph(&o.ledger)
                        .query()
                        .sparql("SELECT ?s ?p ?o WHERE { ?s ?p ?o } ORDER BY ?s ?p ?o")
                        .execute_formatted()
                        .await?)
                })
            };
            let before = raw().await?;
            n.repair_index().await?;
            assert_eq!(raw().await?, before);
            assert_eq!(n.head().await?, p);
            assert!(n.audit_physical(&p, 0).await.is_err());
        }
        Ok(())
    }
}
