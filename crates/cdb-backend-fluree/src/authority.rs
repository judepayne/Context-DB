//! Single-owner atomic admission. P0 clock/receipt and P1 staged validation adapted.
use crate::{journal::*, native::*, options::AuthorityOptions};
use cdb_core::{
    admission::*,
    claim::AdmittedClaim,
    contracts::CapturedSnapshot,
    id::*,
    snapshot::*,
    storage_origin::{RecordOrigin, INTERNAL_PREFIX},
    Timestamp,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub struct FlureeBackend {
    pub(crate) native: NativeStore,
    pub(crate) audited: tokio::sync::Mutex<Option<crate::history::Checkpoint>>,
    pub(crate) options: AuthorityOptions,
    pub(crate) mutation_gate: std::sync::Arc<tokio::sync::Mutex<()>>,
    pub(crate) policy_issuer: std::sync::Arc<()>,
    pub(crate) policy_epoch: std::sync::Arc<std::sync::atomic::AtomicI64>,
}
pub type Authority = FlureeBackend;
impl FlureeBackend {
    pub async fn create(options: AuthorityOptions) -> NativeResult<Self> {
        Self::start(options, OpenMode::CreateNew).await
    }
    pub async fn open(options: AuthorityOptions) -> NativeResult<Self> {
        Self::start(options, OpenMode::OpenExisting).await
    }
    async fn start(options: AuthorityOptions, mode: OpenMode) -> NativeResult<Self> {
        if options.max_changes == 0
            || options.max_changes > 100_000
            || options.max_history_commits < 2
            || options.max_history_commits > 1_000_000
        {
            return Err("invalid authority bounds".into());
        }
        let native = NativeStore::open(
            options.path.clone(),
            options.ledger.clone(),
            mode,
            options.native_limits.clone(),
        )
        .await?;
        let s = Self {
            native,
            audited: tokio::sync::Mutex::new(None),
            options,
            mutation_gate: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            policy_issuer: std::sync::Arc::new(()),
            policy_epoch: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0)),
        };
        let pin = s.native.head().await?;
        if mode == OpenMode::CreateNew {
            if pin.t != 1 {
                return Err("unexpected bootstrap".into());
            }
            let owner = s.owner(2, None, None)?;
            let j = control(
                "journal",
                "2",
                json!({"schema":"ctxql-authority/v1","t":"2","predecessor_t":"1","predecessor_cid":pin.cid,"operation":"init","time":"","key":"","payload":"","digest":"","claims":[],"changes":[]}),
            )?;
            let guard = std::sync::Arc::new(s.mutation_gate.clone().lock_owned().await);
            s.commit_locked(&pin, vec![], vec![owner, j], guard).await?;
        }
        let guard = s.mutation_gate.lock().await;
        if mode == OpenMode::OpenExisting {
            // No audited/keyed helper here: old derived indexes may have broken
            // historical retractions. Validate current RAW identity before any
            // derived-storage mutation, without adoption or permission fallback.
            if pin.t < 2 || pin.t as u64 > s.options.max_history_commits as u64 {
                return Err("history bound exceeded".into());
            }
            let rows = Box::pin(s.native.raw_records(&pin)).await?;
            let r = rows
                .iter()
                .find(|r| r.kind == "control" && r.key == "owner")
                .ok_or("missing authority metadata; repair required")?;
            let v = value(r)?;
            let last = parse_time(text(&v, "last")?)?;
            let closed = parse_time(text(&v, "closed")?)?;
            if *r != s.owner(pin.t, last, closed)? {
                return Err("authority identity/clock/head mismatch; repair required".into());
            }
            Box::pin(s.native.repair_index()).await?;
        }
        let head = s.state().await?.0;
        drop(guard);
        s.policy_epoch
            .store(head.t, std::sync::atomic::Ordering::Release);
        Ok(s)
    }
    fn owner(
        &self,
        t: i64,
        last: Option<Timestamp>,
        closed: Option<Timestamp>,
    ) -> NativeResult<NativeRecord> {
        control(
            "control",
            "owner",
            json!({"schema":"ctxql-authority/v1","backend":self.options.backend.as_str(),"authority":self.options.authority.as_str(),"graph":self.options.graph.as_str(),"ledger":self.options.ledger,"t":t.to_string(),"last":last.map(|v|v.canonical()).unwrap_or_default(),"closed":closed.map(|v|v.canonical()).unwrap_or_default()}),
        )
    }
    pub(crate) async fn keyed(
        &self,
        pin: &NativePin,
        kind: &str,
        key: &str,
    ) -> NativeResult<Option<NativeRecord>> {
        self.ensure_audited(&self.snapshot(pin.clone())?).await?;
        Ok(self
            .native
            .read_records(pin, Some((kind.into(), key.into())))
            .await?
            .into_iter()
            .next())
    }
    async fn state(
        &self,
    ) -> NativeResult<(
        NativePin,
        NativeRecord,
        Option<Timestamp>,
        Option<Timestamp>,
    )> {
        let p = self.native.head().await?;
        self.ensure_audited(&self.snapshot(p.clone())?).await?;
        let r = self
            .keyed(&p, "control", "owner")
            .await?
            .ok_or("missing authority metadata; repair required")?;
        let v = value(&r)?;
        let last = parse_time(text(&v, "last")?)?;
        let closed = parse_time(text(&v, "closed")?)?;
        if r != self.owner(p.t, last, closed)? {
            return Err("authority identity/clock/head mismatch; repair required".into());
        }
        let j = self
            .keyed(&p, "journal", &p.t.to_string())
            .await?
            .ok_or("missing head journal")?;
        let j = value(&j)?;
        if text(&j, "t")? != p.t.to_string() {
            return Err("journal t mismatch".into());
        }
        Ok((p, r, last, closed))
    }
    pub(crate) fn snapshot(&self, p: NativePin) -> NativeResult<SnapshotRef> {
        Ok(SnapshotRef::new(
            self.options.backend.clone(),
            GraphPin::new(
                self.options.authority.clone(),
                self.options.graph.clone(),
                VersionId::new(p.t.to_string())?,
                ResourceId::new(p.cid)?,
            ),
        ))
    }
    pub async fn validate_snapshot(&self, s: &SnapshotRef) -> NativeResult<()> {
        if s.backend() != &self.options.backend
            || s.pin().authority() != &self.options.authority
            || s.pin().graph() != &self.options.graph
        {
            return Err(cdb_core::Error::new(
                cdb_core::ErrorKind::Snapshot,
                "foreign snapshot identity",
            )
            .into());
        }
        let t = s.pin().revision().as_str().parse::<i64>().map_err(|_| {
            cdb_core::Error::new(cdb_core::ErrorKind::Snapshot, "invalid authority revision")
        })?;
        if t < 2 || t.to_string() != s.pin().revision().as_str() || t > self.native.head().await?.t
        {
            return Err(cdb_core::Error::new(
                cdb_core::ErrorKind::Snapshot,
                "invalid authority revision",
            )
            .into());
        }
        self.native
            .validate_pin(&NativePin {
                t,
                cid: s.pin().receipt().as_str().into(),
            })
            .await
    }
    pub async fn head(&self) -> NativeResult<SnapshotRef> {
        let _guard = self.mutation_gate.lock().await;
        self.snapshot(self.state().await?.0)
    }
    async fn result_pin(&self, head: &NativePin, t: i64) -> NativeResult<NativePin> {
        if t < 2 || t > head.t {
            return Err("receipt t outside authority".into());
        }
        let p = if t == head.t {
            head.clone()
        } else {
            let j = self
                .keyed(head, "journal", &(t + 1).to_string())
                .await?
                .ok_or("receipt successor journal missing")?;
            let v = value(&j)?;
            if text(&v, "predecessor_t")? != t.to_string() {
                return Err("receipt predecessor mismatch".into());
            }
            NativePin {
                t,
                cid: text(&v, "predecessor_cid")?.into(),
            }
        };
        self.native.validate_pin(&p).await?;
        Ok(p)
    }
    async fn receipt_at(
        &self,
        p: &NativePin,
        key: &IdempotencyKey,
    ) -> NativeResult<Option<AdmissionReceipt>> {
        let Some(r) = self.keyed(p, "receipt", key.as_str()).await? else {
            return Ok(None);
        };
        let v = value(&r)?;
        if text(&v, "key")? != key.as_str() || text(&v, "operation")? != "admit" {
            return Err("receipt identity mismatch".into());
        }
        let t = text(&v, "t")?.parse()?;
        let result = self.result_pin(p, t).await?;
        let journal = self
            .keyed(&result, "journal", &t.to_string())
            .await?
            .ok_or("receipt journal missing")?;
        if journal.payload != r.payload {
            return Err("receipt journal mismatch".into());
        }
        let digest = ContentHash::parse(text(&v, "digest")?)?;
        if digest != ContentHash::of_bytes(text(&v, "payload")?.as_bytes()) {
            return Err("receipt payload mismatch".into());
        }
        let claims = v["claims"]
            .as_array()
            .ok_or("receipt claims")?
            .iter()
            .map(|v| Ok(ClaimId::new(v.as_str().ok_or("claim string")?)?))
            .collect::<NativeResult<Vec<_>>>()?;
        Ok(Some(AdmissionReceipt::new(
            key.clone(),
            digest,
            self.snapshot(result)?,
            Timestamp::parse(text(&v, "time")?)?,
            claims,
        )?))
    }
    // Read-only; also used by the policy RMW caller already holding mutation_gate.
    pub async fn receipt(&self, key: &IdempotencyKey) -> NativeResult<Option<AdmissionReceipt>> {
        let p = self.state().await?.0;
        self.receipt_at(&p, key).await
    }
    pub async fn capture(&self, requested: Option<Timestamp>) -> NativeResult<CapturedSnapshot> {
        let guard = std::sync::Arc::new(self.mutation_gate.clone().lock_owned().await);
        let (p, old, last, closed) = self.state().await?;
        let now = last
            .into_iter()
            .chain(closed)
            .fold(self.options.clock.now()?, std::cmp::max);
        let cutoff = requested.unwrap_or(now);
        if cutoff > now {
            return Err("future capture unsupported".into());
        }
        let t = self.next_t(&p)?;
        let owner = self.owner(t, last, Some(closed.map_or(cutoff, |c| c.max(cutoff))))?;
        let j = control(
            "journal",
            &t.to_string(),
            json!({"schema":"ctxql-authority/v1","t":t.to_string(),"predecessor_t":p.t.to_string(),"predecessor_cid":p.cid,"operation":"capture","time":cutoff.canonical(),"key":"","payload":"","digest":"","claims":[],"changes":[]}),
        )?;
        let result = self
            .commit_locked(&p, vec![old], vec![owner, j], guard)
            .await?;
        Ok(CapturedSnapshot {
            as_of: cutoff,
            snapshot: self.snapshot(result)?,
        })
    }
    async fn commit_locked(
        &self,
        p: &NativePin,
        delete: Vec<NativeRecord>,
        insert: Vec<NativeRecord>,
        guard: std::sync::Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) -> NativeResult<NativePin> {
        crate::history::prospective(
            &self.options,
            p,
            self.audited.lock().await.as_ref(),
            &delete,
            &insert,
        )?;
        self.native
            .commit_owned(p, delete, insert, Some((guard, self.policy_epoch.clone())))
            .await
    }
    fn next_t(&self, p: &NativePin) -> NativeResult<i64> {
        let t = p.t.checked_add(1).ok_or("native sequence overflow")?;
        if t as u64 > self.options.max_history_commits as u64 {
            return Err("authority history bound exceeded".into());
        }
        Ok(t)
    }
    pub async fn admit(
        &self,
        key: &IdempotencyKey,
        batch: &AdmissionBatch,
    ) -> NativeResult<AdmissionReceipt> {
        let guard = std::sync::Arc::new(self.mutation_gate.clone().lock_owned().await);
        self.admit_locked(key, batch, false, guard).await
    }
    /// Caller holds mutation_gate. Trusted bypass is restricted to the fixed policy record.
    pub(crate) async fn admit_policy_locked(
        &self,
        key: &IdempotencyKey,
        batch: &AdmissionBatch,
        guard: std::sync::Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) -> NativeResult<AdmissionReceipt> {
        self.admit_locked(key, batch, true, guard).await
    }
    pub(crate) async fn admit_locked(
        &self,
        key: &IdempotencyKey,
        batch: &AdmissionBatch,
        trusted: bool,
        guard: std::sync::Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) -> NativeResult<AdmissionReceipt> {
        let reserved = key.as_str().starts_with(INTERNAL_PREFIX);
        if trusted {
            let policy = key
                .as_str()
                .starts_with(&format!("{INTERNAL_PREFIX}policy/admin/"))
                && batch.resources().len() == 1
                && matches!(&batch.resources()[0], ResourceChange::Add(r) | ResourceChange::ReplaceMutable { record: r, .. }
                    if r.id().as_str() == format!("{INTERNAL_PREFIX}policy/state") && r.kind() == ResourceKind::Policy);
            let runs = crate::runs::valid_managed_batch(key, batch);
            if (!policy && !runs)
                || !batch.claims().is_empty()
                || !batch.lifecycle().is_empty()
                || !batch.artifacts().is_empty()
            {
                return Err("invalid trusted managed admission".into());
            }
        } else if reserved
            || batch
                .claims()
                .iter()
                .any(|r| r.id().as_str().starts_with(INTERNAL_PREFIX))
            || batch
                .lifecycle()
                .iter()
                .any(|r| r.id().as_str().starts_with(INTERNAL_PREFIX))
            || batch
                .resources()
                .iter()
                .any(|r| r.id().as_str().starts_with(INTERNAL_PREFIX))
            || batch
                .artifacts()
                .iter()
                .any(|r| r.reference().iri().as_str().starts_with(INTERNAL_PREFIX))
        {
            return Err("reserved system identity/key".into());
        }
        let (p, old, last, closed) = self.state().await?;
        if let Some(r) = self.receipt_at(&p, key).await? {
            return if r.payload() == batch.digest() {
                Ok(r)
            } else {
                Err(cdb_core::Error::new(
                    cdb_core::ErrorKind::Conflict,
                    "idempotency payload conflict",
                )
                .into())
            };
        }
        let count = batch
            .claims()
            .len()
            .saturating_add(batch.lifecycle().len())
            .saturating_add(batch.resources().len())
            .saturating_add(batch.artifacts().len());
        if count > self.options.max_changes {
            return Err("admission change bound exceeded".into());
        }
        let payload = String::from_utf8(
            batch
                .projection()
                .canonical_bytes(self.options.codec_limits)?,
        )?;
        if ContentHash::of_bytes(payload.as_bytes()) != *batch.digest() {
            return Err("admission digest mismatch".into());
        }
        let ids = batch
            .claims()
            .iter()
            .map(|c| c.id().as_str())
            .chain(batch.lifecycle().iter().map(|c| c.id().as_str()))
            .chain(batch.resources().iter().map(|c| c.id().as_str()))
            .chain(
                batch
                    .artifacts()
                    .iter()
                    .map(|a| a.reference().iri().as_str()),
            );
        if !trusted && ids.clone().any(|id| id.starts_with(INTERNAL_PREFIX)) {
            return Err("reserved system identity".into());
        }
        let mut needed: BTreeSet<String> = batch
            .claims()
            .iter()
            .map(|c| resource_key(c.id().as_str()))
            .chain(
                batch
                    .lifecycle()
                    .iter()
                    .map(|l| resource_key(l.id().as_str())),
            )
            .chain(
                batch
                    .resources()
                    .iter()
                    .map(|r| resource_key(r.id().as_str())),
            )
            .chain(
                batch
                    .artifacts()
                    .iter()
                    .map(|a| artifact_key(a.reference())),
            )
            .collect();
        for l in batch.lifecycle() {
            needed.extend(
                std::iter::once(l.target())
                    .chain(l.referenced_claim())
                    .map(|id| resource_key(id.as_str())),
            );
            if let Some(e) = l.event() {
                needed.insert(resource_key(e.as_str()));
            }
        }
        let mut existing = BTreeMap::new();
        let mut raw = BTreeMap::new();
        for k in needed {
            if let Some(r) = self.keyed(&p, "record", &k).await? {
                existing.insert(k.clone(), decode(&r, self.options.codec_limits)?);
                raw.insert(k, r);
            }
        }
        batch.validate_claim_references(
            &existing
                .values()
                .filter_map(|r| r.claim().map(|c| c.id().clone()))
                .collect(),
        )?;
        let mut time = self.options.clock.now()?;
        for bound in last.into_iter().chain(closed) {
            time = time.max(bound.checked_add_millis(1)?);
        }
        let t = self.next_t(&p)?;
        let mut delta = vec![];
        delta.extend(
            batch.claims().iter().map(|c| {
                RecordChange::ClaimAdded(Box::new(AdmittedClaim::assign(c.clone(), time)))
            }),
        );
        delta.extend(
            batch
                .lifecycle()
                .iter()
                .map(|l| RecordChange::LifecycleAdded {
                    assertion: l.clone(),
                    transaction_time: time,
                }),
        );
        delta.extend(
            batch
                .resources()
                .iter()
                .cloned()
                .map(RecordChange::Resource),
        );
        delta.extend(
            batch
                .artifacts()
                .iter()
                .cloned()
                .map(RecordChange::ArtifactAdded),
        );
        let mut delete = vec![old];
        let mut insert = vec![];
        let mut origins = vec![];
        for c in &delta {
            let (record, previous, removed) = match c {
                RecordChange::ClaimAdded(c) => (ExportRecord::Claim(c.clone()), None, false),
                RecordChange::LifecycleAdded {
                    assertion,
                    transaction_time,
                } => (
                    ExportRecord::Lifecycle {
                        assertion: assertion.clone(),
                        transaction_time: *transaction_time,
                    },
                    None,
                    false,
                ),
                RecordChange::ArtifactAdded(a) => (ExportRecord::Artifact(a.clone()), None, false),
                RecordChange::Resource(ResourceChange::Add(r)) => {
                    (ExportRecord::Resource(r.clone()), None, false)
                }
                RecordChange::Resource(ResourceChange::ReplaceMutable { previous, record }) => (
                    ExportRecord::Resource(record.clone()),
                    Some(previous),
                    false,
                ),
                RecordChange::Resource(ResourceChange::RetractMutable { id, kind, previous }) => {
                    let r = existing
                        .get(&resource_key(id.as_str()))
                        .ok_or("retract missing record")?
                        .clone();
                    if !matches!(&r,ExportRecord::Resource(r) if r.kind()==*kind) {
                        return Err(cdb_core::Error::new(
                            cdb_core::ErrorKind::Conflict,
                            "retract kind conflict",
                        )
                        .into());
                    }
                    (r, Some(previous), true)
                }
            };
            let k = record.identity_key();
            if let Some(previous) = previous {
                let Some(ExportRecord::Resource(prior)) = existing.get(&k) else {
                    return Err(cdb_core::Error::new(
                        cdb_core::ErrorKind::Conflict,
                        "previous resource missing",
                    )
                    .into());
                };
                let ExportRecord::Resource(new) = &record else {
                    unreachable!()
                };
                if prior.kind() != new.kind()
                    || !prior.kind().mutable()
                    || ContentHash::of_bytes(
                        &prior
                            .projection()
                            .canonical_bytes(self.options.codec_limits)?,
                    ) != *previous
                {
                    return Err(cdb_core::Error::new(
                        cdb_core::ErrorKind::Conflict,
                        "resource previous hash/kind conflict",
                    )
                    .into());
                }
                delete.push(raw.get(&k).ok_or("missing previous image")?.clone());
            } else if existing.contains_key(&k) {
                return Err(cdb_core::Error::new(
                    cdb_core::ErrorKind::Conflict,
                    "immutable identity occupied",
                )
                .into());
            }
            let origin =
                RecordOrigin::new(&record, t as u64, time, removed, self.options.codec_limits)?
                    .resource(self.options.codec_limits)?;
            insert.push(encode(
                &ExportRecord::Resource(origin.clone()),
                self.options.codec_limits,
            )?);
            origins.push(RecordChange::Resource(ResourceChange::Add(origin)));
            if removed {
                existing.remove(&k);
            } else {
                insert.push(encode(&record, self.options.codec_limits)?);
                existing.insert(k, record);
            }
        }
        for l in batch.lifecycle() {
            if let Some(e) = l.event() {
                if !matches!(existing.get(&resource_key(e.as_str())),Some(ExportRecord::Resource(r)) if r.kind()==ResourceKind::LifecycleEvent)
                {
                    return Err("lifecycle event is not immutable event record".into());
                }
            }
        }
        delta.extend(origins);
        let claims: Vec<_> = batch
            .claims()
            .iter()
            .map(|c| c.id().clone())
            .chain(batch.lifecycle().iter().map(|l| l.id().clone()))
            .collect();
        let v = json!({"schema":"ctxql-authority/v1","t":t.to_string(),"predecessor_t":p.t.to_string(),"predecessor_cid":p.cid,"operation":"admit","time":time.canonical(),"key":key.as_str(),"payload":payload,"digest":batch.digest().as_str(),"claims":claims.iter().map(|id|id.as_str()).collect::<Vec<_>>(),"changes":changes(&delta,self.options.codec_limits)?});
        insert.push(control("journal", &t.to_string(), v.clone())?);
        insert.push(control("receipt", key.as_str(), v)?);
        insert.push(self.owner(t, Some(time), closed)?);
        let result = self.commit_locked(&p, delete, insert, guard).await?;
        Ok(AdmissionReceipt::new(
            key.clone(),
            batch.digest().clone(),
            self.snapshot(result)?,
            time,
            claims,
        )?)
    }
}
fn parse_time(s: &str) -> NativeResult<Option<Timestamp>> {
    if s.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Timestamp::parse(s)?))
    }
}
