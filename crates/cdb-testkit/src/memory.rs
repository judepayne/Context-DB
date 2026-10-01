//! Bounded trusted fixture authority. All authority writes and guarded publication use one gate.
use cdb_core::{
    admission::*, artifact::*, claim::*, contracts::*, id::*, policy::PolicySet, replay::*,
    snapshot::*, CanonicalValue, Error, ErrorKind, Limits, Result, Timestamp,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex, MutexGuard, Weak},
    task::{Poll, Waker},
};

#[derive(Clone, Copy, Debug)]
pub struct MemoryOptions {
    pub records: usize,
    pub history: usize,
    pub bytes: usize,
    pub hints: usize,
}
impl Default for MemoryOptions {
    fn default() -> Self {
        Self {
            records: 1000,
            history: 1000,
            bytes: 16 * 1024 * 1024,
            hints: 32,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryFault {
    BeforePublication,
    LostAcknowledgement,
}
#[derive(Clone)]
pub struct MemoryBackend {
    gate: Arc<Mutex<State>>,
}
#[derive(Clone)]
struct Image {
    pin: SnapshotRef,
    records: BTreeMap<String, ExportRecord>,
}
struct State {
    options: MemoryOptions,
    auxiliary_bytes: usize,
    wall: Timestamp,
    last: Option<Timestamp>,
    closed: Option<Timestamp>,
    images: Vec<Arc<Image>>,
    changes: Vec<ChangeBatch>,
    receipts: BTreeMap<IdempotencyKey, AdmissionReceipt>,
    principals: BTreeMap<PrincipalId, (bool, BTreeSet<Iri>)>,
    classes: BTreeMap<ResourceId, BTreeSet<Iri>>,
    policy: PolicySet,
    runs: BTreeMap<RunId, ExecutionRun>,
    assemblies: BTreeMap<String, AssemblyInvocation>,
    hints: VecDeque<(usize, SnapshotRef)>,
    hint_seq: usize,
    hints_closed: bool,
    waiters: Vec<Waker>,
    fault: Option<MemoryFault>,
}
/// Only trusted fixture administration can issue this handle; it is not a wire credential.
#[derive(Clone)]
pub struct MemoryPrincipal {
    issuer: Weak<Mutex<State>>,
    id: PrincipalId,
}
pub struct MemoryContext {
    issuer: Weak<Mutex<State>>,
    principal: PrincipalId,
    pin: SnapshotRef,
}
fn err(kind: ErrorKind, msg: &str) -> Error {
    Error::new(kind, msg)
}
impl MemoryBackend {
    pub fn new(
        backend: BackendId,
        authority: AuthorityId,
        graph: GraphId,
        wall: Timestamp,
        options: MemoryOptions,
    ) -> Result<Self> {
        if [
            options.records,
            options.history,
            options.bytes,
            options.hints,
        ]
        .contains(&0)
        {
            return Err(Error::limit());
        }
        let pin = SnapshotRef::new(
            backend,
            GraphPin::new(
                authority,
                graph,
                VersionId::new("0")?,
                ResourceId::new("genesis")?,
            ),
        );
        let policy = PolicySet::parse(
            br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[]}"#,
            Limits::default(),
        )?;
        Ok(Self {
            gate: Arc::new(Mutex::new(State {
                options,
                wall,
                last: None,
                closed: None,
                images: vec![Arc::new(Image {
                    pin,
                    records: BTreeMap::new(),
                })],
                changes: vec![],
                receipts: BTreeMap::new(),
                principals: BTreeMap::new(),
                classes: BTreeMap::new(),
                policy,
                runs: BTreeMap::new(),
                assemblies: BTreeMap::new(),
                hints: VecDeque::new(),
                hint_seq: 0,
                hints_closed: false,
                waiters: vec![],
                fault: None,
                auxiliary_bytes: 0,
            })),
        })
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.gate
            .lock()
            .map_err(|_| err(ErrorKind::Backend, "authority gate poisoned"))
    }
    /// Read-only trusted test instrumentation for deterministic release/mutation tests.
    pub fn publication_gate_busy(&self) -> Result<bool> {
        match self.gate.try_lock() {
            Ok(_) => Ok(false),
            Err(std::sync::TryLockError::WouldBlock) => Ok(true),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                Err(err(ErrorKind::Backend, "authority gate poisoned"))
            }
        }
    }
    /// Script the next wall observation (including rollback); does not change logical time.
    pub fn set_wall(&self, wall: Timestamp) -> Result<()> {
        self.lock()?.wall = wall;
        Ok(())
    }
    pub fn inject_fault(&self, fault: MemoryFault) -> Result<()> {
        self.lock()?.fault = Some(fault);
        Ok(())
    }
    pub fn close_hints(&self) -> Result<()> {
        let mut s = self.lock()?;
        s.hints_closed = true;
        for w in s.waiters.drain(..) {
            w.wake();
        }
        Ok(())
    }
    pub fn provision(
        &self,
        id: PrincipalId,
        enabled: bool,
        classes: BTreeSet<Iri>,
    ) -> Result<MemoryPrincipal> {
        let mut s = self.lock()?;
        if !s.principals.contains_key(&id) && s.principals.len() >= s.options.records {
            return Err(Error::limit());
        }
        s.metadata(
            ResourceKind::Identity,
            "principal",
            id.as_str(),
            obj([
                ("enabled", CanonicalValue::Bool(enabled)),
                ("classes", class_value(&classes)),
            ]),
        )?;
        s.principals.insert(id.clone(), (enabled, classes));
        Ok(MemoryPrincipal {
            issuer: Arc::downgrade(&self.gate),
            id,
        })
    }
    pub fn set_policy(&self, policy: PolicySet) -> Result<()> {
        let mut s = self.lock()?;
        if policy.len() > s.options.records {
            return Err(Error::limit());
        }
        s.metadata(
            ResourceKind::Policy,
            "policy",
            "current",
            policy.projection(),
        )?;
        s.policy = policy;
        Ok(())
    }
    pub fn set_classes(&self, id: ResourceId, classes: BTreeSet<Iri>) -> Result<()> {
        let mut s = self.lock()?;
        if !s.classes.contains_key(&id) && s.classes.len() >= s.options.records {
            return Err(Error::limit());
        }
        s.metadata(
            ResourceKind::Identity,
            "classes",
            id.as_str(),
            class_value(&classes),
        )?;
        s.classes.insert(id, classes);
        Ok(())
    }
    fn check_principal(&self, p: &MemoryPrincipal) -> Result<()> {
        if !p.issuer.ptr_eq(&Arc::downgrade(&self.gate)) {
            return Err(err(ErrorKind::Denied, "foreign principal"));
        }
        Ok(())
    }
    fn check_context(&self, s: &State, c: &MemoryContext) -> Result<()> {
        if !c.issuer.ptr_eq(&Arc::downgrade(&self.gate)) || c.pin != s.image().pin {
            return Err(err(ErrorKind::PolicyChanged, "stale context"));
        }
        Ok(())
    }
}
impl State {
    fn image(&self) -> &Image {
        self.images.last().expect("genesis")
    }
    fn index(&self, p: &SnapshotRef) -> Result<usize> {
        self.images
            .iter()
            .position(|i| &i.pin == p)
            .ok_or_else(|| err(ErrorKind::Snapshot, "unknown exact pin"))
    }
    fn allocation(&self) -> Result<Timestamp> {
        let mut t = self.wall;
        for prev in [self.last, self.closed].into_iter().flatten() {
            t = t.max(prev.checked_add_millis(1)?);
        }
        Ok(t)
    }
    fn commit(
        &mut self,
        records: BTreeMap<String, ExportRecord>,
        changes: Vec<RecordChange>,
        last: Option<Timestamp>,
        closed: Option<Timestamp>,
    ) -> Result<SnapshotRef> {
        if self.images.len() >= self.options.history
            || records
                .len()
                .checked_add(self.receipts.len())
                .and_then(|n| n.checked_add(self.runs.len()))
                .and_then(|n| n.checked_add(self.assemblies.len()))
                .ok_or_else(Error::limit)?
                >= self.options.records
        {
            return Err(Error::limit());
        }
        let bytes = records.values().try_fold(0usize, |n, r| {
            n.checked_add(record_bytes(r)?).ok_or_else(Error::limit)
        })?;
        let historical = self.images.iter().try_fold(0usize, |n, i| {
            i.records.values().try_fold(n, |n, r| {
                n.checked_add(record_bytes(r)?).ok_or_else(Error::limit)
            })
        })?;
        if bytes
            .checked_add(historical)
            .and_then(|n| n.checked_add(self.auxiliary_bytes))
            .ok_or_else(Error::limit)?
            > self.options.bytes
        {
            return Err(Error::limit());
        }
        let prev = self.image().pin.clone();
        let material = obj([
            ("schema", CanonicalValue::string("ctxql-memory-commit/v1")),
            ("backend", CanonicalValue::string(prev.backend().as_str())),
            ("predecessor", prev.projection()),
            (
                "ordinal",
                CanonicalValue::string(self.images.len().to_string()),
            ),
            (
                "changes",
                CanonicalValue::Array(changes.iter().map(RecordChange::projection).collect()),
            ),
            (
                "last_admission",
                last.map(|t| CanonicalValue::string(t.canonical()))
                    .unwrap_or(CanonicalValue::Null),
            ),
            (
                "closed_through",
                closed
                    .map(|t| CanonicalValue::string(t.canonical()))
                    .unwrap_or(CanonicalValue::Null),
            ),
        ])
        .canonical_bytes(Limits::default())?;
        let pin = SnapshotRef::new(
            prev.backend().clone(),
            GraphPin::new(
                prev.pin().authority().clone(),
                prev.pin().graph().clone(),
                VersionId::new(self.images.len().to_string())?,
                ResourceId::new(ContentHash::of_bytes(&material).as_str())?,
            ),
        );
        let change = ChangeBatch::new(
            "ctxql-change/v1",
            prev,
            pin.clone(),
            changes,
            Limits::default(),
        )?;
        // Logical retained encoding charge, not allocator/RSS measurement. Charge record
        // encodings twice (authority plus caches), every pin/batch/hint and receipt,
        // and fixed framing per retained object. Checked arithmetic throughout.
        let mut charge = bytes
            .checked_add(historical)
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(Error::limit)?;
        let mut add = |n: usize| -> Result<()> {
            charge = charge
                .checked_add(n)
                .and_then(|v| v.checked_add(256))
                .ok_or_else(Error::limit)?;
            Ok(())
        };
        for image in &self.images {
            for key in image.records.keys() {
                add(key.len().checked_mul(6).ok_or_else(Error::limit)?)?;
            }
            add(image
                .pin
                .projection()
                .canonical_bytes(Limits::default())?
                .len())?;
        }
        add(pin.projection().canonical_bytes(Limits::default())?.len())?;
        for key in records.keys() {
            add(key.len().checked_mul(6).ok_or_else(Error::limit)?)?;
        }
        for batch in self.changes.iter().chain(std::iter::once(&change)) {
            add(batch
                .predecessor()
                .projection()
                .canonical_bytes(Limits::default())?
                .len())?;
            add(batch
                .result()
                .projection()
                .canonical_bytes(Limits::default())?
                .len())?;
            for c in batch.changes() {
                add(c.projection().canonical_bytes(Limits::default())?.len())?;
            }
        }
        for (_, hint) in &self.hints {
            add(hint.projection().canonical_bytes(Limits::default())?.len())?;
        }
        add(pin.projection().canonical_bytes(Limits::default())?.len())?;
        for receipt in self.receipts.values() {
            add(receipt
                .snapshot()
                .projection()
                .canonical_bytes(Limits::default())?
                .len())?;
            add(receipt
                .key()
                .as_str()
                .len()
                .checked_mul(6)
                .ok_or_else(Error::limit)?)?;
            for id in receipt.claim_ids() {
                add(id.as_str().len().checked_mul(6).ok_or_else(Error::limit)?)?;
            }
        }
        add(self.auxiliary_bytes)?;
        if charge > self.options.bytes {
            return Err(Error::limit());
        }
        let next_hint = self.hint_seq.checked_add(1).ok_or_else(Error::limit)?;
        if self.fault == Some(MemoryFault::BeforePublication) {
            self.fault = None;
            return Err(err(ErrorKind::Backend, "injected prepublication fault"));
        }
        self.images.push(Arc::new(Image {
            pin: pin.clone(),
            records,
        }));
        self.changes.push(change);
        self.last = last;
        self.closed = closed;
        self.hint_seq = next_hint;
        self.hints.push_back((self.hint_seq, pin.clone()));
        if self.hints.len() > self.options.hints {
            self.hints.pop_front();
        }
        for w in self.waiters.drain(..) {
            w.wake();
        }
        Ok(pin)
    }
    fn metadata(
        &mut self,
        kind: ResourceKind,
        category: &str,
        id: &str,
        value: CanonicalValue,
    ) -> Result<()> {
        let value = obj([
            ("category", CanonicalValue::string(category)),
            ("id", CanonicalValue::string(id)),
            ("value", value),
        ]);
        let bytes = value.canonical_bytes(Limits::default())?;
        let record = DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new(format!(
                "{INTERNAL}{}:{}",
                self.images.len(),
                ContentHash::of_bytes(&bytes).as_str()
            ))?,
            kind,
            vec![Fact::new(
                Iri::new("urn:ctxql:testkit:value")?,
                FactTerm::Literal(TypedLiteral::new(
                    Iri::new("http://www.w3.org/2001/XMLSchema#string")?,
                    CanonicalValue::string(
                        String::from_utf8(bytes).map_err(|_| Error::invalid("utf8"))?,
                    ),
                    None,
                )?),
            )],
        )?;
        let mut records = self.image().records.clone();
        records.insert(
            resource_key(record.id().as_str()),
            ExportRecord::Resource(record.clone()),
        );
        self.commit(
            records,
            vec![RecordChange::Resource(ResourceChange::Add(record))],
            self.last,
            self.closed,
        )?;
        Ok(())
    }
}
const INTERNAL: &str = "urn:ctxql:testkit:internal:";
fn class_value(classes: &BTreeSet<Iri>) -> CanonicalValue {
    CanonicalValue::Array(
        classes
            .iter()
            .map(|v| CanonicalValue::string(v.as_str()))
            .collect(),
    )
}
fn obj<const N: usize>(fields: [(&str, CanonicalValue); N]) -> CanonicalValue {
    CanonicalValue::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn run_value(r: &ExecutionRun) -> CanonicalValue {
    use CanonicalValue as V;
    let dependencies = r
        .footprint()
        .used()
        .iter()
        .map(|d| {
            let (kind, value) = match d {
                ReadDependency::Claim(id) => ("claim", V::string(id.as_str())),
                ReadDependency::Lifecycle(id) => ("lifecycle", V::string(id.as_str())),
                ReadDependency::Resource(id) => ("resource", V::string(id.as_str())),
                ReadDependency::Fact {
                    resource,
                    predicate,
                } => (
                    "fact",
                    obj([
                        ("resource", V::string(resource.as_str())),
                        ("predicate", V::string(predicate.as_str())),
                    ]),
                ),
                ReadDependency::NegativeLookup { descriptor } => {
                    ("negative", V::string(descriptor.as_str()))
                }
                ReadDependency::Artifact(a) => ("artifact", a.projection()),
                ReadDependency::SourceSelector {
                    descriptor,
                    source,
                    version,
                } => (
                    "selector",
                    obj([
                        ("descriptor", V::string(descriptor.as_str())),
                        ("source", V::string(source.as_str())),
                        ("version", V::string(version.as_str())),
                    ]),
                ),
                ReadDependency::OrderingDescriptor(id) => ("ordering", V::string(id.as_str())),
            };
            obj([("kind", V::string(kind)), ("value", value)])
        })
        .collect();
    obj([
        ("id", V::string(r.id().as_str())),
        ("query", r.query().projection()),
        (
            "profile",
            r.profile().map_or(V::Null, ArtifactRef::projection),
        ),
        ("config", r.config().projection()),
        ("engine", r.engine().projection()),
        ("plan_hash", V::string(r.plan_hash().as_str())),
        ("response_hash", V::string(r.response_hash().as_str())),
        ("snapshot", r.snapshot().projection()),
        ("as_of", V::string(r.as_of().canonical())),
        (
            "landings",
            V::Array(
                r.landings()
                    .iter()
                    .map(RecordedLanding::projection)
                    .collect(),
            ),
        ),
        (
            "functions",
            V::Array(
                r.functions()
                    .iter()
                    .map(|f| {
                        obj([
                            ("name", V::string(f.manifest().name().as_str())),
                            ("version", V::string(f.manifest().version().as_str())),
                            ("hash", V::string(f.manifest().hash().as_str())),
                            ("content", f.manifest().content().clone()),
                            (
                                "inputs",
                                V::Array(
                                    f.input_hashes()
                                        .iter()
                                        .map(|h| V::string(h.as_str()))
                                        .collect(),
                                ),
                            ),
                            (
                                "outputs",
                                V::Array(
                                    f.output_hashes()
                                        .iter()
                                        .map(|h| V::string(h.as_str()))
                                        .collect(),
                                ),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("footprint", V::Array(dependencies)),
        (
            "requested_selectors",
            V::Array(
                r.footprint()
                    .requested_selectors()
                    .iter()
                    .map(|id| V::string(id.as_str()))
                    .collect(),
            ),
        ),
    ])
}
fn record_bytes(r: &ExportRecord) -> Result<usize> {
    Ok(match r {
        ExportRecord::Claim(c) => RecordChange::ClaimAdded(c.clone())
            .projection()
            .canonical_bytes(Limits::default())?
            .len(),
        ExportRecord::Lifecycle { assertion, .. } => assertion
            .projection()
            .canonical_bytes(Limits::default())?
            .len()
            .checked_add(32)
            .ok_or_else(Error::limit)?,
        ExportRecord::Resource(r) => r.projection().canonical_bytes(Limits::default())?.len(),
        ExportRecord::Artifact(a) => a
            .content()
            .len()
            .checked_add(
                a.reference()
                    .projection()
                    .canonical_bytes(Limits::default())?
                    .len(),
            )
            .ok_or_else(Error::limit)?,
    })
}
fn artifact_lookup(
    records: &BTreeMap<String, ExportRecord>,
    r: &ArtifactRef,
) -> Result<Option<PublishedArtifact>> {
    match records.get(&artifact_key(r)) {
        None => Ok(None),
        Some(ExportRecord::Artifact(a)) if a.reference() == r => Ok(Some(a.clone())),
        Some(_) => Err(err(
            ErrorKind::Conflict,
            "artifact identity/version/hash mismatch",
        )),
    }
}
fn page<T: Clone>(
    items: &[T],
    pin: &SnapshotRef,
    stream: ResourceId,
    cursor: Option<&PageCursor>,
    size: PageSize,
) -> Result<Page<T>> {
    let start = match cursor {
        None => 0,
        Some(c) => {
            if c.snapshot() != pin || c.stream() != &stream {
                return Err(Error::invalid("cursor binding"));
            }
            let n = c
                .position()
                .as_str()
                .parse::<usize>()
                .map_err(|_| Error::invalid("cursor position"))?;
            if n == 0 || n >= items.len() || n.to_string() != c.position().as_str() {
                return Err(Error::invalid("cursor range"));
            }
            n
        }
    };
    let end = start.saturating_add(size.get()).min(items.len());
    let next = if end < items.len() {
        Some(PageCursor::new(
            pin.clone(),
            stream,
            VersionId::new(end.to_string())?,
        ))
    } else {
        None
    };
    Page::new(items[start..end].to_vec(), pin.clone(), next, size)
}
impl GraphBackend for MemoryBackend {
    fn capabilities(&self) -> Result<BackendCapabilities> {
        Ok(BackendCapabilities {
            exact_snapshots: true,
            ordered_changes: true,
            atomic_admission: true,
            closed_cutoff: true,
            complete_exports: true,
        })
    }
    fn head(&self) -> IoFuture<'_, SnapshotRef> {
        Box::pin(async move { Ok(self.lock()?.image().pin.clone()) })
    }
    fn admit<'a>(
        &'a self,
        key: &'a IdempotencyKey,
        batch: &'a AdmissionBatch,
    ) -> IoFuture<'a, AdmissionReceipt> {
        Box::pin(async move {
            let mut s = self.lock()?;
            if let Some(r) = s.receipts.get(key) {
                return if r.payload() == batch.digest() {
                    Ok(r.clone())
                } else {
                    Err(err(ErrorKind::Conflict, "idempotency payload conflict"))
                };
            }
            if batch
                .claims()
                .iter()
                .any(|r| r.id().as_str().starts_with(INTERNAL))
                || batch
                    .lifecycle()
                    .iter()
                    .any(|r| r.id().as_str().starts_with(INTERNAL))
                || batch
                    .resources()
                    .iter()
                    .any(|r| r.id().as_str().starts_with(INTERNAL))
            {
                return Err(Error::invalid("reserved testkit namespace"));
            }
            if batch.projection().canonical_bytes(Limits::default())?.len() > s.options.bytes {
                return Err(Error::limit());
            }
            let mut records = s.image().records.clone();
            let existing = records
                .values()
                .filter_map(|r| match r {
                    ExportRecord::Claim(c) => Some(c.id().clone()),
                    ExportRecord::Lifecycle { assertion, .. } => Some(assertion.id().clone()),
                    _ => None,
                })
                .collect();
            batch.validate_claim_references(&existing)?;
            let actual: BTreeSet<_> = records
                .values()
                .filter_map(|r| r.claim().map(|c| c.id().clone()))
                .chain(batch.claims().iter().map(|c| c.id().clone()))
                .chain(batch.lifecycle().iter().map(|l| l.id().clone()))
                .collect();
            for l in batch.lifecycle() {
                if std::iter::once(l.target())
                    .chain(l.referenced_claim())
                    .any(|id| !actual.contains(id))
                {
                    return Err(Error::invalid("lifecycle target is not a claim"));
                }
            }
            let t = s.allocation()?;
            let mut changes = vec![];
            for c in batch.claims() {
                let c = Box::new(AdmittedClaim::assign(c.clone(), t));
                insert_new(
                    &mut records,
                    c.id().as_str(),
                    ExportRecord::Claim(c.clone()),
                )?;
                changes.push(RecordChange::ClaimAdded(c));
            }
            for l in batch.lifecycle() {
                insert_new(
                    &mut records,
                    l.id().as_str(),
                    ExportRecord::Lifecycle {
                        assertion: l.clone(),
                        transaction_time: t,
                    },
                )?;
                changes.push(RecordChange::LifecycleAdded {
                    assertion: l.clone(),
                    transaction_time: t,
                });
            }
            for r in batch.resources() {
                match r {
                    ResourceChange::Add(r) => insert_new(
                        &mut records,
                        r.id().as_str(),
                        ExportRecord::Resource(r.clone()),
                    )?,
                    ResourceChange::ReplaceMutable { previous, record } => {
                        check_previous(&records, record.id(), record.kind(), previous)?;
                        records.insert(
                            resource_key(record.id().as_str()),
                            ExportRecord::Resource(record.clone()),
                        );
                    }
                    ResourceChange::RetractMutable { id, kind, previous } => {
                        check_previous(&records, id, *kind, previous)?;
                        records.remove(&resource_key(id.as_str()));
                    }
                }
                changes.push(RecordChange::Resource(r.clone()));
            }
            for l in batch.lifecycle() {
                if let Some(event) = l.event() {
                    if !matches!(records.get(&resource_key(event.as_str())),
                        Some(ExportRecord::Resource(r)) if r.kind() == ResourceKind::LifecycleEvent)
                    {
                        return Err(Error::invalid(
                            "lifecycle event is not an immutable event record",
                        ));
                    }
                }
            }
            for a in batch.artifacts() {
                insert_new(
                    &mut records,
                    a.reference().iri().as_str(),
                    ExportRecord::Artifact(a.clone()),
                )?;
                changes.push(RecordChange::ArtifactAdded(a.clone()));
            }
            // Retain origin and retry identity in the authoritative image, not only
            // a digest side cache. The snapshot ref is derived after this commit to
            // avoid putting a self-referential content hash inside its own payload.
            let receipt_value = obj([
                ("key", CanonicalValue::string(key.as_str())),
                ("payload", batch.projection()),
                ("transaction_time", CanonicalValue::string(t.canonical())),
            ]);
            let receipt_record = DependencyRecord::new(
                "ctxql-resource/v1",
                ResourceId::new(format!(
                    "{INTERNAL}admission:{}",
                    ContentHash::of_bytes(key.as_str().as_bytes()).as_str()
                ))?,
                ResourceKind::SourceDescriptor,
                vec![Fact::new(
                    Iri::new("urn:ctxql:testkit:admission")?,
                    FactTerm::Literal(TypedLiteral::new(
                        Iri::new("http://www.w3.org/2001/XMLSchema#string")?,
                        CanonicalValue::string(
                            String::from_utf8(receipt_value.canonical_bytes(Limits::default())?)
                                .map_err(|_| Error::invalid("UTF-8"))?,
                        ),
                        None,
                    )?),
                )],
            )?;
            insert_new(
                &mut records,
                receipt_record.id().as_str(),
                ExportRecord::Resource(receipt_record.clone()),
            )?;
            changes.push(RecordChange::Resource(ResourceChange::Add(receipt_record)));
            let closed = s.closed;
            let old_charge = s.auxiliary_bytes;
            let receipt_charge = batch
                .claims()
                .iter()
                .map(|c| c.id().as_str().len())
                .chain(batch.lifecycle().iter().map(|l| l.id().as_str().len()))
                .try_fold(
                    key.as_str()
                        .len()
                        .checked_mul(6)
                        .and_then(|n| n.checked_add(2048))
                        .and_then(|n| {
                            n.checked_add(
                                s.image()
                                    .pin
                                    .projection()
                                    .canonical_bytes(Limits::default())
                                    .ok()?
                                    .len(),
                            )
                        })
                        .ok_or_else(Error::limit)?,
                    |n, len| {
                        n.checked_add(
                            len.checked_mul(6)
                                .and_then(|n| n.checked_add(256))
                                .ok_or_else(Error::limit)?,
                        )
                        .ok_or_else(Error::limit)
                    },
                )?;
            s.auxiliary_bytes = old_charge
                .checked_add(receipt_charge)
                .ok_or_else(Error::limit)?;
            let result = s.commit(records, changes, Some(t), closed);
            s.auxiliary_bytes = old_charge;
            let pin = result?;
            let receipt = AdmissionReceipt::new(
                key.clone(),
                batch.digest().clone(),
                pin,
                t,
                batch
                    .claims()
                    .iter()
                    .map(|c| c.id().clone())
                    .chain(batch.lifecycle().iter().map(|l| l.id().clone()))
                    .collect(),
            )?;
            s.receipts.insert(key.clone(), receipt.clone());
            if s.fault == Some(MemoryFault::LostAcknowledgement) {
                s.fault = None;
                return Err(err(ErrorKind::Backend, "lost acknowledgement"));
            }
            Ok(receipt)
        })
    }
    fn receipt<'a>(&'a self, key: &'a IdempotencyKey) -> IoFuture<'a, Option<AdmissionReceipt>> {
        Box::pin(async move { Ok(self.lock()?.receipts.get(key).cloned()) })
    }
    fn capture(&self, requested: Option<Timestamp>) -> IoFuture<'_, CapturedSnapshot> {
        Box::pin(async move {
            let mut s = self.lock()?;
            let now = s
                .wall
                .max(s.last.unwrap_or(s.wall))
                .max(s.closed.unwrap_or(s.wall));
            let t = requested.unwrap_or(now);
            if t > now {
                return Err(err(ErrorKind::Unsupported, "future cutoff"));
            }
            let closed = Some(s.closed.map_or(t, |c| c.max(t)));
            let records = s.image().records.clone();
            let last = s.last;
            let snapshot = s.commit(records, vec![], last, closed)?;
            Ok(CapturedSnapshot { as_of: t, snapshot })
        })
    }
    fn open_snapshot<'a>(&'a self, pin: &'a SnapshotRef) -> IoFuture<'a, Arc<dyn BackendSnapshot>> {
        Box::pin(async move {
            let s = self.lock()?;
            Ok(s.images[s.index(pin)?].clone() as Arc<dyn BackendSnapshot>)
        })
    }
    fn changes<'a>(
        &'a self,
        after: &'a SnapshotRef,
        through: &'a SnapshotRef,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ChangeBatch>> {
        Box::pin(async move {
            let s = self.lock()?;
            let a = s.index(after)?;
            let b = s.index(through)?;
            if a > b {
                return Err(Error::invalid("reversed range"));
            }
            page(
                &s.changes[a..b],
                through,
                ResourceId::new(format!("changes:{}:{}", a, b))?,
                cursor,
                size,
            )
        })
    }
    fn subscribe(&self) -> IoFuture<'_, Box<dyn ChangeHintSource>> {
        Box::pin(async move {
            let seq = self.lock()?.hint_seq;
            Ok(Box::new(Hints {
                gate: self.gate.clone(),
                seq,
            }) as Box<dyn ChangeHintSource>)
        })
    }
}
fn insert_new(
    records: &mut BTreeMap<String, ExportRecord>,
    _id: &str,
    record: ExportRecord,
) -> Result<()> {
    let id = record.identity_key();
    if records.contains_key(&id) {
        return Err(err(ErrorKind::Conflict, "immutable identity collision"));
    }
    records.insert(id, record);
    Ok(())
}
fn check_previous(
    records: &BTreeMap<String, ExportRecord>,
    id: &ResourceId,
    kind: ResourceKind,
    previous: &ContentHash,
) -> Result<()> {
    match records.get(&resource_key(id.as_str())) {
        Some(ExportRecord::Resource(r))
            if kind.mutable()
                && r.kind() == kind
                && ContentHash::of_bytes(&r.projection().canonical_bytes(Limits::default())?)
                    == *previous =>
        {
            Ok(())
        }
        _ => Err(err(ErrorKind::Conflict, "mutable previous mismatch")),
    }
}
impl BackendSnapshot for Image {
    fn identity(&self) -> &SnapshotRef {
        &self.pin
    }
    fn resource<'a>(&'a self, id: &'a ResourceId) -> IoFuture<'a, Option<DependencyRecord>> {
        Box::pin(async move {
            Ok(match self.records.get(&resource_key(id.as_str())) {
                Some(ExportRecord::Resource(r)) => Some(r.clone()),
                _ => None,
            })
        })
    }
    fn export<'a>(
        &'a self,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ExportRecord>> {
        Box::pin(async move {
            page(
                &self.records.values().cloned().collect::<Vec<_>>(),
                &self.pin,
                ResourceId::new("export")?,
                cursor,
                size,
            )
        })
    }
    fn artifact<'a>(&'a self, r: &'a ArtifactRef) -> IoFuture<'a, Option<PublishedArtifact>> {
        Box::pin(async move { artifact_lookup(&self.records, r) })
    }
}
struct Hints {
    gate: Arc<Mutex<State>>,
    seq: usize,
}
impl ChangeHintSource for Hints {
    fn next(&mut self) -> IoFuture<'_, ChangeHint> {
        Box::pin(std::future::poll_fn(move |cx| {
            let mut s = match self.gate.lock() {
                Ok(s) => s,
                Err(_) => return Poll::Ready(Err(err(ErrorKind::Backend, "hint gate poisoned"))),
            };
            if s.hints
                .front()
                .is_some_and(|(n, _)| self.seq.saturating_add(1) < *n)
            {
                self.seq = s.hint_seq;
                return Poll::Ready(Ok(ChangeHint::Lagged));
            }
            if let Some((n, p)) = s.hints.iter().find(|(n, _)| *n > self.seq) {
                self.seq = *n;
                return Poll::Ready(Ok(ChangeHint::Head(p.clone())));
            }
            if s.hints_closed {
                return Poll::Ready(Ok(ChangeHint::Closed));
            }
            if !s.waiters.iter().any(|w| w.will_wake(cx.waker())) {
                if s.waiters.len() >= s.options.records {
                    return Poll::Ready(Err(Error::limit()));
                }
                s.waiters.push(cx.waker().clone());
            }
            Poll::Pending
        }))
    }
}
impl PolicyService for MemoryBackend {
    type Principal = MemoryPrincipal;
    type Context = MemoryContext;
    fn current<'a>(&'a self, p: &'a MemoryPrincipal) -> IoFuture<'a, MemoryContext> {
        Box::pin(async move {
            self.check_principal(p)?;
            let s = self.lock()?;
            if !s.principals.get(&p.id).is_some_and(|(enabled, _)| *enabled) {
                return Err(err(ErrorKind::Denied, "disabled principal"));
            }
            Ok(MemoryContext {
                issuer: Arc::downgrade(&self.gate),
                principal: p.id.clone(),
                pin: s.image().pin.clone(),
            })
        })
    }
    fn resource_allowed(&self, c: &MemoryContext, r: &ResourceId) -> Result<bool> {
        self.fact_allowed(c, r, &Iri::new("https://ns.flur.ee/db#view")?)
    }
    fn fact_allowed(&self, c: &MemoryContext, r: &ResourceId, p: &Iri) -> Result<bool> {
        let s = self.lock()?;
        self.check_context(&s, c)?;
        let Some((enabled, classes)) = s.principals.get(&c.principal) else {
            return Ok(false);
        };
        let empty = BTreeSet::new();
        let exists = s.image().records.contains_key(&resource_key(r.as_str()))
            || s.image().records.values().any(|record| {
                matches!(record,
                ExportRecord::Artifact(a) if a.reference().iri().as_str() == r.as_str())
            });
        let current = exists.then(|| s.classes.get(r).unwrap_or(&empty));
        Ok(s.policy
            .allows_resource(*enabled, classes, r.as_str(), p, current))
    }
    fn publish<'a>(
        &'a self,
        p: &'a MemoryPrincipal,
        c: &'a MemoryContext,
        sink: &'a mut (dyn FnMut() -> Result<()> + Send),
    ) -> IoFuture<'a, ()> {
        Box::pin(async move {
            self.check_principal(p)?;
            let s = self.lock()?;
            self.check_context(&s, c)?;
            if p.id != c.principal || !s.principals.get(&p.id).is_some_and(|(e, _)| *e) {
                return Err(err(ErrorKind::Denied, "principal changed"));
            }
            sink()
        })
    }
}
impl ArtifactRepository for MemoryBackend {
    fn publish<'a>(&'a self, a: &'a PublishedArtifact) -> IoFuture<'a, ArtifactRef> {
        Box::pin(async move {
            let mut s = self.lock()?;
            if artifact_lookup(&s.image().records, a.reference())?.is_some() {
                return Ok(a.reference().clone());
            }
            let mut records = s.image().records.clone();
            insert_new(
                &mut records,
                a.reference().iri().as_str(),
                ExportRecord::Artifact(a.clone()),
            )?;
            let last = s.last;
            let closed = s.closed;
            s.commit(
                records,
                vec![RecordChange::ArtifactAdded(a.clone())],
                last,
                closed,
            )?;
            Ok(a.reference().clone())
        })
    }
    fn lookup<'a>(&'a self, r: &'a ArtifactRef) -> IoFuture<'a, Option<PublishedArtifact>> {
        Box::pin(async move { artifact_lookup(&self.lock()?.image().records, r) })
    }
    fn record_run<'a>(&'a self, r: &'a ExecutionRun) -> IoFuture<'a, ()> {
        Box::pin(async move {
            let mut s = self.lock()?;
            s.index(r.snapshot())?;
            if let Some(old) = s.runs.get(r.id()) {
                return if old == r {
                    Ok(())
                } else {
                    Err(err(ErrorKind::Conflict, "run collision"))
                };
            }
            let records = &s.images[s.index(r.snapshot())?].records;
            for a in std::iter::once(r.query())
                .chain(std::iter::once(r.config()))
                .chain(r.profile())
            {
                if artifact_lookup(records, a)?.is_none() {
                    return Err(err(ErrorKind::NotFound, "run artifact missing"));
                }
            }
            for d in r.footprint().used() {
                let valid = match d {
                    ReadDependency::Artifact(a) => artifact_lookup(records, a)?.is_some(),
                    ReadDependency::Claim(id) => matches!(
                        records.get(&resource_key(id.as_str())),
                        Some(ExportRecord::Claim(_) | ExportRecord::Lifecycle { .. })
                    ),
                    ReadDependency::Lifecycle(id) => matches!(
                        records.get(&resource_key(id.as_str())),
                        Some(ExportRecord::Lifecycle { .. })
                    ),
                    ReadDependency::Resource(id)
                    | ReadDependency::OrderingDescriptor(id)
                    | ReadDependency::NegativeLookup { descriptor: id }
                    | ReadDependency::SourceSelector { descriptor: id, .. } => matches!(
                        records.get(&resource_key(id.as_str())),
                        Some(ExportRecord::Resource(_))
                    ),
                    ReadDependency::Fact {
                        resource,
                        predicate,
                    } => {
                        matches!(records.get(&resource_key(resource.as_str())), Some(ExportRecord::Resource(r)) if r.facts().iter().any(|f| f.predicate() == predicate))
                    }
                };
                if !valid {
                    return Err(err(ErrorKind::NotFound, "run dependency missing"));
                }
            }
            for landing in r.landings() {
                let value = landing.projection();
                let id = value.field("id")?.as_str()?;
                let mut found = records.contains_key(&resource_key(id));
                for record in records.values() {
                    if let Some(claim) = record.claim() {
                        let response = claim.response(LifecycleState::Active);
                        let meta = response.field("meta")?;
                        found |= meta.field("subject_id")?.as_str()? == id
                            || meta
                                .field("object_id")?
                                .as_str()
                                .is_ok_and(|object| object == id);
                    }
                }
                if !found {
                    return Err(err(ErrorKind::NotFound, "landing entity missing"));
                }
            }
            s.metadata(
                ResourceKind::RunDescriptor,
                "run",
                r.id().as_str(),
                run_value(r),
            )?;
            s.runs.insert(r.id().clone(), r.clone());
            Ok(())
        })
    }
    fn run<'a>(&'a self, id: &'a RunId) -> IoFuture<'a, Option<ExecutionRun>> {
        Box::pin(async move { Ok(self.lock()?.runs.get(id).cloned()) })
    }
    fn record_assembly<'a>(&'a self, a: &'a AssemblyInvocation) -> IoFuture<'a, ()> {
        Box::pin(async move {
            let v = a.projection();
            let id = v.field("invocation_id")?.as_str()?;
            let mut s = self.lock()?;
            if let Some(old) = s.assemblies.get(id) {
                return if old == a {
                    Ok(())
                } else {
                    Err(err(ErrorKind::Conflict, "assembly collision"))
                };
            }
            let assembly = v.field("assembly")?;
            let reference = ArtifactRef::new(
                Iri::new(assembly.field("iri")?.as_str()?)?,
                VersionId::new(assembly.field("version")?.as_str()?)?,
                ContentHash::parse(assembly.field("hash")?.as_str()?)?,
            );
            if artifact_lookup(&s.image().records, &reference)?.is_none() {
                return Err(err(ErrorKind::NotFound, "assembly artifact missing"));
            }
            for input in v.field("inputs")?.as_array()? {
                if *input.field("run_id")? != CanonicalValue::Null {
                    let run = s
                        .runs
                        .get(&RunId::new(input.field("run_id")?.as_str()?)?)
                        .ok_or_else(|| err(ErrorKind::NotFound, "assembly run missing"))?;
                    if run.query().projection() != *input.field("query")?
                        || run
                            .profile()
                            .map_or(CanonicalValue::Null, ArtifactRef::projection)
                            != *input.field("profile")?
                        || run.as_of() != Timestamp::parse(input.field("as_of")?.as_str()?)?
                        || run.plan_hash().as_str() != input.field("plan_hash")?.as_str()?
                        || run.response_hash().as_str() != input.field("response_hash")?.as_str()?
                        || run.snapshot().pin() != &GraphPin::from_value(input.field("db_time")?)?
                    {
                        return Err(err(ErrorKind::Conflict, "assembly run mismatch"));
                    }
                }
            }
            s.metadata(ResourceKind::RunDescriptor, "assembly", id, v.clone())?;
            s.assemblies.insert(id.into(), a.clone());
            Ok(())
        })
    }
}
/// Reusable minimal adapter assertion; caller supplies a fresh backend and a valid unique batch/key.
pub async fn assert_admission_contract<B: GraphBackend>(
    backend: &B,
    key: &IdempotencyKey,
    batch: &AdmissionBatch,
) -> Result<()> {
    let before = backend.head().await?;
    let receipt = backend.admit(key, batch).await?;
    assert_ne!(&before, receipt.snapshot());
    let stable_head = backend.head().await?;
    assert_eq!(backend.admit(key, batch).await?, receipt);
    assert_eq!(backend.head().await?, stable_head);
    let changes = backend
        .changes(&before, receipt.snapshot(), None, PageSize::new(100)?)
        .await?;
    assert_eq!(changes.items().len(), 1);
    assert_eq!(changes.items()[0].predecessor(), &before);
    assert_eq!(changes.items()[0].result(), receipt.snapshot());
    assert_eq!(backend.receipt(key).await?, Some(receipt.clone()));
    assert_eq!(backend.open_snapshot(&before).await?.identity(), &before);
    assert_eq!(
        backend.open_snapshot(receipt.snapshot()).await?.identity(),
        receipt.snapshot()
    );
    Ok(())
}
