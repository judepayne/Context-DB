//! Trusted local administration, not a credential or user JSON authentication API.
//! State is an ordinary journaled Policy record. Sinks must be bounded and non-reentrant.
use crate::{
    authority::FlureeBackend,
    journal::decode,
    native::{NativePin, NativeResult},
};
use cdb_core::{
    admission::*,
    claim::TypedLiteral,
    contracts::{IoFuture, PolicyService},
    id::*,
    policy::PolicySet,
    snapshot::SnapshotRef,
    storage_origin::INTERNAL_PREFIX,
    CanonicalValue as V, Error, ErrorKind, Result,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{atomic::Ordering, Arc, Weak},
};

#[cfg(test)]
#[path = "gate_c_refresh_probe.rs"]
mod gate_c_refresh_probe;

const STATE_PREDICATE: &str = "https://ctxql.org/internal/policy-state-v1";
fn state_id() -> String {
    format!("{INTERNAL_PREFIX}policy/state")
}
fn err(kind: ErrorKind, text: &str) -> Error {
    Error::new(kind, text)
}
fn backend(e: Box<dyn std::error::Error + Send + Sync>) -> Error {
    match e.downcast::<Error>() {
        Ok(e) => *e,
        Err(_) => err(ErrorKind::Backend, "policy authority read/write failed"),
    }
}
fn obj(fields: impl IntoIterator<Item = (String, V)>) -> V {
    V::Object(fields.into_iter().collect())
}
fn classes(v: &BTreeSet<Iri>) -> V {
    V::Array(v.iter().map(|i| V::string(i.as_str())).collect())
}
fn parse_classes(v: &V) -> Result<BTreeSet<Iri>> {
    v.as_array()?
        .iter()
        .map(|v| Iri::http(v.as_str()?))
        .collect()
}

/// Host-owned desired state. Replacing it is one atomic, idempotent admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyState {
    pub policy: PolicySet,
    pub principals: BTreeMap<PrincipalId, (bool, BTreeSet<Iri>)>,
    pub classes: BTreeMap<ResourceId, BTreeSet<Iri>>,
}
impl PolicyState {
    pub fn deny_all() -> Result<Self> {
        Ok(Self {
            policy: PolicySet::parse(
                br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[]}"#,
                Default::default(),
            )?,
            principals: BTreeMap::new(),
            classes: BTreeMap::new(),
        })
    }
    fn projection(&self) -> V {
        obj([
            ("schema".into(), V::string("ctxql-local-policy/v1")),
            ("policy".into(), self.policy.projection()),
            (
                "principals".into(),
                obj(self.principals.iter().map(|(id, (enabled, roles))| {
                    (
                        id.as_str().into(),
                        obj([
                            ("enabled".into(), V::Bool(*enabled)),
                            ("roles".into(), classes(roles)),
                        ]),
                    )
                })),
            ),
            (
                "classes".into(),
                obj(self
                    .classes
                    .iter()
                    .map(|(id, c)| (id.as_str().into(), classes(c)))),
            ),
        ])
    }
    fn parse(v: &V) -> Result<Self> {
        v.closed(&["schema", "policy", "principals", "classes"], &[])?;
        if v.field("schema")?.as_str()? != "ctxql-local-policy/v1" {
            return Err(Error::invalid("policy state schema"));
        }
        let mut principals = BTreeMap::new();
        for (id, p) in v.field("principals")?.as_object()? {
            p.closed(&["enabled", "roles"], &[])?;
            principals.insert(
                PrincipalId::new(id)?,
                (
                    p.field("enabled")?.as_bool()?,
                    parse_classes(p.field("roles")?)?,
                ),
            );
        }
        let mut resources = BTreeMap::new();
        for (id, c) in v.field("classes")?.as_object()? {
            resources.insert(ResourceId::new(id)?, parse_classes(c)?);
        }
        Ok(Self {
            policy: PolicySet::from_value(v.field("policy")?)?,
            principals,
            classes: resources,
        })
    }
    fn record(&self) -> Result<DependencyRecord> {
        // Round-trip validation also validates trusted host supplied class IRIs.
        let value = self.projection();
        Self::parse(&value)?;
        DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new(state_id())?,
            ResourceKind::Policy,
            vec![Fact::new(
                Iri::http(STATE_PREDICATE)?,
                FactTerm::Literal(TypedLiteral::new(
                    Iri::http("https://ctxql.org/internal/policy-state-json-v1")?,
                    V::string(
                        String::from_utf8(value.canonical_bytes(Default::default())?)
                            .map_err(|_| Error::invalid("policy UTF-8"))?,
                    ),
                    None,
                )?),
            )],
        )
    }
    fn from_record(r: &DependencyRecord) -> Result<Self> {
        if r.id().as_str() != state_id()
            || r.kind() != ResourceKind::Policy
            || r.facts().len() != 1
            || r.facts()[0].predicate().as_str() != STATE_PREDICATE
        {
            return Err(Error::invalid("policy record shape"));
        }
        let FactTerm::Literal(l) = r.facts()[0].term() else {
            return Err(Error::invalid("policy state literal"));
        };
        let state = Self::parse(&V::parse(
            l.value().as_str()?.as_bytes(),
            Default::default(),
        )?)?;
        if state.record()? != *r {
            return Err(Error::invalid("noncanonical policy state"));
        }
        Ok(state)
    }
}
/// Private issuer-bound handle; reopening requires trusted host reissuance.
#[derive(Clone)]
pub struct FlureePrincipal {
    issuer: Weak<()>,
    id: PrincipalId,
}
#[derive(Clone)]
pub struct FlureePolicyContext {
    issuer: Weak<()>,
    principal: PrincipalId,
    pin: SnapshotRef,
    epoch: i64,
    state: PolicyState,
    existing: BTreeSet<String>,
}
impl FlureePrincipal {
    pub fn id(&self) -> &PrincipalId {
        &self.id
    }
}
impl FlureePolicyContext {
    pub(crate) fn with_existing(mut self, id: &ResourceId) -> Self {
        self.existing.insert(id.as_str().into());
        self
    }
    pub(crate) fn roles(&self) -> &BTreeSet<Iri> {
        &self.state.principals[&self.principal].1
    }
}
impl FlureeBackend {
    async fn policy_record_at(&self, pin: &NativePin) -> NativeResult<Option<DependencyRecord>> {
        let Some(raw) = self
            .keyed(pin, "record", &resource_key(&state_id()))
            .await?
        else {
            return Ok(None);
        };
        match decode(&raw, self.options.codec_limits)? {
            ExportRecord::Resource(r) => {
                PolicyState::from_record(&r)?;
                Ok(Some(r))
            }
            _ => Err(Error::invalid("policy identity occupied").into()),
        }
    }
    async fn policy_at(&self, pin: &NativePin) -> NativeResult<PolicyState> {
        match self.policy_record_at(pin).await? {
            Some(r) => Ok(PolicyState::from_record(&r)?),
            None => Ok(PolicyState::deny_all()?),
        }
    }
    /// Trusted host inspection of current state, never historical projection state.
    pub async fn policy_state(&self) -> NativeResult<PolicyState> {
        let _gate = self.mutation_gate.lock().await;
        self.policy_at(&self.native.head().await?).await
    }
    /// Atomic whole-state replacement. The host supplies a stable operation key (not a credential).
    /// Concurrent administrators should serialize desired-state construction at the host layer.
    pub async fn set_policy_state(
        &self,
        key: &IdempotencyKey,
        state: &PolicyState,
    ) -> NativeResult<AdmissionReceipt> {
        let key = IdempotencyKey::new(format!("{INTERNAL_PREFIX}policy/admin/{}", key.as_str()))?;
        let record = state.record()?;
        let gate = Arc::new(self.mutation_gate.clone().lock_owned().await);
        if let Some(receipt) = self.receipt(&key).await? {
            let pin = NativePin {
                t: receipt.snapshot().pin().revision().as_str().parse()?,
                cid: receipt.snapshot().pin().receipt().as_str().into(),
            };
            return if self.policy_record_at(&pin).await?.as_ref() == Some(&record) {
                Ok(receipt)
            } else {
                Err(err(ErrorKind::Conflict, "policy idempotency payload conflict").into())
            };
        }
        let prior = self.policy_record_at(&self.native.head().await?).await?;
        let change = match prior {
            None => ResourceChange::Add(record),
            Some(r) => ResourceChange::ReplaceMutable {
                previous: ContentHash::of_bytes(
                    &r.projection().canonical_bytes(self.options.codec_limits)?,
                ),
                record,
            },
        };
        let batch = AdmissionBatch::new(
            vec![],
            vec![],
            vec![change],
            vec![],
            obj([]),
            self.options.codec_limits,
        )?;
        self.admit_policy_locked(&key, &batch, gate).await
    }
    pub async fn issue_principal(&self, id: PrincipalId) -> NativeResult<FlureePrincipal> {
        let _gate = self.mutation_gate.lock().await;
        let state = self.policy_at(&self.native.head().await?).await?;
        if !state.principals.get(&id).is_some_and(|p| p.0) {
            return Err(err(ErrorKind::Denied, "principal not enabled").into());
        }
        Ok(FlureePrincipal {
            issuer: Arc::downgrade(&self.policy_issuer),
            id,
        })
    }
    fn check_issuer(&self, issuer: &Weak<()>) -> Result<()> {
        if !issuer.ptr_eq(&Arc::downgrade(&self.policy_issuer)) {
            return Err(err(ErrorKind::Denied, "foreign policy issuer"));
        }
        Ok(())
    }
    pub(crate) async fn policy_context_locked(
        &self,
        p: &FlureePrincipal,
    ) -> Result<FlureePolicyContext> {
        self.check_issuer(&p.issuer)?;
        let pin = self.native.head().await.map_err(backend)?;
        let state = self.policy_at(&pin).await.map_err(backend)?;
        if !state.principals.get(&p.id).is_some_and(|p| p.0) {
            return Err(err(ErrorKind::Denied, "principal not enabled"));
        }
        // Bounded by NativeLimits; materialized once, never a historical permission source.
        let mut existing = BTreeSet::new();
        let mut offset = 0usize;
        let mut bytes = 0usize;
        loop {
            let page = Box::pin(self.native.read_record_page(&pin, None, offset))
                .await
                .map_err(backend)?;
            let done = page.len() < 128;
            offset = offset.checked_add(page.len()).ok_or_else(Error::limit)?;
            bytes = bytes
                .checked_add(crate::native::image_result_bytes(page.iter()).map_err(backend)?)
                .ok_or_else(Error::limit)?;
            if offset > self.options.native_limits.max_records
                || bytes > self.options.native_limits.max_result_bytes
            {
                return Err(Error::limit());
            }
            for raw in page {
                if raw.kind != "record" {
                    continue;
                }
                let record = decode(&raw, self.options.codec_limits).map_err(backend)?;
                match record {
                    ExportRecord::Artifact(a) => {
                        existing.insert(a.reference().iri().as_str().to_owned());
                    }
                    ExportRecord::Resource(r) => {
                        existing.insert(r.id().as_str().to_owned());
                    }
                    ExportRecord::Claim(c) => {
                        existing.insert(c.id().as_str().to_owned());
                    }
                    ExportRecord::Lifecycle { assertion, .. } => {
                        existing.insert(assertion.id().as_str().to_owned());
                    }
                }
            }
            if done {
                break;
            }
        }
        Ok(FlureePolicyContext {
            issuer: Arc::downgrade(&self.policy_issuer),
            principal: p.id.clone(),
            epoch: pin.t,
            pin: self.snapshot(pin).map_err(backend)?,
            state,
            existing,
        })
    }
    pub(crate) fn context_matches(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        fresh: &FlureePolicyContext,
    ) -> Result<()> {
        self.check_issuer(&p.issuer)?;
        self.check_policy_context(c)?;
        if p.id != c.principal || fresh.pin != c.pin {
            return Err(err(ErrorKind::PolicyChanged, "authority context changed"));
        }
        Ok(())
    }
    pub(crate) fn check_original_context_issuer(&self, c: &FlureePolicyContext) -> Result<()> {
        self.check_issuer(&c.issuer)
    }
    pub(crate) fn check_policy_context(&self, c: &FlureePolicyContext) -> Result<()> {
        self.check_issuer(&c.issuer)?;
        if c.epoch != self.policy_epoch.load(Ordering::Acquire) {
            return Err(err(ErrorKind::PolicyChanged, "authority epoch changed"));
        }
        Ok(())
    }
}
impl PolicyService for FlureeBackend {
    type Principal = FlureePrincipal;
    type Context = FlureePolicyContext;
    fn current<'a>(&'a self, p: &'a FlureePrincipal) -> IoFuture<'a, FlureePolicyContext> {
        Box::pin(async move {
            let _gate = self.mutation_gate.lock().await;
            self.policy_context_locked(p).await
        })
    }
    fn resource_allowed(&self, c: &FlureePolicyContext, r: &ResourceId) -> Result<bool> {
        self.fact_allowed(c, r, &Iri::http("https://ns.flur.ee/db#view")?)
    }
    fn fact_allowed(
        &self,
        c: &FlureePolicyContext,
        r: &ResourceId,
        property: &Iri,
    ) -> Result<bool> {
        self.check_policy_context(c)?;
        original_fact_allowed(c, r, property)
    }
    fn publish<'a>(
        &'a self,
        p: &'a FlureePrincipal,
        c: &'a FlureePolicyContext,
        sink: &'a mut (dyn FnMut() -> Result<()> + Send),
    ) -> IoFuture<'a, ()> {
        Box::pin(async move {
            let _gate = self.mutation_gate.lock().await;
            self.check_issuer(&p.issuer)?;
            self.check_policy_context(c)?;
            if p.id != c.principal {
                return Err(err(ErrorKind::Denied, "principal mismatch"));
            }
            let pin = self.native.head().await.map_err(backend)?;
            if self.snapshot(pin.clone()).map_err(backend)? != c.pin {
                return Err(err(ErrorKind::PolicyChanged, "authority head changed"));
            }
            let current = self.policy_at(&pin).await.map_err(backend)?;
            if !current.principals.get(&p.id).is_some_and(|p| p.0) {
                return Err(err(ErrorKind::Denied, "principal revoked"));
            }
            if current != c.state {
                return Err(err(ErrorKind::PolicyChanged, "policy state changed"));
            }
            sink()
        })
    }
}

pub(crate) fn original_fact_allowed(
    c: &FlureePolicyContext,
    r: &ResourceId,
    property: &Iri,
) -> Result<bool> {
    let Some((enabled, roles)) = c.state.principals.get(&c.principal) else {
        return Ok(false);
    };
    let empty = BTreeSet::new();
    Ok(c.state.policy.allows_resource(
        *enabled,
        roles,
        r.as_str(),
        property,
        c.existing
            .contains(r.as_str())
            .then(|| c.state.classes.get(r).unwrap_or(&empty)),
    ))
}
