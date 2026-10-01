//! Trusted recording host boundary. Decoded envelopes are data, not engine seals.
use crate::execution_authorization::{exact_invocation_role, ExactInvocationRequirement};
use crate::{
    backend::map,
    journal::decode,
    policy::{FlureePolicyContext, FlureePrincipal},
    FlureeBackend,
};
use cdb_core::{
    admission::*,
    contracts::PolicyService,
    id::*,
    recording::{RunEnvelope, REQUIRED_SCOPES, RUN_PAYLOAD, RUN_SCHEMA as RUN_SCHEMA_V2},
    recording_v3::{RunEnvelopeV3, StoredV3, RUN_SCHEMA as RUN_SCHEMA_V3},
    recording_v4::{RunEnvelopeV4, StoredV4, RUN_SCHEMA as RUN_SCHEMA_V4},
    recording_v5::{RunEnvelopeV5, StoredV5, RUN_SCHEMA as RUN_SCHEMA_V5},
    snapshot::SnapshotRef,
    storage_origin::INTERNAL_PREFIX,
    CanonicalValue as V, Error, ErrorKind, Result,
};
use std::sync::Arc;

/// Implementations own the service session read lease and cancellation/deadline state.
/// Acquire that lease before entering this backend. No socket I/O in a sink.
pub trait ExternalPublicationFence: Send + Sync + 'static {
    fn check(&self) -> Result<()>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Query,
    Read,
    Replay,
    Publish,
    Admin,
}

/// A strictly decoded protected run from the shared v2/v3 durable namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtectedRun {
    V2(RunEnvelope),
    V3(RunEnvelopeV3),
    V4(RunEnvelopeV4),
    V5(RunEnvelopeV5),
}
impl Operation {
    pub fn role(self) -> &'static str {
        match self {
            Self::Query => "https://ctxql.org/roles/serviceQuery",
            Self::Read => "https://ctxql.org/roles/serviceRead",
            Self::Replay => "https://ctxql.org/roles/serviceReplay",
            Self::Publish => "https://ctxql.org/roles/servicePublish",
            Self::Admin => "https://ctxql.org/roles/serviceAdmin",
        }
    }
}
fn denied() -> Error {
    Error::new(ErrorKind::Denied, "access denied")
}
fn conflict() -> Error {
    Error::new(ErrorKind::Conflict, "run identity conflict")
}
pub(crate) fn run_key(id: &RunId) -> Result<IdempotencyKey> {
    IdempotencyKey::new(format!(
        "{INTERNAL_PREFIX}runs/{}",
        ContentHash::of_bytes(id.as_str().as_bytes()).as_str()
    ))
}
fn descriptor(id: &RunId) -> Result<ResourceId> {
    ResourceId::new(format!(
        "{INTERNAL_PREFIX}run/{}",
        ContentHash::of_bytes(id.as_str().as_bytes()).as_str()
    ))
}
pub(crate) fn batch(
    records: Vec<DependencyRecord>,
    limits: cdb_core::Limits,
) -> Result<AdmissionBatch> {
    AdmissionBatch::new(
        vec![],
        vec![],
        records.into_iter().map(ResourceChange::Add).collect(),
        vec![],
        V::object([])?,
        limits,
    )
}
pub(crate) fn valid_managed_batch(key: &IdempotencyKey, b: &AdmissionBatch) -> bool {
    let scopes = key.as_str() == format!("{INTERNAL_PREFIX}governance/scopes/v1") && b.resources().len() == 4
        && b.resources().iter().all(|c| matches!(c, ResourceChange::Add(r) if REQUIRED_SCOPES.contains(&r.id().as_str()) && r.kind() == ResourceKind::SourceDescriptor && r.facts().len() == 1));
    let run = key.as_str().starts_with(&format!("{INTERNAL_PREFIX}runs/"))
        && b.resources().len() == 1
        && matches!(&b.resources()[0], ResourceChange::Add(r) if r.kind() == ResourceKind::RunDescriptor && r.id().as_str().starts_with(&format!("{INTERNAL_PREFIX}run/")));
    scopes || run
}
impl FlureeBackend {
    /// Explicit idempotent migration; no roles or credentials are created.
    pub async fn bootstrap_governance(&self) -> Result<AdmissionReceipt> {
        let records = REQUIRED_SCOPES
            .iter()
            .map(|id| {
                DependencyRecord::new(
                    "ctxql-resource/v1",
                    ResourceId::new(*id)?,
                    ResourceKind::SourceDescriptor,
                    vec![Fact::new(
                        Iri::http("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")?,
                        FactTerm::Reference(ResourceId::new("https://ctxql.org/ReadScope")?),
                    )],
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let b = batch(records, self.options.codec_limits)?;
        let key = IdempotencyKey::new(format!("{INTERNAL_PREFIX}governance/scopes/v1"))?;
        let gate = Arc::new(self.mutation_gate.clone().lock_owned().await);
        self.admit_locked(&key, &b, true, gate).await.map_err(map)
    }
    pub fn operation_allowed(&self, c: &FlureePolicyContext, operation: Operation) -> Result<bool> {
        self.check_policy_context(c)?;
        Ok(c.roles().contains(&Iri::http(operation.role())?)
            || c.roles().contains(&Iri::http(Operation::Admin.role())?))
    }
    pub fn require_operation(&self, c: &FlureePolicyContext, operation: Operation) -> Result<()> {
        if self.operation_allowed(c, operation)? {
            Ok(())
        } else {
            Err(denied())
        }
    }
    pub(crate) fn authorize_envelope(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        run: &RunEnvelope,
        stored: bool,
    ) -> Result<()> {
        if run.owner() != p.id() && !self.operation_allowed(c, Operation::Admin)? {
            return Err(denied());
        }
        if stored
            && (!self.resource_allowed(c, &run.descriptor_id()?)?
                || !self.fact_allowed(
                    c,
                    &run.descriptor_id()?,
                    &Iri::http(cdb_core::recording::RUN_PAYLOAD)?,
                )?)
        {
            return Err(denied());
        }
        for scope in &run.replay().data().scopes {
            if !self.resource_allowed(c, scope)? {
                return Err(denied());
            }
        }
        // Negative observations are the original private exclusion mask, not required grants.
        for observation in &run.replay().data().policy {
            if observation.allowed
                && !match &observation.predicate {
                    Some(predicate) => self.fact_allowed(c, &observation.resource, predicate)?,
                    None => self.resource_allowed(c, &observation.resource)?,
                }
            {
                return Err(denied());
            }
        }
        Ok(())
    }
    pub(crate) async fn envelope_locked(&self, id: &RunId) -> Result<Option<RunEnvelope>> {
        let pin = self.native.head().await.map_err(map)?;
        let Some(raw) = self
            .keyed(&pin, "record", &resource_key(descriptor(id)?.as_str()))
            .await
            .map_err(map)?
        else {
            return Ok(None);
        };
        Ok(Some(RunEnvelope::from_record(
            &decode(&raw, self.options.codec_limits).map_err(map)?,
            self.options.codec_limits,
        )?))
    }
    pub(crate) async fn envelope_v3_locked(&self, id: &RunId) -> Result<Option<RunEnvelopeV3>> {
        let pin = self.native.head().await.map_err(map)?;
        let Some(raw) = self
            .keyed(&pin, "record", &resource_key(descriptor(id)?.as_str()))
            .await
            .map_err(map)?
        else {
            return Ok(None);
        };
        Ok(Some(
            StoredV3::from_record(
                &decode(&raw, self.options.codec_limits).map_err(map)?,
                self.options.codec_limits,
            )?
            .0,
        ))
    }

    pub(crate) async fn envelope_v4_locked(&self, id: &RunId) -> Result<Option<RunEnvelopeV4>> {
        let pin = self.native.head().await.map_err(map)?;
        let Some(raw) = self
            .keyed(&pin, "record", &resource_key(descriptor(id)?.as_str()))
            .await
            .map_err(map)?
        else {
            return Ok(None);
        };
        Ok(Some(
            StoredV4::from_record(
                &decode(&raw, self.options.codec_limits).map_err(map)?,
                self.options.codec_limits,
            )?
            .0,
        ))
    }

    pub(crate) async fn envelope_v5_locked(&self, id: &RunId) -> Result<Option<RunEnvelopeV5>> {
        let pin = self.native.head().await.map_err(map)?;
        let Some(raw) = self
            .keyed(&pin, "record", &resource_key(descriptor(id)?.as_str()))
            .await
            .map_err(map)?
        else {
            return Ok(None);
        };
        Ok(Some(
            StoredV5::from_record(
                &decode(&raw, self.options.codec_limits).map_err(map)?,
                self.options.codec_limits,
            )?
            .0,
        ))
    }

    fn decode_protected_run_record(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
        operation: Operation,
        record: &ExportRecord,
    ) -> Result<ProtectedRun> {
        let ExportRecord::Resource(resource) = record else {
            return Err(Error::invalid("run resource"));
        };
        if resource.id() != &descriptor(id)?
            || resource.kind() != ResourceKind::RunDescriptor
            || resource.facts().len() != 1
            || resource.facts()[0].predicate().as_str() != RUN_PAYLOAD
        {
            return Err(Error::invalid("run descriptor"));
        }
        let FactTerm::Literal(literal) = resource.facts()[0].term() else {
            return Err(Error::invalid("run literal"));
        };
        let literal = literal.projection();
        if literal.field("datatype")?.as_str()? != "http://www.w3.org/2001/XMLSchema#string"
            || *literal.field("language")? != V::Null
        {
            return Err(Error::invalid("run literal type"));
        }
        let payload_bytes = literal.field("value")?.as_str()?.as_bytes();
        let payload = V::parse(payload_bytes, self.options.codec_limits)?;
        let stored_owner = PrincipalId::new(payload.field("owner")?.as_str()?)?;
        if stored_owner != *p.id()
            && (operation == Operation::Query || !self.operation_allowed(c, Operation::Admin)?)
        {
            return Err(denied());
        }
        // This is the sole dispatcher inspection. Unknown/corrupt schemas are errors;
        // they are never retried through another version decoder or treated as absent.
        let schema = payload.field("schema")?.as_str()?;
        let run = match schema {
            RUN_SCHEMA_V2 => ProtectedRun::V2(RunEnvelope::from_value(
                &payload,
                self.options.codec_limits,
            )?),
            RUN_SCHEMA_V3 => ProtectedRun::V3(RunEnvelopeV3::from_value(
                &payload,
                self.options.codec_limits,
            )?),
            RUN_SCHEMA_V4 => ProtectedRun::V4(RunEnvelopeV4::from_value(
                &payload,
                self.options.codec_limits,
            )?),
            RUN_SCHEMA_V5 => ProtectedRun::V5(RunEnvelopeV5::from_value(
                &payload,
                self.options.codec_limits,
            )?),
            _ => return Err(Error::invalid("run schema")),
        };
        let (actual_descriptor, canonical) = match &run {
            ProtectedRun::V2(run) => (run.descriptor_id()?, run.bytes(self.options.codec_limits)?),
            ProtectedRun::V3(run) => (run.descriptor_id()?, run.bytes(self.options.codec_limits)?),
            ProtectedRun::V4(run) => (run.descriptor_id()?, run.bytes(self.options.codec_limits)?),
            ProtectedRun::V5(run) => (run.descriptor_id()?, run.bytes(self.options.codec_limits)?),
        };
        if actual_descriptor != *resource.id() || canonical != payload_bytes {
            return Err(Error::invalid("run descriptor identity/canonical payload"));
        }
        Ok(run)
    }
    pub(crate) fn authorize_envelope_v3(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        run: &RunEnvelopeV3,
        stored: bool,
    ) -> Result<()> {
        if run.owner() != p.id() && !self.operation_allowed(c, Operation::Admin)? {
            return Err(denied());
        }
        if stored
            && (!self.resource_allowed(c, &run.descriptor_id()?)?
                || !self.fact_allowed(
                    c,
                    &run.descriptor_id()?,
                    &Iri::http(cdb_core::recording::RUN_PAYLOAD)?,
                )?)
        {
            return Err(denied());
        }
        let requirements = run
            .replay()
            .original_authorization_requirements(self.options.codec_limits)?;
        let projection = requirements.projection();
        for fact in projection.field("facts")?.as_array()? {
            let resource = ResourceId::new(fact.field("resource")?.as_str()?)?;
            let predicate = Iri::new(fact.field("predicate")?.as_str()?)?;
            if !self.fact_allowed(c, &resource, &predicate)? {
                return Err(denied());
            }
        }
        // Authorize immutable stored bindings, never caller/current-route substitutes.
        for invocation in projection.field("invocations")?.as_array()? {
            let requirement = ExactInvocationRequirement::new(
                cdb_core::artifact::ArtifactRef::from_value(invocation.field("manifest")?)?,
                ResourceId::new(invocation.field("provider")?.as_str()?)?,
            );
            if !c.roles().contains(&exact_invocation_role(&requirement)?) {
                return Err(denied());
            }
        }
        Ok(())
    }

    pub(crate) fn authorize_envelope_v4(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        run: &RunEnvelopeV4,
        stored: bool,
    ) -> Result<()> {
        if run.owner() != p.id() && !self.operation_allowed(c, Operation::Admin)? {
            return Err(denied());
        }
        if stored
            && (!self.resource_allowed(c, &run.descriptor_id()?)?
                || !self.fact_allowed(
                    c,
                    &run.descriptor_id()?,
                    &Iri::http(cdb_core::recording::RUN_PAYLOAD)?,
                )?)
        {
            return Err(denied());
        }
        let requirements = run
            .replay()
            .base()
            .original_authorization_requirements(self.options.codec_limits)?;
        let projection = requirements.projection();
        for fact in projection.field("facts")?.as_array()? {
            let resource = ResourceId::new(fact.field("resource")?.as_str()?)?;
            let predicate = Iri::new(fact.field("predicate")?.as_str()?)?;
            if !self.fact_allowed(c, &resource, &predicate)? {
                return Err(denied());
            }
        }
        for invocation in projection.field("invocations")?.as_array()? {
            let requirement = ExactInvocationRequirement::new(
                cdb_core::artifact::ArtifactRef::from_value(invocation.field("manifest")?)?,
                ResourceId::new(invocation.field("provider")?.as_str()?)?,
            );
            if !c.roles().contains(&exact_invocation_role(&requirement)?) {
                return Err(denied());
            }
        }
        Ok(())
    }

    pub(crate) fn authorize_envelope_v5(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        run: &RunEnvelopeV5,
        stored: bool,
    ) -> Result<()> {
        // V5 preserves the V4 authorization evidence; only executor identity is new.
        let base = run.replay().v4();
        let historical = RunEnvelopeV4::new(
            run.id().clone(),
            run.owner().clone(),
            run.operation_hash().clone(),
            base.clone(),
            self.options.codec_limits,
        )?;
        self.authorize_envelope_v4(p, c, &historical, stored)
    }

    pub async fn guarded_v5_run_for(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
        operation: Operation,
    ) -> Result<RunEnvelopeV5> {
        match self
            .guarded_find_versioned_run(p, c, id, operation)
            .await?
            .ok_or_else(denied)?
        {
            ProtectedRun::V5(run) => Ok(run),
            _ => Err(Error::invalid("expected v5 run")),
        }
    }

    pub async fn guarded_v4_run_for(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
        operation: Operation,
    ) -> Result<RunEnvelopeV4> {
        match self
            .guarded_find_versioned_run(p, c, id, operation)
            .await?
            .ok_or_else(denied)?
        {
            ProtectedRun::V4(run) => Ok(run),
            ProtectedRun::V2(_) | ProtectedRun::V3(_) | ProtectedRun::V5(_) => {
                Err(Error::invalid("expected v4 run"))
            }
        }
    }

    pub async fn reopen_v4(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
    ) -> Result<RunEnvelopeV4> {
        self.guarded_v4_run_for(p, c, id, Operation::Replay).await
    }

    pub async fn retry_original_v4(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
        operation_hash: &ContentHash,
    ) -> Result<RunEnvelopeV4> {
        let run = self.guarded_v4_run_for(p, c, id, Operation::Query).await?;
        if run.owner() != p.id() || run.operation_hash() != operation_hash {
            return Err(conflict());
        }
        Ok(run)
    }

    /// V3-only protected read through the protected, single-dispatch decoder.
    pub async fn guarded_v3_run_for(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
        operation: Operation,
    ) -> Result<RunEnvelopeV3> {
        match self
            .guarded_find_versioned_run(p, c, id, operation)
            .await?
            .ok_or_else(denied)?
        {
            ProtectedRun::V3(run) => Ok(run),
            ProtectedRun::V2(_) | ProtectedRun::V4(_) | ProtectedRun::V5(_) => {
                Err(Error::invalid("expected v3 run"))
            }
        }
    }
    pub async fn reopen_v3(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
    ) -> Result<RunEnvelopeV3> {
        self.guarded_v3_run_for(p, c, id, Operation::Replay).await
    }
    /// Immutable successful-operation retry: exact owner/operation and stored bytes only.
    pub async fn retry_original_v3(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
        operation_hash: &ContentHash,
    ) -> Result<RunEnvelopeV3> {
        let run = self.guarded_v3_run_for(p, c, id, Operation::Query).await?;
        if run.owner() != p.id() || run.operation_hash() != operation_hash {
            return Err(conflict());
        }
        Ok(run)
    }
    pub async fn retry_original_v5_with_receipt(
        &self,
        p: &FlureePrincipal,
        id: &RunId,
        operation_hash: &ContentHash,
    ) -> Result<(RunEnvelopeV5, SnapshotRef)> {
        let _gate = self.mutation_gate.lock().await;
        let fresh = self.policy_context_locked(p).await?;
        self.require_operation(&fresh, Operation::Query)?;
        let run = self.envelope_v5_locked(id).await?.ok_or_else(denied)?;
        if run.owner() != p.id() || run.operation_hash() != operation_hash {
            return Err(conflict());
        }
        self.authorize_envelope_v5(p, &fresh, &run, true)?;
        let receipt = self
            .receipt(&run_key(id)?)
            .await
            .map_err(map)?
            .ok_or_else(|| Error::new(ErrorKind::Backend, "missing run receipt"))?;
        Ok((run, receipt.snapshot().clone()))
    }

    pub async fn retry_original_v4_with_receipt(
        &self,
        p: &FlureePrincipal,
        id: &RunId,
        operation_hash: &ContentHash,
    ) -> Result<(RunEnvelopeV4, SnapshotRef)> {
        let _gate = self.mutation_gate.lock().await;
        let fresh = self.policy_context_locked(p).await?;
        self.require_operation(&fresh, Operation::Query)?;
        let run = self.envelope_v4_locked(id).await?.ok_or_else(denied)?;
        if run.owner() != p.id() || run.operation_hash() != operation_hash {
            return Err(conflict());
        }
        self.authorize_envelope_v4(p, &fresh, &run, true)?;
        let receipt = self
            .receipt(&run_key(id)?)
            .await
            .map_err(map)?
            .ok_or_else(|| Error::new(ErrorKind::Backend, "missing run receipt"))?;
        Ok((run, receipt.snapshot().clone()))
    }

    pub async fn retry_original_v3_with_receipt(
        &self,
        p: &FlureePrincipal,
        id: &RunId,
        operation_hash: &ContentHash,
    ) -> Result<(RunEnvelopeV3, SnapshotRef)> {
        let _gate = self.mutation_gate.lock().await;
        let fresh = self.policy_context_locked(p).await?;
        self.require_operation(&fresh, Operation::Query)?;
        let run = self.envelope_v3_locked(id).await?.ok_or_else(denied)?;
        if run.owner() != p.id() || run.operation_hash() != operation_hash {
            return Err(conflict());
        }
        self.authorize_envelope_v3(p, &fresh, &run, true)?;
        let receipt = self
            .receipt(&run_key(id)?)
            .await
            .map_err(map)?
            .ok_or_else(|| Error::new(ErrorKind::Backend, "missing run receipt"))?;
        Ok((run, receipt.snapshot().clone()))
    }

    /// Version-dispatching protected lookup for the shared v2/v3 durable namespace.
    /// The protected descriptor and payload property are authorized before its schema is read.
    pub async fn guarded_find_versioned_run(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
        operation: Operation,
    ) -> Result<Option<ProtectedRun>> {
        if !matches!(
            operation,
            Operation::Query | Operation::Read | Operation::Replay
        ) {
            return Err(denied());
        }
        let _gate = self.mutation_gate.lock().await;
        let fresh = self.policy_context_locked(p).await?;
        self.context_matches(p, c, &fresh)?;
        self.require_operation(&fresh, operation)?;

        let protected_descriptor = descriptor(id)?;
        let pin = self.native.head().await.map_err(map)?;
        let Some(raw) = self
            .keyed(&pin, "record", &resource_key(protected_descriptor.as_str()))
            .await
            .map_err(map)?
        else {
            return if operation == Operation::Query {
                Ok(None)
            } else {
                Err(denied())
            };
        };
        if !self.resource_allowed(&fresh, &protected_descriptor)?
            || !self.fact_allowed(&fresh, &protected_descriptor, &Iri::http(RUN_PAYLOAD)?)?
        {
            return Err(denied());
        }

        let record = decode(&raw, self.options.codec_limits).map_err(map)?;
        let run = self.decode_protected_run_record(p, &fresh, id, operation, &record)?;
        match &run {
            ProtectedRun::V2(run) => self.authorize_envelope(p, &fresh, run, true)?,
            ProtectedRun::V3(run) => self.authorize_envelope_v3(p, &fresh, run, true)?,
            ProtectedRun::V4(run) => self.authorize_envelope_v4(p, &fresh, run, true)?,
            ProtectedRun::V5(run) => self.authorize_envelope_v5(p, &fresh, run, true)?,
        }
        Ok(Some(run))
    }

    /// Fresh guarded protected read; absent and unauthorized identities are indistinguishable.
    pub async fn guarded_run(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
    ) -> Result<RunEnvelope> {
        self.guarded_run_for(p, c, id, Operation::Read).await
    }
    pub async fn guarded_run_for(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
        operation: Operation,
    ) -> Result<RunEnvelope> {
        self.guarded_find_run(p, c, id, operation)
            .await?
            .ok_or_else(denied)
    }
    pub async fn guarded_find_run(
        &self,
        p: &FlureePrincipal,
        c: &FlureePolicyContext,
        id: &RunId,
        operation: Operation,
    ) -> Result<Option<RunEnvelope>> {
        if !matches!(
            operation,
            Operation::Query | Operation::Read | Operation::Replay
        ) {
            return Err(denied());
        }
        let _gate = self.mutation_gate.lock().await;
        let fresh = self.policy_context_locked(p).await?;
        self.context_matches(p, c, &fresh)?;
        self.require_operation(&fresh, operation)?;
        let Some(run) = self.envelope_locked(id).await? else {
            return if operation == Operation::Query {
                Ok(None)
            } else {
                Err(denied())
            };
        };
        if operation == Operation::Query && run.owner() != p.id() {
            return Err(denied());
        }
        self.authorize_envelope(p, &fresh, &run, true)?;
        Ok(Some(run))
    }
    /// Hold the Control mutation gate from the fresh policy check through one
    /// bounded host action. The callback must not re-enter this authority.
    pub async fn guarded_owned_query_action<T, F, Fut>(
        self: Arc<Self>,
        principal: FlureePrincipal,
        context: FlureePolicyContext,
        fence: Box<dyn ExternalPublicationFence>,
        action: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T>> + Send + 'static,
    {
        self.guarded_owned_action(principal, context, Operation::Query, fence, action)
            .await
    }

    /// Run a bounded async publication action under the requested Control
    /// permission. The callback must not re-enter the Control mutation gate.
    pub async fn guarded_owned_action<T, F, Fut>(
        self: Arc<Self>,
        principal: FlureePrincipal,
        context: FlureePolicyContext,
        operation: Operation,
        fence: Box<dyn ExternalPublicationFence>,
        action: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T>> + Send + 'static,
    {
        tokio::spawn(async move {
            let _gate = self.mutation_gate.clone().lock_owned().await;
            fence.check()?;
            let fresh = self.policy_context_locked(&principal).await?;
            self.context_matches(&principal, &context, &fresh)?;
            self.require_operation(&fresh, operation)?;
            fence.check()?;
            let value = action().await?;
            fence.check()?;
            Ok(value)
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "query action task failed"))?
    }

    pub async fn guarded_owned_release<F>(
        self: Arc<Self>,
        principal: FlureePrincipal,
        context: FlureePolicyContext,
        operation: Operation,
        run: Option<RunEnvelope>,
        fence: Box<dyn ExternalPublicationFence>,
        sink: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()> + Send + 'static,
    {
        tokio::spawn(async move {
            let _gate = self.mutation_gate.clone().lock_owned().await;
            fence.check()?;
            let fresh = self.policy_context_locked(&principal).await?;
            self.context_matches(&principal, &context, &fresh)?;
            self.require_operation(&fresh, operation)?;
            if let Some(run) = run {
                self.authorize_envelope(&principal, &fresh, &run, true)?;
            }
            fence.check()?;
            sink()
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "release task failed"))?
    }
    pub async fn guarded_owned_release_v5<F>(
        self: Arc<Self>,
        principal: FlureePrincipal,
        operation: Operation,
        run: RunEnvelopeV5,
        fence: Box<dyn ExternalPublicationFence>,
        sink: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()> + Send + 'static,
    {
        tokio::spawn(async move {
            let _gate = self.mutation_gate.clone().lock_owned().await;
            fence.check()?;
            let fresh = self.policy_context_locked(&principal).await?;
            self.require_operation(&fresh, operation)?;
            self.authorize_envelope_v5(&principal, &fresh, &run, true)?;
            fence.check()?;
            sink()
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "v5 release task failed"))?
    }

    pub async fn guarded_owned_release_v4<F>(
        self: Arc<Self>,
        principal: FlureePrincipal,
        operation: Operation,
        run: RunEnvelopeV4,
        fence: Box<dyn ExternalPublicationFence>,
        sink: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()> + Send + 'static,
    {
        tokio::spawn(async move {
            let _gate = self.mutation_gate.clone().lock_owned().await;
            fence.check()?;
            let fresh = self.policy_context_locked(&principal).await?;
            self.require_operation(&fresh, operation)?;
            self.authorize_envelope_v4(&principal, &fresh, &run, true)?;
            fence.check()?;
            sink()
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "v4 release task failed"))?
    }

    pub async fn guarded_owned_release_v3<F>(
        self: Arc<Self>,
        principal: FlureePrincipal,
        operation: Operation,
        run: RunEnvelopeV3,
        fence: Box<dyn ExternalPublicationFence>,
        sink: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<()> + Send + 'static,
    {
        tokio::spawn(async move {
            let _gate = self.mutation_gate.clone().lock_owned().await;
            fence.check()?;
            let fresh = self.policy_context_locked(&principal).await?;
            self.require_operation(&fresh, operation)?;
            self.authorize_envelope_v3(&principal, &fresh, &run, true)?;
            fence.check()?;
            sink()
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "v3 release task failed"))?
    }

    pub async fn guarded_owned_publish<F>(
        self: Arc<Self>,
        principal: FlureePrincipal,
        context: FlureePolicyContext,
        artifact: cdb_core::artifact::PublishedArtifact,
        fence: Box<dyn ExternalPublicationFence>,
        sink: F,
    ) -> Result<cdb_core::artifact::ArtifactRef>
    where
        F: FnOnce(&cdb_core::artifact::ArtifactRef, &SnapshotRef) -> Result<()> + Send + 'static,
    {
        tokio::spawn(async move {
            let gate = Arc::new(self.mutation_gate.clone().lock_owned().await);
            fence.check()?;
            let fresh = self.policy_context_locked(&principal).await?;
            self.context_matches(&principal, &context, &fresh)?;
            self.require_operation(&fresh, Operation::Publish)?;
            let id = ResourceId::new(artifact.reference().iri().as_str())?;
            self.authorize_artifact(&fresh.clone().with_existing(&id), &id)?;
            let b = AdmissionBatch::new(
                vec![],
                vec![],
                vec![],
                vec![artifact.clone()],
                V::object([])?,
                self.options.codec_limits,
            )?;
            let key = IdempotencyKey::new(format!("artifact-publication:{}", b.digest().as_str()))?;
            fence.check()?;
            let receipt = self
                .admit_locked(&key, &b, false, gate.clone())
                .await
                .map_err(map)?;
            let current = self.policy_context_locked(&principal).await?;
            self.require_operation(&current, Operation::Publish)?;
            self.authorize_artifact(&current, &id)?;
            fence.check()?;
            sink(artifact.reference(), receipt.snapshot())?;
            Ok(artifact.reference().clone())
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "publication task failed"))?
    }
    fn authorize_artifact(&self, c: &FlureePolicyContext, id: &ResourceId) -> Result<()> {
        if !self.resource_allowed(c, id)? {
            return Err(denied());
        }
        for key in ["iri", "version", "hash"] {
            let property = Iri::http(format!(
                "https://ctxql.example/reference-property/v1/artifact%2E{key}"
            ))?;
            if !self.fact_allowed(c, id, &property)? {
                return Err(denied());
            }
        }
        Ok(())
    }
    pub async fn guarded_owned_commit_record_v4<F>(
        self: Arc<Self>,
        principal: FlureePrincipal,
        run: RunEnvelopeV4,
        fence: Box<dyn ExternalPublicationFence>,
        sink: F,
    ) -> Result<SnapshotRef>
    where
        F: FnOnce(&RunEnvelopeV4, &SnapshotRef) -> Result<()> + Send + 'static,
    {
        tokio::spawn(async move {
            let gate = Arc::new(self.mutation_gate.clone().lock_owned().await);
            fence.check()?;
            let fresh = self.policy_context_locked(&principal).await?;
            self.require_operation(&fresh, Operation::Query)?;
            if run.owner() != principal.id() {
                return Err(conflict());
            }
            self.validate_snapshot(run.replay().control_capture())
                .await
                .map_err(map)?;
            let key = run_key(run.id())?;
            let receipt = if let Some(old) = self.envelope_v4_locked(run.id()).await? {
                if old.owner() != run.owner() || old.operation_hash() != run.operation_hash() {
                    return Err(conflict());
                }
                self.authorize_envelope_v4(&principal, &fresh, &old, true)?;
                self.receipt(&key)
                    .await
                    .map_err(map)?
                    .ok_or_else(|| Error::new(ErrorKind::Backend, "missing run receipt"))?
            } else {
                self.authorize_envelope_v4(
                    &principal,
                    &fresh.clone().with_existing(&run.descriptor_id()?),
                    &run,
                    true,
                )?;
                let ExportRecord::Resource(record) = run.to_record(self.options.codec_limits)?
                else {
                    unreachable!()
                };
                let batch = batch(vec![record], self.options.codec_limits)?;
                fence.check()?;
                self.admit_locked(&key, &batch, true, gate.clone())
                    .await
                    .map_err(map)?
            };
            let current = self.policy_context_locked(&principal).await?;
            self.require_operation(&current, Operation::Query)?;
            let stored = self
                .envelope_v4_locked(run.id())
                .await?
                .ok_or_else(denied)?;
            self.authorize_envelope_v4(&principal, &current, &stored, true)?;
            fence.check()?;
            sink(&stored, receipt.snapshot())?;
            Ok(receipt.snapshot().clone())
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "v4 recording task failed"))?
    }

    /// One detached owner holds the same gate and external session lease from validation
    /// through native durability, epoch publication, postchecks and whole-buffer enqueue.
    /// Dropping the caller future does not drop either lease; its fence must signal cancellation.
    pub async fn guarded_owned_commit_record<F>(
        self: Arc<Self>,
        principal: FlureePrincipal,
        context: FlureePolicyContext,
        run: RunEnvelope,
        fence: Box<dyn ExternalPublicationFence>,
        sink: F,
    ) -> Result<SnapshotRef>
    where
        F: FnOnce(&RunEnvelope, &SnapshotRef) -> Result<()> + Send + 'static,
    {
        tokio::spawn(async move {
            let gate = Arc::new(self.mutation_gate.clone().lock_owned().await);
            fence.check()?;
            let fresh = self.policy_context_locked(&principal).await?;
            self.context_matches(&principal, &context, &fresh)?;
            self.require_operation(&fresh, Operation::Query)?;
            if run.owner() != principal.id() {
                return Err(conflict());
            }
            self.validate_snapshot(&run.replay().data().snapshot)
                .await
                .map_err(map)?;
            let key = run_key(run.id())?;
            let receipt = if let Some(old) = self.envelope_locked(run.id()).await? {
                if old.owner() != run.owner() || old.operation_hash() != run.operation_hash() {
                    return Err(conflict());
                }
                self.authorize_envelope(&principal, &fresh, &old, true)?;
                self.receipt(&key)
                    .await
                    .map_err(map)?
                    .ok_or_else(|| Error::new(ErrorKind::Backend, "missing run receipt"))?
            } else {
                self.authorize_envelope(
                    &principal,
                    &fresh.clone().with_existing(&run.descriptor_id()?),
                    &run,
                    true,
                )?;
                let ExportRecord::Resource(record) = run.to_record(self.options.codec_limits)?
                else {
                    unreachable!()
                };
                let b = batch(vec![record], self.options.codec_limits)?;
                fence.check()?;
                self.admit_locked(&key, &b, true, gate.clone())
                    .await
                    .map_err(map)?
            };
            let current = self.policy_context_locked(&principal).await?;
            // The continuous gate permits only our known admission to change the head.
            self.require_operation(&current, Operation::Query)?;
            let stored = self.envelope_locked(run.id()).await?.ok_or_else(denied)?;
            self.authorize_envelope(&principal, &current, &stored, true)?;
            fence.check()?;
            sink(&stored, receipt.snapshot())?;
            let result = receipt.snapshot().clone();
            drop(gate);
            drop(fence);
            Ok(result)
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "recording task failed"))?
    }
}

#[cfg(test)]
mod owned_gate_tests {
    use crate as cdb_backend_fluree;
    use cdb_core::{
        admission::{DependencyRecord, ExportRecord, Fact, FactTerm, ResourceKind},
        recording_v4::RUN_SCHEMA as RUN_SCHEMA_V4,
        recording_v5::RUN_SCHEMA as RUN_SCHEMA_V5,
    };
    include!("../tests/run_service_gates.rs");

    struct HeldFence {
        cancelled: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }
    impl ExternalPublicationFence for HeldFence {
        fn check(&self) -> Result<()> {
            if self.cancelled.load(Ordering::SeqCst) {
                Err(Error::new(ErrorKind::Denied, "cancelled"))
            } else {
                Ok(())
            }
        }
    }
    impl Drop for HeldFence {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
    fn record_with_schema(run: &RunEnvelope, schema: &str) -> ExportRecord {
        let mut payload = run.projection();
        let V::Object(fields) = &mut payload else {
            unreachable!()
        };
        fields.insert("schema".into(), V::string(schema));
        let text = String::from_utf8(
            payload
                .canonical_bytes(cdb_core::Limits::default())
                .unwrap(),
        )
        .unwrap();
        ExportRecord::Resource(
            DependencyRecord::new(
                "ctxql-resource/v1",
                run.descriptor_id().unwrap(),
                ResourceKind::RunDescriptor,
                vec![Fact::new(
                    Iri::new(RUN_PAYLOAD).unwrap(),
                    FactTerm::Literal(
                        cdb_core::claim::TypedLiteral::new(
                            Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                            V::string(text),
                            None,
                        )
                        .unwrap(),
                    ),
                )],
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn protected_dispatch_never_falls_back_after_schema_selection() {
        let (_dir, backend) = setup().await;
        let run = envelope(&backend).await;
        let principal = backend.issue_principal(run.owner().clone()).await.unwrap();
        let context = backend.current(&principal).await.unwrap();

        for schema in [RUN_SCHEMA_V4, RUN_SCHEMA_V5, "ctxql-recorded-run/unknown"] {
            let error = backend
                .decode_protected_run_record(
                    &principal,
                    &context,
                    run.id(),
                    Operation::Query,
                    &record_with_schema(&run, schema),
                )
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Invalid);
        }
    }

    #[tokio::test]
    async fn detached_commit_retains_session_and_blocks_revocation() {
        let (_d, b) = setup().await;
        let run = envelope(&b).await;
        let p = b.issue_principal(run.owner().clone()).await.unwrap();
        let c = b.current(&p).await.unwrap();
        let (entered, release) = b.native.pause_commit().await;
        let cancelled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let sink_called = Arc::new(AtomicBool::new(false));
        let fence = HeldFence {
            cancelled: cancelled.clone(),
            dropped: dropped.clone(),
        };
        let sink_flag = sink_called.clone();
        let owner = b.clone();
        let candidate = run.clone();
        let caller = tokio::spawn(async move {
            owner
                .guarded_owned_commit_record(p, c, candidate, Box::new(fence), move |_, _| {
                    sink_flag.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await
        });
        entered.notified().await;
        caller.abort();
        cancelled.store(true, Ordering::SeqCst);
        let owner = b.clone();
        let mut revoke = tokio::spawn(async move {
            owner
                .set_policy_state(
                    &IdempotencyKey::new("revoke").unwrap(),
                    &PolicyState::deny_all().unwrap(),
                )
                .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut revoke)
                .await
                .is_err()
        );
        assert!(!dropped.load(Ordering::SeqCst));
        release.notify_one();
        revoke.await.unwrap().unwrap();
        assert!(dropped.load(Ordering::SeqCst));
        assert!(!sink_called.load(Ordering::SeqCst));
        assert_eq!(b.envelope_locked(run.id()).await.unwrap().unwrap(), run);
    }
    #[tokio::test]
    async fn prospective_run_limit_leaves_head_readable() {
        let (dir, b) = setup().await;
        let before = b.head().await.unwrap();
        let run = envelope(&b).await;
        drop(b);
        let mut opts = options(dir.path());
        opts.native_limits.max_transaction_bytes = 1024;
        let b = Arc::new(FlureeBackend::open(opts).await.unwrap());
        assert_eq!(
            commit(b.clone(), run.clone(), false)
                .await
                .unwrap_err()
                .kind,
            ErrorKind::Limit
        );
        assert_eq!(b.head().await.unwrap(), before);
        assert!(b.envelope_locked(run.id()).await.unwrap().is_none());
        b.ensure_audited(&before).await.unwrap();
    }
}
