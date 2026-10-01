use crate::artifact::PublishedArtifact;
use crate::claim::*;
use crate::id::*;
use crate::snapshot::SnapshotRef;
use crate::value::obj;
use crate::{CanonicalValue as V, Error, ErrorKind, Limits, Result, Timestamp};
use std::collections::BTreeSet;
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FactTerm {
    Reference(ResourceId),
    Literal(TypedLiteral),
}
impl FactTerm {
    pub fn projection(&self) -> V {
        match self {
            Self::Reference(r) => obj([
                ("kind", V::string("reference")),
                ("value", V::string(r.as_str())),
            ]),
            Self::Literal(v) => v.projection(),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fact {
    predicate: Iri,
    term: FactTerm,
}
impl Fact {
    pub fn new(predicate: Iri, term: FactTerm) -> Self {
        Self { predicate, term }
    }
    pub fn predicate(&self) -> &Iri {
        &self.predicate
    }
    pub fn term(&self) -> &FactTerm {
        &self.term
    }
    pub fn projection(&self) -> V {
        obj([
            ("predicate", V::string(self.predicate.as_str())),
            ("term", self.term.projection()),
        ])
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    Ontology,
    Label,
    Policy,
    Identity,
    SourceDescriptor,
    ArtifactDescriptor,
    RunDescriptor,
    LifecycleEvent,
}
impl ResourceKind {
    pub fn mutable(self) -> bool {
        matches!(
            self,
            Self::Ontology | Self::Label | Self::Policy | Self::Identity
        )
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ontology => "ontology",
            Self::Label => "label",
            Self::Policy => "policy",
            Self::Identity => "identity",
            Self::SourceDescriptor => "source",
            Self::ArtifactDescriptor => "artifact",
            Self::RunDescriptor => "run",
            Self::LifecycleEvent => "lifecycle_event",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyRecord {
    id: ResourceId,
    kind: ResourceKind,
    facts: Vec<Fact>,
}
impl DependencyRecord {
    pub fn new(schema: &str, id: ResourceId, kind: ResourceKind, facts: Vec<Fact>) -> Result<Self> {
        if schema != "ctxql-resource/v1" || facts.is_empty() {
            return Err(Error::invalid("resource schema/facts"));
        }
        let mut seen = BTreeSet::new();
        for f in &facts {
            if !seen.insert(f.projection().canonical_bytes(Limits::default())?) {
                return Err(Error::invalid("duplicate fact"));
            }
        }
        Ok(Self { id, kind, facts })
    }
    pub fn id(&self) -> &ResourceId {
        &self.id
    }
    pub fn kind(&self) -> ResourceKind {
        self.kind
    }
    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }
    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-resource/v1")),
            ("id", V::string(self.id.as_str())),
            ("kind", V::string(self.kind.as_str())),
            (
                "facts",
                V::Array(self.facts.iter().map(Fact::projection).collect()),
            ),
        ])
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceChange {
    Add(DependencyRecord),
    ReplaceMutable {
        previous: ContentHash,
        record: DependencyRecord,
    },
    RetractMutable {
        id: ResourceId,
        kind: ResourceKind,
        previous: ContentHash,
    },
}
impl ResourceChange {
    pub fn validate(&self) -> Result<()> {
        if match self {
            Self::Add(_) => false,
            Self::ReplaceMutable { record, .. } => !record.kind.mutable(),
            Self::RetractMutable { kind, .. } => !kind.mutable(),
        } {
            return Err(Error::invalid("immutable resource mutation"));
        }
        Ok(())
    }
    pub fn id(&self) -> &ResourceId {
        match self {
            Self::Add(r) | Self::ReplaceMutable { record: r, .. } => r.id(),
            Self::RetractMutable { id, .. } => id,
        }
    }
    pub fn projection(&self) -> V {
        match self {
            Self::Add(r) => obj([("operation", V::string("add")), ("record", r.projection())]),
            Self::ReplaceMutable { previous, record } => obj([
                ("operation", V::string("replace_mutable")),
                ("previous", V::string(previous.as_str())),
                ("record", record.projection()),
            ]),
            Self::RetractMutable { id, kind, previous } => obj([
                ("operation", V::string("retract_mutable")),
                ("id", V::string(id.as_str())),
                ("kind", V::string(kind.as_str())),
                ("previous", V::string(previous.as_str())),
            ]),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionBatch {
    claims: Vec<CandidateClaim>,
    lifecycle: Vec<LifecycleAssertion>,
    resources: Vec<ResourceChange>,
    artifacts: Vec<PublishedArtifact>,
    origin: V,
    digest: ContentHash,
}
impl AdmissionBatch {
    pub fn new(
        claims: Vec<CandidateClaim>,
        lifecycle: Vec<LifecycleAssertion>,
        resources: Vec<ResourceChange>,
        artifacts: Vec<PublishedArtifact>,
        origin: V,
        limits: Limits,
    ) -> Result<Self> {
        origin.as_object()?;
        if claims.iter().any(CandidateClaim::is_lifecycle_assertion) {
            return Err(Error::invalid("lifecycle claim requires validated wrapper"));
        }
        let mut ids = BTreeSet::new();
        for id in claims
            .iter()
            .map(|c| resource_key(c.id().as_str()))
            .chain(lifecycle.iter().map(|l| resource_key(l.id().as_str())))
            .chain(resources.iter().map(|r| resource_key(r.id().as_str())))
            .chain(artifacts.iter().map(|a| artifact_key(a.reference())))
        {
            if !ids.insert(id) {
                return Err(Error::invalid("duplicate batch identity"));
            }
        }
        for r in &resources {
            r.validate()?;
        }
        let mut batch = Self {
            claims,
            lifecycle,
            resources,
            artifacts,
            origin,
            digest: ContentHash::of_bytes(b""),
        };
        batch.digest = ContentHash::of_bytes(&batch.projection().canonical_bytes(limits)?);
        Ok(batch)
    }
    pub fn claims(&self) -> &[CandidateClaim] {
        &self.claims
    }
    pub fn lifecycle(&self) -> &[LifecycleAssertion] {
        &self.lifecycle
    }
    pub fn resources(&self) -> &[ResourceChange] {
        &self.resources
    }
    pub fn artifacts(&self) -> &[PublishedArtifact] {
        &self.artifacts
    }
    pub fn digest(&self) -> &ContentHash {
        &self.digest
    }
    /// Backend must call against staged exact state before publishing. IDs cannot be reused.
    pub fn validate_claim_references(&self, existing: &BTreeSet<ClaimId>) -> Result<()> {
        let new: BTreeSet<_> = self
            .claims
            .iter()
            .map(|c| c.id().clone())
            .chain(self.lifecycle.iter().map(|l| l.id().clone()))
            .collect();
        for id in &new {
            if existing.contains(id) {
                return Err(Error::new(ErrorKind::Conflict, "claim ID already exists"));
            }
        }
        for l in &self.lifecycle {
            for id in std::iter::once(l.target()).chain(l.referenced_claim()) {
                if !existing.contains(id) && !new.contains(id) {
                    return Err(Error::invalid("unknown lifecycle target"));
                }
            }
        }
        Ok(())
    }
    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string("ctxql-admission/v1")),
            (
                "claims",
                V::Array(self.claims.iter().map(CandidateClaim::projection).collect()),
            ),
            (
                "lifecycle",
                V::Array(
                    self.lifecycle
                        .iter()
                        .map(LifecycleAssertion::projection)
                        .collect(),
                ),
            ),
            (
                "resources",
                V::Array(
                    self.resources
                        .iter()
                        .map(ResourceChange::projection)
                        .collect(),
                ),
            ),
            (
                "artifacts",
                V::Array(
                    self.artifacts
                        .iter()
                        .map(|a| a.reference().projection())
                        .collect(),
                ),
            ),
            ("origin", self.origin.clone()),
        ])
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionReceipt {
    key: IdempotencyKey,
    payload: ContentHash,
    snapshot: SnapshotRef,
    transaction_time: Timestamp,
    claim_ids: Vec<ClaimId>,
}
impl AdmissionReceipt {
    pub fn new(
        key: IdempotencyKey,
        payload: ContentHash,
        snapshot: SnapshotRef,
        transaction_time: Timestamp,
        claim_ids: Vec<ClaimId>,
    ) -> Result<Self> {
        if claim_ids.iter().collect::<BTreeSet<_>>().len() != claim_ids.len() {
            return Err(Error::invalid("duplicate receipt claims"));
        }
        Ok(Self {
            key,
            payload,
            snapshot,
            transaction_time,
            claim_ids,
        })
    }
    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }
    pub fn payload(&self) -> &ContentHash {
        &self.payload
    }
    pub fn snapshot(&self) -> &SnapshotRef {
        &self.snapshot
    }
    pub fn transaction_time(&self) -> Timestamp {
        self.transaction_time
    }
    pub fn claim_ids(&self) -> &[ClaimId] {
        &self.claim_ids
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordChange {
    ClaimAdded(Box<AdmittedClaim>),
    LifecycleAdded {
        assertion: LifecycleAssertion,
        transaction_time: Timestamp,
    },
    Resource(ResourceChange),
    ArtifactAdded(PublishedArtifact),
}
impl RecordChange {
    pub fn projection(&self) -> V {
        match self {
            Self::ClaimAdded(c) => obj([
                ("kind", V::string("claim_add")),
                ("candidate", c.candidate().projection()),
                (
                    "transaction_time",
                    V::string(c.transaction_time().canonical()),
                ),
            ]),
            Self::LifecycleAdded {
                assertion,
                transaction_time,
            } => obj([
                ("kind", V::string("lifecycle_add")),
                ("assertion", assertion.projection()),
                ("transaction_time", V::string(transaction_time.canonical())),
            ]),
            Self::Resource(r) => r.projection(),
            Self::ArtifactAdded(a) => obj([
                ("kind", V::string("artifact_add")),
                ("reference", a.reference().projection()),
            ]),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeBatch {
    predecessor: SnapshotRef,
    result: SnapshotRef,
    changes: Vec<RecordChange>,
    digest: ContentHash,
}
impl ChangeBatch {
    pub fn new(
        schema: &str,
        predecessor: SnapshotRef,
        result: SnapshotRef,
        changes: Vec<RecordChange>,
        limits: Limits,
    ) -> Result<Self> {
        if schema != "ctxql-change/v1"
            || !predecessor.same_authority(&result)
            || predecessor == result
        {
            return Err(Error::invalid("change schema/ancestry"));
        }
        let mut seen = BTreeSet::new();
        for c in &changes {
            let id = match c {
                RecordChange::ClaimAdded(c) => {
                    if c.candidate().is_lifecycle_assertion() {
                        return Err(Error::invalid("lifecycle claim requires validated wrapper"));
                    }
                    resource_key(c.id().as_str())
                }
                RecordChange::LifecycleAdded { assertion, .. } => {
                    resource_key(assertion.id().as_str())
                }
                RecordChange::Resource(r) => {
                    r.validate()?;
                    resource_key(r.id().as_str())
                }
                RecordChange::ArtifactAdded(a) => artifact_key(a.reference()),
            };
            if !seen.insert(id) {
                return Err(Error::invalid("duplicate change identity"));
            }
        }
        let v = obj([
            ("schema", V::string(schema)),
            ("backend", V::string(result.backend().as_str())),
            ("predecessor", predecessor.projection()),
            ("result", result.projection()),
            (
                "changes",
                V::Array(changes.iter().map(RecordChange::projection).collect()),
            ),
        ]);
        let digest = ContentHash::of_bytes(&v.canonical_bytes(limits)?);
        Ok(Self {
            predecessor,
            result,
            changes,
            digest,
        })
    }
    pub fn predecessor(&self) -> &SnapshotRef {
        &self.predecessor
    }
    pub fn result(&self) -> &SnapshotRef {
        &self.result
    }
    pub fn changes(&self) -> &[RecordChange] {
        &self.changes
    }
    pub fn digest(&self) -> &ContentHash {
        &self.digest
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportRecord {
    Claim(Box<AdmittedClaim>),
    Lifecycle {
        assertion: LifecycleAssertion,
        transaction_time: Timestamp,
    },
    Resource(DependencyRecord),
    Artifact(PublishedArtifact),
}
impl ExportRecord {
    /// Ordinary claim lookup includes lifecycle assertions without a second stored record.
    pub fn claim(&self) -> Option<AdmittedClaim> {
        match self {
            Self::Claim(c) => Some(*c.clone()),
            Self::Lifecycle {
                assertion,
                transaction_time,
            } => Some(AdmittedClaim::assign(
                assertion.candidate().clone(),
                *transaction_time,
            )),
            _ => None,
        }
    }
    /// Unambiguous fixture/index key, not an assertion ID or public hash domain.
    /// Immutable artifact versions coexist; claims/lifecycle/resources share ID space.
    pub fn identity_key(&self) -> String {
        match self {
            Self::Claim(c) => resource_key(c.id().as_str()),
            Self::Lifecycle { assertion, .. } => resource_key(assertion.id().as_str()),
            Self::Resource(r) => resource_key(r.id().as_str()),
            Self::Artifact(a) => artifact_key(a.reference()),
        }
    }
}
pub fn resource_key(id: &str) -> String {
    format!("resource:{id}")
}
pub fn artifact_key(reference: &crate::artifact::ArtifactRef) -> String {
    let iri = reference.iri().as_str();
    format!(
        "artifact:{}:{iri}{}",
        iri.len(),
        reference.version().as_str()
    )
}
