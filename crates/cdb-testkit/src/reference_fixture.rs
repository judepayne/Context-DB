//! Explicit trusted reference fixture construction; no caller timestamps are admitted as authority.
use crate::{
    memory::{MemoryBackend, MemoryOptions, MemoryPrincipal},
    projection::{MemoryProjection, ProjectionOptions},
};
use cdb_core::{
    admission::*, artifact::*, claim::*, contracts::*, id::*, policy::PolicySet, snapshot::*,
    CanonicalValue as V, Error, Limits, Result, Timestamp,
};
use cdb_engine::execution::*;
use std::{collections::BTreeMap, sync::Arc};
pub const CONFIG: &str = r#"{"name":"reference-fixture","version":"1","runtime":{"candidate_order":["depth asc","confidence desc","transaction_time desc","claim_id asc"],"path_ranking":["shorter_path","higher_accumulated_confidence","better_grounding","newer_claims","claim_id_tiebreak"],"cycle_policy":"no_repeated_claim"},"fields":{},"external_functions":{}}"#;
pub fn artifact(iri: &str, bytes: &[u8]) -> Result<PublishedArtifact> {
    PublishedArtifact::new(
        ArtifactRef::new(
            Iri::new(iri)?,
            VersionId::new("1")?,
            ContentHash::of_bytes(bytes),
        ),
        bytes.to_vec(),
        Limits::default(),
    )
}
fn obj<const N: usize>(a: [(&str, V); N]) -> V {
    V::Object(a.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
pub fn allow_policy() -> Result<PolicySet> {
    PolicySet::parse(br#"{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{"@id":"https://fixture.example/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true}]}"#,Limits::default())
}
/// Helpers use explicit metadata resources and normal admission. Arbitrary valid candidates
/// can instead be passed to `claim`; supplied transaction_time is never accepted.
#[derive(Default)]
pub struct FixtureBuilder {
    claims: Vec<CandidateClaim>,
    lifecycle: Vec<LifecycleAssertion>,
    resources: BTreeMap<ResourceId, DependencyRecord>,
    artifacts: Vec<PublishedArtifact>,
}
impl FixtureBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn resource(&mut self, record: DependencyRecord) -> &mut Self {
        self.resources.insert(record.id().clone(), record);
        self
    }
    pub fn artifact(&mut self, a: PublishedArtifact) -> &mut Self {
        self.artifacts.push(a);
        self
    }
    pub fn entity(&mut self, id: &str, label: Option<&str>) -> Result<&mut Self> {
        let mut facts = vec![Fact::new(
            property_iri("entity")?,
            FactTerm::Literal(TypedLiteral::new(
                Iri::new("http://www.w3.org/2001/XMLSchema#boolean")?,
                V::Bool(true),
                None,
            )?),
        )];
        if let Some(label) = label {
            facts.push(Fact::new(
                property_iri("label")?,
                FactTerm::Literal(TypedLiteral::new(
                    Iri::new("http://www.w3.org/2001/XMLSchema#string")?,
                    V::string(label),
                    None,
                )?),
            ));
        }
        self.resource(DependencyRecord::new(
            "ctxql-resource/v1",
            ResourceId::new(id)?,
            ResourceKind::Label,
            facts,
        )?);
        Ok(self)
    }
    pub fn claim(&mut self, c: CandidateClaim) -> Result<&mut Self> {
        if c.is_lifecycle_assertion() {
            return Err(Error::invalid("use lifecycle wrapper"));
        }
        self.claims.push(c);
        Ok(self)
    }
    pub fn lifecycle(&mut self, c: LifecycleAssertion) -> &mut Self {
        self.lifecycle.push(c);
        self
    }
    pub fn edge(
        &mut self,
        id: &str,
        subject: &str,
        object: ClaimObject,
        confidence: &str,
    ) -> Result<&mut Self> {
        let c = CandidateClaim::from_value(&obj([
            ("claim_id", V::string(id)),
            ("subject_id", V::string(subject)),
            ("relation", V::string("https://fixture.example/edge")),
            ("object_id", object.projection()),
            (
                "relation_type",
                V::string("https://fixture.example/Relation"),
            ),
            ("subject_type", V::string("https://fixture.example/Entity")),
            ("object_type", V::string("https://fixture.example/Entity")),
            ("claim_type", V::string("https://fixture.example/Assertion")),
            (
                "confidence",
                V::Number(cdb_core::ExactNumber::parse(confidence)?),
            ),
            ("grounding_level", V::string("claim_only")),
        ]))?;
        self.claim(c)
    }
    pub async fn build(self) -> Result<ReferenceFixture> {
        let backend = MemoryBackend::new(
            BackendId::new("reference")?,
            AuthorityId::new("reference-authority")?,
            GraphId::new("reference-graph")?,
            Timestamp::parse("2026-04-01T00:00:00Z")?,
            MemoryOptions::default(),
        )?;
        let principal = backend.provision(
            PrincipalId::new("reader")?,
            true,
            [Iri::new("https://fixture.example/Reader")?]
                .into_iter()
                .collect(),
        )?;
        backend.set_policy(allow_policy()?)?;
        let config = artifact("https://fixture.example/config", CONFIG.as_bytes())?;
        let batch = self.into_batch()?;
        backend
            .admit(&IdempotencyKey::new("reference-initial")?, &batch)
            .await?;
        Ok(ReferenceFixture {
            backend,
            principal,
            config,
        })
    }
    /// The same authored fixture data admitted through any real GraphBackend.
    pub fn into_batch(self) -> Result<AdmissionBatch> {
        let config = artifact("https://fixture.example/config", CONFIG.as_bytes())?;
        let mut artifacts = self.artifacts;
        if !artifacts
            .iter()
            .any(|a| a.reference() == config.reference())
        {
            artifacts.push(config.clone());
        }
        AdmissionBatch::new(
            self.claims,
            self.lifecycle,
            self.resources
                .into_values()
                .map(ResourceChange::Add)
                .collect(),
            artifacts,
            obj([]),
            Limits::default(),
        )
    }
}
pub struct ReferenceFixture {
    pub backend: MemoryBackend,
    pub principal: MemoryPrincipal,
    pub config: PublishedArtifact,
}
/// Optional immutable scripted-source adapter. It does not grant permissions; the engine
/// checks current resource/claim facts before issuing the exact selector-bound read.
pub struct FixtureEvidence<'a> {
    pub fixture: &'a ReferenceFixture,
    pub sources: &'a crate::sources::ScriptedSources,
}
impl ViewProvider for FixtureEvidence<'_> {
    fn evidence_reader(&self) -> Option<&dyn SourceReader> {
        Some(self.sources)
    }
    fn open<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        self.fixture.open(captured, options)
    }
}
impl ViewProvider for ReferenceFixture {
    fn open<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        open(&self.backend, captured, options)
    }
}
/// Rebuild disposable projection from a complete bounded exact export. Explicit entity/label
/// records, not incidental business strings, form the catalog. No current policy is read here.
pub fn open<'a>(
    backend: &'a MemoryBackend,
    captured: &'a CapturedSnapshot,
    options: &'a ExecutionOptions,
) -> IoFuture<'a, PreparedView> {
    Box::pin(async move {
        let snapshot = backend.open_snapshot(&captured.snapshot).await?;
        // This explicitly selected adapter owns one immutable fixture admission. Its receipt
        // supplies resource visibility time; DependencyRecord itself has no timestamp.
        let admission = backend
            .receipt(&IdempotencyKey::new("reference-initial")?)
            .await?
            .ok_or_else(|| {
                Error::new(
                    cdb_core::ErrorKind::Unsupported,
                    "fixture catalog admission provenance required",
                )
            })?;
        let admitted = backend.open_snapshot(admission.snapshot()).await?;
        let mut pages = vec![];
        let mut cursor = None;
        let mut records = 0usize;
        let mut bytes = 0usize;
        let mut seen = std::collections::BTreeSet::new();
        loop {
            options.check_interrupted()?;
            let page = snapshot.export(cursor.as_ref(), options.page_size).await?;
            records = records
                .checked_add(page.items().len())
                .ok_or_else(Error::limit)?;
            if records > options.max_records || pages.len() >= options.max_work {
                return Err(Error::limit());
            }
            for record in page.items() {
                let v = match record {
                    ExportRecord::Claim(c) => c.response(LifecycleState::Active),
                    ExportRecord::Lifecycle { assertion, .. } => assertion.projection(),
                    ExportRecord::Resource(r) => r.projection(),
                    ExportRecord::Artifact(a) => a.reference().projection(),
                };
                bytes = bytes
                    .checked_add(v.canonical_bytes(options.limits)?.len())
                    .ok_or_else(Error::limit)?;
            }
            if bytes > options.max_retained_bytes {
                return Err(Error::limit());
            }
            cursor = page.next().cloned();
            if let Some(c) = &cursor {
                if !seen.insert(c.position().clone()) {
                    return Err(Error::invalid("export progress"));
                }
            }
            pages.push(page);
            if cursor.is_none() {
                break;
            }
        }
        let stream = pages
            .iter()
            .find_map(|p| p.next().map(|c| c.stream().clone()))
            .unwrap_or(ResourceId::new("export")?);
        let export = CompleteExport::collect(
            captured.snapshot.clone(),
            stream,
            pages,
            options.max_records,
        )?;
        let mut entries = vec![];
        for record in export.records() {
            options.check_interrupted()?;
            if let ExportRecord::Resource(r) = record {
                if !r
                    .facts()
                    .iter()
                    .any(|f| f.predicate() == &property_iri("entity").expect("constant"))
                {
                    continue;
                }
                if admitted.resource(r.id()).await?.as_ref() != Some(r) {
                    return Err(Error::new(
                        cdb_core::ErrorKind::Unsupported,
                        "changed fixture catalog requires new provenance",
                    ));
                }
                if admission.transaction_time() > captured.as_of {
                    continue;
                }
                let id = EntityId::new(r.id().as_str())?;
                entries.push(LandingEntry {
                    id: id.clone(),
                    label: None,
                    dependencies: vec![],
                });
                for fact in r.facts() {
                    if fact.predicate() == &property_iri("label")? {
                        if let FactTerm::Literal(l) = fact.term() {
                            entries.push(LandingEntry {
                                id: id.clone(),
                                label: Some(l.value().as_str()?.into()),
                                dependencies: vec![r.id().clone()],
                            });
                        }
                    }
                }
            }
        }
        let algorithm = Iri::new("https://fixture.example/projection-v1")?;
        let projection = MemoryProjection::new(
            captured.snapshot.clone(),
            algorithm.clone(),
            ProjectionOptions {
                max_records: options.max_records,
                max_bytes: options.max_retained_bytes,
                max_history: 1,
            },
        )?;
        let cp = ProjectionCheckpoint::new(
            captured.snapshot.clone(),
            VersionId::new("ctxql-projection/v1")?,
            VersionId::new("reference")?,
            algorithm,
        )?;
        projection.build(&export, &cp).await?;
        Ok(PreparedView {
            view: projection.open_view(&captured.snapshot).await?,
            landing: Arc::new(Catalog {
                snapshot: captured.snapshot.clone(),
                entries,
            }),
        })
    })
}
struct Catalog {
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
