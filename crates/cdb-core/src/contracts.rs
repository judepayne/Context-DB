//! Trusted host interfaces. No implementation here authenticates JSON or runs queries.
use crate::admission::*;
use crate::artifact::*;
use crate::claim::*;
use crate::id::*;
use crate::replay::*;
use crate::snapshot::*;
use crate::source::*;
use crate::{Limits, Result, Timestamp};
use std::{future::Future, pin::Pin, sync::Arc};
pub type IoFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendCapabilities {
    pub exact_snapshots: bool,
    pub ordered_changes: bool,
    pub atomic_admission: bool,
    pub closed_cutoff: bool,
    pub complete_exports: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedSnapshot {
    pub as_of: Timestamp,
    pub snapshot: SnapshotRef,
}

/// Exact immutable identities for one dual-ledger execution. Semantic traversal
/// and ontology preparation use `semantic`; artifacts, service policy, and
/// publication use `control`. Equality of the two is retained only for legacy
/// single-ledger execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionCaptures {
    semantic: CapturedSnapshot,
    control: SnapshotRef,
}

impl ExecutionCaptures {
    pub fn new(semantic: CapturedSnapshot, control: SnapshotRef) -> Self {
        Self { semantic, control }
    }

    pub fn legacy(capture: CapturedSnapshot) -> Self {
        Self {
            control: capture.snapshot.clone(),
            semantic: capture,
        }
    }

    pub fn semantic(&self) -> &CapturedSnapshot {
        &self.semantic
    }

    pub fn control(&self) -> &SnapshotRef {
        &self.control
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangeHint {
    Head(SnapshotRef),
    Lagged,
    Closed,
}
pub trait ChangeHintSource: Send {
    fn next(&mut self) -> IoFuture<'_, ChangeHint>;
}
pub trait GraphBackend: Send + Sync {
    fn capabilities(&self) -> Result<BackendCapabilities>;
    fn head(&self) -> IoFuture<'_, SnapshotRef>;
    fn admit<'a>(
        &'a self,
        key: &'a IdempotencyKey,
        batch: &'a AdmissionBatch,
    ) -> IoFuture<'a, AdmissionReceipt>;
    fn receipt<'a>(&'a self, key: &'a IdempotencyKey) -> IoFuture<'a, Option<AdmissionReceipt>>;
    fn capture(&self, requested: Option<Timestamp>) -> IoFuture<'_, CapturedSnapshot>;
    fn open_snapshot<'a>(&'a self, pin: &'a SnapshotRef) -> IoFuture<'a, Arc<dyn BackendSnapshot>>;
    fn changes<'a>(
        &'a self,
        after: &'a SnapshotRef,
        through: &'a SnapshotRef,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ChangeBatch>>;
    fn subscribe(&self) -> IoFuture<'_, Box<dyn ChangeHintSource>>;
}
pub trait BackendSnapshot: Send + Sync {
    fn identity(&self) -> &SnapshotRef;
    fn resource<'a>(&'a self, id: &'a ResourceId) -> IoFuture<'a, Option<DependencyRecord>>;
    fn export<'a>(
        &'a self,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ExportRecord>>;
    fn artifact<'a>(
        &'a self,
        reference: &'a ArtifactRef,
    ) -> IoFuture<'a, Option<PublishedArtifact>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticProjectionCapabilities {
    pub exact_snapshots: bool,
    pub ordered_changes: bool,
    pub closed_cutoff: bool,
    pub complete_exports: bool,
    pub schema: VersionId,
    pub algorithm: Iri,
}

/// Backend-neutral identity for one fully prepared authorized ontology view.
/// RDF payloads, Fluree handles, and operational scan counters remain backend-private.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedOntologyDescriptor {
    pub capture: SnapshotRef,
    pub authorized_premise_root: ContentHash,
    pub execution_manifest_root: ContentHash,
    pub ontology_profile: VersionId,
    pub full_ontology_bundle_root: ContentHash,
    pub ontology_profile_result_root: ContentHash,
    pub reasoner_input_root: ContentHash,
    pub structural_mapping_algorithm: VersionId,
    pub profile_limits_identity: ContentHash,
    pub materialization_limits_identity: ContentHash,
    pub reasoning_limits_identity: ContentHash,
    pub budget_identity: ContentHash,
    pub prepared_root: ContentHash,
    pub materializer: VersionId,
    pub reasoner: VersionId,
    pub diagnostics_root: ContentHash,
    pub completeness_root: ContentHash,
}

impl PreparedOntologyDescriptor {
    /// Construct the explicit stored-only descriptor used when no ontology
    /// sandbox, materializer, or reasoner is run.
    pub fn no_sandbox(
        capture: SnapshotRef,
        authorized_premise_root: ContentHash,
        execution_manifest_root: ContentHash,
        completeness_root: ContentHash,
    ) -> Result<Self> {
        Ok(Self {
            capture,
            authorized_premise_root,
            execution_manifest_root,
            ontology_profile: VersionId::new("none/v1")?,
            full_ontology_bundle_root: ContentHash::of_bytes(b"ctxql-ontology-bundle/none/v1"),
            ontology_profile_result_root: ContentHash::of_bytes(
                b"ctxql-ontology-profile-result/none/v1",
            ),
            reasoner_input_root: ContentHash::of_bytes(b"ctxql-reasoner-input/none/v1"),
            structural_mapping_algorithm: VersionId::new("none/v1")?,
            profile_limits_identity: ContentHash::of_bytes(
                b"ctxql-ontology-profile-limits/none/v1",
            ),
            materialization_limits_identity: ContentHash::of_bytes(
                b"ctxql-materialization-limits/none/v1",
            ),
            reasoning_limits_identity: ContentHash::of_bytes(b"ctxql-reasoning-limits/none/v1"),
            budget_identity: ContentHash::of_bytes(b"ctxql-reasoning-budget/none/v1"),
            prepared_root: ContentHash::of_bytes(b"ctxql-prepared-ontology/none/v1"),
            materializer: VersionId::new("none/v1")?,
            reasoner: VersionId::new("none/v1")?,
            diagnostics_root: ContentHash::of_bytes(b"ctxql-reasoning-diagnostics/none/v1"),
            completeness_root,
        })
    }
}

/// Exact read-only snapshot surface needed to build the semantic claim projection.
pub trait SemanticProjectionSnapshot: Send + Sync {
    fn identity(&self) -> &SnapshotRef;
    fn export<'a>(
        &'a self,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ExportRecord>>;
}

/// Read-only source for semantic projection. Mutation and admission receipts are
/// deliberately absent. `GraphBackendProjectionSource` keeps legacy backends usable.
pub trait SemanticProjectionSource: Send + Sync {
    fn capabilities(&self) -> Result<SemanticProjectionCapabilities>;
    fn head(&self) -> IoFuture<'_, SnapshotRef>;
    fn capture(&self, requested: Option<Timestamp>) -> IoFuture<'_, CapturedSnapshot>;
    fn open_snapshot<'a>(
        &'a self,
        pin: &'a SnapshotRef,
    ) -> IoFuture<'a, Arc<dyn SemanticProjectionSnapshot>>;
    fn changes<'a>(
        &'a self,
        after: &'a SnapshotRef,
        through: &'a SnapshotRef,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ChangeBatch>>;
    fn subscribe(&self) -> IoFuture<'_, Box<dyn ChangeHintSource>>;
}

/// Compatibility adapter exposing only the read half of an existing `GraphBackend`.
pub struct GraphBackendProjectionSource<B> {
    backend: Arc<B>,
    schema: VersionId,
    algorithm: Iri,
}
impl<B> GraphBackendProjectionSource<B> {
    pub fn new(backend: Arc<B>, schema: VersionId, algorithm: Iri) -> Self {
        Self {
            backend,
            schema,
            algorithm,
        }
    }
}
impl<B: GraphBackend> SemanticProjectionSource for GraphBackendProjectionSource<B> {
    fn capabilities(&self) -> Result<SemanticProjectionCapabilities> {
        let capabilities = GraphBackend::capabilities(self.backend.as_ref())?;
        Ok(SemanticProjectionCapabilities {
            exact_snapshots: capabilities.exact_snapshots,
            ordered_changes: capabilities.ordered_changes,
            closed_cutoff: capabilities.closed_cutoff,
            complete_exports: capabilities.complete_exports,
            schema: self.schema.clone(),
            algorithm: self.algorithm.clone(),
        })
    }
    fn head(&self) -> IoFuture<'_, SnapshotRef> {
        GraphBackend::head(self.backend.as_ref())
    }
    fn capture(&self, requested: Option<Timestamp>) -> IoFuture<'_, CapturedSnapshot> {
        GraphBackend::capture(self.backend.as_ref(), requested)
    }
    fn open_snapshot<'a>(
        &'a self,
        pin: &'a SnapshotRef,
    ) -> IoFuture<'a, Arc<dyn SemanticProjectionSnapshot>> {
        Box::pin(async move {
            let snapshot = GraphBackend::open_snapshot(self.backend.as_ref(), pin).await?;
            Ok(Arc::new(GraphBackendProjectionSnapshot { snapshot })
                as Arc<dyn SemanticProjectionSnapshot>)
        })
    }
    fn changes<'a>(
        &'a self,
        after: &'a SnapshotRef,
        through: &'a SnapshotRef,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ChangeBatch>> {
        GraphBackend::changes(self.backend.as_ref(), after, through, cursor, size)
    }
    fn subscribe(&self) -> IoFuture<'_, Box<dyn ChangeHintSource>> {
        GraphBackend::subscribe(self.backend.as_ref())
    }
}

struct GraphBackendProjectionSnapshot {
    snapshot: Arc<dyn BackendSnapshot>,
}
impl SemanticProjectionSnapshot for GraphBackendProjectionSnapshot {
    fn identity(&self) -> &SnapshotRef {
        self.snapshot.identity()
    }
    fn export<'a>(
        &'a self,
        cursor: Option<&'a PageCursor>,
        size: PageSize,
    ) -> IoFuture<'a, Page<ExportRecord>> {
        self.snapshot.export(cursor, size)
    }
}
/// Complete export assembled with explicit terminal completion. Build adapters still validate records/identity.
#[derive(Clone, Debug)]
pub struct CompleteExport {
    snapshot: SnapshotRef,
    records: Vec<ExportRecord>,
}
impl CompleteExport {
    pub fn collect(
        snapshot: SnapshotRef,
        stream: ResourceId,
        pages: Vec<Page<ExportRecord>>,
        max_records: usize,
    ) -> Result<Self> {
        let mut tracker = PageTracker::new(snapshot.clone(), stream, max_records);
        let mut cursor = None;
        let mut records = vec![];
        for page in pages {
            tracker.accept(cursor.as_ref(), &page)?;
            cursor = page.next().cloned();
            records.extend(page.into_items());
        }
        tracker.finish()?;
        Ok(Self { snapshot, records })
    }
    pub fn snapshot(&self) -> &SnapshotRef {
        &self.snapshot
    }
    pub fn records(&self) -> &[ExportRecord] {
        &self.records
    }
}
pub trait ProjectionStore: Send + Sync {
    fn checkpoint(&self) -> IoFuture<'_, Option<ProjectionCheckpoint>>;
    fn apply<'a>(
        &'a self,
        batch: &'a ChangeBatch,
        checkpoint: &'a ProjectionCheckpoint,
    ) -> IoFuture<'a, ()>;
    fn build<'a>(
        &'a self,
        export: &'a CompleteExport,
        checkpoint: &'a ProjectionCheckpoint,
    ) -> IoFuture<'a, ()>;
    fn open_view<'a>(&'a self, snapshot: &'a SnapshotRef) -> IoFuture<'a, Arc<dyn RawQueryView>>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Outgoing,
    Incoming,
    Both,
}
/// Synchronous exact raw view. It is not an authorized endpoint or traversal
/// engine. The default claim capability is unprivileged; a bounded E0 adapter
/// may attest only claims already authorized at this exact snapshot.
pub trait RawQueryView: Send + Sync {
    fn identity(&self) -> &SnapshotRef;
    fn claim(&self, id: &ClaimId) -> Result<Option<AdmittedClaim>>;
    fn claim_is_pre_authorized(&self, _id: &ClaimId) -> bool {
        false
    }
    fn entity(&self, id: &EntityId) -> Result<Option<Vec<DependencyRecord>>>;
    fn incident(
        &self,
        id: &EntityId,
        direction: Direction,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<AdmittedClaim>>;
    fn resource(&self, id: &ResourceId) -> Result<Option<DependencyRecord>>;
    fn lifecycle(
        &self,
        id: &ClaimId,
        size: PageSize,
        cursor: Option<&PageCursor>,
    ) -> Result<Page<ExportRecord>>;
}
/// Implementors issue private issuer-bound handles; no Serialize/Deserialize requirement.
/// Context must be current and separate from a historical data view. Every authority write invalidates it.
pub trait PolicyService: Send + Sync {
    type Principal: Send + Sync;
    type Context: Send + Sync;
    fn current<'a>(&'a self, principal: &'a Self::Principal) -> IoFuture<'a, Self::Context>;
    fn resource_allowed(&self, context: &Self::Context, resource: &ResourceId) -> Result<bool>;
    fn fact_allowed(
        &self,
        context: &Self::Context,
        resource: &ResourceId,
        predicate: &Iri,
    ) -> Result<bool>;
    /// Refresh and publish while holding the SAME gate as every mutation. Sink must be bounded/non-reentrant.
    fn publish<'a>(
        &'a self,
        principal: &'a Self::Principal,
        context: &'a Self::Context,
        sink: &'a mut (dyn FnMut() -> Result<()> + Send),
    ) -> IoFuture<'a, ()>;
}
pub trait SourceReader: Send + Sync {
    fn read<'a>(&'a self, request: &'a SourceReadRequest) -> IoFuture<'a, SourceRead>;
    /// Read an exact evidence reference and verify every supported selector
    /// witness against the retained source representation before release.
    fn read_reference<'a>(
        &'a self,
        source: &'a crate::evidence::SourceReference,
        max_bytes: usize,
    ) -> IoFuture<'a, SourceRead>;
}
pub trait CandidateExtractor: Send + Sync {
    fn extract<'a>(
        &'a self,
        request: &'a ExtractionRequest,
        limits: Limits,
    ) -> IoFuture<'a, ExtractionResult>;
}
pub trait AuthorizedSelectorResolver: Send + Sync {
    type Authorization: Send + Sync;
    fn resolve<'a>(
        &'a self,
        authorization: &'a Self::Authorization,
        request: &'a SourceReadRequest,
    ) -> IoFuture<'a, SourceRead>;
}
pub trait ArtifactRepository: Send + Sync {
    fn publish<'a>(&'a self, artifact: &'a PublishedArtifact) -> IoFuture<'a, ArtifactRef>;
    fn lookup<'a>(&'a self, reference: &'a ArtifactRef) -> IoFuture<'a, Option<PublishedArtifact>>;
    fn record_run<'a>(&'a self, run: &'a ExecutionRun) -> IoFuture<'a, ()>;
    fn run<'a>(&'a self, id: &'a RunId) -> IoFuture<'a, Option<ExecutionRun>>;
    fn record_assembly<'a>(&'a self, invocation: &'a AssemblyInvocation) -> IoFuture<'a, ()>;
}
