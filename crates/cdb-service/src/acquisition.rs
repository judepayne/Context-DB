//! Foreground trusted-acquisition composition, separate from the query service.

use crate::{
    acquisition_checkpoints::WorkCheckpoints,
    config::{AcquisitionAccessMode, InstanceConfig},
    graph_query::{GraphQueryHost, GraphQueryLimits},
    graph_session::GraphSession,
};
use cdb_backend_fluree::{
    acquisition_catalog::CertifiedOntologyCatalog,
    semantic_policy::resolve_current_semantic_authority,
    semantic_preparation::{prepare_current_authorized_view, ExtractionLimits},
    FlureeAcquisitionControl, FlureeBackend, FlureeControlLedger, FlureeSemanticLedger,
    FlureeSemanticWriter, SemanticWriterOptions,
};
use cdb_core::acquisition::{
    AcquisitionControl, AdmissionRecovery, BundlePrepared, ProjectionObserver,
    ReviewAdmissionRecovery, SemanticBundleWriter, SourceObjectReader, SourceObjectWriter,
};
use cdb_core::artifact::ArtifactRef;
use cdb_core::contracts::{PolicyService, SemanticProjectionSource};
use cdb_core::id::{AttemptId, ContentHash, Iri, JobId, PrincipalId, VersionId};
use cdb_core::ontology_catalog::OntologyCatalogIdentity;
use cdb_core::review::{ReviewAdmissionReceipt, ReviewBundlePrepared, ValidatedReviewBundle};
use cdb_core::semantic_admission::{
    ProjectionReceipt, SemanticAdmissionReceipt, ValidatedSemanticBundle,
};
use cdb_core::snapshot::ProjectionCheckpoint;
use cdb_core::{CanonicalValue, Error, ErrorKind, Result, Timestamp};
use cdb_projection_redb::{
    Coordinator, CoordinatorOptions, GenerationOptions, RedbProjection, RedbProjectionObserver,
};
use cdb_source_store::{
    SourceObjectReader as FileSourceReader, SourceObjectWriter as FileSourceWriter,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitPoint {
    Admitted,
    Projected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredAdmission {
    bundle_id: cdb_core::id::BundleId,
    receipt: SemanticAdmissionReceipt,
}
impl RecoveredAdmission {
    pub fn receipt(&self) -> &SemanticAdmissionReceipt {
        &self.receipt
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionOutcome {
    pub admission: SemanticAdmissionReceipt,
    pub projection: Option<ProjectionReceipt>,
}

fn require_dedicated_review_role(
    configured_review_graph: &str,
    ledger_review_graphs: &BTreeSet<String>,
) -> Result<()> {
    if ledger_review_graphs != &BTreeSet::from([configured_review_graph.to_owned()]) {
        return Err(Error::invalid(
            "acquisition review graph must be the ledger's dedicated review graph role",
        ));
    }
    Ok(())
}

/// One explicit admission context is required for every business admission.
/// Graph-enabled extraction must carry its session; callers cannot select a
/// parallel admission implementation that omits retained-context checks.
#[allow(dead_code)] // Graph variant is activated by the Phase 2 provider wiring.
pub(crate) enum AdmissionContext {
    NoGraph,
    Graph(Arc<GraphSession>),
    Administrative(Box<AdministrativeAdmission>),
}

/// Additional current Control authority for administrator-only imports. Only
/// the Semantic writer runs inside this guard: Control journal writes must stay
/// outside it to avoid recursively acquiring the Control mutation gate.
pub(crate) struct AdministrativeAdmission {
    pub backend: Arc<FlureeBackend>,
    pub principal: cdb_backend_fluree::policy::FlureePrincipal,
    pub context: cdb_backend_fluree::policy::FlureePolicyContext,
    pub fence: Box<dyn cdb_backend_fluree::runs::ExternalPublicationFence>,
}

/// This type alone receives mutation capabilities. `Service` does not contain,
/// construct, or expose it.
pub struct AcquisitionService {
    pub source_reader: Arc<dyn SourceObjectReader>,
    pub source_writer: Arc<dyn SourceObjectWriter>,
    ontology_catalog: OntologyCatalogIdentity,
    semantic: Arc<FlureeSemanticLedger>,
    semantic_principal: String,
    semantic_action: String,
    pub(crate) semantic_writer: Arc<FlureeSemanticWriter>,
    pub(crate) authority: Arc<FlureeBackend>,
    pub(crate) control: Arc<dyn AcquisitionControl>,
    pub(crate) projection: Arc<dyn ProjectionObserver>,
    pub(crate) work: WorkCheckpoints,
    pub(crate) artifact_limit: usize,
    pub(crate) artifact_page_limit: usize,
    prior_admissions: BTreeMap<JobId, Vec<RecoveredAdmission>>,
    prior_jobs: BTreeSet<JobId>,
    #[allow(dead_code)] // Phase 1 read capability; wired into ingestion in Phase 2.
    projection_store: Arc<RedbProjection>,
    coordinator: Option<Arc<Coordinator>>,
}
impl AcquisitionService {
    pub async fn open(
        config: &InstanceConfig,
        ontology_catalog: OntologyCatalogIdentity,
    ) -> Result<Arc<Self>> {
        config.validate_runtime()?;
        let acquisition = config
            .acquisition
            .as_ref()
            .ok_or_else(|| Error::invalid("trusted acquisition configuration required"))?
            .clone();
        if acquisition.access_mode != AcquisitionAccessMode::Direct {
            return Err(Error::invalid("unsupported semantic access mode"));
        }
        if ontology_catalog.profile_identity() != acquisition.ontology_profile
            || ontology_catalog.catalog_root().as_str() != acquisition.ontology_catalog_root
        {
            return Err(Error::invalid("configured ontology catalog"));
        }
        let (semantic_path, semantic_options) = config.semantic_binding()?;
        let semantic_path = semantic_path.to_path_buf();
        let semantic = Arc::new(
            FlureeSemanticLedger::open_file(&semantic_path, semantic_options.clone()).await?,
        );
        let authority = resolve_current_semantic_authority(
            semantic.as_ref(),
            &acquisition.principal,
            &acquisition.action,
        )
        .await
        .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        if let Some(review_graph) = acquisition.review_graph.as_deref() {
            let prepared = prepare_current_authorized_view(
                semantic.as_ref(),
                &acquisition.principal,
                &acquisition.action,
                ExtractionLimits::default(),
            )
            .await
            .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
            require_dedicated_review_role(review_graph, &prepared.review_graphs)?;
        }
        let writer = Arc::new(
            FlureeSemanticWriter::open_file(
                &semantic_path,
                SemanticWriterOptions {
                    reader: semantic_options,
                    claims_graph: Iri::new(&acquisition.claims_graph)?,
                    review_graph: Iri::new(
                        acquisition
                            .review_graph
                            .as_deref()
                            .unwrap_or("urn:ctxql:acquisition-review:v1"),
                    )?,
                    codec_limits: Default::default(),
                    review_codec_limits: Default::default(),
                    extraction_limits: Default::default(),
                    authority: authority.basis,
                },
            )
            .await?,
        );
        writer.verify_catalog_identity(&ontology_catalog).await?;
        let control_ledger = FlureeControlLedger::open(config.authority_options()?)
            .await
            .map_err(|error| Error::new(ErrorKind::Backend, error.to_string()))?;
        let authority = control_ledger.backend().clone();
        let control = Arc::new(FlureeAcquisitionControl::open(
            &control_ledger,
            acquisition.control_journal_bytes,
        )?);
        for prepared in control.review_prepared_records().await? {
            if let Some(receipt) = control.review_admission(&prepared.bundle_id).await? {
                receipt.verify_prepared(&prepared)?;
                continue;
            }
            if control
                .superseded_absent(&prepared.bundle_id)
                .await?
                .is_some()
            {
                continue;
            }
            match writer.recover_review(&prepared).await? {
                ReviewAdmissionRecovery::Exact(receipt) => {
                    control
                        .append_review_admission(&prepared.bundle_id, &receipt)
                        .await?;
                }
                ReviewAdmissionRecovery::Absent => {}
                ReviewAdmissionRecovery::Conflict => {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "review admission history conflict",
                    ))
                }
            }
        }
        recover_unfinished(control.as_ref(), writer.as_ref()).await?;
        let work = WorkCheckpoints::open(
            &config
                .control
                .as_ref()
                .ok_or_else(|| Error::invalid("Control configuration required"))?
                .path,
            acquisition.control_journal_bytes,
        )?;
        let (prior_jobs, prior_admissions) = collect_prior_jobs(control.as_ref()).await?;
        let source_reader = Arc::new(FileSourceReader::open(
            config.source_root.clone(),
            acquisition.max_source_bytes,
        )?);
        let source_writer = Arc::new(FileSourceWriter::open(
            config.source_root.clone(),
            acquisition.max_source_bytes,
        )?);
        let pin = SemanticProjectionSource::head(semantic.as_ref()).await?;
        let binding = ProjectionCheckpoint::new(
            pin,
            VersionId::new("ctxql-semantic-rdf/v1")?,
            VersionId::new("live")?,
            Iri::new("urn:ctxql:semantic-projection:v1")?,
        )?;
        let projection = Arc::new(
            RedbProjection::open(
                &config.projection,
                binding.clone(),
                GenerationOptions::default(),
            )
            .await?,
        );
        let coordinator = Arc::new(Coordinator::start(
            semantic.clone(),
            projection.clone(),
            binding,
            CoordinatorOptions::default(),
        )?);
        let observer = Arc::new(RedbProjectionObserver::new(
            coordinator.clone(),
            std::time::Duration::from_secs(acquisition.projection_timeout_seconds as u64),
        )?);
        Ok(Arc::new(Self {
            source_reader,
            source_writer,
            ontology_catalog,
            semantic,
            semantic_principal: acquisition.principal,
            semantic_action: acquisition.action,
            semantic_writer: writer,
            authority,
            control,
            work,
            artifact_limit: acquisition.max_source_bytes,
            artifact_page_limit: acquisition.max_source_bytes.min(config.limits.run_bytes),
            projection: observer,
            prior_admissions,
            prior_jobs,
            projection_store: projection,
            coordinator: Some(coordinator),
        }))
    }

    pub fn ontology_catalog(&self) -> &OntologyCatalogIdentity {
        &self.ontology_catalog
    }

    /// Construct a read-only graph-query capability from this service's existing
    /// Semantic reader, Control authority, projection and coordinator. No writer
    /// or raw redb provider crosses the boundary.
    #[allow(dead_code)] // Phase 1 seam; Phase 2 supplies the configured artifacts.
    pub(crate) async fn graph_query_host(
        &self,
        config: ArtifactRef,
        profile: Option<(String, ArtifactRef)>,
        limits: GraphQueryLimits,
    ) -> Result<Arc<GraphQueryHost>> {
        GraphQueryHost::prepare(
            self.semantic.clone(),
            self.semantic_writer.clone(),
            self.authority.clone(),
            self.projection_store.clone(),
            self.coordinator
                .as_ref()
                .ok_or_else(|| {
                    Error::new(ErrorKind::Backend, "projection coordinator unavailable")
                })?
                .clone(),
            PrincipalId::new(&self.semantic_principal)?,
            self.semantic_action.clone(),
            config,
            profile,
            limits,
        )
        .await
    }

    pub(crate) async fn recheck_classification_supports(
        &self,
        claims: &[cdb_core::claim::CandidateClaim],
    ) -> Result<()> {
        use cdb_core::classification::{
            ClassificationMetadata, ClassificationOrigin, EXTENSION_KEY, RDF_TYPE,
        };
        let mut required = BTreeSet::new();
        for claim in claims {
            let Ok(value) = claim.ext().field(EXTENSION_KEY) else {
                continue;
            };
            let metadata = ClassificationMetadata::from_value(value)?;
            let object_id = match claim.object() {
                cdb_core::claim::ClaimObject::Entity(id) => Some(id.as_str()),
                _ => None,
            };
            for (id, endpoint) in [
                (Some(claim.subject().as_str()), metadata.subject()),
                (object_id, metadata.object()),
            ] {
                for class in endpoint
                    .classes()
                    .iter()
                    .filter(|class| class.origin() == ClassificationOrigin::Established)
                {
                    required.insert((
                        id.ok_or_else(|| Error::invalid("literal established classification"))?
                            .to_owned(),
                        class.iri().as_str().to_owned(),
                        class.reference().as_str().to_owned(),
                    ));
                }
            }
        }
        if required.is_empty() {
            return Ok(());
        }
        let current = prepare_current_authorized_view(
            &self.semantic,
            &self.semantic_principal,
            &self.semantic_action,
            ExtractionLimits::default(),
        )
        .await
        .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        for record in &current.authorized_claims {
            let Some(claim) = record.claim() else {
                continue;
            };
            let candidate = claim.candidate();
            if candidate.relation().as_str() != RDF_TYPE {
                continue;
            }
            if let cdb_core::claim::ClaimObject::Entity(class) = candidate.object() {
                required.remove(&(
                    candidate.subject().as_str().to_owned(),
                    class.as_str().to_owned(),
                    claim.id().as_str().to_owned(),
                ));
            }
        }
        if !required.is_empty() {
            return Err(Error::new(
                ErrorKind::Denied,
                "established classification support unavailable",
            ));
        }
        Ok(())
    }

    pub async fn current_catalog(&self) -> Result<CertifiedOntologyCatalog> {
        let prepared = prepare_current_authorized_view(
            &self.semantic,
            &self.semantic_principal,
            &self.semantic_action,
            ExtractionLimits::default(),
        )
        .await
        .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        CertifiedOntologyCatalog::from_prepared(&prepared, self.semantic.options())
    }

    pub fn prior_admissions(&self, job: &JobId) -> &[RecoveredAdmission] {
        self.prior_admissions
            .get(job)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// A prepared record means provider output may already have been admitted.
    /// Without a durable candidate checkpoint, re-extraction must fail closed.
    pub fn has_prior_job(&self, job: &JobId) -> bool {
        self.prior_jobs.contains(job)
    }

    pub async fn complete_recovered(
        &self,
        recovered: &RecoveredAdmission,
        wait: WaitPoint,
    ) -> Result<()> {
        if wait == WaitPoint::Projected {
            let projection = self.projection.wait_exact(&recovered.receipt).await?;
            self.control
                .append_projection(&recovered.bundle_id, &projection)
                .await?;
        }
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        if let Some(coordinator) = &self.coordinator {
            coordinator.shutdown_shared().await?;
        }
        Ok(())
    }

    /// Persist review metadata before dependent business claims. Review writes
    /// share the writer's lease and serialization lock with claim admission.
    pub async fn admit_review(
        &self,
        bundle: &ValidatedReviewBundle,
    ) -> Result<ReviewAdmissionReceipt> {
        let prepared = ReviewBundlePrepared::new(
            JobId::new(bundle.logical_bundle_key())?,
            bundle,
            Timestamp::from_millis(0)?,
        );
        if let Some(receipt) = self.control.review_admission(bundle.id()).await? {
            receipt.verify_prepared(&prepared)?;
            return Ok(receipt);
        }
        self.source_writer
            .put(
                &bundle
                    .projection()
                    .canonical_bytes(cdb_core::Limits::default())?,
                self.artifact_limit,
            )
            .await?;
        self.control.append_review_prepared(&prepared).await?;
        let receipt = self
            .semantic_writer
            .recover_or_admit_review(&prepared, bundle)
            .await?;
        self.control
            .append_review_admission(bundle.id(), &receipt)
            .await?;
        Ok(receipt)
    }

    /// Codec/history checks only; it does not mutate source, Control,
    /// Semantic, projection, report, or log stores.
    pub async fn dry_run(&self, bundle: &ValidatedSemanticBundle) -> Result<()> {
        self.semantic_writer.preflight(bundle).await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn admit_foreground(
        &self,
        job_id: JobId,
        attempt_id: AttemptId,
        bundle: &ValidatedSemanticBundle,
        source_selector_root: ContentHash,
        safe_counts: CanonicalValue,
        recorded_at: Timestamp,
        wait: WaitPoint,
        context: AdmissionContext,
    ) -> Result<AcquisitionOutcome> {
        // A graph-backed flow must prove current access before even recording a
        // new business preparation. The final Semantic mutation is fenced again
        // below, so revocation after this check can leave only a recoverable
        // prepared record, never an unauthorized business claim.
        if let AdmissionContext::Graph(session) = &context {
            session.authorize_final_release().await?;
        }
        if let AdmissionContext::Administrative(guard) = &context {
            guard.fence.check()?;
            let current = guard.backend.current(&guard.principal).await?;
            guard
                .backend
                .require_operation(&current, cdb_backend_fluree::runs::Operation::Admin)?;
        }
        if let Some(receipt) = self.control.admission(bundle.id()).await? {
            verify_receipt(bundle, &receipt)?;
            return self.finish(bundle, receipt, wait).await;
        }
        self.semantic_writer.preflight(bundle).await?;
        let prepared = BundlePrepared {
            job_id,
            attempt_id,
            bundle_id: bundle.id().clone(),
            admission_key: bundle.admission_key().as_str().to_owned(),
            descriptor_root: bundle.descriptor_root().clone(),
            payload_root: bundle.payload_root().clone(),
            canonical_claim_root: bundle.canonical_claim_root().clone(),
            expected_claim_ids: bundle.expected_claim_ids(),
            validation_capture: bundle.validation_capture().clone(),
            source_selector_root,
            safe_counts,
            recorded_at,
        };
        prepared.validate()?;
        let prepared = if let Some(existing) = self.control.prepared(bundle.id()).await? {
            if !same_prepared_request(&existing, &prepared) {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "prepared admission request differs",
                ));
            }
            existing
        } else {
            self.control.append_prepared(&prepared).await?;
            prepared
        };
        let receipt =
            match context {
                AdmissionContext::NoGraph => {
                    self.semantic_writer
                        .recover_or_admit(&prepared, bundle)
                        .await?
                }
                AdmissionContext::Administrative(guard) => {
                    let writer = self.semantic_writer.clone();
                    let prepared = prepared.clone();
                    let bundle = bundle.clone();
                    guard.backend.guarded_owned_action(
                    guard.principal,
                    guard.context,
                    cdb_backend_fluree::runs::Operation::Admin,
                    guard.fence,
                    move || async move { writer.recover_or_admit(&prepared, &bundle).await },
                ).await?
                }
                AdmissionContext::Graph(session) => {
                    let writer = self.semantic_writer.clone();
                    let principal = self.semantic_principal.clone();
                    let action = self.semantic_action.clone();
                    let basis = writer.authority_basis().clone();
                    let prepared_for_guard = prepared.clone();
                    let bundle_for_guard = bundle.clone();
                    session
                        .guarded_final_action(move |supports| async move {
                            writer
                                .recover_or_admit_with_disclosure(
                                    &principal,
                                    &action,
                                    &basis,
                                    &supports,
                                    &prepared_for_guard,
                                    &bundle_for_guard,
                                )
                                .await
                        })
                        .await?
                }
            };
        verify_receipt(bundle, &receipt)?;
        self.control.append_admission(bundle.id(), &receipt).await?;
        self.finish(bundle, receipt, wait).await
    }

    /// Receipt-first restart recovery. Run this before source conversion or
    /// provider work. `None` means either no prepared record exists or exact
    /// history proves the admission absent and the immutable payload must be
    /// reconstructed; an exact lost acknowledgement is finalized in Control.
    pub async fn recover_prepared(
        &self,
        bundle_id: &cdb_core::id::BundleId,
    ) -> Result<Option<SemanticAdmissionReceipt>> {
        if let Some(receipt) = self.control.admission(bundle_id).await? {
            return Ok(Some(receipt));
        }
        let Some(prepared) = self.control.prepared(bundle_id).await? else {
            return Ok(None);
        };
        match self.semantic_writer.recover(&prepared).await? {
            AdmissionRecovery::Exact(receipt) => {
                let receipt = *receipt;
                self.control.append_admission(bundle_id, &receipt).await?;
                Ok(Some(receipt))
            }
            AdmissionRecovery::Absent => Ok(None),
            AdmissionRecovery::Conflict => Err(Error::new(
                ErrorKind::Conflict,
                "semantic admission history conflict",
            )),
        }
    }

    async fn finish(
        &self,
        bundle: &ValidatedSemanticBundle,
        admission: SemanticAdmissionReceipt,
        wait: WaitPoint,
    ) -> Result<AcquisitionOutcome> {
        let projection = if wait == WaitPoint::Projected {
            let receipt = self.projection.wait_exact(&admission).await?;
            self.control
                .append_projection(bundle.id(), &receipt)
                .await?;
            Some(receipt)
        } else {
            None
        };
        Ok(AcquisitionOutcome {
            admission,
            projection,
        })
    }
}

pub async fn load_current_catalog(config: &InstanceConfig) -> Result<CertifiedOntologyCatalog> {
    config.validate_runtime()?;
    let acquisition = config
        .acquisition
        .as_ref()
        .ok_or_else(|| Error::invalid("trusted acquisition configuration required"))?;
    let (semantic_path, semantic_options) = config.semantic_binding()?;
    let semantic = FlureeSemanticLedger::open_file(semantic_path, semantic_options.clone()).await?;
    let prepared = prepare_current_authorized_view(
        &semantic,
        &acquisition.principal,
        &acquisition.action,
        ExtractionLimits::default(),
    )
    .await
    .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
    CertifiedOntologyCatalog::from_prepared(&prepared, &semantic_options)
}

async fn collect_prior_jobs(
    control: &dyn AcquisitionControl,
) -> Result<(BTreeSet<JobId>, BTreeMap<JobId, Vec<RecoveredAdmission>>)> {
    let mut prior_admissions = BTreeMap::<JobId, Vec<RecoveredAdmission>>::new();
    let mut prior_jobs = BTreeSet::new();
    for prepared in control.prepared_records().await? {
        prior_jobs.insert(prepared.job_id.clone());
        if let Some(receipt) = control.admission(&prepared.bundle_id).await? {
            verify_prepared_receipt(&prepared, &receipt)?;
            prior_admissions
                .entry(prepared.job_id)
                .or_default()
                .push(RecoveredAdmission {
                    bundle_id: prepared.bundle_id,
                    receipt,
                });
        }
    }
    Ok((prior_jobs, prior_admissions))
}

async fn recover_unfinished(
    control: &dyn AcquisitionControl,
    writer: &dyn SemanticBundleWriter,
) -> Result<BTreeMap<JobId, Vec<RecoveredAdmission>>> {
    let mut recovered = BTreeMap::<JobId, Vec<RecoveredAdmission>>::new();
    for prepared in control.prepared_records().await? {
        if let Some(receipt) = control.admission(&prepared.bundle_id).await? {
            verify_prepared_receipt(&prepared, &receipt)?;
            continue;
        }
        if control
            .superseded_absent(&prepared.bundle_id)
            .await?
            .is_some()
        {
            continue;
        }
        match writer.recover(&prepared).await? {
            AdmissionRecovery::Exact(receipt) => {
                let receipt = *receipt;
                verify_prepared_receipt(&prepared, &receipt)?;
                control
                    .append_admission(&prepared.bundle_id, &receipt)
                    .await?;
                recovered
                    .entry(prepared.job_id.clone())
                    .or_default()
                    .push(RecoveredAdmission {
                        bundle_id: prepared.bundle_id.clone(),
                        receipt,
                    });
            }
            AdmissionRecovery::Absent => {}
            AdmissionRecovery::Conflict => {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "semantic admission history conflict",
                ));
            }
        }
    }
    Ok(recovered)
}

fn same_prepared_request(left: &BundlePrepared, right: &BundlePrepared) -> bool {
    left.job_id == right.job_id
        && left.attempt_id == right.attempt_id
        && left.bundle_id == right.bundle_id
        && left.admission_key == right.admission_key
        && left.descriptor_root == right.descriptor_root
        && left.payload_root == right.payload_root
        && left.canonical_claim_root == right.canonical_claim_root
        && left.expected_claim_ids == right.expected_claim_ids
        && left.validation_capture == right.validation_capture
        && left.source_selector_root == right.source_selector_root
        && left.safe_counts == right.safe_counts
}

fn verify_prepared_receipt(
    prepared: &BundlePrepared,
    receipt: &SemanticAdmissionReceipt,
) -> Result<()> {
    if receipt.admission_key().as_str() != prepared.admission_key
        || receipt.payload_root() != &prepared.payload_root
        || receipt.claim_ids() != prepared.expected_claim_ids
    {
        return Err(Error::new(
            ErrorKind::Conflict,
            "foreign semantic admission receipt",
        ));
    }
    Ok(())
}

fn verify_receipt(
    bundle: &ValidatedSemanticBundle,
    receipt: &SemanticAdmissionReceipt,
) -> Result<()> {
    if receipt.admission_key() != bundle.admission_key()
        || receipt.payload_root() != bundle.payload_root()
        || receipt.claim_ids() != bundle.expected_claim_ids()
    {
        return Err(Error::new(
            ErrorKind::Conflict,
            "foreign semantic admission receipt",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires CDB_ACQUISITION_OPEN_CONFIG"]
    async fn configured_acquisition_service_opens() {
        let path = std::env::var("CDB_ACQUISITION_OPEN_CONFIG").unwrap();
        let config = InstanceConfig::load(std::path::Path::new(&path)).unwrap();
        let catalog = load_current_catalog(&config).await.unwrap();
        AcquisitionService::open(&config, catalog.identity().clone())
            .await
            .unwrap();
    }
    use cdb_core::{
        contracts::IoFuture,
        id::{
            AuthorityId, BackendId, BundleId, ClaimId, ExtractionRunId, GraphId, IdempotencyKey,
            ResourceId,
        },
        snapshot::{GraphPin, SnapshotRef},
    };
    use std::sync::Mutex;

    fn graph_workspace_claim() -> cdb_core::claim::CandidateClaim {
        let mut value = CanonicalValue::parse(
            br#"{"claim_id":"urn:ctxql:claim:v2:placeholder","claim_type":"urn:type:claim","confidence":1,"ext":{"ctxql.acquisition.v2/claim_identity":"stable-component/v1","ctxql.acquisition.v2/component_ref":"window:graph#attribute:amount"},"grounding_level":"claim_only","lineage":{"schema":"ctxql.lineage.v1","sources":[]},"object_id":{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#integer","value":42,"language":null},"object_type":"http://www.w3.org/2001/XMLSchema#integer","relation":"urn:relation:count","relation_type":"urn:type:relation","subject_id":"urn:subject:graph","subject_type":"urn:type:entity"}"#,
            cdb_core::Limits::default(),
        )
        .unwrap();
        let provisional = cdb_core::claim::CandidateClaim::from_value(&value).unwrap();
        let id = cdb_core::semantic_admission::stable_acquisition_v2_claim_id(
            &provisional,
            cdb_core::Limits::default(),
        )
        .unwrap();
        let CanonicalValue::Object(fields) = &mut value else {
            unreachable!()
        };
        fields.insert("claim_id".into(), CanonicalValue::string(id.as_str()));
        cdb_core::claim::CandidateClaim::from_value(&value).unwrap()
    }

    fn graph_workspace_guarded_claim() -> cdb_core::claim::CandidateClaim {
        let mut value = CanonicalValue::parse(
            br#"{"claim_id":"urn:ctxql:claim:v2:placeholder","claim_type":"urn:type:claim","confidence":1,"ext":{"ctxql.acquisition.v2/claim_identity":"stable-component/v1","ctxql.acquisition.v2/component_ref":"window:graph#attribute:guarded"},"grounding_level":"claim_only","lineage":{"schema":"ctxql.lineage.v1","sources":[]},"object_id":{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#integer","value":7,"language":null},"object_type":"http://www.w3.org/2001/XMLSchema#integer","relation":"urn:relation:guarded","relation_type":"urn:type:relation","subject_id":"urn:subject:guarded","subject_type":"urn:type:entity"}"#,
            cdb_core::Limits::default(),
        )
        .unwrap();
        let provisional = cdb_core::claim::CandidateClaim::from_value(&value).unwrap();
        let id = cdb_core::semantic_admission::stable_acquisition_v2_claim_id(
            &provisional,
            cdb_core::Limits::default(),
        )
        .unwrap();
        let CanonicalValue::Object(fields) = &mut value else {
            unreachable!()
        };
        fields.insert("claim_id".into(), CanonicalValue::string(id.as_str()));
        cdb_core::claim::CandidateClaim::from_value(&value).unwrap()
    }

    fn graph_workspace_supersession(
        target: &ClaimId,
    ) -> (
        cdb_core::claim::CandidateClaim,
        cdb_core::claim::CandidateClaim,
    ) {
        let stable = |mut value: CanonicalValue| {
            let provisional = cdb_core::claim::CandidateClaim::from_value(&value).unwrap();
            let id = cdb_core::semantic_admission::stable_acquisition_v2_claim_id(
                &provisional,
                cdb_core::Limits::default(),
            )
            .unwrap();
            let CanonicalValue::Object(fields) = &mut value else {
                unreachable!()
            };
            fields.insert("claim_id".into(), CanonicalValue::string(id.as_str()));
            cdb_core::claim::CandidateClaim::from_value(&value).unwrap()
        };
        let replacement = stable(
            CanonicalValue::parse(
                br#"{"claim_id":"urn:ctxql:claim:v2:replacement","claim_type":"urn:type:claim","confidence":1,"ext":{"ctxql.acquisition.v2/claim_identity":"stable-component/v1","ctxql.acquisition.v2/component_ref":"window:graph#attribute:replacement"},"grounding_level":"claim_only","lineage":{"schema":"ctxql.lineage.v1","sources":[]},"object_id":{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#integer","value":43,"language":null},"object_type":"http://www.w3.org/2001/XMLSchema#integer","relation":"urn:relation:count","relation_type":"urn:type:relation","subject_id":"urn:subject:graph","subject_type":"urn:type:entity"}"#,
                cdb_core::Limits::default(),
            )
            .unwrap(),
        );
        let lifecycle = stable(
            CanonicalValue::object([
                (
                    "claim_id".into(),
                    CanonicalValue::string("urn:ctxql:claim:v2:lifecycle"),
                ),
                (
                    "claim_type".into(),
                    CanonicalValue::string("urn:type:claim"),
                ),
                (
                    "confidence".into(),
                    CanonicalValue::parse(b"1", cdb_core::Limits::default()).unwrap(),
                ),
                (
                    "ext".into(),
                    CanonicalValue::object([
                        (
                            "ctxql.acquisition.v2/claim_identity".into(),
                            CanonicalValue::string("stable-component/v1"),
                        ),
                        (
                            "ctxql.acquisition.v2/component_ref".into(),
                            CanonicalValue::string("window:graph#lifecycle:supersession"),
                        ),
                    ])
                    .unwrap(),
                ),
                (
                    "grounding_level".into(),
                    CanonicalValue::string("claim_only"),
                ),
                (
                    "lineage".into(),
                    CanonicalValue::object([
                        ("schema".into(), CanonicalValue::string("ctxql.lineage.v1")),
                        ("sources".into(), CanonicalValue::Array(vec![])),
                    ])
                    .unwrap(),
                ),
                (
                    "object_id".into(),
                    CanonicalValue::string(replacement.id().as_str()),
                ),
                (
                    "object_type".into(),
                    CanonicalValue::string("urn:type:claim"),
                ),
                (
                    "relation".into(),
                    CanonicalValue::string("ctxql:superseded_by"),
                ),
                (
                    "relation_type".into(),
                    CanonicalValue::string("urn:type:relation"),
                ),
                ("subject_id".into(), CanonicalValue::string(target.as_str())),
                (
                    "subject_type".into(),
                    CanonicalValue::string("urn:type:claim"),
                ),
            ])
            .unwrap(),
        );
        (replacement, lifecycle)
    }

    #[tokio::test]
    async fn administrative_admission_rechecks_fence_at_semantic_write() {
        use crate::acquisition_v2_fixture::AcquisitionV2Fixture;
        use cdb_backend_fluree::runs::ExternalPublicationFence;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Fence(AtomicUsize);
        impl ExternalPublicationFence for Fence {
            fn check(&self) -> Result<()> {
                if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::Denied,
                        "test authority revoked after preflight",
                    ))
                }
            }
        }
        let fixture = AcquisitionV2Fixture::create().await.unwrap();
        let config = fixture.config().unwrap();
        let acquisition = AcquisitionService::open(&config, fixture.catalog_identity().clone())
            .await
            .unwrap();
        let principal = acquisition
            .authority
            .issue_principal(
                PrincipalId::new(config.acquisition.as_ref().unwrap().principal.clone()).unwrap(),
            )
            .await
            .unwrap();
        let context = acquisition.authority.current(&principal).await.unwrap();
        let capture = SemanticProjectionSource::head(acquisition.semantic.as_ref())
            .await
            .unwrap();
        let bundle = ValidatedSemanticBundle::new(
            BundleId::new("bundle:admin-fence-seed").unwrap(),
            ExtractionRunId::new("extraction:admin-fence-seed").unwrap(),
            capture.clone(),
            CanonicalValue::object([(
                "schema".into(),
                CanonicalValue::string("ctxql-test-admin-seed/v1"),
            )])
            .unwrap(),
            vec![("v2:admin-fence-seed".into(), graph_workspace_claim())],
            cdb_core::Limits::default(),
        )
        .unwrap();
        let error = acquisition
            .admit_foreground(
                JobId::new("job:admin-fence-seed").unwrap(),
                AttemptId::new("attempt:admin-fence-seed").unwrap(),
                &bundle,
                ContentHash::of_bytes(b"admin seed selectors"),
                CanonicalValue::object([]).unwrap(),
                Timestamp::from_millis(1).unwrap(),
                WaitPoint::Admitted,
                AdmissionContext::Administrative(Box::new(AdministrativeAdmission {
                    backend: acquisition.authority.clone(),
                    principal,
                    context,
                    fence: Box::new(Fence(AtomicUsize::new(0))),
                })),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Denied);
        assert_eq!(
            SemanticProjectionSource::head(acquisition.semantic.as_ref())
                .await
                .unwrap(),
            capture
        );
        assert!(acquisition
            .control
            .prepared(bundle.id())
            .await
            .unwrap()
            .is_some());
        assert!(acquisition
            .control
            .admission(bundle.id())
            .await
            .unwrap()
            .is_none());
        acquisition.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn graph_workspace_phase_one_exit_uses_one_acquisition_composition() {
        use crate::{
            acquisition_v2_fixture::AcquisitionV2Fixture,
            graph_query::GraphQueryLimits,
            graph_session::{GraphSession, SessionQueryResult},
            graph_workspace::{
                ApplyRequest, Edit, EndpointRef, RecordRef, ReferenceStatus, TypedLiteral,
                ViewKind, WorkspaceLimits,
            },
            Service,
        };
        use cdb_core::{
            artifact::ArtifactRef,
            contracts::{GraphBackend, SemanticProjectionSource},
            id::PrincipalId,
        };
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};

        let fixture = AcquisitionV2Fixture::create().await.unwrap();
        let config_bytes = include_str!("../../../fixtures/conformance/p2/config.json");
        let config_hash = ContentHash::of_bytes(config_bytes.as_bytes());
        let config_ref = ArtifactRef::new(
            Iri::new("https://test/graph-workspace-config").unwrap(),
            VersionId::new("1").unwrap(),
            config_hash.clone(),
        );
        let token = std::fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
        let publisher = Service::open(fixture.config().unwrap()).await.unwrap();
        publisher
            .dispatch(
                &token,
                &serde_json::to_vec(&serde_json::json!({
                    "schema":"ctxql-service/v1",
                    "op":"publish",
                    "artifact": {
                        "iri": config_ref.iri().as_str(),
                        "version": config_ref.version().as_str(),
                        "hash": config_hash.as_str()
                    },
                    "content": config_bytes
                }))
                .unwrap(),
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        publisher.shutdown().await.unwrap();
        drop(publisher);

        let config = fixture.config().unwrap();
        let acquisition = AcquisitionService::open(&config, fixture.catalog_identity().clone())
            .await
            .unwrap();
        let claim = graph_workspace_claim();
        let seed_claim_id = claim.id().clone();
        let writer_session = acquisition.semantic_writer.session().await;
        let capture = writer_session.capture_current().await.unwrap();
        drop(writer_session);
        let bundle = ValidatedSemanticBundle::new(
            BundleId::new("bundle:graph-workspace-seed").unwrap(),
            ExtractionRunId::new("extraction:graph-workspace-seed").unwrap(),
            capture,
            CanonicalValue::object([
                (
                    "schema".into(),
                    CanonicalValue::string("ctxql-extraction-admission-descriptor/v2"),
                ),
                (
                    "evaluation_id".into(),
                    CanonicalValue::string("evaluation:graph-workspace-seed"),
                ),
                (
                    "review_payload_root".into(),
                    CanonicalValue::string(ContentHash::of_bytes(b"seed review").as_str()),
                ),
                ("ontology_mode".into(), CanonicalValue::string("direct")),
            ])
            .unwrap(),
            vec![("v2:graph-seed".into(), claim)],
            cdb_core::Limits::default(),
        )
        .unwrap();
        acquisition
            .admit_foreground(
                JobId::new("job:graph-workspace-seed").unwrap(),
                AttemptId::new("attempt:graph-workspace-seed").unwrap(),
                &bundle,
                ContentHash::of_bytes(b"seed selectors"),
                CanonicalValue::object([]).unwrap(),
                Timestamp::from_millis(1).unwrap(),
                WaitPoint::Projected,
                AdmissionContext::NoGraph,
            )
            .await
            .unwrap();

        let semantic_before =
            SemanticProjectionSource::capture(acquisition.semantic.as_ref(), None)
                .await
                .unwrap();
        let control_before = GraphBackend::head(acquisition.authority.as_ref())
            .await
            .unwrap();
        let host = acquisition
            .graph_query_host(config_ref, None, GraphQueryLimits::default())
            .await
            .unwrap();
        let exhausted_limits = WorkspaceLimits {
            max_tool_calls: 1,
            ..WorkspaceLimits::default()
        };
        let exhausted = GraphSession::new(
            "acquisition-test".into(),
            "exhausted-session".into(),
            "attempt:exhausted".into(),
            "source:phase-one".into(),
            "range:phase-one".into(),
            BTreeSet::new(),
            host.clone(),
            exhausted_limits,
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap();
        exhausted.check().await.unwrap();
        assert_eq!(exhausted.check().await.unwrap_err().kind, ErrorKind::Limit);
        assert_eq!(exhausted.check().await.unwrap_err().kind, ErrorKind::Limit);

        let error_budget_limits = WorkspaceLimits {
            max_aggregate_bytes: 80,
            ..WorkspaceLimits::default()
        };
        let error_budget = GraphSession::new(
            "acquisition-test".into(),
            "error-budget-session".into(),
            "attempt:error-budget".into(),
            "source:phase-one".into(),
            "range:phase-one".into(),
            BTreeSet::new(),
            host.clone(),
            error_budget_limits,
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap();
        let foreign_error = crate::graph_workspace::Handle("g1~foreign-session".into());
        assert_eq!(
            error_budget
                .import_graph(&foreign_error)
                .await
                .unwrap_err()
                .kind,
            ErrorKind::Limit
        );
        assert_eq!(
            error_budget.check().await.unwrap_err().kind,
            ErrorKind::Limit
        );

        let session = GraphSession::new(
            "acquisition-test".into(),
            "phase-one-session".into(),
            "attempt:phase-one".into(),
            "source:phase-one".into(),
            "range:phase-one".into(),
            ["evidence:definition".into(), "evidence:member".into()]
                .into_iter()
                .collect(),
            host.clone(),
            WorkspaceLimits::default(),
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap();
        let query = br#"{"about":[{"from":["urn:subject:graph"],"match":"exact"}],"bounds":{"max_depth":1}}"#;
        let graph = match session
            .query(query, GraphQueryLimits::default())
            .await
            .unwrap()
        {
            SessionQueryResult::Graph {
                handle,
                node_count,
                claim_count,
                ..
            } => {
                assert!(node_count >= 1);
                assert!(claim_count >= 1);
                handle
            }
            other => panic!("expected complete graph: {other:?}"),
        };
        session.import_graph(&graph).await.unwrap();
        let revision = session.check().await.unwrap().revision;
        let applied = session
            .apply(ApplyRequest {
                schema: "ctxql.graph-workspace/v1".into(),
                session_id: "phase-one-session".into(),
                expected_revision: revision,
                idempotency_key: "phase-one-drafts".into(),
                edits: vec![
                    Edit::AddNode {
                        temp_id: "agreement".into(),
                        local_id: "agreement".into(),
                        label: "Agreement".into(),
                        evidence: vec!["evidence:definition".into()],
                    },
                    Edit::AddNode {
                        temp_id: "borrower".into(),
                        local_id: "borrower".into(),
                        label: "Borrower".into(),
                        evidence: vec!["evidence:member".into()],
                    },
                    Edit::AddClaim {
                        temp_id: "relationship".into(),
                        subject: RecordRef::Temp {
                            id: "agreement".into(),
                        },
                        predicate: "urn:relation:borrower".into(),
                        object: EndpointRef::Record {
                            record: RecordRef::Temp {
                                id: "borrower".into(),
                            },
                        },
                        evidence: vec!["evidence:member".into()],
                        fit_note: "direct".into(),
                    },
                    Edit::AddClaim {
                        temp_id: "name".into(),
                        subject: RecordRef::Temp {
                            id: "borrower".into(),
                        },
                        predicate: "urn:relation:name".into(),
                        object: EndpointRef::Literal {
                            value: TypedLiteral {
                                lexical: "Borrower".into(),
                                datatype: "http://www.w3.org/2001/XMLSchema#string".into(),
                                language: None,
                            },
                        },
                        evidence: vec!["evidence:member".into()],
                        fit_note: "direct".into(),
                    },
                    Edit::AddReference {
                        temp_id: "original-borrowers".into(),
                        label: "Original Borrowers".into(),
                        scope: "agreement".into(),
                        definition_evidence: vec!["evidence:definition".into()],
                        referent_shape: "collective_role".into(),
                        target_text: Some("Borrower".into()),
                        members: vec![RecordRef::Temp {
                            id: "borrower".into(),
                        }],
                        membership_evidence: vec!["evidence:member".into()],
                        status: ReferenceStatus::Resolved,
                    },
                ],
            })
            .await
            .unwrap();
        assert_eq!(applied.handles.len(), 5);
        assert!(!session
            .view(ViewKind::Overview, None)
            .await
            .unwrap()
            .rendered
            .is_empty());
        assert!(!session
            .view(ViewKind::Changes, None)
            .await
            .unwrap()
            .rendered
            .is_empty());
        let foreign_session = GraphSession::new(
            "acquisition-test".into(),
            "foreign-session".into(),
            "attempt:foreign".into(),
            "source:phase-one".into(),
            "range:phase-one".into(),
            BTreeSet::new(),
            host.clone(),
            WorkspaceLimits::default(),
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap();
        assert_eq!(
            foreign_session.import_graph(&graph).await.unwrap_err().kind,
            ErrorKind::Denied
        );
        assert_eq!(
            SemanticProjectionSource::capture(acquisition.semantic.as_ref(), None)
                .await
                .unwrap()
                .snapshot,
            semantic_before.snapshot
        );
        assert_eq!(
            GraphBackend::head(acquisition.authority.as_ref())
                .await
                .unwrap(),
            control_before
        );

        let writer_session = acquisition.semantic_writer.session().await;
        let guarded_capture = writer_session.capture_current().await.unwrap();
        drop(writer_session);
        let guarded_bundle = ValidatedSemanticBundle::new(
            BundleId::new("bundle:graph-workspace-guarded").unwrap(),
            ExtractionRunId::new("extraction:graph-workspace-guarded").unwrap(),
            guarded_capture,
            CanonicalValue::object([
                (
                    "schema".into(),
                    CanonicalValue::string("ctxql-extraction-admission-descriptor/v2"),
                ),
                (
                    "evaluation_id".into(),
                    CanonicalValue::string("evaluation:graph-workspace-guarded"),
                ),
                (
                    "review_payload_root".into(),
                    CanonicalValue::string(ContentHash::of_bytes(b"guarded review").as_str()),
                ),
                ("ontology_mode".into(), CanonicalValue::string("direct")),
            ])
            .unwrap(),
            vec![("v2:graph-guarded".into(), graph_workspace_guarded_claim())],
            cdb_core::Limits::default(),
        )
        .unwrap();
        let guarded = acquisition
            .admit_foreground(
                JobId::new("job:graph-workspace-guarded").unwrap(),
                AttemptId::new("attempt:graph-workspace-guarded").unwrap(),
                &guarded_bundle,
                ContentHash::of_bytes(b"guarded selectors"),
                CanonicalValue::object([]).unwrap(),
                Timestamp::from_millis(2).unwrap(),
                WaitPoint::Admitted,
                AdmissionContext::Graph(session.clone()),
            )
            .await
            .unwrap();
        let recovered = acquisition
            .admit_foreground(
                JobId::new("job:graph-workspace-guarded").unwrap(),
                AttemptId::new("attempt:graph-workspace-guarded").unwrap(),
                &guarded_bundle,
                ContentHash::of_bytes(b"guarded selectors"),
                CanonicalValue::object([]).unwrap(),
                Timestamp::from_millis(2).unwrap(),
                WaitPoint::Admitted,
                AdmissionContext::Graph(session.clone()),
            )
            .await
            .unwrap();
        assert_eq!(guarded.admission, recovered.admission);

        let revocation_session = GraphSession::new(
            "acquisition-test".into(),
            "revocation-session".into(),
            "attempt:revocation".into(),
            "source:phase-one".into(),
            "range:phase-one".into(),
            BTreeSet::new(),
            host,
            WorkspaceLimits::default(),
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap();
        revocation_session
            .view(ViewKind::Overview, None)
            .await
            .unwrap();
        let original_policy = acquisition.authority.policy_state().await.unwrap();
        let mut revoked = original_policy.clone();
        revoked
            .principals
            .get_mut(
                &PrincipalId::new(
                    cdb_backend_fluree::official_bootstrap::ACQUISITION_V2_FIXTURE_PRINCIPAL,
                )
                .unwrap(),
            )
            .unwrap()
            .0 = false;
        acquisition
            .authority
            .set_policy_state(
                &IdempotencyKey::new("phase-one-graph-revoke").unwrap(),
                &revoked,
            )
            .await
            .unwrap();
        assert_eq!(
            revocation_session
                .view(ViewKind::Overview, None)
                .await
                .unwrap_err()
                .kind,
            ErrorKind::Denied
        );
        acquisition
            .authority
            .set_policy_state(
                &IdempotencyKey::new("phase-one-graph-restore").unwrap(),
                &original_policy,
            )
            .await
            .unwrap();
        assert_eq!(
            revocation_session
                .view(ViewKind::Overview, None)
                .await
                .unwrap_err()
                .kind,
            ErrorKind::Denied
        );

        let (replacement, lifecycle) = graph_workspace_supersession(&seed_claim_id);
        let writer_session = acquisition.semantic_writer.session().await;
        let lifecycle_capture = writer_session.capture_current().await.unwrap();
        drop(writer_session);
        let lifecycle_bundle = ValidatedSemanticBundle::new(
            BundleId::new("bundle:graph-workspace-supersession").unwrap(),
            ExtractionRunId::new("extraction:graph-workspace-supersession").unwrap(),
            lifecycle_capture,
            CanonicalValue::object([
                (
                    "schema".into(),
                    CanonicalValue::string("ctxql-extraction-admission-descriptor/v2"),
                ),
                (
                    "evaluation_id".into(),
                    CanonicalValue::string("evaluation:graph-workspace-supersession"),
                ),
                (
                    "review_payload_root".into(),
                    CanonicalValue::string(ContentHash::of_bytes(b"supersession review").as_str()),
                ),
                ("ontology_mode".into(), CanonicalValue::string("direct")),
            ])
            .unwrap(),
            vec![
                ("v2:graph-replacement".into(), replacement),
                ("v2:graph-lifecycle".into(), lifecycle),
            ],
            cdb_core::Limits::default(),
        )
        .unwrap();
        acquisition
            .admit_foreground(
                JobId::new("job:graph-workspace-supersession").unwrap(),
                AttemptId::new("attempt:graph-workspace-supersession").unwrap(),
                &lifecycle_bundle,
                ContentHash::of_bytes(b"supersession selectors"),
                CanonicalValue::object([]).unwrap(),
                Timestamp::from_millis(3).unwrap(),
                WaitPoint::Admitted,
                AdmissionContext::NoGraph,
            )
            .await
            .unwrap();
        assert_eq!(
            session
                .view(ViewKind::Overview, None)
                .await
                .unwrap_err()
                .kind,
            ErrorKind::Denied
        );
        assert!(acquisition
            .admit_foreground(
                JobId::new("job:graph-workspace-seed").unwrap(),
                AttemptId::new("attempt:graph-workspace-seed").unwrap(),
                &bundle,
                ContentHash::of_bytes(b"seed selectors"),
                CanonicalValue::object([]).unwrap(),
                Timestamp::from_millis(1).unwrap(),
                WaitPoint::Projected,
                AdmissionContext::Graph(session),
            )
            .await
            .is_err());
        acquisition.shutdown().await.unwrap();
    }

    struct RecoveryControl {
        prepared: BundlePrepared,
        admissions: Mutex<Vec<SemanticAdmissionReceipt>>,
    }
    impl AcquisitionControl for RecoveryControl {
        fn append_prepared<'a>(&'a self, _: &'a BundlePrepared) -> IoFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn prepared<'a>(&'a self, _: &'a BundleId) -> IoFuture<'a, Option<BundlePrepared>> {
            Box::pin(async { Ok(Some(self.prepared.clone())) })
        }
        fn prepared_records(&self) -> IoFuture<'_, Vec<BundlePrepared>> {
            Box::pin(async { Ok(vec![self.prepared.clone()]) })
        }
        fn admission<'a>(
            &'a self,
            _: &'a BundleId,
        ) -> IoFuture<'a, Option<SemanticAdmissionReceipt>> {
            Box::pin(async { Ok(self.admissions.lock().unwrap().last().cloned()) })
        }
        fn append_admission<'a>(
            &'a self,
            _: &'a BundleId,
            receipt: &'a SemanticAdmissionReceipt,
        ) -> IoFuture<'a, ()> {
            Box::pin(async move {
                self.admissions.lock().unwrap().push(receipt.clone());
                Ok(())
            })
        }
        fn append_projection<'a>(
            &'a self,
            _: &'a BundleId,
            _: &'a ProjectionReceipt,
        ) -> IoFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    struct RecoveryWriter(SemanticAdmissionReceipt);
    impl SemanticBundleWriter for RecoveryWriter {
        fn preflight<'a>(&'a self, _: &'a ValidatedSemanticBundle) -> IoFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn recover<'a>(&'a self, _: &'a BundlePrepared) -> IoFuture<'a, AdmissionRecovery> {
            Box::pin(async { Ok(AdmissionRecovery::Exact(Box::new(self.0.clone()))) })
        }
        fn recover_or_admit<'a>(
            &'a self,
            _: &'a BundlePrepared,
            _: &'a ValidatedSemanticBundle,
        ) -> IoFuture<'a, SemanticAdmissionReceipt> {
            Box::pin(async { Err(Error::invalid("unexpected admission")) })
        }
    }

    #[test]
    fn configured_review_graph_must_match_one_dedicated_ledger_role() {
        assert!(require_dedicated_review_role(
            "urn:review",
            &BTreeSet::from(["urn:review".to_owned()]),
        )
        .is_ok());
        for roles in [
            BTreeSet::new(),
            BTreeSet::from(["urn:other".to_owned()]),
            BTreeSet::from(["urn:review".to_owned(), "urn:other".to_owned()]),
        ] {
            assert!(require_dedicated_review_role("urn:review", &roles).is_err());
        }
    }

    #[tokio::test]
    async fn startup_enumeration_finalizes_lost_ack_before_provider_work() {
        let snapshot = SnapshotRef::new(
            BackendId::new("semantic-backend").unwrap(),
            GraphPin::new(
                AuthorityId::new("semantic-authority").unwrap(),
                GraphId::new("semantic-graph").unwrap(),
                VersionId::new("2").unwrap(),
                ResourceId::new("cid").unwrap(),
            ),
        );
        let hash = |bytes| ContentHash::of_bytes(bytes);
        let claim = ClaimId::new("urn:claim:one").unwrap();
        let prepared = BundlePrepared {
            job_id: JobId::new("job").unwrap(),
            attempt_id: AttemptId::new("attempt").unwrap(),
            bundle_id: BundleId::new("bundle").unwrap(),
            admission_key: "p6:key".into(),
            descriptor_root: hash(b"descriptor"),
            payload_root: hash(b"payload"),
            canonical_claim_root: hash(b"decoded"),
            expected_claim_ids: vec![claim.clone()],
            validation_capture: snapshot.clone(),
            source_selector_root: hash(b"selectors"),
            safe_counts: CanonicalValue::object([]).unwrap(),
            recorded_at: Timestamp::parse("2026-09-22T00:00:00.000Z").unwrap(),
        };
        let receipt = SemanticAdmissionReceipt::new(
            IdempotencyKey::new("p6:key").unwrap(),
            hash(b"descriptor"),
            hash(b"payload"),
            hash(b"decoded"),
            hash(b"stored"),
            snapshot,
            Timestamp::parse("2026-09-22T00:00:01.000Z").unwrap(),
            vec![claim],
        )
        .unwrap();
        let control = RecoveryControl {
            prepared,
            admissions: Mutex::new(Vec::new()),
        };
        let recovered = recover_unfinished(&control, &RecoveryWriter(receipt.clone()))
            .await
            .unwrap();
        let recovered = recovered.get(&JobId::new("job").unwrap()).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].receipt(), &receipt);
        assert_eq!(
            &*control.admissions.lock().unwrap(),
            std::slice::from_ref(&receipt)
        );
        let (prior_jobs, prior_admissions) = collect_prior_jobs(&control).await.unwrap();
        assert!(prior_jobs.contains(&JobId::new("job").unwrap()));
        assert_eq!(
            prior_admissions[&JobId::new("job").unwrap()][0].receipt(),
            &receipt
        );
    }
}
