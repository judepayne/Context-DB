//! Foreground trusted acquisition from bounded local or HTTPS source targets.

use crate::{
    acquisition::{load_current_catalog, AcquisitionService, AdmissionContext, WaitPoint},
    config::{
        AcquisitionConfig, AcquisitionConverterConfig, AcquisitionGraphWorkspaceConfig,
        AcquisitionProtocol, InstanceConfig,
    },
    entity_lookup::{
        EntityEligibility, EntityGazetteer, EntityLookupRequest, IdentifierProbe,
        KnownIriResolution,
    },
    graph_capture::{
        verify_graph_capture, GraphCapability, GraphCaptureIndex, GraphCaptureLimits,
        GraphCaptureRecorder, GraphCaptureStore, GraphResultKind, VerifiedGraphCapture,
    },
    graph_context::{GazetteerContext, GraphContextLimits, GraphContextManifest},
    graph_query::{GraphQueryHost, GraphQueryLimits},
    graph_session::{GraphSession, SessionQueryResult},
    graph_workspace::{ApplyRequest, Handle, ViewKind, WorkspaceLimits},
    ontology_direct::DirectFlureeOntologyToolHost,
    ontology_mapping::RawMappingAuthority,
    source_target::{
        AcquiredDocument, AcquiredDocumentOutcome, MediaKind, SourceLocator, SourceTarget,
    },
    sources::{AcquisitionArtifactDescriptor, SourcePlusGraphArtifactDescriptor},
};
use cdb_acquisition::{
    candidates::{
        AdvisoryBundle, AdvisoryClaim, CandidateLimits, CandidateObject, ClaimMetadata,
        EntityCandidate, LocalId, TypedLiteral,
    },
    contracts::EntityResolver,
    coordinates::{CoordinateMap, LineCoordinate, LineSelection},
    document_entities::DocumentEntityTable,
    lineage::strict_lineage,
    outcomes::{ground_evidence, typed_literal as validated_typed_literal, GroundedEvidence},
    proposals::{
        EntityRef as ProposalEntityRef, Evidence, ProposalComponent, ProposalEnvelopeV2,
        ProposalLimits, RelationObject as ProposalRelationObject, SemanticFit, SourceMode,
        TermChoice,
    },
    source::{ConverterDeclaration, ExtractionText, SourceMediaType},
    validator::{validate_bundle, validate_provisional_bundle, ValidationInput},
    windows::{plan_windows, DocumentKind, Window, WindowConfig, WindowMode},
};
use cdb_backend_fluree::{
    acquisition_catalog::{CaptureEntityResolver, CertifiedOntologyCatalog, OntologyDiscoveryText},
    semantic::FlureeSemanticLedger,
};
use cdb_core::{
    artifact::ArtifactRef,
    claim::CandidateClaim,
    evidence::{EvidenceSelector, Utf8Span},
    id::{
        AttemptId, BundleId, ClaimId, ContentHash, EntityId, ExtractionRunId, Iri, JobId, SourceId,
    },
    ontology_catalog::OntologyTermKind,
    review::{
        ReviewAssertionIntent, ReviewRecord, ReviewRecordId, ValidatedReviewBundle,
        VocabularyVerdict,
    },
    source::SourceReadRequest,
    CanonicalValue as V, Error, ErrorKind, ExactNumber, Limits, Result, Timestamp,
};
use cdb_provider_pi::{
    advisory::into_advisory,
    agent_bundle::{
        hash_agent_bundle, verify_recorded_assets, AgentBundle, VerifiedRecordedAssets,
    },
    cancel::CancellationToken,
    fact_blocks::{parse_fact_blocks, FactBlockLimits, FactProposal},
    ontology_bridge::{OntologyBridgeConfig, OntologyToolError, OntologyToolHost, ToolCapability},
    parser::{ParseError, ParseLimits},
    proposal_protocol::{parse_proposals, ProposalParseContext, ProposalParseError},
    proposal_text::{parse_proposals_text, TextProposalDiagnostic, TEXT_PROPOSAL_PROTOCOL},
    provider::{CapturedResponse, PiProvider, ProviderError},
    transport::{
        ExtractionProtocol, PiTransport, TransportConfig, TransportError, TransportLimits,
    },
    usage::Usage,
};
use cdb_source_store::{ConverterManifest, Normalization, SourceObjectReader, SourceObjectWriter};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const RDF_CLASS: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const BUSINESS_RELATION_TYPE: &str = "urn:ctxql:acquisition:v1:BusinessRelationshipRelationType";
const BUSINESS_CLAIM_TYPE: &str = "urn:ctxql:acquisition:v1:BusinessRelationshipClaimType";
const TYPE_ASSERTION_RELATION_TYPE: &str = "urn:ctxql:acquisition:v1:TypeAssertionRelationType";
const TYPE_ASSERTION_CLAIM_TYPE: &str = "urn:ctxql:acquisition:v1:TypeAssertionClaimType";
const PROVISIONAL_ENTITY_CLASS: &str = "urn:ctxql:poc:soft:Entity";
const PROVISIONAL_ENTITY_PREFIX: &str = "urn:ctxql:poc:soft:entity:";
const PROVISIONAL_PREDICATE_PREFIX: &str = "urn:ctxql:poc:soft:predicate:";
const MIN_INGEST_REPORT_BYTES: usize = 4096;
const REPORT_ENVELOPE_RESERVE: usize = 1024;
const CAPTURE_MANIFEST_SCHEMA: &str = "ctxql-provider-capture-manifest/v2";
const MULTI_CAPTURE_MANIFEST_SCHEMA: &str = "ctxql-provider-multipassage-capture-manifest/v1";
const MAX_CAPTURE_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CapturedConverterDeclaration {
    executable_hash: String,
    version_probe: String,
    arguments: Vec<String>,
    timeout_millis: u64,
    output_byte_limit: usize,
    encoding: String,
    normalization: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CapturedSourceRepresentation {
    media_type: String,
    original_object: String,
    original_manifest: String,
    text_object: Option<String>,
    text_manifest: Option<String>,
    converter_manifest: Option<String>,
    converter: Option<CapturedConverterDeclaration>,
}

#[derive(Clone)]
struct CapturedEntitySource {
    ledger: FlureeSemanticLedger,
    gazetteer: EntityGazetteer,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderCaptureManifest {
    schema: String,
    source_id: String,
    locator: String,
    text_version: String,
    window_id: String,
    request_root: String,
    request: String,
    source_text: String,
    coordinate_seed: String,
    window_start: usize,
    window_end: usize,
    asset_manifest: Value,
    assets: BTreeMap<String, String>,
    response_root: String,
    response: String,
    model: String,
    thinking: String,
    agent_bundle_hash: String,
    ontology_lookup: Option<Value>,
    issued_ranges: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_representation: Option<CapturedSourceRepresentation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PassageCaptureManifest {
    ordinal: usize,
    window_id: String,
    request_seed: String,
    context_before: String,
    request_root: String,
    request: String,
    response_root: String,
    response: String,
    context_after: String,
    window_start: usize,
    window_end: usize,
    issued_ranges: Vec<String>,
    leaf_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MultiPassageCaptureManifest {
    schema: String,
    source_id: String,
    locator: String,
    text_version: String,
    source_text: String,
    document_seed: String,
    asset_manifest: Value,
    assets: BTreeMap<String, String>,
    model: String,
    thinking: String,
    agent_bundle_hash: String,
    ontology_lookup: Option<Value>,
    passage_count: usize,
    leaves: Vec<PassageCaptureManifest>,
    entity_checkpoint: String,
    capture_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_representation: Option<CapturedSourceRepresentation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphCaptureExport {
    schema: String,
    capability: Value,
    workspace: Value,
    context: Value,
    transcript_leaves: Vec<Value>,
    graph_payloads: BTreeMap<String, Value>,
    index: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphProviderCaptureManifest {
    schema: String,
    provider: ProviderCaptureManifest,
    graph: GraphCaptureExport,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum CaptureManifest {
    Graph(Box<GraphProviderCaptureManifest>),
    Single(ProviderCaptureManifest),
    Multi(MultiPassageCaptureManifest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestWait {
    Admitted,
    Projected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestMode {
    Admit(IngestWait),
    ExtractOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OntologyMode {
    Hard,
    Soft,
}
impl OntologyMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "hard" => Ok(Self::Hard),
            "soft" => Ok(Self::Soft),
            _ => Err(Error::invalid("invalid ontology mode")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hard => "hard",
            Self::Soft => "soft",
        }
    }
}
impl IngestMode {
    fn wait(self) -> Option<IngestWait> {
        match self {
            Self::Admit(wait) => Some(wait),
            Self::ExtractOnly => None,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Admit(_) => "admit",
            Self::ExtractOnly => "extract_only",
        }
    }
}
impl IngestWait {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "admitted" => Ok(Self::Admitted),
            "projected" => Ok(Self::Projected),
            _ => Err(Error::invalid("invalid ingest wait point")),
        }
    }
    fn wait_point(self) -> WaitPoint {
        match self {
            Self::Admitted => WaitPoint::Admitted,
            Self::Projected => WaitPoint::Projected,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Projected => "projected",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct IngestReport {
    schema: &'static str,
    mode: &'static str,
    ontology_mode: &'static str,
    wait: Option<&'static str>,
    documents: Vec<DocumentReport>,
    document_count: usize,
    omitted_document_count: usize,
    details_truncated: bool,
    validated_bundle_count: usize,
    validated_claim_count: usize,
    admitted_bundle_count: usize,
    admitted_claim_count: usize,
    candidate_count: usize,
    mapped_candidate_count: usize,
    provisional_candidate_count: usize,
    unmapped_candidate_count: usize,
    rejected_candidate_count: usize,
    provider_usage: UsageReport,
}

#[derive(Clone, Debug, Serialize)]
struct DocumentReport {
    locator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    job_id: Option<String>,
    ontology_mode: &'static str,
    mapping_status: &'static str,
    original_object: Option<String>,
    original_manifest: Option<String>,
    text_version: Option<String>,
    text_manifest: Option<String>,
    agent_bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ontology_lookup: Option<Value>,
    window_count: usize,
    issued_ranges: BTreeMap<String, Vec<String>>,
    admitted_bundle_count: usize,
    admitted_claim_count: usize,
    candidate_count: usize,
    mapped_candidate_count: usize,
    provisional_candidate_count: usize,
    unmapped_candidate_count: usize,
    rejected_candidate_count: usize,
    no_claim_window_count: usize,
    provider_responses: Vec<ProviderResponseReport>,
    artifacts: Vec<ArtifactReport>,
    artifact_descriptors: Vec<Value>,
    validations: Vec<ValidationReport>,
    review_record_count: usize,
    review_receipts: Vec<Value>,
    validated_bundle_count: usize,
    validated_claim_count: usize,
    admissions: Vec<Value>,
    admitted_claims: Vec<Value>,
    errors: Vec<StageError>,
    details_truncated: bool,
    omitted_admission_count: usize,
    omitted_claim_count: usize,
    omitted_error_count: usize,
    #[serde(skip)]
    detail_bytes_remaining: usize,
}

#[derive(Clone, Debug, Serialize)]
struct ArtifactReport {
    kind: &'static str,
    window_id: String,
    root: String,
}

#[derive(Clone, Debug, Serialize)]
struct ProviderResponseReport {
    phase: &'static str,
    window_ids: Vec<String>,
    text: Option<String>,
    text_sha256: Option<String>,
    parse_error: Option<&'static str>,
    transport_error: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
struct ValidationReport {
    window_id: String,
    candidate_index: Option<usize>,
    status: &'static str,
    validated_claim_count: usize,
    error: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
struct StageError {
    stage: &'static str,
    code: &'static str,
    window_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct UsageReport {
    requests: u64,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    cost_microusd: u64,
}
impl DocumentReport {
    fn retain_detail<T: Serialize>(&mut self, value: &T) -> Result<bool> {
        let bytes = serde_json::to_vec(value)
            .map_err(|error| Error::new(ErrorKind::Backend, error.to_string()))?;
        let cost = bytes.len().saturating_add(1);
        if cost > self.detail_bytes_remaining {
            self.details_truncated = true;
            return Ok(false);
        }
        self.detail_bytes_remaining -= cost;
        Ok(true)
    }

    fn push_error(&mut self, error: StageError) -> Result<()> {
        if self.retain_detail(&error)? {
            self.errors.push(error);
        } else {
            self.omitted_error_count = self.omitted_error_count.saturating_add(1);
        }
        Ok(())
    }

    fn push_claim(&mut self, claim: Value) -> Result<()> {
        if self.retain_detail(&claim)? {
            self.admitted_claims.push(claim);
        } else {
            self.omitted_claim_count = self.omitted_claim_count.saturating_add(1);
        }
        Ok(())
    }

    fn push_admission(&mut self, admission: Value) -> Result<()> {
        if self.retain_detail(&admission)? {
            self.admissions.push(admission);
        } else {
            self.omitted_admission_count = self.omitted_admission_count.saturating_add(1);
        }
        Ok(())
    }
}

impl UsageReport {
    fn add(&mut self, usage: &Usage) {
        self.requests = self.requests.saturating_add(usage.requests);
        self.input_tokens = self.input_tokens.saturating_add(usage.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(usage.output_tokens);
        self.cache_read_tokens = self
            .cache_read_tokens
            .saturating_add(usage.cache_read_tokens);
        self.cache_write_tokens = self
            .cache_write_tokens
            .saturating_add(usage.cache_write_tokens);
        self.cost_microusd = self.cost_microusd.saturating_add(usage.cost_microusd);
    }
}

struct PreparedSource {
    extraction: ExtractionText,
    source_id: SourceId,
    original_manifest: ContentHash,
    text_manifest: Option<ContentHash>,
    converter_manifest: Option<ContentHash>,
}

#[allow(clippy::too_many_arguments)] // CLI orchestration inputs are independently optional.
pub async fn ingest(
    config: InstanceConfig,
    target: SourceTarget,
    mode: IngestMode,
    ontology_mode: OntologyMode,
    max_report_bytes: usize,
    captured_response_path: Option<String>,
    capture_manifest_path: Option<String>,
    save_capture_manifest_path: Option<String>,
    cancel: CancellationToken,
) -> Result<IngestReport> {
    config.validate_runtime()?;
    if max_report_bytes < MIN_INGEST_REPORT_BYTES {
        return Err(Error::invalid("ingest report byte limit is too small"));
    }
    let acquisition = config
        .acquisition
        .as_ref()
        .ok_or_else(|| Error::invalid("trusted acquisition configuration required"))?
        .clone();
    let graph_query_config = acquisition
        .graph_workspace
        .as_ref()
        .map(|workspace| {
            workspace
                .query_config
                .as_ref()
                .map(|reference| reference.artifact_ref())
                .unwrap_or_else(|| config.required_default_config())
        })
        .transpose()?;
    let current_dir = std::env::current_dir()
        .map_err(|_| Error::new(ErrorKind::Backend, "current directory unavailable"))?;
    let documents =
        crate::source_target::acquire_source_target_outcomes(&acquisition, &current_dir, target)
            .await?;
    if documents.is_empty() {
        return Err(Error::invalid(
            "ingest target contains no supported documents",
        ));
    }
    if captured_response_path.is_some()
        && (capture_manifest_path.is_some() || save_capture_manifest_path.is_some())
    {
        return Err(Error::invalid(
            "raw captured response cannot be combined with a verified capture manifest",
        ));
    }
    if capture_manifest_path.is_some() && save_capture_manifest_path.is_some() {
        return Err(Error::invalid(
            "capture replay and capture creation are mutually exclusive",
        ));
    }
    let captured_response = if let Some(path) = captured_response_path {
        if mode != IngestMode::ExtractOnly {
            return Err(Error::invalid(
                "captured response evaluation is extract-only until a verified capture manifest is supplied",
            ));
        }
        if acquisition.protocol != AcquisitionProtocol::OntologyV2 || documents.len() != 1 {
            return Err(Error::invalid(
                "captured response requires ontology-v2 and one document",
            ));
        }
        let bytes =
            std::fs::read(path).map_err(|_| Error::invalid("captured response unavailable"))?;
        if bytes.len() > 256 * 1024 {
            return Err(Error::limit());
        }
        Some(
            String::from_utf8(bytes)
                .map_err(|_| Error::invalid("captured response must be UTF-8"))?,
        )
    } else {
        None
    };
    let capture_manifest = if let Some(path) = capture_manifest_path {
        if acquisition.protocol != AcquisitionProtocol::OntologyV2 || documents.len() != 1 {
            return Err(Error::invalid(
                "capture manifest requires ontology-v2 and one document",
            ));
        }
        let bytes =
            std::fs::read(path).map_err(|_| Error::invalid("capture manifest unavailable"))?;
        if bytes.len() > MAX_CAPTURE_MANIFEST_BYTES {
            return Err(Error::limit());
        }
        let manifest: CaptureManifest = serde_json::from_slice(&bytes)
            .map_err(|_| Error::invalid("capture manifest is invalid"))?;
        verify_capture_manifest_integrity(&manifest)?;
        Some(manifest)
    } else {
        None
    };

    let needs_semantic_vocabulary = acquisition.protocol == AcquisitionProtocol::OntologyV2
        && acquisition.ontology_ledger_path.is_none();
    let needs_entity_source = acquisition.protocol == AcquisitionProtocol::OntologyV2
        && acquisition.entity_source.is_some();
    // Fluree's file open may maintain WAL/lock bookkeeping even for reads.
    // Extract-only therefore reads an isolated private copy and never opens a
    // configured durable Semantic path.
    let ephemeral_semantic = if mode == IngestMode::ExtractOnly
        && (needs_semantic_vocabulary || needs_entity_source)
    {
        let (path, _) = config.semantic_binding()?;
        let directory = tempfile::tempdir()
            .map_err(|_| Error::new(ErrorKind::Backend, "ephemeral Semantic copy unavailable"))?;
        let copy = directory.path().join("semantic");
        copy_private_tree(path, &copy)?;
        Some((directory, copy))
    } else {
        None
    };
    let (semantic_vocabulary, entity_source, isolated_catalog) = if needs_semantic_vocabulary
        || needs_entity_source
    {
        let (configured_path, options) = config.semantic_binding()?;
        let path = ephemeral_semantic
            .as_ref()
            .map(|(_, copy)| copy.as_path())
            .unwrap_or(configured_path);
        let ledger = FlureeSemanticLedger::open_file(path, options.clone()).await?;
        let prepared = cdb_backend_fluree::semantic_preparation::prepare_current_authorized_view(
            &ledger,
            &acquisition.principal,
            &acquisition.action,
            Default::default(),
        )
        .await
        .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        let vocabulary = needs_semantic_vocabulary
            .then(|| {
                crate::semantic_vocabulary::SemanticVocabularyToolHost::from_prepared(&prepared)
                    .map(Arc::new)
                    .map_err(|reason| Error::new(ErrorKind::Invalid, reason))
            })
            .transpose()?;
        let entities = acquisition
            .entity_source
            .as_ref()
            .map(|source| {
                let eligibility = EntityEligibility::poc(
                    source.graphs.iter().cloned().collect(),
                    source.classes.iter().cloned().collect(),
                    source.identifying_predicates.iter().cloned().collect(),
                );
                EntityGazetteer::from_prepared(
                    &acquisition.approved_entity_iris,
                    &prepared,
                    &eligibility,
                )
                .map(|gazetteer| {
                    Arc::new(CapturedEntitySource {
                        ledger: ledger.clone(),
                        gazetteer,
                    })
                })
                .map_err(|reason| Error::new(ErrorKind::Denied, reason))
            })
            .transpose()?;
        let isolated_catalog = if mode == IngestMode::ExtractOnly {
            Some(CertifiedOntologyCatalog::from_prepared(
                &prepared, &options,
            )?)
        } else {
            None
        };
        (vocabulary, entities, isolated_catalog)
    } else {
        (None, None, None)
    };
    let initial_catalog = match isolated_catalog {
        Some(catalog) => catalog,
        None => load_current_catalog(&config).await?,
    };
    let service = match mode {
        IngestMode::Admit(_) => {
            Some(AcquisitionService::open(&config, initial_catalog.identity().clone()).await?)
        }
        IngestMode::ExtractOnly => None,
    };
    let ephemeral_source_root =
        if mode == IngestMode::ExtractOnly {
            Some(tempfile::tempdir().map_err(|_| {
                Error::new(ErrorKind::Backend, "ephemeral source store unavailable")
            })?)
        } else {
            None
        };
    let source_root = if let Some(directory) = ephemeral_source_root.as_ref() {
        #[cfg(unix)]
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::new(ErrorKind::Backend, "ephemeral source store unavailable"))?;
        std::fs::canonicalize(directory.path())
            .map_err(|_| Error::new(ErrorKind::Backend, "ephemeral source store unavailable"))?
    } else {
        config.source_root.clone()
    };
    let source_store = SourceObjectWriter::open(source_root, acquisition.max_source_bytes)?;
    let mut reports = Vec::new();
    let mut report_bytes_remaining = max_report_bytes.saturating_sub(REPORT_ENVELOPE_RESERVE);
    let mut omitted_document_count = 0usize;
    let mut document_count = 0usize;
    let mut validated_bundle_count = 0usize;
    let mut validated_claim_count = 0usize;
    let mut admitted_bundle_count = 0usize;
    let mut admitted_claim_count = 0usize;
    let mut candidate_count = 0usize;
    let mut mapped_candidate_count = 0usize;
    let mut provisional_candidate_count = 0usize;
    let mut unmapped_candidate_count = 0usize;
    let mut rejected_candidate_count = 0usize;
    let mut usage = UsageReport::default();
    let result = async {
        for document in documents {
            document_count = document_count.saturating_add(1);
            if cancel.is_cancelled() {
                return Err(Error::new(ErrorKind::Deadline, "cancelled"));
            }
            let document = match document {
                AcquiredDocumentOutcome::Acquired(document) => document,
                AcquiredDocumentOutcome::Rejected { locator, error } => {
                    let report = failed_document(
                        locator_display(&locator),
                        ontology_mode,
                        "source_acquisition",
                        error.public_code(),
                        max_report_bytes / 2,
                    );
                    retain_document_report(
                        &mut reports,
                        &mut report_bytes_remaining,
                        &mut omitted_document_count,
                        report,
                        mode == IngestMode::ExtractOnly,
                    )?;
                    continue;
                }
            };
            let locator = locator_display(&document.locator);
            let prepared =
                match prepare_source(document, &acquisition, &source_store, cancel.clone()).await {
                    Ok(prepared) => prepared,
                    Err(error) if error.kind != ErrorKind::Deadline => {
                        let report = failed_document(
                            locator,
                            ontology_mode,
                            "source_preparation",
                            error.public_code(),
                            max_report_bytes / 2,
                        );
                        retain_document_report(
                            &mut reports,
                            &mut report_bytes_remaining,
                            &mut omitted_document_count,
                            report,
                            mode == IngestMode::ExtractOnly,
                        )?;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
            let catalog = if let Some(service) = service.as_ref() {
                service.current_catalog().await?
            } else {
                initial_catalog.clone()
            };
            let (report, document_usage) = ingest_document(
                service.as_ref(),
                &acquisition,
                &source_store,
                prepared,
                catalog,
                mode,
                ontology_mode,
                max_report_bytes / 2,
                captured_response.as_deref(),
                capture_manifest.as_ref(),
                save_capture_manifest_path.as_deref(),
                semantic_vocabulary.clone(),
                entity_source.clone(),
                graph_query_config.clone(),
                (mode == IngestMode::ExtractOnly).then_some(&config),
                cancel.clone(),
                false,
                None,
            )
            .await?;
            usage.add(&document_usage);
            validated_bundle_count =
                validated_bundle_count.saturating_add(report.validated_bundle_count);
            validated_claim_count =
                validated_claim_count.saturating_add(report.validated_claim_count);
            admitted_bundle_count =
                admitted_bundle_count.saturating_add(report.admitted_bundle_count);
            admitted_claim_count = admitted_claim_count.saturating_add(report.admitted_claim_count);
            candidate_count = candidate_count.saturating_add(report.candidate_count);
            mapped_candidate_count =
                mapped_candidate_count.saturating_add(report.mapped_candidate_count);
            provisional_candidate_count =
                provisional_candidate_count.saturating_add(report.provisional_candidate_count);
            unmapped_candidate_count =
                unmapped_candidate_count.saturating_add(report.unmapped_candidate_count);
            rejected_candidate_count =
                rejected_candidate_count.saturating_add(report.rejected_candidate_count);
            retain_document_report(
                &mut reports,
                &mut report_bytes_remaining,
                &mut omitted_document_count,
                report,
                mode == IngestMode::ExtractOnly,
            )?;
        }
        Ok(())
    }
    .await;
    let closed = if let Some(service) = service.as_ref() {
        service.shutdown().await
    } else {
        Ok(())
    };
    result?;
    closed?;

    let mut report = IngestReport {
        schema: "ctxql-ingest-report/v1",
        mode: mode.as_str(),
        ontology_mode: ontology_mode.as_str(),
        wait: mode.wait().map(IngestWait::as_str),
        document_count,
        omitted_document_count,
        details_truncated: omitted_document_count != 0
            || reports.iter().any(|document| document.details_truncated),
        documents: reports,
        validated_bundle_count,
        validated_claim_count,
        admitted_bundle_count,
        admitted_claim_count,
        candidate_count,
        mapped_candidate_count,
        provisional_candidate_count,
        unmapped_candidate_count,
        rejected_candidate_count,
        provider_usage: usage,
    };
    fit_report(&mut report, max_report_bytes)?;
    Ok(report)
}

fn copy_private_tree(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy source unavailable"))?;
    if metadata.file_type().is_symlink() {
        return Err(Error::invalid("unsafe Semantic copy source"));
    }
    if metadata.is_file() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy failed"))?;
        }
        fs::copy(source, destination)
            .map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy failed"))?;
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(Error::invalid("unsafe Semantic copy source"));
    }
    fs::create_dir_all(destination)
        .map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy failed"))?;
    for entry in
        fs::read_dir(source).map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy failed"))?
    {
        let entry = entry.map_err(|_| Error::new(ErrorKind::Backend, "Semantic copy failed"))?;
        copy_private_tree(&entry.path(), &destination.join(entry.file_name()))?;
    }
    Ok(())
}

async fn prepare_source(
    document: AcquiredDocument,
    config: &AcquisitionConfig,
    store: &SourceObjectWriter,
    cancel: CancellationToken,
) -> Result<PreparedSource> {
    let locator = locator_iri(&document.locator)?;
    let media_type = media_type(document.media_kind);
    let acquisition_metadata = V::object([
        ("schema".into(), V::string("ctxql-source-acquisition/v1")),
        ("locator".into(), V::string(locator.as_str())),
        ("media_type".into(), V::string(media_type)),
    ])?;
    let acquisition_metadata_root =
        ContentHash::of_bytes(&acquisition_metadata.canonical_bytes(Limits::default())?);
    let stored_original =
        store.put_original(&document.bytes, media_type, acquisition_metadata_root)?;

    match document.media_kind {
        MediaKind::Text | MediaKind::Markdown => {
            let source_media = if document.media_kind == MediaKind::Markdown {
                SourceMediaType::Markdown
            } else {
                SourceMediaType::PlainText
            };
            let extraction = ExtractionText::exact_text(locator, source_media, document.bytes)?;
            if extraction.original_object != *stored_original.object() {
                return Err(Error::invalid("source-store original mismatch"));
            }
            let source_id = SourceId::new(format!(
                "urn:ctxql:source:{}",
                &stored_original.manifest().as_str()[7..]
            ))?;
            Ok(PreparedSource {
                extraction,
                source_id,
                original_manifest: stored_original.manifest().clone(),
                text_manifest: None,
                converter_manifest: None,
            })
        }
        MediaKind::Pdf => {
            let converter = config
                .converters
                .get("application/pdf")
                .or_else(|| config.converters.get("pdf"))
                .ok_or_else(|| Error::new(ErrorKind::Unsupported, "PDF converter not configured"))?
                .clone();
            let input = document.bytes.clone();
            let timeout = Duration::from_secs(config.provider_timeout_seconds as u64);
            let limit = config.max_source_bytes;
            let converter_for_process = converter.clone();
            let cancel_for_process = cancel.clone();
            let text = tokio::task::spawn_blocking(move || {
                run_pdf_converter(
                    &converter_for_process,
                    &input,
                    timeout,
                    limit,
                    &cancel_for_process,
                )
            })
            .await
            .map_err(|_| Error::new(ErrorKind::Backend, "PDF converter task failed"))??;
            let executable_hash = ContentHash::parse(&converter.executable_hash)?;
            let mut argv = converter.arguments.clone();
            argv.extend(["-".to_owned(), "-".to_owned()]);
            let normalization = if converter.normalization == "none" {
                Normalization::None
            } else {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "PDF normalization unsupported",
                ));
            };
            let manifest = ConverterManifest::new(
                executable_hash.clone(),
                &converter.version,
                argv.clone(),
                timeout.as_millis() as u64,
                limit as u64,
                normalization,
            )?;
            let converter_manifest = store.put_converter_manifest(&manifest)?;
            let stored_text = store.put_text(
                text.as_bytes(),
                stored_original.manifest().clone(),
                converter_manifest.clone(),
            )?;
            let declaration = ConverterDeclaration {
                executable_hash,
                version_probe: converter.version,
                arguments: argv,
                timeout_millis: timeout.as_millis() as u64,
                output_byte_limit: limit,
                encoding: "UTF-8".into(),
                normalization: "none".into(),
            };
            let extraction = ExtractionText::converted_pdf_text_with_version(
                locator,
                &document.bytes,
                text,
                stored_text.version().clone(),
                declaration,
            )?;
            if extraction.original_object != *stored_original.object()
                || extraction.text_version != *stored_text.version()
                || ContentHash::of_bytes(extraction.text().as_bytes()) != *stored_text.object()
            {
                return Err(Error::invalid("source-store PDF representation mismatch"));
            }
            let source_id = SourceId::new(format!(
                "urn:ctxql:source:{}",
                &stored_text.manifest().as_str()[7..]
            ))?;
            Ok(PreparedSource {
                extraction,
                source_id,
                original_manifest: stored_original.manifest().clone(),
                text_manifest: Some(stored_text.manifest().clone()),
                converter_manifest: Some(converter_manifest),
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn ingest_document(
    service: Option<&Arc<AcquisitionService>>,
    config: &AcquisitionConfig,
    store: &SourceObjectWriter,
    source: PreparedSource,
    catalog: CertifiedOntologyCatalog,
    mode: IngestMode,
    ontology_mode: OntologyMode,
    detail_byte_limit: usize,
    captured_response: Option<&str>,
    capture_manifest: Option<&CaptureManifest>,
    save_capture_manifest_path: Option<&str>,
    semantic_vocabulary: Option<Arc<crate::semantic_vocabulary::SemanticVocabularyToolHost>>,
    entity_source: Option<Arc<CapturedEntitySource>>,
    graph_query_config: Option<ArtifactRef>,
    read_only_config: Option<&InstanceConfig>,
    cancel: CancellationToken,
    stored_replay: bool,
    replay_authority: Option<Arc<GraphQueryHost>>,
) -> Result<(DocumentReport, Usage)> {
    let window_config = window_config(config)?;
    let document_kind = match source.extraction.media_type {
        SourceMediaType::Markdown => DocumentKind::Markdown,
        SourceMediaType::PlainText => DocumentKind::Plain,
        SourceMediaType::Pdf => DocumentKind::PdfText,
    };
    let windows = plan_windows(source.extraction.text(), document_kind, &window_config)?;
    if config.graph_workspace.is_some()
        && (windows.len() != 1
            || windows[0].span.start() != 0
            || windows[0].span.end() != source.extraction.text().len())
    {
        return Err(Error::new(
            ErrorKind::Limit,
            "graph_workspace_requires_complete_document",
        ));
    }
    let recorded_assets = capture_manifest.map(verified_recorded_assets).transpose()?;
    if stored_replay && recorded_assets.is_none() {
        return Err(Error::invalid("stored replay manifest unavailable"));
    }
    // Stored replay treats retained assets as verified data. It must neither
    // require nor stage today's executable bundle.
    let bundle = (!stored_replay)
        .then(|| {
            hash_agent_bundle(&config.pi_bundle)
                .and_then(|bundle| bundle.stage_verified())
                .map_err(|_| Error::invalid("invalid Pi acquisition bundle"))
        })
        .transpose()?;
    let (extraction_run, mut ontology_lookup) = extraction_run(
        &source,
        &catalog,
        bundle.as_ref(),
        recorded_assets.as_ref(),
        config,
        ontology_mode,
        entity_source
            .as_deref()
            .map(|source| source.gazetteer.commitment()),
    )?;
    if let Some(host) = &semantic_vocabulary {
        ontology_lookup = Some(
            host.provenance()
                .map_err(|reason| Error::new(ErrorKind::Invalid, reason))?,
        );
    }
    let job_key = if config.protocol == AcquisitionProtocol::OntologyV2 {
        ContentHash::of_bytes(
            format!(
                "ctxql-evaluation-job/v1\0{}\0{}\0{:?}\0{}\0{}\0{}\0{}",
                extraction_run.as_str(),
                ontology_mode.as_str(),
                config.assertions,
                config.window.mode,
                config.window.target_bytes,
                config.window.max_bytes,
                config.window.overlap_bytes
            )
            .as_bytes(),
        )
    } else {
        ContentHash::parse(format!("sha256:{}", &extraction_run.as_str()[11..]))?
    };
    let job_key = if config.graph_workspace.is_some() {
        let context = if stored_replay {
            let CaptureManifest::Graph(manifest) = capture_manifest
                .ok_or_else(|| Error::invalid("stored graph replay manifest unavailable"))?
            else {
                return Err(Error::invalid("stored graph replay requires graph capture"));
            };
            let request: Value = serde_json::from_str(&manifest.provider.request)
                .map_err(|_| Error::invalid("recorded graph request encoding"))?;
            serde_json::to_string(&json!({
                "graph_workspace": request
                    .get("graph_workspace")
                    .ok_or_else(|| Error::invalid("recorded graph context unavailable"))?,
            }))
            .map_err(|_| Error::invalid("recorded graph context encoding"))?
        } else {
            graph_workspace_request_context("{}".into(), config, graph_query_config.as_ref())?
        };
        ContentHash::of_bytes(&serde_json::to_vec(&json!({
            "schema":"ctxql-graph-evaluation-job/v1", "evaluation":job_key.as_str(), "context":context,
        })).map_err(|_| Error::invalid("graph work identity encoding"))?)
    } else {
        job_key
    };
    let job_id = JobId::new(format!("job:{}", &job_key.as_str()[7..]))?;
    let attempt_id = AttemptId::new(format!("attempt:{}", &extraction_run.as_str()[11..]))?;
    let mut report = document_report(&source, windows.len(), ontology_mode, detail_byte_limit);
    report.job_id = Some(job_id.as_str().to_owned());
    report.ontology_lookup = ontology_lookup.as_ref().map(canonical_json).transpose()?;
    report.agent_bundle_hash =
        Some(asset_hash(bundle.as_ref(), recorded_assets.as_ref())?.to_owned());
    if let (Some(service), Some(wait)) = (service, mode.wait()) {
        if config.protocol == AcquisitionProtocol::OntologyV2 {
            if let Some(draft) = service.work_value(&job_id, "evaluation").await? {
                restore_work_report(&mut report, &draft)?;
                let outcome = if draft.field("schema")?.as_str()?
                    == "ctxql-acquisition-graph-work/v1"
                {
                    let host = match replay_authority.clone() {
                        Some(host) => host,
                        None => {
                            create_graph_query_host(
                                service,
                                config,
                                graph_query_config
                                    .clone()
                                    .ok_or_else(|| Error::invalid("graph config missing"))?,
                            )
                            .await?
                        }
                    };
                    let dependencies = service.frozen_graph_dependencies(&job_id, &draft).await?;
                    service
                        .complete_work_guarded_dependencies(
                            &job_id,
                            wait.wait_point(),
                            host,
                            dependencies,
                            Instant::now()
                                + Duration::from_secs(config.provider_timeout_seconds as u64),
                        )
                        .await?
                } else {
                    service.complete_work(&job_id, wait.wait_point()).await?
                };
                apply_work_outcome(&mut report, &draft, outcome)?;
                report.mapping_status = document_mapping_status(&report);
                return Ok((report, Usage::default()));
            }
        }
        for recovered in service.prior_admissions(&job_id) {
            service
                .complete_recovered(recovered, wait.wait_point())
                .await?;
            let receipt = recovered.receipt();
            report.admitted_bundle_count = report.admitted_bundle_count.saturating_add(1);
            report.admitted_claim_count = report
                .admitted_claim_count
                .saturating_add(receipt.claim_ids().len());
            report.omitted_claim_count = report
                .omitted_claim_count
                .saturating_add(receipt.claim_ids().len());
            report.details_truncated = true;
            report.push_admission(canonical_json(&receipt.projection())?)?;
        }
        if service.has_prior_job(&job_id) {
            report.push_error(StageError {
                stage: "recovery",
                code: "prior_job_requires_explicit_new_extraction",
                window_id: None,
            })?;
            return Ok((report, Usage::default()));
        }
    }

    let raw_mapping_host = config
        .ontology_ledger_path
        .as_ref()
        .map(|path| {
            DirectFlureeOntologyToolHost::from_bootstrap(path)
                .map_err(|_| Error::invalid("raw ontology lookup pin unavailable"))
        })
        .transpose()?;
    if let Some(host) = &raw_mapping_host {
        if Some(
            host.provenance()
                .map_err(|_| Error::invalid("raw ontology pin unavailable"))?,
        ) != ontology_lookup
        {
            return Err(Error::new(
                ErrorKind::Conflict,
                "raw ontology capture changed",
            ));
        }
    }
    let vocabulary_host: Option<Arc<dyn OntologyToolHost>> = raw_mapping_host
        .clone()
        .map(|host| Arc::new(host) as Arc<dyn OntologyToolHost>)
        .or_else(|| semantic_vocabulary.map(|host| host as Arc<dyn OntologyToolHost>));
    let ontology_briefing = if config.protocol == AcquisitionProtocol::OntologyV2 {
        Some(build_v2_briefing(
            vocabulary_host
                .as_deref()
                .ok_or_else(|| Error::invalid("ontology-v2 requires a verified ontology source"))?,
            config,
            source.extraction.text(),
            &[],
        )?)
    } else {
        None
    };
    let streaming = if config.protocol == AcquisitionProtocol::OntologyV2 {
        Some(
            capture_v2_stream(
                service,
                config,
                store,
                &source,
                &catalog,
                bundle.as_ref(),
                recorded_assets.as_ref(),
                &windows,
                &job_id,
                ontology_lookup.as_ref(),
                ontology_briefing
                    .as_ref()
                    .ok_or_else(|| Error::invalid("missing ontology briefing"))?,
                vocabulary_host.clone(),
                entity_source.clone(),
                graph_query_config.clone(),
                read_only_config,
                captured_response,
                capture_manifest,
                mode != IngestMode::ExtractOnly || save_capture_manifest_path.is_some(),
                cancel.clone(),
                stored_replay,
                &mut report,
            )
            .await?,
        )
    } else {
        None
    };
    if let (Some(path), Some(streaming)) = (save_capture_manifest_path, streaming.as_ref()) {
        let manifest = capture_export_manifest(
            &source,
            bundle.as_ref(),
            recorded_assets.as_ref(),
            ontology_lookup.as_ref(),
            streaming,
        )?;
        write_capture_manifest(path, &manifest)?;
    }
    let mut maps = BTreeMap::new();
    let mut requests = Vec::with_capacity(windows.len());
    if streaming.is_none() {
        for window in &windows {
            let window_id = format!(
                "window:{}",
                &ContentHash::of_bytes(
                    format!(
                        "ctxql-window/v1\0{}\0{}",
                        source.extraction.text_version.as_str(),
                        window.ordinal
                    )
                    .as_bytes(),
                )
                .as_str()[7..]
            );
            let map = CoordinateMap::issue(
                source.extraction.text(),
                attempt_id.as_str(),
                &window_id,
                source.extraction.locator.clone(),
                source.extraction.text_version.clone(),
                ContentHash::of_bytes(source.extraction.text().as_bytes()),
                window.span,
            )?;
            let request = if config.protocol == AcquisitionProtocol::OntologyV2 {
                let (entity_capture, known_mentions) = if let Some(entity_source) = &entity_source {
                    let passage = window.span.select(source.extraction.text())?;
                    let released = entity_source
                        .gazetteer
                        .release_known_mentions(&entity_source.ledger, passage, window.span.start())
                        .await
                        .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
                    (
                        Some(entity_source.gazetteer.commitment().as_str()),
                        serde_json::from_str::<Value>(&released)
                            .map_err(|_| Error::invalid("entity mention encoding"))?,
                    )
                } else {
                    (None, Value::Array(Vec::new()))
                };
                render_request_v2(
                    &window_id,
                    source.extraction.locator.as_str(),
                    source.extraction.text_version.as_str(),
                    &map,
                    source.extraction.text(),
                    ontology_lookup.as_ref(),
                    ontology_briefing
                        .as_ref()
                        .ok_or_else(|| Error::invalid("missing ontology briefing"))?,
                    entity_capture,
                    Value::Array(Vec::new()),
                    known_mentions,
                    attempt_id.as_str(),
                    ContentHash::of_bytes(b"ctxql-empty-document-context/v1").as_str(),
                    &[],
                )?
            } else {
                render_request(
                    &window_id,
                    source.extraction.locator.as_str(),
                    source.extraction.text_version.as_str(),
                    &map,
                    source.extraction.text(),
                )?
            };
            report
                .issued_ranges
                .insert(window_id.clone(), map.issued_ranges());
            maps.insert(window_id.clone(), map);
            requests.push((window_id, request));
        }
    }
    let graph_session = streaming
        .as_ref()
        .and_then(|capture| capture.graph_session.clone());
    let graph_export = streaming
        .as_ref()
        .and_then(|capture| capture.graph_export.clone());
    if let Some(graph) = graph_export.as_ref() {
        let retained = verified_graph_capture(graph)?;
        let current_gazetteer = entity_source
            .as_deref()
            .map(|source| source.gazetteer.commitment().as_str());
        if retained.gazetteer_commitment.as_deref() != current_gazetteer {
            return Err(Error::new(
                ErrorKind::Conflict,
                "captured gazetteer context differs",
            ));
        }
    }
    let replay_graph_guard = if graph_session.is_none() {
        match (graph_export.as_ref(), service, graph_query_config.clone()) {
            (Some(graph), Some(service), Some(query_config)) => {
                let verified = verified_graph_capture(graph)?;
                let host = match replay_authority.clone() {
                    Some(host) => host,
                    None => create_graph_query_host(service, config, query_config).await?,
                };
                Some((host, verified.dependencies))
            }
            (Some(graph), None, _) if mode == IngestMode::ExtractOnly && stored_replay => {
                // Ephemeral replay reconstructs and verifies the retained graph
                // transcript below but has no admission/release sink. Current
                // authorization was checked by the authenticated replay owner.
                verified_graph_capture(graph)?;
                None
            }
            (Some(_), _, _) => {
                return Err(Error::new(
                    ErrorKind::Denied,
                    "graph replay authorization unavailable",
                ))
            }
            (None, _, _) => None,
        }
    } else {
        None
    };
    if let Some(streaming) = &streaming {
        maps = streaming.maps.clone();
    }

    let capture_raw = mode == IngestMode::ExtractOnly;
    let document_table = streaming.as_ref().map(|value| value.table.clone());
    let request_seeds = streaming
        .as_ref()
        .map(|value| value.request_seeds.clone())
        .unwrap_or_default();
    let issued_document_handles = streaming
        .as_ref()
        .map(|value| value.issued_handles.clone())
        .unwrap_or_default();
    let response_protocols = if let Some(streaming) = streaming.as_ref() {
        streaming.response_protocols.clone()
    } else {
        requests
            .iter()
            .map(|(window, request)| {
                request_response_protocol(request).map(|protocol| (window.clone(), protocol))
            })
            .collect::<Result<BTreeMap<_, _>>>()?
    };
    let request_snapshot = requests.clone();
    // Ontology-v2 uses immutable per-leaf capture jobs. This remains only as
    // an explicitly versioned legacy batch fallback.
    let capture_checkpoint: Option<V> = None;
    let single_request = if requests.len() == 1 {
        requests.first().cloned()
    } else {
        None
    };
    let (asset_manifest, assets) = capture_assets(bundle.as_ref(), recorded_assets.as_ref())?;
    let provider_model = asset_model(bundle.as_ref(), recorded_assets.as_ref())?;
    let provider_thinking = asset_thinking(bundle.as_ref(), recorded_assets.as_ref())?;
    let provider_bundle_hash = asset_hash(bundle.as_ref(), recorded_assets.as_ref())?;
    let source_representation = captured_source_representation(&source)?;
    let make_manifest = |window_id: &str, request: &str, response: &str| ProviderCaptureManifest {
        schema: CAPTURE_MANIFEST_SCHEMA.to_owned(),
        source_id: source.source_id.as_str().to_owned(),
        locator: source.extraction.locator.as_str().to_owned(),
        text_version: source.extraction.text_version.as_str().to_owned(),
        window_id: window_id.to_owned(),
        request_root: ContentHash::of_bytes(request.as_bytes())
            .as_str()
            .to_owned(),
        request: request.to_owned(),
        source_text: source.extraction.text().to_owned(),
        coordinate_seed: request_seeds
            .get(window_id)
            .map(String::as_str)
            .unwrap_or(attempt_id.as_str())
            .to_owned(),
        window_start: windows
            .iter()
            .find(|window| window_id_for(&source, window) == window_id)
            .map(|window| window.span.start())
            .unwrap_or(0),
        window_end: windows
            .iter()
            .find(|window| window_id_for(&source, window) == window_id)
            .map(|window| window.span.end())
            .unwrap_or(0),
        asset_manifest: asset_manifest.clone(),
        assets: assets.clone(),
        response_root: ContentHash::of_bytes(response.as_bytes())
            .as_str()
            .to_owned(),
        response: response.to_owned(),
        model: provider_model.to_owned(),
        thinking: provider_thinking.to_owned(),
        agent_bundle_hash: provider_bundle_hash.to_owned(),
        ontology_lookup: report.ontology_lookup.clone(),
        issued_ranges: report
            .issued_ranges
            .get(window_id)
            .cloned()
            .unwrap_or_default(),
        source_representation: Some(source_representation.clone()),
    };
    let (usage, outcomes) = if let Some(streaming) = streaming {
        (streaming.usage, streaming.outcomes)
    } else if let Some(ref checkpoint) = capture_checkpoint {
        let expected = V::parse(
            &serde_json::to_vec(&request_snapshot)
                .map_err(|_| Error::invalid("request encoding"))?,
            Limits::default(),
        )?;
        checkpoint.closed(&["schema", "requests", "responses", "bundle_hash"], &[])?;
        if checkpoint.field("schema")?.as_str()? != "ctxql-passage-capture/v1"
            || checkpoint.field("requests")? != &expected
            || checkpoint.field("bundle_hash")?.as_str()? != provider_bundle_hash
        {
            return Err(Error::new(
                ErrorKind::Conflict,
                "captured request context differs",
            ));
        }
        let responses = checkpoint
            .field("responses")?
            .as_array()?
            .iter()
            .map(|value| {
                value.closed(&["window", "text", "error"], &[])?;
                let window = value.field("window")?.as_str()?.to_owned();
                let response = match value.field("text")? {
                    V::String(text) if value.field("error")? == &V::Null => Ok(text.clone()),
                    V::Null => Err(saved_transport_error(value.field("error")?.as_str()?)?),
                    _ => return Err(Error::invalid("captured response shape")),
                };
                Ok((window, response))
            })
            .collect::<Result<Vec<_>>>()?;
        (Usage::default(), responses)
    } else if let Some(manifest) = capture_manifest {
        let CaptureManifest::Single(manifest) = manifest else {
            return Err(Error::invalid(
                "multi-passage capture requires ontology-v2 streaming",
            ));
        };
        let (window_id, request) = single_request
            .as_ref()
            .ok_or_else(|| Error::invalid("capture manifest requires one issued passage"))?;
        let expected = make_manifest(window_id, request, &manifest.response);
        verify_capture_manifest(manifest, &expected)?;
        (
            Usage::default(),
            vec![(
                window_id.clone(),
                Ok::<String, TransportError>(manifest.response.clone()),
            )],
        )
    } else if let Some(captured) = captured_response {
        if requests.len() != 1 {
            return Err(Error::invalid(
                "captured response requires one issued passage",
            ));
        }
        let (window_id, _) = requests
            .pop()
            .ok_or_else(|| Error::invalid("captured response has no passage"))?;
        (
            Usage::default(),
            vec![(window_id, Ok::<String, TransportError>(captured.to_owned()))],
        )
    } else {
        if let Some(source) = &entity_source {
            source
                .gazetteer
                .recheck_release(&source.ledger)
                .await
                .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        }
        let transport = build_transport_with_host(
            config,
            &catalog,
            bundle
                .as_ref()
                .ok_or_else(|| Error::invalid("live provider bundle unavailable"))?
                .clone(),
            ontology_lookup.as_ref(),
            vocabulary_host.clone(),
            entity_source.clone(),
            None,
            None,
        )?;
        let provider_cancel = cancel.clone();
        let (transport, outcomes) = tokio::task::spawn_blocking(move || {
            let mut outcomes = Vec::with_capacity(requests.len());
            for (window_id, request) in requests {
                if provider_cancel.is_cancelled() {
                    break;
                }
                let result = transport
                    .request(&request, &provider_cancel)
                    .map(|reply| reply.text);
                outcomes.push((window_id, result));
            }
            (transport, outcomes)
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Backend, "provider task failed"))?;
        let usage = transport.usage();
        transport.teardown();
        (usage, outcomes)
    };
    if config.protocol == AcquisitionProtocol::OntologyV2 && capture_checkpoint.is_some() {
        if let Some(service) = service {
            let capture = V::object([
                ("schema".into(), V::string("ctxql-passage-capture/v1")),
                (
                    "requests".into(),
                    V::parse(
                        &serde_json::to_vec(&request_snapshot)
                            .map_err(|_| Error::invalid("request encoding"))?,
                        Limits::default(),
                    )?,
                ),
                ("bundle_hash".into(), V::string(provider_bundle_hash)),
                (
                    "responses".into(),
                    V::Array(
                        outcomes
                            .iter()
                            .map(|(window, result)| {
                                V::object([
                                    ("window".into(), V::string(window)),
                                    (
                                        "text".into(),
                                        result.as_ref().map(V::string).unwrap_or(V::Null),
                                    ),
                                    (
                                        "error".into(),
                                        result
                                            .as_ref()
                                            .err()
                                            .map(|error| V::string(transport_error_code(error)))
                                            .unwrap_or(V::Null),
                                    ),
                                ])
                            })
                            .collect::<Result<Vec<_>>>()?,
                    ),
                ),
            ])?;
            service
                .seal_work_value(&job_id, "capture", &capture)
                .await?;
        }
    }
    if cancel.is_cancelled() {
        return Err(Error::new(ErrorKind::Deadline, "cancelled"));
    }

    if config.protocol == AcquisitionProtocol::OntologyV2 {
        if let Some(entity_source) = &entity_source {
            entity_source
                .gazetteer
                .recheck_release(&entity_source.ledger)
                .await
                .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        }
        if let Some(session) = graph_session.as_ref() {
            session.authorize_final_release().await?;
        }
        let processed = process_v2_outcomes(
            store,
            &source,
            mode,
            &maps,
            outcomes,
            ontology_mode,
            vocabulary_host
                .as_deref()
                .ok_or_else(|| Error::invalid("ontology-v2 lookup unavailable"))?,
            entity_source.as_deref().map(|source| &source.gazetteer),
            document_table
                .as_ref()
                .ok_or_else(|| Error::invalid("missing document entity checkpoint"))?,
            &response_protocols,
            &request_seeds,
            &issued_document_handles,
            &mut report,
        )?;
        let review_pages = processed.review_pages;
        if mode != IngestMode::ExtractOnly && !review_pages.is_empty() {
            if let Some(entity_source) = &entity_source {
                entity_source
                    .gazetteer
                    .recheck_release(&entity_source.ledger)
                    .await
                    .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
            }
            let service =
                service.ok_or_else(|| Error::invalid("review admission service unavailable"))?;
            let graph_artifacts = if let Some(graph) = graph_export.as_ref() {
                seal_graph_work(service, &job_id, graph).await?
            } else {
                V::Null
            };
            let records = build_review_records(&source, &extraction_run, &review_pages)?;
            // Outcome pages contain source-derived review only. A capture that
            // included a protected entity gazetteer is deliberately not
            // provisioned until that context has its own authorized reader.
            if entity_source.is_none() && graph_export.is_none() {
                let capture_root = service
                    .work
                    .get(&job_id, "capture")?
                    .ok_or_else(|| Error::invalid("missing acquisition capture binding"))?;
                let source_request = SourceReadRequest {
                    source_id: source.source_id.clone(),
                    version: source.extraction.text_version.clone(),
                    selector: EvidenceSelector::WholeDocument,
                    max_bytes: source.extraction.text().len(),
                };
                let source_hash = ContentHash::of_bytes(source.extraction.text().as_bytes());
                report.artifact_descriptors = review_pages
                    .iter()
                    .map(|page| {
                        AcquisitionArtifactDescriptor::new(
                            source_request.clone(),
                            source_hash.clone(),
                            page.outcome_root.clone(),
                            "evaluation_outcomes",
                            capture_root.clone(),
                        )
                        .and_then(|descriptor| canonical_json(&descriptor.projection()))
                    })
                    .collect::<Result<Vec<_>>>()?;
            }
            let graph_artifact_descriptors = if graph_artifacts != V::Null {
                let graph_context_root =
                    ContentHash::parse(graph_artifacts.field("context_root")?.as_str()?)?;
                let capture_root = service
                    .work
                    .get(&job_id, "capture")?
                    .ok_or_else(|| Error::invalid("missing acquisition capture binding"))?;
                let source_request = SourceReadRequest {
                    source_id: source.source_id.clone(),
                    version: source.extraction.text_version.clone(),
                    selector: EvidenceSelector::WholeDocument,
                    max_bytes: source.extraction.text().len(),
                };
                let source_hash = ContentHash::of_bytes(source.extraction.text().as_bytes());
                review_pages
                    .iter()
                    .map(|page| {
                        SourcePlusGraphArtifactDescriptor::new(
                            source_request.clone(),
                            source_hash.clone(),
                            page.outcome_root.clone(),
                            "evaluation_outcomes",
                            capture_root.clone(),
                            graph_context_root.clone(),
                        )
                        .map(|descriptor| descriptor.projection())
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                Vec::new()
            };
            let capture = service
                .current_catalog()
                .await?
                .identity()
                .capture()
                .clone();
            let bundle_hash = ContentHash::of_bytes(
                format!(
                    "ctxql-review-bundle/v1\0{}\0{}",
                    extraction_run.as_str(),
                    records
                        .iter()
                        .map(|record| record.id().as_str())
                        .collect::<Vec<_>>()
                        .join("\0")
                )
                .as_bytes(),
            );
            let review_bundle = ValidatedReviewBundle::new(
                BundleId::new(format!("bundle:{}", &bundle_hash.as_str()[7..]))?,
                format!("evaluation:{}", &job_key.as_str()[7..]),
                job_id.as_str(),
                attempt_id.clone(),
                capture,
                records,
                Limits::default(),
            )?;
            let report_value = V::parse(
                &serde_json::to_vec(&report).map_err(|_| Error::invalid("work report encoding"))?,
                Limits::default(),
            )?;
            let common = [
                ("job_id".to_owned(), V::string(job_id.as_str())),
                ("review".to_owned(), review_bundle.projection()),
                (
                    "claims".to_owned(),
                    V::Array(
                        processed
                            .claims
                            .iter()
                            .map(CandidateClaim::projection)
                            .collect(),
                    ),
                ),
                (
                    "assertions".to_owned(),
                    V::string(
                        if config.assertions == crate::config::AcquisitionAssertionPolicy::Accepted
                        {
                            "accepted"
                        } else {
                            "evidence-only"
                        },
                    ),
                ),
                (
                    "ontology_mode".to_owned(),
                    V::string(ontology_mode.as_str()),
                ),
                (
                    "extraction_run".to_owned(),
                    V::string(extraction_run.as_str()),
                ),
                ("report".to_owned(), report_value),
            ];
            let draft = if graph_artifacts == V::Null {
                let mut fields = std::collections::BTreeMap::from(common);
                fields.insert("schema".into(), V::string("ctxql-acquisition-work/v1"));
                V::Object(fields)
            } else {
                let mut fields = std::collections::BTreeMap::from(common);
                fields.insert(
                    "schema".into(),
                    V::string("ctxql-acquisition-graph-work/v1"),
                );
                fields.insert("graph".into(), graph_artifacts);
                fields.insert(
                    "graph_artifact_descriptors".into(),
                    V::Array(graph_artifact_descriptors),
                );
                V::Object(fields)
            };
            service
                .seal_work_value(&job_id, "evaluation", &draft)
                .await?;
            let wait = mode
                .wait()
                .ok_or_else(|| Error::invalid("admission wait point unavailable"))?
                .wait_point();
            let outcome = if let Some(session) = graph_session.clone() {
                service
                    .complete_work_guarded(&job_id, wait, Some(session))
                    .await?
            } else if let Some((host, dependencies)) = replay_graph_guard.clone() {
                service
                    .complete_work_guarded_dependencies(
                        &job_id,
                        wait,
                        host,
                        dependencies,
                        Instant::now()
                            + Duration::from_secs(config.provider_timeout_seconds as u64),
                    )
                    .await?
            } else {
                service.complete_work(&job_id, wait).await?
            };
            apply_work_outcome(&mut report, &draft, outcome)?;
        }
        report.mapping_status = document_mapping_status(&report);
        if mode == IngestMode::ExtractOnly {
            if let Some(session) = graph_session.as_ref() {
                session.authorize_final_release().await?;
                session.complete()?;
            }
        }
        return Ok((report, usage));
    }

    let candidate_limits = CandidateLimits::default();
    let fact_limits = FactBlockLimits::default();
    for (window_id, outcome) in outcomes {
        let raw = match outcome {
            Ok(raw) => raw,
            Err(error) => {
                let code = transport_error_code(&error);
                if capture_raw {
                    report.provider_responses.push(ProviderResponseReport {
                        phase: "individual",
                        window_ids: vec![window_id.clone()],
                        text: None,
                        text_sha256: None,
                        parse_error: None,
                        transport_error: Some(code),
                    });
                }
                report.push_error(StageError {
                    stage: "provider",
                    code,
                    window_id: Some(window_id),
                })?;
                continue;
            }
        };
        let map = maps
            .get(&window_id)
            .ok_or_else(|| Error::invalid("provider returned unknown window"))?;
        let line_ids = map
            .lines()
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>();
        let parsed = parse_independent_fact_blocks(&raw, &line_ids, &fact_limits);
        if capture_raw {
            report.provider_responses.push(ProviderResponseReport {
                phase: "individual",
                window_ids: vec![window_id.clone()],
                text_sha256: Some(ContentHash::of_bytes(raw.as_bytes()).as_str().to_owned()),
                text: Some(raw),
                parse_error: parsed
                    .as_ref()
                    .err()
                    .map(fact_parse_error_code)
                    .or_else(|| {
                        parsed.as_ref().ok().and_then(|blocks| {
                            blocks
                                .iter()
                                .find_map(|block| block.as_ref().err().map(fact_parse_error_code))
                        })
                    }),
                transport_error: None,
            });
        }
        let proposals = match parsed {
            Ok(proposals) => proposals,
            Err(error) => {
                report.push_error(StageError {
                    stage: "provider_grammar",
                    code: fact_parse_error_code(&error),
                    window_id: Some(window_id),
                })?;
                continue;
            }
        };
        if proposals.is_empty() {
            report.no_claim_window_count = report.no_claim_window_count.saturating_add(1);
            continue;
        }

        for (candidate_index, proposal) in proposals.into_iter().enumerate() {
            report.candidate_count = report.candidate_count.saturating_add(1);
            let proposal = match proposal {
                Ok(proposal) => proposal,
                Err(error) => {
                    report.rejected_candidate_count =
                        report.rejected_candidate_count.saturating_add(1);
                    let code = fact_parse_error_code(&error);
                    report.validations.push(ValidationReport {
                        window_id: window_id.clone(),
                        candidate_index: Some(candidate_index),
                        status: "grammar_rejected",
                        validated_claim_count: 0,
                        error: Some(code),
                    });
                    report.push_error(StageError {
                        stage: "provider_grammar",
                        code,
                        window_id: Some(window_id.clone()),
                    })?;
                    continue;
                }
            };
            let coordinate = match exact_quote_coordinate(
                map,
                source.extraction.text(),
                &proposal.line_id,
                &proposal.quote,
            ) {
                Ok(coordinate) => coordinate,
                Err(_) => {
                    report.rejected_candidate_count =
                        report.rejected_candidate_count.saturating_add(1);
                    report.validations.push(ValidationReport {
                        window_id: window_id.clone(),
                        candidate_index: Some(candidate_index),
                        status: "grounding_rejected",
                        validated_claim_count: 0,
                        error: Some("source_evidence_rejected"),
                    });
                    continue;
                }
            };
            // Only typed blocks independently evidence both endpoint roles.
            let typed_coordinates = if let Some(typed) = &proposal.typed_endpoint_evidence {
                let subject = exact_quote_coordinate(
                    map,
                    source.extraction.text(),
                    &typed.subject_line_id,
                    &typed.subject_quote,
                );
                let object = exact_quote_coordinate(
                    map,
                    source.extraction.text(),
                    &typed.object_line_id,
                    &typed.object_quote,
                );
                if !role_is_explicit(&typed.subject_role, &proposal.subject, &typed.subject_quote)
                    || !role_is_explicit(&typed.object_role, &proposal.object, &typed.object_quote)
                    || subject.is_err()
                    || object.is_err()
                {
                    report.rejected_candidate_count =
                        report.rejected_candidate_count.saturating_add(1);
                    report.validations.push(ValidationReport {
                        window_id: window_id.clone(),
                        candidate_index: Some(candidate_index),
                        status: "grounding_rejected",
                        validated_claim_count: 0,
                        error: Some("endpoint_evidence_rejected"),
                    });
                    continue;
                }
                Some((subject?, object?))
            } else {
                None
            };
            let typed_mapping = typed_coordinates
                .as_ref()
                .filter(|_| ontology_mode == OntologyMode::Hard)
                .and_then(|(subject, object)| {
                    let typed = proposal.typed_endpoint_evidence.as_ref()?;
                    let host = raw_mapping_host.as_ref()?;
                    let authority = RawMappingAuthority::new(&catalog, host, true).ok()?;
                    Some((
                        authority
                            .resolve_unique(&proposal.predicate, OntologyTermKind::Property)
                            .ok()?,
                        authority
                            .resolve_unique(&typed.subject_role, OntologyTermKind::Class)
                            .ok()?,
                        authority
                            .resolve_unique(&typed.object_role, OntologyTermKind::Class)
                            .ok()?,
                        subject.clone(),
                        object.clone(),
                    ))
                });
            let mapping = if ontology_mode == OntologyMode::Hard
                && proposal.typed_endpoint_evidence.is_none()
            {
                exact_ontology_mapping(&catalog, &proposal, None)
            } else {
                None
            };
            let (advisory, mapping_status, provisional) = match (typed_mapping, mapping) {
                (
                    Some((
                        predicate,
                        subject_type,
                        object_type,
                        subject_coordinate,
                        object_coordinate,
                    )),
                    _,
                ) => {
                    report.mapped_candidate_count = report.mapped_candidate_count.saturating_add(1);
                    (
                        mapped_object_advisory(
                            &source,
                            &window_id,
                            candidate_index,
                            &proposal,
                            coordinate,
                            subject_coordinate,
                            object_coordinate,
                            predicate,
                            subject_type,
                            object_type,
                            &candidate_limits,
                        )?,
                        "mapped",
                        false,
                    )
                }
                (None, Some((predicate, subject_type, type_coordinate))) => {
                    report.mapped_candidate_count = report.mapped_candidate_count.saturating_add(1);
                    (
                        mapped_advisory(
                            &source,
                            &window_id,
                            candidate_index,
                            &proposal,
                            coordinate,
                            type_coordinate,
                            predicate,
                            subject_type,
                            &candidate_limits,
                        )?,
                        "mapped",
                        false,
                    )
                }
                (None, None) if ontology_mode == OntologyMode::Soft => {
                    report.provisional_candidate_count =
                        report.provisional_candidate_count.saturating_add(1);
                    (
                        provisional_advisory(
                            &source,
                            &window_id,
                            candidate_index,
                            &proposal,
                            coordinate,
                            &candidate_limits,
                        )?,
                        "provisional",
                        true,
                    )
                }
                (None, None) => {
                    report.unmapped_candidate_count =
                        report.unmapped_candidate_count.saturating_add(1);
                    report.validations.push(ValidationReport {
                        window_id: window_id.clone(),
                        candidate_index: Some(candidate_index),
                        status: "unmapped",
                        validated_claim_count: 0,
                        error: None,
                    });
                    continue;
                }
            };

            let current_catalog = if let Some(service) = service {
                service.current_catalog().await?
            } else {
                catalog.clone()
            };
            if current_catalog.identity().catalog_root() != catalog.identity().catalog_root() {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "ontology catalog changed during ingestion",
                ));
            }
            // Labels are not identity evidence. Fall back to a per-fact key.
            let resolver =
                CaptureEntityResolver::new(current_catalog.capture_token(), std::iter::empty())?;
            let descriptor = fact_descriptor(
                &source,
                &advisory,
                &window_id,
                provider_bundle_hash,
                &catalog,
                ontology_mode,
                mapping_status,
                &proposal,
                ontology_lookup.as_ref(),
            )?;
            let input = ValidationInput {
                extraction_run: extraction_run.clone(),
                validation_capture: current_catalog.identity().capture().clone(),
                descriptor,
                source_id: source.source_id.clone(),
                document: source.extraction.text(),
                attempt_id: attempt_id.as_str(),
                window_id: &window_id,
                coordinates: map,
                max_spans_per_claim: candidate_limits.max_spans_per_claim,
                limits: Limits::default(),
            };
            let validated = if provisional {
                validate_provisional_bundle(advisory.clone(), input)
            } else if let Some(host) = raw_mapping_host
                .as_ref()
                .filter(|_| typed_coordinates.is_some())
            {
                let authority = RawMappingAuthority::new(&current_catalog, host, true)?;
                validate_bundle(advisory.clone(), input, &authority, &resolver)
            } else {
                validate_bundle(advisory.clone(), input, &current_catalog, &resolver)
            };
            let validated = match validated {
                Ok(validated) => validated,
                Err(error) => {
                    report.rejected_candidate_count =
                        report.rejected_candidate_count.saturating_add(1);
                    let code = validation_error_code(&error);
                    report.validations.push(ValidationReport {
                        window_id: window_id.clone(),
                        candidate_index: Some(candidate_index),
                        status: "validation_rejected",
                        validated_claim_count: 0,
                        error: Some(code),
                    });
                    report.push_error(StageError {
                        stage: "validation",
                        code,
                        window_id: Some(window_id.clone()),
                    })?;
                    continue;
                }
            };
            report.validated_bundle_count = report.validated_bundle_count.saturating_add(1);
            report.validated_claim_count = report
                .validated_claim_count
                .saturating_add(validated.claims().len());
            report.validations.push(ValidationReport {
                window_id: window_id.clone(),
                candidate_index: Some(candidate_index),
                status: mapping_status,
                validated_claim_count: validated.claims().len(),
                error: None,
            });
            if !provisional && typed_coordinates.is_some() {
                let path = config.ontology_ledger_path.as_ref().ok_or_else(|| {
                    Error::new(
                        ErrorKind::Conflict,
                        "raw ontology pin absent before admission",
                    )
                })?;
                let current_raw =
                    DirectFlureeOntologyToolHost::from_bootstrap(path).map_err(|_| {
                        Error::new(
                            ErrorKind::Conflict,
                            "raw ontology pin drifted before admission",
                        )
                    })?;
                if Some(
                    current_raw.provenance().map_err(|_| {
                        Error::new(ErrorKind::Conflict, "raw ontology pin unavailable")
                    })?,
                ) != ontology_lookup
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "raw ontology capture changed before admission",
                    ));
                }
            }
            if mode == IngestMode::ExtractOnly {
                continue;
            }
            let selector_root = selector_root(&source, &window_id, map)?;
            let safe_counts = V::object([
                (
                    "claim_count".into(),
                    V::Number(ExactNumber::parse(&validated.claims().len().to_string())?),
                ),
                (
                    "source_span_count".into(),
                    V::Number(ExactNumber::parse(
                        &advisory
                            .metadata
                            .iter()
                            .map(|item| item.coordinates.len())
                            .sum::<usize>()
                            .to_string(),
                    )?),
                ),
            ])?;
            let admitted_count = validated.claims().len();
            let admission = service
                .ok_or_else(|| Error::invalid("admission service unavailable"))?
                .admit_foreground(
                    job_id.clone(),
                    attempt_id.clone(),
                    &validated,
                    selector_root,
                    safe_counts,
                    now()?,
                    mode.wait()
                        .ok_or_else(|| Error::invalid("admission wait point unavailable"))?
                        .wait_point(),
                    AdmissionContext::NoGraph,
                )
                .await?;
            report.admitted_bundle_count = report.admitted_bundle_count.saturating_add(1);
            report.admitted_claim_count =
                report.admitted_claim_count.saturating_add(admitted_count);
            for claim in validated.claims() {
                report.push_claim(canonical_json(&claim.projection())?)?;
            }
            report.push_admission(canonical_json(&admission.admission.projection())?)?;
        }
    }
    report.mapping_status = document_mapping_status(&report);
    Ok((report, usage))
}

struct GraphObjectStore {
    writer: SourceObjectWriter,
}

impl GraphObjectStore {
    fn persist_payload(&self, root: &ContentHash, bytes: &[u8]) -> Result<()> {
        let stored = self.writer.put_object(bytes)?;
        if &stored != root {
            return Err(Error::new(
                ErrorKind::Conflict,
                "graph payload root mismatch",
            ));
        }
        Ok(())
    }
}

impl GraphCaptureStore for GraphObjectStore {
    fn persist_leaf(&self, root: &ContentHash, bytes: &[u8]) -> Result<()> {
        let stored = self.writer.put_object(bytes)?;
        if &stored != root {
            return Err(Error::new(
                ErrorKind::Conflict,
                "graph capture root mismatch",
            ));
        }
        Ok(())
    }
}

struct LiveGraphCapture {
    capability: Value,
    recorder: Mutex<GraphCaptureRecorder>,
    payloads: Mutex<BTreeMap<String, Value>>,
    store: GraphObjectStore,
}

#[derive(Clone)]
struct StreamingV2Capture {
    maps: BTreeMap<String, CoordinateMap>,
    outcomes: Vec<(String, std::result::Result<String, TransportError>)>,
    response_protocols: BTreeMap<String, ProposalResponseProtocol>,
    request_seeds: BTreeMap<String, String>,
    issued_handles: BTreeMap<String, Vec<String>>,
    passage_manifests: Vec<PassageCaptureManifest>,
    document_seed: String,
    graph_session: Option<Arc<GraphSession>>,
    graph_export: Option<GraphCaptureExport>,
    table: DocumentEntityTable,
    usage: Usage,
}

fn window_id_for(source: &PreparedSource, window: &Window) -> String {
    format!(
        "window:{}",
        &ContentHash::of_bytes(
            format!(
                "ctxql-window/v1\0{}\0{}",
                source.extraction.text_version.as_str(),
                window.ordinal
            )
            .as_bytes(),
        )
        .as_str()[7..]
    )
}

fn leaf_job_id(parent: &JobId, ordinal: usize, window_id: &str) -> Result<JobId> {
    let root = ContentHash::of_bytes(
        format!(
            "ctxql-streaming-capture-leaf/v2\0{}\0{}\0{}",
            parent.as_str(),
            ordinal,
            window_id
        )
        .as_bytes(),
    );
    JobId::new(format!("job:{}", &root.as_str()[7..]))
}

fn request_seed(
    document_seed: &ContentHash,
    window: &Window,
    window_id: &str,
    prior_context: &ContentHash,
) -> String {
    ContentHash::of_bytes(
        format!(
            "ctxql-passage-request-seed/v2\0{}\0{}\0{}\0{}\0{}",
            document_seed.as_str(),
            window_id,
            window.span.start(),
            window.span.end(),
            prior_context.as_str()
        )
        .as_bytes(),
    )
    .as_str()
    .to_owned()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProposalResponseProtocol {
    HistoricalJson,
    TextV1,
}

fn request_response_protocol(request: &str) -> Result<ProposalResponseProtocol> {
    let value: Value = serde_json::from_str(request)
        .map_err(|_| Error::invalid("acquisition request encoding"))?;
    match value.get("response_protocol") {
        None => Ok(ProposalResponseProtocol::HistoricalJson),
        Some(Value::String(value)) if value == TEXT_PROPOSAL_PROTOCOL => {
            Ok(ProposalResponseProtocol::TextV1)
        }
        Some(_) => Err(Error::invalid("unsupported acquisition response protocol")),
    }
}

struct ParsedProposalResponse {
    envelope: ProposalEnvelopeV2,
    diagnostics: Vec<TextProposalDiagnostic>,
}

fn parse_proposal_response(
    raw: &str,
    context: &ProposalParseContext<'_>,
    limits: &ProposalLimits,
    protocol: ProposalResponseProtocol,
) -> std::result::Result<ParsedProposalResponse, ProposalParseError> {
    match protocol {
        ProposalResponseProtocol::HistoricalJson => {
            parse_proposals(raw, context, limits).map(|envelope| ParsedProposalResponse {
                envelope,
                diagnostics: Vec::new(),
            })
        }
        ProposalResponseProtocol::TextV1 => {
            parse_proposals_text(raw, context, limits).map(|parsed| ParsedProposalResponse {
                envelope: parsed.envelope,
                diagnostics: parsed.diagnostics,
            })
        }
    }
}

fn update_document_table(
    table: &mut DocumentEntityTable,
    source: &PreparedSource,
    map: &CoordinateMap,
    window_id: &str,
    request_seed: &str,
    raw: &str,
    protocol: ProposalResponseProtocol,
) -> Result<usize> {
    let handles = table
        .entities()
        .map(|entity| entity.handle.as_str().to_owned())
        .collect::<Vec<_>>();
    let issued = map.issued_ranges();
    let context = ProposalParseContext {
        passage_namespace: window_id,
        issued_ranges: &issued,
        document_handles: &handles,
    };
    let Ok(parsed) = parse_proposal_response(raw, &context, &ProposalLimits::default(), protocol)
    else {
        return Ok(0);
    };
    let envelope = parsed.envelope;
    let component_count = envelope
        .entities
        .iter()
        .map(|entity| {
            1usize.saturating_add(entity.parsed().map_or(0, |entity| {
                entity.aliases.len().saturating_add(entity.classes.len())
            }))
        })
        .sum::<usize>()
        .saturating_add(envelope.attributes.len())
        .saturating_add(envelope.relations.len())
        .saturating_add(parsed.diagnostics.len());
    for component in &envelope.entities {
        let Some(entity) = component.parsed() else {
            continue;
        };
        let Ok(grounded) = ground_evidence(
            map,
            source.extraction.text(),
            &entity.evidence,
            ProposalLimits::default().max_evidence,
        ) else {
            continue;
        };
        let spans = grounded
            .iter()
            .map(|item| item.resolved.span)
            .collect::<Vec<Utf8Span>>();
        let handle = table.resolve_or_mint(
            source.extraction.text(),
            request_seed,
            &entity.id,
            &entity.name,
            &spans,
            &[],
        )?;
        for alias in &entity.aliases {
            let Some(alias) = alias.parsed() else {
                continue;
            };
            if let Ok(grounded) = ground_evidence(
                map,
                source.extraction.text(),
                std::slice::from_ref(&alias.evidence),
                1,
            ) {
                if let Some(item) = grounded.first() {
                    // Invalid/nonliteral alias proposals remain review outcomes;
                    // only evidence-backed aliases enter identity context.
                    let _ = table.bind_alias(
                        source.extraction.text(),
                        &handle,
                        alias.name.clone(),
                        item.resolved.span,
                    );
                }
            }
        }
    }
    Ok(component_count)
}

async fn create_graph_query_host(
    service: &Arc<AcquisitionService>,
    config: &AcquisitionConfig,
    query_config: ArtifactRef,
) -> Result<Arc<GraphQueryHost>> {
    let workspace = config
        .graph_workspace
        .as_ref()
        .ok_or_else(|| Error::invalid("graph workspace configuration unavailable"))?;
    let profile = match (&workspace.profile_selector, &workspace.profile) {
        (Some(selector), Some(reference)) => Some((selector.clone(), reference.artifact_ref()?)),
        (None, None) => None,
        _ => return Err(Error::invalid("graph query profile binding")),
    };
    let query_limits = GraphQueryLimits {
        max_nodes: workspace.max_nodes,
        max_claims: workspace.max_claims,
        max_response_bytes: workspace.max_response_bytes,
        max_work: 100_000,
        timeout: Duration::from_secs(workspace.query_timeout_seconds as u64),
    };
    service
        .graph_query_host(query_config, profile, query_limits)
        .await
}

async fn create_extract_only_graph_host(
    instance: &InstanceConfig,
    config: &AcquisitionConfig,
    query_config: ArtifactRef,
) -> Result<Arc<GraphQueryHost>> {
    use cdb_core::{
        contracts::SemanticProjectionSource, id::VersionId, snapshot::ProjectionCheckpoint,
    };
    let workspace = config
        .graph_workspace
        .as_ref()
        .ok_or_else(|| Error::invalid("graph workspace configuration unavailable"))?;
    let (path, options) = instance.semantic_binding()?;
    let original = Arc::new(FlureeSemanticLedger::open_file(path, options.clone()).await?);
    let binding = ProjectionCheckpoint::new(
        SemanticProjectionSource::head(original.as_ref()).await?,
        VersionId::new("ctxql-semantic-rdf/v1")?,
        VersionId::new("live")?,
        Iri::new("urn:ctxql:semantic-projection:v1")?,
    )?;
    let isolated = Arc::new(
        crate::graph_read_only::IsolatedGraphReadSnapshot::copy_from(
            &original,
            path,
            options,
            &instance.projection,
            binding,
        )
        .await?,
    );
    let control = Arc::new(
        cdb_backend_fluree::FlureeBackend::open(instance.authority_options()?)
            .await
            .map_err(|_| Error::new(ErrorKind::Backend, "graph read authority unavailable"))?,
    );
    let profile = match (&workspace.profile_selector, &workspace.profile) {
        (Some(selector), Some(reference)) => Some((selector.clone(), reference.artifact_ref()?)),
        (None, None) => None,
        _ => return Err(Error::invalid("graph query profile binding")),
    };
    GraphQueryHost::prepare_read_only(
        original,
        isolated,
        control,
        cdb_core::id::PrincipalId::new(&config.principal)?,
        config.action.clone(),
        query_config,
        profile,
        GraphQueryLimits {
            max_nodes: workspace.max_nodes,
            max_claims: workspace.max_claims,
            max_response_bytes: workspace.max_response_bytes,
            max_work: 100_000,
            timeout: Duration::from_secs(workspace.query_timeout_seconds as u64),
        },
    )
    .await
}

async fn create_graph_session(
    host: Arc<GraphQueryHost>,
    config: &AcquisitionConfig,
    source: &PreparedSource,
    parent_job: &JobId,
    stable_session_seed: &ContentHash,
    evidence: &[String],
    entity_source: Option<&CapturedEntitySource>,
) -> Result<Arc<GraphSession>> {
    let workspace = config
        .graph_workspace
        .as_ref()
        .ok_or_else(|| Error::invalid("graph workspace configuration unavailable"))?;
    let workspace_limits = WorkspaceLimits {
        max_nodes_per_graph: workspace.max_nodes,
        max_claims_per_graph: workspace.max_claims,
        max_live_graphs: workspace.max_live_graphs,
        max_imported_nodes: workspace
            .max_nodes
            .saturating_mul(workspace.max_live_graphs),
        max_imported_claims: workspace
            .max_claims
            .saturating_mul(workspace.max_live_graphs),
        max_tool_calls: workspace.max_tool_calls,
        max_graph_queries: workspace.max_graph_queries,
        max_request_bytes: workspace.max_request_bytes,
        max_response_bytes: workspace.max_response_bytes,
        max_aggregate_bytes: workspace
            .max_aggregate_bytes
            .min(workspace.reserved_tool_result_bytes),
        max_state_bytes: workspace.max_state_bytes,
        ..WorkspaceLimits::default()
    };
    let range_root = ContentHash::of_bytes(
        &serde_json::to_vec(evidence).map_err(|_| Error::invalid("graph evidence encoding"))?,
    );
    // Persist the fresh attempt seed in the capture index. It is independent
    // of source coordinates and is reused only by offline reconstruction.
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce)
        .map_err(|_| Error::new(ErrorKind::Backend, "graph session seed unavailable"))?;
    let mut seed = stable_session_seed.as_str().as_bytes().to_vec();
    seed.extend_from_slice(&nonce);
    let session_seed = ContentHash::of_bytes(&seed);
    GraphSession::new_with_gazetteer(
        "ctxql-acquisition-v1".into(),
        session_seed.as_str().to_owned(),
        parent_job.as_str().to_owned(),
        source.extraction.text_version.as_str().to_owned(),
        range_root.as_str().to_owned(),
        evidence.iter().cloned().collect(),
        entity_source
            .map(|source| {
                let mut context = GazetteerContext::new(
                    source.gazetteer.commitment().as_str().to_owned(),
                    source.gazetteer.dependencies().clone(),
                )?;
                context.snapshot = Some(
                    source
                        .gazetteer
                        .replay_snapshot()
                        .map_err(|reason| Error::new(ErrorKind::Invalid, reason))?,
                );
                Ok::<_, Error>(context)
            })
            .transpose()?,
        host,
        workspace_limits,
        Instant::now() + Duration::from_secs(config.provider_timeout_seconds as u64),
    )
}

fn finalize_graph_export(
    _workspace: &AcquisitionGraphWorkspaceConfig,
    session: &Arc<GraphSession>,
    capture: &Arc<LiveGraphCapture>,
) -> Result<GraphCaptureExport> {
    let (_, workspace_value, context) = session.capture_state()?;
    let capability = capture.capability.clone();
    let capability_value = V::parse(
        &serde_json::to_vec(&capability)
            .map_err(|_| Error::invalid("graph capability encoding"))?,
        Limits::default(),
    )?;
    let workspace_root =
        ContentHash::of_bytes(&workspace_value.canonical_bytes(Limits::default())?);
    let recorder = capture
        .recorder
        .lock()
        .map_err(|_| Error::new(ErrorKind::Backend, "graph capture lock"))?;
    let index = recorder.finalize(
        session.session_id(),
        ContentHash::of_bytes(&capability_value.canonical_bytes(Limits::default())?),
        workspace_root,
        &context,
    )?;
    Ok(GraphCaptureExport {
        schema: if context.gazetteer().is_some() {
            "ctxql-provider-graph-capture/v3"
        } else {
            "ctxql-provider-graph-capture/v2"
        }
        .into(),
        capability,
        workspace: canonical_json(&workspace_value)?,
        context: canonical_json(&context.projection()?)?,
        transcript_leaves: recorder
            .leaf_projections()?
            .iter()
            .map(canonical_json)
            .collect::<Result<Vec<_>>>()?,
        graph_payloads: capture
            .payloads
            .lock()
            .map_err(|_| Error::new(ErrorKind::Backend, "graph capture lock"))?
            .clone(),
        index: canonical_json(&index.projection()?)?,
    })
}

fn graph_workspace_capability(workspace: &AcquisitionGraphWorkspaceConfig) -> Value {
    json!({
        "schema": "ctxql-graph-query-capability/v1",
        "query_language": "ctxql-inline/v1",
        "read_only": true,
        "max_nodes": workspace.max_nodes,
        "max_claims": workspace.max_claims,
        "max_live_graphs": workspace.max_live_graphs,
        "max_tool_calls": workspace.max_tool_calls,
        "max_graph_queries": workspace.max_graph_queries,
        "max_request_bytes": workspace.max_request_bytes,
        "max_response_bytes": workspace.max_response_bytes,
        "max_aggregate_bytes": workspace.max_aggregate_bytes.min(workspace.reserved_tool_result_bytes),
        "query_timeout_seconds": workspace.query_timeout_seconds,
        "complete_results_only": true,
        "skills": ["read-loan-agreement-v2", "ctxql-ontology", "ctxql-query", "graph-workspace"]
    })
}

fn graph_workspace_request_context(
    request: String,
    config: &AcquisitionConfig,
    query_config: Option<&ArtifactRef>,
) -> Result<String> {
    let Some(workspace) = &config.graph_workspace else {
        return Ok(request);
    };
    let mut value: Value =
        serde_json::from_str(&request).map_err(|_| Error::invalid("provider request encoding"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Error::invalid("provider request shape"))?;
    let mut capability = graph_workspace_capability(workspace);
    capability["query_config"] = canonical_json(
        &query_config
            .ok_or_else(|| Error::invalid("graph query config unavailable"))?
            .projection(),
    )?;
    capability["profile_selector"] = serde_json::to_value(&workspace.profile_selector)
        .map_err(|_| Error::invalid("graph profile encoding"))?;
    capability["profile"] = workspace
        .profile
        .as_ref()
        .map(|reference| canonical_json(&reference.artifact_ref()?.projection()))
        .transpose()?
        .unwrap_or(Value::Null);
    capability["renderer_version"] = json!("ctxql-graph-renderer/v1");
    capability["tool_version"] = json!("ctxql-graph-tools/v1");
    object.insert("graph_workspace".into(), capability);
    serde_json::to_string(&value).map_err(|_| Error::invalid("provider request encoding"))
}

fn check_provider_context_budget(
    request_bytes: usize,
    system_bytes: usize,
    config: &AcquisitionConfig,
) -> Result<()> {
    let (max_context, final_reserve, tool_reserve) = config
        .graph_workspace
        .as_ref()
        .map(|workspace| {
            (
                workspace.max_context_bytes,
                workspace.reserved_final_output_bytes,
                workspace.reserved_tool_result_bytes,
            )
        })
        .unwrap_or((512 * 1024, 128 * 1024, 128 * 1024));
    if request_bytes
        .checked_add(system_bytes)
        .and_then(|bytes| bytes.checked_add(final_reserve))
        .and_then(|bytes| bytes.checked_add(tool_reserve))
        .is_none_or(|bytes| bytes > max_context)
    {
        return Err(Error::new(ErrorKind::Limit, "context_budget_insufficient"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn capture_v2_stream(
    service: Option<&Arc<AcquisitionService>>,
    config: &AcquisitionConfig,
    store: &SourceObjectWriter,
    source: &PreparedSource,
    catalog: &CertifiedOntologyCatalog,
    bundle: Option<&AgentBundle>,
    recorded_assets: Option<&VerifiedRecordedAssets>,
    windows: &[Window],
    parent_job: &JobId,
    ontology_lookup: Option<&V>,
    ontology_briefing: &Value,
    vocabulary_host: Option<Arc<dyn OntologyToolHost>>,
    entity_source: Option<Arc<CapturedEntitySource>>,
    graph_query_config: Option<ArtifactRef>,
    read_only_config: Option<&InstanceConfig>,
    captured_response: Option<&str>,
    capture_manifest: Option<&CaptureManifest>,
    retain_export: bool,
    cancel: CancellationToken,
    stored_replay: bool,
    report: &mut DocumentReport,
) -> Result<StreamingV2Capture> {
    let mut table = DocumentEntityTable::new(
        source.source_id.clone(),
        source.extraction.text_version.clone(),
        source.extraction.text(),
    );
    // Evaluation jobs include assertion/mapping policy; coordinate seeds must
    // not. Bind the actual model context instead, so one capture can be
    // evaluated in different modes without rewriting issued evidence handles.
    let document_seed = ContentHash::of_bytes(&serde_json::to_vec(&json!({
        "schema": "ctxql-document-capture-seed/v3",
        "limits": {"schema": "ctxql-document-capture-limits/v1", "passages": 256,
            "components": 4096, "retained_bytes": config.max_source_bytes,
            "combined_context_bytes": 512 * 1024, "output_tool_reserve_bytes": 256 * 1024},
        "source_id": source.source_id.as_str(),
        "locator": source.extraction.locator.as_str(),
        "text_version": source.extraction.text_version.as_str(),
        "source_text_hash": ContentHash::of_bytes(source.extraction.text().as_bytes()).as_str(),
        "bundle_hash": asset_hash(bundle, recorded_assets)?,
        "model": asset_model(bundle, recorded_assets)?,
        "thinking": asset_thinking(bundle, recorded_assets)?,
        "ontology": ontology_lookup.map(canonical_json).transpose()?,
        "briefing": ontology_briefing,
        "gazetteer": entity_source.as_ref().map(|source| source.gazetteer.commitment().as_str()),
        "windows": windows.iter().map(|window| (window.ordinal, window.span.start(), window.span.end())).collect::<Vec<_>>(),
    })).map_err(|_| Error::invalid("capture seed encoding"))?);
    let leaf_jobs = windows
        .iter()
        .map(|window| {
            let id = window_id_for(source, window);
            leaf_job_id(parent_job, window.ordinal, &id).map(|job| (id, job))
        })
        .collect::<Result<Vec<_>>>()?;
    let existing = if let Some(service) = service {
        let mut values = Vec::with_capacity(leaf_jobs.len());
        for (_, job) in &leaf_jobs {
            values.push(service.work_value(job, "capture").await?);
        }
        values
    } else {
        vec![None; leaf_jobs.len()]
    };
    let existing_count = existing.iter().filter(|value| value.is_some()).count();
    if existing_count != 0 && existing_count != windows.len() {
        let missing = existing
            .iter()
            .enumerate()
            .filter_map(|(ordinal, value)| value.is_none().then_some(ordinal.to_string()))
            .collect::<Vec<_>>()
            .join(",");
        return Err(Error::new(
            ErrorKind::Conflict,
            format!("partial passage capture is missing passage ordinals [{missing}]; explicit continuation required"),
        ));
    }
    if let Some(CaptureManifest::Multi(manifest)) = capture_manifest {
        verify_multi_capture_context(
            manifest,
            source,
            recorded_assets.ok_or_else(|| Error::invalid("recorded assets unavailable"))?,
            ontology_lookup,
            document_seed.as_str(),
            windows,
        )?;
    }
    let replaying = existing_count == windows.len();
    let graph_enabled = config.graph_workspace.is_some();
    let mut graph_session: Option<Arc<GraphSession>> = None;
    let mut graph_capture: Option<Arc<LiveGraphCapture>> = None;
    let mut transport = if replaying
        || captured_response.is_some()
        || capture_manifest.is_some()
        || graph_enabled
    {
        None
    } else {
        if let Some(source) = &entity_source {
            source
                .gazetteer
                .recheck_release(&source.ledger)
                .await
                .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
        }
        Some(build_transport_with_host(
            config,
            catalog,
            bundle
                .ok_or_else(|| Error::invalid("live provider bundle unavailable"))?
                .clone(),
            ontology_lookup,
            vocabulary_host.clone(),
            entity_source.clone(),
            None,
            None,
        )?)
    };
    let mut maps = BTreeMap::new();
    let mut outcomes = Vec::with_capacity(windows.len());
    let mut seeds = BTreeMap::new();
    let mut issued_handles = BTreeMap::new();
    let mut response_protocols = BTreeMap::new();
    let mut leaf_roots = Vec::new();
    let mut passage_manifests = Vec::with_capacity(windows.len());
    if windows.len() > 256 {
        return Err(Error::new(ErrorKind::Limit, "document_passage_limit"));
    }
    let system_bytes = extraction_system_prompt_bytes(bundle, recorded_assets)?;
    let mut retained_bytes = 0usize;
    let mut proposal_components = 0usize;

    for (index, window) in windows.iter().enumerate() {
        if cancel.is_cancelled() {
            return Err(Error::new(ErrorKind::Deadline, "cancelled"));
        }
        let (window_id, leaf_job) = &leaf_jobs[index];
        let before = table.checkpoint_bytes()?;
        let prior_root = ContentHash::of_bytes(&before);
        let names = table
            .entities()
            .flat_map(|entity| entity.aliases.iter().map(|alias| alias.alias.as_str()))
            .collect::<Vec<_>>();
        let previous = windows[..index]
            .iter()
            .map(|window| (window.span.start(), window.span.end()))
            .collect::<Vec<_>>();
        let context = crate::passage_context::document_context(
            source.extraction.text(),
            window.span.start(),
            window.span.end(),
            &previous,
        );
        let passage_briefing = build_v2_briefing_with_context(
            vocabulary_host
                .as_deref()
                .ok_or_else(|| Error::invalid("missing vocabulary host"))?,
            config,
            window.span.select(source.extraction.text())?,
            &names,
            &context,
        )?;
        let request_context = ContentHash::of_bytes(&serde_json::to_vec(&json!({
            "prior_context": prior_root.as_str(), "briefing": passage_briefing, "document_context": context,
        })).map_err(|_| Error::invalid("request context encoding"))?);
        let seed = if stored_replay {
            match capture_manifest {
                Some(CaptureManifest::Graph(manifest)) => manifest.provider.coordinate_seed.clone(),
                Some(CaptureManifest::Single(manifest)) => manifest.coordinate_seed.clone(),
                Some(CaptureManifest::Multi(manifest)) => {
                    manifest.leaves[index].request_seed.clone()
                }
                None => return Err(Error::invalid("stored replay manifest unavailable")),
            }
        } else {
            request_seed(&document_seed, window, window_id, &request_context)
        };
        let map = CoordinateMap::issue(
            source.extraction.text(),
            &seed,
            window_id,
            source.extraction.locator.clone(),
            source.extraction.text_version.clone(),
            ContentHash::of_bytes(source.extraction.text().as_bytes()),
            window.span,
        )?;
        if stored_replay {
            let (captured_window, start, end, ranges) = match capture_manifest {
                Some(CaptureManifest::Graph(manifest)) => (
                    manifest.provider.window_id.as_str(),
                    manifest.provider.window_start,
                    manifest.provider.window_end,
                    manifest.provider.issued_ranges.as_slice(),
                ),
                Some(CaptureManifest::Single(manifest)) => (
                    manifest.window_id.as_str(),
                    manifest.window_start,
                    manifest.window_end,
                    manifest.issued_ranges.as_slice(),
                ),
                Some(CaptureManifest::Multi(manifest)) => {
                    let leaf = &manifest.leaves[index];
                    (
                        leaf.window_id.as_str(),
                        leaf.window_start,
                        leaf.window_end,
                        leaf.issued_ranges.as_slice(),
                    )
                }
                None => return Err(Error::invalid("stored replay manifest unavailable")),
            };
            if captured_window != window_id
                || start != window.span.start()
                || end != window.span.end()
                || ranges != map.issued_ranges()
            {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "stored capture coordinate context differs",
                ));
            }
        }
        issued_handles.insert(
            window_id.clone(),
            table
                .entities()
                .map(|entity| entity.handle.as_str().to_owned())
                .collect(),
        );
        let handles: Value = serde_json::from_slice(&table.prompt_projection()?.bytes)
            .map_err(|_| Error::invalid("document entity prompt checkpoint"))?;
        let (entity_capture, known_mentions) = if let Some(entity_source) = &entity_source {
            let passage = window.span.select(source.extraction.text())?;
            let released = entity_source
                .gazetteer
                .release_known_mentions(&entity_source.ledger, passage, window.span.start())
                .await
                .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
            (
                Some(entity_source.gazetteer.commitment().as_str()),
                serde_json::from_str(&released)
                    .map_err(|_| Error::invalid("entity mention encoding"))?,
            )
        } else {
            (None, Value::Array(Vec::new()))
        };
        let request = if let Some(checkpoint) = &existing[index] {
            checkpoint.field("request")?.as_str()?.to_owned()
        } else if let Some(manifest) = capture_manifest {
            match manifest {
                CaptureManifest::Graph(manifest) => manifest.provider.request.clone(),
                CaptureManifest::Single(manifest) => manifest.request.clone(),
                CaptureManifest::Multi(manifest) => manifest.leaves[index].request.clone(),
            }
        } else if stored_replay {
            return Err(Error::invalid("stored replay manifest unavailable"));
        } else {
            render_request_v2(
                window_id,
                source.extraction.locator.as_str(),
                source.extraction.text_version.as_str(),
                &map,
                source.extraction.text(),
                ontology_lookup,
                &passage_briefing,
                entity_capture,
                handles,
                known_mentions,
                &seed,
                prior_root.as_str(),
                &previous,
            )?
        };
        let request = if stored_replay {
            // The retained request already contains its exact historical graph
            // capability, profile and skill context. Reapplying current config
            // would silently replace that committed context.
            request
        } else {
            graph_workspace_request_context(request, config, graph_query_config.as_ref())?
        };
        let response_protocol = request_response_protocol(&request)?;
        response_protocols.insert(window_id.clone(), response_protocol);
        check_provider_context_budget(request.len(), system_bytes, config)?;
        let response = if let Some(checkpoint) = &existing[index] {
            checkpoint.closed(
                &[
                    "schema",
                    "parent_job",
                    "window",
                    "ordinal",
                    "request_seed",
                    "context_before",
                    "request",
                    "response",
                    "error",
                    "context_after",
                ],
                &[],
            )?;
            let expected_leaf_schema = if graph_enabled {
                "ctxql-passage-graph-capture-leaf/v1"
            } else {
                "ctxql-passage-capture-leaf/v2"
            };
            if checkpoint.field("schema")?.as_str()? != expected_leaf_schema
                || checkpoint.field("parent_job")?.as_str()? != parent_job.as_str()
                || checkpoint.field("window")?.as_str()? != window_id
                || checkpoint.field("ordinal")?.u64()? != window.ordinal as u64
                || checkpoint.field("request_seed")?.as_str()? != seed
                || checkpoint.field("context_before")?.as_str()? != String::from_utf8_lossy(&before)
                || checkpoint.field("request")?.as_str()? != request
            {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "passage capture context differs",
                ));
            }
            match checkpoint.field("response")? {
                V::String(text) if checkpoint.field("error")? == &V::Null => Ok(text.clone()),
                V::Null => Err(saved_transport_error(checkpoint.field("error")?.as_str()?)?),
                _ => return Err(Error::invalid("passage capture response shape")),
            }
        } else if let Some(manifest) = capture_manifest {
            match manifest {
                CaptureManifest::Graph(manifest) => {
                    if windows.len() != 1 {
                        return Err(Error::invalid(
                            "graph capture manifest requires one issued passage",
                        ));
                    }
                    Ok(manifest.provider.response.clone())
                }
                CaptureManifest::Single(manifest) => {
                    if windows.len() != 1 {
                        return Err(Error::invalid(
                            "single-passage capture manifest requires one issued passage",
                        ));
                    }
                    Ok(manifest.response.clone())
                }
                CaptureManifest::Multi(manifest) => {
                    Ok::<String, TransportError>(manifest.leaves[index].response.clone())
                }
            }
        } else if let Some(response) = captured_response {
            if windows.len() != 1 {
                return Err(Error::invalid(
                    "captured response requires one issued passage",
                ));
            }
            Ok(response.to_owned())
        } else {
            if let Some(source) = &entity_source {
                source
                    .gazetteer
                    .recheck_release(&source.ledger)
                    .await
                    .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
            }
            if transport.is_none() && graph_enabled {
                let reference = graph_query_config
                    .clone()
                    .ok_or_else(|| Error::invalid("graph query config unavailable"))?;
                let host = match service {
                    Some(service) => create_graph_query_host(service, config, reference).await?,
                    None => {
                        create_extract_only_graph_host(
                            read_only_config.ok_or_else(|| {
                                Error::invalid("graph read configuration unavailable")
                            })?,
                            config,
                            reference,
                        )
                        .await?
                    }
                };
                let session = create_graph_session(
                    host,
                    config,
                    source,
                    parent_job,
                    &document_seed,
                    &map.issued_ranges(),
                    entity_source.as_deref(),
                )
                .await?;
                let workspace = config
                    .graph_workspace
                    .as_ref()
                    .ok_or_else(|| Error::invalid("graph workspace configuration unavailable"))?;
                let capture = Arc::new(LiveGraphCapture {
                    capability: serde_json::from_str::<Value>(&request)
                        .map_err(|_| Error::invalid("graph request encoding"))?["graph_workspace"]
                        .clone(),
                    payloads: Mutex::new(BTreeMap::new()),
                    recorder: Mutex::new(GraphCaptureRecorder::new(
                        session.session_id(),
                        GraphCaptureLimits {
                            max_leaves: workspace.max_tool_calls,
                            max_request_bytes: workspace.max_request_bytes,
                            max_response_bytes: workspace.max_response_bytes,
                            max_total_bytes: workspace.max_aggregate_bytes,
                            max_dependencies: workspace
                                .max_claims
                                .saturating_mul(workspace.max_live_graphs),
                        },
                    )?),
                    store: GraphObjectStore {
                        writer: store.clone(),
                    },
                });
                transport = Some(build_transport_with_host(
                    config,
                    catalog,
                    bundle
                        .ok_or_else(|| Error::invalid("live provider bundle unavailable"))?
                        .clone(),
                    ontology_lookup,
                    vocabulary_host.clone(),
                    entity_source.clone(),
                    Some(session.clone()),
                    Some(capture.clone()),
                )?);
                graph_session = Some(session);
                graph_capture = Some(capture);
            }
            let active = transport
                .take()
                .ok_or_else(|| Error::invalid("provider unavailable"))?;
            let request_for_provider = request.clone();
            let cancel_for_provider = cancel.clone();
            let (active, result) = tokio::task::spawn_blocking(move || {
                let result = active
                    .request(&request_for_provider, &cancel_for_provider)
                    .map(|reply| reply.text);
                (active, result)
            })
            .await
            .map_err(|_| Error::new(ErrorKind::Backend, "provider task failed"))?;
            transport = Some(active);
            result
        };
        if let Ok(raw) = &response {
            if proposal_components <= 4096 {
                proposal_components = proposal_components.saturating_add(update_document_table(
                    &mut table,
                    source,
                    &map,
                    window_id,
                    &seed,
                    raw,
                    response_protocol,
                )?);
            }
        }
        retained_bytes = retained_bytes
            .saturating_add(request.len())
            .saturating_add(response.as_ref().map_or(0, String::len));
        let after = table.checkpoint_bytes()?;
        if let Ok(response_text) = &response {
            let mut passage = PassageCaptureManifest {
                ordinal: window.ordinal,
                window_id: window_id.clone(),
                request_seed: seed.clone(),
                context_before: String::from_utf8_lossy(&before).into_owned(),
                request_root: ContentHash::of_bytes(request.as_bytes())
                    .as_str()
                    .to_owned(),
                request: request.clone(),
                response_root: ContentHash::of_bytes(response_text.as_bytes())
                    .as_str()
                    .to_owned(),
                response: response_text.clone(),
                context_after: String::from_utf8_lossy(&after).into_owned(),
                window_start: window.span.start(),
                window_end: window.span.end(),
                issued_ranges: map.issued_ranges(),
                leaf_root: String::new(),
            };
            passage.leaf_root = passage_capture_root(&passage)?;
            if !stored_replay {
                if let Some(manifest) = capture_manifest {
                    match manifest {
                        CaptureManifest::Graph(actual) => {
                            let mut expected = make_single_capture_manifest(
                                source,
                                bundle.ok_or_else(|| {
                                    Error::invalid("live provider bundle unavailable")
                                })?,
                                ontology_lookup,
                                window,
                                window_id,
                                &seed,
                                &request,
                                response_text,
                                map.issued_ranges(),
                            )?;
                            expected.asset_manifest = actual.provider.asset_manifest.clone();
                            expected.assets = actual.provider.assets.clone();
                            expected.model = actual.provider.model.clone();
                            expected.thinking = actual.provider.thinking.clone();
                            expected.agent_bundle_hash = actual.provider.agent_bundle_hash.clone();
                            if actual.provider.source_representation.is_none() {
                                expected.source_representation = None;
                            }
                            verify_capture_manifest(&actual.provider, &expected)?;
                        }
                        CaptureManifest::Single(actual) => {
                            let mut expected = make_single_capture_manifest(
                                source,
                                bundle.ok_or_else(|| {
                                    Error::invalid("live provider bundle unavailable")
                                })?,
                                ontology_lookup,
                                window,
                                window_id,
                                &seed,
                                &request,
                                response_text,
                                map.issued_ranges(),
                            )?;
                            // Asset integrity was verified independently from live
                            // files. Reconstruct the request using its exact recorded
                            // provider context rather than substituting today's bundle.
                            expected.asset_manifest = actual.asset_manifest.clone();
                            expected.assets = actual.assets.clone();
                            expected.model = actual.model.clone();
                            expected.thinking = actual.thinking.clone();
                            expected.agent_bundle_hash = actual.agent_bundle_hash.clone();
                            // Historical UTF-8 manifests predate representation-chain
                            // metadata. Preserve their decoding without allowing a
                            // converted representation to be guessed.
                            if actual.source_representation.is_none() {
                                expected.source_representation = None;
                            }
                            verify_capture_manifest(actual, &expected)?;
                        }
                        CaptureManifest::Multi(actual) => {
                            let captured = actual.leaves.get(index).ok_or_else(|| {
                                Error::new(
                                    ErrorKind::Conflict,
                                    format!("capture manifest missing passage ordinal {index}"),
                                )
                            })?;
                            if captured != &passage {
                                return Err(Error::new(
                            ErrorKind::Conflict,
                            format!("capture manifest passage {index} differs from the current extraction request/context"),
                        ));
                            }
                        }
                    }
                }
            }
            if retain_export {
                passage_manifests.push(passage);
            }
        }
        if let Some(service) = service {
            let leaf = V::object([
                (
                    "schema".into(),
                    V::string(if graph_enabled {
                        "ctxql-passage-graph-capture-leaf/v1"
                    } else {
                        "ctxql-passage-capture-leaf/v2"
                    }),
                ),
                ("parent_job".into(), V::string(parent_job.as_str())),
                ("window".into(), V::string(window_id)),
                ("ordinal".into(), V::integer(window.ordinal as u64)),
                ("request_seed".into(), V::string(&seed)),
                (
                    "context_before".into(),
                    V::string(String::from_utf8_lossy(&before)),
                ),
                ("request".into(), V::string(&request)),
                (
                    "response".into(),
                    response.as_ref().map(V::string).unwrap_or(V::Null),
                ),
                (
                    "error".into(),
                    response
                        .as_ref()
                        .err()
                        .map(|e| V::string(transport_error_code(e)))
                        .unwrap_or(V::Null),
                ),
                (
                    "context_after".into(),
                    V::string(String::from_utf8_lossy(&after)),
                ),
            ])?;
            if let Some(checkpoint) = &existing[index] {
                if checkpoint != &leaf {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "passage capture reconstruction differs",
                    ));
                }
            }
            leaf_roots.push(service.seal_work_value(leaf_job, "capture", &leaf).await?);
        }
        if proposal_components > 4096 || retained_bytes > config.max_source_bytes {
            // The completed leaf remains immutable evidence, but no further
            // provider work or business evaluation may exceed the document cap.
            return Err(Error::new(ErrorKind::Limit, "document_capture_limit"));
        }
        report
            .issued_ranges
            .insert(window_id.clone(), map.issued_ranges());
        seeds.insert(window_id.clone(), seed);
        maps.insert(window_id.clone(), map);
        outcomes.push((window_id.clone(), response));
    }
    let graph_export = match capture_manifest {
        Some(CaptureManifest::Graph(manifest)) => Some(manifest.graph.clone()),
        _ => match (
            config.graph_workspace.as_ref(),
            graph_session.as_ref(),
            graph_capture.as_ref(),
        ) {
            (Some(workspace), Some(session), Some(capture)) => {
                Some(finalize_graph_export(workspace, session, capture)?)
            }
            (None, None, None) => None,
            _ => {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "incomplete graph capture state",
                ))
            }
        },
    };
    let usage = transport
        .as_ref()
        .map(PiTransport::usage)
        .unwrap_or_default();
    if let Some(transport) = transport {
        transport.teardown();
    }
    if let Some(service) = service {
        // Persist the complete, integrity-verifiable replay input beside the
        // aggregate link. The work-link root is the registered capability
        // lookup key; the manifest remains content, not authorization.
        let replay_manifest = (passage_manifests.len() == outcomes.len())
            .then(|| {
                capture_export_manifest(
                    source,
                    bundle,
                    recorded_assets,
                    ontology_lookup,
                    &StreamingV2Capture {
                        maps: maps.clone(),
                        outcomes: outcomes.clone(),
                        response_protocols: response_protocols.clone(),
                        request_seeds: seeds.clone(),
                        issued_handles: issued_handles.clone(),
                        passage_manifests: passage_manifests.clone(),
                        document_seed: document_seed.as_str().to_owned(),
                        graph_session: graph_session.clone(),
                        graph_export: graph_export.clone(),
                        table: table.clone(),
                        usage: Usage::default(),
                    },
                )
            })
            .transpose()?;
        let manifest_value = replay_manifest
            .as_ref()
            .map(|manifest| {
                V::parse(
                    &serde_json::to_vec(manifest)
                        .map_err(|_| Error::invalid("capture manifest encoding"))?,
                    Limits::default(),
                )
            })
            .transpose()?
            .unwrap_or(V::Null);
        let aggregate = V::object([
            (
                "schema".into(),
                V::string(if graph_export.is_some() {
                    "ctxql-passage-graph-capture/v1"
                } else {
                    "ctxql-passage-capture/v3"
                }),
            ),
            ("manifest".into(), manifest_value),
            ("document_seed".into(), V::string(document_seed.as_str())),
            (
                "bundle_hash".into(),
                V::string(asset_hash(bundle, recorded_assets)?),
            ),
            (
                "leaf_jobs".into(),
                V::Array(
                    leaf_jobs
                        .iter()
                        .map(|(_, job)| V::string(job.as_str()))
                        .collect(),
                ),
            ),
            (
                "leaf_roots".into(),
                V::Array(
                    leaf_roots
                        .iter()
                        .map(|root| V::string(root.as_str()))
                        .collect(),
                ),
            ),
            (
                "entity_checkpoint".into(),
                V::string(String::from_utf8_lossy(&table.checkpoint_bytes()?)),
            ),
        ])?;
        service
            .seal_work_value(parent_job, "capture", &aggregate)
            .await?;
    }
    Ok(StreamingV2Capture {
        maps,
        outcomes,
        response_protocols,
        request_seeds: seeds,
        issued_handles,
        passage_manifests,
        document_seed: document_seed.as_str().to_owned(),
        graph_session,
        graph_export,
        table,
        usage,
    })
}

#[allow(dead_code, clippy::too_many_arguments)]
async fn legacy_ingest_document(
    service: Option<&Arc<AcquisitionService>>,
    config: &AcquisitionConfig,
    _store: &SourceObjectWriter,
    source: PreparedSource,
    catalog: CertifiedOntologyCatalog,
    entities: &mut BTreeMap<(String, Iri), Iri>,
    mode: IngestMode,
    detail_byte_limit: usize,
    cancel: CancellationToken,
) -> Result<(DocumentReport, Usage)> {
    let window_config = window_config(config)?;
    let document_kind = match source.extraction.media_type {
        SourceMediaType::Markdown => DocumentKind::Markdown,
        SourceMediaType::PlainText => DocumentKind::Plain,
        SourceMediaType::Pdf => DocumentKind::PdfText,
    };
    let windows = plan_windows(source.extraction.text(), document_kind, &window_config)?;
    let bundle = hash_agent_bundle(&config.pi_bundle)
        .map_err(|_| Error::invalid("invalid Pi acquisition bundle"))?;
    let (extraction_run, ontology_lookup) = extraction_run(
        &source,
        &catalog,
        Some(&bundle),
        None,
        config,
        OntologyMode::Hard,
        None,
    )?;
    let job_id = JobId::new(format!("job:{}", &extraction_run.as_str()[11..]))?;
    let attempt_id = AttemptId::new(format!("attempt:{}", &extraction_run.as_str()[11..]))?;
    let mut report = document_report(
        &source,
        windows.len(),
        OntologyMode::Hard,
        detail_byte_limit,
    );
    report.ontology_lookup = ontology_lookup.as_ref().map(canonical_json).transpose()?;
    report.agent_bundle_hash = Some(bundle.hash.clone());
    if let (Some(service), Some(wait)) = (service, mode.wait()) {
        let recovered = service.prior_admissions(&job_id);
        for recovered in recovered {
            service
                .complete_recovered(recovered, wait.wait_point())
                .await?;
            let receipt = recovered.receipt();
            report.admitted_bundle_count = report.admitted_bundle_count.saturating_add(1);
            report.admitted_claim_count = report
                .admitted_claim_count
                .saturating_add(receipt.claim_ids().len());
            report.omitted_claim_count = report
                .omitted_claim_count
                .saturating_add(receipt.claim_ids().len());
            report.details_truncated = true;
            report.push_admission(canonical_json(&receipt.projection())?)?;
        }
        if service.has_prior_job(&job_id) {
            report.push_error(StageError {
                stage: "recovery",
                code: "prior_job_requires_explicit_new_extraction",
                window_id: None,
            })?;
            return Ok((report, Usage::default()));
        }
    }
    let provider = build_provider(config, &catalog, bundle.clone(), ontology_lookup.as_ref())?;

    let mut maps = BTreeMap::new();
    let mut requests = Vec::with_capacity(windows.len());
    for window in &windows {
        let window_id = format!(
            "window:{}",
            &ContentHash::of_bytes(
                format!(
                    "ctxql-window/v1\0{}\0{}",
                    source.extraction.text_version.as_str(),
                    window.ordinal
                )
                .as_bytes(),
            )
            .as_str()[7..]
        );
        let map = CoordinateMap::issue(
            source.extraction.text(),
            attempt_id.as_str(),
            &window_id,
            source.extraction.locator.clone(),
            source.extraction.text_version.clone(),
            ContentHash::of_bytes(source.extraction.text().as_bytes()),
            window.span,
        )?;
        let request = render_request(
            &window_id,
            source.extraction.locator.as_str(),
            source.extraction.text_version.as_str(),
            &map,
            source.extraction.text(),
        )?;
        maps.insert(window_id.clone(), map);
        requests.push((window_id, request));
    }

    let provider_cancel = cancel.clone();
    let batch_size = config.batch_size;
    let (provider, outcomes, captured) = tokio::task::spawn_blocking(move || {
        let mut outcomes = Vec::new();
        let mut captured = Vec::new();
        for pair in requests.chunks(batch_size) {
            if provider_cancel.is_cancelled() {
                break;
            }
            let batch = pair
                .iter()
                .map(|(_, request)| request.as_str())
                .collect::<Vec<_>>()
                .join("\n\n--- NEXT WINDOW ---\n\n");
            if mode == IngestMode::ExtractOnly {
                let (batch_outcomes, batch_captured) =
                    provider.extract_batch_with_fallback_captured(&batch, pair, &provider_cancel);
                outcomes.extend(batch_outcomes);
                captured.extend(batch_captured);
            } else {
                outcomes.extend(provider.extract_batch_with_fallback(
                    &batch,
                    pair,
                    &provider_cancel,
                ));
            }
        }
        (provider, outcomes, captured)
    })
    .await
    .map_err(|_| Error::new(ErrorKind::Backend, "provider task failed"))?;
    let usage = provider.usage();
    provider.teardown();
    if cancel.is_cancelled() {
        return Err(Error::new(ErrorKind::Deadline, "cancelled"));
    }
    if mode == IngestMode::ExtractOnly {
        report.provider_responses = captured.into_iter().map(provider_response_report).collect();
    }

    let candidate_limits = CandidateLimits::default();
    for outcome in outcomes {
        let window_id = outcome.window_id;
        let parsed = match outcome.output {
            Ok(output) => output,
            Err(error) => {
                let code = provider_error_code(&error);
                if mode == IngestMode::ExtractOnly {
                    report.validations.push(ValidationReport {
                        window_id: window_id.clone(),
                        candidate_index: None,
                        status: "provider_rejected",
                        validated_claim_count: 0,
                        error: Some(code),
                    });
                }
                report.push_error(StageError {
                    stage: "provider",
                    code,
                    window_id: Some(window_id),
                })?;
                continue;
            }
        };
        let advisories = match into_advisory(parsed, &candidate_limits) {
            Ok(value) => value,
            Err(_) => {
                if mode == IngestMode::ExtractOnly {
                    report.validations.push(ValidationReport {
                        window_id: window_id.clone(),
                        candidate_index: None,
                        status: "candidate_conversion_rejected",
                        validated_claim_count: 0,
                        error: Some("candidate_conversion_failed"),
                    });
                }
                report.push_error(StageError {
                    stage: "provider_grammar",
                    code: "candidate_conversion_failed",
                    window_id: Some(window_id),
                })?;
                continue;
            }
        };
        if advisories.is_empty() {
            report.no_claim_window_count += 1;
            if mode == IngestMode::ExtractOnly {
                report.validations.push(ValidationReport {
                    window_id,
                    candidate_index: None,
                    status: "no_claims",
                    validated_claim_count: 0,
                    error: None,
                });
            }
            continue;
        }
        let map = maps
            .get(&window_id)
            .ok_or_else(|| Error::invalid("provider returned unknown window"))?;
        for (candidate_index, advisory) in advisories.into_iter().enumerate() {
            let current_catalog = if let Some(service) = service {
                service.current_catalog().await?
            } else {
                catalog.clone()
            };
            if current_catalog.identity().catalog_root() != catalog.identity().catalog_root() {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "ontology catalog changed during ingestion",
                ));
            }
            let resolver = CaptureEntityResolver::new(
                current_catalog.capture_token(),
                entities
                    .iter()
                    .map(|((spelling, kind), iri)| (spelling.clone(), kind.clone(), iri.clone())),
            )?;
            let descriptor = descriptor(
                &source,
                &advisory,
                &window_id,
                &bundle,
                &catalog,
                ontology_lookup.as_ref(),
            )?;
            let validated = match validate_bundle(
                advisory.clone(),
                ValidationInput {
                    extraction_run: extraction_run.clone(),
                    validation_capture: current_catalog.identity().capture().clone(),
                    descriptor,
                    source_id: source.source_id.clone(),
                    document: source.extraction.text(),
                    attempt_id: attempt_id.as_str(),
                    window_id: &window_id,
                    coordinates: map,
                    max_spans_per_claim: candidate_limits.max_spans_per_claim,
                    limits: Limits::default(),
                },
                &current_catalog,
                &resolver,
            ) {
                Ok(value) => value,
                Err(error) => {
                    report.rejected_candidate_count += 1;
                    let code = validation_error_code(&error);
                    if mode == IngestMode::ExtractOnly {
                        report.validations.push(ValidationReport {
                            window_id: window_id.clone(),
                            candidate_index: Some(candidate_index),
                            status: "validation_rejected",
                            validated_claim_count: 0,
                            error: Some(code),
                        });
                    }
                    report.push_error(StageError {
                        stage: "validation",
                        code,
                        window_id: Some(window_id.clone()),
                    })?;
                    continue;
                }
            };
            report.validated_bundle_count = report.validated_bundle_count.saturating_add(1);
            report.validated_claim_count = report
                .validated_claim_count
                .saturating_add(validated.claims().len());
            if mode == IngestMode::ExtractOnly {
                report.validations.push(ValidationReport {
                    window_id: window_id.clone(),
                    candidate_index: Some(candidate_index),
                    status: "validated",
                    validated_claim_count: validated.claims().len(),
                    error: None,
                });
            }
            remember_entities(
                entities,
                &resolver,
                current_catalog.capture_token(),
                &source,
                &extraction_run,
                &advisory,
            )?;
            if mode == IngestMode::ExtractOnly {
                continue;
            }
            let selector_root = selector_root(&source, &window_id, map)?;
            let safe_counts = V::object([
                (
                    "claim_count".into(),
                    V::Number(ExactNumber::parse(&validated.claims().len().to_string())?),
                ),
                (
                    "source_span_count".into(),
                    V::Number(ExactNumber::parse(
                        &advisory
                            .metadata
                            .iter()
                            .map(|item| item.coordinates.len())
                            .sum::<usize>()
                            .to_string(),
                    )?),
                ),
            ])?;
            let admitted_claim_count = validated.claims().len();
            let admission = service
                .ok_or_else(|| Error::invalid("admission service unavailable"))?
                .admit_foreground(
                    job_id.clone(),
                    attempt_id.clone(),
                    &validated,
                    selector_root,
                    safe_counts,
                    now()?,
                    mode.wait()
                        .ok_or_else(|| Error::invalid("admission wait point unavailable"))?
                        .wait_point(),
                    AdmissionContext::NoGraph,
                )
                .await?;
            report.admitted_bundle_count += 1;
            report.admitted_claim_count += admitted_claim_count;
            for claim in validated.claims() {
                report.push_claim(canonical_json(&claim.projection())?)?;
            }
            report.push_admission(canonical_json(&admission.admission.projection())?)?;
        }
    }
    Ok((report, usage))
}

fn build_transport(
    config: &AcquisitionConfig,
    catalog: &CertifiedOntologyCatalog,
    bundle: AgentBundle,
    ontology_lookup: Option<&V>,
) -> Result<PiTransport> {
    build_transport_with_host(
        config,
        catalog,
        bundle,
        ontology_lookup,
        None,
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_transport_with_host(
    config: &AcquisitionConfig,
    catalog: &CertifiedOntologyCatalog,
    bundle: AgentBundle,
    ontology_lookup: Option<&V>,
    captured_host: Option<Arc<dyn OntologyToolHost>>,
    entity_source: Option<Arc<CapturedEntitySource>>,
    graph_session: Option<Arc<GraphSession>>,
    graph_capture: Option<Arc<LiveGraphCapture>>,
) -> Result<PiTransport> {
    let (system_prompt, protocol) = match config.protocol {
        AcquisitionProtocol::LegacyV1 => (bundle.system_prompt(), ExtractionProtocol::LegacyV1),
        AcquisitionProtocol::OntologyV2 => {
            (bundle.system_prompt_v2(), ExtractionProtocol::ProposalsV2)
        }
    };
    let system_prompt =
        system_prompt.map_err(|_| Error::invalid("invalid Pi acquisition bundle"))?;
    let mut env = Vec::new();
    for name in ["HOME", "PATH", "OPENROUTER_API_KEY"] {
        let value = std::env::var(name)
            .map_err(|_| Error::invalid("required provider environment unavailable"))?;
        env.push((name.to_owned(), value));
    }
    let ontology_host: Arc<dyn OntologyToolHost> = if let Some(host) = captured_host {
        host
    } else {
        match &config.ontology_ledger_path {
            Some(path) => {
                let host = DirectFlureeOntologyToolHost::from_bootstrap(path)
                    .map_err(|_| Error::invalid("ontology ledger bootstrap"))?;
                if host
                    .provenance()
                    .map_err(|_| Error::invalid("ontology ledger bootstrap"))?
                    != *ontology_lookup.ok_or_else(|| Error::invalid("ontology lookup capture"))?
                {
                    return Err(Error::invalid("ontology lookup capture changed"));
                }
                Arc::new(host)
            }
            None if ontology_lookup.is_none() => Arc::new(CatalogToolHost {
                catalog: catalog.clone(),
            }),
            None => return Err(Error::invalid("ontology lookup capture changed")),
        }
    };
    let lookup_host: Arc<dyn OntologyToolHost> = Arc::new(AcquisitionLookupHost {
        ontology: ontology_host,
        entity_source,
        graph_session,
        graph_capture,
        ontology_gate: Arc::new(Mutex::new(())),
        graph_gate: Arc::new(Mutex::new(())),
        runtime: tokio::runtime::Handle::current(),
    });
    if config.graph_workspace.is_some() {
        env.push(("CTXQL_GRAPH_WORKSPACE_ENABLED".into(), "1".into()));
    }
    let transport = PiTransport::new(TransportConfig {
        command: config.pi_command.clone(),
        env,
        system_prompt,
        protocol,
        bundle,
        ontology_bridge: OntologyBridgeConfig {
            host: lookup_host,
            max_request_bytes: 4096,
            max_response_bytes: 256 * 1024,
        },
        limits: TransportLimits {
            timeout: Duration::from_secs(config.provider_timeout_seconds as u64),
            max_events: 16_384,
            max_tool_calls: config
                .graph_workspace
                .as_ref()
                .map(|workspace| workspace.max_tool_calls)
                .unwrap_or(128),
            ..TransportLimits::default()
        },
        session_logging: config
            .pi_session_log_dir
            .clone()
            .map(|root| cdb_provider_pi::SessionLogging { root }),
    })
    .map_err(|_| Error::new(ErrorKind::Backend, "provider initialization failed"))?;
    Ok(transport)
}

fn build_provider(
    config: &AcquisitionConfig,
    catalog: &CertifiedOntologyCatalog,
    bundle: AgentBundle,
    ontology_lookup: Option<&V>,
) -> Result<PiProvider> {
    Ok(PiProvider::new(
        build_transport(config, catalog, bundle, ontology_lookup)?,
        ParseLimits::default(),
    ))
}

#[derive(Clone)]
struct AcquisitionLookupHost {
    ontology: Arc<dyn OntologyToolHost>,
    entity_source: Option<Arc<CapturedEntitySource>>,
    graph_session: Option<Arc<GraphSession>>,
    graph_capture: Option<Arc<LiveGraphCapture>>,
    ontology_gate: Arc<Mutex<()>>,
    graph_gate: Arc<Mutex<()>>,
    runtime: tokio::runtime::Handle,
}

impl AcquisitionLookupHost {
    fn lookup_ontology(&self, request: &Value) -> std::result::Result<Value, OntologyToolError> {
        // Socket OS workers may issue independent calls concurrently. Queue
        // ontology reads without changing capability dispatch or native guards.
        let _serial = self
            .ontology_gate
            .lock()
            .map_err(|_| OntologyToolError::Denied)?;
        self.ontology.lookup(request)
    }
}

impl OntologyToolHost for AcquisitionLookupHost {
    fn lookup(&self, request: &Value) -> std::result::Result<Value, OntologyToolError> {
        if request.get("capability").and_then(Value::as_str) != Some("entities") {
            return self.lookup_ontology(request);
        }
        let Some(inner) = request.get("request").and_then(Value::as_object) else {
            return Err(OntologyToolError::Denied);
        };
        if inner
            .keys()
            .any(|key| !matches!(key.as_str(), "operation" | "query" | "limit"))
            || !matches!(
                inner.get("operation").and_then(Value::as_str),
                Some("search" | "describe")
            )
            || inner
                .get("query")
                .and_then(Value::as_str)
                .is_none_or(|query| query.is_empty() || query.len() > 512)
            || inner.get("limit").and_then(Value::as_u64).unwrap_or(10) > 20
        {
            return Err(OntologyToolError::Denied);
        }
        let Some(source) = &self.entity_source else {
            return Ok(json!({
                "schema": "ctxql-entity-lookup/v1",
                "capture": null,
                "complete": true,
                "status": "results",
                "entities": []
            }));
        };
        let operation = inner
            .get("operation")
            .and_then(Value::as_str)
            .ok_or(OntologyToolError::Denied)?;
        let query = inner
            .get("query")
            .and_then(Value::as_str)
            .ok_or(OntologyToolError::Denied)?;
        let request = match operation {
            "search" => EntityLookupRequest::Search {
                text: query.to_owned(),
                limit: inner.get("limit").and_then(Value::as_u64).unwrap_or(10) as usize,
            },
            "describe" => EntityLookupRequest::Describe {
                iri: query.to_owned(),
            },
            _ => return Err(OntologyToolError::Denied),
        };
        let response = self
            .runtime
            .block_on(
                source
                    .gazetteer
                    .release_ctxql_entities(&source.ledger, request),
            )
            .map_err(|_| OntologyToolError::Denied)?;
        let mut value = serde_json::to_value(response).map_err(|_| OntologyToolError::Denied)?;
        let object = value.as_object_mut().ok_or(OntologyToolError::Denied)?;
        object.insert(
            "schema".into(),
            Value::String("ctxql-entity-lookup/v1".into()),
        );
        object.insert(
            "capture".into(),
            Value::String(source.gazetteer.commitment().as_str().to_owned()),
        );
        object.insert("complete".into(), Value::Bool(true));
        Ok(value)
    }

    fn invoke(
        &self,
        capability: ToolCapability,
        _call_id: &str,
        request: &Value,
    ) -> std::result::Result<Value, OntologyToolError> {
        match capability {
            ToolCapability::Ontology => self.lookup_ontology(request),
            ToolCapability::Entities => self.lookup(&json!({
                "capability": "entities",
                "request": request,
            })),
            ToolCapability::Capabilities | ToolCapability::Source => Err(OntologyToolError::Denied),
            ToolCapability::GraphQuery | ToolCapability::GraphPlayground => {
                let session = self
                    .graph_session
                    .as_ref()
                    .ok_or(OntologyToolError::Denied)?;
                // This mutex runs only on socket OS workers, never Tokio workers.
                // Serialize the full dispatch/capture boundary, not just edits.
                let result = (|| {
                    let _serial = self
                        .graph_gate
                        .lock()
                        .map_err(|_| OntologyToolError::Denied)?;
                    let before = session
                        .capture_state()
                        .map_err(|_| OntologyToolError::Denied)?
                        .0;
                    let (kind, response) = match capability {
                        ToolCapability::GraphQuery => (
                            GraphCapability::Query,
                            graph_query_tool(&self.runtime, session, request)?,
                        ),
                        _ => (
                            GraphCapability::Playground,
                            graph_playground_tool(&self.runtime, session, request)?,
                        ),
                    };
                    record_graph_tool(
                        self.graph_capture.as_ref(),
                        session,
                        kind,
                        request,
                        &response,
                        before,
                    )
                })();
                if result.is_err() {
                    session.cancel();
                }
                result
            }
        }
    }

    fn cancel(&self, _call_id: &str) -> std::result::Result<(), OntologyToolError> {
        if let Some(session) = &self.graph_session {
            session.cancel();
        }
        Ok(())
    }
}

fn record_graph_tool(
    capture: Option<&Arc<LiveGraphCapture>>,
    session: &Arc<GraphSession>,
    capability: GraphCapability,
    request: &Value,
    response: &Value,
    revision_before: u64,
) -> std::result::Result<Value, OntologyToolError> {
    let capture = capture.ok_or(OntologyToolError::Denied)?;
    if serde_json::to_vec(&json!({"ok": true, "response": response}))
        .map_err(|_| OntologyToolError::Denied)?
        .len()
        + 1
        > 64 * 1024
    {
        session.cancel();
        return Err(OntologyToolError::Denied);
    }
    let (revision_after, _, context) = session
        .capture_state()
        .map_err(|_| OntologyToolError::Denied)?;
    let status = response
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("error");
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kind = match (capability, status, operation) {
        (_, "error", _) => GraphResultKind::Error,
        (GraphCapability::Query, "graph", _) => GraphResultKind::Graph,
        (GraphCapability::Query, _, _) => GraphResultKind::Diagnostic,
        (GraphCapability::Playground, _, "apply" | "import" | "release_graph") => {
            GraphResultKind::Mutation
        }
        (GraphCapability::Playground, _, "check") => GraphResultKind::Check,
        (GraphCapability::Playground, _, _) => GraphResultKind::View,
    };
    let suffix = format!("~{}", session.session_id());
    let mut issued = Vec::new();
    collect_issued_handles(response, &suffix, &mut issued);
    issued.sort();
    issued.dedup();
    let mut recorder = capture
        .recorder
        .lock()
        .map_err(|_| OntologyToolError::Denied)?;
    issued.retain(|handle| !recorder.previously_issued(handle));
    let graph_handle = if kind == GraphResultKind::Graph {
        issued
            .iter()
            .find(|handle| handle.starts_with('g'))
            .map(|handle| Handle(handle.clone()))
    } else {
        None
    };
    let graph_payload_root = graph_handle
        .as_ref()
        .map(|handle| session.graph_payload_root(handle))
        .transpose()
        .map_err(|_| OntologyToolError::Denied)?
        .flatten();
    if let (Some(handle), Some(root)) = (graph_handle.as_ref(), graph_payload_root.as_ref()) {
        let payload = session
            .graph_payload(handle)
            .map_err(|_| OntologyToolError::Denied)?
            .ok_or(OntologyToolError::Denied)?;
        let mut payloads = capture
            .payloads
            .lock()
            .map_err(|_| OntologyToolError::Denied)?;
        if !payloads.contains_key(root.as_str()) {
            recorder.reserve_payload_bytes(payload.len()).map_err(|_| {
                session.cancel();
                OntologyToolError::Denied
            })?;
            capture.store.persist_payload(root, &payload).map_err(|_| {
                session.cancel();
                OntologyToolError::Denied
            })?;
            payloads.insert(
                root.as_str().to_owned(),
                serde_json::from_slice(&payload).map_err(|_| OntologyToolError::Denied)?,
            );
        }
    }
    let dependencies = if let Some(handle) = graph_handle.as_ref() {
        session
            .graph_dependencies(handle)
            .map_err(|_| OntologyToolError::Denied)?
    } else {
        context.disclosed().clone()
    };
    let request = serde_json::to_vec(request).map_err(|_| OntologyToolError::Denied)?;
    let response = serde_json::to_vec(response).map_err(|_| OntologyToolError::Denied)?;
    let recorded = recorder
        .append_before_disclosure(
            &capture.store,
            capability,
            request,
            response,
            revision_before,
            revision_after,
            kind,
            issued,
            graph_payload_root,
            dependencies,
        )
        .map_err(|_| {
            session.cancel();
            OntologyToolError::Denied
        })?;
    let model_visible = serde_json::from_slice(recorded.model_visible_bytes())
        .map_err(|_| OntologyToolError::Denied)?;
    let _ = recorded.leaf_root();
    Ok(model_visible)
}

fn collect_issued_handles(value: &Value, suffix: &str, output: &mut Vec<String>) {
    match value {
        Value::String(value)
            if value.ends_with(suffix)
                && matches!(
                    value.as_bytes().first(),
                    Some(b'g' | b'n' | b'c' | b'r' | b'h' | b'q')
                ) =>
        {
            output.push(value.clone());
        }
        Value::Array(values) => {
            for value in values {
                collect_issued_handles(value, suffix, output);
            }
        }
        Value::Object(fields) => {
            for value in fields.values() {
                collect_issued_handles(value, suffix, output);
            }
        }
        _ => {}
    }
}

fn tool_error(error: Error) -> Value {
    json!({
        "schema": "ctxql-graph-tool-error/v1",
        "status": "error",
        "code": error.public_code(),
    })
}

fn graph_query_tool(
    runtime: &tokio::runtime::Handle,
    session: &Arc<GraphSession>,
    request: &Value,
) -> std::result::Result<Value, OntologyToolError> {
    let object = request.as_object().ok_or(OntologyToolError::Denied)?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "query" | "max_nodes" | "max_claims" | "max_response_bytes" | "timeout_ms"
        )
    }) {
        return Err(OntologyToolError::Denied);
    }
    let query = object
        .get("query")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 32 * 1024)
        .ok_or(OntologyToolError::Denied)?;
    let mut limits = GraphQueryLimits::default();
    if let Some(value) = object.get("max_nodes").and_then(Value::as_u64) {
        limits.max_nodes = usize::try_from(value).map_err(|_| OntologyToolError::Denied)?;
    }
    if let Some(value) = object.get("max_claims").and_then(Value::as_u64) {
        limits.max_claims = usize::try_from(value).map_err(|_| OntologyToolError::Denied)?;
    }
    if let Some(value) = object.get("max_response_bytes").and_then(Value::as_u64) {
        limits.max_response_bytes =
            usize::try_from(value).map_err(|_| OntologyToolError::Denied)?;
    }
    if let Some(value) = object.get("timeout_ms").and_then(Value::as_u64) {
        limits.timeout = Duration::from_millis(value);
    }
    let result = runtime.block_on(session.query(query.as_bytes(), limits));
    Ok(match result {
        Ok(SessionQueryResult::Graph {
            handle,
            snapshot,
            node_count,
            claim_count,
            complete,
            overview,
        }) => json!({
            "schema": "ctxql-graph-query-result/v1",
            "status": "graph",
            "handle": handle,
            "snapshot": snapshot,
            "node_count": node_count,
            "claim_count": claim_count,
            "complete": complete,
            "overview": overview,
        }),
        Ok(SessionQueryResult::Diagnostic(diagnostic)) => json!({
            "schema": "ctxql-graph-query-result/v1",
            "status": "diagnostic",
            "diagnostic": diagnostic,
        }),
        Err(error) => tool_error(error),
    })
}

fn graph_playground_tool(
    runtime: &tokio::runtime::Handle,
    session: &Arc<GraphSession>,
    request: &Value,
) -> std::result::Result<Value, OntologyToolError> {
    let object = request.as_object().ok_or(OntologyToolError::Denied)?;
    let operation = object
        .get("operation")
        .and_then(Value::as_str)
        .ok_or(OntologyToolError::Denied)?;
    let allowed: &[&str] = match operation {
        "import" | "release_graph" => &["operation", "handle"],
        "inspect" => &["operation", "handle", "max_bytes"],
        "apply" => &["operation", "expected_revision", "idempotency_key", "edits"],
        "view" => &["operation", "view", "handle", "max_bytes"],
        "check" => &["operation"],
        _ => return Err(OntologyToolError::Denied),
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(OntologyToolError::Denied);
    }
    let handle = || {
        object
            .get("handle")
            .and_then(Value::as_str)
            .map(|value| Handle(value.to_owned()))
            .ok_or(OntologyToolError::Denied)
    };
    let response = match operation {
        "import" => runtime
            .block_on(session.import_graph(&handle()?))
            .and_then(|value| {
                serde_json::to_value(value).map_err(|_| Error::invalid("tool response"))
            }),
        "release_graph" => runtime
            .block_on(session.release_graph(&handle()?))
            .map(|()| json!({"released": true})),
        "apply" => {
            let request = ApplyRequest {
                schema: "ctxql.graph-workspace/v1".into(),
                session_id: session.session_id().to_owned(),
                expected_revision: object
                    .get("expected_revision")
                    .and_then(Value::as_u64)
                    .ok_or(OntologyToolError::Denied)?,
                idempotency_key: object
                    .get("idempotency_key")
                    .and_then(Value::as_str)
                    .ok_or(OntologyToolError::Denied)?
                    .to_owned(),
                edits: serde_json::from_value(
                    object
                        .get("edits")
                        .cloned()
                        .ok_or(OntologyToolError::Denied)?,
                )
                .map_err(|_| OntologyToolError::Denied)?,
            };
            runtime.block_on(session.apply(request)).and_then(|value| {
                serde_json::to_value(value).map_err(|_| Error::invalid("tool response"))
            })
        }
        "inspect" => runtime
            .block_on(
                session.inspect(
                    handle()?,
                    object
                        .get("max_bytes")
                        .and_then(Value::as_u64)
                        .map(|value| value as usize),
                ),
            )
            .and_then(|value| {
                serde_json::to_value(value).map_err(|_| Error::invalid("tool response"))
            }),
        "view" => {
            let kind = match object.get("view").and_then(Value::as_str) {
                Some("overview") => ViewKind::Overview,
                Some("changes") => ViewKind::Changes,
                Some("open_questions") => ViewKind::OpenQuestions,
                Some("neighbourhood") => ViewKind::Neighbourhood { centre: handle()? },
                _ => return Err(OntologyToolError::Denied),
            };
            runtime
                .block_on(
                    session.view(
                        kind,
                        object
                            .get("max_bytes")
                            .and_then(Value::as_u64)
                            .map(|value| value as usize),
                    ),
                )
                .and_then(|value| {
                    serde_json::to_value(value).map_err(|_| Error::invalid("tool response"))
                })
        }
        "check" => runtime.block_on(session.check()).and_then(|value| {
            serde_json::to_value(value).map_err(|_| Error::invalid("tool response"))
        }),
        _ => return Err(OntologyToolError::Denied),
    };
    Ok(match response {
        Ok(value) => json!({
            "schema": "ctxql-graph-playground-result/v1",
            "status": "ok",
            "result": value,
        }),
        Err(error) => tool_error(error),
    })
}

struct CatalogToolHost {
    catalog: CertifiedOntologyCatalog,
}
impl OntologyToolHost for CatalogToolHost {
    fn lookup(&self, request: &Value) -> std::result::Result<Value, OntologyToolError> {
        let object = request.as_object().ok_or(OntologyToolError::Denied)?;
        if object.len() < 2
            || object.len() > 3
            || object
                .keys()
                .any(|key| !matches!(key.as_str(), "operation" | "query" | "limit"))
        {
            return Err(OntologyToolError::Denied);
        }
        let operation = object
            .get("operation")
            .and_then(Value::as_str)
            .filter(|value| {
                matches!(
                    *value,
                    "search" | "describe" | "hierarchy" | "vocabulary_status"
                )
            })
            .ok_or(OntologyToolError::Denied)?;
        let query = object
            .get("query")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(OntologyToolError::Denied)?;
        let limit = match object.get("limit") {
            Some(value) => value.as_u64().ok_or(OntologyToolError::Denied)?,
            None => 10,
        };
        if !(1..=20).contains(&limit) {
            return Err(OntologyToolError::Denied);
        }
        let query_key = ontology_search_key(query);
        if operation == "search" && query_key.is_empty() {
            return Err(OntologyToolError::Denied);
        }
        let mut ranked = self
            .catalog
            .terms()
            .filter_map(|term| {
                let rank = if operation == "search" {
                    ontology_match_rank(
                        term.iri().as_str(),
                        self.catalog.discovery_text(term.iri()),
                        &query_key,
                    )?
                } else if term.iri().as_str() == query {
                    0
                } else {
                    return None;
                };
                Some((rank, term))
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|(left_rank, left), (right_rank, right)| {
            left_rank
                .cmp(right_rank)
                .then_with(|| left.iri().cmp(right.iri()))
        });
        let terms = ranked
            .into_iter()
            .take(limit as usize)
            .map(|(_, term)| {
                let mut value =
                    canonical_json(&term.projection()).map_err(|_| OntologyToolError::Denied)?;
                if let (Some(object), Some(text)) = (
                    value.as_object_mut(),
                    self.catalog.discovery_text(term.iri()),
                ) {
                    object.insert("labels".into(), json!(text.labels()));
                    object.insert("definitions".into(), json!(text.definitions()));
                    object.insert("synonyms".into(), json!(text.synonyms()));
                }
                Ok(value)
            })
            .collect::<std::result::Result<Vec<_>, OntologyToolError>>()?;
        Ok(json!({
            "schema": "ctxql-ontology-tool-response/v1",
            "capture": self.catalog.capture_token(),
            "catalog_root": self.catalog.identity().catalog_root().as_str(),
            "operation": operation,
            "query": query,
            "terms": terms
        }))
    }
}

fn ontology_search_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn ontology_match_rank(
    iri: &str,
    text: Option<&OntologyDiscoveryText>,
    query_key: &str,
) -> Option<u8> {
    let mut candidates = vec![(0, ontology_search_key(iri))];
    if let Some(text) = text {
        candidates.extend(
            text.labels()
                .iter()
                .map(|value| (1, ontology_search_key(value))),
        );
        candidates.extend(
            text.synonyms()
                .iter()
                .map(|value| (2, ontology_search_key(value))),
        );
        candidates.extend(
            text.definitions()
                .iter()
                .map(|value| (3, ontology_search_key(value))),
        );
    }
    candidates
        .into_iter()
        .filter_map(|(field_rank, candidate)| {
            if candidate == query_key {
                Some(field_rank)
            } else if candidate.starts_with(query_key) {
                Some(4 + field_rank)
            } else if candidate.contains(query_key) {
                Some(8 + field_rank)
            } else {
                None
            }
        })
        .min()
}

fn exact_quote_coordinate(
    map: &CoordinateMap,
    document: &str,
    line_id: &str,
    quote: &str,
) -> Result<LineCoordinate> {
    let row = map
        .lines()
        .iter()
        .find(|row| row.id.as_str() == line_id)
        .ok_or_else(|| Error::invalid("unknown line ID"))?;
    let line = row.document_span.select(document)?;
    let mut matches = line.match_indices(quote);
    let (start, _) = matches
        .next()
        .ok_or_else(|| Error::invalid("quote not found in issued line"))?;
    if matches.next().is_some() {
        return Err(Error::invalid("quote is ambiguous in issued line"));
    }
    let end = start.checked_add(quote.len()).ok_or_else(Error::limit)?;
    let selection = if start == 0 && end == line.len() {
        LineSelection::WholeLine
    } else {
        LineSelection::Range { start, end }
    };
    Ok(LineCoordinate {
        line_id: row.id.clone(),
        selection,
    })
}

fn exact_ontology_mapping(
    catalog: &CertifiedOntologyCatalog,
    fact: &FactProposal,
    type_coordinate: Option<LineCoordinate>,
) -> Option<(Iri, Iri, LineCoordinate)> {
    // The current atomic grammar has no separate explicit type assertion.
    // A domain and a class-label mention do not prove an instance's type.
    let type_coordinate = type_coordinate?;
    let key = fact.predicate.to_lowercase();
    let mut matches = catalog
        .terms()
        .filter(|term| term.kind() == OntologyTermKind::Property && term.extraction_eligible())
        .filter(|term| {
            term.iri().as_str() == fact.predicate
                || catalog.discovery_text(term.iri()).is_some_and(|text| {
                    text.labels()
                        .iter()
                        .chain(text.synonyms())
                        .any(|value| value.to_lowercase() == key)
                })
        })
        .filter_map(|term| {
            if term.domains().len() != 1
                || term.ranges().len() != 1
                || term.ranges().iter().next()?.as_str() != XSD_STRING
            {
                return None;
            }
            let subject_type = term.domains().iter().next()?.clone();
            // A property's domain does not establish that an arbitrary named
            // subject is an instance. Require the class designation itself in
            // the fact and its exact source quote before asserting rdf:type.
            let eligible_class = fact.quote.contains(&fact.subject)
                && catalog.terms().any(|candidate| {
                    candidate.iri() == &subject_type
                        && candidate.kind() == OntologyTermKind::Class
                        && candidate.extraction_eligible()
                        && catalog.discovery_text(candidate.iri()).is_some_and(|text| {
                            text.labels()
                                .iter()
                                .chain(text.synonyms())
                                .any(|label| label.eq_ignore_ascii_case(&fact.subject))
                        })
                });
            eligible_class.then(|| (term.iri().clone(), subject_type))
        });
    let first = matches.next()?;
    if matches.next().is_some() {
        None
    } else {
        Some((first.0, first.1, type_coordinate))
    }
}

fn deterministic_local_id(kind: &str, seed: &str) -> Result<LocalId> {
    let hash = ContentHash::of_bytes(format!("ctxql-fact-candidate/v1\0{kind}\0{seed}").as_bytes());
    LocalId::new(format!("{kind}:{}", &hash.as_str()[7..]), 128)
}

fn soft_iri(prefix: &str, phrase: &str) -> Result<Iri> {
    let lowered = phrase.to_lowercase();
    let hash = ContentHash::of_bytes(lowered.as_bytes());
    Iri::new(format!("{prefix}{}", &hash.as_str()[7..]))
}

fn provisional_entity_iri(source_id: &SourceId, locator: &Iri, phrase: &str) -> Result<Iri> {
    soft_iri(
        PROVISIONAL_ENTITY_PREFIX,
        &format!("{}\0{}\0{phrase}", source_id.as_str(), locator.as_str()),
    )
}

// A model's ontology label alone cannot establish an endpoint's source role.
// Only conservative, affirmative local constructions bind a named endpoint
// to a role; more complex linguistic readings remain unmapped/provisional.
fn role_is_explicit(role: &str, entity: &str, quote: &str) -> bool {
    let compact = |value: &str| ontology_search_key(value);
    let role = compact(role);
    let entity = compact(entity);
    let quote = compact(quote);
    if role.is_empty() || entity.is_empty() || !quote.contains(&role) || !quote.contains(&entity) {
        return false;
    }
    if ["not", "nota", "notthe", "no"]
        .iter()
        .any(|prefix| quote.contains(&format!("{prefix}{role}")))
    {
        return false;
    }
    role == entity
        || [
            format!("{role}{entity}"),
            format!("{role}is{entity}"),
            format!("{entity}as{role}"),
            format!("{entity}isthe{role}"),
            format!("{entity}isa{role}"),
        ]
        .iter()
        .any(|pattern| quote.contains(pattern))
}

fn candidate_seed(window_id: &str, index: usize, fact: &FactProposal) -> String {
    let mut seed = format!(
        "{window_id}\0{index}\0{}\0{}\0{}\0{}\0{}",
        fact.subject, fact.predicate, fact.object, fact.line_id, fact.quote
    );
    if let Some(typed) = &fact.typed_endpoint_evidence {
        seed.push_str(&format!(
            "\0{}\0{}\0{}\0{}\0{}\0{}",
            typed.subject_role,
            typed.subject_line_id,
            typed.subject_quote,
            typed.object_role,
            typed.object_line_id,
            typed.object_quote
        ));
    }
    seed
}

#[allow(clippy::too_many_arguments)]
fn mapped_advisory(
    source: &PreparedSource,
    window_id: &str,
    index: usize,
    fact: &FactProposal,
    coordinate: LineCoordinate,
    type_coordinate: LineCoordinate,
    predicate: Iri,
    subject_type: Iri,
    limits: &CandidateLimits,
) -> Result<AdvisoryBundle> {
    let seed = candidate_seed(window_id, index, fact);
    let bundle_id = deterministic_local_id("bundle", &seed)?;
    let subject_id = deterministic_local_id("subject", &seed)?;
    let type_id = deterministic_local_id("type", &format!("{seed}\0{}", subject_type.as_str()))?;
    let type_claim_id = deterministic_local_id("claim-type", &seed)?;
    let fact_claim_id = deterministic_local_id("claim-fact", &seed)?;
    let entities = vec![
        EntityCandidate::new(
            subject_id.clone(),
            fact.subject.clone(),
            subject_type.clone(),
            limits,
        )?,
        EntityCandidate::new(
            type_id.clone(),
            subject_type.as_str(),
            Iri::new(RDF_CLASS)?,
            limits,
        )?,
    ];
    let claims = vec![
        AdvisoryClaim {
            local_claim_id: type_claim_id.clone(),
            subject: subject_id.clone(),
            predicate: Iri::new(RDF_TYPE)?,
            object: CandidateObject::Entity(type_id),
            relation_type: Iri::new(TYPE_ASSERTION_RELATION_TYPE)?,
            claim_type: Iri::new(TYPE_ASSERTION_CLAIM_TYPE)?,
            endpoint_type_claims: Vec::new(),
            confidence: None,
            valid_time: None,
        },
        AdvisoryClaim {
            local_claim_id: fact_claim_id.clone(),
            subject: subject_id,
            predicate,
            object: CandidateObject::Literal(TypedLiteral::new(
                fact.object.clone(),
                Iri::new(XSD_STRING)?,
                None,
                limits,
            )?),
            relation_type: Iri::new(BUSINESS_RELATION_TYPE)?,
            claim_type: Iri::new(BUSINESS_CLAIM_TYPE)?,
            endpoint_type_claims: vec![type_claim_id.clone()],
            confidence: None,
            valid_time: None,
        },
    ];
    let metadata = [
        (type_claim_id, type_coordinate),
        (fact_claim_id, coordinate),
    ]
    .into_iter()
    .map(|(local_claim_id, coordinate)| ClaimMetadata {
        local_claim_id,
        locator: source.extraction.locator.clone(),
        text_version: source.extraction.text_version.clone(),
        coordinates: vec![coordinate],
        temporal_qualifier_claim: None,
    })
    .collect();
    let advisory = AdvisoryBundle {
        local_bundle_id: bundle_id,
        entities,
        claims,
        metadata,
    };
    advisory.validate_shape(limits)?;
    Ok(advisory)
}

#[allow(clippy::too_many_arguments)]
fn mapped_object_advisory(
    source: &PreparedSource,
    window_id: &str,
    index: usize,
    fact: &FactProposal,
    relation_coordinate: LineCoordinate,
    subject_type_coordinate: LineCoordinate,
    object_type_coordinate: LineCoordinate,
    predicate: Iri,
    subject_type: Iri,
    object_type: Iri,
    limits: &CandidateLimits,
) -> Result<AdvisoryBundle> {
    let seed = format!(
        "{}\0{}\0{}\0{:?}\0{:?}",
        candidate_seed(window_id, index, fact),
        subject_type.as_str(),
        object_type.as_str(),
        subject_type_coordinate,
        object_type_coordinate
    );
    let bundle_id = deterministic_local_id("bundle", &seed)?;
    let subject_id = deterministic_local_id("subject", &seed)?;
    let object_id = deterministic_local_id("object", &seed)?;
    let subject_class_id = deterministic_local_id("subject-class", &seed)?;
    let object_class_id = deterministic_local_id("object-class", &seed)?;
    let subject_type_claim = deterministic_local_id("claim-subject-type", &seed)?;
    let object_type_claim = deterministic_local_id("claim-object-type", &seed)?;
    let relation_claim = deterministic_local_id("claim-relation", &seed)?;
    let entities = vec![
        EntityCandidate::new(
            subject_id.clone(),
            fact.subject.clone(),
            subject_type.clone(),
            limits,
        )?,
        EntityCandidate::new(
            object_id.clone(),
            fact.object.clone(),
            object_type.clone(),
            limits,
        )?,
        EntityCandidate::new(
            subject_class_id.clone(),
            subject_type.as_str(),
            Iri::new(RDF_CLASS)?,
            limits,
        )?,
        EntityCandidate::new(
            object_class_id.clone(),
            object_type.as_str(),
            Iri::new(RDF_CLASS)?,
            limits,
        )?,
    ];
    let type_claim = |local_claim_id, subject, object| AdvisoryClaim {
        local_claim_id,
        subject,
        predicate: Iri::new(RDF_TYPE).expect("fixed rdf:type IRI"),
        object: CandidateObject::Entity(object),
        relation_type: Iri::new(TYPE_ASSERTION_RELATION_TYPE).expect("fixed relation type IRI"),
        claim_type: Iri::new(TYPE_ASSERTION_CLAIM_TYPE).expect("fixed claim type IRI"),
        endpoint_type_claims: Vec::new(),
        confidence: None,
        valid_time: None,
    };
    let claims = vec![
        type_claim(
            subject_type_claim.clone(),
            subject_id.clone(),
            subject_class_id,
        ),
        type_claim(
            object_type_claim.clone(),
            object_id.clone(),
            object_class_id,
        ),
        AdvisoryClaim {
            local_claim_id: relation_claim.clone(),
            subject: subject_id,
            predicate,
            object: CandidateObject::Entity(object_id),
            relation_type: Iri::new(BUSINESS_RELATION_TYPE)?,
            claim_type: Iri::new(BUSINESS_CLAIM_TYPE)?,
            endpoint_type_claims: vec![subject_type_claim.clone(), object_type_claim.clone()],
            confidence: None,
            valid_time: None,
        },
    ];
    let metadata = [
        (subject_type_claim, subject_type_coordinate),
        (object_type_claim, object_type_coordinate),
        (relation_claim, relation_coordinate),
    ]
    .into_iter()
    .map(|(local_claim_id, coordinate)| ClaimMetadata {
        local_claim_id,
        locator: source.extraction.locator.clone(),
        text_version: source.extraction.text_version.clone(),
        coordinates: vec![coordinate],
        temporal_qualifier_claim: None,
    })
    .collect();
    let advisory = AdvisoryBundle {
        local_bundle_id: bundle_id,
        entities,
        claims,
        metadata,
    };
    advisory.validate_shape(limits)?;
    Ok(advisory)
}

fn provisional_advisory(
    source: &PreparedSource,
    window_id: &str,
    index: usize,
    fact: &FactProposal,
    coordinate: LineCoordinate,
    limits: &CandidateLimits,
) -> Result<AdvisoryBundle> {
    let seed = candidate_seed(window_id, index, fact);
    let subject_id = deterministic_local_id("subject", &seed)?;
    let claim_id = deterministic_local_id("claim-fact", &seed)?;
    let subject_iri =
        provisional_entity_iri(&source.source_id, &source.extraction.locator, &fact.subject)?;
    let advisory = AdvisoryBundle {
        local_bundle_id: deterministic_local_id("bundle", &seed)?,
        entities: vec![EntityCandidate::new(
            subject_id.clone(),
            subject_iri.as_str(),
            Iri::new(PROVISIONAL_ENTITY_CLASS)?,
            limits,
        )?],
        claims: vec![AdvisoryClaim {
            local_claim_id: claim_id.clone(),
            subject: subject_id,
            predicate: soft_iri(PROVISIONAL_PREDICATE_PREFIX, &fact.predicate)?,
            object: CandidateObject::Literal(TypedLiteral::new(
                fact.object.clone(),
                Iri::new(XSD_STRING)?,
                None,
                limits,
            )?),
            relation_type: Iri::new(BUSINESS_RELATION_TYPE)?,
            claim_type: Iri::new(BUSINESS_CLAIM_TYPE)?,
            endpoint_type_claims: Vec::new(),
            confidence: None,
            valid_time: None,
        }],
        metadata: vec![ClaimMetadata {
            local_claim_id: claim_id,
            locator: source.extraction.locator.clone(),
            text_version: source.extraction.text_version.clone(),
            coordinates: vec![coordinate],
            temporal_qualifier_claim: None,
        }],
    };
    advisory.validate_shape(limits)?;
    Ok(advisory)
}

fn document_mapping_status(report: &DocumentReport) -> &'static str {
    let nonzero = [
        report.mapped_candidate_count,
        report.provisional_candidate_count,
        report.unmapped_candidate_count,
    ]
    .into_iter()
    .filter(|count| *count != 0)
    .count();
    if nonzero > 1 {
        "mixed"
    } else if report.mapped_candidate_count != 0 {
        "mapped"
    } else if report.provisional_candidate_count != 0 {
        "provisional"
    } else if report.unmapped_candidate_count != 0 {
        "unmapped"
    } else if report.candidate_count != 0 {
        "rejected"
    } else {
        "no_candidates"
    }
}

// Assess atomic fact blocks independently. Resynchronization skips an invalid
// block to the next exact header; it never repairs that block.
fn parse_independent_fact_blocks<S: AsRef<str>>(
    raw: &str,
    line_ids: &[S],
    limits: &FactBlockLimits,
) -> std::result::Result<
    Vec<std::result::Result<FactProposal, cdb_provider_pi::fact_blocks::FactBlockParseError>>,
    cdb_provider_pi::fact_blocks::FactBlockParseError,
> {
    use cdb_provider_pi::fact_blocks::FactBlockParseError;
    if raw.len() > limits.max_output_bytes {
        return Err(FactBlockParseError::Limit("output_bytes"));
    }
    if raw == "NO_CLAIMS" {
        return Ok(Vec::new());
    }
    let lines = raw.lines().collect::<Vec<_>>();
    let mut results = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut offset = 0;
    while offset < lines.len() {
        if results.len() >= limits.max_facts {
            return Err(FactBlockParseError::Limit("facts"));
        }
        let block_len = match lines[offset] {
            "FACT:" => Some(5),
            "TYPED_FACT:" => Some(13),
            _ => None,
        };
        if let Some(block_len) = block_len {
            let end = offset.saturating_add(block_len).min(lines.len());
            let block = lines[offset..end].join("\n");
            let result = parse_fact_blocks(&block, line_ids, limits).and_then(|mut facts| {
                if facts.len() != 1 {
                    return Err(FactBlockParseError::Grammar("expected_single_fact"));
                }
                let fact = facts.remove(0);
                if !seen.insert((
                    fact.subject.clone(),
                    fact.predicate.clone(),
                    fact.object.clone(),
                    fact.line_id.clone(),
                    fact.quote.clone(),
                )) {
                    return Err(FactBlockParseError::DuplicateFact);
                }
                Ok(fact)
            });
            if result.is_ok() {
                offset = end;
                results.push(result);
                continue;
            }
            results.push(result);
        } else {
            results.push(Err(FactBlockParseError::Grammar("expected_fact_header")));
        }
        offset += 1;
        while offset < lines.len() && !matches!(lines[offset], "FACT:" | "TYPED_FACT:") {
            offset += 1;
        }
    }
    if results.is_empty() {
        results.push(Err(FactBlockParseError::Grammar("empty")));
    }
    Ok(results)
}

fn restore_work_report(report: &mut DocumentReport, draft: &V) -> Result<()> {
    let saved = canonical_json(draft.field("report")?)?;
    let count = |key: &str| -> Result<usize> {
        usize::try_from(
            saved
                .get(key)
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::invalid("frozen report counts"))?,
        )
        .map_err(|_| Error::limit())
    };
    report.candidate_count = count("candidate_count")?;
    report.mapped_candidate_count = count("mapped_candidate_count")?;
    report.provisional_candidate_count = count("provisional_candidate_count")?;
    report.unmapped_candidate_count = count("unmapped_candidate_count")?;
    report.rejected_candidate_count = count("rejected_candidate_count")?;
    report.no_claim_window_count = count("no_claim_window_count")?;
    report.issued_ranges = serde_json::from_value(saved["issued_ranges"].clone())
        .map_err(|_| Error::invalid("frozen report ranges"))?;
    for artifact in saved["artifacts"]
        .as_array()
        .ok_or_else(|| Error::invalid("frozen artifacts"))?
    {
        let kind = match artifact["kind"].as_str() {
            Some("provider_capture") => "provider_capture",
            Some("evaluation_outcomes") => "evaluation_outcomes",
            _ => return Err(Error::invalid("frozen artifact kind")),
        };
        report.artifacts.push(ArtifactReport {
            kind,
            window_id: artifact["window_id"]
                .as_str()
                .ok_or_else(|| Error::invalid("frozen artifact window"))?
                .into(),
            root: artifact["root"]
                .as_str()
                .ok_or_else(|| Error::invalid("frozen artifact root"))?
                .into(),
        });
    }
    report.artifact_descriptors = saved
        .get("artifact_descriptors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(())
}

fn apply_work_outcome(
    report: &mut DocumentReport,
    draft: &V,
    outcome: crate::acquisition_work::WorkOutcome,
) -> Result<()> {
    report.review_record_count = outcome.review.review_ids().len();
    report
        .review_receipts
        .push(canonical_json(&outcome.review.projection())?);
    if let Some(receipt) = outcome.result_review {
        report
            .review_receipts
            .push(canonical_json(&receipt.projection())?);
    }
    if let Some(receipt) = outcome.business {
        report.validated_bundle_count = 1;
        report.admitted_bundle_count = 1;
        report.validated_claim_count = receipt.claim_ids().len();
        report.admitted_claim_count = receipt.claim_ids().len();
        for value in draft.field("claims")?.as_array()? {
            let claim = CandidateClaim::from_value(value)?;
            if !receipt.claim_ids().contains(claim.id()) {
                return Err(Error::invalid("frozen claim not admitted"));
            }
            report.push_claim(canonical_json(value)?)?;
        }
        report.push_admission(canonical_json(&receipt.projection())?)?;
    }
    if let Some(root) = outcome.result_root {
        report.artifacts.push(ArtifactReport {
            kind: "admission_result",
            window_id: "document".into(),
            root: root.as_str().into(),
        });
    }
    if let Some(code) = outcome.publication_error {
        report.push_error(StageError {
            stage: "result_publication_pending",
            code,
            window_id: None,
        })?;
    }
    if let Some(code) = outcome.projection_error {
        report.push_error(StageError {
            stage: "projection_pending",
            code,
            window_id: None,
        })?;
    }
    Ok(())
}

struct PendingReviewPage {
    window_id: String,
    outcome_root: ContentHash,
    outcomes: Vec<Value>,
}

struct V2Processing {
    review_pages: Vec<PendingReviewPage>,
    claims: Vec<CandidateClaim>,
}

fn build_review_records(
    source: &PreparedSource,
    extraction_run: &ExtractionRunId,
    pages: &[PendingReviewPage],
) -> Result<Vec<ReviewRecord>> {
    let mut records = Vec::new();
    for page in pages {
        let synthetic = json!({
            "candidate_index": 0,
            "kind": "no_claims",
            "reason": "explicit_no_claims"
        });
        let outcomes: &[Value] = if page.outcomes.is_empty() {
            std::slice::from_ref(&synthetic)
        } else {
            &page.outcomes
        };
        for (ordinal, outcome) in outcomes.iter().enumerate() {
            let candidate_index = outcome
                .get("candidate_index")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(ordinal);
            let commitment = ContentHash::of_bytes(
                format!(
                    "ctxql-review-record/v1\0{}\0{}\0{}\0{}",
                    extraction_run.as_str(),
                    page.window_id,
                    candidate_index,
                    page.outcome_root.as_str()
                )
                .as_bytes(),
            );
            let (suggested_predicates, suggested_types) = review_suggestions(outcome);
            let assertion_intent = match outcome.get("assertion").and_then(Value::as_str) {
                Some("direct") => ReviewAssertionIntent::Direct,
                Some("provisional") => ReviewAssertionIntent::Provisional,
                _ => ReviewAssertionIntent::None,
            };
            let vocabulary_verdict = match outcome.get("vocabulary").and_then(Value::as_str) {
                Some("valid") => VocabularyVerdict::Valid,
                Some("repaired") => VocabularyVerdict::Repaired,
                Some("rejected") => VocabularyVerdict::Rejected,
                _ => VocabularyVerdict::NotChecked,
            };
            let reason = outcome
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or(match assertion_intent {
                    ReviewAssertionIntent::Direct => "accepted_direct",
                    ReviewAssertionIntent::Provisional => "accepted_provisional",
                    ReviewAssertionIntent::None => "grounded_review_only",
                })
                .to_owned();
            let strings = |key: &str| {
                outcome
                    .get(key)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            };
            let accepted_claim_ids = strings("accepted_claim_ids")
                .into_iter()
                .map(ClaimId::new)
                .collect::<Result<Vec<_>>>()?;
            records.push(ReviewRecord::new(
                ReviewRecordId::new(format!("urn:ctxql:review:{}", &commitment.as_str()[7..]))?,
                format!("{}#{candidate_index}", page.window_id),
                source.source_id.as_str(),
                page.outcome_root.clone(),
                vocabulary_verdict,
                assertion_intent,
                vec![reason],
                suggested_predicates,
                suggested_types,
                strings("resolved_predicates"),
                strings("resolved_types"),
                accepted_claim_ids,
            )?);
        }
    }
    Ok(records)
}

fn normalized_outcome_component(outcome: &Value) -> Option<Value> {
    outcome
        .get("normalized_projection")
        .or_else(|| outcome.get("original"))
        .and_then(Value::as_str)
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
}

fn review_suggestions(outcome: &Value) -> (Vec<String>, Vec<String>) {
    let Some(value) = normalized_outcome_component(outcome) else {
        return (Vec::new(), Vec::new());
    };
    let kind = if value.get("predicate").is_some() {
        "predicate"
    } else if value.get("term").is_some() {
        "term"
    } else {
        return (Vec::new(), Vec::new());
    };
    let mut values = value
        .get(kind)
        .and_then(|value| value.get("suggestions"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|suggestion| suggestion.get("text").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values.truncate(8);
    if kind == "term" {
        (Vec::new(), values)
    } else {
        (values, Vec::new())
    }
}

#[allow(clippy::too_many_arguments)] // Coordinates multiple independently bound capture inputs.
fn process_v2_outcomes(
    store: &SourceObjectWriter,
    source: &PreparedSource,
    mode: IngestMode,
    maps: &BTreeMap<String, CoordinateMap>,
    outcomes: Vec<(String, std::result::Result<String, TransportError>)>,
    ontology_mode: OntologyMode,
    ontology: &dyn OntologyToolHost,
    gazetteer: Option<&EntityGazetteer>,
    document_table: &DocumentEntityTable,
    response_protocols: &BTreeMap<String, ProposalResponseProtocol>,
    request_seeds: &BTreeMap<String, String>,
    issued_document_handles: &BTreeMap<String, Vec<String>>,
    report: &mut DocumentReport,
) -> Result<V2Processing> {
    let limits = ProposalLimits::default();
    let mut review_pages = Vec::new();
    let mut claims = BTreeMap::new();
    let mut term_cache = BTreeMap::new();
    for (window_id, transport_outcome) in outcomes {
        let raw = match transport_outcome {
            Ok(raw) => raw,
            Err(error) => {
                let code = transport_error_code(&error);
                report.provider_responses.push(ProviderResponseReport {
                    phase: "individual_v2",
                    window_ids: vec![window_id.clone()],
                    text: None,
                    text_sha256: None,
                    parse_error: None,
                    transport_error: Some(code),
                });
                report.push_error(StageError {
                    stage: "provider",
                    code,
                    window_id: Some(window_id),
                })?;
                continue;
            }
        };
        let raw_hash = ContentHash::of_bytes(raw.as_bytes());
        if mode != IngestMode::ExtractOnly {
            let root = store.put_object(raw.as_bytes())?;
            if root != raw_hash {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "provider capture root mismatch",
                ));
            }
            report.artifacts.push(ArtifactReport {
                kind: "provider_capture",
                window_id: window_id.clone(),
                root: root.as_str().to_owned(),
            });
        }
        let map = maps
            .get(&window_id)
            .ok_or_else(|| Error::invalid("provider returned unknown v2 window"))?;
        let issued_ranges = map.issued_ranges();
        let document_handles = issued_document_handles
            .get(&window_id)
            .ok_or_else(|| Error::invalid("missing issued document handle context"))?;
        let context = ProposalParseContext {
            passage_namespace: &window_id,
            issued_ranges: &issued_ranges,
            document_handles,
        };
        let protocol = response_protocols
            .get(&window_id)
            .copied()
            .ok_or_else(|| Error::invalid("missing acquisition response protocol binding"))?;
        let parsed = parse_proposal_response(&raw, &context, &limits, protocol);
        report.provider_responses.push(ProviderResponseReport {
            phase: "individual_v2",
            window_ids: vec![window_id.clone()],
            text: (mode == IngestMode::ExtractOnly).then_some(raw.clone()),
            text_sha256: Some(raw_hash.as_str().to_owned()),
            parse_error: parsed.as_ref().err().map(v2_parse_error_code),
            transport_error: None,
        });
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                let code = v2_parse_error_code(&error);
                report.push_error(StageError {
                    stage: "provider_grammar_v2",
                    code,
                    window_id: Some(window_id.clone()),
                })?;
                if mode != IngestMode::ExtractOnly {
                    let page = vec![json!({
                        "kind": "envelope",
                        "syntax": "rejected",
                        "reason": code
                    })];
                    let outcome_root = persist_v2_outcome_page(
                        store,
                        source,
                        &window_id,
                        raw_hash.as_str(),
                        &page,
                        protocol,
                        report,
                    )?;
                    review_pages.push(PendingReviewPage {
                        window_id: window_id.clone(),
                        outcome_root,
                        outcomes: page,
                    });
                }
                continue;
            }
        };
        let ParsedProposalResponse {
            envelope,
            diagnostics,
        } = parsed;
        if envelope.no_claims {
            report.no_claim_window_count = report.no_claim_window_count.saturating_add(1);
        }
        let mut page = evaluate_v2_envelope(
            source.extraction.text(),
            map,
            &window_id,
            &envelope,
            protocol,
            report,
        );
        evaluate_text_diagnostics(&diagnostics, &window_id, report, &mut page);
        let seed = request_seeds
            .get(&window_id)
            .ok_or_else(|| Error::invalid("missing passage request seed"))?;
        let lowered = if ontology_mode == OntologyMode::Soft {
            lower_v2_soft_claims(source, map, &envelope, document_table, seed)?
        } else {
            lower_v2_claims(
                source,
                map,
                &envelope,
                ontology,
                gazetteer,
                document_table,
                seed,
                &mut term_cache,
            )?
        };
        let lowered = freeze_v2_classifications(lowered, seed, ontology_mode, gazetteer, &claims)?;
        reconcile_v2_outcomes(&mut page, &lowered, ontology_mode, ontology, &envelope);
        for claim in lowered {
            claims.insert(claim.id().as_str().to_owned(), claim);
        }
        if mode != IngestMode::ExtractOnly {
            let outcome_root = persist_v2_outcome_page(
                store,
                source,
                &window_id,
                raw_hash.as_str(),
                &page,
                protocol,
                report,
            )?;
            review_pages.push(PendingReviewPage {
                window_id: window_id.clone(),
                outcome_root,
                outcomes: page,
            });
        }
    }
    let accepted_count = claims.len();
    report.unmapped_candidate_count = report
        .unmapped_candidate_count
        .saturating_sub(accepted_count);
    if accepted_count != 0 {
        if ontology_mode == OntologyMode::Soft {
            report.provisional_candidate_count = report
                .provisional_candidate_count
                .saturating_add(accepted_count);
            report.mapping_status = "provisional";
        } else {
            report.mapped_candidate_count =
                report.mapped_candidate_count.saturating_add(accepted_count);
            report.mapping_status = "mapped";
        }
    }
    Ok(V2Processing {
        review_pages,
        claims: claims.into_values().collect(),
    })
}

fn selected_suggestion(choice: &TermChoice) -> Option<&str> {
    choice
        .selected
        .and_then(|index| choice.suggestions.get(index))
        .map(|suggestion| suggestion.text.as_str())
}

fn identifying_probes(
    gazetteer: &EntityGazetteer,
    proposed_iri: &str,
    grounded: &[GroundedEvidence],
) -> Vec<IdentifierProbe> {
    let Some(entity) = gazetteer.describe(proposed_iri) else {
        return Vec::new();
    };
    entity
        .identifiers
        .iter()
        .filter(|identifier| {
            grounded
                .iter()
                .any(|evidence| evidence.quote.contains(&identifier.value))
        })
        .map(|identifier| IdentifierProbe {
            predicate: identifier.predicate.clone(),
            value: identifier.value.clone(),
        })
        .collect()
}

fn resolved_known_entity(
    gazetteer: Option<&EntityGazetteer>,
    proposed_iri: &str,
    grounded: &[GroundedEvidence],
) -> Option<EntityId> {
    let gazetteer = gazetteer?;
    let probes = identifying_probes(gazetteer, proposed_iri, grounded);
    match gazetteer.resolve_known_iri(proposed_iri, &probes) {
        KnownIriResolution::Resolved { iri } => EntityId::new(iri).ok(),
        KnownIriResolution::NotApproved
        | KnownIriResolution::IdentifierRequired
        | KnownIriResolution::IdentifierMismatch
        | KnownIriResolution::Ambiguous { .. } => None,
    }
}

fn resolve_entity_reference(
    reference: &ProposalEntityRef,
    local: &BTreeMap<String, EntityId>,
    gazetteer: Option<&EntityGazetteer>,
    grounded: &[GroundedEvidence],
    document_table: &DocumentEntityTable,
) -> Option<(EntityId, Vec<String>)> {
    match reference {
        ProposalEntityRef::Local { id, .. } => {
            local.get(id).cloned().map(|entity| (entity, Vec::new()))
        }
        ProposalEntityRef::Known { proposed_iri } => {
            let entity = resolved_known_entity(gazetteer, proposed_iri, grounded)?;
            let classes = gazetteer?.describe(proposed_iri)?.classes.clone();
            Some((entity, classes))
        }
        ProposalEntityRef::Document { handle } => document_table
            .entities()
            .find(|entity| entity.handle.as_str() == handle)
            .map(|entity| (entity.iri.clone(), Vec::new())),
    }
}

fn spans_from_grounded(
    grounded: &[GroundedEvidence],
) -> Option<Vec<cdb_acquisition::coordinates::ResolvedSpan>> {
    let mut spans = grounded
        .iter()
        .map(|item| item.resolved.clone())
        .collect::<Vec<_>>();
    spans.sort_by_key(|item| (item.span.start(), item.span.end()));
    spans.dedup_by_key(|item| (item.span.start(), item.span.end()));
    (!spans
        .windows(2)
        .any(|pair| pair[0].span.end() > pair[1].span.start()))
    .then_some(spans)
}

fn lower_v2_soft_claims(
    source: &PreparedSource,
    map: &CoordinateMap,
    envelope: &ProposalEnvelopeV2,
    document_table: &DocumentEntityTable,
    request_seed: &str,
) -> Result<Vec<CandidateClaim>> {
    const PROVISIONAL_CLASS: &str = "https://ctxql.example/acquisition/v2/ProvisionalEntity";
    const PROVISIONAL_RELATION: &str = "https://ctxql.example/acquisition/v2/ProvisionalRelation";
    const PROVISIONAL_CLAIM: &str =
        "https://ctxql.example/acquisition/v2/ProvisionalExtractionClaim";
    const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

    let mut entities = BTreeMap::<String, EntityId>::new();
    for component in &envelope.entities {
        let Some(entity) = component.parsed() else {
            continue;
        };
        if ground_evidence(map, source.extraction.text(), &entity.evidence, 16).is_err() {
            continue;
        }
        let Some(handle) = document_table.resolve_local(request_seed, &entity.id) else {
            continue;
        };
        entities.insert(
            entity.id.clone(),
            document_table.resolve_reference(handle)?.iri.clone(),
        );
    }

    let literal = |value: &str| {
        cdb_core::claim::TypedLiteral::new(Iri::new(XSD_STRING)?, V::string(value), None)
            .map(|literal| literal.projection())
    };
    let mut claims = Vec::new();
    for component in &envelope.entities {
        let Some(entity) = component.parsed() else {
            continue;
        };
        let Some(subject) = entities.get(&entity.id) else {
            continue;
        };
        for component in &entity.classes {
            let Some(class) = component.parsed() else {
                continue;
            };
            if class.source_mode != SourceMode::Affirmative || class.fit != SemanticFit::Supported {
                continue;
            }
            let (Some(suggestion), Some(spans)) = (
                selected_suggestion(&class.term),
                grounded_spans(map, source.extraction.text(), &class.evidence),
            ) else {
                continue;
            };
            claims.push(make_v2_claim(
                source,
                subject,
                soft_iri(PROVISIONAL_PREDICATE_PREFIX, "classification")?.as_str(),
                literal(suggestion)?,
                PROVISIONAL_RELATION,
                PROVISIONAL_CLASS,
                XSD_STRING,
                PROVISIONAL_CLAIM,
                &spans,
                "provisional_classification",
                &class.id,
            )?);
        }
    }
    for component in &envelope.relations {
        let Some(relation) = component.parsed() else {
            continue;
        };
        if relation.source_mode != SourceMode::Affirmative
            || relation.fit != SemanticFit::Supported
            || !relation.qualifiers.is_empty()
        {
            continue;
        }
        let ProposalRelationObject::Entity(object_reference) = &relation.object else {
            continue;
        };
        let Ok(grounded) = ground_evidence(map, source.extraction.text(), &relation.evidence, 16)
        else {
            continue;
        };
        let (Some((subject, _)), Some((object, _)), Some(suggestion), Some(spans)) = (
            resolve_entity_reference(
                &relation.subject,
                &entities,
                None,
                &grounded,
                document_table,
            ),
            resolve_entity_reference(object_reference, &entities, None, &grounded, document_table),
            selected_suggestion(&relation.predicate),
            spans_from_grounded(&grounded),
        ) else {
            continue;
        };
        claims.push(make_v2_claim(
            source,
            &subject,
            soft_iri(PROVISIONAL_PREDICATE_PREFIX, suggestion)?.as_str(),
            V::string(object.as_str()),
            PROVISIONAL_RELATION,
            PROVISIONAL_CLASS,
            PROVISIONAL_CLASS,
            PROVISIONAL_CLAIM,
            &spans,
            "provisional_relation",
            &relation.id,
        )?);
    }
    for component in &envelope.attributes {
        let Some(attribute) = component.parsed() else {
            continue;
        };
        if attribute.source_mode != SourceMode::Affirmative
            || attribute.fit != SemanticFit::Supported
            || !attribute.qualifiers.is_empty()
        {
            continue;
        }
        let Ok(grounded) = ground_evidence(map, source.extraction.text(), &attribute.evidence, 16)
        else {
            continue;
        };
        let (Some((subject, _)), Some(suggestion), Some(spans)) = (
            resolve_entity_reference(
                &attribute.subject,
                &entities,
                None,
                &grounded,
                document_table,
            ),
            selected_suggestion(&attribute.predicate),
            spans_from_grounded(&grounded),
        ) else {
            continue;
        };
        claims.push(make_v2_claim(
            source,
            &subject,
            soft_iri(PROVISIONAL_PREDICATE_PREFIX, suggestion)?.as_str(),
            literal(&attribute.value.lexical)?,
            PROVISIONAL_RELATION,
            PROVISIONAL_CLASS,
            XSD_STRING,
            PROVISIONAL_CLAIM,
            &spans,
            "provisional_attribute",
            &attribute.id,
        )?);
    }
    Ok(claims)
}

#[allow(clippy::too_many_arguments)] // Claim lowering requires each validated capture dependency.
fn lower_v2_claims(
    source: &PreparedSource,
    map: &CoordinateMap,
    envelope: &ProposalEnvelopeV2,
    ontology: &dyn OntologyToolHost,
    gazetteer: Option<&EntityGazetteer>,
    document_table: &DocumentEntityTable,
    request_seed: &str,
    term_cache: &mut BTreeMap<(String, String), Option<String>>,
) -> Result<Vec<CandidateClaim>> {
    const UNCLASSIFIED: &str = "https://ctxql.example/acquisition/v2/UnclassifiedEntity";
    const ACCEPTED: &str = "https://ctxql.example/acquisition/v2/AcceptedExtractionClaim";
    const TYPE_RELATION: &str = "https://ctxql.example/acquisition/v2/TypeAssertionRelation";
    const OBJECT_RELATION: &str = "https://ctxql.example/acquisition/v2/ObjectPropertyRelation";
    const DATATYPE_RELATION: &str = "https://ctxql.example/acquisition/v2/DatatypePropertyRelation";

    let mut entities = BTreeMap::<String, EntityId>::new();
    let mut entity_types = BTreeMap::<String, Vec<String>>::new();
    for component in &envelope.entities {
        let Some(entity) = component.parsed() else {
            continue;
        };
        let Ok(grounded) = ground_evidence(map, source.extraction.text(), &entity.evidence, 16)
        else {
            continue;
        };
        let id = entity
            .known_entity
            .as_deref()
            .and_then(|iri| resolved_known_entity(gazetteer, iri, &grounded))
            .or_else(|| {
                document_table
                    .resolve_local(request_seed, &entity.id)
                    .and_then(|handle| document_table.resolve_reference(handle).ok())
                    .map(|entity| entity.iri.clone())
            })
            .ok_or_else(|| Error::invalid("missing document entity binding"))?;
        entities.insert(entity.id.clone(), id);
        let mut classes = entity
            .known_entity
            .as_deref()
            .and_then(|iri| gazetteer.and_then(|source| source.describe(iri)))
            .filter(|known| entities[&entity.id].as_str() == known.iri)
            .map(|known| known.classes.clone())
            .unwrap_or_default();
        for class in &entity.classes {
            let Some(class) = class.parsed() else {
                continue;
            };
            if class.source_mode != SourceMode::Affirmative || class.fit != SemanticFit::Supported {
                continue;
            }
            if let Some(iri) = resolve_v2_choice(ontology, &class.term, "class", term_cache) {
                classes.push(iri);
            }
        }
        classes.sort();
        classes.dedup();
        entity_types.insert(entity.id.clone(), classes);
    }

    let mut claims = Vec::new();
    for component in &envelope.entities {
        let Some(entity) = component.parsed() else {
            continue;
        };
        let Some(subject) = entities.get(&entity.id) else {
            continue;
        };
        for class_component in &entity.classes {
            let Some(class) = class_component.parsed() else {
                continue;
            };
            if class.source_mode != SourceMode::Affirmative || class.fit != SemanticFit::Supported {
                continue;
            }
            let Some(class_iri) = resolve_v2_choice(ontology, &class.term, "class", term_cache)
            else {
                continue;
            };
            let Some(spans) = grounded_spans(map, source.extraction.text(), &class.evidence) else {
                continue;
            };
            claims.push(make_v2_claim(
                source,
                subject,
                RDF_TYPE,
                V::string(&class_iri),
                TYPE_RELATION,
                &class_iri,
                RDF_CLASS,
                ACCEPTED,
                &spans,
                "classification",
                &class.id,
            )?);
        }
    }

    for component in &envelope.relations {
        let Some(relation) = component.parsed() else {
            continue;
        };
        if relation.source_mode != SourceMode::Affirmative
            || relation.fit != SemanticFit::Supported
            || !relation.qualifiers.is_empty()
        {
            continue;
        }
        let ProposalRelationObject::Entity(object_reference) = &relation.object else {
            continue;
        };
        let Ok(grounded) = ground_evidence(map, source.extraction.text(), &relation.evidence, 16)
        else {
            continue;
        };
        let (Some((subject, established_subject_types)), Some((object, established_object_types))) = (
            resolve_entity_reference(
                &relation.subject,
                &entities,
                gazetteer,
                &grounded,
                document_table,
            ),
            resolve_entity_reference(
                object_reference,
                &entities,
                gazetteer,
                &grounded,
                document_table,
            ),
        ) else {
            continue;
        };
        let Some(predicate) =
            resolve_v2_choice(ontology, &relation.predicate, "object_property", term_cache)
        else {
            continue;
        };
        let Some(spans) = spans_from_grounded(&grounded) else {
            continue;
        };
        let subject_type = match &relation.subject {
            ProposalEntityRef::Local { id, .. } => {
                representative_type(&entity_types, id, UNCLASSIFIED)
            }
            _ => established_subject_types
                .first()
                .map(String::as_str)
                .unwrap_or(UNCLASSIFIED),
        };
        let object_type = match object_reference {
            ProposalEntityRef::Local { id, .. } => {
                representative_type(&entity_types, id, UNCLASSIFIED)
            }
            _ => established_object_types
                .first()
                .map(String::as_str)
                .unwrap_or(UNCLASSIFIED),
        };
        claims.push(make_v2_claim(
            source,
            &subject,
            &predicate,
            V::string(object.as_str()),
            OBJECT_RELATION,
            subject_type,
            object_type,
            ACCEPTED,
            &spans,
            "relation",
            &relation.id,
        )?);
    }

    for component in &envelope.attributes {
        let Some(attribute) = component.parsed() else {
            continue;
        };
        if attribute.source_mode != SourceMode::Affirmative
            || attribute.fit != SemanticFit::Supported
            || !attribute.qualifiers.is_empty()
        {
            continue;
        }
        let Ok(grounded) = ground_evidence(map, source.extraction.text(), &attribute.evidence, 16)
        else {
            continue;
        };
        let Some((subject, established_types)) = resolve_entity_reference(
            &attribute.subject,
            &entities,
            gazetteer,
            &grounded,
            document_table,
        ) else {
            continue;
        };
        let Some(predicate) = resolve_v2_choice(
            ontology,
            &attribute.predicate,
            "datatype_property",
            term_cache,
        ) else {
            continue;
        };
        let Some(datatype) =
            resolve_v2_choice(ontology, &attribute.value.datatype, "datatype", term_cache)
        else {
            continue;
        };
        let Ok(literal) = validated_typed_literal(&datatype, &attribute.value.lexical) else {
            continue;
        };
        let Some(spans) = spans_from_grounded(&grounded) else {
            continue;
        };
        let subject_type = match &attribute.subject {
            ProposalEntityRef::Local { id, .. } => {
                representative_type(&entity_types, id, UNCLASSIFIED)
            }
            _ => established_types
                .first()
                .map(String::as_str)
                .unwrap_or(UNCLASSIFIED),
        };
        claims.push(make_v2_claim(
            source,
            &subject,
            &predicate,
            literal.projection(),
            DATATYPE_RELATION,
            subject_type,
            &datatype,
            ACCEPTED,
            &spans,
            "attribute",
            &attribute.id,
        )?);
    }
    Ok(claims)
}

fn resolve_v2_choice(
    ontology: &dyn OntologyToolHost,
    choice: &TermChoice,
    kind: &str,
    cache: &mut BTreeMap<(String, String), Option<String>>,
) -> Option<String> {
    let selected = choice.selected?;
    let suggestion = choice.suggestions.get(selected)?.text.clone();
    let key = (kind.to_owned(), suggestion.clone());
    if let Some(value) = cache.get(&key) {
        return value.clone();
    }
    let resolved = ontology
        .lookup(&json!({
            "operation": "resolve_exact",
            "query": suggestion,
            "kind": kind,
            "limit": 20
        }))
        .ok()
        .and_then(|response| {
            (response["resolution"]["status"] == "unique")
                .then(|| {
                    response["resolution"]["match"]
                        .as_str()
                        .map(ToOwned::to_owned)
                })
                .flatten()
                .filter(|iri| {
                    response["terms"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|term| {
                            term["iri"].as_str() == Some(iri.as_str())
                                && term["kind"].as_str() == Some(kind)
                                && term["extraction_eligible"].as_bool() == Some(true)
                        })
                })
        });
    cache.insert(key, resolved.clone());
    resolved
}

fn grounded_spans(
    map: &CoordinateMap,
    document: &str,
    evidence: &[Evidence],
) -> Option<Vec<cdb_acquisition::coordinates::ResolvedSpan>> {
    let mut spans = ground_evidence(map, document, evidence, 16)
        .ok()?
        .into_iter()
        .map(|item| item.resolved)
        .collect::<Vec<_>>();
    spans.sort_by_key(|item| (item.span.start(), item.span.end()));
    spans.dedup_by_key(|item| (item.span.start(), item.span.end()));
    if spans
        .windows(2)
        .any(|pair| pair[0].span.end() > pair[1].span.start())
    {
        return None;
    }
    Some(spans)
}

fn representative_type<'a>(
    types: &'a BTreeMap<String, Vec<String>>,
    id: &str,
    fallback: &'a str,
) -> &'a str {
    types
        .get(id)
        .and_then(|values| values.first())
        .map(String::as_str)
        .unwrap_or(fallback)
}

#[allow(clippy::too_many_arguments)]
fn freeze_v2_classifications(
    claims: Vec<CandidateClaim>,
    request_seed: &str,
    mode: OntologyMode,
    gazetteer: Option<&EntityGazetteer>,
    previous: &BTreeMap<String, CandidateClaim>,
) -> Result<Vec<CandidateClaim>> {
    use cdb_core::classification::{
        ClassificationMetadata, ClassificationOrigin, ClassificationRef, EndpointClassification,
        EndpointClassificationStatus as Status, EXTENSION_KEY, RDF_TYPE,
    };
    let mut classes = BTreeMap::<String, Vec<ClassificationRef>>::new();
    if mode == OntologyMode::Hard {
        for claim in previous.values() {
            if let Ok(value) = claim.ext().field(EXTENSION_KEY) {
                let metadata = ClassificationMetadata::from_value(value)?;
                classes
                    .entry(claim.subject().as_str().to_owned())
                    .or_default()
                    .extend(metadata.subject().classes().iter().cloned());
            }
        }
    }
    for claim in &claims {
        if claim.relation().as_str() == RDF_TYPE {
            if let cdb_core::claim::ClaimObject::Entity(class) = claim.object() {
                // Capture-local component references avoid cyclic claim-ID dependencies.
                let component = claim
                    .ext()
                    .field("ctxql.acquisition.v2/component_ref")?
                    .as_str()?;
                let root = ContentHash::of_bytes(format!("{request_seed}\0{component}").as_bytes());
                classes
                    .entry(claim.subject().as_str().to_owned())
                    .or_default()
                    .push(ClassificationRef::new(
                        Iri::new(class.as_str())?,
                        ClassificationOrigin::Extracted,
                        cdb_core::id::ResourceId::new(format!(
                            "urn:ctxql:classification-component:{}",
                            &root.as_str()[7..]
                        ))?,
                    ));
            }
        }
    }
    claims
        .into_iter()
        .map(|claim| {
            let endpoint = |id: &str| {
                let mut entries = classes.get(id).cloned().unwrap_or_default();
                if mode == OntologyMode::Hard {
                    if let Some(gazetteer) = gazetteer {
                        entries.extend_from_slice(gazetteer.classification_refs(id));
                    }
                }
                EndpointClassification::new(
                    if mode == OntologyMode::Soft {
                        Status::Provisional
                    } else if entries.is_empty() {
                        Status::Unclassified
                    } else {
                        Status::Classified
                    },
                    entries,
                )
            };
            let subject = endpoint(claim.subject().as_str())?;
            let object = match claim.object() {
                cdb_core::claim::ClaimObject::Entity(id)
                    if claim.relation().as_str() != RDF_TYPE =>
                {
                    endpoint(id.as_str())?
                }
                _ => EndpointClassification::new(Status::Unclassified, Vec::new())?,
            };
            let mut projection = claim.projection().as_object()?.clone();
            projection.insert("subject_type".into(), V::string(subject.representative()));
            if matches!(claim.object(), cdb_core::claim::ClaimObject::Entity(_))
                && claim.relation().as_str() != RDF_TYPE
            {
                projection.insert("object_type".into(), V::string(object.representative()));
            }
            let frozen_context = V::object([
                ("request_seed".into(), V::string(request_seed)),
                ("subject".into(), subject.projection()),
                ("object".into(), object.projection()),
            ])?;
            let metadata = ClassificationMetadata::new(
                ContentHash::of_bytes(&frozen_context.canonical_bytes(Limits::default())?),
                subject,
                object,
            );
            let mut ext = claim.ext().as_object()?.clone();
            ext.insert(EXTENSION_KEY.into(), metadata.projection());
            projection.insert("ext".into(), V::Object(ext));
            let annotated = CandidateClaim::from_value(&V::Object(projection.clone()))?;
            let id = cdb_core::semantic_admission::stable_acquisition_v2_claim_id(
                &annotated,
                Limits::default(),
            )?;
            projection.insert("claim_id".into(), V::string(id.as_str()));
            CandidateClaim::from_value(&V::Object(projection))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)] // Claim identity commits each semantic and lineage field.
fn make_v2_claim(
    source: &PreparedSource,
    subject: &EntityId,
    predicate: &str,
    object: V,
    relation_type: &str,
    subject_type: &str,
    object_type: &str,
    claim_type: &str,
    spans: &[cdb_acquisition::coordinates::ResolvedSpan],
    component_kind: &str,
    component_id: &str,
) -> Result<CandidateClaim> {
    let lineage = strict_lineage(
        &source.source_id,
        &source.extraction.locator,
        &source.extraction.text_version,
        &ContentHash::of_bytes(source.extraction.text().as_bytes()),
        spans,
        16,
    )?;
    let identity = V::object([
        ("source".into(), V::string(source.source_id.as_str())),
        ("subject".into(), V::string(subject.as_str())),
        ("predicate".into(), V::string(predicate)),
        ("object".into(), object.clone()),
        ("lineage".into(), lineage.projection()),
    ])?;
    let root = ContentHash::of_bytes(&identity.canonical_bytes(Limits::default())?);
    let claim = CandidateClaim::from_value(&V::object([
        (
            "claim_id".into(),
            V::string(format!("urn:ctxql:claim:v2:{}", &root.as_str()[7..])),
        ),
        ("subject_id".into(), V::string(subject.as_str())),
        ("relation".into(), V::string(predicate)),
        ("object_id".into(), object),
        ("relation_type".into(), V::string(relation_type)),
        ("subject_type".into(), V::string(subject_type)),
        ("object_type".into(), V::string(object_type)),
        ("claim_type".into(), V::string(claim_type)),
        ("confidence".into(), V::Number(ExactNumber::from_u64(1))),
        (
            "grounding_level".into(),
            V::string("source_spans_available"),
        ),
        ("lineage".into(), lineage.projection()),
        (
            "ext".into(),
            V::object([
                (
                    "ctxql.acquisition.v2/component_kind".into(),
                    V::string(component_kind),
                ),
                (
                    "ctxql.acquisition.v2/source_mode".into(),
                    V::string("affirmative"),
                ),
                (
                    "ctxql.acquisition.v2/semantic_fit".into(),
                    V::string("supported"),
                ),
                (
                    "ctxql.acquisition.v2/claim_identity".into(),
                    V::string("stable-component/v1"),
                ),
                (
                    "ctxql.acquisition.v2/component_ref".into(),
                    V::string(format!("{component_kind}:{component_id}")),
                ),
            ])?,
        ),
    ])?)?;
    let id =
        cdb_core::semantic_admission::stable_acquisition_v2_claim_id(&claim, Limits::default())?;
    let V::Object(mut projection) = claim.projection() else {
        unreachable!("candidate claim projection is an object")
    };
    projection.insert("claim_id".into(), V::string(id.as_str()));
    CandidateClaim::from_value(&V::Object(projection))
}

fn reconcile_v2_outcomes(
    outcomes: &mut [Value],
    claims: &[CandidateClaim],
    ontology_mode: OntologyMode,
    ontology: &dyn OntologyToolHost,
    envelope: &ProposalEnvelopeV2,
) {
    let component_ids = proposal_component_ids(envelope);
    let mut accepted = BTreeMap::new();
    for claim in claims {
        let Ok(component_ref) = claim
            .ext()
            .field("ctxql.acquisition.v2/component_ref")
            .and_then(V::as_str)
        else {
            continue;
        };
        let component_ref = component_ref
            .strip_prefix("provisional_")
            .unwrap_or(component_ref);
        accepted.insert(component_ref.to_owned(), claim);
    }
    for outcome in outcomes {
        if outcome.get("syntax").and_then(Value::as_str) != Some("valid")
            || outcome.get("grounding").and_then(Value::as_str) != Some("verified")
        {
            continue;
        }
        let Some(kind) = outcome
            .get("kind")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            continue;
        };
        let Some(original) = normalized_outcome_component(outcome) else {
            continue;
        };
        // Read the parser-owned identity, not an optional ID in the normalized
        // projection. V3 deliberately omits wire IDs for non-entity components.
        // Text responses retain their exact block separately as `original`.
        let Some(id) = outcome
            .get("candidate_index")
            .and_then(Value::as_u64)
            .and_then(|index| component_ids.get(index as usize))
            .and_then(|id| *id)
        else {
            continue;
        };
        let key = format!("{kind}:{id}");
        // Vocabulary membership is independent of assertion eligibility/uncertainty.
        let term_kind = match kind.as_str() {
            "classification" => Some("class"),
            "attribute" => Some("datatype_property"),
            "relation" => Some("object_property"),
            _ => None,
        };
        let choice = &original[if kind == "classification" {
            "term"
        } else {
            "predicate"
        }];
        let spelling = choice["selected"]
            .as_u64()
            .and_then(|index| choice["suggestions"].get(index as usize))
            .and_then(|item| item["text"].as_str());
        let resolution = term_kind.zip(spelling).and_then(|(kind, query)| {
            ontology
                .lookup(
                    &json!({"operation":"resolve_exact", "query":query, "kind":kind, "limit":20}),
                )
                .ok()
        });
        let resolved = resolution.as_ref().and_then(|response| {
            if response["resolution"]["status"] != "unique" {
                return None;
            }
            response["resolution"]["match"].as_str().filter(|iri| {
                response["terms"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|term| {
                        term["iri"].as_str() == Some(*iri)
                            && term["kind"].as_str() == term_kind
                            && term["extraction_eligible"] == true
                    })
            })
        });
        let vocabulary = if let Some(iri) = resolved {
            if spelling == Some(iri) {
                "valid"
            } else {
                "repaired"
            }
        } else if term_kind.is_none() {
            "not_applicable"
        } else {
            "rejected"
        };
        outcome["vocabulary"] = json!(vocabulary);
        if let Some(iri) = resolved {
            outcome[if kind == "classification" {
                "resolved_types"
            } else {
                "resolved_predicates"
            }] = json!([iri]);
        }
        let Some(claim) = accepted.get(&key) else {
            outcome["semantic_fit"] = original
                .get("fit")
                .cloned()
                .unwrap_or(json!("not_applicable"));
            outcome["assertion"] = json!("withheld");
            outcome["admission"] = json!("not_applicable");
            outcome["reason"] = json!(if original["fit"] == "uncertain" {
                "semantic_fit_uncertain"
            } else if original["fit"] == "not_evaluated" {
                "semantic_fit_not_evaluated"
            } else if term_kind.is_some() && resolved.is_none() {
                match resolution
                    .as_ref()
                    .and_then(|r| r["resolution"]["status"].as_str())
                {
                    Some("ambiguous") => "ambiguous_vocabulary",
                    Some("not_found") | Some("unknown") => {
                        if kind == "classification" {
                            "unknown_class"
                        } else {
                            "unknown_predicate"
                        }
                    }
                    _ => "vocabulary_resolution_unavailable",
                }
            } else {
                "not_eligible_for_assertion"
            });
            continue;
        };
        let mut resolved_predicates = Vec::new();
        let mut resolved_types = Vec::new();
        if ontology_mode == OntologyMode::Hard {
            if kind == "classification" {
                if let cdb_core::claim::ClaimObject::Entity(value) = claim.object() {
                    resolved_types.push(value.as_str().to_owned());
                }
            } else {
                resolved_predicates.push(claim.relation().as_str().to_owned());
            }
        }
        outcome["vocabulary"] = json!(vocabulary);
        outcome["semantic_fit"] = json!("supported");
        outcome["assertion"] = json!(if ontology_mode == OntologyMode::Hard {
            "direct"
        } else {
            "provisional"
        });
        outcome["admission"] = json!("pending_review_first");
        outcome["reason"] = Value::Null;
        outcome["resolved_predicates"] = json!(resolved_predicates);
        outcome["resolved_types"] = json!(resolved_types);
        outcome["accepted_claim_ids"] = json!([claim.id().as_str()]);
    }
}

/// Identity order must match evaluate_v2_envelope, including invalid slots and aliases.
fn proposal_component_ids(envelope: &ProposalEnvelopeV2) -> Vec<Option<&str>> {
    let mut ids = Vec::new();
    for component in &envelope.entities {
        ids.push(component.parsed().map(|entity| entity.id.as_str()));
        if let Some(entity) = component.parsed() {
            ids.extend(entity.aliases.iter().map(|_| None));
            ids.extend(
                entity
                    .classes
                    .iter()
                    .map(|class| class.parsed().map(|value| value.id.as_str())),
            );
        }
    }
    ids.extend(
        envelope
            .attributes
            .iter()
            .map(|attribute| attribute.parsed().map(|value| value.id.as_str())),
    );
    ids.extend(
        envelope
            .relations
            .iter()
            .map(|relation| relation.parsed().map(|value| value.id.as_str())),
    );
    ids
}

fn evaluate_v2_envelope(
    document: &str,
    map: &CoordinateMap,
    window_id: &str,
    envelope: &ProposalEnvelopeV2,
    protocol: ProposalResponseProtocol,
    report: &mut DocumentReport,
) -> Vec<Value> {
    let mut page = Vec::new();
    let mut index = 0usize;
    for entity in &envelope.entities {
        evaluate_v2_component(
            "entity",
            entity,
            entity.parsed().map(|value| value.evidence.as_slice()),
            document,
            map,
            window_id,
            protocol,
            &mut index,
            report,
            &mut page,
        );
        if let Some(entity) = entity.parsed() {
            for alias in &entity.aliases {
                evaluate_v2_component(
                    "alias",
                    alias,
                    alias
                        .parsed()
                        .map(|value| std::slice::from_ref(&value.evidence)),
                    document,
                    map,
                    window_id,
                    protocol,
                    &mut index,
                    report,
                    &mut page,
                );
            }
            for class in &entity.classes {
                evaluate_v2_component(
                    "classification",
                    class,
                    class.parsed().map(|value| value.evidence.as_slice()),
                    document,
                    map,
                    window_id,
                    protocol,
                    &mut index,
                    report,
                    &mut page,
                );
            }
        }
    }
    for attribute in &envelope.attributes {
        evaluate_v2_component(
            "attribute",
            attribute,
            attribute.parsed().map(|value| value.evidence.as_slice()),
            document,
            map,
            window_id,
            protocol,
            &mut index,
            report,
            &mut page,
        );
    }
    for relation in &envelope.relations {
        evaluate_v2_component(
            "relation",
            relation,
            relation.parsed().map(|value| value.evidence.as_slice()),
            document,
            map,
            window_id,
            protocol,
            &mut index,
            report,
            &mut page,
        );
    }
    page
}

#[allow(clippy::too_many_arguments)]
fn evaluate_v2_component<T>(
    kind: &'static str,
    component: &ProposalComponent<T>,
    evidence: Option<&[Evidence]>,
    document: &str,
    map: &CoordinateMap,
    window_id: &str,
    protocol: ProposalResponseProtocol,
    index: &mut usize,
    report: &mut DocumentReport,
    page: &mut Vec<Value>,
) {
    let candidate_index = *index;
    *index = index.saturating_add(1);
    report.candidate_count = report.candidate_count.saturating_add(1);
    let (syntax, grounding, reason, status) = match (&component.value, evidence) {
        (Err(error), _) => (
            "rejected",
            "not_evaluated",
            Some(v2_component_error_code(error.code)),
            "grammar_rejected",
        ),
        (Ok(_), Some(evidence)) => match ground_evidence(map, document, evidence, 16) {
            Ok(_) => ("valid", "verified", None, "grounded_review_only"),
            Err(_) => (
                "valid",
                "rejected",
                Some("source_evidence_rejected"),
                "grounding_rejected",
            ),
        },
        (Ok(_), None) => (
            "valid",
            "rejected",
            Some("source_evidence_missing"),
            "grounding_rejected",
        ),
    };
    if status == "grounded_review_only" {
        report.unmapped_candidate_count = report.unmapped_candidate_count.saturating_add(1);
    } else {
        report.rejected_candidate_count = report.rejected_candidate_count.saturating_add(1);
    }
    report.validations.push(ValidationReport {
        window_id: window_id.to_owned(),
        candidate_index: Some(candidate_index),
        status,
        validated_claim_count: 0,
        error: reason,
    });
    let mut outcome = json!({
        "candidate_index": candidate_index,
        "kind": kind,
        "original": match protocol {
            ProposalResponseProtocol::HistoricalJson => Some(component.original_json.as_str()),
            ProposalResponseProtocol::TextV1 => component.original_text.as_deref(),
        },
        "syntax": syntax,
        "grounding": grounding,
        "vocabulary": "not_evaluated",
        "semantic_fit": "not_evaluated",
        "assertion": "withheld",
        "admission": "not_admitted",
        "projection": "not_projected",
        "reason": reason
    });
    if protocol == ProposalResponseProtocol::TextV1 {
        outcome["normalized_projection"] = json!(component.original_json);
    }
    page.push(outcome);
}

fn evaluate_text_diagnostics(
    diagnostics: &[TextProposalDiagnostic],
    window_id: &str,
    report: &mut DocumentReport,
    page: &mut Vec<Value>,
) {
    for diagnostic in diagnostics {
        let candidate_index = page.len();
        let reason = v2_component_error_code(diagnostic.code);
        report.candidate_count = report.candidate_count.saturating_add(1);
        report.rejected_candidate_count = report.rejected_candidate_count.saturating_add(1);
        report.validations.push(ValidationReport {
            window_id: window_id.to_owned(),
            candidate_index: Some(candidate_index),
            status: "grammar_rejected",
            validated_claim_count: 0,
            error: Some(reason),
        });
        page.push(json!({
            "candidate_index": candidate_index,
            "record_index": diagnostic.record_index,
            "kind": "orphan",
            "original": diagnostic.original_text,
            "normalized_projection": Value::Null,
            "syntax": "rejected",
            "grounding": "not_evaluated",
            "vocabulary": "not_evaluated",
            "semantic_fit": "not_evaluated",
            "assertion": "withheld",
            "admission": "not_admitted",
            "projection": "not_projected",
            "reason": reason
        }));
    }
}

fn persist_v2_outcome_page(
    store: &SourceObjectWriter,
    source: &PreparedSource,
    window_id: &str,
    capture_root: &str,
    outcomes: &[Value],
    protocol: ProposalResponseProtocol,
    report: &mut DocumentReport,
) -> Result<ContentHash> {
    let mut page = json!({
        "schema": if protocol == ProposalResponseProtocol::TextV1 {
            "ctxql-extraction-outcomes/v3"
        } else {
            "ctxql-extraction-outcomes/v2"
        },
        "source_id": source.source_id.as_str(),
        "text_version": source.extraction.text_version.as_str(),
        "window_id": window_id,
        "capture_root": capture_root,
        "outcomes": outcomes
    });
    if protocol == ProposalResponseProtocol::TextV1 {
        page["response_protocol"] = json!(TEXT_PROPOSAL_PROTOCOL);
    }
    let bytes = serde_json::to_vec(&page)
        .map_err(|_| Error::new(ErrorKind::Backend, "outcome encoding failed"))?;
    let root = store.put_object(&bytes)?;
    report.artifacts.push(ArtifactReport {
        kind: "evaluation_outcomes",
        window_id: window_id.to_owned(),
        root: root.as_str().to_owned(),
    });
    Ok(root)
}

fn v2_parse_error_code(error: &ProposalParseError) -> &'static str {
    match error {
        ProposalParseError::Limit(_) => "provider_v2_limit",
        ProposalParseError::Json(_) => "provider_v2_json",
        ProposalParseError::Envelope(_) => "provider_v2_envelope",
        ProposalParseError::InvalidContext(_) => "provider_v2_context",
    }
}

fn v2_component_error_code(error: cdb_acquisition::proposals::ComponentErrorCode) -> &'static str {
    use cdb_acquisition::proposals::ComponentErrorCode;
    match error {
        ComponentErrorCode::MissingField => "component_missing_field",
        ComponentErrorCode::UnknownField => "component_unknown_field",
        ComponentErrorCode::InvalidType => "component_invalid_type",
        ComponentErrorCode::InvalidValue => "component_invalid_value",
        ComponentErrorCode::LimitExceeded => "component_limit",
        ComponentErrorCode::DuplicateId => "component_duplicate_id",
        ComponentErrorCode::UnresolvedReference => "component_unresolved_reference",
    }
}

fn fact_parse_error_code(
    error: &cdb_provider_pi::fact_blocks::FactBlockParseError,
) -> &'static str {
    use cdb_provider_pi::fact_blocks::FactBlockParseError;
    match error {
        FactBlockParseError::Limit(_) => "provider_grammar_limit",
        FactBlockParseError::UnknownLineId => "provider_unknown_line",
        FactBlockParseError::DuplicateFact => "provider_duplicate_fact",
        FactBlockParseError::Grammar(_) => "provider_grammar_shape",
        FactBlockParseError::InvalidValue(_) => "provider_invalid_scalar",
    }
}

fn build_v2_briefing(
    host: &dyn OntologyToolHost,
    config: &AcquisitionConfig,
    passage: &str,
    names: &[&str],
) -> Result<Value> {
    let context = crate::passage_context::document_context(passage, 0, passage.len(), &[]);
    build_v2_briefing_with_context(host, config, passage, names, &context)
}

fn build_v2_briefing_with_context(
    host: &dyn OntologyToolHost,
    config: &AcquisitionConfig,
    passage: &str,
    names: &[&str],
    context: &Value,
) -> Result<Value> {
    use crate::ontology_briefing::{
        build_ontology_briefing, loan_briefing_seed_manifest, OntologyBriefingContext,
        OntologyBriefingLimits,
    };
    let manifest = config
        .ontology_briefing
        .clone()
        .map(Ok)
        .unwrap_or_else(loan_briefing_seed_manifest)
        .map_err(|error| Error::invalid(error.code))?;
    let headings = context["active_headings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| value["text"].as_str())
        .collect::<Vec<_>>();
    let briefing = build_ontology_briefing(
        host,
        &manifest,
        &OntologyBriefingContext {
            passage,
            title: context["title"]["text"].as_str(),
            headings: &headings,
            grounded_entity_names: names,
        },
        &OntologyBriefingLimits::default(),
    )
    .map_err(|error| Error::invalid(error.code))?;
    Ok(
        json!({"rendering": briefing.rendering, "commitment": briefing.commitment, "provenance": briefing.provenance}),
    )
}

#[allow(clippy::too_many_arguments)] // The request commits independently derived capture context.
fn render_request_v2(
    window_id: &str,
    locator: &str,
    text_version: &str,
    map: &CoordinateMap,
    document: &str,
    ontology_lookup: Option<&V>,
    ontology_briefing: &Value,
    entity_capture: Option<&str>,
    document_entity_handles: Value,
    known_entity_mentions: Value,
    request_seed: &str,
    prior_context_checkpoint: &str,
    previous_passages: &[(usize, usize)],
) -> Result<String> {
    let mut ranges = Vec::with_capacity(map.lines().len() + 1);
    let window_text = map
        .lines()
        .first()
        .and_then(|first| map.lines().last().map(|last| (first, last)))
        .map(|(first, last)| {
            cdb_core::evidence::Utf8Span::new(first.document_span.start(), last.document_span.end())
        })
        .transpose()?
        .ok_or_else(|| Error::invalid("empty v2 window"))?
        .select(document)?;
    ranges.push(json!({
        "range": map.window_range_id(),
        "kind": "window",
        "text": window_text
    }));
    for row in map.lines() {
        ranges.push(json!({
            "range": row.id.as_str(),
            "kind": "line",
            "line_number": row.line_number,
            "text": row.document_span.select(document)?
        }));
    }
    serde_json::to_string(&json!({
        "schema": "ctxql-acquisition-request/v2",
        "instruction": "Classify this untrusted passage, load read-loan-agreement-v2 when applicable, then return only the bound ctxql-extraction-text/v1 record format; do not return JSON.",
        "response_protocol": TEXT_PROPOSAL_PROTOCOL,
        "window_id": window_id,
        "passage_namespace": window_id,
        "locator": locator,
        "text_version": text_version,
        "ontology_capture": ontology_lookup.map(canonical_json).transpose()?,
        "ontology_briefing": ontology_briefing,
        "entity_gazetteer_capture": entity_capture,
        "request_seed": request_seed,
        "prior_context_checkpoint": prior_context_checkpoint,
        "document_context": crate::passage_context::document_context(document,
            map.lines().first().ok_or_else(|| Error::invalid("empty v2 window"))?.document_span.start(),
            map.lines().last().ok_or_else(|| Error::invalid("empty v2 window"))?.document_span.end(),
            previous_passages),
        "document_entity_handles": document_entity_handles,
        "known_entity_mentions": known_entity_mentions,
        "ranges": ranges,
        "tool_call_budget": 24
    }))
    .map_err(|_| Error::new(ErrorKind::Backend, "v2 prompt encoding failed"))
}

fn render_request(
    window_id: &str,
    locator: &str,
    text_version: &str,
    map: &CoordinateMap,
    document: &str,
) -> Result<String> {
    let mut lines = String::new();
    for row in map.lines() {
        let text = row.document_span.select(document)?;
        let encoded = serde_json::to_string(text)
            .map_err(|_| Error::new(ErrorKind::Backend, "prompt encoding failed"))?;
        lines.push_str(&format!(
            "line_id={} line_number={} text={}\n",
            row.id.as_str(),
            row.line_number,
            encoded
        ));
    }
    Ok(format!(
        "Classify and process exactly one untrusted document window according to the system routing protocol. Load the required allow-listed extraction skill before extracting any fact. Make no more than 24 total tool calls and reuse tool results.\nwindow_id={window_id}\nlocator={locator}\ntext_version={text_version}\n<untrusted_document>\nHost-issued lines follow; each text value is a JSON string whose decoded UTF-8 bytes define coordinate offsets. The encoding is transport framing only and is never model-authored candidate JSON.\n{lines}</untrusted_document>\nFollow the system FACT/EVIDENCE output grammar exactly. Your first output byte MUST be F in FACT: or N in NO_CLAIMS; never emit classification, reasoning, tool status, JSON, a preface, or trailing text."
    ))
}

fn descriptor(
    source: &PreparedSource,
    advisory: &AdvisoryBundle,
    window_id: &str,
    bundle: &AgentBundle,
    provider_catalog: &CertifiedOntologyCatalog,
    ontology_lookup: Option<&V>,
) -> Result<V> {
    let mut fields = vec![
        ("schema".into(), V::string("ctxql-extraction-descriptor/v1")),
        ("source_id".into(), V::string(source.source_id.as_str())),
        (
            "original_manifest".into(),
            V::string(source.original_manifest.as_str()),
        ),
        (
            "text_manifest".into(),
            source
                .text_manifest
                .as_ref()
                .map(|value| V::string(value.as_str()))
                .unwrap_or(V::Null),
        ),
        ("window_id".into(), V::string(window_id)),
        ("provider_bundle".into(), V::string(&bundle.hash)),
        (
            "provider_ontology_catalog".into(),
            provider_catalog.identity().projection(),
        ),
        (
            "candidate_topology_root".into(),
            V::string(advisory_root(advisory)?.as_str()),
        ),
    ];
    if let Some(provenance) = ontology_lookup {
        fields.push(("ontology_lookup".into(), provenance.clone()));
    }
    V::object(fields)
}

#[allow(clippy::too_many_arguments)]
fn fact_descriptor(
    source: &PreparedSource,
    advisory: &AdvisoryBundle,
    window_id: &str,
    provider_bundle_hash: &str,
    provider_catalog: &CertifiedOntologyCatalog,
    ontology_mode: OntologyMode,
    mapping_status: &str,
    fact: &FactProposal,
    ontology_lookup: Option<&V>,
) -> Result<V> {
    let mut fields = vec![
        ("schema".into(), V::string("ctxql-extraction-descriptor/v1")),
        ("source_id".into(), V::string(source.source_id.as_str())),
        (
            "original_manifest".into(),
            V::string(source.original_manifest.as_str()),
        ),
        (
            "text_manifest".into(),
            source
                .text_manifest
                .as_ref()
                .map(|value| V::string(value.as_str()))
                .unwrap_or(V::Null),
        ),
        ("window_id".into(), V::string(window_id)),
        ("provider_bundle".into(), V::string(provider_bundle_hash)),
        ("ontology_mode".into(), V::string(ontology_mode.as_str())),
        ("mapping_status".into(), V::string(mapping_status)),
        (
            "provider_ontology_catalog".into(),
            provider_catalog.identity().projection(),
        ),
        (
            "candidate_topology_root".into(),
            V::string(advisory_root(advisory)?.as_str()),
        ),
        (
            "raw_fact".into(),
            V::object([
                ("subject".into(), V::string(&fact.subject)),
                ("predicate".into(), V::string(&fact.predicate)),
                ("object".into(), V::string(&fact.object)),
                ("line_id".into(), V::string(&fact.line_id)),
            ])?,
        ),
    ];
    if let Some(provenance) = ontology_lookup {
        fields.push(("ontology_lookup".into(), provenance.clone()));
    }
    V::object(fields)
}

fn advisory_root(advisory: &AdvisoryBundle) -> Result<ContentHash> {
    let mut entities = advisory
        .entities
        .iter()
        .map(|entity| {
            Ok((
                entity.local_id().as_str(),
                V::object([
                    ("id".into(), V::string(entity.local_id().as_str())),
                    ("spelling".into(), V::string(entity.source_spelling())),
                    ("type".into(), V::string(entity.proposed_type().as_str())),
                ])?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    entities.sort_by_key(|(id, _)| *id);
    let mut claims = advisory
        .claims
        .iter()
        .map(|claim| {
            let object = match &claim.object {
                CandidateObject::Entity(id) => V::object([
                    ("kind".into(), V::string("entity")),
                    ("value".into(), V::string(id.as_str())),
                ])?,
                CandidateObject::Literal(value) => V::object([
                    ("kind".into(), V::string("literal")),
                    ("lexical".into(), V::string(value.lexical())),
                    ("datatype".into(), V::string(value.datatype().as_str())),
                    (
                        "language".into(),
                        value.language().map(V::string).unwrap_or(V::Null),
                    ),
                ])?,
            };
            let mut endpoint_types = claim
                .endpoint_type_claims
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<_>>();
            endpoint_types.sort_unstable();
            Ok((
                claim.local_claim_id.as_str(),
                V::object([
                    ("id".into(), V::string(claim.local_claim_id.as_str())),
                    ("subject".into(), V::string(claim.subject.as_str())),
                    ("predicate".into(), V::string(claim.predicate.as_str())),
                    ("object".into(), object),
                    (
                        "relation_type".into(),
                        V::string(claim.relation_type.as_str()),
                    ),
                    ("claim_type".into(), V::string(claim.claim_type.as_str())),
                    (
                        "endpoint_type_claims".into(),
                        V::Array(endpoint_types.into_iter().map(V::string).collect()),
                    ),
                    (
                        "confidence".into(),
                        claim
                            .confidence
                            .as_deref()
                            .map(V::string)
                            .unwrap_or(V::Null),
                    ),
                    (
                        "valid_time".into(),
                        claim
                            .valid_time
                            .as_deref()
                            .map(V::string)
                            .unwrap_or(V::Null),
                    ),
                ])?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    claims.sort_by_key(|(id, _)| *id);
    let mut metadata = advisory
        .metadata
        .iter()
        .map(|item| {
            let coordinates = item
                .coordinates
                .iter()
                .map(|coordinate| match &coordinate.selection {
                    LineSelection::WholeLine => V::object([
                        ("line_id".into(), V::string(coordinate.line_id.as_str())),
                        ("whole_line".into(), V::Bool(true)),
                    ]),
                    LineSelection::Range { start, end } => V::object([
                        ("line_id".into(), V::string(coordinate.line_id.as_str())),
                        (
                            "start".into(),
                            V::Number(ExactNumber::parse(&start.to_string())?),
                        ),
                        (
                            "end".into(),
                            V::Number(ExactNumber::parse(&end.to_string())?),
                        ),
                    ]),
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((
                item.local_claim_id.as_str(),
                V::object([
                    ("claim_id".into(), V::string(item.local_claim_id.as_str())),
                    ("locator".into(), V::string(item.locator.as_str())),
                    ("text_version".into(), V::string(item.text_version.as_str())),
                    ("coordinates".into(), V::Array(coordinates)),
                    (
                        "temporal_qualifier_claim".into(),
                        item.temporal_qualifier_claim
                            .as_ref()
                            .map(|id| V::string(id.as_str()))
                            .unwrap_or(V::Null),
                    ),
                ])?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    metadata.sort_by_key(|(id, _)| *id);
    let value = V::object([
        (
            "bundle".into(),
            V::string(advisory.local_bundle_id.as_str()),
        ),
        (
            "entities".into(),
            V::Array(entities.into_iter().map(|(_, value)| value).collect()),
        ),
        (
            "claims".into(),
            V::Array(claims.into_iter().map(|(_, value)| value).collect()),
        ),
        (
            "metadata".into(),
            V::Array(metadata.into_iter().map(|(_, value)| value).collect()),
        ),
    ])?;
    Ok(ContentHash::of_bytes(
        &value.canonical_bytes(Limits::default())?,
    ))
}

fn selector_root(
    source: &PreparedSource,
    window_id: &str,
    map: &CoordinateMap,
) -> Result<ContentHash> {
    let value = V::object([
        ("schema".into(), V::string("ctxql-source-selector-root/v1")),
        ("source_id".into(), V::string(source.source_id.as_str())),
        ("locator".into(), V::string(map.locator().as_str())),
        (
            "text_version".into(),
            V::string(map.text_version().as_str()),
        ),
        ("window_id".into(), V::string(window_id)),
    ])?;
    Ok(ContentHash::of_bytes(
        &value.canonical_bytes(Limits::default())?,
    ))
}

fn remember_entities(
    known: &mut BTreeMap<(String, Iri), Iri>,
    resolver: &CaptureEntityResolver,
    capture: &str,
    source: &PreparedSource,
    extraction_run: &ExtractionRunId,
    advisory: &AdvisoryBundle,
) -> Result<()> {
    for entity in &advisory.entities {
        if entity.proposed_type().as_str() == RDF_CLASS {
            continue;
        }
        let iri = resolver.resolve(
            capture,
            &source.extraction.text_version,
            extraction_run.as_str(),
            entity.local_id().as_str(),
            entity.source_spelling(),
            entity.proposed_type(),
        )?;
        known
            .entry((
                entity.source_spelling().to_owned(),
                entity.proposed_type().clone(),
            ))
            .or_insert(iri);
    }
    Ok(())
}

fn extraction_run(
    source: &PreparedSource,
    catalog: &CertifiedOntologyCatalog,
    bundle: Option<&AgentBundle>,
    recorded_assets: Option<&VerifiedRecordedAssets>,
    config: &AcquisitionConfig,
    ontology_mode: OntologyMode,
    entity_capture: Option<&ContentHash>,
) -> Result<(ExtractionRunId, Option<V>)> {
    let ontology_lookup = config
        .ontology_ledger_path
        .as_deref()
        .map(|path| {
            DirectFlureeOntologyToolHost::from_bootstrap(path)
                .and_then(|host| host.provenance())
                .map_err(|_| Error::invalid("ontology ledger bootstrap"))
        })
        .transpose()?;
    let mut fields = vec![
        ("schema".into(), V::string("ctxql-extraction-run/v2")),
        ("source_id".into(), V::string(source.source_id.as_str())),
        (
            "locator".into(),
            V::string(source.extraction.locator.as_str()),
        ),
        (
            "text_version".into(),
            V::string(source.extraction.text_version.as_str()),
        ),
        (
            "catalog_root".into(),
            V::string(catalog.identity().catalog_root().as_str()),
        ),
        (
            "provider_bundle".into(),
            V::string(asset_hash(bundle, recorded_assets)?),
        ),
        (
            "ontology_mode".into(),
            V::string(if config.protocol == AcquisitionProtocol::OntologyV2 {
                // V2 model inputs are mode-independent. Keep the historical
                // field shape while assigning one capture identity; hard/soft
                // are committed separately by evaluation/admission.
                OntologyMode::Hard.as_str()
            } else {
                ontology_mode.as_str()
            }),
        ),
        (
            "model".into(),
            V::string(
                recorded_assets.map_or(cdb_provider_pi::MODEL, |assets| assets.model.as_str()),
            ),
        ),
        (
            "thinking".into(),
            V::string(
                recorded_assets
                    .map_or(cdb_provider_pi::THINKING, |assets| assets.thinking.as_str()),
            ),
        ),
    ];
    if let Some(provenance) = &ontology_lookup {
        fields.push(("ontology_lookup".into(), provenance.clone()));
    }
    if let Some(capture) = entity_capture {
        fields.push(("entity_gazetteer".into(), V::string(capture.as_str())));
    }
    let value = V::object(fields)?;
    let root = ContentHash::of_bytes(&value.canonical_bytes(Limits::default())?);
    Ok((
        ExtractionRunId::new(format!("extraction:{}", &root.as_str()[7..]))?,
        ontology_lookup,
    ))
}

fn window_config(config: &AcquisitionConfig) -> Result<WindowConfig> {
    let mode = match config.window.mode.as_str() {
        "off" => WindowMode::Off,
        "auto" => WindowMode::Auto,
        "always" => WindowMode::Always,
        _ => return Err(Error::invalid("window mode")),
    };
    let mut value = WindowConfig::default();
    value.mode = mode;
    value.target_bytes = config.window.target_bytes;
    value.max_bytes = config.window.max_bytes;
    value.overlap_bytes = config.window.overlap_bytes;
    value.small_block_bytes = value.target_bytes.min(256);
    value.whole_document_threshold = value.target_bytes.min(value.max_bytes);
    value.hard_document_bytes = config.max_document_bytes;
    value.max_total_provider_bytes = config.max_source_bytes;
    value.validate()?;
    Ok(value)
}

fn document_report(
    source: &PreparedSource,
    window_count: usize,
    ontology_mode: OntologyMode,
    detail_byte_limit: usize,
) -> DocumentReport {
    DocumentReport {
        locator: source.extraction.locator.as_str().to_owned(),
        job_id: None,
        ontology_mode: ontology_mode.as_str(),
        mapping_status: "no_candidates",
        original_object: Some(source.extraction.original_object.as_str().to_owned()),
        original_manifest: Some(source.original_manifest.as_str().to_owned()),
        text_version: Some(source.extraction.text_version.as_str().to_owned()),
        text_manifest: source
            .text_manifest
            .as_ref()
            .map(|manifest| manifest.as_str().to_owned()),
        agent_bundle_hash: None,
        ontology_lookup: None,
        window_count,
        issued_ranges: BTreeMap::new(),
        admitted_bundle_count: 0,
        admitted_claim_count: 0,
        candidate_count: 0,
        mapped_candidate_count: 0,
        provisional_candidate_count: 0,
        unmapped_candidate_count: 0,
        rejected_candidate_count: 0,
        no_claim_window_count: 0,
        provider_responses: Vec::new(),
        artifacts: Vec::new(),
        artifact_descriptors: Vec::new(),
        validations: Vec::new(),
        review_record_count: 0,
        review_receipts: Vec::new(),
        validated_bundle_count: 0,
        validated_claim_count: 0,
        admissions: Vec::new(),
        admitted_claims: Vec::new(),
        errors: Vec::new(),
        details_truncated: false,
        omitted_admission_count: 0,
        omitted_claim_count: 0,
        omitted_error_count: 0,
        detail_bytes_remaining: detail_byte_limit,
    }
}

fn failed_document(
    locator: String,
    ontology_mode: OntologyMode,
    stage: &'static str,
    code: &'static str,
    detail_byte_limit: usize,
) -> DocumentReport {
    DocumentReport {
        locator,
        job_id: None,
        ontology_mode: ontology_mode.as_str(),
        mapping_status: "no_candidates",
        original_object: None,
        original_manifest: None,
        text_version: None,
        text_manifest: None,
        agent_bundle_hash: None,
        ontology_lookup: None,
        window_count: 0,
        issued_ranges: BTreeMap::new(),
        admitted_bundle_count: 0,
        admitted_claim_count: 0,
        candidate_count: 0,
        mapped_candidate_count: 0,
        provisional_candidate_count: 0,
        unmapped_candidate_count: 0,
        rejected_candidate_count: 0,
        no_claim_window_count: 0,
        provider_responses: Vec::new(),
        artifacts: Vec::new(),
        artifact_descriptors: Vec::new(),
        validations: Vec::new(),
        review_record_count: 0,
        review_receipts: Vec::new(),
        validated_bundle_count: 0,
        validated_claim_count: 0,
        admissions: Vec::new(),
        admitted_claims: Vec::new(),
        errors: vec![StageError {
            stage,
            code,
            window_id: None,
        }],
        details_truncated: false,
        omitted_admission_count: 0,
        omitted_claim_count: 0,
        omitted_error_count: 0,
        detail_bytes_remaining: detail_byte_limit,
    }
}

fn retain_document_report(
    reports: &mut Vec<DocumentReport>,
    bytes_remaining: &mut usize,
    omitted: &mut usize,
    report: DocumentReport,
    preserve_exact: bool,
) -> Result<()> {
    let bytes = serde_json::to_vec(&report)
        .map_err(|error| Error::new(ErrorKind::Backend, error.to_string()))?;
    let cost = bytes.len().saturating_add(1);
    if cost <= *bytes_remaining {
        *bytes_remaining -= cost;
        reports.push(report);
    } else if preserve_exact {
        return Err(Error::limit());
    } else if !report.artifacts.is_empty()
        || !report.review_receipts.is_empty()
        || !report.admissions.is_empty()
    {
        let compact = compact_document_for_retention(report);
        let bytes = serde_json::to_vec(&compact)
            .map_err(|error| Error::new(ErrorKind::Backend, error.to_string()))?;
        let cost = bytes.len().saturating_add(1);
        if cost > *bytes_remaining {
            return Err(Error::limit());
        }
        *bytes_remaining -= cost;
        reports.push(compact);
    } else {
        *omitted = omitted.saturating_add(1);
    }
    Ok(())
}

fn compact_document_for_retention(mut report: DocumentReport) -> DocumentReport {
    report.issued_ranges.clear();
    report.provider_responses.clear();
    report.validations.clear();
    report.omitted_claim_count = report
        .omitted_claim_count
        .saturating_add(report.admitted_claims.len());
    report.admitted_claims.clear();
    report.omitted_error_count = report
        .omitted_error_count
        .saturating_add(report.errors.len());
    report.errors.clear();
    report.details_truncated = true;
    report.detail_bytes_remaining = 0;
    report
}

fn fit_report(report: &mut IngestReport, limit: usize) -> Result<()> {
    loop {
        let bytes = serde_json::to_vec_pretty(report)
            .map_err(|error| Error::new(ErrorKind::Backend, error.to_string()))?;
        if bytes.len() <= limit {
            return Ok(());
        }
        if report.mode == "extract_only" {
            return Err(Error::limit());
        }
        let Some(last) = report.documents.last_mut() else {
            return Err(Error::limit());
        };
        if !last.details_truncated
            && (!last.artifacts.is_empty()
                || !last.review_receipts.is_empty()
                || !last.admissions.is_empty())
        {
            let compact = compact_document_for_retention(last.clone());
            *last = compact;
            report.details_truncated = true;
        } else if last.artifacts.is_empty()
            && last.review_receipts.is_empty()
            && last.admissions.is_empty()
        {
            report.documents.pop();
            report.omitted_document_count = report.omitted_document_count.saturating_add(1);
            report.details_truncated = true;
        } else {
            return Err(Error::limit());
        }
    }
}

fn locator_display(locator: &SourceLocator) -> String {
    match locator {
        SourceLocator::Https(value) => value.clone(),
        SourceLocator::Local(path) => path.to_string_lossy().into_owned(),
    }
}

fn locator_iri(locator: &SourceLocator) -> Result<Iri> {
    match locator {
        SourceLocator::Https(value) => Iri::http(value),
        SourceLocator::Local(path) => {
            let value = reqwest::Url::from_file_path(path)
                .map_err(|_| Error::invalid("local source locator"))?;
            Iri::new(value.as_str())
        }
    }
}

fn media_type(kind: MediaKind) -> &'static str {
    match kind {
        MediaKind::Text => "text/plain",
        MediaKind::Markdown => "text/markdown",
        MediaKind::Pdf => "application/pdf",
    }
}

fn run_pdf_converter(
    converter: &AcquisitionConverterConfig,
    input: &[u8],
    timeout: Duration,
    output_limit: usize,
    cancel: &CancellationToken,
) -> Result<String> {
    let metadata = fs::symlink_metadata(&converter.command)
        .map_err(|_| Error::new(ErrorKind::Backend, "PDF converter unavailable"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 * 1024
    {
        return Err(Error::invalid("unsafe PDF converter"));
    }
    let executable = fs::read(&converter.command)
        .map_err(|_| Error::new(ErrorKind::Backend, "PDF converter unavailable"))?;
    if ContentHash::of_bytes(&executable) != ContentHash::parse(&converter.executable_hash)? {
        return Err(Error::new(
            ErrorKind::Conflict,
            "PDF converter hash mismatch",
        ));
    }
    let mut child = Command::new(&converter.command)
        .args(&converter.arguments)
        .args(["-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::new(ErrorKind::Backend, "PDF converter failed"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::new(ErrorKind::Backend, "PDF converter failed"))?;
    let input = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::new(ErrorKind::Backend, "PDF converter failed"))?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .by_ref()
            .take(output_limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if cancel.is_cancelled() || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::new(ErrorKind::Deadline, "PDF conversion cancelled"));
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|_| Error::new(ErrorKind::Backend, "PDF converter failed"))?
        {
            break status;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    writer
        .join()
        .map_err(|_| Error::new(ErrorKind::Backend, "PDF converter failed"))?
        .map_err(|_| Error::new(ErrorKind::Backend, "PDF converter failed"))?;
    let bytes = reader
        .join()
        .map_err(|_| Error::new(ErrorKind::Backend, "PDF converter failed"))?
        .map_err(|_| Error::new(ErrorKind::Backend, "PDF converter failed"))?;
    if !status.success() || bytes.is_empty() || bytes.len() > output_limit {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "PDF has no bounded text output",
        ));
    }
    String::from_utf8(bytes).map_err(|_| Error::invalid("PDF converter output is not UTF-8"))
}

fn validation_error_code(error: &Error) -> &'static str {
    let message = error.message.as_str();
    if message.contains("ontology") || message.contains("relation and claim type") {
        "ontology_term_rejected"
    } else if message.contains("endpoint") || message.contains("type assertion") {
        "endpoint_type_grounding_rejected"
    } else if message.contains("metadata") || message.contains("coordinate") {
        "source_evidence_rejected"
    } else if message.contains("literal") || message.contains("dateTime") {
        "literal_value_rejected"
    } else if message.contains("disconnected") || message.contains("bundle") {
        "bundle_topology_rejected"
    } else {
        "candidate_rejected"
    }
}

fn provider_response_report(response: CapturedResponse) -> ProviderResponseReport {
    let text_sha256 = response
        .text
        .as_ref()
        .map(|text| ContentHash::of_bytes(text.as_bytes()).as_str().to_owned());
    ProviderResponseReport {
        phase: response.phase,
        window_ids: response.window_ids,
        text: response.text,
        text_sha256,
        parse_error: response.parse_error.as_ref().map(parse_error_code),
        transport_error: response.transport_error.as_ref().map(transport_error_code),
    }
}

fn provider_error_code(error: &ProviderError) -> &'static str {
    match error {
        ProviderError::Transport(error) => transport_error_code(error),
        ProviderError::Grammar(error) => parse_error_code(error),
    }
}

fn saved_transport_error(code: &str) -> Result<TransportError> {
    match code {
        "provider_timeout" => Ok(TransportError::Timeout),
        "provider_cancelled" => Ok(TransportError::Cancelled),
        "provider_tool_call_limit" => Ok(TransportError::Limit("tool_calls")),
        "provider_limit" => Ok(TransportError::Limit("captured_limit")),
        "provider_transport_failed" => Ok(TransportError::Rpc),
        _ => Err(Error::invalid("captured transport failure code")),
    }
}

fn transport_error_code(error: &TransportError) -> &'static str {
    match error {
        TransportError::Timeout => "provider_timeout",
        TransportError::Cancelled => "provider_cancelled",
        TransportError::Limit("tool_calls") => "provider_tool_call_limit",
        TransportError::Limit(_) => "provider_limit",
        _ => "provider_transport_failed",
    }
}

fn parse_error_code(error: &ParseError) -> &'static str {
    match error {
        ParseError::Limit(_) => "provider_grammar_limit",
        ParseError::Grammar(reason) => match *reason {
            "fences_or_cr" => "provider_fenced_output",
            "sentinel_must_be_exact" => "provider_inexact_no_claims",
            "forbidden_section" => "provider_forbidden_section",
            "empty" => "provider_empty_output",
            "expected_claim_header" => "provider_claim_header_missing",
            "truncated_claim" => "provider_truncated_claim",
            "claim_must_be_one_json_object" => "provider_multiline_claim_json",
            "expected_metadata_header" => "provider_metadata_header_missing",
            "truncated_metadata" => "provider_truncated_metadata",
            "metadata_must_be_one_json_object" => "provider_multiline_metadata_json",
            "missing_terminator" => "provider_terminator_missing",
            _ => "provider_grammar_shape",
        },
        ParseError::Json(_) => "provider_json_rejected",
        ParseError::UnknownWindow => "provider_unknown_window",
        ParseError::DuplicateClaimId => "provider_duplicate_claim_id",
        ParseError::DuplicateMetadata => "provider_duplicate_metadata",
        ParseError::DuplicateCoordinate => "provider_duplicate_coordinate",
        ParseError::MissingMetadata => "provider_missing_metadata",
        ParseError::Mismatch => "provider_metadata_mismatch",
        ParseError::UnresolvedReference => "provider_unresolved_reference",
        ParseError::CrossWindowAmbiguity => "provider_cross_window_ambiguity",
        ParseError::InvalidScalar(_) => "provider_invalid_scalar",
    }
}

fn canonical_json(value: &V) -> Result<Value> {
    serde_json::from_slice(&value.canonical_bytes(Limits::default())?)
        .map_err(|_| Error::new(ErrorKind::Backend, "canonical output encoding failed"))
}

fn verified_recorded_assets(manifest: &CaptureManifest) -> Result<VerifiedRecordedAssets> {
    let (asset_manifest, assets, hash) = match manifest {
        CaptureManifest::Graph(value) => (
            &value.provider.asset_manifest,
            &value.provider.assets,
            value.provider.agent_bundle_hash.as_str(),
        ),
        CaptureManifest::Single(value) => (
            &value.asset_manifest,
            &value.assets,
            value.agent_bundle_hash.as_str(),
        ),
        CaptureManifest::Multi(value) => (
            &value.asset_manifest,
            &value.assets,
            value.agent_bundle_hash.as_str(),
        ),
    };
    verify_recorded_assets(asset_manifest, assets, hash)
        .map_err(|_| Error::new(ErrorKind::Conflict, "recorded asset context differs"))
}

fn asset_hash<'a>(
    bundle: Option<&'a AgentBundle>,
    recorded: Option<&'a VerifiedRecordedAssets>,
) -> Result<&'a str> {
    recorded
        .map(|assets| assets.hash.as_str())
        .or_else(|| bundle.map(|bundle| bundle.hash.as_str()))
        .ok_or_else(|| Error::invalid("provider asset context unavailable"))
}

fn asset_model<'a>(
    bundle: Option<&'a AgentBundle>,
    recorded: Option<&'a VerifiedRecordedAssets>,
) -> Result<&'a str> {
    recorded
        .map(|assets| assets.model.as_str())
        .or_else(|| bundle.map(|bundle| bundle.manifest.model))
        .ok_or_else(|| Error::invalid("provider asset context unavailable"))
}

fn asset_thinking<'a>(
    bundle: Option<&'a AgentBundle>,
    recorded: Option<&'a VerifiedRecordedAssets>,
) -> Result<&'a str> {
    recorded
        .map(|assets| assets.thinking.as_str())
        .or_else(|| bundle.map(|bundle| bundle.manifest.thinking))
        .ok_or_else(|| Error::invalid("provider asset context unavailable"))
}

fn extraction_system_prompt_bytes(
    bundle: Option<&AgentBundle>,
    recorded: Option<&VerifiedRecordedAssets>,
) -> Result<usize> {
    if let Some(recorded) = recorded {
        let provider = recorded
            .assets
            .get("prompts/provider-system-v2.md")
            .ok_or_else(|| Error::invalid("recorded system prompt unavailable"))?;
        let acquisition = recorded
            .assets
            .get("prompts/ctxql-acquisition-v2.md")
            .ok_or_else(|| Error::invalid("recorded acquisition prompt unavailable"))?;
        return Ok(provider.trim_end().len() + 2 + acquisition.trim_end().len());
    }
    bundle
        .ok_or_else(|| Error::invalid("live provider bundle unavailable"))?
        .system_prompt_v2()
        .map(|prompt| prompt.len())
        .map_err(|_| Error::invalid("system prompt unavailable"))
}

fn capture_assets(
    bundle: Option<&AgentBundle>,
    recorded: Option<&VerifiedRecordedAssets>,
) -> Result<(Value, BTreeMap<String, String>)> {
    if let Some(recorded) = recorded {
        let manifest = if recorded.is_legacy_v1() {
            json!({
                "schema": recorded.schema,
                "model": recorded.model,
                "thinking": recorded.thinking,
                "files": recorded.files,
            })
        } else {
            json!({
                "schema": recorded.schema,
                "profile": recorded.profile,
                "model": recorded.model,
                "thinking": recorded.thinking,
                "files": recorded.files,
            })
        };
        return Ok((manifest, recorded.assets.clone()));
    }
    capture_bundle_assets(bundle.ok_or_else(|| Error::invalid("live provider bundle unavailable"))?)
}

fn capture_bundle_assets(bundle: &AgentBundle) -> Result<(Value, BTreeMap<String, String>)> {
    let manifest = serde_json::to_value(&bundle.manifest)
        .map_err(|_| Error::invalid("asset manifest encoding"))?;
    let assets = bundle
        .manifest
        .files
        .iter()
        .map(|file| {
            let bytes = fs::read(bundle.root.join(&file.path))
                .map_err(|_| Error::invalid("staged asset unavailable"))?;
            if ContentHash::of_bytes(&bytes).as_str() != file.sha256 {
                return Err(Error::invalid("staged asset changed"));
            }
            Ok((
                file.path.clone(),
                String::from_utf8(bytes).map_err(|_| Error::invalid("staged asset encoding"))?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok((manifest, assets))
}

fn captured_source_representation(source: &PreparedSource) -> Result<CapturedSourceRepresentation> {
    let converter =
        source
            .extraction
            .converter
            .as_ref()
            .map(|value| CapturedConverterDeclaration {
                executable_hash: value.executable_hash.as_str().to_owned(),
                version_probe: value.version_probe.clone(),
                arguments: value.arguments.clone(),
                timeout_millis: value.timeout_millis,
                output_byte_limit: value.output_byte_limit,
                encoding: value.encoding.clone(),
                normalization: value.normalization.clone(),
            });
    if source.extraction.media_type == SourceMediaType::Pdf
        && (source.text_manifest.is_none()
            || source.converter_manifest.is_none()
            || converter.is_none())
    {
        return Err(Error::invalid("PDF source representation is incomplete"));
    }
    Ok(CapturedSourceRepresentation {
        media_type: match source.extraction.media_type {
            SourceMediaType::PlainText => "text/plain",
            SourceMediaType::Markdown => "text/markdown",
            SourceMediaType::Pdf => "application/pdf",
        }
        .to_owned(),
        original_object: source.extraction.original_object.as_str().to_owned(),
        original_manifest: source.original_manifest.as_str().to_owned(),
        text_object: source.text_manifest.as_ref().map(|_| {
            ContentHash::of_bytes(source.extraction.text().as_bytes())
                .as_str()
                .to_owned()
        }),
        text_manifest: source
            .text_manifest
            .as_ref()
            .map(|value| value.as_str().to_owned()),
        converter_manifest: source
            .converter_manifest
            .as_ref()
            .map(|value| value.as_str().to_owned()),
        converter,
    })
}

#[allow(clippy::too_many_arguments)]
fn make_single_capture_manifest(
    source: &PreparedSource,
    bundle: &AgentBundle,
    ontology_lookup: Option<&V>,
    window: &Window,
    window_id: &str,
    seed: &str,
    request: &str,
    response: &str,
    issued_ranges: Vec<String>,
) -> Result<ProviderCaptureManifest> {
    let (asset_manifest, assets) = capture_bundle_assets(bundle)?;
    Ok(ProviderCaptureManifest {
        schema: CAPTURE_MANIFEST_SCHEMA.to_owned(),
        source_id: source.source_id.as_str().to_owned(),
        locator: source.extraction.locator.as_str().to_owned(),
        text_version: source.extraction.text_version.as_str().to_owned(),
        window_id: window_id.to_owned(),
        request_root: ContentHash::of_bytes(request.as_bytes())
            .as_str()
            .to_owned(),
        request: request.to_owned(),
        source_text: source.extraction.text().to_owned(),
        coordinate_seed: seed.to_owned(),
        window_start: window.span.start(),
        window_end: window.span.end(),
        asset_manifest,
        assets,
        response_root: ContentHash::of_bytes(response.as_bytes())
            .as_str()
            .to_owned(),
        response: response.to_owned(),
        model: bundle.manifest.model.to_owned(),
        thinking: bundle.manifest.thinking.to_owned(),
        agent_bundle_hash: bundle.hash.as_str().to_owned(),
        ontology_lookup: ontology_lookup.map(canonical_json).transpose()?,
        issued_ranges,
        source_representation: Some(captured_source_representation(source)?),
    })
}

fn passage_capture_root(passage: &PassageCaptureManifest) -> Result<String> {
    let mut committed = passage.clone();
    committed.leaf_root.clear();
    let bytes =
        serde_json::to_vec(&committed).map_err(|_| Error::invalid("capture passage encoding"))?;
    Ok(ContentHash::of_bytes(&bytes).as_str().to_owned())
}

fn multi_capture_root(manifest: &MultiPassageCaptureManifest) -> Result<String> {
    let mut committed = manifest.clone();
    committed.capture_root.clear();
    let bytes =
        serde_json::to_vec(&committed).map_err(|_| Error::invalid("capture manifest encoding"))?;
    Ok(ContentHash::of_bytes(&bytes).as_str().to_owned())
}

fn capture_export_manifest(
    source: &PreparedSource,
    bundle: Option<&AgentBundle>,
    recorded_assets: Option<&VerifiedRecordedAssets>,
    ontology_lookup: Option<&V>,
    streaming: &StreamingV2Capture,
) -> Result<CaptureManifest> {
    if streaming.passage_manifests.len() != streaming.outcomes.len() {
        return Err(Error::invalid(
            "successful provider response required for every captured passage",
        ));
    }
    if streaming.passage_manifests.len() == 1 {
        let passage = &streaming.passage_manifests[0];
        let (asset_manifest, assets) = capture_assets(bundle, recorded_assets)?;
        let provider = ProviderCaptureManifest {
            schema: CAPTURE_MANIFEST_SCHEMA.to_owned(),
            source_id: source.source_id.as_str().to_owned(),
            locator: source.extraction.locator.as_str().to_owned(),
            text_version: source.extraction.text_version.as_str().to_owned(),
            window_id: passage.window_id.clone(),
            request_root: passage.request_root.clone(),
            request: passage.request.clone(),
            source_text: source.extraction.text().to_owned(),
            coordinate_seed: passage.request_seed.clone(),
            window_start: passage.window_start,
            window_end: passage.window_end,
            asset_manifest,
            assets,
            response_root: passage.response_root.clone(),
            response: passage.response.clone(),
            model: asset_model(bundle, recorded_assets)?.to_owned(),
            thinking: asset_thinking(bundle, recorded_assets)?.to_owned(),
            agent_bundle_hash: asset_hash(bundle, recorded_assets)?.to_owned(),
            ontology_lookup: ontology_lookup.map(canonical_json).transpose()?,
            issued_ranges: passage.issued_ranges.clone(),
            source_representation: Some(captured_source_representation(source)?),
        };
        return match &streaming.graph_export {
            Some(graph) => Ok(CaptureManifest::Graph(Box::new(
                GraphProviderCaptureManifest {
                    schema: if graph.schema == "ctxql-provider-graph-capture/v3" {
                        "ctxql-provider-graph-capture-manifest/v2"
                    } else {
                        "ctxql-provider-graph-capture-manifest/v1"
                    }
                    .into(),
                    provider,
                    graph: graph.clone(),
                },
            ))),
            None => Ok(CaptureManifest::Single(provider)),
        };
    }
    if streaming.graph_export.is_some() {
        return Err(Error::invalid(
            "graph capture requires one complete document passage",
        ));
    }
    let (asset_manifest, assets) = capture_assets(bundle, recorded_assets)?;
    let mut manifest = MultiPassageCaptureManifest {
        schema: MULTI_CAPTURE_MANIFEST_SCHEMA.to_owned(),
        source_id: source.source_id.as_str().to_owned(),
        locator: source.extraction.locator.as_str().to_owned(),
        text_version: source.extraction.text_version.as_str().to_owned(),
        source_text: source.extraction.text().to_owned(),
        document_seed: streaming.document_seed.clone(),
        asset_manifest,
        assets,
        model: asset_model(bundle, recorded_assets)?.to_owned(),
        thinking: asset_thinking(bundle, recorded_assets)?.to_owned(),
        agent_bundle_hash: asset_hash(bundle, recorded_assets)?.to_owned(),
        ontology_lookup: ontology_lookup.map(canonical_json).transpose()?,
        passage_count: streaming.passage_manifests.len(),
        leaves: streaming.passage_manifests.clone(),
        entity_checkpoint: String::from_utf8(streaming.table.checkpoint_bytes()?)
            .map_err(|_| Error::invalid("document entity checkpoint encoding"))?,
        capture_root: String::new(),
        source_representation: Some(captured_source_representation(source)?),
    };
    manifest.capture_root = multi_capture_root(&manifest)?;
    Ok(CaptureManifest::Multi(manifest))
}

fn write_capture_manifest(path: &str, manifest: &CaptureManifest) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|_| Error::new(ErrorKind::Backend, "capture manifest encoding failed"))?;
    if bytes.len() > MAX_CAPTURE_MANIFEST_BYTES {
        return Err(Error::limit());
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| Error::invalid("capture manifest path is unavailable"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| Error::new(ErrorKind::Backend, "capture manifest write failed"))
}

fn verify_multi_capture_context(
    manifest: &MultiPassageCaptureManifest,
    source: &PreparedSource,
    recorded: &VerifiedRecordedAssets,
    ontology_lookup: Option<&V>,
    document_seed: &str,
    windows: &[Window],
) -> Result<()> {
    if manifest.leaves.len() < windows.len() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "capture manifest missing passage ordinals [{}]",
                (manifest.leaves.len()..windows.len())
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ));
    }
    if manifest.leaves.len() > windows.len() {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "capture manifest has unexpected passage ordinal {}",
                windows.len()
            ),
        ));
    }
    let common_matches = manifest.source_id == source.source_id.as_str()
        && manifest.locator == source.extraction.locator.as_str()
        && manifest.text_version == source.extraction.text_version.as_str()
        && manifest.source_text == source.extraction.text()
        && manifest.document_seed == document_seed
        && manifest.model == recorded.model
        && manifest.thinking == recorded.thinking
        && manifest.agent_bundle_hash == recorded.hash
        && manifest.ontology_lookup == ontology_lookup.map(canonical_json).transpose()?;
    if !common_matches {
        return Err(Error::new(
            ErrorKind::Conflict,
            "capture manifest does not match the current document/model context",
        ));
    }
    for (ordinal, (leaf, window)) in manifest.leaves.iter().zip(windows).enumerate() {
        if leaf.ordinal != ordinal || leaf.window_id != window_id_for(source, window) {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!("capture manifest passage order mismatch at ordinal {ordinal}"),
            ));
        }
    }
    Ok(())
}

/// Checks the bounded external capture envelope and all content commitments
/// without opening stores or invoking a provider. Replay additionally compares
/// every request seed, request, coordinate set, and entity-table checkpoint to
/// the current host-rendered extraction context.
pub fn verify_capture_manifest_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_CAPTURE_MANIFEST_BYTES {
        return Err(Error::limit());
    }
    let manifest: CaptureManifest =
        serde_json::from_slice(bytes).map_err(|_| Error::invalid("capture manifest is invalid"))?;
    verify_capture_manifest_integrity(&manifest)
}

fn replay_source_representation(
    source_root: &std::path::Path,
    max_source_bytes: usize,
    source_id: &str,
    locator: &str,
    text_version: &str,
    source_text: &str,
    captured: Option<&CapturedSourceRepresentation>,
) -> Result<PreparedSource> {
    let Some(captured) = captured else {
        if locator.to_ascii_lowercase().ends_with(".pdf") {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "stored PDF replay requires a captured converter representation",
            ));
        }
        // Historical manifests did not carry source-store chain metadata. They
        // remain decodable, but only their exact UTF-8 text commitment can be
        // replayed; no converted representation is inferred.
        let media = if locator.to_ascii_lowercase().ends_with(".md") {
            SourceMediaType::Markdown
        } else {
            SourceMediaType::PlainText
        };
        let extraction =
            ExtractionText::exact_text(Iri::new(locator)?, media, source_text.as_bytes().to_vec())?;
        if extraction.text_version.as_str() != text_version {
            return Err(Error::new(
                ErrorKind::Conflict,
                "captured source representation differs",
            ));
        }
        return Ok(PreparedSource {
            extraction,
            source_id: SourceId::new(source_id)?,
            original_manifest: ContentHash::parse(text_version)?,
            text_manifest: None,
            converter_manifest: None,
        });
    };

    let reader = SourceObjectReader::open(source_root.to_path_buf(), max_source_bytes)?;
    let original_manifest_root = ContentHash::parse(&captured.original_manifest)?;
    let original_manifest = reader.read_original_manifest(&original_manifest_root)?;
    let original_object = ContentHash::parse(&captured.original_object)?;
    if original_manifest.object() != &original_object
        || original_manifest.media_type() != captured.media_type
    {
        return Err(Error::new(
            ErrorKind::Conflict,
            "captured original representation chain differs",
        ));
    }
    let original = reader.read_object(&original_object)?;
    let locator = Iri::new(locator)?;
    let (extraction, text_manifest, converter_manifest) =
        match captured.media_type.as_str() {
            "text/plain" | "text/markdown" => {
                if captured.text_object.is_some()
                    || captured.text_manifest.is_some()
                    || captured.converter_manifest.is_some()
                    || captured.converter.is_some()
                    || original.as_slice() != source_text.as_bytes()
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "captured exact-text representation chain differs",
                    ));
                }
                let media = if captured.media_type == "text/markdown" {
                    SourceMediaType::Markdown
                } else {
                    SourceMediaType::PlainText
                };
                (
                    ExtractionText::exact_text(locator, media, original)?,
                    None,
                    None,
                )
            }
            "application/pdf" => {
                let text_manifest_root = ContentHash::parse(
                    captured
                        .text_manifest
                        .as_deref()
                        .ok_or_else(|| Error::invalid("captured PDF text manifest missing"))?,
                )?;
                let converter_manifest_root =
                    ContentHash::parse(captured.converter_manifest.as_deref().ok_or_else(
                        || Error::invalid("captured PDF converter manifest missing"),
                    )?)?;
                let text_object = ContentHash::parse(
                    captured
                        .text_object
                        .as_deref()
                        .ok_or_else(|| Error::invalid("captured PDF text object missing"))?,
                )?;
                let text_manifest_value = reader.read_text_manifest(&text_manifest_root)?;
                if text_manifest_value.original_manifest() != &original_manifest_root
                    || text_manifest_value.converter_manifest() != &converter_manifest_root
                    || text_manifest_value.object() != &text_object
                    || text_manifest_value.version().as_str() != text_version
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "captured PDF representation chain differs",
                    ));
                }
                let text = reader.read_text(&text_manifest_value)?;
                if text != source_text {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "captured PDF text bytes differ",
                    ));
                }
                let declaration = captured
                    .converter
                    .as_ref()
                    .ok_or_else(|| Error::invalid("captured PDF converter declaration missing"))?;
                let converter = ConverterDeclaration {
                    executable_hash: ContentHash::parse(&declaration.executable_hash)?,
                    version_probe: declaration.version_probe.clone(),
                    arguments: declaration.arguments.clone(),
                    timeout_millis: declaration.timeout_millis,
                    output_byte_limit: declaration.output_byte_limit,
                    encoding: declaration.encoding.clone(),
                    normalization: declaration.normalization.clone(),
                };
                converter.validate(128, 4096)?;
                if converter.encoding != "UTF-8" || converter.normalization != "none" {
                    return Err(Error::invalid(
                        "captured PDF converter declaration unsupported",
                    ));
                }
                let converter_value = ConverterManifest::new(
                    converter.executable_hash.clone(),
                    &converter.version_probe,
                    converter.arguments.clone(),
                    converter.timeout_millis,
                    converter.output_byte_limit as u64,
                    Normalization::None,
                )?;
                if converter_value.id()? != converter_manifest_root
                    || reader.read_converter_manifest(&converter_manifest_root)? != converter_value
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        "captured PDF converter chain differs",
                    ));
                }
                (
                    ExtractionText::converted_pdf_text_with_version(
                        locator,
                        &original,
                        text,
                        ContentHash::parse(text_version)?,
                        converter,
                    )?,
                    Some(text_manifest_root),
                    Some(converter_manifest_root),
                )
            }
            _ => return Err(Error::invalid("captured source media type unsupported")),
        };
    if extraction.original_object != original_object
        || extraction.text_version.as_str() != text_version
    {
        return Err(Error::new(
            ErrorKind::Conflict,
            "captured source representation differs",
        ));
    }
    Ok(PreparedSource {
        extraction,
        source_id: SourceId::new(source_id)?,
        original_manifest: original_manifest_root,
        text_manifest,
        converter_manifest,
    })
}

/// Re-evaluate an authenticated stored capture without invoking the provider.
/// The caller must authenticate the immutable work/capture binding and all
/// inherited source/context scopes before calling this function.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn replay_capture_manifest(
    config: &InstanceConfig,
    acquisition: &AcquisitionConfig,
    service: &Arc<AcquisitionService>,
    manifest_bytes: &[u8],
    ontology_mode: OntologyMode,
    wait: IngestWait,
    ephemeral: bool,
    replay_authority: Option<Arc<GraphQueryHost>>,
) -> Result<Value> {
    verify_capture_manifest_bytes(manifest_bytes)?;
    let manifest: CaptureManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|_| Error::invalid("capture manifest is invalid"))?;
    let (source_id, locator, text_version, source_text, representation) = match &manifest {
        CaptureManifest::Graph(value) => (
            value.provider.source_id.as_str(),
            value.provider.locator.as_str(),
            value.provider.text_version.as_str(),
            value.provider.source_text.as_str(),
            value.provider.source_representation.as_ref(),
        ),
        CaptureManifest::Single(value) => (
            value.source_id.as_str(),
            value.locator.as_str(),
            value.text_version.as_str(),
            value.source_text.as_str(),
            value.source_representation.as_ref(),
        ),
        CaptureManifest::Multi(value) => (
            value.source_id.as_str(),
            value.locator.as_str(),
            value.text_version.as_str(),
            value.source_text.as_str(),
            value.source_representation.as_ref(),
        ),
    };
    let source = replay_source_representation(
        &config.source_root,
        acquisition.max_source_bytes,
        source_id,
        locator,
        text_version,
        source_text,
        representation,
    )?;
    if acquisition.protocol != AcquisitionProtocol::OntologyV2 {
        return Err(Error::invalid("stored replay requires ontology-v2"));
    }
    let (semantic_path, semantic_options) = config.semantic_binding()?;
    let semantic = FlureeSemanticLedger::open_file(semantic_path, semantic_options.clone()).await?;
    let prepared = cdb_backend_fluree::semantic_preparation::prepare_current_authorized_view(
        &semantic,
        &acquisition.principal,
        &acquisition.action,
        Default::default(),
    )
    .await
    .map_err(|reason| Error::new(ErrorKind::Denied, reason))?;
    let vocabulary = if acquisition.ontology_ledger_path.is_none() {
        let host = Arc::new(
            crate::semantic_vocabulary::SemanticVocabularyToolHost::from_prepared(&prepared)
                .map_err(|reason| Error::new(ErrorKind::Invalid, reason))?,
        );
        let captured = match &manifest {
            CaptureManifest::Graph(value) => value.provider.ontology_lookup.as_ref(),
            CaptureManifest::Single(value) => value.ontology_lookup.as_ref(),
            CaptureManifest::Multi(value) => value.ontology_lookup.as_ref(),
        }
        .ok_or_else(|| Error::invalid("captured ontology context unavailable"))?;
        let current = host
            .provenance()
            .map_err(|reason| Error::new(ErrorKind::Invalid, reason))?;
        let captured = V::parse(
            &serde_json::to_vec(captured)
                .map_err(|_| Error::invalid("captured ontology context"))?,
            Limits::default(),
        )?;
        for field in ["mode", "inventory_root", "source_quad_root"] {
            if captured.field(field)? != current.field(field)? {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "captured ontology authority differs",
                ));
            }
        }
        Some(host)
    } else {
        None
    };
    let entities = acquisition
        .entity_source
        .as_ref()
        .map(|entity| {
            let eligibility = EntityEligibility::poc(
                entity.graphs.iter().cloned().collect(),
                entity.classes.iter().cloned().collect(),
                entity.identifying_predicates.iter().cloned().collect(),
            );
            EntityGazetteer::from_prepared(
                &acquisition.approved_entity_iris,
                &prepared,
                &eligibility,
            )
            .and_then(|mut gazetteer| {
                if let CaptureManifest::Graph(graph) = &manifest {
                    let context = V::parse(
                        &serde_json::to_vec(&graph.graph.context).map_err(|e| e.to_string())?,
                        Limits::default(),
                    )
                    .map_err(|e| e.to_string())?;
                    let context =
                        GraphContextManifest::from_value(&context, GraphContextLimits::default())
                            .map_err(|e| e.to_string())?;
                    let retained = context.gazetteer().ok_or("captured gazetteer missing")?;
                    gazetteer.restore_replay_snapshot(
                        retained
                            .snapshot
                            .as_deref()
                            .ok_or("captured gazetteer snapshot missing")?,
                    )?;
                    if gazetteer.commitment().as_str() != retained.commitment
                        || gazetteer.dependencies() != &retained.dependencies
                    {
                        return Err("captured gazetteer binding mismatch".into());
                    }
                }
                Ok(Arc::new(CapturedEntitySource {
                    ledger: semantic.clone(),
                    gazetteer,
                }))
            })
            .map_err(|reason| Error::new(ErrorKind::Denied, reason))
        })
        .transpose()?;
    let catalog = service.current_catalog().await?;
    let ephemeral_store = ephemeral
        .then(tempfile::tempdir)
        .transpose()
        .map_err(|_| Error::new(ErrorKind::Backend, "ephemeral replay store unavailable"))?;
    let store_root = match ephemeral_store.as_ref() {
        Some(directory) => {
            #[cfg(unix)]
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).map_err(
                |_| Error::new(ErrorKind::Backend, "ephemeral replay store unavailable"),
            )?;
            fs::canonicalize(directory.path())
                .map_err(|_| Error::new(ErrorKind::Backend, "ephemeral replay store unavailable"))?
        }
        None => config.source_root.clone(),
    };
    let store = SourceObjectWriter::open(store_root, acquisition.max_source_bytes)?;
    let replay_graph_query_config = acquisition
        .graph_workspace
        .as_ref()
        .map(|workspace| {
            workspace
                .query_config
                .as_ref()
                .map(|reference| reference.artifact_ref())
                .unwrap_or_else(|| config.required_default_config())
        })
        .transpose()?;
    let (report, _usage) = ingest_document(
        (!ephemeral).then_some(service),
        acquisition,
        &store,
        source,
        catalog,
        if ephemeral {
            IngestMode::ExtractOnly
        } else {
            IngestMode::Admit(wait)
        },
        ontology_mode,
        config.limits.run_bytes / 2,
        None,
        Some(&manifest),
        None,
        vocabulary,
        entities,
        replay_graph_query_config,
        None,
        CancellationToken::default(),
        true,
        replay_authority,
    )
    .await?;
    serde_json::to_value(report)
        .map_err(|_| Error::new(ErrorKind::Backend, "replay report encoding failed"))
}

fn verify_captured_source_representation(
    representation: Option<&CapturedSourceRepresentation>,
) -> Result<()> {
    let Some(value) = representation else {
        return Ok(());
    };
    ContentHash::parse(&value.original_object)?;
    ContentHash::parse(&value.original_manifest)?;
    match value.media_type.as_str() {
        "text/plain" | "text/markdown" => {
            if value.text_object.is_some()
                || value.text_manifest.is_some()
                || value.converter_manifest.is_some()
                || value.converter.is_some()
            {
                return Err(Error::invalid(
                    "exact-text source representation is invalid",
                ));
            }
        }
        "application/pdf" => {
            ContentHash::parse(
                value
                    .text_object
                    .as_deref()
                    .ok_or_else(|| Error::invalid("PDF text object missing"))?,
            )?;
            ContentHash::parse(
                value
                    .text_manifest
                    .as_deref()
                    .ok_or_else(|| Error::invalid("PDF text manifest missing"))?,
            )?;
            ContentHash::parse(
                value
                    .converter_manifest
                    .as_deref()
                    .ok_or_else(|| Error::invalid("PDF converter manifest missing"))?,
            )?;
            let converter = value
                .converter
                .as_ref()
                .ok_or_else(|| Error::invalid("PDF converter declaration missing"))?;
            ContentHash::parse(&converter.executable_hash)?;
            if converter.encoding != "UTF-8"
                || converter.normalization != "none"
                || converter.version_probe.is_empty()
                || converter.arguments.len() > 128
                || converter.timeout_millis == 0
                || converter.output_byte_limit == 0
            {
                return Err(Error::invalid("PDF converter declaration is invalid"));
            }
        }
        _ => return Err(Error::invalid("source representation media type")),
    }
    Ok(())
}

type GraphCaptureValues = (V, Vec<V>, V, Vec<u8>, V, BTreeMap<ContentHash, V>);

fn graph_capture_values(graph: &GraphCaptureExport) -> Result<GraphCaptureValues> {
    if !matches!(
        graph.schema.as_str(),
        "ctxql-provider-graph-capture/v2" | "ctxql-provider-graph-capture/v3"
    ) {
        return Err(Error::invalid("graph capture schema"));
    }
    let parse = |value: &Value| {
        V::parse(
            &serde_json::to_vec(value).map_err(|_| Error::invalid("graph capture encoding"))?,
            Limits::default(),
        )
    };
    let index = parse(&graph.index)?;
    let leaves = graph
        .transcript_leaves
        .iter()
        .map(parse)
        .collect::<Result<Vec<_>>>()?;
    let context = parse(&graph.context)?;
    let capability = parse(&graph.capability)?;
    let capability_bytes = capability.canonical_bytes(Limits::default())?;
    let workspace = parse(&graph.workspace)?;
    let mut payloads = BTreeMap::new();
    for (root, value) in &graph.graph_payloads {
        let root = ContentHash::parse(root)?;
        let value = parse(value)?;
        if ContentHash::of_bytes(&value.canonical_bytes(Limits::default())?) != root
            || payloads.insert(root, value).is_some()
        {
            return Err(Error::invalid("graph capture payload root"));
        }
    }
    Ok((
        index,
        leaves,
        context,
        capability_bytes,
        workspace,
        payloads,
    ))
}

async fn seal_graph_work(
    service: &Arc<AcquisitionService>,
    job: &JobId,
    graph: &GraphCaptureExport,
) -> Result<V> {
    verify_graph_capture_export(graph)?;
    let (index, leaves, context, capability, workspace, payloads) = graph_capture_values(graph)?;
    let workspace_root = service
        .seal_work_value(job, "graph_workspace", &workspace)
        .await?;
    let context_root = service
        .seal_work_value(job, "graph_context", &context)
        .await?;
    let capability = V::parse(&capability, Limits::default())?;
    let capability_root = service
        .seal_work_value(job, "graph_capability", &capability)
        .await?;
    // Transcript leaves were persisted before socket disclosure by the live
    // recorder. Recompute and retain their roots here; do not create an
    // unversioned family of checkpoint stages.
    let leaf_roots = leaves
        .iter()
        .map(|leaf| {
            Ok(ContentHash::of_bytes(
                &leaf.canonical_bytes(Limits::default())?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    for leaf in &leaves {
        let payload = leaf.field("graph_payload_root")?;
        if payload == &V::Null {
            continue;
        }
        let root = ContentHash::parse(payload.as_str()?)?;
        let retained = payloads
            .get(&root)
            .ok_or_else(|| Error::invalid("graph payload missing"))?;
        let retained_bytes = retained.canonical_bytes(Limits::default())?;
        let object = service
            .source_reader
            .read(&root, service.artifact_limit)
            .await?;
        if object.bytes() != retained_bytes || ContentHash::of_bytes(object.bytes()) != root {
            return Err(Error::invalid("graph payload object root"));
        }
        let issued: crate::graph_workspace::IssuedGraph = serde_json::from_slice(object.bytes())
            .map_err(|_| Error::invalid("graph payload object"))?;
        let response: Value = serde_json::from_str(leaf.field("response")?.as_str()?)
            .map_err(|_| Error::invalid("graph transcript response"))?;
        let handle = response
            .get("handle")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::invalid("graph transcript response handle"))?;
        if issued.session_id.is_empty()
            || !handle.ends_with(&format!("~{}", issued.session_id))
            || response.get("node_count").and_then(Value::as_u64) != Some(issued.nodes.len() as u64)
            || response.get("claim_count").and_then(Value::as_u64)
                != Some(issued.claims.len() as u64)
            || response.get("snapshot").and_then(Value::as_str) != Some(issued.snapshot.as_str())
            || response.get("complete").and_then(Value::as_bool) != Some(true)
        {
            return Err(Error::invalid("graph transcript payload binding"));
        }
    }
    let index_root = service
        .seal_work_value(job, "graph_capture", &index)
        .await?;
    V::object([
        ("capture_root".into(), V::string(index_root.as_str())),
        ("context_root".into(), V::string(context_root.as_str())),
        ("workspace_root".into(), V::string(workspace_root.as_str())),
        (
            "capability_root".into(),
            V::string(capability_root.as_str()),
        ),
        (
            "leaf_roots".into(),
            V::Array(
                leaf_roots
                    .iter()
                    .map(|root| V::string(root.as_str()))
                    .collect(),
            ),
        ),
    ])
}

fn verified_graph_capture(graph: &GraphCaptureExport) -> Result<VerifiedGraphCapture> {
    let (index, leaves, context, capability, workspace, payloads) = graph_capture_values(graph)?;
    let limits = GraphCaptureLimits::default();
    let total = leaves
        .iter()
        .chain(payloads.values())
        .try_fold(0usize, |total, value| {
            total
                .checked_add(value.canonical_bytes(Limits::default())?.len())
                .ok_or_else(Error::limit)
        })?;
    if total > limits.max_total_bytes {
        return Err(Error::limit());
    }
    let index = GraphCaptureIndex::from_value(&index, limits)?;
    let verified =
        verify_graph_capture(&index, &leaves, &context, &capability, &workspace, limits)?;
    let mut referenced = std::collections::BTreeSet::new();
    for leaf in &leaves {
        let value = leaf.field("graph_payload_root")?;
        if value != &V::Null {
            referenced.insert(ContentHash::parse(value.as_str()?)?);
        }
    }
    if referenced != payloads.keys().cloned().collect() {
        return Err(Error::invalid("graph capture payload set"));
    }
    Ok(verified)
}

fn verify_graph_capture_export(graph: &GraphCaptureExport) -> Result<()> {
    verified_graph_capture(graph).map(|_| ())
}

fn verify_capture_manifest_integrity(manifest: &CaptureManifest) -> Result<()> {
    let recorded = verified_recorded_assets(manifest)?;
    let (model, thinking) = match manifest {
        CaptureManifest::Graph(value) => (&value.provider.model, &value.provider.thinking),
        CaptureManifest::Single(value) => (&value.model, &value.thinking),
        CaptureManifest::Multi(value) => (&value.model, &value.thinking),
    };
    if model != &recorded.model || thinking != &recorded.thinking {
        return Err(Error::new(
            ErrorKind::Conflict,
            "recorded model context differs",
        ));
    }
    match manifest {
        CaptureManifest::Graph(manifest) => {
            if !matches!(
                (manifest.schema.as_str(), manifest.graph.schema.as_str()),
                (
                    "ctxql-provider-graph-capture-manifest/v1",
                    "ctxql-provider-graph-capture/v2"
                ) | (
                    "ctxql-provider-graph-capture-manifest/v2",
                    "ctxql-provider-graph-capture/v3"
                )
            ) {
                return Err(Error::invalid("graph capture manifest schema"));
            }
            verify_capture_manifest_integrity(&CaptureManifest::Single(manifest.provider.clone()))?;
            let verified = verified_graph_capture(&manifest.graph)?;
            let request: Value = serde_json::from_str(&manifest.provider.request)
                .map_err(|_| Error::invalid("graph request encoding"))?;
            let captured_skills = request
                .get("graph_workspace")
                .and_then(|value| value.get("skills"))
                .and_then(Value::as_array)
                .ok_or_else(|| Error::invalid("graph skill context unavailable"))?;
            if captured_skills
                != &recorded
                    .required_graph_skills()
                    .iter()
                    .map(|skill| Value::String((*skill).to_owned()))
                    .collect::<Vec<_>>()
            {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "recorded graph skill context differs",
                ));
            }
            if request
                .get("entity_gazetteer_capture")
                .and_then(Value::as_str)
                != verified.gazetteer_commitment.as_deref()
            {
                return Err(Error::invalid("graph provider gazetteer binding"));
            }
            if request.get("graph_workspace") != Some(&manifest.graph.capability)
                || manifest.graph.context["source_version"].as_str()
                    != Some(manifest.provider.text_version.as_str())
                || manifest.graph.context["source_range_root"].as_str()
                    != Some(
                        ContentHash::of_bytes(
                            &serde_json::to_vec(&manifest.provider.issued_ranges)
                                .map_err(|_| Error::invalid("range encoding"))?,
                        )
                        .as_str(),
                    )
            {
                return Err(Error::invalid("graph provider context binding"));
            }
            let (_, leaves, _, _, workspace, payloads) = graph_capture_values(&manifest.graph)?;
            crate::graph_capture::reconstruct_workspace(
                &leaves,
                &payloads,
                &workspace,
                &manifest.provider.issued_ranges.iter().cloned().collect(),
            )?;
        }
        CaptureManifest::Single(manifest) => {
            verify_captured_source_representation(manifest.source_representation.as_ref())?;
            request_response_protocol(&manifest.request)?;
            if manifest.schema != CAPTURE_MANIFEST_SCHEMA
                || manifest.request.len() > 512 * 1024
                || manifest.response.len() > 256 * 1024
                || manifest.request_root
                    != ContentHash::of_bytes(manifest.request.as_bytes()).as_str()
                || manifest.response_root
                    != ContentHash::of_bytes(manifest.response.as_bytes()).as_str()
            {
                return Err(Error::invalid("capture manifest is invalid"));
            }
        }
        CaptureManifest::Multi(manifest) => {
            verify_captured_source_representation(manifest.source_representation.as_ref())?;
            if manifest.schema != MULTI_CAPTURE_MANIFEST_SCHEMA
                || manifest.passage_count == 0
                || manifest.passage_count > 256
            {
                return Err(Error::invalid("multi-passage capture manifest is invalid"));
            }
            if manifest.leaves.len() < manifest.passage_count {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!(
                        "capture manifest missing passage ordinals [{}]",
                        (manifest.leaves.len()..manifest.passage_count)
                            .map(|value| value.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                ));
            }
            if manifest.leaves.len() > manifest.passage_count {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!(
                        "capture manifest has unexpected passage ordinal {}",
                        manifest.passage_count
                    ),
                ));
            }
            for (ordinal, leaf) in manifest.leaves.iter().enumerate() {
                request_response_protocol(&leaf.request)?;
                if leaf.ordinal != ordinal {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        format!("capture manifest passage order mismatch at ordinal {ordinal}"),
                    ));
                }
                if leaf.request.len() > 512 * 1024
                    || leaf.response.len() > 256 * 1024
                    || leaf.request_root != ContentHash::of_bytes(leaf.request.as_bytes()).as_str()
                    || leaf.response_root
                        != ContentHash::of_bytes(leaf.response.as_bytes()).as_str()
                    || leaf.leaf_root != passage_capture_root(leaf)?
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        format!("capture manifest passage {ordinal} commitment mismatch"),
                    ));
                }
                if ordinal > 0 && manifest.leaves[ordinal - 1].context_after != leaf.context_before
                {
                    return Err(Error::new(
                        ErrorKind::Conflict,
                        format!("capture manifest passage {ordinal} context chain mismatch"),
                    ));
                }
            }
            if manifest
                .leaves
                .last()
                .is_some_and(|leaf| leaf.context_after != manifest.entity_checkpoint)
                || manifest.capture_root != multi_capture_root(manifest)?
            {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    "capture manifest aggregate commitment mismatch",
                ));
            }
        }
    }
    Ok(())
}

fn verify_capture_manifest(
    manifest: &ProviderCaptureManifest,
    expected: &ProviderCaptureManifest,
) -> Result<()> {
    if manifest != expected {
        return Err(Error::new(
            ErrorKind::Conflict,
            "capture manifest does not match the current extraction request",
        ));
    }
    Ok(())
}

fn now() -> Result<Timestamp> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorKind::Range, "system time"))?
        .as_millis();
    Timestamp::from_millis(i64::try_from(millis).map_err(|_| Error::limit())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture_manifest() -> ProviderCaptureManifest {
        ProviderCaptureManifest {
            schema: CAPTURE_MANIFEST_SCHEMA.to_owned(),
            source_id: "urn:ctxql:source:test".to_owned(),
            locator: "file:///document.md".to_owned(),
            text_version: ContentHash::of_bytes(b"text").as_str().to_owned(),
            window_id: "window:test".to_owned(),
            request_root: ContentHash::of_bytes(b"request").as_str().to_owned(),
            request: "request".into(),
            source_text: "text".into(),
            coordinate_seed: "attempt:test".into(),
            window_start: 0,
            window_end: 4,
            asset_manifest: json!({}),
            assets: BTreeMap::new(),
            response_root: ContentHash::of_bytes(b"response").as_str().to_owned(),
            response: "response".to_owned(),
            model: cdb_provider_pi::MODEL.to_owned(),
            thinking: cdb_provider_pi::THINKING.to_owned(),
            agent_bundle_hash: ContentHash::of_bytes(b"bundle").as_str().to_owned(),
            ontology_lookup: Some(json!({"capture":"sha256:ontology"})),
            issued_ranges: vec!["sha256:range".to_owned()],
            source_representation: None,
        }
    }

    #[test]
    fn capture_manifest_binds_every_replay_input_and_response_bytes() {
        let expected = capture_manifest();
        assert!(verify_capture_manifest(&expected, &expected).is_ok());

        type ManifestMutation = Box<dyn Fn(&mut ProviderCaptureManifest)>;
        let mutations: Vec<ManifestMutation> = vec![
            Box::new(|v| v.source_id.push_str(":other")),
            Box::new(|v| v.locator.push_str(".other")),
            Box::new(|v| v.text_version.push('0')),
            Box::new(|v| v.window_id.push_str(":other")),
            Box::new(|v| v.request_root.push('0')),
            Box::new(|v| v.response.push('!')),
            Box::new(|v| v.response_root.push('0')),
            Box::new(|v| v.model.push_str(":other")),
            Box::new(|v| v.thinking.push_str(":other")),
            Box::new(|v| v.agent_bundle_hash.push('0')),
            Box::new(|v| v.ontology_lookup = Some(json!({"capture":"changed"}))),
            Box::new(|v| v.issued_ranges.push("sha256:other".to_owned())),
        ];
        for mutate in mutations {
            let mut actual = expected.clone();
            mutate(&mut actual);
            let error = verify_capture_manifest(&actual, &expected).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Conflict);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn acquisition_lookup_serializes_parallel_ontology_calls() {
        struct SingleReaderHost {
            active: std::sync::atomic::AtomicBool,
            calls: std::sync::atomic::AtomicUsize,
        }
        impl OntologyToolHost for SingleReaderHost {
            fn lookup(&self, request: &Value) -> std::result::Result<Value, OntologyToolError> {
                if request.get("capability").is_some() {
                    return Err(OntologyToolError::Denied);
                }
                if self.active.swap(true, std::sync::atomic::Ordering::AcqRel) {
                    return Err(OntologyToolError::Denied);
                }
                std::thread::sleep(Duration::from_millis(30));
                self.calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                self.active
                    .store(false, std::sync::atomic::Ordering::Release);
                Ok(json!({"query":request["query"]}))
            }
        }

        let ontology = Arc::new(SingleReaderHost {
            active: std::sync::atomic::AtomicBool::new(false),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let host = Arc::new(AcquisitionLookupHost {
            ontology: ontology.clone(),
            entity_source: None,
            graph_session: None,
            graph_capture: None,
            ontology_gate: Arc::new(Mutex::new(())),
            graph_gate: Arc::new(Mutex::new(())),
            runtime: tokio::runtime::Handle::current(),
        });
        let start = Arc::new(std::sync::Barrier::new(3));
        let workers = ["urn:test:first", "urn:test:second"].map(|query| {
            let host = host.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                host.invoke(
                    ToolCapability::Ontology,
                    query,
                    &json!({"operation":"describe","query":query}),
                )
            })
        });
        start.wait();
        for worker in workers {
            assert!(worker.join().unwrap().is_ok());
        }
        assert_eq!(ontology.calls.load(std::sync::atomic::Ordering::Acquire), 2);
        // Ontology payloads cannot select entity dispatch via an untrusted field.
        assert!(host
            .invoke(
                ToolCapability::Ontology,
                "nested-capability",
                &json!({"capability":"entities","request":{"operation":"search","query":"name"}}),
            )
            .is_err());
    }

    fn coordinate_map(text: &str) -> CoordinateMap {
        CoordinateMap::issue(
            text,
            "attempt:test",
            "window:test",
            Iri::new("file:///fact.txt").unwrap(),
            ContentHash::of_bytes(b"text-version"),
            ContentHash::of_bytes(text.as_bytes()),
            cdb_core::evidence::Utf8Span::new(0, text.len()).unwrap(),
        )
        .unwrap()
    }

    struct V2Ontology;
    impl OntologyToolHost for V2Ontology {
        fn lookup(&self, request: &Value) -> std::result::Result<Value, OntologyToolError> {
            let query = request.get("query").and_then(Value::as_str).unwrap();
            let kind = request.get("kind").and_then(Value::as_str).unwrap();
            let iri = format!("https://example.test/{query}");
            Ok(json!({
                "resolution": {"status":"unique", "match":iri},
                "terms": [{"iri":iri,"kind":kind,"extraction_eligible":true}]
            }))
        }
    }

    fn choice(text: &str) -> Value {
        json!({"suggestions":[{"text":text,"note":"source meaning"}],"selected":0})
    }

    #[test]
    fn v2_lowering_accepts_three_classes_and_two_directional_party_edges() {
        check_directional_party_lowering(false);
    }

    #[test]
    fn v3_lowering_and_review_link_host_ids_without_rewriting_originals() {
        check_directional_party_lowering(true);
    }

    fn check_directional_party_lowering(v3: bool) {
        let text = "This Agreement is made between Dignity plc as Borrower and Phoenix as Lender.";
        let map = coordinate_map(text);
        let range = map.window_range_id();
        let evidence = |quote: &str| json!([{"range":range,"quote":quote,"occurrence":0}]);
        let mut wire = json!({
            "schema":"ctxql-extraction-proposals/v2",
            "no_claims":false,
            "entities":[
                {"id":"agreement","name":"Agreement","aliases":[],"known_entity":null,"evidence":evidence("Agreement"),"classes":[
                    {"id":"agreement-class","term":choice("CreditAgreement"),"evidence":evidence("This Agreement"),"source_mode":"affirmative","fit":"supported","fit_note":""}
                ]},
                {"id":"borrower","name":"Dignity plc","aliases":[],"known_entity":null,"evidence":evidence("Dignity plc"),"classes":[
                    {"id":"borrower-class","term":choice("Borrower"),"evidence":evidence("Dignity plc as Borrower"),"source_mode":"affirmative","fit":"supported","fit_note":""}
                ]},
                {"id":"lender","name":"Phoenix","aliases":[],"known_entity":null,"evidence":evidence("Phoenix"),"classes":[
                    {"id":"lender-class","term":choice("Lender"),"evidence":evidence("Phoenix as Lender"),"source_mode":"affirmative","fit":"supported","fit_note":""}
                ]}
            ],
            "attributes":[],
            "relations":[
                {"id":"borrower-edge","subject":{"kind":"local","id":"agreement"},"predicate":choice("hasBorrower"),"object":{"kind":"local","id":"borrower"},"evidence":evidence("Agreement is made between Dignity plc as Borrower"),"source_mode":"affirmative","qualifiers":[],"fit":"supported","fit_note":""},
                {"id":"lender-edge","subject":{"kind":"local","id":"agreement"},"predicate":choice("hasLender"),"object":{"kind":"local","id":"lender"},"evidence":evidence("Phoenix as Lender"),"source_mode":"affirmative","qualifiers":[],"fit":"supported","fit_note":""}
            ]
        });
        if v3 {
            wire["schema"] = json!("ctxql-extraction-proposals/v3");
            for entity in wire["entities"].as_array_mut().unwrap() {
                for class in entity["classes"].as_array_mut().unwrap() {
                    class.as_object_mut().unwrap().remove("id");
                }
            }
            for relation in wire["relations"].as_array_mut().unwrap() {
                relation.as_object_mut().unwrap().remove("id");
            }
        }
        let ranges = map.issued_ranges();
        let envelope = parse_proposals(
            &wire.to_string(),
            &ProposalParseContext {
                passage_namespace: "window:test",
                issued_ranges: &ranges,
                document_handles: &[],
            },
            &ProposalLimits::default(),
        )
        .unwrap();
        let extraction = ExtractionText::exact_text(
            Iri::new("file:///fact.txt").unwrap(),
            SourceMediaType::PlainText,
            text.as_bytes().to_vec(),
        )
        .unwrap();
        let source = PreparedSource {
            source_id: SourceId::new("urn:ctxql:source:v2-test").unwrap(),
            original_manifest: ContentHash::of_bytes(text.as_bytes()),
            text_manifest: None,
            converter_manifest: None,
            extraction,
        };
        let mut document_table = DocumentEntityTable::new(
            source.source_id.clone(),
            source.extraction.text_version.clone(),
            source.extraction.text(),
        );
        update_document_table(
            &mut document_table,
            &source,
            &map,
            "window:test",
            "test-request",
            &wire.to_string(),
            ProposalResponseProtocol::HistoricalJson,
        )
        .unwrap();
        let claims = lower_v2_claims(
            &source,
            &map,
            &envelope,
            &V2Ontology,
            None,
            &document_table,
            "test-request",
            &mut BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(claims.len(), 5);
        let mut report = document_report(&source, 1, OntologyMode::Hard, 1024 * 1024);
        let mut outcomes = evaluate_v2_envelope(
            text,
            &map,
            "window:test",
            &envelope,
            ProposalResponseProtocol::HistoricalJson,
            &mut report,
        );
        let originals = outcomes
            .iter()
            .map(|outcome| outcome["original"].clone())
            .collect::<Vec<_>>();
        reconcile_v2_outcomes(
            &mut outcomes,
            &claims,
            OntologyMode::Hard,
            &V2Ontology,
            &envelope,
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome["assertion"] == "direct")
                .count(),
            5
        );
        assert_eq!(
            originals,
            outcomes
                .iter()
                .map(|outcome| outcome["original"].clone())
                .collect::<Vec<_>>()
        );
        assert!(claims.iter().all(|claim| claim
            .subject()
            .as_str()
            .starts_with("urn:ctxql:entity:document:v2:")));
        let classified_subjects = claims
            .iter()
            .filter(|claim| claim.relation().as_str() == RDF_TYPE)
            .map(|claim| claim.subject().as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(classified_subjects.len(), 3);
        assert!(claims
            .iter()
            .any(|claim| { claim.relation().as_str() == "https://example.test/hasBorrower" }));
        assert!(claims
            .iter()
            .any(|claim| { claim.relation().as_str() == "https://example.test/hasLender" }));

        let soft = lower_v2_soft_claims(&source, &map, &envelope, &document_table, "test-request")
            .unwrap();
        assert_eq!(soft.len(), 5);
        assert!(soft.iter().all(|claim| {
            claim
                .relation()
                .as_str()
                .starts_with(PROVISIONAL_PREDICATE_PREFIX)
                && claim.relation().as_str() != RDF_TYPE
        }));
        let hard_subjects = claims
            .iter()
            .map(|claim| claim.subject().as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let soft_subjects = soft
            .iter()
            .map(|claim| claim.subject().as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(hard_subjects, soft_subjects);
    }

    #[test]
    fn text_protocol_populates_document_context_lowers_and_retains_raw_blocks() {
        let text = "Agreement names Orion as Borrower.";
        let map = coordinate_map(text);
        let range = map.window_range_id();
        let wire = format!(
            "ENTITY:\nId: agreement\nName: Agreement\nKnown entity: none\nEVIDENCE:\nRange: {range}\nOccurrence: 0\nQuote: Agreement\n---\n\
ENTITY:\nId: borrower\nName: Orion\nKnown entity: none\nEVIDENCE:\nRange: {range}\nOccurrence: 0\nQuote: Orion\n---\n\
CLAIM:\nKind: classification\nSubject: local agreement\nTerm: CreditAgreement\nTerm note:\nTerm selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nEVIDENCE:\nRange: {range}\nOccurrence: 0\nQuote: Agreement\n---\n\
CLAIM:\nKind: classification\nSubject: local borrower\nTerm: Borrower\nTerm note:\nTerm selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nEVIDENCE:\nRange: {range}\nOccurrence: 0\nQuote: Borrower\n---\n\
CLAIM:\nKind: relation\nSubject: local agreement\nPredicate: hasBorrower\nPredicate note:\nPredicate selected: 0\nObject: local borrower\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nEVIDENCE:\nRange: {range}\nOccurrence: 0\nQuote: Agreement names Orion as Borrower\n---"
        );
        let ranges = map.issued_ranges();
        let context = ProposalParseContext {
            passage_namespace: "window:test",
            issued_ranges: &ranges,
            document_handles: &[],
        };
        let parsed = parse_proposal_response(
            &wire,
            &context,
            &ProposalLimits::default(),
            ProposalResponseProtocol::TextV1,
        )
        .unwrap();
        assert!(parsed.diagnostics.is_empty());
        let extraction = ExtractionText::exact_text(
            Iri::new("file:///fact.txt").unwrap(),
            SourceMediaType::PlainText,
            text.as_bytes().to_vec(),
        )
        .unwrap();
        let source = PreparedSource {
            source_id: SourceId::new("urn:ctxql:source:text-test").unwrap(),
            original_manifest: ContentHash::of_bytes(text.as_bytes()),
            text_manifest: None,
            converter_manifest: None,
            extraction,
        };
        let mut table = DocumentEntityTable::new(
            source.source_id.clone(),
            source.extraction.text_version.clone(),
            source.extraction.text(),
        );
        assert_eq!(
            update_document_table(
                &mut table,
                &source,
                &map,
                "window:test",
                "text-request",
                &wire,
                ProposalResponseProtocol::TextV1,
            )
            .unwrap(),
            5
        );
        assert_eq!(table.entities().count(), 2);
        let claims = lower_v2_claims(
            &source,
            &map,
            &parsed.envelope,
            &V2Ontology,
            None,
            &table,
            "text-request",
            &mut BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(claims.len(), 3);

        let mut report = document_report(&source, 1, OntologyMode::Hard, 1024 * 1024);
        let mut outcomes = evaluate_v2_envelope(
            text,
            &map,
            "window:test",
            &parsed.envelope,
            ProposalResponseProtocol::TextV1,
            &mut report,
        );
        reconcile_v2_outcomes(
            &mut outcomes,
            &claims,
            OntologyMode::Hard,
            &V2Ontology,
            &parsed.envelope,
        );
        assert!(outcomes.iter().all(|outcome| outcome["original"]
            .as_str()
            .is_some_and(|raw| raw.ends_with("---"))));
        assert!(outcomes
            .iter()
            .all(|outcome| outcome["normalized_projection"]
                .as_str()
                .is_some_and(|normalized| serde_json::from_str::<Value>(normalized).is_ok())));
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome["assertion"] == "direct")
                .count(),
            3
        );
    }

    #[test]
    fn response_protocol_dispatch_is_explicit_and_never_falls_back_to_json() {
        let json = r#"{"schema":"ctxql-extraction-proposals/v3","no_claims":true,"entities":[],"attributes":[],"relations":[]}"#;
        let context = ProposalParseContext {
            passage_namespace: "window:test",
            issued_ranges: &[],
            document_handles: &[],
        };
        assert!(parse_proposal_response(
            json,
            &context,
            &ProposalLimits::default(),
            ProposalResponseProtocol::HistoricalJson,
        )
        .is_ok());
        assert!(parse_proposal_response(
            json,
            &context,
            &ProposalLimits::default(),
            ProposalResponseProtocol::TextV1,
        )
        .is_err());
        assert_eq!(
            request_response_protocol(r#"{"schema":"ctxql-acquisition-request/v2"}"#).unwrap(),
            ProposalResponseProtocol::HistoricalJson
        );
        assert_eq!(
            request_response_protocol(
                r#"{"schema":"ctxql-acquisition-request/v2","response_protocol":"ctxql-extraction-text/v1"}"#,
            )
            .unwrap(),
            ProposalResponseProtocol::TextV1
        );
        assert!(request_response_protocol(
            r#"{"schema":"ctxql-acquisition-request/v2","response_protocol":"unknown"}"#,
        )
        .is_err());
    }

    #[test]
    fn text_orphan_diagnostics_are_visible_and_counted() {
        let raw = "ALIAS:\nEntity: missing\nName: Lost\nEVIDENCE:\nRange: h1\nOccurrence: 0\nQuote: Lost\n---";
        let ranges = vec!["h1".to_owned()];
        let context = ProposalParseContext {
            passage_namespace: "window:test",
            issued_ranges: &ranges,
            document_handles: &[],
        };
        let parsed = parse_proposal_response(
            raw,
            &context,
            &ProposalLimits::default(),
            ProposalResponseProtocol::TextV1,
        )
        .unwrap();
        assert_eq!(parsed.diagnostics.len(), 1);
        let source = "Lost";
        let extraction = ExtractionText::exact_text(
            Iri::new("file:///fact.txt").unwrap(),
            SourceMediaType::PlainText,
            source.as_bytes().to_vec(),
        )
        .unwrap();
        let prepared = PreparedSource {
            source_id: SourceId::new("urn:ctxql:source:diagnostic-test").unwrap(),
            original_manifest: ContentHash::of_bytes(source.as_bytes()),
            text_manifest: None,
            converter_manifest: None,
            extraction,
        };
        let mut report = document_report(&prepared, 1, OntologyMode::Hard, 1024 * 1024);
        let mut page = Vec::new();
        evaluate_text_diagnostics(&parsed.diagnostics, "window:test", &mut report, &mut page);
        assert_eq!(report.candidate_count, 1);
        assert_eq!(report.rejected_candidate_count, 1);
        assert_eq!(page[0]["original"], raw);
        assert_eq!(page[0]["kind"], "orphan");
        assert_eq!(page[0]["record_index"], 0);
    }

    #[test]
    fn malformed_fact_is_rejected_without_erasing_valid_neighbors_or_repairing_it() {
        let valid = "FACT:\nsubject | relation | object\nEVIDENCE:\nline:1 | quoted\n---\n";
        let invalid = "FACT:\nsubject | missing object\nEVIDENCE:\nline:1 | quoted\n---\n";
        let output = format!("{valid}{invalid}{valid}");
        let results =
            parse_independent_fact_blocks(&output, &["line:1"], &FactBlockLimits::default())
                .unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert_eq!(
            results[1],
            Err(cdb_provider_pi::fact_blocks::FactBlockParseError::Grammar(
                "fact_fields"
            ))
        );
        assert_eq!(
            results[2],
            Err(cdb_provider_pi::fact_blocks::FactBlockParseError::DuplicateFact)
        );
        let distinct = "FACT:\nsecond | relation | value\nEVIDENCE:\nline:1 | quoted\n---\n";
        let missing_terminator = format!("{}{}", invalid.trim_end_matches("---\n"), distinct);
        let recovered = parse_independent_fact_blocks(
            &missing_terminator,
            &["line:1"],
            &FactBlockLimits::default(),
        )
        .unwrap();
        assert_eq!(recovered.len(), 2);
        assert!(recovered[0].is_err());
        assert_eq!(recovered[1].as_ref().unwrap().subject, "second");
        assert!(parse_independent_fact_blocks(
            "NO_CLAIMS",
            &["line:1"],
            &FactBlockLimits::default()
        )
        .unwrap()
        .is_empty());
        assert!(parse_independent_fact_blocks(
            "NO_CLAIMS\n",
            &["line:1"],
            &FactBlockLimits::default()
        )
        .unwrap()[0]
            .is_err());
    }

    #[test]
    fn typed_fact_resynchronizes_without_repairing_a_bad_neighbor() {
        let typed = "TYPED_FACT:\nAgreement | has borrower | Acme\nEVIDENCE:\nline:1 | Agreement names Acme\nSUBJECT_ROLE:\ncredit agreement\nSUBJECT_EVIDENCE:\nline:1 | Agreement names Acme\nOBJECT_ROLE:\nborrower\nOBJECT_EVIDENCE:\nline:1 | Agreement names Acme\n---\n";
        let bad = "TYPED_FACT:\nAgreement | has borrower | Acme\nEVIDENCE:\nline:1 | Agreement names Acme\nSUBJECT_ROLE:\ncredit agreement\nSUBJECT_EVIDENCE:\nline:1 | Agreement names Acme\nOBJECT_ROLE:\nborrower\nWRONG_EVIDENCE:\nline:1 | Agreement names Acme\n---\n";
        let old = "FACT:\nsubject | relation | object\nEVIDENCE:\nline:1 | quoted\n---\n";
        let results = parse_independent_fact_blocks(
            &format!("{typed}{bad}{old}"),
            &["line:1"],
            &FactBlockLimits::default(),
        )
        .unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0]
            .as_ref()
            .unwrap()
            .typed_endpoint_evidence
            .is_some());
        assert!(results[1].is_err());
        assert!(results[2]
            .as_ref()
            .unwrap()
            .typed_endpoint_evidence
            .is_none());
    }

    #[test]
    fn exact_quote_is_scoped_to_issued_line_and_uses_utf8_byte_offsets() {
        let text = "α café here\nother café";
        let map = coordinate_map(text);
        let coordinate =
            exact_quote_coordinate(&map, text, map.lines()[0].id.as_str(), "café").unwrap();
        assert_eq!(
            coordinate.selection,
            LineSelection::Range { start: 3, end: 8 }
        );
        assert!(
            exact_quote_coordinate(&map, text, map.lines()[0].id.as_str(), "other café").is_err()
        );
    }

    #[test]
    fn duplicate_quote_on_the_issued_line_is_ambiguous() {
        let text = "same then same";
        let map = coordinate_map(text);
        assert!(exact_quote_coordinate(&map, text, map.lines()[0].id.as_str(), "same").is_err());
    }

    #[test]
    fn typed_roles_require_affirmative_local_entity_binding() {
        assert!(role_is_explicit(
            "Borrower",
            "Dignity PLC",
            "**Borrower:** Dignity PLC"
        ));
        assert!(role_is_explicit(
            "Borrower",
            "Acme Ltd",
            "Acme Ltd as Borrower"
        ));
        assert!(role_is_explicit(
            "CreditAgreement",
            "Credit Agreement",
            "The Credit Agreement names Acme Ltd"
        ));
        assert!(!role_is_explicit(
            "Borrower",
            "Acme",
            "Acme signed the agreement"
        ));
        assert!(!role_is_explicit(
            "Borrower",
            "Acme",
            "Acme is not a Borrower"
        ));
        assert!(!role_is_explicit(
            "Borrower",
            "Acme",
            "Acme signed; Bob is the Borrower"
        ));
    }

    #[test]
    fn provisional_entities_are_scoped_by_source_not_just_spelling() {
        let one = SourceId::new("urn:ctxql:source:one").unwrap();
        let two = SourceId::new("urn:ctxql:source:two").unwrap();
        let first = Iri::new("file:///one.md").unwrap();
        let second = Iri::new("file:///two.md").unwrap();
        assert_ne!(
            provisional_entity_iri(&one, &first, "Acme").unwrap(),
            provisional_entity_iri(&two, &first, "Acme").unwrap()
        );
        assert_ne!(
            provisional_entity_iri(&one, &first, "Acme").unwrap(),
            provisional_entity_iri(&one, &second, "Acme").unwrap()
        );
        assert_eq!(
            provisional_entity_iri(&one, &first, "Acme").unwrap(),
            provisional_entity_iri(&one, &first, "ACME").unwrap()
        );
    }

    #[test]
    fn soft_uris_are_host_deterministic_and_case_folded() {
        let first = soft_iri(PROVISIONAL_PREDICATE_PREFIX, "Has Lender").unwrap();
        let second = soft_iri(PROVISIONAL_PREDICATE_PREFIX, "has lender").unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first,
            soft_iri(PROVISIONAL_PREDICATE_PREFIX, "Has Lender").unwrap()
        );
        assert_ne!(
            soft_iri(PROVISIONAL_ENTITY_PREFIX, "has lender").unwrap(),
            first
        );
    }

    #[test]
    fn ontology_mode_is_part_of_identity_material() {
        let root = |mode: OntologyMode| {
            ContentHash::of_bytes(format!("ctxql-extraction-run/v2\0{}", mode.as_str()).as_bytes())
        };
        assert_ne!(root(OntologyMode::Hard), root(OntologyMode::Soft));
        assert_eq!(OntologyMode::parse("hard").unwrap(), OntologyMode::Hard);
        assert!(OntologyMode::parse("other").is_err());
    }

    #[test]
    fn ontology_search_ranking_is_applied_before_limit_with_iri_tiebreaks() {
        let query = ontology_search_key("Borrower");
        let mut matches = [
            "urn:test:z-borrower",
            "urn:test:borrower",
            "Borrower",
            "urn:test:a-borrower",
        ]
        .into_iter()
        .filter_map(|iri| ontology_match_rank(iri, None, &query).map(|rank| (rank, iri)))
        .collect::<Vec<_>>();
        matches.sort();
        assert_eq!(
            matches,
            vec![
                (0, "Borrower"),
                (8, "urn:test:a-borrower"),
                (8, "urn:test:borrower"),
                (8, "urn:test:z-borrower"),
            ]
        );
        assert_eq!(
            matches
                .into_iter()
                .take(2)
                .map(|(_, iri)| iri)
                .collect::<Vec<_>>(),
            ["Borrower", "urn:test:a-borrower"]
        );
    }

    #[test]
    fn report_compaction_preserves_counts_and_never_fails_after_admission() {
        let mut report = IngestReport {
            schema: "ctxql-ingest-report/v1",
            mode: "admit",
            ontology_mode: "hard",
            wait: Some("admitted"),
            documents: (0..16)
                .map(|index| {
                    failed_document(
                        format!("file:///{}-{index}", "x".repeat(1024)),
                        OntologyMode::Hard,
                        "source_acquisition",
                        "invalid_input",
                        2048,
                    )
                })
                .collect(),
            document_count: 16,
            omitted_document_count: 0,
            details_truncated: false,
            validated_bundle_count: 16,
            validated_claim_count: 32,
            admitted_bundle_count: 16,
            admitted_claim_count: 32,
            candidate_count: 16,
            mapped_candidate_count: 16,
            provisional_candidate_count: 0,
            unmapped_candidate_count: 0,
            rejected_candidate_count: 0,
            provider_usage: UsageReport::default(),
        };
        fit_report(&mut report, MIN_INGEST_REPORT_BYTES).unwrap();
        assert!(report.details_truncated);
        assert!(report.omitted_document_count > 0);
        assert_eq!(report.admitted_bundle_count, 16);
        assert_eq!(report.admitted_claim_count, 32);
        assert!(serde_json::to_vec_pretty(&report).unwrap().len() <= MIN_INGEST_REPORT_BYTES);
    }

    #[test]
    fn extract_only_never_discards_raw_provider_text_to_fit_the_report() {
        let mut document = failed_document(
            "file:///loan.md".into(),
            OntologyMode::Soft,
            "provider",
            "provider_json_rejected",
            2048,
        );
        document.provider_responses.push(ProviderResponseReport {
            phase: "individual",
            window_ids: vec!["window:one".into()],
            text: Some(format!("CLAIM:\n{}", "x".repeat(MIN_INGEST_REPORT_BYTES))),
            text_sha256: Some(ContentHash::of_bytes(b"test").as_str().to_owned()),
            parse_error: Some("provider_json_rejected"),
            transport_error: None,
        });
        let mut report = IngestReport {
            schema: "ctxql-ingest-report/v1",
            mode: "extract_only",
            ontology_mode: "soft",
            wait: None,
            documents: vec![document],
            document_count: 1,
            omitted_document_count: 0,
            details_truncated: false,
            validated_bundle_count: 0,
            validated_claim_count: 0,
            admitted_bundle_count: 0,
            admitted_claim_count: 0,
            candidate_count: 0,
            mapped_candidate_count: 0,
            provisional_candidate_count: 0,
            unmapped_candidate_count: 0,
            rejected_candidate_count: 0,
            provider_usage: UsageReport::default(),
        };
        assert!(fit_report(&mut report, MIN_INGEST_REPORT_BYTES).is_err());
        assert_eq!(report.documents.len(), 1);
        assert!(report.documents[0].provider_responses[0]
            .text
            .as_deref()
            .is_some_and(|text| text.starts_with("CLAIM:\n")));
    }
}
