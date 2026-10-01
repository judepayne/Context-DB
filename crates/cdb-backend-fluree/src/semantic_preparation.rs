//! Bounded policy-before-inference preparation over exact semantic views.
//!
//! The unrestricted view is used only for complete claim/infrastructure
//! classification. Only policy-visible, profile-valid premises are sealed into
//! the returned manifest; the source view is never passed to the reasoner.

use crate::{
    authorized_view::{
        build_reasoner_input, framed_root, quad_root, AuthorizedViewManifest, ExactTerm,
        OntologyProfileDescriptor, OperationalScanStats, RdfNodeId, ReasoningDescriptor,
        SemanticCaptureDescriptor, SourceQuad,
    },
    exact_term::{decode_iri as decode_exact_iri, decode_node, decode_term as decode_exact_term},
    executable_profile_v3::{
        ExecutableProfileManifestV3, CONSTRUCT_AUDIT_ROOT_PREDICATE,
        EXECUTABLE_PROFILE_ROOT_PREDICATE, EXECUTABLE_PROFILE_V3_MANIFEST_PREDICATE,
        ONTOLOGY_PROFILE_PREDICATE,
    },
    ontology_profile_v2::{
        classify_ontology_bundle_v2, OntologyProfileLimits, STRUCTURAL_MAPPING_ALGORITHM,
    },
    ontology_profile_v3::{
        verify_historical_ontology_bundle_v3_supported_subset, OntologyProfileV3Limits,
        ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID,
    },
    semantic::FlureeSemanticLedger,
    semantic_codec::{
        decode_claim, ExactRdfTerm, MetadataFact, RdfClaimDocument, SemanticCodecLimits, NS,
    },
    semantic_policy::{
        resolve_current_semantic_authority, verify_semantic_authority_current,
        ResolvedSemanticAuthority, SemanticPolicyBasis,
    },
};
use cdb_core::{
    admission::ExportRecord,
    id::ContentHash,
    recording_v4::SemanticEvidenceV4,
    review::ReviewRecordId,
    snapshot::{SemanticCapture, SnapshotRef},
    CanonicalValue, Limits, Timestamp,
};
use fluree_db_api::{
    config_resolver, ontology_imports, HistoricalLedgerView, LedgerState, ResolvedValue,
};
use fluree_db_core::{
    DatatypeConstraint, FlakeValue, GraphDbRef, GraphId, LedgerSnapshot, OverlayProvider,
};
use fluree_db_query::{
    execute, Binding, ContextConfig, ExecutableQuery, Pattern, Query, QueryOutput,
    QueryPolicyEnforcer, Ref, SortSpec, Term, TriplePattern, VarId, VarRegistry,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const FLUREE_LEDGER_CONFIG: &str = "https://ns.flur.ee/db#LedgerConfig";
const CLAIM: &str = "https://ctxql.example/semantic-rdf/v1/Claim";
const GOVERNED_DATA_GRAPH: &str = "https://ctxql.example/semantic-rdf/v1/governedDataGraph";
const CLAIM_GRAPH: &str = "https://ctxql.example/semantic-rdf/v1/claimGraph";
const REVIEW_GRAPH: &str = "https://ctxql.example/semantic-rdf/v1/reviewGraph";
const INFRASTRUCTURE_GRAPH: &str = "https://ctxql.example/semantic-rdf/v1/infrastructureGraph";
const REIFIES_SUBJECT: &str = "https://ns.flur.ee/db#reifiesSubject";
const REIFIES_PREDICATE: &str = "https://ns.flur.ee/db#reifiesPredicate";
const REIFIES_OBJECT: &str = "https://ns.flur.ee/db#reifiesObject";
const REIFIES_GRAPH: &str = "https://ns.flur.ee/db#reifiesGraph";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtractionLimits {
    pub page_size: usize,
    pub max_pages: usize,
    pub max_rows: usize,
    pub max_bytes: usize,
    pub max_history_commits: usize,
    pub query_timeout: Duration,
    pub codec: SemanticCodecLimits,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            page_size: 128,
            max_pages: 256,
            max_rows: 100_000,
            max_bytes: 64 * 1024 * 1024,
            max_history_commits: 100_000,
            query_timeout: Duration::from_secs(10),
            codec: SemanticCodecLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAuthorizedView {
    pub manifest: AuthorizedViewManifest,
    pub policy_basis: SemanticPolicyBasis,
    pub graph_role_map_root: ContentHash,
    pub configuration_graph: String,
    pub governed_data_graphs: BTreeSet<String>,
    pub claim_graphs: BTreeSet<String>,
    /// Administrative acquisition-review graphs. These are committed as a
    /// separate role and are never scanned into business data, schema,
    /// reasoning premises, or the business claim export.
    pub review_graphs: BTreeSet<String>,
    /// Complete claims admitted to this principal-specific view. Lifecycle
    /// assertions appear only as `ExportRecord::Lifecycle`.
    pub authorized_claims: Vec<ExportRecord>,
    operational: OperationalScanStats,
}

impl PreparedAuthorizedView {
    /// Protected operational telemetry. It is not part of disclosure-safe
    /// counts or semantic-result equality.
    pub fn operational_stats(&self) -> &OperationalScanStats {
        &self.operational
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoricalOntologyActivation {
    ProfileV2Default,
    ProfileV3 {
        manifest: Box<ExecutableProfileManifestV3>,
        executable_profile_root: ContentHash,
    },
}

/// Resolve profile activation only from the exact captured configuration graph.
/// Absence preserves historical profile-v2 behavior; partial or duplicate v3
/// activation fails before any reasoning sandbox is constructed.
pub fn resolve_historical_ontology_activation(
    complete_config: &BTreeSet<SourceQuad>,
    limits: Limits,
) -> Result<HistoricalOntologyActivation, String> {
    let predicates = [
        ONTOLOGY_PROFILE_PREDICATE,
        CONSTRUCT_AUDIT_ROOT_PREDICATE,
        EXECUTABLE_PROFILE_ROOT_PREDICATE,
        EXECUTABLE_PROFILE_V3_MANIFEST_PREDICATE,
    ];
    let activation = complete_config
        .iter()
        .filter(|quad| predicates.contains(&quad.predicate.as_str()))
        .collect::<Vec<_>>();
    if activation.is_empty() {
        return Ok(HistoricalOntologyActivation::ProfileV2Default);
    }
    let config_subjects = complete_config
        .iter()
        .filter(|quad| {
            quad.predicate == RDF_TYPE && quad.object.as_iri() == Some(FLUREE_LEDGER_CONFIG)
        })
        .filter_map(|quad| quad.subject.as_iri())
        .collect::<BTreeSet<_>>();
    if config_subjects.len() != 1 {
        return Err("ontology_configuration_invalid".into());
    }
    let config_subject = *config_subjects.iter().next().expect("one config subject");
    if activation
        .iter()
        .any(|quad| quad.subject.as_iri() != Some(config_subject))
    {
        return Err("ontology_configuration_invalid".into());
    }
    let exact_literal = |predicate: &str| -> Result<&str, String> {
        let values = activation
            .iter()
            .filter(|quad| quad.predicate == predicate)
            .collect::<Vec<_>>();
        if values.len() != 1 {
            return Err("ontology_configuration_invalid".into());
        }
        match &values[0].object {
            ExactTerm::Literal {
                lexical,
                datatype,
                language: None,
            } if datatype == XSD_STRING => Ok(lexical),
            _ => Err("ontology_configuration_invalid".into()),
        }
    };
    let profile = exact_literal(ONTOLOGY_PROFILE_PREDICATE)?;
    if profile == crate::ontology_profile_v3::ONTOLOGY_PROFILE_V3_SUPERSEDED_ID {
        return Err("ontology_profile_unsupported".into());
    }
    if profile != crate::ontology_profile_v3::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID {
        return Err("ontology_profile_unsupported".into());
    }
    let construct_audit_root = ContentHash::parse(exact_literal(CONSTRUCT_AUDIT_ROOT_PREDICATE)?)
        .map_err(|_| "ontology_configuration_invalid".to_string())?;
    let executable_profile_root =
        ContentHash::parse(exact_literal(EXECUTABLE_PROFILE_ROOT_PREDICATE)?)
            .map_err(|_| "ontology_configuration_invalid".to_string())?;
    let manifest = ExecutableProfileManifestV3::from_canonical_bytes(
        exact_literal(EXECUTABLE_PROFILE_V3_MANIFEST_PREDICATE)?.as_bytes(),
        limits,
    )
    .map_err(|_| "ontology_configuration_invalid".to_string())?;
    if manifest.input().construct_audit_root != construct_audit_root
        || manifest
            .root(limits)
            .map_err(|_| "ontology_configuration_invalid".to_string())?
            != executable_profile_root
    {
        return Err("ontology_configuration_invalid".into());
    }
    Ok(HistoricalOntologyActivation::ProfileV3 {
        manifest: Box::new(manifest),
        executable_profile_root,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GraphRoles {
    governed_data: BTreeSet<String>,
    claim_graphs: BTreeSet<String>,
    review_graphs: BTreeSet<String>,
    infrastructure: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Proposition {
    graph: String,
    subject: String,
    predicate: String,
    object: ExactTerm,
}

impl Proposition {
    fn as_quad(&self) -> SourceQuad {
        SourceQuad {
            graph: self.graph.clone(),
            subject: RdfNodeId::Iri(self.subject.clone()),
            predicate: self.predicate.clone(),
            object: self.object.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct Attachment {
    claim: String,
    proposition: Proposition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedClaim {
    proposition: Proposition,
    record: ExportRecord,
    attachment_t: i64,
    detachment_t: Option<i64>,
}

impl ValidatedClaim {
    fn is_attached(&self) -> bool {
        self.detachment_t.is_none()
    }
}

fn close_visible_classification_supports(
    visible: &mut BTreeSet<String>,
    dependencies: &BTreeMap<String, BTreeSet<String>>,
) {
    loop {
        let retained = visible
            .iter()
            .filter(|claim| {
                dependencies
                    .get(*claim)
                    .is_some_and(|required| required.is_subset(visible))
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        if retained == *visible {
            return;
        }
        *visible = retained;
    }
}

#[cfg(test)]
mod classification_support_tests {
    use super::*;

    #[test]
    fn hidden_established_support_removes_dependants_to_a_fixed_point() {
        let mut visible = ["type-visible", "relation", "dependent"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let dependencies = BTreeMap::from([
            ("type-visible".into(), BTreeSet::new()),
            ("relation".into(), BTreeSet::from(["type-hidden".into()])),
            ("dependent".into(), BTreeSet::from(["relation".into()])),
        ]);
        close_visible_classification_supports(&mut visible, &dependencies);
        assert_eq!(visible, BTreeSet::from(["type-visible".into()]));
    }
}

#[derive(Clone, Debug)]
struct HistoricalAttachment {
    proposition: Proposition,
    assertion_time: Timestamp,
    assertion_t: i64,
    detachment_t: Option<i64>,
}

#[derive(Default)]
struct AttachmentBundle {
    graph: Option<String>,
    subject: Vec<String>,
    predicate: Vec<String>,
    object: Vec<ExactTerm>,
    graph_anchor: Vec<String>,
}

struct ReadView<'a> {
    snapshot: &'a LedgerSnapshot,
    overlay: &'a dyn OverlayProvider,
    to_t: i64,
}

impl<'a> ReadView<'a> {
    fn current(state: &'a LedgerState) -> Self {
        Self {
            snapshot: &state.snapshot,
            overlay: state.novelty.as_ref(),
            to_t: state.t(),
        }
    }

    fn historical(view: &'a HistoricalLedgerView) -> Self {
        Self {
            snapshot: &view.snapshot,
            overlay: view,
            to_t: view.to_t(),
        }
    }

    fn graph(&self, graph: GraphId) -> GraphDbRef<'a> {
        GraphDbRef::new(self.snapshot, graph, self.overlay, self.to_t).eager()
    }
}

struct QueryShape {
    vars: VarRegistry,
    patterns: Vec<Pattern>,
    output: Vec<VarId>,
    ordering: Vec<SortSpec>,
}

fn triple_shape() -> QueryShape {
    let mut vars = VarRegistry::new();
    let subject = vars.get_or_insert("?s");
    let predicate = vars.get_or_insert("?p");
    let object = vars.get_or_insert("?o");
    QueryShape {
        vars,
        patterns: vec![Pattern::Triple(TriplePattern::new(
            Ref::Var(subject),
            Ref::Var(predicate),
            Term::Var(object),
        ))],
        output: vec![subject, predicate, object],
        ordering: vec![
            SortSpec::asc(subject),
            SortSpec::asc(predicate),
            SortSpec::asc(object),
        ],
    }
}

fn iri_object_shape(predicate: &str) -> QueryShape {
    let mut vars = VarRegistry::new();
    let subject = vars.get_or_insert("?s");
    let object = vars.get_or_insert("?o");
    QueryShape {
        vars,
        patterns: vec![Pattern::Triple(TriplePattern::new(
            Ref::Var(subject),
            Ref::Iri(Arc::from(predicate)),
            Term::Var(object),
        ))],
        output: vec![subject, object],
        ordering: vec![SortSpec::asc(subject), SortSpec::asc(object)],
    }
}

fn attachment_shape() -> QueryShape {
    let mut vars = VarRegistry::new();
    let subject = vars.get_or_insert("?s");
    let predicate = vars.get_or_insert("?p");
    let object = vars.get_or_insert("?o");
    let annotation = vars.get_or_insert("?annotation");
    QueryShape {
        vars,
        patterns: vec![Pattern::EdgeAnnotation {
            edge: TriplePattern::new(Ref::Var(subject), Ref::Var(predicate), Term::Var(object)),
            annotation: Ref::Var(annotation),
            body: Vec::new(),
        }],
        output: vec![subject, predicate, object, annotation],
        ordering: vec![
            SortSpec::asc(subject),
            SortSpec::asc(predicate),
            SortSpec::asc(object),
            SortSpec::asc(annotation),
        ],
    }
}

pub async fn prepare_current_authorized_view(
    ledger: &FlureeSemanticLedger,
    principal: &str,
    action: &str,
    limits: ExtractionLimits,
) -> Result<PreparedAuthorizedView, String> {
    let capture = ledger
        .capture_current(None)
        .await
        .map_err(|_| "semantic_capture_incomplete".to_string())?;
    let state = ledger
        .current_state()
        .await
        .map_err(|_| "semantic_capture_incomplete".to_string())?;
    if u64::try_from(state.t()).ok() != Some(capture.t())
        || state.head_commit_id.as_ref().map(ToString::to_string)
            != Some(capture.commit_cid().as_str().to_string())
    {
        return Err("semantic_snapshot_divergence".into());
    }
    let authority = resolve_current_semantic_authority(ledger, principal, action).await?;
    prepare_view(
        ledger,
        ReadView::current(&state),
        &capture,
        authority,
        limits,
    )
    .await
}

pub async fn prepare_historical_authorized_view(
    ledger: &FlureeSemanticLedger,
    capture: &SemanticCapture,
    principal: &str,
    action: &str,
    limits: ExtractionLimits,
) -> Result<PreparedAuthorizedView, String> {
    if capture.ledger() != &ledger.options().ledger {
        return Err("semantic_snapshot_divergence".into());
    }
    let historical = ledger
        .historical_view_at(capture)
        .await
        .map_err(|_| "semantic_history_unavailable".to_string())?;
    let authority = resolve_current_semantic_authority(ledger, principal, action).await?;
    prepare_view(
        ledger,
        ReadView::historical(&historical),
        capture,
        authority,
        limits,
    )
    .await
}

/// Authorize complete, exact review-record descriptions at an immutable
/// receipt snapshot under the principal's current same-ledger policy.
///
/// The review graph is scanned twice through the fixed bounded native query:
/// once without filtering to establish each requested subject's complete raw
/// description, and once with the resolved current enforcer. Any absent record
/// or partially hidden description denies the whole request. No inference or
/// caller-supplied query is involved.
pub async fn authorize_review_records(
    ledger: &FlureeSemanticLedger,
    receipt: &SnapshotRef,
    configured_review_graph: &str,
    review_ids: &[ReviewRecordId],
    principal: &str,
    action: &str,
    limits: ExtractionLimits,
) -> Result<BTreeSet<SourceQuad>, String> {
    if receipt.backend() != &ledger.options().backend
        || receipt.pin().authority() != &ledger.options().authority
        || receipt.pin().graph() != &ledger.options().ledger
        || configured_review_graph.is_empty()
        || review_ids.is_empty()
    {
        return Err("review_authorization_denied".into());
    }
    let t_text = receipt.pin().revision().as_str();
    let t = t_text
        .parse::<i64>()
        .ok()
        .filter(|value| *value >= 0 && value.to_string() == t_text)
        .ok_or_else(|| "review_authorization_denied".to_string())?;
    let requested = review_ids
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let requested_bytes = requested.iter().try_fold(0usize, |total, id| {
        total
            .checked_add(id.len())
            .ok_or_else(|| "review_authorization_denied".to_string())
    })?;
    if requested.len() != review_ids.len()
        || requested.len() > limits.max_rows
        || requested_bytes > limits.max_bytes
    {
        return Err("review_authorization_denied".into());
    }

    let capture = ledger
        .capture_at_t(t, Some(receipt.pin().receipt()), None)
        .await
        .map_err(|_| "review_authorization_denied".to_string())?;
    let historical = ledger
        .historical_view_at(&capture)
        .await
        .map_err(|_| "review_authorization_denied".to_string())?;
    let authority = resolve_current_semantic_authority(ledger, principal, action).await?;
    verify_semantic_authority_current(ledger, &authority.basis).await?;
    let view = ReadView::historical(&historical);
    let mut stats = OperationalScanStats::default();
    let roles = resolve_graph_roles(ledger, &view, limits, &authority.basis, &mut stats).await?;
    if !roles.review_graphs.contains(configured_review_graph) {
        return Err("review_authorization_denied".into());
    }
    let raw = scan_quads(
        ledger,
        &view,
        configured_review_graph,
        None,
        limits,
        &authority.basis,
        &mut stats,
    )
    .await?;
    let visible = scan_quads(
        ledger,
        &view,
        configured_review_graph,
        authority.enforcer(),
        limits,
        &authority.basis,
        &mut stats,
    )
    .await?;
    let requested_quads = |quads: &BTreeSet<SourceQuad>| {
        quads
            .iter()
            .filter(|quad| {
                quad.subject_iri()
                    .is_some_and(|subject| requested.contains(subject))
            })
            .cloned()
            .collect::<BTreeSet<_>>()
    };
    let raw_requested = requested_quads(&raw);
    let visible_requested = requested_quads(&visible);
    let present = raw_requested
        .iter()
        .filter_map(SourceQuad::subject_iri)
        .collect::<BTreeSet<_>>();
    if present.len() != requested.len() || raw_requested != visible_requested {
        return Err("review_authorization_denied".into());
    }
    verify_semantic_authority_current(ledger, &authority.basis).await?;
    Ok(visible_requested)
}

/// Reauthorize the exact historical source, then intersect it with the recorded
/// positive member selectors. This is deliberately asymmetric: a later grant
/// may add candidates to the current authorized view, but cannot add them to
/// the reconstructed manifest; a missing or revoked original member denies.
pub async fn reconstruct_recorded_authorized_view(
    ledger: &FlureeSemanticLedger,
    capture: &SemanticCapture,
    evidence: &SemanticEvidenceV4,
    limits: ExtractionLimits,
    wire_limits: Limits,
) -> Result<PreparedAuthorizedView, String> {
    if evidence
        .capture(wire_limits)
        .map_err(|_| "authorized_view_divergence".to_string())?
        != *capture.snapshot()
        || evidence
            .version_field("semantic_codec")
            .map_err(|_| "authorized_view_divergence".to_string())?
            .as_str()
            != "ctxql-semantic-rdf/v1"
        || evidence
            .version_field("commitment_algorithm")
            .map_err(|_| "authorized_view_divergence".to_string())?
            .as_str()
            != "ctxql-source-quad-commitment/sha256-v2"
        || evidence
            .version_field("extraction_algorithm")
            .map_err(|_| "authorized_view_divergence".to_string())?
            .as_str()
            != "ctxql-authorized-view-extraction/v2"
    {
        return Err("authorized_view_divergence".into());
    }
    let principal = evidence
        .principal()
        .map_err(|_| "authorized_view_divergence".to_string())?;
    let action = evidence
        .action()
        .map_err(|_| "authorized_view_divergence".to_string())?;
    let mut current = prepare_historical_authorized_view(
        ledger,
        capture,
        principal.as_str(),
        action.as_str(),
        limits,
    )
    .await?;
    validate_recorded_selectors(&current, evidence, wire_limits)?;

    let data = select_recorded_quads(
        &current.manifest.data_quads,
        &evidence
            .data_commitments(wire_limits)
            .map_err(|_| "authorized_view_divergence".to_string())?,
    )?;
    let schema = select_recorded_quads(
        &current.manifest.schema_quads,
        &evidence
            .schema_commitments(wire_limits)
            .map_err(|_| "authorized_view_divergence".to_string())?,
    )?;
    let support_ids = evidence
        .visible_support_ids(wire_limits)
        .map_err(|_| "authorized_view_divergence".to_string())?;
    let supports = support_ids
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if !supports.is_subset(&current.manifest.visible_supports) {
        return Err("ontology_authorization_denied".into());
    }
    current.authorized_claims.retain(|record| {
        record
            .claim()
            .is_some_and(|claim| supports.contains(claim.id().as_str()))
    });
    let recorded_policy_root = evidence
        .hash_field("policy_dependency_root")
        .map_err(|_| "authorized_view_divergence".to_string())?;
    let completeness = evidence
        .string_field("completeness_selector")
        .map_err(|_| "authorized_view_divergence".to_string())?;
    let recorded_profile = evidence
        .version_field("ontology_profile")
        .map_err(|_| "authorized_view_divergence".to_string())?;
    let manifest = match recorded_profile.as_str() {
        crate::ontology_profile_v2::ONTOLOGY_PROFILE_V2_ID => {
            if evidence
                .supported_subset(wire_limits)
                .map_err(|_| "authorized_view_divergence".to_string())?
                .is_some()
            {
                return Err("authorized_view_divergence".into());
            }
            let profile_limits = OntologyProfileLimits::default();
            let profile = classify_ontology_bundle_v2(&schema, profile_limits)?;
            let reasoner_input = build_reasoner_input(
                &current.manifest.capture,
                &data,
                &profile.reasoner_projection.quads,
            )?;
            AuthorizedViewManifest::seal_profiled_v2(
                current.manifest.capture.clone(),
                current.manifest.reasoning.clone(),
                data,
                schema,
                reasoner_input,
                STRUCTURAL_MAPPING_ALGORITHM.into(),
                profile.limits_identity.clone(),
                supports,
                current.manifest.historical_config_root.clone(),
                OntologyProfileDescriptor {
                    identity: profile.identity.into(),
                    full_bundle_root: profile.full_bundle_root,
                    result_root: profile.result_root,
                },
                recorded_policy_root,
                completeness,
            )
        }
        ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID => {
            let supported = current
                .manifest
                .supported_subset
                .clone()
                .ok_or_else(|| "authorized_view_divergence".to_string())?;
            verify_recorded_supported_subset(evidence, &supported, wire_limits)?;
            let verified = verify_historical_ontology_bundle_v3_supported_subset(
                &schema,
                &supported,
                OntologyProfileV3Limits::default(),
            )
            .map_err(|error| error.public_code.to_string())?;
            let reasoner_input = build_reasoner_input(
                &current.manifest.capture,
                &data,
                &verified.ontology_c0_input,
            )?;
            AuthorizedViewManifest::seal_profiled_v3(
                current.manifest.capture.clone(),
                current.manifest.reasoning.clone(),
                data,
                schema,
                reasoner_input,
                STRUCTURAL_MAPPING_ALGORITHM.into(),
                supported.input().profile_limits_identity.clone(),
                supports,
                current.manifest.historical_config_root.clone(),
                OntologyProfileDescriptor {
                    identity: ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID.into(),
                    full_bundle_root: verified.stored_bundle_root,
                    result_root: verified.verification_root,
                },
                verified.ontology_c0_input,
                supported,
                recorded_policy_root,
                completeness,
            )?
        }
        _ => return Err("ontology_profile_unsupported".into()),
    };
    manifest.validate()?;
    if evidence
        .version_field("ontology_profile")
        .map_err(|_| "authorized_view_divergence".to_string())?
        .as_str()
        != manifest.ontology_profile.identity
        || evidence
            .version_field("structural_mapping_algorithm")
            .map_err(|_| "authorized_view_divergence".to_string())?
            .as_str()
            != manifest.structural_mapping_algorithm
    {
        return Err("authorized_view_divergence".into());
    }
    for (field, actual) in [
        ("data_root", &manifest.data_root),
        ("schema_root", &manifest.schema_root),
        (
            "full_ontology_bundle_root",
            &manifest.ontology_profile.full_bundle_root,
        ),
        (
            "ontology_profile_result_root",
            &manifest.ontology_profile.result_root,
        ),
        ("reasoner_input_root", &manifest.reasoner_input_root),
        ("profile_limits_identity", &manifest.profile_limits_identity),
        (
            "authorized_premise_root",
            &manifest.authorized_premise_root.0,
        ),
        (
            "execution_manifest_root",
            &manifest.execution_manifest_root.0,
        ),
    ] {
        if evidence
            .hash_field(field)
            .map_err(|_| "authorized_view_divergence".to_string())?
            != *actual
        {
            return Err("authorized_view_divergence".into());
        }
    }
    current.manifest = manifest;
    Ok(current)
}

fn verify_recorded_supported_subset(
    evidence: &SemanticEvidenceV4,
    supported: &ExecutableProfileManifestV3,
    limits: Limits,
) -> Result<(), String> {
    let expected = cdb_core::recording_v4::SupportedSubsetEvidenceV4::new(
        supported
            .recording_input(limits)
            .map_err(|_| "authorized_view_divergence".to_string())?,
        limits,
    )
    .map_err(|_| "authorized_view_divergence".to_string())?;
    if evidence
        .supported_subset(limits)
        .map_err(|_| "authorized_view_divergence".to_string())?
        != Some(expected)
    {
        return Err("authorized_view_divergence".into());
    }
    Ok(())
}

fn select_recorded_quads(
    available: &BTreeSet<SourceQuad>,
    selectors: &[ContentHash],
) -> Result<BTreeSet<SourceQuad>, String> {
    let mut by_commitment = BTreeMap::new();
    for quad in available {
        if by_commitment
            .insert(quad.commitment_hash(), quad.clone())
            .is_some()
        {
            return Err("authorized_view_divergence".into());
        }
    }
    selectors
        .iter()
        .map(|selector| {
            by_commitment
                .get(selector)
                .cloned()
                .ok_or_else(|| "ontology_authorization_denied".to_string())
        })
        .collect()
}

fn validate_recorded_selectors(
    current: &PreparedAuthorizedView,
    evidence: &SemanticEvidenceV4,
    limits: Limits,
) -> Result<(), String> {
    let wire = evidence.projection();
    let array = |field: &str| -> Result<BTreeSet<String>, String> {
        wire.field(field)
            .and_then(CanonicalValue::as_array)
            .map_err(|_| "authorized_view_divergence".to_string())?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .map_err(|_| "authorized_view_divergence".to_string())
            })
            .collect()
    };
    let configuration = wire
        .field("configuration_graph")
        .and_then(CanonicalValue::as_str)
        .map_err(|_| "authorized_view_divergence".to_string())?;
    let schema_source = wire
        .field("schema_source")
        .and_then(CanonicalValue::as_str)
        .map_err(|_| "authorized_view_divergence".to_string())?;
    let follows = wire
        .field("follow_owl_imports")
        .and_then(CanonicalValue::as_bool)
        .map_err(|_| "authorized_view_divergence".to_string())?;
    if configuration != current.configuration_graph
        || array("governed_data_graphs")? != current.governed_data_graphs
        || array("claim_graphs")? != current.claim_graphs
        || schema_source != current.manifest.reasoning.schema_source
        || array("schema_graphs")? != current.manifest.reasoning.schema_graphs
        || follows != current.manifest.reasoning.follow_owl_imports
        || evidence
            .hash_field("historical_config_root")
            .map_err(|_| "authorized_view_divergence".to_string())?
            != current.manifest.historical_config_root
        || evidence
            .hash_field("graph_role_map_root")
            .map_err(|_| "authorized_view_divergence".to_string())?
            != current.graph_role_map_root
        || evidence
            .projection()
            .canonical_bytes(limits)
            .map_err(|_| "authorized_view_divergence".to_string())?
            .len()
            > limits.input_bytes()
    {
        return Err("authorized_view_divergence".into());
    }
    Ok(())
}

/// Export every complete native semantic claim at the current exact capture.
/// Current policy is resolved only as a freshness dependency; it never filters
/// this trusted projection feed. Caller-facing disclosure remains an engine
/// authorization concern.
pub async fn export_current_semantic_records(
    ledger: &FlureeSemanticLedger,
    limits: ExtractionLimits,
) -> Result<(SemanticCapture, Vec<ExportRecord>), String> {
    let capture = ledger
        .capture_current(None)
        .await
        .map_err(|_| "semantic_capture_incomplete".to_string())?;
    let state = ledger
        .current_state()
        .await
        .map_err(|_| "semantic_capture_incomplete".to_string())?;
    if u64::try_from(state.t()).ok() != Some(capture.t())
        || state.head_commit_id.as_ref().map(ToString::to_string)
            != Some(capture.commit_cid().as_str().to_string())
    {
        return Err("semantic_snapshot_divergence".into());
    }
    let records = export_semantic_records(ledger, ReadView::current(&state), limits).await?;
    Ok((capture, records))
}

/// Reconstruct the complete native semantic claim export for one exact capture.
pub async fn export_historical_semantic_records(
    ledger: &FlureeSemanticLedger,
    capture: &SemanticCapture,
    limits: ExtractionLimits,
) -> Result<Vec<ExportRecord>, String> {
    if capture.ledger() != &ledger.options().ledger {
        return Err("semantic_snapshot_divergence".into());
    }
    let historical = ledger
        .historical_view_at(capture)
        .await
        .map_err(|_| "semantic_history_unavailable".to_string())?;
    export_semantic_records(ledger, ReadView::historical(&historical), limits).await
}

async fn export_semantic_records(
    semantic: &FlureeSemanticLedger,
    view: ReadView<'_>,
    limits: ExtractionLimits,
) -> Result<Vec<ExportRecord>, String> {
    // This identity is not an authorization principal. It gives extraction the
    // same current-policy freshness barrier as E0 while all scans deliberately
    // run without a policy enforcer.
    let authority = resolve_current_semantic_authority(
        semantic,
        "urn:ctxql:trusted-semantic-projection",
        "https://ns.flur.ee/db#view",
    )
    .await?;
    verify_semantic_authority_current(semantic, &authority.basis).await?;
    let mut stats = OperationalScanStats::default();
    let roles = resolve_graph_roles(semantic, &view, limits, &authority.basis, &mut stats).await?;
    let mut facts = BTreeSet::new();
    let mut attachments = Vec::new();
    for graph in &roles.claim_graphs {
        facts.extend(
            scan_quads(
                semantic,
                &view,
                graph,
                None,
                limits,
                &authority.basis,
                &mut stats,
            )
            .await?,
        );
        attachments.extend(
            scan_attachments(
                semantic,
                &view,
                graph,
                None,
                limits,
                &authority.basis,
                &mut stats,
            )
            .await?,
        );
    }
    let marked: BTreeSet<String> = facts
        .iter()
        .filter(|quad| quad.predicate == RDF_TYPE && quad.object == ExactTerm::Iri(CLAIM.into()))
        .filter_map(|quad| quad.subject_iri().map(str::to_owned))
        .collect();
    ensure_markers_current(
        semantic,
        &marked,
        &roles.claim_graphs,
        view.to_t,
        limits,
        &authority.basis,
    )
    .await?;
    let metadata = claim_metadata(&marked, &facts);
    let histories = claim_histories(
        semantic,
        &marked,
        &metadata,
        &attachments,
        view.to_t,
        limits,
        &authority.basis,
    )
    .await?;
    let claims = validate_claims(&marked, &metadata, &histories, limits.codec)?;
    validate_lifecycle(&claims)?;
    let records = claims.into_values().map(|claim| claim.record).collect();
    verify_semantic_authority_current(semantic, &authority.basis).await?;
    Ok(records)
}

async fn prepare_view(
    semantic: &FlureeSemanticLedger,
    view: ReadView<'_>,
    capture: &SemanticCapture,
    authority: ResolvedSemanticAuthority,
    limits: ExtractionLimits,
) -> Result<PreparedAuthorizedView, String> {
    verify_semantic_authority_current(semantic, &authority.basis).await?;
    let enforcer = authority.enforcer();
    let mut stats = OperationalScanStats::default();
    let roles = resolve_graph_roles(semantic, &view, limits, &authority.basis, &mut stats).await?;

    let mut complete_claim_facts = BTreeSet::new();
    let mut visible_claim_facts = BTreeSet::new();
    let mut complete_attachments = Vec::new();
    let mut visible_attachments = Vec::new();
    for graph in &roles.claim_graphs {
        complete_claim_facts.extend(
            scan_quads(
                semantic,
                &view,
                graph,
                None,
                limits,
                &authority.basis,
                &mut stats,
            )
            .await?,
        );
        visible_claim_facts.extend(
            scan_quads(
                semantic,
                &view,
                graph,
                enforcer.clone(),
                limits,
                &authority.basis,
                &mut stats,
            )
            .await?,
        );
        complete_attachments.extend(
            scan_attachments(
                semantic,
                &view,
                graph,
                None,
                limits,
                &authority.basis,
                &mut stats,
            )
            .await?,
        );
        visible_attachments.extend(
            scan_attachments(
                semantic,
                &view,
                graph,
                enforcer.clone(),
                limits,
                &authority.basis,
                &mut stats,
            )
            .await?,
        );
    }

    let marked: BTreeSet<String> = complete_claim_facts
        .iter()
        .filter(|quad| quad.predicate == RDF_TYPE && quad.object == ExactTerm::Iri(CLAIM.into()))
        .filter_map(|quad| quad.subject_iri().map(str::to_owned))
        .collect();
    ensure_markers_current(
        semantic,
        &marked,
        &roles.claim_graphs,
        view.to_t,
        limits,
        &authority.basis,
    )
    .await?;
    let complete_metadata = claim_metadata(&marked, &complete_claim_facts);
    let visible_metadata = claim_metadata(&marked, &visible_claim_facts);
    let histories = claim_histories(
        semantic,
        &marked,
        &complete_metadata,
        &complete_attachments,
        view.to_t,
        limits,
        &authority.basis,
    )
    .await?;
    let by_claim = validate_claims(&marked, &complete_metadata, &histories, limits.codec)?;
    validate_lifecycle(&by_claim)?;

    let mut visible_targets: BTreeMap<&str, Vec<&Proposition>> = BTreeMap::new();
    for attachment in &visible_attachments {
        visible_targets
            .entry(&attachment.claim)
            .or_default()
            .push(&attachment.proposition);
    }
    let mut visible_supports: BTreeSet<String> = marked
        .iter()
        .filter(|claim| {
            visible_targets.get(claim.as_str()).is_some_and(|targets| {
                targets.len() == 1
                    && targets[0] == &by_claim.get(*claim).expect("validated claim").proposition
            }) && visible_metadata.get(*claim) == complete_metadata.get(*claim)
        })
        .cloned()
        .collect();
    // Established classification entries are dependencies on separately
    // admitted support claims, not permissions embedded in JSON metadata.
    // Remove dependants to a fixed point before either export or reasoning so
    // a hidden class assertion cannot leak through ext or become a premise.
    let classification_dependencies = by_claim
        .iter()
        .map(|(id, validated)| {
            let admitted = validated.record.claim().expect("validated semantic claim");
            let dependencies = admitted
                .candidate()
                .classification_metadata()
                .map_err(|_| "claim_profile_invalid".to_string())?
                .map(|metadata| {
                    metadata
                        .established_supports()
                        .map(|support| support.as_str().to_owned())
                        .collect()
                })
                .unwrap_or_default();
            Ok((id.clone(), dependencies))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    close_visible_classification_supports(&mut visible_supports, &classification_dependencies);

    let managed: BTreeSet<Proposition> = by_claim
        .values()
        .map(|claim| claim.proposition.clone())
        .collect();
    // Lifecycle assertions govern support state but are never RDF premises for
    // C0. Keep their authorized records/selectors for lifecycle evaluation and
    // replay while excluding their propositions from the reasoner dataset.
    let admitted: BTreeSet<Proposition> = visible_supports
        .iter()
        .filter_map(|claim| by_claim.get(claim))
        .filter(|claim| {
            !claim
                .record
                .claim()
                .expect("validated semantic claim")
                .candidate()
                .is_lifecycle_assertion()
        })
        .map(|claim| claim.proposition.clone())
        .collect();
    let authorized_claims = visible_supports
        .iter()
        .filter_map(|claim| by_claim.get(claim).map(|claim| claim.record.clone()))
        .collect();
    let mut data: BTreeSet<SourceQuad> = visible_claim_facts
        .into_iter()
        .filter(|quad| {
            quad.subject_iri()
                .is_some_and(|subject| !marked.contains(subject))
        })
        .filter(|quad| {
            quad.subject_iri().is_some_and(|subject| {
                !managed.contains(&Proposition {
                    graph: quad.graph.clone(),
                    subject: subject.to_owned(),
                    predicate: quad.predicate.clone(),
                    object: quad.object.clone(),
                })
            })
        })
        .collect();
    data.extend(admitted.iter().map(Proposition::as_quad));
    for graph in roles.governed_data.difference(&roles.claim_graphs) {
        data.extend(
            scan_quads(
                semantic,
                &view,
                graph,
                enforcer.clone(),
                limits,
                &authority.basis,
                &mut stats,
            )
            .await?,
        );
    }

    let config_graph = fluree_db_core::graph_registry::config_graph_iri(&view.snapshot.ledger_id);
    let complete_config = scan_infrastructure_quads(
        semantic,
        &view,
        &config_graph,
        None,
        limits,
        &authority.basis,
        &mut stats,
    )
    .await?;
    let visible_config = scan_infrastructure_quads(
        semantic,
        &view,
        &config_graph,
        enforcer.clone(),
        limits,
        &authority.basis,
        &mut stats,
    )
    .await?;
    if complete_config != visible_config {
        return Err("ontology_authorization_denied".into());
    }
    let ontology_activation =
        resolve_historical_ontology_activation(&complete_config, Limits::default())?;
    let configuration_member_root = quad_root(&complete_config);
    let config = config_resolver::resolve_ledger_config(view.snapshot, view.overlay, view.to_t)
        .await
        .map_err(|_| "ontology_configuration_invalid".to_string())?
        .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let reasoning = config_resolver::resolve_effective_config(&config, None)
        .reasoning
        .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let bundle =
        ontology_imports::resolve_schema_bundle(view.snapshot, view.overlay, view.to_t, &reasoning)
            .await
            .map_err(|_| "ontology_configuration_invalid".to_string())?
            .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let schema_source = reasoning
        .schema_source
        .as_ref()
        .and_then(|source| source.graph_selector.clone())
        .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let mut schema_graphs = BTreeSet::new();
    let mut schema_quads = BTreeSet::new();
    for graph_id in &bundle.sources {
        let graph = view
            .snapshot
            .graph_registry
            .iri_for_graph_id(*graph_id)
            .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
        if !roles.infrastructure.contains(graph) {
            return Err("graph_role_map_invalid".into());
        }
        schema_graphs.insert(graph.to_string());
        let complete = scan_ontology_quads(
            semantic,
            &view,
            graph,
            None,
            limits,
            &authority.basis,
            &mut stats,
        )
        .await?;
        let visible = scan_ontology_quads(
            semantic,
            &view,
            graph,
            enforcer.clone(),
            limits,
            &authority.basis,
            &mut stats,
        )
        .await?;
        if complete != visible {
            return Err("ontology_authorization_denied".into());
        }
        schema_quads.extend(complete);
    }
    if bundle.sources.len() != roles.infrastructure.len() {
        return Err("graph_role_map_invalid".into());
    }
    if let HistoricalOntologyActivation::ProfileV3 {
        manifest: supported_subset,
        executable_profile_root,
    } = ontology_activation
    {
        let verified = verify_historical_ontology_bundle_v3_supported_subset(
            &schema_quads,
            &supported_subset,
            OntologyProfileV3Limits::default(),
        )
        .map_err(|error| error.public_code.to_string())?;
        let historical_config_root = framed_root(
            "ctxql-historical-config-and-ontology/v3-supported-subset",
            [
                ("configuration", configuration_member_root.as_str()),
                (
                    "source-ontology-bundle",
                    supported_subset.input().full_bundle_root.as_str(),
                ),
                (
                    "stored-ontology-bundle",
                    verified.stored_bundle_root.as_str(),
                ),
                (
                    "source-ontology-c0",
                    supported_subset.input().ontology_c0_input_root.as_str(),
                ),
                ("stored-ontology-c0", verified.stored_c0_root.as_str()),
                ("verification", verified.verification_root.as_str()),
                ("executable-profile", executable_profile_root.as_str()),
            ],
        );
        verify_semantic_authority_current(semantic, &authority.basis).await?;
        let graph_roles = graph_roles_commitment(&roles);
        let protected = completeness_evidence(
            limits,
            &graph_roles,
            ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID,
            &verified.verification_root,
        );
        let graph_role_map_root = ContentHash::of_bytes(graph_roles.as_bytes());
        let capture_descriptor = capture_descriptor(capture);
        let reasoner_input =
            build_reasoner_input(&capture_descriptor, &data, &verified.ontology_c0_input)?;
        let manifest = AuthorizedViewManifest::seal_profiled_v3(
            capture_descriptor,
            ReasoningDescriptor {
                schema_source,
                follow_owl_imports: reasoning.follow_owl_imports.unwrap_or(false),
                schema_graphs,
            },
            data,
            schema_quads,
            reasoner_input,
            STRUCTURAL_MAPPING_ALGORITHM.into(),
            supported_subset.input().profile_limits_identity.clone(),
            visible_supports,
            historical_config_root,
            OntologyProfileDescriptor {
                identity: ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID.into(),
                full_bundle_root: verified.stored_bundle_root.clone(),
                result_root: verified.verification_root,
            },
            verified.ontology_c0_input,
            *supported_subset,
            authority.basis.dependency_root.clone(),
            &protected,
        )?;
        manifest.validate()?;
        return Ok(PreparedAuthorizedView {
            manifest,
            policy_basis: authority.basis,
            graph_role_map_root,
            configuration_graph: config_graph,
            governed_data_graphs: roles.governed_data,
            claim_graphs: roles.claim_graphs,
            review_graphs: roles.review_graphs,
            authorized_claims,
            operational: stats,
        });
    }
    let profile_limits = OntologyProfileLimits::default();
    let profile = classify_ontology_bundle_v2(&schema_quads, profile_limits)?;
    let historical_config_root = framed_root(
        "ctxql-historical-config-and-ontology/v2",
        [
            ("configuration", configuration_member_root.as_str()),
            ("ontology-bundle", profile.full_bundle_root.as_str()),
            ("ontology-profile-result", profile.result_root.as_str()),
            ("profile-limits", profile.limits_identity.as_str()),
        ],
    );
    verify_semantic_authority_current(semantic, &authority.basis).await?;

    let graph_roles = graph_roles_commitment(&roles);
    let protected =
        completeness_evidence(limits, &graph_roles, profile.identity, &profile.result_root);
    let graph_role_map_root = ContentHash::of_bytes(graph_roles.as_bytes());
    let capture_descriptor = capture_descriptor(capture);
    let reasoner_input = build_reasoner_input(
        &capture_descriptor,
        &data,
        &profile.reasoner_projection.quads,
    )?;
    let manifest = AuthorizedViewManifest::seal_profiled_v2(
        capture_descriptor,
        ReasoningDescriptor {
            schema_source,
            follow_owl_imports: reasoning.follow_owl_imports.unwrap_or(false),
            schema_graphs,
        },
        data,
        schema_quads,
        reasoner_input,
        STRUCTURAL_MAPPING_ALGORITHM.into(),
        profile.limits_identity.clone(),
        visible_supports,
        historical_config_root,
        OntologyProfileDescriptor {
            identity: profile.identity.into(),
            full_bundle_root: profile.full_bundle_root,
            result_root: profile.result_root,
        },
        authority.basis.dependency_root.clone(),
        &protected,
    );
    manifest.validate()?;
    Ok(PreparedAuthorizedView {
        manifest,
        policy_basis: authority.basis,
        graph_role_map_root,
        configuration_graph: config_graph,
        governed_data_graphs: roles.governed_data,
        claim_graphs: roles.claim_graphs,
        review_graphs: roles.review_graphs,
        authorized_claims,
        operational: stats,
    })
}

fn claim_metadata(
    marked: &BTreeSet<String>,
    facts: &BTreeSet<SourceQuad>,
) -> BTreeMap<String, BTreeSet<SourceQuad>> {
    marked
        .iter()
        .map(|claim| {
            (
                claim.clone(),
                facts
                    .iter()
                    .filter(|quad| {
                        &quad.subject == claim
                            && (quad.predicate == RDF_TYPE
                                || (quad.predicate.starts_with(NS)
                                    && !is_lifecycle_predicate(&quad.predicate)))
                    })
                    .cloned()
                    .collect(),
            )
        })
        .collect()
}

async fn ensure_markers_current(
    semantic: &FlureeSemanticLedger,
    current: &BTreeSet<String>,
    claim_graphs: &BTreeSet<String>,
    to_t: i64,
    limits: ExtractionLimits,
    policy_basis: &SemanticPolicyBasis,
) -> Result<(), String> {
    let commit_count = usize::try_from(to_t).map_err(|_| "claim_history_invalid".to_string())?;
    if commit_count > limits.max_history_commits {
        return Err("claim_history_limit_exceeded".into());
    }
    let mut historical = BTreeSet::new();
    let mut history_flakes = 0usize;
    for t in 1..=to_t {
        verify_semantic_authority_current(semantic, policy_basis).await?;
        let detail = tokio::time::timeout(limits.query_timeout, semantic.commit_detail(t))
            .await
            .map_err(|_| "semantic_extraction_timeout".to_string())?
            .map_err(|_| "semantic_history_unavailable".to_string())?;
        verify_semantic_authority_current(semantic, policy_basis).await?;
        history_flakes = history_flakes
            .checked_add(detail.flakes.len())
            .ok_or_else(|| "claim_history_limit_exceeded".to_string())?;
        if history_flakes > limits.max_rows {
            return Err("claim_history_limit_exceeded".into());
        }
        for flake in &detail.flakes {
            let predicate = expand_commit_iri(&flake.p, &detail.context);
            let graph = flake
                .graph
                .as_deref()
                .map(|value| expand_commit_iri(value, &detail.context));
            if predicate == RDF_TYPE
                && graph
                    .as_ref()
                    .is_some_and(|graph| claim_graphs.contains(graph))
                && commit_iri(flake, &detail.context)? == CLAIM
            {
                historical.insert(expand_commit_iri(&flake.s, &detail.context));
            }
        }
    }
    if &historical != current {
        return Err("claim_history_invalid".into());
    }
    Ok(())
}

async fn claim_histories(
    semantic: &FlureeSemanticLedger,
    marked: &BTreeSet<String>,
    metadata: &BTreeMap<String, BTreeSet<SourceQuad>>,
    current_attachments: &[Attachment],
    to_t: i64,
    limits: ExtractionLimits,
    policy_basis: &SemanticPolicyBasis,
) -> Result<BTreeMap<String, HistoricalAttachment>, String> {
    if marked.is_empty() {
        return Ok(BTreeMap::new());
    }
    let commit_count = usize::try_from(to_t).map_err(|_| "claim_history_invalid".to_string())?;
    if commit_count == 0 || commit_count > limits.max_history_commits {
        return Err("claim_history_limit_exceeded".into());
    }

    let claim_graphs: BTreeSet<&str> = metadata
        .values()
        .flat_map(|facts| facts.iter().map(|fact| fact.graph.as_str()))
        .collect();
    let mut bundles: BTreeMap<(String, i64, bool), AttachmentBundle> = BTreeMap::new();
    let mut metadata_events: BTreeMap<String, BTreeMap<SourceQuad, Vec<(i64, bool)>>> =
        BTreeMap::new();
    let mut base_events = Vec::new();
    let mut timestamps = BTreeMap::new();
    let mut previous_timestamp = None;
    let mut history_flakes = 0usize;
    for t in 1..=to_t {
        verify_semantic_authority_current(semantic, policy_basis).await?;
        let detail = tokio::time::timeout(limits.query_timeout, semantic.commit_detail(t))
            .await
            .map_err(|_| "semantic_extraction_timeout".to_string())?
            .map_err(|_| "semantic_history_unavailable".to_string())?;
        verify_semantic_authority_current(semantic, policy_basis).await?;
        history_flakes = history_flakes
            .checked_add(detail.flakes.len())
            .ok_or_else(|| "claim_history_limit_exceeded".to_string())?;
        if history_flakes > limits.max_rows {
            return Err("claim_history_limit_exceeded".into());
        }
        let observed = detail
            .time
            .as_deref()
            .ok_or_else(|| "claim_history_invalid".to_string())
            .and_then(portable_commit_timestamp)?;
        let timestamp = match previous_timestamp {
            Some(previous) if observed <= previous => previous
                .checked_add_millis(1)
                .map_err(|_| "claim_history_invalid".to_string())?,
            _ => observed,
        };
        previous_timestamp = Some(timestamp);
        timestamps.insert(t, timestamp);

        for flake in &detail.flakes {
            let subject = expand_commit_iri(&flake.s, &detail.context);
            let predicate = expand_commit_iri(&flake.p, &detail.context);
            let graph = flake
                .graph
                .as_deref()
                .map(|value| expand_commit_iri(value, &detail.context));
            if !graph
                .as_deref()
                .is_some_and(|graph| claim_graphs.contains(graph))
            {
                continue;
            }
            if predicate.starts_with("https://ns.flur.ee/db#reifies") {
                let bundle = bundles.entry((subject, t, flake.op)).or_default();
                let graph = graph.ok_or_else(|| "claim_history_invalid".to_string())?;
                if bundle
                    .graph
                    .replace(graph.clone())
                    .is_some_and(|old| old != graph)
                {
                    return Err("claim_history_invalid".into());
                }
                match predicate.as_str() {
                    REIFIES_SUBJECT => bundle.subject.push(commit_iri(flake, &detail.context)?),
                    REIFIES_PREDICATE => bundle.predicate.push(commit_iri(flake, &detail.context)?),
                    REIFIES_OBJECT => bundle.object.push(commit_term(flake, &detail.context)?),
                    REIFIES_GRAPH => bundle
                        .graph_anchor
                        .push(commit_iri(flake, &detail.context)?),
                    _ => return Err("claim_history_invalid".into()),
                }
                continue;
            }

            let object = commit_term(flake, &detail.context)?;
            if marked.contains(&subject)
                && (predicate == RDF_TYPE
                    || (predicate.starts_with(NS) && !is_lifecycle_predicate(&predicate)))
            {
                let graph = graph
                    .clone()
                    .ok_or_else(|| "claim_history_invalid".to_string())?;
                metadata_events
                    .entry(subject.clone())
                    .or_default()
                    .entry(SourceQuad {
                        graph,
                        subject: RdfNodeId::Iri(subject.clone()),
                        predicate: predicate.clone(),
                        object: object.clone(),
                    })
                    .or_default()
                    .push((t, flake.op));
            }
            if let Some(graph) = graph {
                base_events.push((
                    t,
                    flake.op,
                    Proposition {
                        graph,
                        subject,
                        predicate,
                        object,
                    },
                ));
            }
        }
    }

    let mut attachment_events: BTreeMap<String, Vec<(i64, bool, Proposition)>> = BTreeMap::new();
    for ((claim, t, op), bundle) in bundles {
        if bundle.subject.len() != 1 || bundle.predicate.len() != 1 || bundle.object.len() != 1 {
            return Err("claim_history_invalid".into());
        }
        let graph = bundle
            .graph
            .ok_or_else(|| "claim_history_invalid".to_string())?;
        if !bundle.graph_anchor.is_empty()
            && (bundle.graph_anchor.len() != 1 || bundle.graph_anchor[0] != graph)
        {
            return Err("claim_history_invalid".into());
        }
        attachment_events.entry(claim).or_default().push((
            t,
            op,
            Proposition {
                graph,
                subject: bundle.subject[0].clone(),
                predicate: bundle.predicate[0].clone(),
                object: bundle.object[0].clone(),
            },
        ));
    }

    let mut all_histories = BTreeMap::new();
    for (claim, events) in &attachment_events {
        let assertions: Vec<_> = events.iter().filter(|(_, op, _)| *op).collect();
        let retractions: Vec<_> = events.iter().filter(|(_, op, _)| !*op).collect();
        if assertions.len() != 1
            || retractions.len() > 1
            || retractions
                .first()
                .is_some_and(|retract| retract.0 <= assertions[0].0 || retract.2 != assertions[0].2)
        {
            return Err("claim_history_invalid".into());
        }
        let assertion_t = assertions[0].0;
        all_histories.insert(
            claim.clone(),
            HistoricalAttachment {
                proposition: assertions[0].2.clone(),
                assertion_time: *timestamps
                    .get(&assertion_t)
                    .ok_or_else(|| "claim_history_invalid".to_string())?,
                assertion_t,
                detachment_t: retractions.first().map(|event| event.0),
            },
        );
    }

    let live_members: Vec<_> = current_attachments
        .iter()
        .filter(|attachment| marked.contains(&attachment.claim))
        .collect();
    let live: BTreeMap<_, _> = live_members
        .iter()
        .map(|attachment| (attachment.claim.as_str(), &attachment.proposition))
        .collect();
    if live.len() != live_members.len() {
        return Err("claim_history_invalid".into());
    }
    let mut histories = BTreeMap::new();
    for claim in marked {
        let history = all_histories
            .get(claim)
            .ok_or_else(|| "claim_history_invalid".to_string())?;
        match (history.detachment_t, live.get(claim.as_str())) {
            (None, Some(proposition)) if *proposition == &history.proposition => {}
            (Some(_), None) => {}
            _ => return Err("claim_history_invalid".into()),
        }
        let expected = metadata
            .get(claim)
            .ok_or_else(|| "claim_profile_invalid".to_string())?;
        let events = metadata_events.get(claim).cloned().unwrap_or_default();
        for (fact, fact_events) in &events {
            let immutable = fact.predicate.starts_with(NS)
                || (fact.predicate == RDF_TYPE && fact.object == ExactTerm::Iri(CLAIM.into()));
            if immutable
                && (!expected.contains(fact)
                    || fact_events.as_slice() != [(history.assertion_t, true)])
            {
                return Err("claim_history_invalid".into());
            }
        }
        for fact in expected.iter().filter(|fact| {
            fact.predicate.starts_with(NS)
                || (fact.predicate == RDF_TYPE && fact.object == ExactTerm::Iri(CLAIM.into()))
        }) {
            if events.get(fact).map(Vec::as_slice) != Some(&[(history.assertion_t, true)]) {
                return Err("claim_history_invalid".into());
            }
        }
        histories.insert(claim.clone(), history.clone());
    }

    // The first managed attachment creates the base edge. A detachment may
    // retract it only when no attachment (including a sparse sibling) remains.
    for history in histories.values() {
        let earliest = all_histories
            .values()
            .filter(|candidate| candidate.proposition == history.proposition)
            .map(|candidate| candidate.assertion_t)
            .min()
            .ok_or_else(|| "claim_history_invalid".to_string())?;
        if !base_events.iter().any(|(t, op, proposition)| {
            *t == earliest && *op && proposition == &history.proposition
        }) {
            return Err("claim_history_invalid".into());
        }
        let Some(detachment_t) = history.detachment_t else {
            continue;
        };
        let surviving_support = all_histories.values().any(|candidate| {
            candidate.proposition == history.proposition
                && candidate.assertion_t <= detachment_t
                && candidate.detachment_t.is_none_or(|t| t > detachment_t)
        });
        let base_retracted = base_events.iter().any(|(t, op, proposition)| {
            *t == detachment_t && !*op && proposition == &history.proposition
        });
        if surviving_support == base_retracted {
            return Err("claim_history_invalid".into());
        }
    }
    Ok(histories)
}

fn is_lifecycle_predicate(predicate: &str) -> bool {
    matches!(
        predicate.strip_prefix(NS),
        Some("superseded_by" | "contradicted_by" | "retracted_by")
    )
}

fn commit_iri(
    flake: &fluree_db_api::ResolvedFlake,
    context: &std::collections::HashMap<String, String>,
) -> Result<String, String> {
    match &flake.o {
        ResolvedValue::String(value) | ResolvedValue::Lexical(value) => {
            Ok(expand_commit_iri(value, context))
        }
        _ => Err("claim_history_invalid".into()),
    }
}

fn commit_term(
    flake: &fluree_db_api::ResolvedFlake,
    context: &std::collections::HashMap<String, String>,
) -> Result<ExactTerm, String> {
    let lexical = match &flake.o {
        ResolvedValue::String(value) | ResolvedValue::Lexical(value) => value.clone(),
        ResolvedValue::Boolean(value) => value.to_string(),
        ResolvedValue::Long(value) => value.to_string(),
        ResolvedValue::Double(_) => return Err("claim_history_invalid".into()),
    };
    if flake.dt == "@id" {
        return Ok(ExactTerm::Iri(expand_commit_iri(&lexical, context)));
    }
    let datatype = expand_commit_iri(&flake.dt, context);
    let lexical = if datatype == "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON" {
        lexical
            .strip_prefix("@json:")
            .ok_or_else(|| "claim_history_invalid".to_string())?
            .to_string()
    } else {
        lexical
    };
    Ok(ExactTerm::Literal {
        lexical,
        datatype,
        language: flake.lang.clone(),
    })
}

fn portable_commit_timestamp(value: &str) -> Result<Timestamp, String> {
    let normalized = if let Some(dot) = value.find('.') {
        let fraction_end = value[dot + 1..]
            .find(|c: char| !c.is_ascii_digit())
            .map(|offset| dot + 1 + offset)
            .unwrap_or(value.len());
        let mut millis = value[dot + 1..fraction_end]
            .chars()
            .take(3)
            .collect::<String>();
        while millis.len() < 3 {
            millis.push('0');
        }
        format!("{}.{}{}", &value[..dot], millis, &value[fraction_end..])
    } else {
        value.to_string()
    };
    Timestamp::parse(&normalized).map_err(|_| "claim_history_invalid".to_string())
}

fn expand_commit_iri(value: &str, context: &std::collections::HashMap<String, String>) -> String {
    let Some((prefix, local)) = value.split_once(':') else {
        return value.to_string();
    };
    context
        .get(prefix)
        .map(|namespace| format!("{namespace}{local}"))
        .unwrap_or_else(|| value.to_string())
}

fn validate_claims(
    marked: &BTreeSet<String>,
    metadata: &BTreeMap<String, BTreeSet<SourceQuad>>,
    histories: &BTreeMap<String, HistoricalAttachment>,
    limits: SemanticCodecLimits,
) -> Result<BTreeMap<String, ValidatedClaim>, String> {
    let mut complete = BTreeMap::new();
    for claim in marked {
        let facts = metadata
            .get(claim)
            .ok_or_else(|| "claim_profile_invalid".to_string())?;
        let history = histories
            .get(claim)
            .ok_or_else(|| "claim_history_invalid".to_string())?;
        if facts
            .iter()
            .any(|fact| fact.graph != history.proposition.graph)
        {
            return Err("claim_profile_invalid".into());
        }
        let target = &history.proposition;
        let document = RdfClaimDocument {
            graph: target.graph.clone(),
            claim_iri: claim.clone(),
            subject_iri: target.subject.clone(),
            predicate_iri: target.predicate.clone(),
            object: codec_term(&target.object),
            metadata: facts
                .iter()
                .map(|fact| MetadataFact {
                    graph: fact.graph.clone(),
                    predicate: fact.predicate.clone(),
                    object: codec_term(&fact.object),
                })
                .collect(),
            attachment_transaction_time: history.assertion_time,
        };
        let record =
            decode_claim(&document, limits).map_err(|_| "claim_profile_invalid".to_string())?;
        complete.insert(
            claim.clone(),
            ValidatedClaim {
                proposition: target.clone(),
                record,
                attachment_t: history.assertion_t,
                detachment_t: history.detachment_t,
            },
        );
    }
    Ok(complete)
}

fn validate_lifecycle(claims: &BTreeMap<String, ValidatedClaim>) -> Result<(), String> {
    let mut transitions: BTreeMap<&str, Vec<(&str, i64)>> = BTreeMap::new();
    for claim in claims.values() {
        let ExportRecord::Lifecycle {
            assertion,
            transaction_time: _,
        } = &claim.record
        else {
            continue;
        };
        if !claim.is_attached() {
            return Err("claim_history_invalid".into());
        }
        let relation = assertion.candidate().relation().as_str();
        let target = claims
            .get(assertion.target().as_str())
            .ok_or_else(|| "claim_history_invalid".to_string())?;
        if claim.attachment_t < target.attachment_t {
            return Err("claim_history_invalid".into());
        }
        match relation {
            "ctxql:retracted_by" | "ctxql:superseded_by" => {
                transitions
                    .entry(assertion.target().as_str())
                    .or_default()
                    .push((relation, claim.attachment_t));
                if relation == "ctxql:superseded_by"
                    && assertion
                        .referenced_claim()
                        .is_none_or(|id| !claims.contains_key(id.as_str()))
                {
                    return Err("claim_history_invalid".into());
                }
            }
            "ctxql:contradicted_by" => {
                if !target.is_attached()
                    || assertion
                        .referenced_claim()
                        .is_none_or(|id| !claims.contains_key(id.as_str()))
                {
                    return Err("claim_history_invalid".into());
                }
            }
            _ => return Err("claim_history_invalid".into()),
        }
    }
    for (id, claim) in claims {
        if matches!(claim.record, ExportRecord::Lifecycle { .. }) {
            continue;
        }
        match (claim.detachment_t, transitions.get(id.as_str())) {
            (None, None) => {}
            (Some(detachment_t), Some(matches))
                if matches.len() == 1 && matches[0].1 == detachment_t => {}
            _ => return Err("claim_history_invalid".into()),
        }
    }
    Ok(())
}

fn codec_term(term: &ExactTerm) -> ExactRdfTerm {
    match term {
        ExactTerm::Iri(value) => ExactRdfTerm::Iri(value.clone()),
        ExactTerm::ScopedBlankNode(_) => {
            unreachable!("claim and metadata scans reject structural blank nodes")
        }
        ExactTerm::Literal {
            lexical,
            datatype,
            language,
        } => ExactRdfTerm::Literal {
            lexical: lexical.clone(),
            datatype: datatype.clone(),
            language: language.clone(),
        },
    }
}

async fn resolve_graph_roles(
    semantic: &FlureeSemanticLedger,
    view: &ReadView<'_>,
    limits: ExtractionLimits,
    basis: &SemanticPolicyBasis,
    stats: &mut OperationalScanStats,
) -> Result<GraphRoles, String> {
    let roles = GraphRoles {
        governed_data: config_iri_values(semantic, view, GOVERNED_DATA_GRAPH, limits, basis, stats)
            .await?,
        claim_graphs: config_iri_values(semantic, view, CLAIM_GRAPH, limits, basis, stats).await?,
        review_graphs: config_iri_values(semantic, view, REVIEW_GRAPH, limits, basis, stats)
            .await?,
        infrastructure: config_iri_values(
            semantic,
            view,
            INFRASTRUCTURE_GRAPH,
            limits,
            basis,
            stats,
        )
        .await?,
    };
    let config_graph = fluree_db_core::graph_registry::config_graph_iri(&view.snapshot.ledger_id);
    if roles.governed_data.is_empty()
        || roles.claim_graphs.is_empty()
        || !roles.claim_graphs.is_subset(&roles.governed_data)
        || !roles.governed_data.is_disjoint(&roles.infrastructure)
        || !roles.review_graphs.is_disjoint(&roles.governed_data)
        || !roles.review_graphs.is_disjoint(&roles.infrastructure)
        || roles.review_graphs.contains(&config_graph)
    {
        return Err("graph_role_map_invalid".into());
    }
    Ok(roles)
}

async fn config_iri_values(
    semantic: &FlureeSemanticLedger,
    view: &ReadView<'_>,
    predicate: &str,
    limits: ExtractionLimits,
    basis: &SemanticPolicyBasis,
    stats: &mut OperationalScanStats,
) -> Result<BTreeSet<String>, String> {
    let config_graph = fluree_db_core::graph_registry::config_graph_iri(&view.snapshot.ledger_id);
    let graph = view
        .snapshot
        .graph_registry
        .graph_id_for_iri(&config_graph)
        .ok_or_else(|| "graph_role_map_invalid".to_string())?;
    paged_rows(
        semantic,
        view,
        graph,
        None,
        &iri_object_shape(predicate),
        limits,
        basis,
        stats,
    )
    .await?
    .into_iter()
    .map(|row| decode_iri(view.snapshot, &row[1]))
    .collect()
}

async fn scan_quads(
    semantic: &FlureeSemanticLedger,
    view: &ReadView<'_>,
    graph_iri: &str,
    enforcer: Option<Arc<QueryPolicyEnforcer>>,
    limits: ExtractionLimits,
    basis: &SemanticPolicyBasis,
    stats: &mut OperationalScanStats,
) -> Result<BTreeSet<SourceQuad>, String> {
    let graph = view
        .snapshot
        .graph_registry
        .graph_id_for_iri(graph_iri)
        .ok_or_else(|| "authorized_view_incomplete".to_string())?;
    paged_rows(
        semantic,
        view,
        graph,
        enforcer,
        &triple_shape(),
        limits,
        basis,
        stats,
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(SourceQuad {
            graph: graph_iri.to_string(),
            subject: RdfNodeId::Iri(decode_iri(view.snapshot, &row[0])?),
            predicate: decode_iri(view.snapshot, &row[1])?,
            object: decode_term(view.snapshot, &row[2])?,
        })
    })
    .collect()
}

async fn scan_ontology_quads(
    semantic: &FlureeSemanticLedger,
    view: &ReadView<'_>,
    graph_iri: &str,
    enforcer: Option<Arc<QueryPolicyEnforcer>>,
    limits: ExtractionLimits,
    basis: &SemanticPolicyBasis,
    stats: &mut OperationalScanStats,
) -> Result<BTreeSet<SourceQuad>, String> {
    let graph = view
        .snapshot
        .graph_registry
        .graph_id_for_iri(graph_iri)
        .ok_or_else(|| "authorized_view_incomplete".to_string())?;
    paged_rows(
        semantic,
        view,
        graph,
        enforcer,
        &triple_shape(),
        limits,
        basis,
        stats,
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(SourceQuad {
            graph: graph_iri.to_string(),
            subject: decode_node(view.snapshot, &row[0], "authorized_view_incomplete")?,
            predicate: decode_iri(view.snapshot, &row[1])?,
            object: decode_exact_term(view.snapshot, &row[2], true, "authorized_view_incomplete")?,
        })
    })
    .collect()
}

async fn scan_infrastructure_quads(
    semantic: &FlureeSemanticLedger,
    view: &ReadView<'_>,
    graph_iri: &str,
    enforcer: Option<Arc<QueryPolicyEnforcer>>,
    limits: ExtractionLimits,
    basis: &SemanticPolicyBasis,
    stats: &mut OperationalScanStats,
) -> Result<BTreeSet<SourceQuad>, String> {
    let graph = view
        .snapshot
        .graph_registry
        .graph_id_for_iri(graph_iri)
        .ok_or_else(|| "authorized_view_incomplete".to_string())?;
    paged_rows(
        semantic,
        view,
        graph,
        enforcer,
        &triple_shape(),
        limits,
        basis,
        stats,
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(SourceQuad {
            graph: graph_iri.to_string(),
            subject: RdfNodeId::Iri(decode_iri(view.snapshot, &row[0])?),
            predicate: decode_iri(view.snapshot, &row[1])?,
            object: decode_infrastructure_term(view.snapshot, &row[2])?,
        })
    })
    .collect()
}

async fn scan_attachments(
    semantic: &FlureeSemanticLedger,
    view: &ReadView<'_>,
    graph_iri: &str,
    enforcer: Option<Arc<QueryPolicyEnforcer>>,
    limits: ExtractionLimits,
    basis: &SemanticPolicyBasis,
    stats: &mut OperationalScanStats,
) -> Result<Vec<Attachment>, String> {
    let graph = view
        .snapshot
        .graph_registry
        .graph_id_for_iri(graph_iri)
        .ok_or_else(|| "authorized_view_incomplete".to_string())?;
    paged_rows(
        semantic,
        view,
        graph,
        enforcer,
        &attachment_shape(),
        limits,
        basis,
        stats,
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(Attachment {
            claim: decode_iri(view.snapshot, &row[3])?,
            proposition: Proposition {
                graph: graph_iri.to_string(),
                subject: decode_iri(view.snapshot, &row[0])?,
                predicate: decode_iri(view.snapshot, &row[1])?,
                object: decode_term(view.snapshot, &row[2])?,
            },
        })
    })
    .collect()
}

#[allow(clippy::too_many_arguments)]
async fn paged_rows(
    semantic: &FlureeSemanticLedger,
    view: &ReadView<'_>,
    graph: GraphId,
    enforcer: Option<Arc<QueryPolicyEnforcer>>,
    shape: &QueryShape,
    limits: ExtractionLimits,
    basis: &SemanticPolicyBasis,
    stats: &mut OperationalScanStats,
) -> Result<Vec<Vec<Binding>>, String> {
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    let mut offset = 0usize;
    let mut bytes = 0usize;
    let mut pages = 0usize;
    loop {
        verify_semantic_authority_current(semantic, basis).await?;
        pages += 1;
        stats.pages += 1;
        if pages > limits.max_pages {
            return Err("authorized_view_incomplete".into());
        }
        let mut query = Query::new(Default::default());
        query.output = QueryOutput::select_all(shape.output.clone());
        query.patterns = shape.patterns.clone();
        query.ordering = shape.ordering.clone();
        query.limit = Some(limits.page_size);
        query.offset = Some(offset);
        if query.reasoning.modes.has_any_enabled() {
            return Err("authorized_view_incomplete".into());
        }
        let batches = tokio::time::timeout(
            limits.query_timeout,
            execute(
                view.graph(graph),
                &shape.vars,
                &ExecutableQuery::simple(query),
                ContextConfig {
                    policy_enforcer: enforcer.clone(),
                    ..ContextConfig::default()
                },
            ),
        )
        .await
        .map_err(|_| "authorized_view_incomplete".to_string())?
        .map_err(|_| "authorized_view_incomplete".to_string())?;
        verify_semantic_authority_current(semantic, basis).await?;
        let mut page = Vec::new();
        for batch in batches {
            for row in 0..batch.len() {
                let values = shape
                    .output
                    .iter()
                    .map(|var| {
                        batch
                            .get(row, *var)
                            .cloned()
                            .ok_or_else(|| "authorized_view_incomplete".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let key = format!("{values:?}");
                if !seen.insert(key.clone()) {
                    return Err("authorized_view_incomplete".into());
                }
                bytes = bytes
                    .checked_add(key.len())
                    .ok_or_else(|| "authorized_view_incomplete".to_string())?;
                if bytes > limits.max_bytes {
                    return Err("authorized_view_incomplete".into());
                }
                stats.rows += 1;
                stats.bytes += key.len();
                page.push(values);
            }
        }
        if page.is_empty() {
            break;
        }
        offset = offset
            .checked_add(page.len())
            .ok_or_else(|| "authorized_view_incomplete".to_string())?;
        rows.extend(page);
        if rows.len() > limits.max_rows {
            return Err("authorized_view_incomplete".into());
        }
    }
    Ok(rows)
}

fn decode_iri(snapshot: &LedgerSnapshot, binding: &Binding) -> Result<String, String> {
    decode_exact_iri(snapshot, binding, "authorized_view_incomplete")
}

fn decode_term(snapshot: &LedgerSnapshot, binding: &Binding) -> Result<ExactTerm, String> {
    decode_exact_term(snapshot, binding, false, "authorized_view_incomplete")
}

fn decode_infrastructure_term(
    snapshot: &LedgerSnapshot,
    binding: &Binding,
) -> Result<ExactTerm, String> {
    if let Binding::Lit { val, dtc, .. } = binding {
        let lexical = match val {
            FlakeValue::Boolean(value) => Some(value.to_string()),
            FlakeValue::Long(value) => Some(value.to_string()),
            _ => None,
        };
        if let Some(lexical) = lexical {
            let DatatypeConstraint::Explicit(datatype) = dtc else {
                return Err("unsupported_exact_literal".into());
            };
            return Ok(ExactTerm::Literal {
                lexical,
                datatype: snapshot
                    .decode_sid(datatype)
                    .ok_or_else(|| "authorized_view_incomplete".to_string())?,
                language: None,
            });
        }
    }
    decode_term(snapshot, binding)
}

fn capture_descriptor(capture: &SemanticCapture) -> SemanticCaptureDescriptor {
    SemanticCaptureDescriptor {
        ledger: capture.ledger().as_str().to_string(),
        requested_as_of: capture
            .requested_as_of()
            .map(|value| value.canonical().to_string())
            .unwrap_or_else(|| format!("t:{}", capture.t())),
        t: i64::try_from(capture.t()).expect("semantic transaction validated"),
        commit_cid: capture.commit_cid().as_str().to_string(),
    }
}

fn completeness_evidence(
    limits: ExtractionLimits,
    graph_roles: &str,
    profile_identity: &str,
    profile_result_root: &ContentHash,
) -> String {
    // Batch sizing, page count, and observed row/byte totals are execution
    // telemetry. Exact replay commits the extraction procedure, semantic hard
    // bounds, and the fact that every ordered scan reached an empty terminal
    // page, but not how the driver happened to batch that work.
    format!(
        "algorithm=ctxql-authorized-view-extraction/v2;terminal=empty-page/v1;max_pages={};max_rows={};max_bytes={};max_history_commits={};query_timeout_ms={};metadata_facts={};metadata_bytes={};ontology_profile={profile_identity};ontology_profile_result={};roles={graph_roles}",
        limits.max_pages,
        limits.max_rows,
        limits.max_bytes,
        limits.max_history_commits,
        limits.query_timeout.as_millis(),
        limits.codec.max_metadata_facts,
        limits.codec.max_metadata_bytes,
        profile_result_root.as_str(),
    )
}

fn graph_roles_commitment(roles: &GraphRoles) -> String {
    let governed = roles
        .governed_data
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\u{0}");
    let claims = roles
        .claim_graphs
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\u{0}");
    let infrastructure = roles
        .infrastructure
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\u{0}");
    if roles.review_graphs.is_empty() {
        // Preserve the historical role commitment for ledgers predating the
        // explicit review role.
        return [governed, claims, infrastructure].join("\u{1}");
    }
    let review = roles
        .review_graphs
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\u{0}");
    [
        "ctxql-graph-role-map/v2".to_owned(),
        governed,
        claims,
        review,
        infrastructure,
    ]
    .join("\u{1}")
}

#[cfg(test)]
mod recorded_selector_tests {
    use super::*;

    fn quad(object: &str) -> SourceQuad {
        SourceQuad {
            graph: "urn:graph:data".into(),
            subject: "urn:subject".into(),
            predicate: "urn:predicate".into(),
            object: ExactTerm::Iri(object.into()),
        }
    }

    #[test]
    fn recorded_quad_selection_does_not_broaden_on_later_grant() {
        let original = quad("urn:original");
        let later = quad("urn:later-grant");
        let available = [original.clone(), later]
            .into_iter()
            .collect::<BTreeSet<_>>();

        let selected = select_recorded_quads(&available, &[original.commitment_hash()]).unwrap();
        assert_eq!(selected, [original].into_iter().collect());
    }

    #[test]
    fn recorded_quad_selection_denies_missing_or_mutated_member() {
        let original = quad("urn:original");
        let selector = original.commitment_hash();
        assert_eq!(
            select_recorded_quads(&BTreeSet::new(), std::slice::from_ref(&selector)).unwrap_err(),
            "ontology_authorization_denied"
        );
        assert_eq!(
            select_recorded_quads(
                &[quad("urn:mutated")].into_iter().collect(),
                std::slice::from_ref(&selector),
            )
            .unwrap_err(),
            "ontology_authorization_denied"
        );
    }
}
