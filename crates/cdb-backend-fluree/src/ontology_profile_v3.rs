//! Fluree-supported-subset ontology profile.
//!
//! This profile is deliberately a policy projection over the immutable Gate 1
//! audit. It does not reinterpret OWL. It retains registered, well-formed
//! constructs that the pinned Fluree reasoner does not implement, and commits
//! the resulting coverage limitations.

use crate::authorized_view::{framed_root, quad_root, ExactTerm, RdfNodeId, SourceQuad};
use crate::{
    executable_profile_v3::ExecutableProfileManifestV3,
    ontology_construct_audit::{
        audit_ontology_closure, reconstruct_historical_audit_closure, AuditedOntologyClosure,
        ConstructAuditLimits, ConstructAuditResult, ConstructDisposition,
    },
};
use cdb_core::id::ContentHash;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID: &str =
    "ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v3-supported-subset";
pub const ONTOLOGY_PROFILE_V3_SUPERSEDED_ID: &str =
    "ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v3";
pub const ONTOLOGY_PROFILE_V3_RESULT_LABEL: &str = "fluree_supported_subset";
pub const ONTOLOGY_PROFILE_V3_ANALYSIS_ID: &str =
    "ctxql-ontology-profile-analysis/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v3-supported-subset-candidate";
pub const ONTOLOGY_PROFILE_V3_ANALYSIS_LABEL: &str = "classification_pending_gate3";
pub const PINNED_FLUREE_REVISION: &str = "603974fad5c13efed9d147d214d613849fb43c73";
pub const RELATIONS_SCOPE: &str = "FND/Relations/Relations";
pub const AGREEMENTS_SCOPE: &str = "FND/Agreements/Agreements";
pub const CONTRACTS_SCOPE: &str = "FND/Agreements/Contracts";

pub const ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED: &str =
    "ontology_uninterpreted_semantics_unregistered";
pub const ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED: &str =
    "ontology_uninterpreted_semantics_changed";
pub const ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH: &str = "ontology_semantic_coverage_mismatch";
pub const ONTOLOGY_PROFILE_LIMIT_EXCEEDED: &str = "ontology_profile_limit_exceeded";

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_FIRST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
const RDF_REST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
const RDF_NIL: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";
const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
const RDFS_DATATYPE: &str = "http://www.w3.org/2000/01/rdf-schema#Datatype";
const RDFS_SUBCLASS: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
const RDFS_RANGE: &str = "http://www.w3.org/2000/01/rdf-schema#range";
const RDFS_LABEL: &str = "http://www.w3.org/2000/01/rdf-schema#label";
const RDFS_COMMENT: &str = "http://www.w3.org/2000/01/rdf-schema#comment";
const RDFS_SEE_ALSO: &str = "http://www.w3.org/2000/01/rdf-schema#seeAlso";
const RDFS_IS_DEFINED_BY: &str = "http://www.w3.org/2000/01/rdf-schema#isDefinedBy";
const OWL_RESTRICTION: &str = "http://www.w3.org/2002/07/owl#Restriction";
const OWL_NAMED_INDIVIDUAL: &str = "http://www.w3.org/2002/07/owl#NamedIndividual";
const OWL_EQUIVALENT_CLASS: &str = "http://www.w3.org/2002/07/owl#equivalentClass";
const OWL_ON_PROPERTY: &str = "http://www.w3.org/2002/07/owl#onProperty";
const OWL_SOME_VALUES_FROM: &str = "http://www.w3.org/2002/07/owl#someValuesFrom";
const OWL_MIN_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#minCardinality";
const OWL_MIN_QUALIFIED_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#minQualifiedCardinality";
const OWL_QUALIFIED_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#qualifiedCardinality";
const OWL_MAX_QUALIFIED_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#maxQualifiedCardinality";
const OWL_ON_CLASS: &str = "http://www.w3.org/2002/07/owl#onClass";
const OWL_ON_DATA_RANGE: &str = "http://www.w3.org/2002/07/owl#onDataRange";
const OWL_UNION_OF: &str = "http://www.w3.org/2002/07/owl#unionOf";
const OWL_ON_DATATYPE: &str = "http://www.w3.org/2002/07/owl#onDatatype";
const OWL_WITH_RESTRICTIONS: &str = "http://www.w3.org/2002/07/owl#withRestrictions";
const OWL_DISJOINT_WITH: &str = "http://www.w3.org/2002/07/owl#disjointWith";
const OWL_PROPERTY_DISJOINT_WITH: &str = "http://www.w3.org/2002/07/owl#propertyDisjointWith";
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const XSD_ANY_URI: &str = "http://www.w3.org/2001/XMLSchema#anyURI";
const XSD_DATE_TIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";
const XSD_NON_NEGATIVE_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#nonNegativeInteger";
const XSD_DECIMAL: &str = "http://www.w3.org/2001/XMLSchema#decimal";
const XSD_MIN_INCLUSIVE: &str = "http://www.w3.org/2001/XMLSchema#minInclusive";
const XSD_MAX_INCLUSIVE: &str = "http://www.w3.org/2001/XMLSchema#maxInclusive";
const DCT_ABSTRACT: &str = "http://purl.org/dc/terms/abstract";
const DCT_CONTRIBUTOR: &str = "http://purl.org/dc/terms/contributor";
const DCT_ISSUED: &str = "http://purl.org/dc/terms/issued";
const DCT_LICENSE: &str = "http://purl.org/dc/terms/license";
const DCT_MODIFIED: &str = "http://purl.org/dc/terms/modified";
const DCT_REFERENCES: &str = "http://purl.org/dc/terms/references";
const DCT_SOURCE: &str = "http://purl.org/dc/terms/source";
const DCT_TITLE: &str = "http://purl.org/dc/terms/title";
const SKOS_CHANGE_NOTE: &str = "http://www.w3.org/2004/02/skos/core#changeNote";
const SKOS_DEFINITION: &str = "http://www.w3.org/2004/02/skos/core#definition";
const SKOS_EXAMPLE: &str = "http://www.w3.org/2004/02/skos/core#example";
const SKOS_NOTE: &str = "http://www.w3.org/2004/02/skos/core#note";
const SKOS_PREF_LABEL: &str = "http://www.w3.org/2004/02/skos/core#prefLabel";
const SKOS_SCOPE_NOTE: &str = "http://www.w3.org/2004/02/skos/core#scopeNote";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OntologyMemberCategory {
    Reasoned,
    InferenceInertDeclaration,
    RetainedAnnotation,
    RetainedUninterpretedSemantic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OntologyProfileV3Limits {
    pub max_bundle_quads: usize,
    pub max_components: usize,
    pub max_component_quads: usize,
    pub max_structural_work: usize,
}

impl Default for OntologyProfileV3Limits {
    fn default() -> Self {
        Self {
            max_bundle_quads: 500_000,
            max_components: 100_000,
            max_component_quads: 100_000,
            max_structural_work: 50_000_000,
        }
    }
}

impl OntologyProfileV3Limits {
    pub fn identity(&self) -> ContentHash {
        ContentHash::of_bytes(
            format!(
                "ctxql-ontology-profile-limits/v3-supported-subset;bundle={};components={};component-quads={};work={}",
                self.max_bundle_quads,
                self.max_components,
                self.max_component_quads,
                self.max_structural_work
            )
            .as_bytes(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologyProfileV3Failure {
    pub public_code: &'static str,
    pub reason: &'static str,
}

impl std::fmt::Display for OntologyProfileV3Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.public_code)
    }
}

impl std::error::Error for OntologyProfileV3Failure {}

type Result<T> = std::result::Result<T, OntologyProfileV3Failure>;
type NodeKey = (String, RdfNodeId);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UninterpretedComponent {
    pub family_id: &'static str,
    pub graph: String,
    pub root_node: RdfNodeId,
    pub quads: BTreeSet<SourceQuad>,
    pub occurrence_identities: Vec<ContentHash>,
    pub source_owners: Vec<String>,
    pub component_root: ContentHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticCaveat {
    pub code: &'static str,
    pub text: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalOntologyProfileV3 {
    pub categories: BTreeMap<OntologyMemberCategory, BTreeSet<SourceQuad>>,
    pub stored_bundle_root: ContentHash,
    pub ontology_c0_input: BTreeSet<SourceQuad>,
    pub stored_c0_root: ContentHash,
    pub verification_root: ContentHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologyProfileV3Result {
    pub identity: &'static str,
    pub result_label: &'static str,
    pub full_bundle: BTreeSet<SourceQuad>,
    pub full_bundle_root: ContentHash,
    pub categories: BTreeMap<OntologyMemberCategory, BTreeSet<SourceQuad>>,
    pub category_counts: BTreeMap<OntologyMemberCategory, usize>,
    pub category_roots: BTreeMap<OntologyMemberCategory, ContentHash>,
    pub category_occurrence_roots: BTreeMap<OntologyMemberCategory, ContentHash>,
    pub components: Vec<UninterpretedComponent>,
    pub component_projection_root: ContentHash,
    pub registry_root: ContentHash,
    pub family_root: ContentHash,
    pub annotation_policy_root: ContentHash,
    pub caveat_set_root: ContentHash,
    pub semantic_coverage_root: ContentHash,
    pub ontology_c0_input: BTreeSet<SourceQuad>,
    pub ontology_c0_input_root: ContentHash,
    pub audit_root: ContentHash,
    pub source_entry_root: ContentHash,
    pub limits_identity: ContentHash,
    pub result_root: ContentHash,
}

impl OntologyProfileV3Result {
    pub fn verify_integrity(
        &self,
        closure: &AuditedOntologyClosure,
        audit: &ConstructAuditResult,
        limits: OntologyProfileV3Limits,
    ) -> bool {
        classify_ontology_closure_v3_supported_subset(closure, audit, limits)
            .is_ok_and(|rebuilt| rebuilt == *self)
    }
}

/// Exact, content-free declaration evidence accepted by Gate 3. Construction
/// rejects every alternate serialization or payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclarationEvidenceV3;

impl DeclarationEvidenceV3 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes
            != include_bytes!("../../../fixtures/conformance/p5_7/declaration-evidence.json")
                .as_slice()
        {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "declaration_evidence_artifact_mismatch",
            ));
        }
        Ok(Self)
    }

    pub fn root(&self) -> ContentHash {
        ContentHash::of_bytes(include_bytes!(
            "../../../fixtures/conformance/p5_7/declaration-evidence.json"
        ))
    }
}

/// Exact, content-free uninterpreted-family non-interference evidence accepted
/// by Gate 3. Construction rejects every alternate serialization or payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UninterpretedNonInterferenceEvidenceV3;

impl UninterpretedNonInterferenceEvidenceV3 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes
            != include_bytes!("../../../fixtures/conformance/p5_7/non-interference-evidence.json")
                .as_slice()
        {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "uninterpreted_non_interference_artifact_mismatch",
            ));
        }
        Ok(Self)
    }

    pub fn root(&self) -> ContentHash {
        ContentHash::of_bytes(include_bytes!(
            "../../../fixtures/conformance/p5_7/non-interference-evidence.json"
        ))
    }
}

/// One exact source member pinned by the runtime-provided acquisition authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TrustedOntologySourceMemberV3 {
    pub source_release_id: String,
    pub source_file_id: String,
    pub ontology_iri: String,
    pub authoritative_hash: ContentHash,
    pub conversion_root: ContentHash,
    pub graph: String,
    pub graph_root: ContentHash,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AcquisitionFileV3 {
    bytes: usize,
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionArtifactWireV3 {
    schema: String,
    file_count: usize,
    total_authoritative_bytes: usize,
    inventory_root: String,
    files: Vec<AcquisitionFileV3>,
}

/// Content-free, canonical acquisition inventory supplied by the runtime trust
/// boundary. It commits exact external source paths, byte counts, and hashes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedAcquisitionAuthorityV3 {
    files: Vec<AcquisitionFileV3>,
    inventory_root: ContentHash,
}

impl TrustedAcquisitionAuthorityV3 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let wire: AcquisitionArtifactWireV3 = serde_json::from_slice(bytes).map_err(|_| {
            failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "acquisition_authority_invalid",
            )
        })?;
        let trusted_schema = wire.schema.starts_with("ctxql.p5-7-official-")
            || wire.schema == "ctxql.p6-official-commercial-loans-closure/v1";
        if !trusted_schema
            || wire.file_count == 0
            || wire.file_count != wire.files.len()
            || wire.total_authoritative_bytes
                != wire.files.iter().map(|file| file.bytes).sum::<usize>()
        {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "acquisition_authority_invalid",
            ));
        }
        let mut files = wire.files;
        files.sort_by(|left, right| left.path.cmp(&right.path));
        if files.windows(2).any(|pair| pair[0].path == pair[1].path)
            || files.iter().any(|file| {
                file.path.is_empty()
                    || file.bytes == 0
                    || file.sha256.len() != 64
                    || !file
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
        {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "acquisition_authority_invalid",
            ));
        }
        let mut material = Vec::new();
        for file in &files {
            material.extend_from_slice(file.path.as_bytes());
            material.push(0);
            material.extend_from_slice(file.sha256.as_bytes());
            material.push(b'\n');
        }
        let inventory_root = ContentHash::parse(&wire.inventory_root).map_err(|_| {
            failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "acquisition_authority_invalid",
            )
        })?;
        if ContentHash::of_bytes(&material) != inventory_root {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "acquisition_authority_root_mismatch",
            ));
        }
        Ok(Self {
            files,
            inventory_root,
        })
    }

    pub fn root(&self) -> &ContentHash {
        &self.inventory_root
    }
}

/// Canonical runtime trust anchor for one selected scope and its complete
/// source/dependency closure. The anchor is content-free: it contains only
/// source identities and roots. Construction verifies exact equality with an
/// integrity-checked audited closure, so a scope label cannot bless unrelated
/// bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedOntologyScopeAuthorityV3 {
    selected_scope: String,
    selected_source_release_id: String,
    selected_source_file_id: String,
    selected_ontology_iri: String,
    acquisition_authority_root: ContentHash,
    dependency_universe_root: ContentHash,
    dependency_limits_identity: ContentHash,
    source_occurrence_root: ContentHash,
    closure_root: ContentHash,
    full_bundle_root: ContentHash,
    full_bundle_count: usize,
    members: Vec<TrustedOntologySourceMemberV3>,
    member_root: ContentHash,
    root: ContentHash,
}

impl TrustedOntologyScopeAuthorityV3 {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        selected_scope: String,
        selected_source_release_id: String,
        selected_source_file_id: String,
        selected_ontology_iri: String,
        acquisition_authority: TrustedAcquisitionAuthorityV3,
        dependency_limits_identity: ContentHash,
        expected_members: Vec<TrustedOntologySourceMemberV3>,
        closure: &AuditedOntologyClosure,
        audit: &ConstructAuditResult,
    ) -> Result<Self> {
        if selected_scope.is_empty() || selected_scope.chars().any(char::is_control) {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "scope_authority_scope_invalid",
            ));
        }
        if !audit.verify_integrity(closure) {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "scope_authority_closure_invalid",
            ));
        }
        let mut members = expected_members;
        members.sort();
        if members.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "scope_authority_duplicate_member",
            ));
        }
        let actual = closure
            .members
            .iter()
            .map(|member| TrustedOntologySourceMemberV3 {
                source_release_id: member.source_release_id.clone(),
                source_file_id: member.source_file_id.clone(),
                ontology_iri: member.ontology_iri.clone(),
                authoritative_hash: member.authoritative_hash.clone(),
                conversion_root: member.conversion_root.clone(),
                graph: member.graph.clone(),
                graph_root: member.graph_root.clone(),
            })
            .collect::<Vec<_>>();
        let mut actual = actual;
        actual.sort();
        if members != actual {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "scope_authority_members_mismatch",
            ));
        }
        let acquisition_members = acquisition_authority
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.sha256.as_str()))
            .collect::<BTreeSet<_>>();
        let closure_members = members
            .iter()
            .map(|member| {
                (
                    member.source_file_id.as_str(),
                    &member.authoritative_hash.as_str()[7..],
                )
            })
            .collect::<BTreeSet<_>>();
        if acquisition_members != closure_members {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "acquisition_authority_members_mismatch",
            ));
        }
        if !members.iter().any(|member| {
            member.source_release_id == selected_source_release_id
                && member.source_file_id == selected_source_file_id
                && member.ontology_iri == selected_ontology_iri
        }) {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "scope_authority_selected_member_missing",
            ));
        }
        let acquisition_authority_root = acquisition_authority.root().clone();
        let full_bundle_root = quad_root(&closure.bundle);
        let count = closure.bundle.len().to_string();
        let member_values = members
            .iter()
            .map(|member| {
                format!(
                    "{}\0{}\0{}\0{}\0{}\0{}\0{}",
                    member.source_release_id,
                    member.source_file_id,
                    member.ontology_iri,
                    member.authoritative_hash.as_str(),
                    member.conversion_root.as_str(),
                    member.graph,
                    member.graph_root.as_str()
                )
            })
            .collect::<Vec<_>>();
        let member_root = framed_root(
            "ctxql-ontology-scope-authority-members/v1",
            member_values.iter().map(|value| ("member", value.as_str())),
        );
        let root = framed_root(
            "ctxql-ontology-scope-authority/v1",
            [
                ("scope", selected_scope.as_str()),
                ("selected-release", selected_source_release_id.as_str()),
                ("selected-path", selected_source_file_id.as_str()),
                ("selected-ontology", selected_ontology_iri.as_str()),
                ("acquisition-authority", acquisition_authority_root.as_str()),
                ("dependency-universe", closure.dependency_root.as_str()),
                ("dependency-limits", dependency_limits_identity.as_str()),
                ("closure", closure.closure_root.as_str()),
                ("source-occurrences", closure.source_quad_root.as_str()),
                ("bundle", full_bundle_root.as_str()),
                ("bundle-count", count.as_str()),
                ("members", member_root.as_str()),
            ],
        );
        Ok(Self {
            selected_scope,
            selected_source_release_id,
            selected_source_file_id,
            selected_ontology_iri,
            acquisition_authority_root,
            dependency_universe_root: closure.dependency_root.clone(),
            dependency_limits_identity,
            source_occurrence_root: closure.source_quad_root.clone(),
            closure_root: closure.closure_root.clone(),
            full_bundle_root,
            full_bundle_count: closure.bundle.len(),
            members,
            member_root,
            root,
        })
    }

    pub fn selected_scope(&self) -> &str {
        &self.selected_scope
    }
    pub fn selected_source_release_id(&self) -> &str {
        &self.selected_source_release_id
    }
    pub fn selected_source_file_id(&self) -> &str {
        &self.selected_source_file_id
    }
    pub fn selected_ontology_iri(&self) -> &str {
        &self.selected_ontology_iri
    }
    pub fn acquisition_authority_root(&self) -> &ContentHash {
        &self.acquisition_authority_root
    }
    pub fn member_root(&self) -> &ContentHash {
        &self.member_root
    }
    pub fn dependency_universe_root(&self) -> &ContentHash {
        &self.dependency_universe_root
    }
    pub fn dependency_limits_identity(&self) -> &ContentHash {
        &self.dependency_limits_identity
    }
    pub fn source_occurrence_root(&self) -> &ContentHash {
        &self.source_occurrence_root
    }
    pub fn root(&self) -> &ContentHash {
        &self.root
    }

    fn verify_integrity(
        &self,
        closure: &AuditedOntologyClosure,
        audit: &ConstructAuditResult,
    ) -> bool {
        Self::verify(
            self.selected_scope.clone(),
            self.selected_source_release_id.clone(),
            self.selected_source_file_id.clone(),
            self.selected_ontology_iri.clone(),
            TrustedAcquisitionAuthorityV3 {
                files: self
                    .members
                    .iter()
                    .map(|member| AcquisitionFileV3 {
                        bytes: 1,
                        path: member.source_file_id.clone(),
                        sha256: member.authoritative_hash.as_str()[7..].to_owned(),
                    })
                    .collect(),
                inventory_root: self.acquisition_authority_root.clone(),
            },
            self.dependency_limits_identity.clone(),
            self.members.clone(),
            closure,
            audit,
        )
        .is_ok_and(|rebuilt| rebuilt == *self)
    }
}

/// Generic Gate-3 artifacts. Their hashes are never stored directly in a final
/// manifest; certification derives scope/closure-specific commitments below.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologyProfileV3CertificationEvidence {
    pub reasoned_family_inventory_bytes: Vec<u8>,
    pub declaration_evidence: DeclarationEvidenceV3,
    pub uninterpreted_non_interference_evidence: UninterpretedNonInterferenceEvidenceV3,
    pub parity_matrix_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeBoundGate3RootsV3 {
    pub reasoned_family_inventory_root: ContentHash,
    pub declaration_evidence_root: ContentHash,
    pub uninterpreted_non_interference_root: ContentHash,
    pub parity_matrix_root: ContentHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedOntologyProfileV3 {
    identity: &'static str,
    result_label: &'static str,
    closure: AuditedOntologyClosure,
    audit: ConstructAuditResult,
    authority: TrustedOntologyScopeAuthorityV3,
    limits: OntologyProfileV3Limits,
    analysis: OntologyProfileV3Result,
    evidence: OntologyProfileV3CertificationEvidence,
    manifest: ExecutableProfileManifestV3,
    semantic_coverage_root: ContentHash,
    result_root: ContentHash,
}

impl CertifiedOntologyProfileV3 {
    pub fn identity(&self) -> &'static str {
        self.identity
    }
    pub fn result_label(&self) -> &'static str {
        self.result_label
    }
    pub fn analysis(&self) -> &OntologyProfileV3Result {
        &self.analysis
    }
    pub fn manifest(&self) -> &ExecutableProfileManifestV3 {
        &self.manifest
    }
    pub fn semantic_coverage_root(&self) -> &ContentHash {
        &self.semantic_coverage_root
    }
    pub fn result_root(&self) -> &ContentHash {
        &self.result_root
    }
    pub fn verify_integrity(&self) -> bool {
        certify_ontology_profile_v3(
            self.closure.clone(),
            self.audit.clone(),
            self.authority.clone(),
            self.limits,
            self.evidence.clone(),
            self.manifest.clone(),
        )
        .is_ok_and(|rebuilt| rebuilt == *self)
    }
}

fn category_name(category: OntologyMemberCategory) -> &'static str {
    match category {
        OntologyMemberCategory::Reasoned => "reasoned",
        OntologyMemberCategory::InferenceInertDeclaration => "inference-inert-declaration",
        OntologyMemberCategory::RetainedAnnotation => "retained-annotation",
        OntologyMemberCategory::RetainedUninterpretedSemantic => "retained-uninterpreted-semantic",
    }
}

fn scope_bound_artifact_root(
    kind: &str,
    artifact_root: &ContentHash,
    authority: &TrustedOntologyScopeAuthorityV3,
    analysis: &OntologyProfileV3Result,
    category: OntologyMemberCategory,
) -> ContentHash {
    let count = analysis.category_counts[&category].to_string();
    framed_root(
        "ctxql-ontology-profile-v3-gate3-artifact/v3",
        [
            ("kind", kind),
            ("artifact", artifact_root.as_str()),
            ("scope", authority.selected_scope()),
            ("scope-authority", authority.root().as_str()),
            (
                "dependency-universe",
                authority.dependency_universe_root().as_str(),
            ),
            (
                "dependency-limits",
                authority.dependency_limits_identity().as_str(),
            ),
            ("closure", authority.closure_root.as_str()),
            (
                "source-occurrences",
                authority.source_occurrence_root().as_str(),
            ),
            ("bundle", analysis.full_bundle_root.as_str()),
            ("audit", analysis.audit_root.as_str()),
            ("source-entry", analysis.source_entry_root.as_str()),
            ("category", category_name(category)),
            ("category-count", count.as_str()),
            ("category-root", analysis.category_roots[&category].as_str()),
            (
                "category-occurrences",
                analysis.category_occurrence_roots[&category].as_str(),
            ),
            ("families", analysis.family_root.as_str()),
            ("components", analysis.component_projection_root.as_str()),
            ("c0", analysis.ontology_c0_input_root.as_str()),
        ],
    )
}

pub fn scope_bound_gate3_roots(
    analysis: &OntologyProfileV3Result,
    authority: &TrustedOntologyScopeAuthorityV3,
    evidence: &OntologyProfileV3CertificationEvidence,
) -> Result<ScopeBoundGate3RootsV3> {
    let reasoned_raw = ContentHash::of_bytes(&evidence.reasoned_family_inventory_bytes);
    let parity_raw = ContentHash::of_bytes(&evidence.parity_matrix_bytes);
    Ok(ScopeBoundGate3RootsV3 {
        reasoned_family_inventory_root: scope_bound_artifact_root(
            "reasoned-family-inventory",
            &reasoned_raw,
            authority,
            analysis,
            OntologyMemberCategory::Reasoned,
        ),
        declaration_evidence_root: scope_bound_artifact_root(
            "declaration",
            &evidence.declaration_evidence.root(),
            authority,
            analysis,
            OntologyMemberCategory::InferenceInertDeclaration,
        ),
        uninterpreted_non_interference_root: scope_bound_artifact_root(
            "uninterpreted-non-interference",
            &evidence.uninterpreted_non_interference_evidence.root(),
            authority,
            analysis,
            OntologyMemberCategory::RetainedUninterpretedSemantic,
        ),
        parity_matrix_root: scope_bound_artifact_root(
            "parity",
            &parity_raw,
            authority,
            analysis,
            OntologyMemberCategory::Reasoned,
        ),
    })
}

pub fn certification_semantic_coverage_root(
    analysis: &OntologyProfileV3Result,
    authority: &TrustedOntologyScopeAuthorityV3,
    evidence: &OntologyProfileV3CertificationEvidence,
) -> Result<ContentHash> {
    let roots = scope_bound_gate3_roots(analysis, authority, evidence)?;
    let evidence_root = framed_root(
        "ctxql-ontology-profile-v3-gate3-evidence/v3",
        [
            ("scope", authority.selected_scope()),
            ("scope-authority", authority.root().as_str()),
            (
                "dependency-universe",
                authority.dependency_universe_root().as_str(),
            ),
            (
                "dependency-limits",
                authority.dependency_limits_identity().as_str(),
            ),
            (
                "source-occurrences",
                authority.source_occurrence_root().as_str(),
            ),
            (
                "reasoned-family-inventory",
                roots.reasoned_family_inventory_root.as_str(),
            ),
            ("declaration", roots.declaration_evidence_root.as_str()),
            (
                "uninterpreted-non-interference",
                roots.uninterpreted_non_interference_root.as_str(),
            ),
            ("parity", roots.parity_matrix_root.as_str()),
        ],
    );
    Ok(framed_root(
        "ctxql-ontology-semantic-coverage/v3-supported-subset",
        [
            ("profile", ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID),
            ("label", ONTOLOGY_PROFILE_V3_RESULT_LABEL),
            ("fluree-revision", PINNED_FLUREE_REVISION),
            (
                "candidate-coverage",
                analysis.semantic_coverage_root.as_str(),
            ),
            ("gate3-evidence", evidence_root.as_str()),
        ],
    ))
}

/// Promote only an exact integrity-verified closure/audit plus an explicit
/// runtime source/dependency/scope authority and closure-bound Gate-3 evidence.
pub fn certify_ontology_profile_v3(
    closure: AuditedOntologyClosure,
    audit: ConstructAuditResult,
    authority: TrustedOntologyScopeAuthorityV3,
    limits: OntologyProfileV3Limits,
    evidence: OntologyProfileV3CertificationEvidence,
    manifest: ExecutableProfileManifestV3,
) -> Result<CertifiedOntologyProfileV3> {
    if !authority.verify_integrity(&closure, &audit) || !audit.verify_integrity(&closure) {
        return Err(failure(
            ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
            "certification_source_authority_mismatch",
        ));
    }
    let analysis = classify_ontology_closure_v3_supported_subset(&closure, &audit, limits)?;
    let expected_artifacts = [
        (
            evidence.reasoned_family_inventory_bytes.as_slice(),
            include_bytes!("../../../fixtures/conformance/p5_6/direct-reasoner-inventory.json")
                .as_slice(),
        ),
        (
            evidence.parity_matrix_bytes.as_slice(),
            include_bytes!("../../../fixtures/conformance/p5_7/parity-applicability-matrix.json")
                .as_slice(),
        ),
    ];
    if expected_artifacts
        .iter()
        .any(|(actual, expected)| actual != expected)
    {
        return Err(failure(
            ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
            "certification_evidence_artifact_mismatch",
        ));
    }
    let roots = scope_bound_gate3_roots(&analysis, &authority, &evidence)?;
    let input = manifest.input();
    let manifest_root = manifest.root(cdb_core::Limits::default()).map_err(|_| {
        failure(
            ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
            "certification_manifest_invalid",
        )
    })?;
    let commitments = [
        (OntologyMemberCategory::Reasoned, &input.categories.reasoned),
        (
            OntologyMemberCategory::InferenceInertDeclaration,
            &input.categories.inference_inert_declaration,
        ),
        (
            OntologyMemberCategory::RetainedAnnotation,
            &input.categories.retained_annotation,
        ),
        (
            OntologyMemberCategory::RetainedUninterpretedSemantic,
            &input.categories.retained_uninterpreted_semantic,
        ),
    ];
    let categories_match = commitments.iter().all(|(category, commitment)| {
        u64::try_from(analysis.category_counts[category]).ok() == Some(commitment.count)
            && analysis.category_roots.get(category) == Some(&commitment.root)
            && analysis.category_occurrence_roots.get(category) == Some(&commitment.occurrence_root)
    });
    if input.selected_scope != authority.selected_scope
        || input.scope_authority_root != authority.root
        || input.acquisition_authority_root != authority.acquisition_authority_root
        || input.selected_source_release_id != authority.selected_source_release_id
        || input.selected_source_file_id != authority.selected_source_file_id
        || input.selected_ontology_iri != authority.selected_ontology_iri
        || input.source_member_root != authority.member_root
        || input.source_closure_root != authority.closure_root
        || input.dependency_universe_root != authority.dependency_universe_root
        || input.dependency_limits_identity != authority.dependency_limits_identity
        || input.source_occurrence_root != authority.source_occurrence_root
        || input.reasoned_family_inventory_root != roots.reasoned_family_inventory_root
        || input.declaration_evidence_root != roots.declaration_evidence_root
        || input.uninterpreted_non_interference_root != roots.uninterpreted_non_interference_root
        || input.parity_matrix_root != roots.parity_matrix_root
        || input.full_bundle_root != analysis.full_bundle_root
        || u64::try_from(analysis.full_bundle.len()).ok() != Some(input.full_bundle_count)
        || input.construct_audit_root != analysis.audit_root
        || input.source_entry_root != analysis.source_entry_root
        || !categories_match
        || input.annotation_policy_root != analysis.annotation_policy_root
        || input.registry_root != analysis.registry_root
        || input.family_root != analysis.family_root
        || input.component_projection_root != analysis.component_projection_root
        || input.caveat_set_root != analysis.caveat_set_root
        || input.ontology_c0_input_root != analysis.ontology_c0_input_root
        || u64::try_from(analysis.ontology_c0_input.len()).ok()
            != Some(input.ontology_c0_input_count)
        || input.profile_limits_identity != analysis.limits_identity
    {
        return Err(failure(
            ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
            "certification_manifest_commitment_mismatch",
        ));
    }
    let semantic_coverage_root =
        certification_semantic_coverage_root(&analysis, &authority, &evidence)?;
    if input.final_gate3_semantic_coverage_root != semantic_coverage_root {
        return Err(failure(
            ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
            "certification_coverage_commitment_mismatch",
        ));
    }
    let result_root = framed_root(
        "ctxql-ontology-profile-result/v3-supported-subset",
        [
            ("profile", ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID),
            ("label", ONTOLOGY_PROFILE_V3_RESULT_LABEL),
            ("fluree-revision", PINNED_FLUREE_REVISION),
            ("analysis", analysis.result_root.as_str()),
            ("coverage", semantic_coverage_root.as_str()),
            ("executable-profile", manifest_root.as_str()),
        ],
    );
    Ok(CertifiedOntologyProfileV3 {
        identity: ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID,
        result_label: ONTOLOGY_PROFILE_V3_RESULT_LABEL,
        closure,
        audit,
        authority,
        limits,
        analysis,
        evidence,
        manifest,
        semantic_coverage_root,
        result_root,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UninterpretedFamily {
    pub id: &'static str,
    pub shape: &'static str,
}

type FamilyDefinition = UninterpretedFamily;

// This is the closed set of shapes present in the exact Relations closure.
// Value- and qualifier-dependent rows are separate because pinned Fluree reads
// the same structural predicates for supported max-qualified class restrictions.
const FAMILIES: &[FamilyDefinition] = &[
    FamilyDefinition {
        id: "unqualified-min-cardinality-zero/v1",
        shape: "Restriction;onProperty=IRI;minCardinality=0^^xsd:nonNegativeInteger;no-qualifier",
    },
    FamilyDefinition {
        id: "qualified-min-cardinality-class-zero/v1",
        shape: "Restriction;onProperty=IRI;minQualifiedCardinality=0^^xsd:nonNegativeInteger;onClass=IRI",
    },
    FamilyDefinition {
        id: "qualified-min-cardinality-class-two/v1",
        shape: "Restriction;onProperty=IRI;minQualifiedCardinality=2^^xsd:nonNegativeInteger;onClass=IRI",
    },
    FamilyDefinition {
        id: "qualified-min-cardinality-class-three/v1",
        shape: "Restriction;onProperty=IRI;minQualifiedCardinality=3^^xsd:nonNegativeInteger;onClass=IRI",
    },
    FamilyDefinition {
        id: "qualified-min-cardinality-data-zero/v1",
        shape: "Restriction;onProperty=IRI;minQualifiedCardinality=0^^xsd:nonNegativeInteger;onDataRange=IRI",
    },
    FamilyDefinition {
        id: "qualified-exact-cardinality-class-one/v1",
        shape: "Restriction;onProperty=IRI;qualifiedCardinality=1^^xsd:nonNegativeInteger;onClass=IRI",
    },
    FamilyDefinition {
        id: "qualified-exact-cardinality-class-two/v1",
        shape: "Restriction;onProperty=IRI;qualifiedCardinality=2^^xsd:nonNegativeInteger;onClass=IRI",
    },
    FamilyDefinition {
        id: "qualified-exact-cardinality-data-one/v1",
        shape: "Restriction;onProperty=IRI;qualifiedCardinality=1^^xsd:nonNegativeInteger;onDataRange=IRI",
    },
    FamilyDefinition {
        id: "qualified-max-cardinality-data-one/v1",
        shape: "Restriction;onProperty=IRI;maxQualifiedCardinality=1^^xsd:nonNegativeInteger;onDataRange=IRI",
    },
    FamilyDefinition {
        id: "datatype-standalone-declaration/v1",
        shape: "IRI rdf:type rdfs:Datatype;no-structural-expression",
    },
    FamilyDefinition {
        id: "datatype-union-expression/v1",
        shape: "Datatype;equivalentClass;Datatype;unionOf;nonempty-IRI-list",
    },
    FamilyDefinition {
        id: "datatype-decimal-inclusive-facets/v1",
        shape: "range;Datatype;onDatatype=xsd:decimal;withRestrictions;two-node min/maxInclusive decimal list",
    },
    FamilyDefinition {
        id: "class-disjointness-edge/v1",
        shape: "IRI owl:disjointWith IRI",
    },
    FamilyDefinition {
        id: "property-disjointness-edge/v1",
        shape: "IRI owl:propertyDisjointWith IRI",
    },
];

const CAVEATS: &[SemanticCaveat] = &[
    SemanticCaveat {
        code: "minimum_exact_cardinalities_not_enforced",
        text: "minimum/exact cardinalities are not enforced",
    },
    SemanticCaveat {
        code: "data_range_datatype_facets_not_enforced",
        text: "qualified data-range/datatype facets are not enforced",
    },
    SemanticCaveat {
        code: "disjointness_violations_not_detected",
        text: "disjointness violations are not detected",
    },
    SemanticCaveat {
        code: "uninterpreted_axioms_excluded_from_admission",
        text: "uninterpreted axioms do not drive extraction/admission constraints",
    },
    SemanticCaveat {
        code: "answers_may_be_incomplete",
        text: "answers may be incomplete relative to OWL/FIBO",
    },
    SemanticCaveat {
        code: "no_fibo_compliance_inference",
        text: "absence of inconsistency is not proof of FIBO compliance",
    },
    SemanticCaveat {
        code: "poc_revision_profile_specific",
        text:
            "evidence is POC-, revision-, and profile-root-specific, not production/legal clearance",
    },
    SemanticCaveat {
        code: "fluree_storage_projection_blindly_blessed",
        text: "POC replay blesses Fluree's complete stored RDF projection even when blank-node identifiers, language-tag case, or typed-literal lexical forms differ from the source-exact bundle",
    },
];

pub fn uninterpreted_families() -> &'static [UninterpretedFamily] {
    FAMILIES
}

pub fn uninterpreted_family_ids() -> Vec<&'static str> {
    FAMILIES.iter().map(|family| family.id).collect()
}

pub fn semantic_caveats() -> &'static [SemanticCaveat] {
    CAVEATS
}

pub fn classify_ontology_closure_v3_supported_subset(
    closure: &AuditedOntologyClosure,
    audit: &ConstructAuditResult,
    limits: OntologyProfileV3Limits,
) -> Result<OntologyProfileV3Result> {
    if !audit.verify_integrity(closure) {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
            "construct_audit_integrity_mismatch",
        ));
    }
    if closure.bundle.len() > limits.max_bundle_quads
        || limits.max_bundle_quads == 0
        || limits.max_components == 0
        || limits.max_component_quads == 0
        || limits.max_structural_work == 0
    {
        return Err(failure(
            ONTOLOGY_PROFILE_LIMIT_EXCEEDED,
            "profile_limits_invalid_or_exceeded",
        ));
    }
    if audit.entries.iter().any(|entry| {
        matches!(
            entry.disposition,
            ConstructDisposition::Malformed | ConstructDisposition::Incomplete
        )
    }) {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
            "construct_audit_contains_invalid_structure",
        ));
    }

    let by_subject = subject_index(&closure.bundle);
    let incoming = incoming_index(&closure.bundle);
    let mut work = 0usize;
    let mut components = Vec::new();

    for quad in &closure.bundle {
        if quad.predicate == OWL_DISJOINT_WITH || quad.predicate == OWL_PROPERTY_DISJOINT_WITH {
            require_iri_edge(quad)?;
            let family_id = if quad.predicate == OWL_DISJOINT_WITH {
                "class-disjointness-edge/v1"
            } else {
                "property-disjointness-edge/v1"
            };
            components.push(make_component(
                family_id,
                quad.graph.clone(),
                quad.subject.clone(),
                BTreeSet::from([quad.clone()]),
                closure,
            )?);
        }
    }

    let mut restriction_roots = BTreeSet::new();
    let mut datatype_nodes = BTreeSet::new();
    for quad in &closure.bundle {
        if quad.predicate == RDF_TYPE && quad.object.as_iri() == Some(OWL_RESTRICTION) {
            restriction_roots.insert((quad.graph.clone(), quad.subject.clone()));
        }
        if quad.predicate == RDF_TYPE && quad.object.as_iri() == Some(RDFS_DATATYPE) {
            datatype_nodes.insert((quad.graph.clone(), quad.subject.clone()));
        }
    }

    for root in restriction_roots {
        add_work(&mut work, 1, limits.max_structural_work)?;
        if let Some((family, quads)) = restriction_component(&root, &by_subject, &incoming)? {
            if quads.len() > limits.max_component_quads {
                return Err(failure(
                    ONTOLOGY_PROFILE_LIMIT_EXCEEDED,
                    "component_quad_limit_exceeded",
                ));
            }
            components.push(make_component(
                family,
                root.0.clone(),
                root.1.clone(),
                quads,
                closure,
            )?);
        }
    }

    let datatype_top_roots = datatype_nodes
        .iter()
        .filter(|node| {
            !incoming.get(*node).is_some_and(|edges| {
                edges.iter().any(|edge| {
                    edge.predicate == OWL_EQUIVALENT_CLASS
                        && matches!(
                            edge.subject,
                            RdfNodeId::Iri(_) | RdfNodeId::ScopedBlankNode(_)
                        )
                })
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    for root in datatype_top_roots {
        let (family, quads) = datatype_component(
            &root,
            &by_subject,
            &incoming,
            &mut work,
            limits.max_structural_work,
        )?;
        if quads.len() > limits.max_component_quads {
            return Err(failure(
                ONTOLOGY_PROFILE_LIMIT_EXCEEDED,
                "component_quad_limit_exceeded",
            ));
        }
        components.push(make_component(
            family,
            root.0.clone(),
            root.1.clone(),
            quads,
            closure,
        )?);
    }

    if components.len() > limits.max_components {
        return Err(failure(
            ONTOLOGY_PROFILE_LIMIT_EXCEEDED,
            "component_count_limit_exceeded",
        ));
    }
    components.sort_by(|left, right| left.component_root.cmp(&right.component_root));

    let mut component_members = BTreeMap::<SourceQuad, &'static str>::new();
    for component in &components {
        for quad in &component.quads {
            if component_members
                .insert(quad.clone(), component.family_id)
                .is_some()
            {
                return Err(failure(
                    ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
                    "component_overlap",
                ));
            }
        }
    }

    let entry_dispositions = audit
        .entries
        .iter()
        .map(|entry| (entry.quad.clone(), entry.disposition))
        .collect::<BTreeMap<_, _>>();
    let mut categories = BTreeMap::<OntologyMemberCategory, BTreeSet<SourceQuad>>::new();
    for quad in &closure.bundle {
        let category = if component_members.contains_key(quad) {
            OntologyMemberCategory::RetainedUninterpretedSemantic
        } else if annotation_shape(quad)? {
            OntologyMemberCategory::RetainedAnnotation
        } else if is_named_individual_declaration(quad) {
            OntologyMemberCategory::InferenceInertDeclaration
        } else {
            match entry_dispositions.get(quad) {
                Some(ConstructDisposition::Unsupported) => {
                    return Err(failure(
                        ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
                        "unsupported_occurrence_unregistered",
                    ));
                }
                Some(
                    ConstructDisposition::ReasonedCandidate
                    | ConstructDisposition::RetainedAnnotationCandidate,
                ) => OntologyMemberCategory::Reasoned,
                Some(ConstructDisposition::DeclarationCandidate) => {
                    return Err(failure(
                        ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
                        "declaration_shape_changed",
                    ));
                }
                Some(ConstructDisposition::Malformed | ConstructDisposition::Incomplete) | None => {
                    return Err(failure(
                        ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
                        "audit_partition_mismatch",
                    ));
                }
            }
        };
        categories.entry(category).or_default().insert(quad.clone());
    }
    for category in [
        OntologyMemberCategory::Reasoned,
        OntologyMemberCategory::InferenceInertDeclaration,
        OntologyMemberCategory::RetainedAnnotation,
        OntologyMemberCategory::RetainedUninterpretedSemantic,
    ] {
        categories.entry(category).or_default();
    }
    let classified_count = categories.values().map(BTreeSet::len).sum::<usize>();
    if classified_count != closure.bundle.len() {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
            "category_partition_not_total",
        ));
    }

    let category_counts = categories
        .iter()
        .map(|(category, quads)| (*category, quads.len()))
        .collect::<BTreeMap<_, _>>();
    let category_roots = categories
        .iter()
        .map(|(category, quads)| (*category, quad_root(quads)))
        .collect::<BTreeMap<_, _>>();
    let category_occurrence_roots = categories
        .iter()
        .map(|(category, quads)| {
            let mut occurrence_ids = occurrence_ids_for(quads, closure);
            occurrence_ids.sort();
            (
                *category,
                framed_root(
                    "ctxql-ontology-profile-v3-category-occurrences/v1",
                    occurrence_ids
                        .iter()
                        .map(|value| ("occurrence", value.as_str())),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let registry_root = registry_root();
    let family_values = components
        .iter()
        .map(|component| {
            format!(
                "{}\0{}",
                component.family_id,
                component.component_root.as_str()
            )
        })
        .collect::<Vec<_>>();
    let family_root = framed_root(
        "ctxql-ontology-profile-v3-families/v1",
        family_values
            .iter()
            .map(|value| ("component", value.as_str())),
    );
    let component_projection_root = framed_root(
        "ctxql-ontology-profile-v3-component-projection/v1",
        [
            ("closure", closure.closure_root.as_str()),
            ("source-entries", audit.source_entry_root.as_str()),
            ("classification", audit.bundle_classification_root.as_str()),
            ("issues", audit.issue_root.as_str()),
            ("audit", audit.construct_audit_root.as_str()),
            ("registry", registry_root.as_str()),
            ("families", family_root.as_str()),
        ],
    );
    let annotation_policy_root = annotation_policy_root();
    let caveat_set_root = caveat_set_root();
    let full_bundle_root = quad_root(&closure.bundle);
    let ontology_c0_input = categories
        .iter()
        .filter(|(category, _)| **category != OntologyMemberCategory::RetainedAnnotation)
        .flat_map(|(_, quads)| quads.iter().cloned())
        .collect::<BTreeSet<_>>();
    let ontology_c0_input_root = quad_root(&ontology_c0_input);
    let limits_identity = limits.identity();
    let category_commitment = category_commitment(&category_counts, &category_roots);
    let category_occurrence_commitment = category_occurrence_commitment(&category_occurrence_roots);
    let semantic_coverage_root = framed_root(
        "ctxql-ontology-semantic-coverage-candidate/v3-supported-subset",
        [
            ("analysis", ONTOLOGY_PROFILE_V3_ANALYSIS_ID),
            ("label", ONTOLOGY_PROFILE_V3_ANALYSIS_LABEL),
            ("fluree-revision", PINNED_FLUREE_REVISION),
            ("registry", registry_root.as_str()),
            ("families", family_root.as_str()),
            ("categories", category_commitment.as_str()),
            (
                "category-occurrences",
                category_occurrence_commitment.as_str(),
            ),
            ("caveats", caveat_set_root.as_str()),
        ],
    );
    let result_root = framed_root(
        "ctxql-ontology-profile-analysis-result/v3-supported-subset",
        [
            ("analysis", ONTOLOGY_PROFILE_V3_ANALYSIS_ID),
            ("label", ONTOLOGY_PROFILE_V3_ANALYSIS_LABEL),
            ("fluree-revision", PINNED_FLUREE_REVISION),
            ("full-bundle", full_bundle_root.as_str()),
            ("audit", audit.construct_audit_root.as_str()),
            ("source-entries", audit.source_entry_root.as_str()),
            ("component-projection", component_projection_root.as_str()),
            ("registry", registry_root.as_str()),
            ("families", family_root.as_str()),
            ("annotations", annotation_policy_root.as_str()),
            ("categories", category_commitment.as_str()),
            (
                "category-occurrences",
                category_occurrence_commitment.as_str(),
            ),
            ("coverage", semantic_coverage_root.as_str()),
            ("caveats", caveat_set_root.as_str()),
            ("ontology-c0", ontology_c0_input_root.as_str()),
            ("limits", limits_identity.as_str()),
        ],
    );

    Ok(OntologyProfileV3Result {
        identity: ONTOLOGY_PROFILE_V3_ANALYSIS_ID,
        result_label: ONTOLOGY_PROFILE_V3_ANALYSIS_LABEL,
        full_bundle: closure.bundle.clone(),
        full_bundle_root,
        categories,
        category_counts,
        category_roots,
        category_occurrence_roots,
        components,
        component_projection_root,
        registry_root,
        family_root,
        annotation_policy_root,
        caveat_set_root,
        semantic_coverage_root,
        ontology_c0_input,
        ontology_c0_input_root,
        audit_root: audit.construct_audit_root.clone(),
        source_entry_root: audit.source_entry_root.clone(),
        limits_identity,
        result_root,
    })
}

/// Reclassifies an exact historical ledger bundle without consulting source
/// caches. Source-occurrence and original component-provenance roots cannot be
/// regenerated from RDF alone; they remain authenticated by the root-verified
/// executable manifest. Every semantic projection that can be recomputed from
/// the loaded RDF terms is checked exactly before C0 is returned.
pub fn verify_historical_ontology_bundle_v3_supported_subset(
    bundle: &BTreeSet<SourceQuad>,
    manifest: &ExecutableProfileManifestV3,
    limits: OntologyProfileV3Limits,
) -> Result<HistoricalOntologyProfileV3> {
    let expected = manifest.input();
    // POC storage projection: Fluree may rewrite blank-node labels, language-tag
    // case, and typed-literal lexical forms. The source-exact commitments remain
    // bound by the in-ledger executable manifest, while historical execution
    // deliberately blesses and separately roots the complete stored projection.
    // Counts, closed classification policy, and C0 membership must still hold.
    if u64::try_from(bundle.len()).ok() != Some(expected.full_bundle_count)
        || limits.identity() != expected.profile_limits_identity
    {
        return Err(failure(
            ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
            "historical_bundle_commitment_mismatch",
        ));
    }
    let closure =
        reconstruct_historical_audit_closure(bundle, expected.dependency_universe_root.clone())
            .map_err(|_| {
                failure(
                    ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
                    "historical_audit_projection_invalid",
                )
            })?;
    let audit =
        audit_ontology_closure(&closure, ConstructAuditLimits::default()).map_err(|_| {
            failure(
                ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
                "historical_construct_audit_failed",
            )
        })?;
    let rebuilt = classify_ontology_closure_v3_supported_subset(&closure, &audit, limits)?;

    let commitments = [
        (
            OntologyMemberCategory::Reasoned,
            &expected.categories.reasoned,
        ),
        (
            OntologyMemberCategory::InferenceInertDeclaration,
            &expected.categories.inference_inert_declaration,
        ),
        (
            OntologyMemberCategory::RetainedAnnotation,
            &expected.categories.retained_annotation,
        ),
        (
            OntologyMemberCategory::RetainedUninterpretedSemantic,
            &expected.categories.retained_uninterpreted_semantic,
        ),
    ];
    for (category, commitment) in commitments {
        if rebuilt
            .category_counts
            .get(&category)
            .copied()
            .and_then(|value| u64::try_from(value).ok())
            != Some(commitment.count)
        {
            return Err(failure(
                ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
                "historical_category_commitment_mismatch",
            ));
        }
    }
    if rebuilt.annotation_policy_root != expected.annotation_policy_root
        || rebuilt.registry_root != expected.registry_root
        || rebuilt.caveat_set_root != expected.caveat_set_root
        || u64::try_from(rebuilt.ontology_c0_input.len()).ok()
            != Some(expected.ontology_c0_input_count)
    {
        return Err(failure(
            ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
            "historical_semantic_projection_mismatch",
        ));
    }
    let manifest_root = manifest.root(cdb_core::Limits::default()).map_err(|_| {
        failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
            "historical_manifest_invalid",
        )
    })?;
    let stored_bundle_root = rebuilt.full_bundle_root.clone();
    let stored_c0_root = rebuilt.ontology_c0_input_root.clone();
    let verification_root = framed_root(
        "ctxql-historical-ontology-profile-verification/v3-supported-subset-poc-storage-v1",
        [
            ("executable-profile", manifest_root.as_str()),
            ("source-full-bundle", expected.full_bundle_root.as_str()),
            ("stored-full-bundle", stored_bundle_root.as_str()),
            (
                "source-ontology-c0",
                expected.ontology_c0_input_root.as_str(),
            ),
            ("stored-ontology-c0", stored_c0_root.as_str()),
            (
                "source-coverage",
                expected.final_gate3_semantic_coverage_root.as_str(),
            ),
            (
                "poc-caveat",
                "fluree_storage_projection_blindly_blessed_not_source_exact",
            ),
        ],
    );
    Ok(HistoricalOntologyProfileV3 {
        categories: rebuilt.categories,
        stored_bundle_root,
        ontology_c0_input: rebuilt.ontology_c0_input,
        stored_c0_root,
        verification_root,
    })
}

fn failure(public_code: &'static str, reason: &'static str) -> OntologyProfileV3Failure {
    OntologyProfileV3Failure {
        public_code,
        reason,
    }
}

fn subject_index(bundle: &BTreeSet<SourceQuad>) -> BTreeMap<NodeKey, Vec<&SourceQuad>> {
    let mut result: BTreeMap<NodeKey, Vec<&SourceQuad>> = BTreeMap::new();
    for quad in bundle {
        result
            .entry((quad.graph.clone(), quad.subject.clone()))
            .or_default()
            .push(quad);
    }
    result
}

fn incoming_index(bundle: &BTreeSet<SourceQuad>) -> BTreeMap<NodeKey, Vec<&SourceQuad>> {
    let mut result: BTreeMap<NodeKey, Vec<&SourceQuad>> = BTreeMap::new();
    for quad in bundle {
        if let ExactTerm::ScopedBlankNode(value) = &quad.object {
            result
                .entry((
                    quad.graph.clone(),
                    RdfNodeId::ScopedBlankNode(value.clone()),
                ))
                .or_default()
                .push(quad);
        }
    }
    result
}

fn restriction_component(
    root: &NodeKey,
    by_subject: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
    incoming: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
) -> Result<Option<(&'static str, BTreeSet<SourceQuad>)>> {
    let outgoing = by_subject.get(root).cloned().unwrap_or_default();
    let marker = exact_predicate(&outgoing, RDF_TYPE)?;
    if marker.object.as_iri() != Some(OWL_RESTRICTION) {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
            "restriction_marker_changed",
        ));
    }
    let on_property = exact_predicate(&outgoing, OWL_ON_PROPERTY)?;
    if on_property.object.as_iri().is_none() {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
            "restriction_property_not_iri",
        ));
    }
    let kinds = outgoing
        .iter()
        .copied()
        .filter(|quad| {
            matches!(
                quad.predicate.as_str(),
                OWL_MIN_CARDINALITY
                    | OWL_MIN_QUALIFIED_CARDINALITY
                    | OWL_QUALIFIED_CARDINALITY
                    | OWL_MAX_QUALIFIED_CARDINALITY
            )
        })
        .collect::<Vec<_>>();
    if kinds.is_empty() {
        return Ok(None);
    }
    if kinds.len() != 1 {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
            "restriction_kind_ambiguous",
        ));
    }
    let kind = kinds[0];
    let on_class = optional_predicate(&outgoing, OWL_ON_CLASS)?;
    let on_data = optional_predicate(&outgoing, OWL_ON_DATA_RANGE)?;
    let family = match (
        kind.predicate.as_str(),
        cardinality_value(&kind.object),
        on_class,
        on_data,
    ) {
        (OWL_MIN_CARDINALITY, Some(0), None, None) => "unqualified-min-cardinality-zero/v1",
        (OWL_MIN_QUALIFIED_CARDINALITY, Some(value @ (0 | 2 | 3)), Some(class), None)
            if class.object.as_iri().is_some() =>
        {
            match value {
                0 => "qualified-min-cardinality-class-zero/v1",
                2 => "qualified-min-cardinality-class-two/v1",
                3 => "qualified-min-cardinality-class-three/v1",
                _ => unreachable!("matched closed cardinality values"),
            }
        }
        (OWL_MIN_QUALIFIED_CARDINALITY, Some(0), None, Some(data))
            if data.object.as_iri().is_some() =>
        {
            "qualified-min-cardinality-data-zero/v1"
        }
        (OWL_QUALIFIED_CARDINALITY, Some(value @ (1 | 2)), Some(class), None)
            if class.object.as_iri().is_some() =>
        {
            match value {
                1 => "qualified-exact-cardinality-class-one/v1",
                2 => "qualified-exact-cardinality-class-two/v1",
                _ => unreachable!("matched closed cardinality values"),
            }
        }
        (OWL_QUALIFIED_CARDINALITY, Some(1), None, Some(data))
            if data.object.as_iri().is_some() =>
        {
            "qualified-exact-cardinality-data-one/v1"
        }
        (OWL_MAX_QUALIFIED_CARDINALITY, Some(1), None, Some(data))
            if data.object.as_iri().is_some() =>
        {
            "qualified-max-cardinality-data-one/v1"
        }
        (OWL_MAX_QUALIFIED_CARDINALITY, Some(1), Some(class), None)
            if class.object.as_iri().is_some() =>
        {
            return Ok(None);
        }
        _ => {
            return Err(failure(
                ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
                "restriction_shape_unregistered",
            ));
        }
    };
    let allowed = BTreeSet::from([
        RDF_TYPE,
        OWL_ON_PROPERTY,
        kind.predicate.as_str(),
        if on_class.is_some() {
            OWL_ON_CLASS
        } else {
            OWL_ON_DATA_RANGE
        },
    ]);
    if outgoing
        .iter()
        .any(|quad| !allowed.contains(quad.predicate.as_str()))
    {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
            "restriction_member_unregistered",
        ));
    }
    let owners = incoming.get(root).cloned().unwrap_or_default();
    if owners.len() != 1
        || !matches!(
            owners[0].predicate.as_str(),
            RDFS_SUBCLASS | OWL_EQUIVALENT_CLASS | OWL_SOME_VALUES_FROM | RDF_FIRST
        )
    {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
            "restriction_owner_ambiguous",
        ));
    }
    let mut quads = outgoing.into_iter().cloned().collect::<BTreeSet<_>>();
    quads.insert(owners[0].clone());
    Ok(Some((family, quads)))
}

fn datatype_component(
    root: &NodeKey,
    by_subject: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
    incoming: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
    work: &mut usize,
    max_work: usize,
) -> Result<(&'static str, BTreeSet<SourceQuad>)> {
    let mut quads = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut stack = vec![root.clone()];
    if matches!(root.1, RdfNodeId::ScopedBlankNode(_)) {
        let owners = incoming.get(root).cloned().unwrap_or_default();
        if owners.len() != 1 || owners[0].predicate != RDFS_RANGE {
            return Err(failure(
                ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
                "datatype_owner_ambiguous",
            ));
        }
        quads.insert(owners[0].clone());
    }
    while let Some(node) = stack.pop() {
        add_work(work, 1, max_work)?;
        if !visited.insert(node.clone()) {
            return Err(failure(
                ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
                "datatype_component_cycle_or_shared_node",
            ));
        }
        if matches!(node.1, RdfNodeId::ScopedBlankNode(_)) && node != *root {
            let owners = incoming.get(&node).cloned().unwrap_or_default();
            if owners.len() != 1 {
                return Err(failure(
                    ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
                    "datatype_structural_node_shared",
                ));
            }
        }
        let outgoing = by_subject.get(&node).cloned().unwrap_or_default();
        for quad in outgoing {
            if annotation_shape(quad)? {
                continue;
            }
            if !is_datatype_component_predicate(&quad.predicate) {
                if matches!(node.1, RdfNodeId::Iri(_)) {
                    // Named datatype resources may carry ordinary authored
                    // statements that are not part of the structural datatype
                    // expression. They are classified independently below.
                    continue;
                }
                return Err(failure(
                    ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
                    "datatype_member_unregistered",
                ));
            }
            quads.insert(quad.clone());
            if matches!(
                quad.predicate.as_str(),
                OWL_EQUIVALENT_CLASS | OWL_UNION_OF | OWL_WITH_RESTRICTIONS | RDF_FIRST | RDF_REST
            ) {
                if let ExactTerm::ScopedBlankNode(value) = &quad.object {
                    stack.push((
                        quad.graph.clone(),
                        RdfNodeId::ScopedBlankNode(value.clone()),
                    ));
                } else if quad.predicate == RDF_REST && quad.object.as_iri() != Some(RDF_NIL) {
                    return Err(failure(
                        ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
                        "datatype_list_tail_invalid",
                    ));
                }
            }
        }
    }
    let has_union = quads.iter().any(|quad| quad.predicate == OWL_UNION_OF);
    let has_facets = quads.iter().any(|quad| {
        matches!(
            quad.predicate.as_str(),
            XSD_MIN_INCLUSIVE | XSD_MAX_INCLUSIVE
        )
    });
    let family = if has_union {
        validate_union_datatype(&quads)?;
        "datatype-union-expression/v1"
    } else if has_facets {
        validate_facet_datatype(&quads)?;
        "datatype-decimal-inclusive-facets/v1"
    } else if matches!(root.1, RdfNodeId::Iri(_)) && quads.len() == 1 {
        "datatype-standalone-declaration/v1"
    } else {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
            "datatype_shape_unregistered",
        ));
    };
    Ok((family, quads))
}

fn validate_union_datatype(quads: &BTreeSet<SourceQuad>) -> Result<()> {
    if !quads
        .iter()
        .any(|quad| quad.predicate == OWL_EQUIVALENT_CLASS)
        || quads
            .iter()
            .filter(|quad| quad.predicate == OWL_UNION_OF)
            .count()
            != 1
        || !valid_closed_iri_list(quads)
        || quads.iter().any(|quad| {
            matches!(
                quad.predicate.as_str(),
                OWL_ON_DATATYPE | OWL_WITH_RESTRICTIONS
            )
        })
    {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
            "datatype_union_shape_changed",
        ));
    }
    Ok(())
}

fn validate_facet_datatype(quads: &BTreeSet<SourceQuad>) -> Result<()> {
    let on_datatype = quads
        .iter()
        .filter(|quad| quad.predicate == OWL_ON_DATATYPE)
        .collect::<Vec<_>>();
    let with_restrictions = quads
        .iter()
        .filter(|quad| quad.predicate == OWL_WITH_RESTRICTIONS)
        .count();
    let min = quads
        .iter()
        .filter(|quad| quad.predicate == XSD_MIN_INCLUSIVE)
        .collect::<Vec<_>>();
    let max = quads
        .iter()
        .filter(|quad| quad.predicate == XSD_MAX_INCLUSIVE)
        .collect::<Vec<_>>();
    if on_datatype.len() != 1
        || on_datatype[0].object.as_iri() != Some(XSD_DECIMAL)
        || with_restrictions != 1
        || min.len() != 1
        || max.len() != 1
        || !valid_decimal_literal(&min[0].object)
        || !valid_decimal_literal(&max[0].object)
        || !valid_closed_blank_list(quads, 2)
    {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
            "datatype_facet_shape_changed",
        ));
    }
    Ok(())
}

fn valid_closed_iri_list(quads: &BTreeSet<SourceQuad>) -> bool {
    valid_list(quads, None, |term| matches!(term, ExactTerm::Iri(_)))
}

fn valid_closed_blank_list(quads: &BTreeSet<SourceQuad>, expected: usize) -> bool {
    valid_list(quads, Some(expected), |term| {
        matches!(term, ExactTerm::ScopedBlankNode(_))
    })
}

fn valid_list(
    quads: &BTreeSet<SourceQuad>,
    expected: Option<usize>,
    member: impl Fn(&ExactTerm) -> bool,
) -> bool {
    let firsts = quads
        .iter()
        .filter(|quad| quad.predicate == RDF_FIRST)
        .collect::<Vec<_>>();
    let rests = quads
        .iter()
        .filter(|quad| quad.predicate == RDF_REST)
        .collect::<Vec<_>>();
    !firsts.is_empty()
        && expected.is_none_or(|count| firsts.len() == count)
        && firsts.len() == rests.len()
        && firsts.iter().all(|quad| member(&quad.object))
        && rests
            .iter()
            .filter(|quad| quad.object.as_iri() == Some(RDF_NIL))
            .count()
            == 1
}

fn is_datatype_component_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        RDF_TYPE
            | OWL_EQUIVALENT_CLASS
            | OWL_UNION_OF
            | OWL_ON_DATATYPE
            | OWL_WITH_RESTRICTIONS
            | RDF_FIRST
            | RDF_REST
            | XSD_MIN_INCLUSIVE
            | XSD_MAX_INCLUSIVE
    )
}

fn exact_predicate<'a>(outgoing: &'a [&SourceQuad], predicate: &str) -> Result<&'a SourceQuad> {
    let matches = outgoing
        .iter()
        .copied()
        .filter(|quad| quad.predicate == predicate)
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
            "component_member_count_invalid",
        ))
    }
}

fn optional_predicate<'a>(
    outgoing: &'a [&SourceQuad],
    predicate: &str,
) -> Result<Option<&'a SourceQuad>> {
    let matches = outgoing
        .iter()
        .copied()
        .filter(|quad| quad.predicate == predicate)
        .collect::<Vec<_>>();
    if matches.len() <= 1 {
        Ok(matches.first().copied())
    } else {
        Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
            "component_member_count_invalid",
        ))
    }
}

fn cardinality_value(term: &ExactTerm) -> Option<u8> {
    match term {
        ExactTerm::Literal {
            lexical,
            datatype,
            language: None,
        } if datatype == XSD_NON_NEGATIVE_INTEGER => lexical.parse().ok(),
        _ => None,
    }
}

fn valid_decimal_literal(term: &ExactTerm) -> bool {
    matches!(term, ExactTerm::Literal { lexical, datatype, language: None }
        if datatype == XSD_DECIMAL && xsd_decimal_lexical(lexical))
}

fn xsd_decimal_lexical(value: &str) -> bool {
    let unsigned = value
        .strip_prefix('+')
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or(value);
    if unsigned.is_empty()
        || unsigned
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && byte != b'.')
    {
        return false;
    }
    let mut parts = unsigned.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some() {
        return false;
    }
    match fraction {
        None => !whole.is_empty() && whole.bytes().all(|byte| byte.is_ascii_digit()),
        Some(fraction) => {
            (!whole.is_empty() || !fraction.is_empty())
                && whole.bytes().all(|byte| byte.is_ascii_digit())
                && fraction.bytes().all(|byte| byte.is_ascii_digit())
        }
    }
}

fn require_iri_edge(quad: &SourceQuad) -> Result<()> {
    if quad.subject.as_iri().is_none() || quad.object.as_iri().is_none() {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
            "disjointness_shape_unregistered",
        ));
    }
    Ok(())
}

fn is_named_individual_declaration(quad: &SourceQuad) -> bool {
    quad.subject.as_iri().is_some()
        && quad.predicate == RDF_TYPE
        && quad.object.as_iri() == Some(OWL_NAMED_INDIVIDUAL)
}

fn annotation_shape(quad: &SourceQuad) -> Result<bool> {
    let annotation_predicate = matches!(
        quad.predicate.as_str(),
        RDFS_LABEL
            | RDFS_COMMENT
            | RDFS_SEE_ALSO
            | RDFS_IS_DEFINED_BY
            | DCT_ABSTRACT
            | DCT_CONTRIBUTOR
            | DCT_ISSUED
            | DCT_LICENSE
            | DCT_MODIFIED
            | DCT_REFERENCES
            | DCT_SOURCE
            | DCT_TITLE
            | SKOS_CHANGE_NOTE
            | SKOS_DEFINITION
            | SKOS_EXAMPLE
            | SKOS_NOTE
            | SKOS_PREF_LABEL
            | SKOS_SCOPE_NOTE
            | "http://www.w3.org/2002/07/owl#versionInfo"
            | "http://www.w3.org/2002/07/owl#versionIRI"
            | "http://www.w3.org/2002/07/owl#priorVersion"
            | "http://www.w3.org/2002/07/owl#backwardCompatibleWith"
            | "http://www.w3.org/2002/07/owl#incompatibleWith"
            | "http://www.w3.org/2002/07/owl#deprecated"
    );
    if !annotation_predicate {
        if quad.predicate.starts_with("http://purl.org/dc/terms/")
            || quad
                .predicate
                .starts_with("http://www.w3.org/2004/02/skos/core#")
        {
            return Err(failure(
                ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
                "annotation_predicate_unregistered",
            ));
        }
        return Ok(false);
    }
    if quad.subject.as_iri().is_none() {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
            "annotation_subject_not_iri",
        ));
    }
    let valid = match quad.predicate.as_str() {
        RDFS_LABEL | RDFS_COMMENT => is_string_or_language_literal(&quad.object),
        RDFS_SEE_ALSO => {
            matches!(quad.object, ExactTerm::Iri(_)) || is_typed_literal(&quad.object, XSD_ANY_URI)
        }
        RDFS_IS_DEFINED_BY
        | "http://www.w3.org/2002/07/owl#versionIRI"
        | "http://www.w3.org/2002/07/owl#priorVersion"
        | "http://www.w3.org/2002/07/owl#backwardCompatibleWith"
        | "http://www.w3.org/2002/07/owl#incompatibleWith" => {
            matches!(quad.object, ExactTerm::Iri(_))
        }
        "http://www.w3.org/2002/07/owl#versionInfo" => {
            matches!(quad.object, ExactTerm::Iri(_)) || is_string_or_language_literal(&quad.object)
        }
        "http://www.w3.org/2002/07/owl#deprecated" => matches!(
            &quad.object,
            ExactTerm::Literal { lexical, datatype, language: None }
                if datatype == &format!("{XSD}boolean")
                    && matches!(lexical.as_str(), "true" | "false" | "1" | "0")
        ),
        DCT_ABSTRACT | DCT_CONTRIBUTOR | DCT_TITLE | SKOS_CHANGE_NOTE | SKOS_EXAMPLE
        | SKOS_PREF_LABEL | SKOS_SCOPE_NOTE => is_typed_literal(&quad.object, XSD_STRING),
        DCT_ISSUED | DCT_MODIFIED => is_typed_literal(&quad.object, XSD_DATE_TIME),
        DCT_LICENSE => {
            is_typed_literal(&quad.object, XSD_STRING)
                || is_typed_literal(&quad.object, XSD_ANY_URI)
        }
        DCT_REFERENCES => matches!(quad.object, ExactTerm::Iri(_)),
        DCT_SOURCE => {
            matches!(quad.object, ExactTerm::Iri(_))
                || is_string_or_language_literal(&quad.object)
                || is_typed_literal(&quad.object, XSD_ANY_URI)
        }
        SKOS_DEFINITION | SKOS_NOTE => is_string_or_language_literal(&quad.object),
        _ => false,
    };
    if valid {
        Ok(true)
    } else {
        Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
            "annotation_shape_unregistered",
        ))
    }
}

fn is_typed_literal(term: &ExactTerm, expected: &str) -> bool {
    matches!(term, ExactTerm::Literal { datatype, language: None, .. } if datatype == expected)
}

fn is_string_or_language_literal(term: &ExactTerm) -> bool {
    matches!(
        term,
        ExactTerm::Literal { datatype, language: None, .. } if datatype == XSD_STRING
    ) || matches!(
        term,
        ExactTerm::Literal { datatype, language: Some(language), .. }
            if datatype == RDF_LANG_STRING && !language.is_empty()
    )
}

fn make_component(
    family_id: &'static str,
    graph: String,
    root_node: RdfNodeId,
    quads: BTreeSet<SourceQuad>,
    closure: &AuditedOntologyClosure,
) -> Result<UninterpretedComponent> {
    if !FAMILIES.iter().any(|family| family.id == family_id) {
        return Err(failure(
            ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
            "family_not_registered",
        ));
    }
    let mut occurrence_identities = Vec::new();
    let mut source_owners = BTreeSet::new();
    let mut expected_owner_set: Option<BTreeSet<String>> = None;
    for quad in &quads {
        let occurrences = closure
            .occurrences
            .iter()
            .filter(|occurrence| {
                *quad
                    == SourceQuad {
                        graph: occurrence.graph.clone(),
                        subject: occurrence.subject.clone(),
                        predicate: occurrence.predicate.clone(),
                        object: occurrence.object.clone(),
                    }
            })
            .collect::<Vec<_>>();
        if occurrences.is_empty() {
            return Err(failure(
                ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
                "component_occurrence_missing",
            ));
        }
        let quad_owners = occurrences
            .iter()
            .map(|occurrence| {
                format!(
                    "{}\0{}\0{}",
                    occurrence.source_release_id,
                    occurrence.source_file_id,
                    occurrence.ontology_iri
                )
            })
            .collect::<BTreeSet<_>>();
        if expected_owner_set
            .as_ref()
            .is_some_and(|expected| expected != &quad_owners)
        {
            return Err(failure(
                ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED,
                "component_cross_source_inconsistent",
            ));
        }
        expected_owner_set.get_or_insert_with(|| quad_owners.clone());
        source_owners.extend(quad_owners);
        occurrence_identities.extend(
            occurrences
                .into_iter()
                .map(|occurrence| occurrence.occurrence_identity.clone()),
        );
    }
    occurrence_identities.sort();
    let quad_root = quad_root(&quads);
    let occurrence_root = framed_root(
        "ctxql-ontology-profile-v3-component-occurrences/v1",
        occurrence_identities
            .iter()
            .map(|value| ("occurrence", value.as_str())),
    );
    let owner_values = source_owners.into_iter().collect::<Vec<_>>();
    let owner_root = framed_root(
        "ctxql-ontology-profile-v3-component-owners/v1",
        owner_values.iter().map(|value| ("owner", value.as_str())),
    );
    let root_commitment = root_node.commitment();
    let component_root = framed_root(
        "ctxql-ontology-profile-v3-component/v1",
        [
            ("family", family_id),
            ("graph", graph.as_str()),
            ("root", root_commitment.as_str()),
            ("quads", quad_root.as_str()),
            ("occurrences", occurrence_root.as_str()),
            ("owners", owner_root.as_str()),
        ],
    );
    Ok(UninterpretedComponent {
        family_id,
        graph,
        root_node,
        quads,
        occurrence_identities,
        source_owners: owner_values,
        component_root,
    })
}

fn occurrence_ids_for(
    quads: &BTreeSet<SourceQuad>,
    closure: &AuditedOntologyClosure,
) -> Vec<ContentHash> {
    closure
        .occurrences
        .iter()
        .filter(|occurrence| {
            quads.contains(&SourceQuad {
                graph: occurrence.graph.clone(),
                subject: occurrence.subject.clone(),
                predicate: occurrence.predicate.clone(),
                object: occurrence.object.clone(),
            })
        })
        .map(|occurrence| occurrence.occurrence_identity.clone())
        .collect()
}

fn registry_root() -> ContentHash {
    let values = FAMILIES
        .iter()
        .map(|family| format!("{}\0{}", family.id, family.shape))
        .collect::<Vec<_>>();
    framed_root(
        "ctxql-ontology-uninterpreted-registry/v1",
        values.iter().map(|value| ("family", value.as_str())),
    )
}

fn annotation_policy_root() -> ContentHash {
    let values = [
        "rdfs:label|string-or-langString;iri-subject",
        "rdfs:comment|string-or-langString;iri-subject",
        "rdfs:seeAlso|iri-or-anyURI;iri-subject",
        "rdfs:isDefinedBy|iri;iri-subject",
        "owl:versionInfo|iri-or-string-or-langString;iri-subject",
        "owl:versionIRI|iri;iri-subject",
        "owl:priorVersion|iri;iri-subject",
        "owl:backwardCompatibleWith|iri;iri-subject",
        "owl:incompatibleWith|iri;iri-subject",
        "owl:deprecated|boolean;iri-subject",
        "dcterms:source|iri-or-string-or-langString-or-anyURI;iri-subject",
        "dcterms:abstract|string;iri-subject",
        "dcterms:contributor|string;iri-subject",
        "dcterms:issued|dateTime;iri-subject",
        "dcterms:license|string-or-anyURI;iri-subject",
        "dcterms:modified|dateTime;iri-subject",
        "dcterms:references|iri;iri-subject",
        "dcterms:title|string;iri-subject",
        "skos:definition|string-or-langString;iri-subject",
        "skos:note|string-or-langString;iri-subject",
        "skos:changeNote|string;iri-subject",
        "skos:example|string;iri-subject",
        "skos:prefLabel|string;iri-subject",
        "skos:scopeNote|string;iri-subject",
    ];
    framed_root(
        "ctxql-ontology-retained-annotation-policy/v3-supported-subset",
        values.iter().map(|value| ("shape", *value)),
    )
}

fn caveat_set_root() -> ContentHash {
    let values = CAVEATS
        .iter()
        .map(|caveat| format!("{}\0{}", caveat.code, caveat.text))
        .collect::<Vec<_>>();
    framed_root(
        "ctxql-ontology-caveat-set/v3-supported-subset",
        values.iter().map(|value| ("caveat", value.as_str())),
    )
}

fn category_commitment(
    counts: &BTreeMap<OntologyMemberCategory, usize>,
    roots: &BTreeMap<OntologyMemberCategory, ContentHash>,
) -> String {
    counts
        .iter()
        .map(|(category, count)| {
            format!(
                "{category:?}\0{count}\0{}",
                roots.get(category).expect("same category keys").as_str()
            )
        })
        .collect::<Vec<_>>()
        .join("\0")
}

fn category_occurrence_commitment(roots: &BTreeMap<OntologyMemberCategory, ContentHash>) -> String {
    roots
        .iter()
        .map(|(category, root)| format!("{category:?}\0{}", root.as_str()))
        .collect::<Vec<_>>()
        .join("\0")
}

fn add_work(work: &mut usize, amount: usize, max: usize) -> Result<()> {
    *work = work
        .checked_add(amount)
        .ok_or_else(|| failure(ONTOLOGY_PROFILE_LIMIT_EXCEEDED, "structural_work_overflow"))?;
    if *work > max {
        return Err(failure(
            ONTOLOGY_PROFILE_LIMIT_EXCEEDED,
            "structural_work_limit_exceeded",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ontology_construct_audit::OntologySourceOccurrence;

    #[test]
    fn historical_verifier_rebuilds_c0_without_original_source_occurrences() {
        use crate::executable_profile_v3::{
            CategoryCommitmentV3, CategoryCommitmentsV3, ExecutableProfileManifestV3Input,
        };

        let bundle = BTreeSet::from([
            SourceQuad {
                graph: "urn:test:schema".into(),
                subject: RdfNodeId::Iri("urn:test:C".into()),
                predicate: RDF_TYPE.into(),
                object: ExactTerm::Iri("http://www.w3.org/2002/07/owl#Class".into()),
            },
            SourceQuad {
                graph: "urn:test:schema".into(),
                subject: RdfNodeId::Iri("urn:test:C".into()),
                predicate: SKOS_DEFINITION.into(),
                object: ExactTerm::Literal {
                    lexical: "definition".into(),
                    datatype: RDF_LANG_STRING.into(),
                    language: Some("en".into()),
                },
            },
        ]);
        let dependency_root = ContentHash::of_bytes(b"dependency");
        let closure =
            reconstruct_historical_audit_closure(&bundle, dependency_root.clone()).unwrap();
        let audit = audit_ontology_closure(&closure, ConstructAuditLimits::default()).unwrap();
        let limits = OntologyProfileV3Limits::default();
        let analysis =
            classify_ontology_closure_v3_supported_subset(&closure, &audit, limits).unwrap();
        let commitment = |category| CategoryCommitmentV3 {
            count: analysis.category_counts[&category] as u64,
            root: analysis.category_roots[&category].clone(),
            occurrence_root: analysis.category_occurrence_roots[&category].clone(),
        };
        let manifest = ExecutableProfileManifestV3::new(
            ExecutableProfileManifestV3Input {
                selected_scope: RELATIONS_SCOPE.into(),
                scope_authority_root: ContentHash::of_bytes(b"historical test authority"),
                acquisition_authority_root: ContentHash::of_bytes(
                    b"historical acquisition authority",
                ),
                selected_source_release_id: "ctxql-historical-ledger/v1".into(),
                selected_source_file_id: "urn:test:schema".into(),
                selected_ontology_iri: "urn:test:schema".into(),
                source_member_root: ContentHash::of_bytes(b"historical source members"),
                source_closure_root: closure.closure_root.clone(),
                dependency_universe_root: dependency_root,
                full_bundle_root: analysis.full_bundle_root.clone(),
                full_bundle_count: analysis.full_bundle.len() as u64,
                construct_audit_root: analysis.audit_root.clone(),
                source_entry_root: analysis.source_entry_root.clone(),
                categories: CategoryCommitmentsV3 {
                    reasoned: commitment(OntologyMemberCategory::Reasoned),
                    inference_inert_declaration: commitment(
                        OntologyMemberCategory::InferenceInertDeclaration,
                    ),
                    retained_annotation: commitment(OntologyMemberCategory::RetainedAnnotation),
                    retained_uninterpreted_semantic: commitment(
                        OntologyMemberCategory::RetainedUninterpretedSemantic,
                    ),
                },
                annotation_policy_root: analysis.annotation_policy_root.clone(),
                registry_root: analysis.registry_root.clone(),
                family_root: analysis.family_root.clone(),
                component_projection_root: analysis.component_projection_root.clone(),
                source_occurrence_root: ContentHash::of_bytes(b"source occurrences"),
                reasoned_family_inventory_root: ContentHash::of_bytes(b"families"),
                declaration_evidence_root: ContentHash::of_bytes(b"declarations"),
                uninterpreted_non_interference_root: ContentHash::of_bytes(b"non interference"),
                parity_matrix_root: ContentHash::of_bytes(b"parity"),
                final_gate3_semantic_coverage_root: analysis.semantic_coverage_root.clone(),
                caveat_set_root: analysis.caveat_set_root.clone(),
                ontology_c0_input_root: analysis.ontology_c0_input_root.clone(),
                ontology_c0_input_count: analysis.ontology_c0_input.len() as u64,
                profile_limits_identity: analysis.limits_identity.clone(),
                dependency_limits_identity: ContentHash::of_bytes(b"dependency limits"),
            },
            cdb_core::Limits::default(),
        )
        .unwrap();

        let historical =
            verify_historical_ontology_bundle_v3_supported_subset(&bundle, &manifest, limits)
                .unwrap();
        assert_eq!(historical.ontology_c0_input, analysis.ontology_c0_input);

        let mut changed = bundle;
        changed.insert(SourceQuad {
            graph: "urn:test:schema".into(),
            subject: RdfNodeId::Iri("urn:test:C".into()),
            predicate: "http://www.w3.org/2002/07/owl#complementOf".into(),
            object: ExactTerm::Iri("urn:test:D".into()),
        });
        assert_eq!(
            verify_historical_ontology_bundle_v3_supported_subset(&changed, &manifest, limits)
                .unwrap_err()
                .public_code,
            ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH
        );
    }

    #[test]
    fn component_commits_consistent_many_to_many_source_owners() {
        let quad = SourceQuad {
            graph: "urn:test:graph".to_owned(),
            subject: RdfNodeId::from("urn:test:C"),
            predicate: OWL_DISJOINT_WITH.to_owned(),
            object: ExactTerm::Iri("urn:test:D".to_owned()),
        };
        let occurrences = ["a.rdf", "b.rdf"]
            .into_iter()
            .map(|file| OntologySourceOccurrence {
                source_release_id:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                source_file_id: file.to_owned(),
                ontology_iri: format!("urn:test:{file}"),
                conversion_root: ContentHash::of_bytes(file.as_bytes()),
                graph: quad.graph.clone(),
                subject: quad.subject.clone(),
                predicate: quad.predicate.clone(),
                object: quad.object.clone(),
                occurrence_identity: ContentHash::of_bytes(format!("occurrence:{file}").as_bytes()),
            })
            .collect::<Vec<_>>();
        let none = ContentHash::of_bytes(b"not-used-by-component-projection");
        let closure = AuditedOntologyClosure {
            members: Vec::new(),
            bundle: BTreeSet::from([quad.clone()]),
            occurrences,
            graph_map: BTreeMap::new(),
            dependency_root: none.clone(),
            source_quad_root: none.clone(),
            closure_root: none,
        };
        let component = make_component(
            "class-disjointness-edge/v1",
            quad.graph.clone(),
            quad.subject.clone(),
            BTreeSet::from([quad]),
            &closure,
        )
        .unwrap();
        assert_eq!(component.source_owners.len(), 2);
        assert_eq!(component.occurrence_identities.len(), 2);
    }
}
