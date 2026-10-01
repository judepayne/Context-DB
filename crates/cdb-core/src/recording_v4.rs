//! Portable P5.5 recording descriptors. Source RDF and inferred facts are never recorded.

use crate::{
    admission::{DependencyRecord, ExportRecord, Fact, FactTerm, ResourceKind},
    claim::TypedLiteral,
    contracts::ExecutionCaptures,
    id::{ContentHash, Iri, PrincipalId, ResourceId, RunId, VersionId},
    record_codec::{snapshot_from_value, snapshot_value},
    recording::RUN_PAYLOAD,
    recording_v3::ReplayDataV3,
    snapshot::SnapshotRef,
    storage_origin::INTERNAL_PREFIX,
    value::obj,
    CanonicalValue as V, Error, Limits, Result, Timestamp,
};

pub const REPLAY_SCHEMA: &str = "ctxql-replay-data/v4";
pub const RUN_SCHEMA: &str = "ctxql-recorded-run/v4";
pub const REPLAY_ABI: &str = "ctxql-execution/v4";
pub const ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID: &str =
    "ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v3-supported-subset";
pub const SUPPORTED_SUBSET_RESULT_LABEL: &str = "fluree_supported_subset";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticPolicyModeV4 {
    Unrestricted,
    Configured,
}

impl SemanticPolicyModeV4 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unrestricted => "unrestricted",
            Self::Configured => "configured",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "unrestricted" => Ok(Self::Unrestricted),
            "configured" => Ok(Self::Configured),
            _ => Err(Error::invalid("semantic policy mode")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSemanticMappingDescriptor {
    wire: V,
}

impl PreparedSemanticMappingDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capture: SnapshotRef,
        algorithm: VersionId,
        definition_root: ContentHash,
        definition_count: u64,
        resolver_root: ContentHash,
        resolver_count: u64,
        value_root: ContentHash,
        value_count: u64,
        dependency_root: ContentHash,
        prepared_ontology_root: ContentHash,
        limits: Limits,
    ) -> Result<Self> {
        Self::from_value(
            &obj([
                ("capture", snapshot_value(&capture)),
                ("algorithm", V::string(algorithm.as_str())),
                ("definition_root", V::string(definition_root.as_str())),
                ("definition_count", V::integer(definition_count)),
                ("resolver_root", V::string(resolver_root.as_str())),
                ("resolver_count", V::integer(resolver_count)),
                ("value_root", V::string(value_root.as_str())),
                ("value_count", V::integer(value_count)),
                ("dependency_root", V::string(dependency_root.as_str())),
                (
                    "prepared_ontology_root",
                    V::string(prepared_ontology_root.as_str()),
                ),
            ]),
            limits,
        )
    }

    pub fn none(
        capture: SnapshotRef,
        prepared_ontology_root: ContentHash,
        limits: Limits,
    ) -> Result<Self> {
        let none = ContentHash::of_bytes(b"ctxql-semantic-mapping/none/v1");
        Self::new(
            capture,
            VersionId::new("none/v1")?,
            none.clone(),
            0,
            none.clone(),
            0,
            none.clone(),
            0,
            none,
            prepared_ontology_root,
            limits,
        )
    }

    pub fn from_value(value: &V, limits: Limits) -> Result<Self> {
        value.closed(
            &[
                "capture",
                "algorithm",
                "definition_root",
                "definition_count",
                "resolver_root",
                "resolver_count",
                "value_root",
                "value_count",
                "dependency_root",
                "prepared_ontology_root",
            ],
            &[],
        )?;
        snapshot_from_value(value.field("capture")?, limits)?;
        let algorithm = VersionId::new(value.field("algorithm")?.as_str()?)?;
        let roots = [
            "definition_root",
            "resolver_root",
            "value_root",
            "dependency_root",
            "prepared_ontology_root",
        ]
        .into_iter()
        .map(|field| ContentHash::parse(value.field(field)?.as_str()?))
        .collect::<Result<Vec<_>>>()?;
        let definition_count = value.field("definition_count")?.as_number()?.to_u64()?;
        let resolver_count = value.field("resolver_count")?.as_number()?.to_u64()?;
        let value_count = value.field("value_count")?.as_number()?.to_u64()?;
        let maximum = u64::try_from(limits.values()).map_err(|_| Error::limit())?;
        if definition_count > maximum || resolver_count > maximum || value_count > maximum {
            return Err(Error::limit());
        }
        if algorithm.as_str() == "none/v1" {
            let none = ContentHash::of_bytes(b"ctxql-semantic-mapping/none/v1");
            if definition_count != 0
                || resolver_count != 0
                || value_count != 0
                || roots[..4].iter().any(|root| root != &none)
            {
                return Err(Error::invalid("semantic mapping none descriptor"));
            }
        } else if definition_count == 0 || resolver_count > definition_count {
            return Err(Error::invalid("semantic mapping descriptor counts"));
        }
        value.canonical_bytes(limits)?;
        Ok(Self {
            wire: value.clone(),
        })
    }

    pub fn projection(&self) -> V {
        self.wire.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportedSubsetEvidenceV4Input {
    pub construct_audit_root: ContentHash,
    pub executable_profile_root: ContentHash,
    pub reasoned_family_inventory_root: ContentHash,
    pub declaration_evidence_root: ContentHash,
    pub uninterpreted_non_interference_root: ContentHash,
    pub parity_matrix_root: ContentHash,
    pub reasoned_category_root: ContentHash,
    pub declaration_category_root: ContentHash,
    pub retained_annotation_category_root: ContentHash,
    pub retained_uninterpreted_category_root: ContentHash,
    pub registry_root: ContentHash,
    pub family_root: ContentHash,
    pub component_root: ContentHash,
    pub source_occurrence_root: ContentHash,
    pub annotation_policy_root: ContentHash,
    pub semantic_coverage_root: ContentHash,
    pub caveat_set_root: ContentHash,
    pub ontology_c0_input_root: ContentHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportedSubsetEvidenceV4 {
    wire: V,
}

impl SupportedSubsetEvidenceV4 {
    pub fn new(input: SupportedSubsetEvidenceV4Input, limits: Limits) -> Result<Self> {
        Self::from_value(
            &obj([
                ("result_label", V::string(SUPPORTED_SUBSET_RESULT_LABEL)),
                (
                    "construct_audit_root",
                    V::string(input.construct_audit_root.as_str()),
                ),
                (
                    "executable_profile_root",
                    V::string(input.executable_profile_root.as_str()),
                ),
                (
                    "reasoned_family_inventory_root",
                    V::string(input.reasoned_family_inventory_root.as_str()),
                ),
                (
                    "declaration_evidence_root",
                    V::string(input.declaration_evidence_root.as_str()),
                ),
                (
                    "uninterpreted_non_interference_root",
                    V::string(input.uninterpreted_non_interference_root.as_str()),
                ),
                (
                    "parity_matrix_root",
                    V::string(input.parity_matrix_root.as_str()),
                ),
                (
                    "reasoned_category_root",
                    V::string(input.reasoned_category_root.as_str()),
                ),
                (
                    "declaration_category_root",
                    V::string(input.declaration_category_root.as_str()),
                ),
                (
                    "retained_annotation_category_root",
                    V::string(input.retained_annotation_category_root.as_str()),
                ),
                (
                    "retained_uninterpreted_category_root",
                    V::string(input.retained_uninterpreted_category_root.as_str()),
                ),
                ("registry_root", V::string(input.registry_root.as_str())),
                ("family_root", V::string(input.family_root.as_str())),
                ("component_root", V::string(input.component_root.as_str())),
                (
                    "source_occurrence_root",
                    V::string(input.source_occurrence_root.as_str()),
                ),
                (
                    "annotation_policy_root",
                    V::string(input.annotation_policy_root.as_str()),
                ),
                (
                    "semantic_coverage_root",
                    V::string(input.semantic_coverage_root.as_str()),
                ),
                ("caveat_set_root", V::string(input.caveat_set_root.as_str())),
                (
                    "ontology_c0_input_root",
                    V::string(input.ontology_c0_input_root.as_str()),
                ),
            ]),
            limits,
        )
    }

    pub fn from_value(value: &V, limits: Limits) -> Result<Self> {
        value.closed(
            &[
                "result_label",
                "construct_audit_root",
                "executable_profile_root",
                "reasoned_family_inventory_root",
                "declaration_evidence_root",
                "uninterpreted_non_interference_root",
                "parity_matrix_root",
                "reasoned_category_root",
                "declaration_category_root",
                "retained_annotation_category_root",
                "retained_uninterpreted_category_root",
                "registry_root",
                "family_root",
                "component_root",
                "source_occurrence_root",
                "annotation_policy_root",
                "semantic_coverage_root",
                "caveat_set_root",
                "ontology_c0_input_root",
            ],
            &[],
        )?;
        if value.field("result_label")?.as_str()? != SUPPORTED_SUBSET_RESULT_LABEL {
            return Err(Error::invalid("supported subset result label"));
        }
        for field in [
            "construct_audit_root",
            "executable_profile_root",
            "reasoned_family_inventory_root",
            "declaration_evidence_root",
            "uninterpreted_non_interference_root",
            "parity_matrix_root",
            "reasoned_category_root",
            "declaration_category_root",
            "retained_annotation_category_root",
            "retained_uninterpreted_category_root",
            "registry_root",
            "family_root",
            "component_root",
            "source_occurrence_root",
            "annotation_policy_root",
            "semantic_coverage_root",
            "caveat_set_root",
            "ontology_c0_input_root",
        ] {
            ContentHash::parse(value.field(field)?.as_str()?)?;
        }
        value.canonical_bytes(limits)?;
        Ok(Self {
            wire: value.clone(),
        })
    }

    pub fn projection(&self) -> V {
        self.wire.clone()
    }

    pub fn hash_field(&self, name: &str) -> Result<ContentHash> {
        ContentHash::parse(self.wire.field(name)?.as_str()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticEvidenceV4Input {
    pub capture: SnapshotRef,
    pub requested_as_of: Option<Timestamp>,
    pub policy_mode: SemanticPolicyModeV4,
    pub policy_dependency_root: ContentHash,
    pub policy_source_observation: ResourceId,
    pub principal: PrincipalId,
    pub action: Iri,
    pub historical_config_root: ContentHash,
    pub graph_role_map_root: ContentHash,
    pub configuration_graph: Iri,
    pub governed_data_graphs: Vec<Iri>,
    pub claim_graphs: Vec<Iri>,
    pub schema_source: Iri,
    pub schema_graphs: Vec<Iri>,
    pub follow_owl_imports: bool,
    pub data_root: ContentHash,
    pub schema_root: ContentHash,
    /// Sorted, duplicate-free hashes of the canonical source-quad commitments.
    /// These select source members without persisting RDF payloads.
    pub data_commitments: Vec<ContentHash>,
    pub schema_commitments: Vec<ContentHash>,
    /// Sorted, duplicate-free identifiers for the originally visible supports.
    pub visible_support_ids: Vec<Iri>,
    pub authorized_data_quads: u64,
    pub authorized_schema_quads: u64,
    pub visible_supports: u64,
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
    pub prepared_root: ContentHash,
    pub semantic_codec: VersionId,
    pub commitment_algorithm: VersionId,
    pub extraction_algorithm: VersionId,
    pub materializer: VersionId,
    pub reasoner: VersionId,
    pub budget_identity: ContentHash,
    pub diagnostics_root: ContentHash,
    pub completeness_selector: String,
    pub completeness_evidence: ContentHash,
    pub mapping: PreparedSemanticMappingDescriptor,
    pub supported_subset: Option<SupportedSubsetEvidenceV4>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticEvidenceV4 {
    wire: V,
}

impl SemanticEvidenceV4 {
    pub fn new(input: SemanticEvidenceV4Input, limits: Limits) -> Result<Self> {
        let supported_subset = input.supported_subset.map(|value| value.projection());
        let mut wire = obj([
            ("capture", snapshot_value(&input.capture)),
            (
                "requested_as_of",
                input
                    .requested_as_of
                    .map_or(V::Null, |value| V::string(value.canonical())),
            ),
            ("policy_mode", V::string(input.policy_mode.as_str())),
            (
                "policy_dependency_root",
                V::string(input.policy_dependency_root.as_str()),
            ),
            (
                "policy_source_observation",
                V::string(input.policy_source_observation.as_str()),
            ),
            ("principal", V::string(input.principal.as_str())),
            ("action", V::string(input.action.as_str())),
            (
                "historical_config_root",
                V::string(input.historical_config_root.as_str()),
            ),
            (
                "graph_role_map_root",
                V::string(input.graph_role_map_root.as_str()),
            ),
            (
                "configuration_graph",
                V::string(input.configuration_graph.as_str()),
            ),
            (
                "governed_data_graphs",
                V::Array(
                    input
                        .governed_data_graphs
                        .into_iter()
                        .map(|value| V::string(value.as_str()))
                        .collect(),
                ),
            ),
            (
                "claim_graphs",
                V::Array(
                    input
                        .claim_graphs
                        .into_iter()
                        .map(|value| V::string(value.as_str()))
                        .collect(),
                ),
            ),
            ("schema_source", V::string(input.schema_source.as_str())),
            (
                "schema_graphs",
                V::Array(
                    input
                        .schema_graphs
                        .into_iter()
                        .map(|value| V::string(value.as_str()))
                        .collect(),
                ),
            ),
            ("follow_owl_imports", V::Bool(input.follow_owl_imports)),
            ("data_root", V::string(input.data_root.as_str())),
            ("schema_root", V::string(input.schema_root.as_str())),
            (
                "data_commitments",
                V::Array(
                    input
                        .data_commitments
                        .into_iter()
                        .map(|value| V::string(value.as_str()))
                        .collect(),
                ),
            ),
            (
                "schema_commitments",
                V::Array(
                    input
                        .schema_commitments
                        .into_iter()
                        .map(|value| V::string(value.as_str()))
                        .collect(),
                ),
            ),
            (
                "visible_support_ids",
                V::Array(
                    input
                        .visible_support_ids
                        .into_iter()
                        .map(|value| V::string(value.as_str()))
                        .collect(),
                ),
            ),
            (
                "authorized_data_quads",
                V::integer(input.authorized_data_quads),
            ),
            (
                "authorized_schema_quads",
                V::integer(input.authorized_schema_quads),
            ),
            ("visible_supports", V::integer(input.visible_supports)),
            (
                "authorized_premise_root",
                V::string(input.authorized_premise_root.as_str()),
            ),
            (
                "execution_manifest_root",
                V::string(input.execution_manifest_root.as_str()),
            ),
            (
                "ontology_profile",
                V::string(input.ontology_profile.as_str()),
            ),
            (
                "full_ontology_bundle_root",
                V::string(input.full_ontology_bundle_root.as_str()),
            ),
            (
                "ontology_profile_result_root",
                V::string(input.ontology_profile_result_root.as_str()),
            ),
            (
                "reasoner_input_root",
                V::string(input.reasoner_input_root.as_str()),
            ),
            (
                "structural_mapping_algorithm",
                V::string(input.structural_mapping_algorithm.as_str()),
            ),
            (
                "profile_limits_identity",
                V::string(input.profile_limits_identity.as_str()),
            ),
            (
                "materialization_limits_identity",
                V::string(input.materialization_limits_identity.as_str()),
            ),
            (
                "reasoning_limits_identity",
                V::string(input.reasoning_limits_identity.as_str()),
            ),
            ("prepared_root", V::string(input.prepared_root.as_str())),
            ("semantic_codec", V::string(input.semantic_codec.as_str())),
            (
                "commitment_algorithm",
                V::string(input.commitment_algorithm.as_str()),
            ),
            (
                "extraction_algorithm",
                V::string(input.extraction_algorithm.as_str()),
            ),
            ("materializer", V::string(input.materializer.as_str())),
            ("reasoner", V::string(input.reasoner.as_str())),
            ("budget_identity", V::string(input.budget_identity.as_str())),
            (
                "diagnostics_root",
                V::string(input.diagnostics_root.as_str()),
            ),
            (
                "completeness_selector",
                V::string(input.completeness_selector),
            ),
            (
                "completeness_evidence",
                V::string(input.completeness_evidence.as_str()),
            ),
            ("mapping", input.mapping.projection()),
        ]);
        if let Some(supported_subset) = supported_subset {
            let V::Object(fields) = &mut wire else {
                unreachable!("canonical object constructor returned non-object")
            };
            fields.insert("supported_subset".to_owned(), supported_subset);
        }
        Self::from_value(&wire, limits)
    }

    pub fn from_value(value: &V, limits: Limits) -> Result<Self> {
        value.closed(
            &[
                "capture",
                "requested_as_of",
                "policy_mode",
                "policy_dependency_root",
                "policy_source_observation",
                "principal",
                "action",
                "historical_config_root",
                "graph_role_map_root",
                "configuration_graph",
                "governed_data_graphs",
                "claim_graphs",
                "schema_source",
                "schema_graphs",
                "follow_owl_imports",
                "data_root",
                "schema_root",
                "data_commitments",
                "schema_commitments",
                "visible_support_ids",
                "authorized_data_quads",
                "authorized_schema_quads",
                "visible_supports",
                "authorized_premise_root",
                "execution_manifest_root",
                "ontology_profile",
                "full_ontology_bundle_root",
                "ontology_profile_result_root",
                "reasoner_input_root",
                "structural_mapping_algorithm",
                "profile_limits_identity",
                "materialization_limits_identity",
                "reasoning_limits_identity",
                "prepared_root",
                "semantic_codec",
                "commitment_algorithm",
                "extraction_algorithm",
                "materializer",
                "reasoner",
                "budget_identity",
                "diagnostics_root",
                "completeness_selector",
                "completeness_evidence",
                "mapping",
            ],
            &["supported_subset"],
        )?;
        let capture = snapshot_from_value(value.field("capture")?, limits)?;
        let mapping =
            PreparedSemanticMappingDescriptor::from_value(value.field("mapping")?, limits)?;
        if snapshot_from_value(mapping.projection().field("capture")?, limits)? != capture
            || mapping
                .projection()
                .field("prepared_ontology_root")?
                .as_str()?
                != value.field("prepared_root")?.as_str()?
        {
            return Err(Error::invalid("semantic mapping evidence binding"));
        }
        let requested = value.field("requested_as_of")?;
        if !matches!(requested, V::Null) {
            Timestamp::parse(requested.as_str()?)?;
        }
        SemanticPolicyModeV4::parse(value.field("policy_mode")?.as_str()?)?;
        for field in [
            "policy_dependency_root",
            "historical_config_root",
            "graph_role_map_root",
            "data_root",
            "schema_root",
            "authorized_premise_root",
            "execution_manifest_root",
            "full_ontology_bundle_root",
            "ontology_profile_result_root",
            "reasoner_input_root",
            "profile_limits_identity",
            "materialization_limits_identity",
            "reasoning_limits_identity",
            "prepared_root",
            "budget_identity",
            "diagnostics_root",
            "completeness_evidence",
        ] {
            ContentHash::parse(value.field(field)?.as_str()?)?;
        }
        ResourceId::new(value.field("policy_source_observation")?.as_str()?)?;
        PrincipalId::new(value.field("principal")?.as_str()?)?;
        Iri::new(value.field("action")?.as_str()?)?;
        let configuration_graph = Iri::new(value.field("configuration_graph")?.as_str()?)?;
        let governed = validate_iri_array_bounded(value.field("governed_data_graphs")?, limits)?;
        let claims = validate_iri_array_bounded(value.field("claim_graphs")?, limits)?;
        let schema_source = Iri::new(value.field("schema_source")?.as_str()?)?;
        let schemas = validate_iri_array_bounded(value.field("schema_graphs")?, limits)?;
        if claims.iter().any(|graph| !governed.contains(graph))
            || governed.contains(&configuration_graph)
            || governed.contains(&schema_source)
            || schemas.iter().any(|graph| governed.contains(graph))
        {
            return Err(Error::invalid("semantic graph role overlap"));
        }
        value.field("follow_owl_imports")?.as_bool()?;
        for field in [
            "semantic_codec",
            "commitment_algorithm",
            "extraction_algorithm",
            "ontology_profile",
            "structural_mapping_algorithm",
            "materializer",
            "reasoner",
        ] {
            VersionId::new(value.field(field)?.as_str()?)?;
        }
        let ontology_profile = value.field("ontology_profile")?.as_str()?;
        match (
            ontology_profile == ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID,
            value.as_object()?.get("supported_subset"),
        ) {
            (true, Some(supported_subset)) => {
                SupportedSubsetEvidenceV4::from_value(supported_subset, limits)?;
            }
            (false, None) => {}
            (true, None) => {
                return Err(Error::invalid("supported subset evidence missing"));
            }
            (false, Some(_)) => {
                return Err(Error::invalid("supported subset evidence unexpected"));
            }
        }
        let completeness_selector = value.field("completeness_selector")?.as_str()?;
        if completeness_selector.is_empty()
            || completeness_selector.len() > limits.input_bytes()
            || ContentHash::of_bytes(completeness_selector.as_bytes())
                != ContentHash::parse(value.field("completeness_evidence")?.as_str()?)?
        {
            return Err(Error::invalid("semantic completeness selector"));
        }
        let data_commitments = validate_hash_array(value.field("data_commitments")?, limits)?;
        let schema_commitments = validate_hash_array(value.field("schema_commitments")?, limits)?;
        let support_ids = validate_iri_array_bounded(value.field("visible_support_ids")?, limits)?;
        let data_count = value
            .field("authorized_data_quads")?
            .as_number()?
            .to_u64()?;
        let schema_count = value
            .field("authorized_schema_quads")?
            .as_number()?
            .to_u64()?;
        let support_count = value.field("visible_supports")?.as_number()?.to_u64()?;
        if usize::try_from(data_count).ok() != Some(data_commitments.len())
            || usize::try_from(schema_count).ok() != Some(schema_commitments.len())
            || usize::try_from(support_count).ok() != Some(support_ids.len())
        {
            return Err(Error::invalid("semantic member commitment count"));
        }
        value.canonical_bytes(limits)?;
        Ok(Self {
            wire: value.clone(),
        })
    }

    pub fn projection(&self) -> V {
        self.wire.clone()
    }

    pub fn capture(&self, limits: Limits) -> Result<SnapshotRef> {
        snapshot_from_value(self.wire.field("capture")?, limits)
    }

    pub fn requested_as_of(&self) -> Result<Option<Timestamp>> {
        match self.wire.field("requested_as_of")? {
            V::Null => Ok(None),
            value => Ok(Some(Timestamp::parse(value.as_str()?)?)),
        }
    }

    pub fn principal(&self) -> Result<PrincipalId> {
        PrincipalId::new(self.wire.field("principal")?.as_str()?)
    }

    pub fn action(&self) -> Result<Iri> {
        Iri::new(self.wire.field("action")?.as_str()?)
    }

    pub fn data_commitments(&self, limits: Limits) -> Result<Vec<ContentHash>> {
        validate_hash_array(self.wire.field("data_commitments")?, limits)
    }

    pub fn schema_commitments(&self, limits: Limits) -> Result<Vec<ContentHash>> {
        validate_hash_array(self.wire.field("schema_commitments")?, limits)
    }

    pub fn visible_support_ids(&self, limits: Limits) -> Result<Vec<Iri>> {
        validate_iri_array_bounded(self.wire.field("visible_support_ids")?, limits)
    }

    pub fn hash_field(&self, name: &str) -> Result<ContentHash> {
        ContentHash::parse(self.wire.field(name)?.as_str()?)
    }

    pub fn version_field(&self, name: &str) -> Result<VersionId> {
        VersionId::new(self.wire.field(name)?.as_str()?)
    }

    pub fn string_field(&self, name: &str) -> Result<&str> {
        self.wire.field(name)?.as_str()
    }

    pub fn mapping(&self, limits: Limits) -> Result<PreparedSemanticMappingDescriptor> {
        PreparedSemanticMappingDescriptor::from_value(self.wire.field("mapping")?, limits)
    }

    pub fn supported_subset(&self, limits: Limits) -> Result<Option<SupportedSubsetEvidenceV4>> {
        self.wire
            .as_object()?
            .get("supported_subset")
            .map(|value| SupportedSubsetEvidenceV4::from_value(value, limits))
            .transpose()
    }
}

fn validate_iri_array_bounded(value: &V, limits: Limits) -> Result<Vec<Iri>> {
    let array = value.as_array()?;
    if array.len() > limits.values() {
        return Err(Error::limit());
    }
    let mut bytes = 0usize;
    let mut values = Vec::with_capacity(array.len());
    for item in array {
        let text = item.as_str()?;
        bytes = bytes.checked_add(text.len()).ok_or_else(Error::limit)?;
        if bytes > limits.input_bytes() {
            return Err(Error::limit());
        }
        let iri = Iri::new(text)?;
        if values.last().is_some_and(|old| old >= &iri) {
            return Err(Error::invalid("semantic selector order/duplicate"));
        }
        values.push(iri);
    }
    Ok(values)
}

fn validate_hash_array(value: &V, limits: Limits) -> Result<Vec<ContentHash>> {
    let array = value.as_array()?;
    if array.len() > limits.values() {
        return Err(Error::limit());
    }
    let mut bytes = 0usize;
    let mut values = Vec::with_capacity(array.len());
    for item in array {
        let text = item.as_str()?;
        bytes = bytes.checked_add(text.len()).ok_or_else(Error::limit)?;
        if bytes > limits.input_bytes() {
            return Err(Error::limit());
        }
        let hash = ContentHash::parse(text)?;
        if values.last().is_some_and(|old| old >= &hash) {
            return Err(Error::invalid("semantic commitment order/duplicate"));
        }
        values.push(hash);
    }
    Ok(values)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayDataV4 {
    base: ReplayDataV3,
    semantic: SemanticEvidenceV4,
    control_capture: SnapshotRef,
    wire: V,
}

impl ReplayDataV4 {
    /// V4-only construction binds both immutable execution roles. V2/V3 wire
    /// formats remain single-capture and never receive this container.
    pub fn new(
        base: ReplayDataV3,
        semantic: SemanticEvidenceV4,
        captures: &ExecutionCaptures,
        limits: Limits,
    ) -> Result<Self> {
        let semantic_capture =
            snapshot_from_value(semantic.projection().field("capture")?, limits)?;
        if semantic_capture != captures.semantic().snapshot {
            return Err(Error::invalid("v4 semantic capture identity"));
        }
        Self::from_value(
            &obj([
                ("schema", V::string(REPLAY_SCHEMA)),
                ("base", base.projection()),
                ("semantic", semantic.projection()),
                ("control_capture", snapshot_value(captures.control())),
            ]),
            limits,
        )
    }

    pub fn from_value(value: &V, limits: Limits) -> Result<Self> {
        value.closed(&["schema", "base", "semantic", "control_capture"], &[])?;
        if value.field("schema")?.as_str()? != REPLAY_SCHEMA {
            return Err(Error::invalid("v4 replay schema"));
        }
        let base = ReplayDataV3::from_value(value.field("base")?, limits)?;
        let semantic = SemanticEvidenceV4::from_value(value.field("semantic")?, limits)?;
        let control_capture = snapshot_from_value(value.field("control_capture")?, limits)?;
        let semantic_capture =
            snapshot_from_value(semantic.projection().field("capture")?, limits)?;
        let base_capture = snapshot_from_value(base.projection().field("snapshot")?, limits)?;
        if base_capture != semantic_capture || control_capture == semantic_capture {
            return Err(Error::invalid("v4 dual capture identity"));
        }
        value.canonical_bytes(limits)?;
        Ok(Self {
            base,
            semantic,
            control_capture,
            wire: value.clone(),
        })
    }

    pub fn base(&self) -> &ReplayDataV3 {
        &self.base
    }

    pub fn semantic(&self) -> &SemanticEvidenceV4 {
        &self.semantic
    }

    pub fn control_capture(&self) -> &SnapshotRef {
        &self.control_capture
    }

    pub fn projection(&self) -> V {
        self.wire.clone()
    }

    pub fn bytes(&self, limits: Limits) -> Result<Vec<u8>> {
        self.wire.canonical_bytes(limits)
    }

    pub fn read(bytes: &[u8], limits: Limits) -> Result<Self> {
        Self::from_value(&V::parse(bytes, limits)?, limits)
    }

    pub fn verify_semantics(&self, replay: &Self) -> Result<()> {
        self.base.verify_semantics(&replay.base)?;
        if self.semantic != replay.semantic || self.control_capture != replay.control_capture {
            return Err(Error::invalid("v4 semantic replay divergence"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunEnvelopeV4 {
    id: RunId,
    owner: PrincipalId,
    operation_hash: ContentHash,
    replay: ReplayDataV4,
}

impl RunEnvelopeV4 {
    pub fn new(
        id: RunId,
        owner: PrincipalId,
        operation_hash: ContentHash,
        replay: ReplayDataV4,
        limits: Limits,
    ) -> Result<Self> {
        let value = obj([
            ("schema", V::string(RUN_SCHEMA)),
            ("id", V::string(id.as_str())),
            ("owner", V::string(owner.as_str())),
            ("operation_hash", V::string(operation_hash.as_str())),
            ("replay", replay.projection()),
        ]);
        value.canonical_bytes(limits)?;
        Ok(Self {
            id,
            owner,
            operation_hash,
            replay,
        })
    }

    pub fn id(&self) -> &RunId {
        &self.id
    }

    pub fn owner(&self) -> &PrincipalId {
        &self.owner
    }

    pub fn operation_hash(&self) -> &ContentHash {
        &self.operation_hash
    }

    pub fn projection(&self) -> V {
        obj([
            ("schema", V::string(RUN_SCHEMA)),
            ("id", V::string(self.id.as_str())),
            ("owner", V::string(self.owner.as_str())),
            ("operation_hash", V::string(self.operation_hash.as_str())),
            ("replay", self.replay.projection()),
        ])
    }

    pub fn from_value(value: &V, limits: Limits) -> Result<Self> {
        value.closed(&["schema", "id", "owner", "operation_hash", "replay"], &[])?;
        if value.field("schema")?.as_str()? != RUN_SCHEMA {
            return Err(Error::invalid("v4 run schema"));
        }
        Self::new(
            RunId::new(value.field("id")?.as_str()?)?,
            PrincipalId::new(value.field("owner")?.as_str()?)?,
            ContentHash::parse(value.field("operation_hash")?.as_str()?)?,
            ReplayDataV4::from_value(value.field("replay")?, limits)?,
            limits,
        )
    }

    pub fn bytes(&self, limits: Limits) -> Result<Vec<u8>> {
        self.projection().canonical_bytes(limits)
    }

    pub fn read(bytes: &[u8], limits: Limits) -> Result<Self> {
        Self::from_value(&V::parse(bytes, limits)?, limits)
    }

    pub fn replay(&self) -> &ReplayDataV4 {
        &self.replay
    }

    pub fn integrity_hash(&self, limits: Limits) -> Result<ContentHash> {
        Ok(ContentHash::of_bytes(&self.bytes(limits)?))
    }

    pub fn descriptor_id(&self) -> Result<ResourceId> {
        ResourceId::new(format!(
            "{INTERNAL_PREFIX}run/{}",
            ContentHash::of_bytes(self.id.as_str().as_bytes()).as_str()
        ))
    }

    pub fn to_record(&self, limits: Limits) -> Result<ExportRecord> {
        let bytes = self.bytes(limits)?;
        Ok(ExportRecord::Resource(DependencyRecord::new(
            "ctxql-resource/v1",
            self.descriptor_id()?,
            ResourceKind::RunDescriptor,
            vec![Fact::new(
                Iri::new(RUN_PAYLOAD)?,
                FactTerm::Literal(TypedLiteral::new(
                    Iri::new(XSD_STRING)?,
                    V::string(String::from_utf8(bytes).map_err(|_| Error::invalid("run UTF-8"))?),
                    None,
                )?),
            )],
        )?))
    }

    pub fn from_record(record: &ExportRecord, limits: Limits) -> Result<Self> {
        let ExportRecord::Resource(resource) = record else {
            return Err(Error::invalid("run resource"));
        };
        if resource.kind() != ResourceKind::RunDescriptor
            || resource.facts().len() != 1
            || resource.facts()[0].predicate().as_str() != RUN_PAYLOAD
        {
            return Err(Error::invalid("run descriptor"));
        }
        let FactTerm::Literal(literal) = resource.facts()[0].term() else {
            return Err(Error::invalid("run literal"));
        };
        let projection = literal.projection();
        if projection.field("datatype")?.as_str()? != XSD_STRING
            || *projection.field("language")? != V::Null
        {
            return Err(Error::invalid("run literal type"));
        }
        let bytes = projection.field("value")?.as_str()?.as_bytes();
        let run = Self::read(bytes, limits)?;
        if run.descriptor_id()? != *resource.id() || run.bytes(limits)? != bytes {
            return Err(Error::invalid("run descriptor identity/canonical payload"));
        }
        Ok(run)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredV4(pub RunEnvelopeV4);

impl StoredV4 {
    pub fn to_record(&self, limits: Limits) -> Result<ExportRecord> {
        self.0.to_record(limits)
    }

    pub fn from_record(record: &ExportRecord, limits: Limits) -> Result<Self> {
        Ok(Self(RunEnvelopeV4::from_record(record, limits)?))
    }
}
