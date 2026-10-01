//! Canonical, content-free executable profile manifest for the P5.7
//! Fluree-supported-subset profile.
//!
//! The manifest commits certification evidence needed after cache-free
//! historical reopen. It deliberately contains neither ontology RDF nor its
//! own root. `executableProfileRoot` is the SHA-256 commitment to the exact
//! canonical JSON bytes returned by [`ExecutableProfileManifestV3::canonical_bytes`].

use cdb_core::{
    id::ContentHash, recording_v4::SupportedSubsetEvidenceV4Input, CanonicalValue as V, Error,
    Limits, Result,
};

pub const EXECUTABLE_PROFILE_V3_SCHEMA: &str = "ctxql.executable-profile-v3/v1";
pub const EXECUTABLE_PROFILE_V3_MANIFEST_PREDICATE: &str =
    "https://ctxql.example/semantic-rdf/v2/executableProfileManifest";
pub const ONTOLOGY_PROFILE_PREDICATE: &str =
    "https://ctxql.example/semantic-rdf/v2/ontologyProfile";
pub const CONSTRUCT_AUDIT_ROOT_PREDICATE: &str =
    "https://ctxql.example/semantic-rdf/v2/constructAuditRoot";
pub const EXECUTABLE_PROFILE_ROOT_PREDICATE: &str =
    "https://ctxql.example/semantic-rdf/v2/executableProfileRoot";

pub const ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID: &str =
    "ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v3-supported-subset";
pub const ONTOLOGY_PROFILE_V3_RESULT_LABEL: &str = "fluree_supported_subset";
pub const PINNED_FLUREE_REVISION: &str = "603974fad5c13efed9d147d214d613849fb43c73";

const MANIFEST_FIELDS: &[&str] = &[
    "schema",
    "profile",
    "result_label",
    "fluree_revision",
    "selected_scope",
    "scope_authority_root",
    "acquisition_authority_root",
    "selected_source_release_id",
    "selected_source_file_id",
    "selected_ontology_iri",
    "source_member_root",
    "source_closure_root",
    "dependency_universe_root",
    "full_bundle_root",
    "full_bundle_count",
    "construct_audit_root",
    "source_entry_root",
    "categories",
    "annotation_policy_root",
    "registry_root",
    "family_root",
    "component_projection_root",
    "source_occurrence_root",
    "reasoned_family_inventory_root",
    "declaration_evidence_root",
    "uninterpreted_non_interference_root",
    "parity_matrix_root",
    "final_gate3_semantic_coverage_root",
    "caveat_set_root",
    "ontology_c0_input_root",
    "ontology_c0_input_count",
    "profile_limits_identity",
    "dependency_limits_identity",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategoryCommitmentV3 {
    pub count: u64,
    pub root: ContentHash,
    pub occurrence_root: ContentHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategoryCommitmentsV3 {
    pub reasoned: CategoryCommitmentV3,
    pub inference_inert_declaration: CategoryCommitmentV3,
    pub retained_annotation: CategoryCommitmentV3,
    pub retained_uninterpreted_semantic: CategoryCommitmentV3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableProfileManifestV3Input {
    pub selected_scope: String,
    pub scope_authority_root: ContentHash,
    pub acquisition_authority_root: ContentHash,
    pub selected_source_release_id: String,
    pub selected_source_file_id: String,
    pub selected_ontology_iri: String,
    pub source_member_root: ContentHash,
    pub source_closure_root: ContentHash,
    pub dependency_universe_root: ContentHash,
    pub full_bundle_root: ContentHash,
    pub full_bundle_count: u64,
    pub construct_audit_root: ContentHash,
    pub source_entry_root: ContentHash,
    pub categories: CategoryCommitmentsV3,
    pub annotation_policy_root: ContentHash,
    pub registry_root: ContentHash,
    pub family_root: ContentHash,
    pub component_projection_root: ContentHash,
    pub source_occurrence_root: ContentHash,
    pub reasoned_family_inventory_root: ContentHash,
    pub declaration_evidence_root: ContentHash,
    pub uninterpreted_non_interference_root: ContentHash,
    pub parity_matrix_root: ContentHash,
    /// Acyclic final Gate-3 commitment. This excludes the manifest root,
    /// because that root is computed from the canonical manifest bytes.
    pub final_gate3_semantic_coverage_root: ContentHash,
    pub caveat_set_root: ContentHash,
    pub ontology_c0_input_root: ContentHash,
    pub ontology_c0_input_count: u64,
    pub profile_limits_identity: ContentHash,
    pub dependency_limits_identity: ContentHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableProfileManifestV3 {
    input: ExecutableProfileManifestV3Input,
    wire: V,
}

impl ExecutableProfileManifestV3 {
    pub fn new(input: ExecutableProfileManifestV3Input, limits: Limits) -> Result<Self> {
        validate_input(&input)?;
        let wire = manifest_value(&input)?;
        wire.canonical_bytes(limits)?;
        Ok(Self { input, wire })
    }

    /// Parse a value that is already represented as structured canonical data.
    /// Unknown, missing, or self-root fields fail closed.
    pub fn from_value(value: &V, limits: Limits) -> Result<Self> {
        value.closed(MANIFEST_FIELDS, &[])?;
        if value.field("schema")?.as_str()? != EXECUTABLE_PROFILE_V3_SCHEMA {
            return Err(Error::invalid("executable profile schema"));
        }
        if value.field("profile")?.as_str()? != ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID {
            return Err(Error::invalid("executable profile identity"));
        }
        if value.field("result_label")?.as_str()? != ONTOLOGY_PROFILE_V3_RESULT_LABEL {
            return Err(Error::invalid("executable profile result label"));
        }
        if value.field("fluree_revision")?.as_str()? != PINNED_FLUREE_REVISION {
            return Err(Error::invalid("executable profile Fluree revision"));
        }
        let categories = value.field("categories")?;
        categories.closed(
            &[
                "reasoned",
                "inference_inert_declaration",
                "retained_annotation",
                "retained_uninterpreted_semantic",
            ],
            &[],
        )?;
        let input = ExecutableProfileManifestV3Input {
            selected_scope: value.field("selected_scope")?.as_str()?.to_owned(),
            scope_authority_root: hash_field(value, "scope_authority_root")?,
            acquisition_authority_root: hash_field(value, "acquisition_authority_root")?,
            selected_source_release_id: value
                .field("selected_source_release_id")?
                .as_str()?
                .to_owned(),
            selected_source_file_id: value.field("selected_source_file_id")?.as_str()?.to_owned(),
            selected_ontology_iri: value.field("selected_ontology_iri")?.as_str()?.to_owned(),
            source_member_root: hash_field(value, "source_member_root")?,
            source_closure_root: hash_field(value, "source_closure_root")?,
            dependency_universe_root: hash_field(value, "dependency_universe_root")?,
            full_bundle_root: hash_field(value, "full_bundle_root")?,
            full_bundle_count: value.field("full_bundle_count")?.u64()?,
            construct_audit_root: hash_field(value, "construct_audit_root")?,
            source_entry_root: hash_field(value, "source_entry_root")?,
            categories: CategoryCommitmentsV3 {
                reasoned: category_from_value(categories.field("reasoned")?)?,
                inference_inert_declaration: category_from_value(
                    categories.field("inference_inert_declaration")?,
                )?,
                retained_annotation: category_from_value(categories.field("retained_annotation")?)?,
                retained_uninterpreted_semantic: category_from_value(
                    categories.field("retained_uninterpreted_semantic")?,
                )?,
            },
            annotation_policy_root: hash_field(value, "annotation_policy_root")?,
            registry_root: hash_field(value, "registry_root")?,
            family_root: hash_field(value, "family_root")?,
            component_projection_root: hash_field(value, "component_projection_root")?,
            source_occurrence_root: hash_field(value, "source_occurrence_root")?,
            reasoned_family_inventory_root: hash_field(value, "reasoned_family_inventory_root")?,
            declaration_evidence_root: hash_field(value, "declaration_evidence_root")?,
            uninterpreted_non_interference_root: hash_field(
                value,
                "uninterpreted_non_interference_root",
            )?,
            parity_matrix_root: hash_field(value, "parity_matrix_root")?,
            final_gate3_semantic_coverage_root: hash_field(
                value,
                "final_gate3_semantic_coverage_root",
            )?,
            caveat_set_root: hash_field(value, "caveat_set_root")?,
            ontology_c0_input_root: hash_field(value, "ontology_c0_input_root")?,
            ontology_c0_input_count: value.field("ontology_c0_input_count")?.u64()?,
            profile_limits_identity: hash_field(value, "profile_limits_identity")?,
            dependency_limits_identity: hash_field(value, "dependency_limits_identity")?,
        };
        let parsed = Self::new(input, limits)?;
        if parsed.wire != *value {
            return Err(Error::invalid("executable profile projection"));
        }
        Ok(parsed)
    }

    /// Parse exact canonical JSON bytes. Whitespace, alternate field order, or
    /// any otherwise equivalent non-canonical JSON is rejected.
    pub fn from_canonical_bytes(bytes: &[u8], limits: Limits) -> Result<Self> {
        let value = V::parse(bytes, limits)?;
        let manifest = Self::from_value(&value, limits)?;
        if manifest.canonical_bytes(limits)? != bytes {
            return Err(Error::invalid("noncanonical executable profile manifest"));
        }
        Ok(manifest)
    }

    pub fn input(&self) -> &ExecutableProfileManifestV3Input {
        &self.input
    }

    pub fn projection(&self) -> V {
        self.wire.clone()
    }

    pub fn canonical_bytes(&self, limits: Limits) -> Result<Vec<u8>> {
        self.wire.canonical_bytes(limits)
    }

    pub fn root(&self, limits: Limits) -> Result<ContentHash> {
        Ok(ContentHash::of_bytes(&self.canonical_bytes(limits)?))
    }

    pub fn recording_input(&self, limits: Limits) -> Result<SupportedSubsetEvidenceV4Input> {
        Ok(SupportedSubsetEvidenceV4Input {
            construct_audit_root: self.input.construct_audit_root.clone(),
            executable_profile_root: self.root(limits)?,
            reasoned_family_inventory_root: self.input.reasoned_family_inventory_root.clone(),
            declaration_evidence_root: self.input.declaration_evidence_root.clone(),
            uninterpreted_non_interference_root: self
                .input
                .uninterpreted_non_interference_root
                .clone(),
            parity_matrix_root: self.input.parity_matrix_root.clone(),
            reasoned_category_root: self.input.categories.reasoned.root.clone(),
            declaration_category_root: self
                .input
                .categories
                .inference_inert_declaration
                .root
                .clone(),
            retained_annotation_category_root: self
                .input
                .categories
                .retained_annotation
                .root
                .clone(),
            retained_uninterpreted_category_root: self
                .input
                .categories
                .retained_uninterpreted_semantic
                .root
                .clone(),
            registry_root: self.input.registry_root.clone(),
            family_root: self.input.family_root.clone(),
            component_root: self.input.component_projection_root.clone(),
            source_occurrence_root: self.input.source_occurrence_root.clone(),
            annotation_policy_root: self.input.annotation_policy_root.clone(),
            semantic_coverage_root: self.input.final_gate3_semantic_coverage_root.clone(),
            caveat_set_root: self.input.caveat_set_root.clone(),
            ontology_c0_input_root: self.input.ontology_c0_input_root.clone(),
        })
    }
}

fn validate_input(input: &ExecutableProfileManifestV3Input) -> Result<()> {
    if [
        &input.selected_scope,
        &input.selected_source_release_id,
        &input.selected_source_file_id,
        &input.selected_ontology_iri,
    ]
    .iter()
    .any(|value| value.is_empty() || value.chars().any(char::is_control))
    {
        return Err(Error::invalid(
            "executable profile source authority identity",
        ));
    }
    if input.full_bundle_count == 0 {
        return Err(Error::invalid("executable profile empty bundle"));
    }
    let category_count = input
        .categories
        .reasoned
        .count
        .checked_add(input.categories.inference_inert_declaration.count)
        .and_then(|n| n.checked_add(input.categories.retained_annotation.count))
        .and_then(|n| n.checked_add(input.categories.retained_uninterpreted_semantic.count))
        .ok_or_else(Error::limit)?;
    if category_count != input.full_bundle_count {
        return Err(Error::invalid("executable profile category count"));
    }
    let expected_c0 = input
        .full_bundle_count
        .checked_sub(input.categories.retained_annotation.count)
        .ok_or_else(|| Error::invalid("executable profile annotation count"))?;
    if input.ontology_c0_input_count != expected_c0 {
        return Err(Error::invalid("executable profile C0 count"));
    }
    Ok(())
}

fn manifest_value(input: &ExecutableProfileManifestV3Input) -> Result<V> {
    V::object([
        ("schema".into(), V::string(EXECUTABLE_PROFILE_V3_SCHEMA)),
        (
            "profile".into(),
            V::string(ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID),
        ),
        (
            "result_label".into(),
            V::string(ONTOLOGY_PROFILE_V3_RESULT_LABEL),
        ),
        ("fluree_revision".into(), V::string(PINNED_FLUREE_REVISION)),
        ("selected_scope".into(), V::string(&input.selected_scope)),
        hash_value("scope_authority_root", &input.scope_authority_root),
        hash_value(
            "acquisition_authority_root",
            &input.acquisition_authority_root,
        ),
        (
            "selected_source_release_id".into(),
            V::string(&input.selected_source_release_id),
        ),
        (
            "selected_source_file_id".into(),
            V::string(&input.selected_source_file_id),
        ),
        (
            "selected_ontology_iri".into(),
            V::string(&input.selected_ontology_iri),
        ),
        hash_value("source_member_root", &input.source_member_root),
        hash_value("source_closure_root", &input.source_closure_root),
        hash_value("dependency_universe_root", &input.dependency_universe_root),
        hash_value("full_bundle_root", &input.full_bundle_root),
        (
            "full_bundle_count".into(),
            V::integer(input.full_bundle_count),
        ),
        hash_value("construct_audit_root", &input.construct_audit_root),
        hash_value("source_entry_root", &input.source_entry_root),
        (
            "categories".into(),
            V::object([
                (
                    "reasoned".into(),
                    category_value(&input.categories.reasoned)?,
                ),
                (
                    "inference_inert_declaration".into(),
                    category_value(&input.categories.inference_inert_declaration)?,
                ),
                (
                    "retained_annotation".into(),
                    category_value(&input.categories.retained_annotation)?,
                ),
                (
                    "retained_uninterpreted_semantic".into(),
                    category_value(&input.categories.retained_uninterpreted_semantic)?,
                ),
            ])?,
        ),
        hash_value("annotation_policy_root", &input.annotation_policy_root),
        hash_value("registry_root", &input.registry_root),
        hash_value("family_root", &input.family_root),
        hash_value(
            "component_projection_root",
            &input.component_projection_root,
        ),
        hash_value("source_occurrence_root", &input.source_occurrence_root),
        hash_value(
            "reasoned_family_inventory_root",
            &input.reasoned_family_inventory_root,
        ),
        hash_value(
            "declaration_evidence_root",
            &input.declaration_evidence_root,
        ),
        hash_value(
            "uninterpreted_non_interference_root",
            &input.uninterpreted_non_interference_root,
        ),
        hash_value("parity_matrix_root", &input.parity_matrix_root),
        hash_value(
            "final_gate3_semantic_coverage_root",
            &input.final_gate3_semantic_coverage_root,
        ),
        hash_value("caveat_set_root", &input.caveat_set_root),
        hash_value("ontology_c0_input_root", &input.ontology_c0_input_root),
        (
            "ontology_c0_input_count".into(),
            V::integer(input.ontology_c0_input_count),
        ),
        hash_value("profile_limits_identity", &input.profile_limits_identity),
        hash_value(
            "dependency_limits_identity",
            &input.dependency_limits_identity,
        ),
    ])
}

fn category_value(category: &CategoryCommitmentV3) -> Result<V> {
    V::object([
        ("count".into(), V::integer(category.count)),
        hash_value("root", &category.root),
        hash_value("occurrence_root", &category.occurrence_root),
    ])
}

fn category_from_value(value: &V) -> Result<CategoryCommitmentV3> {
    value.closed(&["count", "root", "occurrence_root"], &[])?;
    Ok(CategoryCommitmentV3 {
        count: value.field("count")?.u64()?,
        root: hash_field(value, "root")?,
        occurrence_root: hash_field(value, "occurrence_root")?,
    })
}

fn hash_value(name: &str, value: &ContentHash) -> (String, V) {
    (name.to_owned(), V::string(value.as_str()))
}

fn hash_field(value: &V, name: &str) -> Result<ContentHash> {
    ContentHash::parse(value.field(name)?.as_str()?)
}
