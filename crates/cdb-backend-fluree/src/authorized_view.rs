//! Canonical, sealed authorized RDF input for disposable reasoning.
//!
//! The full manifest is backend-owned and memory-only. Core/engine recording
//! contracts receive descriptors and roots, never copied source RDF.

use crate::executable_profile_v3::ExecutableProfileManifestV3;
use cdb_core::{id::ContentHash, Limits};
use std::collections::BTreeSet;

pub const STRUCTURAL_NODE_IRI_PREFIX: &str = "urn:ctxql:sandbox-struct:sha256:";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OperationalScanStats {
    pub pages: usize,
    pub rows: usize,
    pub bytes: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthorizedCounts {
    pub data_quads: usize,
    pub schema_quads: usize,
    pub visible_supports: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedPremiseRoot(pub ContentHash);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionManifestRoot(pub ContentHash);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologyProfileDescriptor {
    pub identity: String,
    pub full_bundle_root: ContentHash,
    pub result_root: ContentHash,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RdfNodeId {
    Iri(String),
    /// Backend-scoped ontology structure identity. The stored value is an RDF
    /// blank label beginning with `_:`; it is never a portable/public ID.
    ScopedBlankNode(String),
}

impl RdfNodeId {
    pub fn as_iri(&self) -> Option<&str> {
        match self {
            Self::Iri(value) => Some(value),
            Self::ScopedBlankNode(_) => None,
        }
    }

    pub fn as_source_label(&self) -> &str {
        match self {
            Self::Iri(value) | Self::ScopedBlankNode(value) => value,
        }
    }

    pub fn commitment(&self) -> String {
        match self {
            Self::Iri(value) => format!("I{}:{value}", value.len()),
            Self::ScopedBlankNode(value) => format!("B{}:{value}", value.len()),
        }
    }
}

impl From<String> for RdfNodeId {
    fn from(value: String) -> Self {
        Self::Iri(value)
    }
}

impl From<&str> for RdfNodeId {
    fn from(value: &str) -> Self {
        Self::Iri(value.to_owned())
    }
}

impl PartialEq<str> for RdfNodeId {
    fn eq(&self, other: &str) -> bool {
        self.as_iri() == Some(other)
    }
}

impl PartialEq<&str> for RdfNodeId {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl PartialEq<String> for RdfNodeId {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExactTerm {
    Iri(String),
    ScopedBlankNode(String),
    Literal {
        lexical: String,
        datatype: String,
        language: Option<String>,
    },
}

impl ExactTerm {
    pub fn as_iri(&self) -> Option<&str> {
        match self {
            Self::Iri(value) => Some(value),
            Self::ScopedBlankNode(_) | Self::Literal { .. } => None,
        }
    }

    pub fn commitment(&self) -> String {
        match self {
            Self::Iri(iri) => format!("I{}:{iri}", iri.len()),
            Self::ScopedBlankNode(value) => format!("B{}:{value}", value.len()),
            Self::Literal {
                lexical,
                datatype,
                language,
            } => format!(
                "L{}:{}:{}:{}:{}:{}",
                lexical.len(),
                lexical,
                datatype.len(),
                datatype,
                language.as_deref().map_or(0, str::len),
                language.as_deref().unwrap_or("")
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceQuad {
    pub graph: String,
    pub subject: RdfNodeId,
    pub predicate: String,
    pub object: ExactTerm,
}

impl SourceQuad {
    pub fn subject_iri(&self) -> Option<&str> {
        self.subject.as_iri()
    }

    pub fn object_iri(&self) -> Option<&str> {
        self.object.as_iri()
    }

    pub fn commitment(&self) -> String {
        format!(
            "G{}:{}S{}P{}:{}O{}",
            self.graph.len(),
            self.graph,
            self.subject.commitment(),
            self.predicate.len(),
            self.predicate,
            self.object.commitment()
        )
    }

    /// Cryptographic selector used by durable recordings. The canonical
    /// commitment is backend-owned; neither RDF bytes nor display/debug output
    /// cross the recording boundary.
    pub fn commitment_hash(&self) -> ContentHash {
        ContentHash::of_bytes(self.commitment().as_bytes())
    }

    pub fn turtle(&self) -> String {
        let object = match &self.object {
            ExactTerm::Iri(iri) => format!("<{iri}>"),
            ExactTerm::ScopedBlankNode(label) => label.clone(),
            ExactTerm::Literal {
                lexical,
                datatype,
                language,
            } => {
                let escaped = lexical
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
                    .replace('\r', "\\r")
                    .replace('\t', "\\t")
                    .replace('\u{0008}', "\\b")
                    .replace('\u{000c}', "\\f");
                match language {
                    Some(language) => format!("\"{escaped}\"@{language}"),
                    None => format!("\"{escaped}\"^^<{datatype}>"),
                }
            }
        };
        let subject = match &self.subject {
            RdfNodeId::Iri(iri) => format!("<{iri}>"),
            RdfNodeId::ScopedBlankNode(label) => label.clone(),
        };
        format!("{subject} <{}> {object} .", self.predicate)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticCaptureDescriptor {
    pub ledger: String,
    pub requested_as_of: String,
    pub t: i64,
    pub commit_cid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReasoningDescriptor {
    pub schema_source: String,
    pub follow_owl_imports: bool,
    pub schema_graphs: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedViewManifest {
    pub capture: SemanticCaptureDescriptor,
    pub reasoning: ReasoningDescriptor,
    pub data_quads: BTreeSet<SourceQuad>,
    /// Complete authorized schema/import bundle, including harmless metadata.
    pub schema_quads: BTreeSet<SourceQuad>,
    /// Exact union-graph/projected and structurally mapped C0 input.
    pub reasoner_input_quads: BTreeSet<SourceQuad>,
    pub reasoner_input_root: ContentHash,
    pub structural_mapping_algorithm: String,
    pub profile_limits_identity: ContentHash,
    pub visible_supports: BTreeSet<String>,
    pub authorized_counts: AuthorizedCounts,
    pub data_root: ContentHash,
    pub schema_root: ContentHash,
    pub historical_config_root: ContentHash,
    pub ontology_profile: OntologyProfileDescriptor,
    /// Present only for the exact certified v3 supported-subset profile.
    pub supported_subset: Option<ExecutableProfileManifestV3>,
    /// Exact verified C0 ontology projection used to rebuild the sealed input.
    pub supported_subset_c0: Option<BTreeSet<SourceQuad>>,
    pub policy_dependency_root: ContentHash,
    /// Deterministic extraction algorithm/bounds and terminal proof only.
    /// Runtime page/row/byte counters remain private operational telemetry.
    pub protected_completeness: String,
    pub authorized_premise_root: AuthorizedPremiseRoot,
    pub execution_manifest_root: ExecutionManifestRoot,
}

impl AuthorizedViewManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        capture: SemanticCaptureDescriptor,
        reasoning: ReasoningDescriptor,
        data_quads: BTreeSet<SourceQuad>,
        schema_quads: BTreeSet<SourceQuad>,
        visible_supports: BTreeSet<String>,
        historical_config_root: ContentHash,
        policy_dependency_root: ContentHash,
        protected_completeness: &str,
    ) -> Self {
        let schema_root = quad_root(&schema_quads);
        let profile = OntologyProfileDescriptor {
            identity: crate::ontology_profile::ONTOLOGY_PROFILE_ID.into(),
            full_bundle_root: schema_root.clone(),
            result_root: framed_root(
                "ctxql-ontology-profile-result/legacy-sealed-v1",
                [
                    ("profile", crate::ontology_profile::ONTOLOGY_PROFILE_ID),
                    ("schema", schema_root.as_str()),
                ],
            ),
        };
        Self::seal_profiled(
            capture,
            reasoning,
            data_quads,
            schema_quads,
            visible_supports,
            historical_config_root,
            profile,
            policy_dependency_root,
            protected_completeness,
        )
    }

    /// Historical P5.5 constructor retained for source/test compatibility.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_profiled(
        capture: SemanticCaptureDescriptor,
        reasoning: ReasoningDescriptor,
        data_quads: BTreeSet<SourceQuad>,
        schema_quads: BTreeSet<SourceQuad>,
        visible_supports: BTreeSet<String>,
        historical_config_root: ContentHash,
        ontology_profile: OntologyProfileDescriptor,
        policy_dependency_root: ContentHash,
        protected_completeness: &str,
    ) -> Self {
        let reasoner_input_quads = legacy_reasoner_input(&data_quads, &schema_quads);
        Self::seal_profiled_v2(
            capture,
            reasoning,
            data_quads,
            schema_quads,
            reasoner_input_quads,
            "none/v1".into(),
            ContentHash::of_bytes(b"ctxql-ontology-profile-limits/legacy-v1"),
            visible_supports,
            historical_config_root,
            ontology_profile,
            policy_dependency_root,
            protected_completeness,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn seal_profiled_v2(
        capture: SemanticCaptureDescriptor,
        reasoning: ReasoningDescriptor,
        data_quads: BTreeSet<SourceQuad>,
        schema_quads: BTreeSet<SourceQuad>,
        reasoner_input_quads: BTreeSet<SourceQuad>,
        structural_mapping_algorithm: String,
        profile_limits_identity: ContentHash,
        visible_supports: BTreeSet<String>,
        historical_config_root: ContentHash,
        ontology_profile: OntologyProfileDescriptor,
        policy_dependency_root: ContentHash,
        protected_completeness: &str,
    ) -> Self {
        let authorized_counts = AuthorizedCounts {
            data_quads: data_quads.len(),
            schema_quads: schema_quads.len(),
            visible_supports: visible_supports.len(),
        };
        let data_root = quad_root(&data_quads);
        let schema_root = quad_root(&schema_quads);
        let reasoner_input_root = quad_root(&reasoner_input_quads);
        let support_commitment = visible_supports
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\u{0}");
        let count_commitment = format!(
            "{}:{}:{}",
            authorized_counts.data_quads,
            authorized_counts.schema_quads,
            authorized_counts.visible_supports
        );
        let authorized_premise_root = AuthorizedPremiseRoot(framed_root(
            "ctxql-authorized-premises/v1",
            [
                ("data", data_root.as_str()),
                ("schema", schema_root.as_str()),
                ("supports", support_commitment.as_str()),
                ("counts", count_commitment.as_str()),
            ],
        ));
        let capture_commitment = format!(
            "{}:{}:{}:{}",
            capture.ledger, capture.requested_as_of, capture.t, capture.commit_cid
        );
        let schema_graphs = reasoning
            .schema_graphs
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\u{0}");
        let reasoning_commitment = format!(
            "{}:{}:{}",
            reasoning.schema_source, reasoning.follow_owl_imports, schema_graphs
        );
        let execution_manifest_root = ExecutionManifestRoot(framed_root(
            "ctxql-execution-manifest/v2",
            [
                ("authorized-premises", authorized_premise_root.0.as_str()),
                ("capture", capture_commitment.as_str()),
                ("historical-config", historical_config_root.as_str()),
                ("ontology-profile", ontology_profile.identity.as_str()),
                (
                    "ontology-bundle",
                    ontology_profile.full_bundle_root.as_str(),
                ),
                (
                    "ontology-profile-result",
                    ontology_profile.result_root.as_str(),
                ),
                ("reasoner-input", reasoner_input_root.as_str()),
                ("structural-mapping", structural_mapping_algorithm.as_str()),
                ("profile-limits", profile_limits_identity.as_str()),
                ("policy", policy_dependency_root.as_str()),
                ("reasoning", reasoning_commitment.as_str()),
                ("completeness", protected_completeness),
            ],
        ));
        Self {
            capture,
            reasoning,
            data_quads,
            schema_quads,
            reasoner_input_quads,
            reasoner_input_root,
            structural_mapping_algorithm,
            profile_limits_identity,
            visible_supports,
            authorized_counts,
            data_root,
            schema_root,
            historical_config_root,
            ontology_profile,
            supported_subset: None,
            supported_subset_c0: None,
            policy_dependency_root,
            protected_completeness: protected_completeness.to_string(),
            authorized_premise_root,
            execution_manifest_root,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn seal_profiled_v3(
        capture: SemanticCaptureDescriptor,
        reasoning: ReasoningDescriptor,
        data_quads: BTreeSet<SourceQuad>,
        schema_quads: BTreeSet<SourceQuad>,
        reasoner_input_quads: BTreeSet<SourceQuad>,
        structural_mapping_algorithm: String,
        profile_limits_identity: ContentHash,
        visible_supports: BTreeSet<String>,
        historical_config_root: ContentHash,
        ontology_profile: OntologyProfileDescriptor,
        supported_subset_c0: BTreeSet<SourceQuad>,
        supported_subset: ExecutableProfileManifestV3,
        policy_dependency_root: ContentHash,
        protected_completeness: &str,
    ) -> Result<Self, String> {
        let executable_profile_root = supported_subset
            .root(Limits::default())
            .map_err(|_| "ontology_configuration_invalid".to_string())?;
        let input = supported_subset.input();
        if u64::try_from(supported_subset_c0.len()).ok() != Some(input.ontology_c0_input_count)
            || build_reasoner_input(&capture, &data_quads, &supported_subset_c0)?
                != reasoner_input_quads
        {
            return Err("authorized_manifest_invalid".into());
        }
        let mut sealed = Self::seal_profiled_v2(
            capture,
            reasoning,
            data_quads,
            schema_quads,
            reasoner_input_quads,
            structural_mapping_algorithm,
            profile_limits_identity,
            visible_supports,
            historical_config_root,
            ontology_profile,
            policy_dependency_root,
            protected_completeness,
        );
        let base_root = sealed.execution_manifest_root.0.clone();
        sealed.supported_subset = Some(supported_subset);
        sealed.supported_subset_c0 = Some(supported_subset_c0);
        sealed.execution_manifest_root = ExecutionManifestRoot(framed_root(
            "ctxql-execution-manifest/v3-supported-subset",
            [
                ("base-v2", base_root.as_str()),
                ("executable-profile", executable_profile_root.as_str()),
            ],
        ));
        Ok(sealed)
    }

    pub fn validate(&self) -> Result<(), String> {
        reject_reserved_structural_iris(self.data_quads.iter().chain(self.schema_quads.iter()))?;
        for quad in &self.data_quads {
            if quad
                .subject
                .as_iri()
                .is_none_or(|subject| subject.starts_with("_:"))
                || matches!(quad.object, ExactTerm::ScopedBlankNode(_))
                || quad
                    .object
                    .as_iri()
                    .is_some_and(|object| object.starts_with("_:"))
            {
                return Err("blank_node_not_supported".into());
            }
        }
        for quad in &self.schema_quads {
            let labels = match (&quad.subject, &quad.object) {
                (RdfNodeId::ScopedBlankNode(subject), ExactTerm::ScopedBlankNode(object)) => {
                    vec![subject, object]
                }
                (RdfNodeId::ScopedBlankNode(subject), _) => vec![subject],
                (_, ExactTerm::ScopedBlankNode(object)) => vec![object],
                _ => Vec::new(),
            };
            if labels.iter().any(|label| !label.starts_with("_:fdb-")) {
                return Err("unstable_structural_node_identity".into());
            }
        }
        for quad in &self.reasoner_input_quads {
            if quad.subject.as_iri().is_none()
                || matches!(quad.object, ExactTerm::ScopedBlankNode(_))
            {
                return Err("reasoner_input_divergence".into());
            }
        }
        for quad in self
            .data_quads
            .iter()
            .chain(&self.schema_quads)
            .chain(&self.reasoner_input_quads)
        {
            validate_iri(&quad.graph)?;
            validate_node(&quad.subject)?;
            validate_iri(&quad.predicate)?;
            match &quad.object {
                ExactTerm::Iri(iri) => validate_iri(iri)?,
                ExactTerm::ScopedBlankNode(label) => validate_blank_node(label)?,
                ExactTerm::Literal {
                    lexical,
                    datatype,
                    language,
                } => {
                    if lexical.chars().any(|ch| ch == '\0') {
                        return Err("authorized_manifest_invalid".into());
                    }
                    validate_iri(datatype)?;
                    match language {
                        Some(language) => {
                            if datatype != "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString"
                                || !valid_language_tag(language)
                            {
                                return Err("authorized_manifest_invalid".into());
                            }
                        }
                        None if datatype
                            == "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString" =>
                        {
                            return Err("authorized_manifest_invalid".into());
                        }
                        None => {}
                    }
                }
            }
        }
        for graph in &self.reasoning.schema_graphs {
            validate_iri(graph)?;
        }
        validate_iri(&self.reasoning.schema_source)?;
        let v3 = self.ontology_profile.identity
            == crate::ontology_profile_v3::ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID;
        if self.ontology_profile.identity != crate::ontology_profile::ONTOLOGY_PROFILE_ID
            && self.ontology_profile.identity != crate::ontology_profile_v2::ONTOLOGY_PROFILE_V2_ID
            && self.ontology_profile.identity
                != crate::current_reasoning_profile::CURRENT_REASONING_PROFILE_ID
            && !v3
        {
            return Err("ontology_profile_unsupported".into());
        }
        if v3 != self.supported_subset.is_some() || v3 != self.supported_subset_c0.is_some() {
            return Err("authorized_manifest_invalid".into());
        }
        if self.ontology_profile.full_bundle_root != quad_root(&self.schema_quads) {
            return Err("authorized_manifest_invalid".into());
        }
        if let Some(supported) = &self.supported_subset {
            let input = supported.input();
            if u64::try_from(self.schema_quads.len()).ok() != Some(input.full_bundle_count)
                || input.profile_limits_identity != self.profile_limits_identity
            {
                return Err("authorized_manifest_invalid".into());
            }
        }
        let resealed = if let Some(supported) = &self.supported_subset {
            Self::seal_profiled_v3(
                self.capture.clone(),
                self.reasoning.clone(),
                self.data_quads.clone(),
                self.schema_quads.clone(),
                self.reasoner_input_quads.clone(),
                self.structural_mapping_algorithm.clone(),
                self.profile_limits_identity.clone(),
                self.visible_supports.clone(),
                self.historical_config_root.clone(),
                self.ontology_profile.clone(),
                self.supported_subset_c0
                    .clone()
                    .ok_or_else(|| "authorized_manifest_invalid".to_string())?,
                supported.clone(),
                self.policy_dependency_root.clone(),
                &self.protected_completeness,
            )?
        } else {
            Self::seal_profiled_v2(
                self.capture.clone(),
                self.reasoning.clone(),
                self.data_quads.clone(),
                self.schema_quads.clone(),
                self.reasoner_input_quads.clone(),
                self.structural_mapping_algorithm.clone(),
                self.profile_limits_identity.clone(),
                self.visible_supports.clone(),
                self.historical_config_root.clone(),
                self.ontology_profile.clone(),
                self.policy_dependency_root.clone(),
                &self.protected_completeness,
            )
        };
        if self.authorized_counts != resealed.authorized_counts
            || self.data_root != resealed.data_root
            || self.schema_root != resealed.schema_root
            || self.reasoner_input_root != resealed.reasoner_input_root
            || self.authorized_premise_root != resealed.authorized_premise_root
            || self.execution_manifest_root != resealed.execution_manifest_root
        {
            return Err("authorized_manifest_invalid".into());
        }
        Ok(())
    }
}

fn legacy_reasoner_input(
    data_quads: &BTreeSet<SourceQuad>,
    schema_quads: &BTreeSet<SourceQuad>,
) -> BTreeSet<SourceQuad> {
    let mut input = schema_quads.clone();
    input.extend(data_quads.iter().cloned().map(|mut quad| {
        quad.graph = "urn:ctxql:sandbox-union".into();
        quad
    }));
    input
}

pub fn build_reasoner_input(
    capture: &SemanticCaptureDescriptor,
    data_quads: &BTreeSet<SourceQuad>,
    schema_projection: &BTreeSet<SourceQuad>,
) -> Result<BTreeSet<SourceQuad>, String> {
    reject_reserved_structural_iris(data_quads.iter().chain(schema_projection.iter()))?;
    let authored_iris = authored_iris(data_quads.iter().chain(schema_projection.iter()));
    let mut input = BTreeSet::new();
    input.extend(data_quads.iter().cloned().map(|mut quad| {
        quad.graph = "urn:ctxql:sandbox-union".into();
        quad
    }));
    let mut mapped: std::collections::BTreeMap<String, (String, String)> =
        std::collections::BTreeMap::new();
    for quad in schema_projection {
        let map_label = |graph: &str, label: &str| {
            let transaction = capture.t.to_string();
            let identity = framed_root(
                crate::ontology_profile_v2::STRUCTURAL_MAPPING_ALGORITHM,
                [
                    ("ledger", capture.ledger.as_str()),
                    ("t", transaction.as_str()),
                    ("cid", capture.commit_cid.as_str()),
                    ("graph", graph),
                    ("blank", label),
                ],
            );
            format!(
                "{}{}",
                STRUCTURAL_NODE_IRI_PREFIX,
                identity.as_str().trim_start_matches("sha256:")
            )
        };
        let subject = match &quad.subject {
            RdfNodeId::Iri(value) => RdfNodeId::Iri(value.clone()),
            RdfNodeId::ScopedBlankNode(label) => {
                let target = map_label(&quad.graph, label);
                if authored_iris.contains(&target) {
                    return Err("structural_node_mapping_collision".into());
                }
                if mapped
                    .insert(target.clone(), (quad.graph.clone(), label.clone()))
                    .is_some_and(|prior| prior != (quad.graph.clone(), label.clone()))
                {
                    return Err("structural_node_mapping_collision".into());
                }
                RdfNodeId::Iri(target)
            }
        };
        let object = match &quad.object {
            ExactTerm::ScopedBlankNode(label) => {
                let target = map_label(&quad.graph, label);
                if authored_iris.contains(&target) {
                    return Err("structural_node_mapping_collision".into());
                }
                if mapped
                    .insert(target.clone(), (quad.graph.clone(), label.clone()))
                    .is_some_and(|prior| prior != (quad.graph.clone(), label.clone()))
                {
                    return Err("structural_node_mapping_collision".into());
                }
                ExactTerm::Iri(target)
            }
            value => value.clone(),
        };
        input.insert(SourceQuad {
            graph: "urn:ctxql:sandbox-union".into(),
            subject,
            predicate: quad.predicate.clone(),
            object,
        });
    }
    Ok(input)
}

fn authored_iris<'a>(quads: impl Iterator<Item = &'a SourceQuad>) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for quad in quads {
        values.insert(quad.graph.clone());
        if let Some(subject) = quad.subject.as_iri() {
            values.insert(subject.to_owned());
        }
        values.insert(quad.predicate.clone());
        if let Some(object) = quad.object.as_iri() {
            values.insert(object.to_owned());
        }
    }
    values
}

fn reject_reserved_structural_iris<'a>(
    quads: impl Iterator<Item = &'a SourceQuad>,
) -> Result<(), String> {
    if authored_iris(quads)
        .iter()
        .any(|value| value.starts_with(STRUCTURAL_NODE_IRI_PREFIX))
    {
        Err("structural_node_mapping_collision".into())
    } else {
        Ok(())
    }
}

fn validate_node(value: &RdfNodeId) -> Result<(), String> {
    match value {
        RdfNodeId::Iri(value) => validate_iri(value),
        RdfNodeId::ScopedBlankNode(value) => validate_blank_node(value),
    }
}

fn validate_blank_node(value: &str) -> Result<(), String> {
    if value.starts_with("_:")
        && value.len() > 2
        && !value.chars().any(|ch| ch == '\0' || ch.is_whitespace())
    {
        Ok(())
    } else {
        Err("authorized_manifest_invalid".into())
    }
}

fn validate_iri(value: &str) -> Result<(), String> {
    if value.starts_with("_:") {
        return Err("authorized_manifest_invalid".into());
    }
    cdb_core::id::Iri::new(value)
        .map(|_| ())
        .map_err(|_| "authorized_manifest_invalid".into())
}

fn valid_language_tag(value: &str) -> bool {
    value.len() <= 63
        && value.split('-').enumerate().all(|(index, part)| {
            !part.is_empty()
                && part.chars().all(|ch| ch.is_ascii_alphanumeric())
                && (index != 0 || part.chars().all(|ch| ch.is_ascii_alphabetic()))
        })
}

pub fn quad_root(quads: &BTreeSet<SourceQuad>) -> ContentHash {
    let mut bytes = Vec::new();
    for quad in quads {
        let commitment = quad.commitment();
        frame(&mut bytes, "quad", &commitment);
    }
    ContentHash::of_bytes(&bytes)
}

pub fn framed_root<'a>(
    tag: &str,
    fields: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> ContentHash {
    let mut bytes = Vec::new();
    frame(&mut bytes, "version", tag);
    for (name, value) in fields {
        frame(&mut bytes, name, value);
    }
    ContentHash::of_bytes(&bytes)
}

fn frame(bytes: &mut Vec<u8>, name: &str, value: &str) {
    bytes.extend_from_slice(name.len().to_string().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(value.len().to_string().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(value.as_bytes());
}
