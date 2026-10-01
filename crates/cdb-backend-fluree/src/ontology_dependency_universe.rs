//! Exact, offline ontology ownership and import resolution.

use crate::{
    authorized_view::{framed_root, ExactTerm, RdfNodeId},
    ontology_conversion::{convert_rdfxml, ConversionRequest, ConversionResult},
    ontology_release::{ArtifactRole, RelativeSourcePath, SourceReleaseId, SourceReleaseManifest},
};
use cdb_core::id::{ContentHash, Iri};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

pub const ONTOLOGY_DEPENDENCY_UNIVERSE_INVALID: &str = "ontology_dependency_universe_invalid";

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const OWL_ONTOLOGY: &str = "http://www.w3.org/2002/07/owl#Ontology";
const OWL_IMPORTS: &str = "http://www.w3.org/2002/07/owl#imports";
const OWL_VERSION_IRI: &str = "http://www.w3.org/2002/07/owl#versionIRI";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UniverseErrorKind {
    MissingRelease,
    MissingArtifact,
    HashMismatch,
    DuplicateOwnership,
    VersionAlias,
    UndeclaredOwner,
    CatalogRewrite,
    UnresolvedImport,
    OutOfUniverseImport,
    ImportCycle,
    ConversionFailure,
    SerializationGap,
    LimitExceeded,
    InvalidIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniverseError {
    kind: UniverseErrorKind,
    detail: String,
}
impl UniverseError {
    fn new(kind: UniverseErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
    pub fn reason_code(&self) -> &'static str {
        ONTOLOGY_DEPENDENCY_UNIVERSE_INVALID
    }
    pub fn kind(&self) -> UniverseErrorKind {
        self.kind
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
}
impl fmt::Display for UniverseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({:?}): {}",
            self.reason_code(),
            self.kind,
            self.detail
        )
    }
}
impl std::error::Error for UniverseError {}
type Result<T> = std::result::Result<T, UniverseError>;

fn iri(value: impl Into<String>, label: &str) -> Result<String> {
    let value = value.into();
    Iri::new(value.clone()).map_err(|_| {
        UniverseError::new(
            UniverseErrorKind::InvalidIdentity,
            format!("invalid {label}"),
        )
    })?;
    Ok(value)
}
fn text(value: impl Into<String>, label: &str) -> Result<String> {
    let value = value.into();
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(UniverseError::new(
            UniverseErrorKind::InvalidIdentity,
            format!("invalid {label}"),
        ));
    }
    Ok(value)
}
fn serialize_hash<S: serde::Serializer>(
    hash: &ContentHash,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(hash.as_str())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConversionPin {
    source_release_id: String,
    source_file_id: String,
    base_iri: String,
    graph_iri: String,
    parser_identity: String,
    parser_options: String,
    blank_node_algorithm: String,
    #[serde(serialize_with = "serialize_hash")]
    authoritative_hash: ContentHash,
    #[serde(serialize_with = "serialize_hash")]
    derived_hash: ContentHash,
    #[serde(serialize_with = "serialize_hash")]
    root: ContentHash,
    #[serde(serialize_with = "serialize_hash")]
    graph_root: ContentHash,
    serialization: String,
    ontology_iris: Vec<String>,
    version_iris: Vec<String>,
    imports: Vec<String>,
}
impl ConversionPin {
    pub fn from_result(result: &ConversionResult, authoritative_bytes: &[u8]) -> Result<Self> {
        if !result.verify_integrity() {
            return Err(UniverseError::new(
                UniverseErrorKind::ConversionFailure,
                "conversion result integrity check failed",
            ));
        }
        let recomputed = convert_rdfxml(ConversionRequest {
            authoritative_bytes,
            source_release_id: &result.source_release_id,
            source_file_id: &result.source_file_id,
            base_iri: &result.base_iri,
            graph_iri: &result.graph_iri,
            limits: result.limits,
        })
        .map_err(|_| {
            UniverseError::new(
                UniverseErrorKind::ConversionFailure,
                "authoritative bytes do not reproduce the conversion",
            )
        })?;
        if &recomputed != result {
            return Err(UniverseError::new(
                UniverseErrorKind::ConversionFailure,
                "authoritative bytes do not reproduce the conversion",
            ));
        }
        let mut ontology_iris = BTreeSet::new();
        let mut version_iris = BTreeSet::new();
        let mut imports = BTreeSet::new();
        for quad in &result.quads {
            if quad.graph != result.graph_iri {
                return Err(UniverseError::new(
                    UniverseErrorKind::ConversionFailure,
                    "conversion contains an unexpected graph",
                ));
            }
            let RdfNodeId::Iri(subject) = &quad.subject else {
                continue;
            };
            match (quad.predicate.as_str(), &quad.object) {
                (RDF_TYPE, ExactTerm::Iri(object)) if object == OWL_ONTOLOGY => {
                    ontology_iris.insert(subject.clone());
                }
                (OWL_VERSION_IRI, ExactTerm::Iri(object)) => {
                    version_iris.insert(object.clone());
                }
                (OWL_IMPORTS, ExactTerm::Iri(object)) => {
                    imports.insert(object.clone());
                }
                _ => {}
            }
        }
        if ontology_iris.is_empty() || ontology_iris.len() != 1 || version_iris.len() != 1 {
            return Err(UniverseError::new(
                UniverseErrorKind::ConversionFailure,
                "conversion must declare exactly one ontology and version IRI",
            ));
        }
        Ok(Self {
            source_release_id: result.source_release_id.clone(),
            source_file_id: result.source_file_id.clone(),
            base_iri: result.base_iri.clone(),
            graph_iri: result.graph_iri.clone(),
            parser_identity: result.parser_identity.to_owned(),
            parser_options: result.parser_options.to_owned(),
            blank_node_algorithm: result.blank_node_algorithm.to_owned(),
            authoritative_hash: result.original_hash.clone(),
            derived_hash: result.derived_hash.clone(),
            root: result.conversion_root.clone(),
            graph_root: result.graph_root.clone(),
            serialization: "application/n-triples".to_owned(),
            ontology_iris: ontology_iris.into_iter().collect(),
            version_iris: version_iris.into_iter().collect(),
            imports: imports.into_iter().collect(),
        })
    }
    pub fn root(&self) -> &ContentHash {
        &self.root
    }
    pub fn graph_root(&self) -> &ContentHash {
        &self.graph_root
    }
    pub fn serialization(&self) -> &str {
        &self.serialization
    }
    pub fn ontology_iris(&self) -> &[String] {
        &self.ontology_iris
    }
    pub fn version_iris(&self) -> &[String] {
        &self.version_iris
    }
    pub fn imports(&self) -> &[String] {
        &self.imports
    }
    /// Revalidates all result commitments available after authoritative-byte
    /// conversion and requires exact equality with this sealed pin.
    pub fn matches_result(&self, result: &ConversionResult) -> bool {
        result.verify_integrity()
            && self.source_release_id == result.source_release_id
            && self.source_file_id == result.source_file_id
            && self.base_iri == result.base_iri
            && self.graph_iri == result.graph_iri
            && self.parser_identity == result.parser_identity
            && self.parser_options == result.parser_options
            && self.blank_node_algorithm == result.blank_node_algorithm
            && self.authoritative_hash == result.original_hash
            && self.derived_hash == result.derived_hash
            && self.root == result.conversion_root
            && self.graph_root == result.graph_root
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OntologyOwnership {
    ontology_iri: String,
    version_iri: String,
    release_id: SourceReleaseId,
    artifact: RelativeSourcePath,
    #[serde(serialize_with = "serialize_hash")]
    authoritative_hash: ContentHash,
    media_type: String,
    conversion: ConversionPin,
    graph_iri: String,
    imports: Vec<String>,
}
impl OntologyOwnership {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ontology_iri: impl Into<String>,
        version_iri: impl Into<String>,
        release_id: SourceReleaseId,
        artifact: RelativeSourcePath,
        authoritative_hash: ContentHash,
        media_type: impl Into<String>,
        conversion: ConversionPin,
        graph_iri: impl Into<String>,
        imports: Vec<String>,
    ) -> Result<Self> {
        let ontology_iri = iri(ontology_iri, "ontology IRI")?;
        let version_iri = iri(version_iri, "version IRI")?;
        if ontology_iri == version_iri {
            return Err(UniverseError::new(
                UniverseErrorKind::VersionAlias,
                "ontology and version IRI must differ",
            ));
        }
        let graph_iri = iri(graph_iri, "graph IRI")?;
        let media_type = text(media_type, "media type")?;
        if !media_type.contains('/') {
            return Err(UniverseError::new(
                UniverseErrorKind::SerializationGap,
                "invalid media type",
            ));
        }
        let mut imports = imports
            .into_iter()
            .map(|v| iri(v, "import IRI"))
            .collect::<Result<Vec<_>>>()?;
        imports.sort();
        if imports.windows(2).any(|w| w[0] == w[1]) {
            return Err(UniverseError::new(
                UniverseErrorKind::InvalidIdentity,
                "duplicate import IRI",
            ));
        }
        Ok(Self {
            ontology_iri,
            version_iri,
            release_id,
            artifact,
            authoritative_hash,
            media_type,
            conversion,
            graph_iri,
            imports,
        })
    }
    pub fn ontology_iri(&self) -> &str {
        &self.ontology_iri
    }
    pub fn version_iri(&self) -> &str {
        &self.version_iri
    }
    pub fn release_id(&self) -> &SourceReleaseId {
        &self.release_id
    }
    pub fn artifact(&self) -> &RelativeSourcePath {
        &self.artifact
    }
    pub fn authoritative_hash(&self) -> &ContentHash {
        &self.authoritative_hash
    }
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
    pub fn conversion(&self) -> &ConversionPin {
        &self.conversion
    }
    pub fn graph_iri(&self) -> &str {
        &self.graph_iri
    }
    pub fn imports(&self) -> &[String] {
        &self.imports
    }
    fn identity(&self) -> ContentHash {
        let mut fields = vec![
            ("ontology", self.ontology_iri.as_str()),
            ("version", self.version_iri.as_str()),
            ("release", self.release_id.as_str()),
            ("artifact", self.artifact.as_str()),
            ("authoritative-hash", self.authoritative_hash.as_str()),
            ("media-type", self.media_type.as_str()),
            ("conversion", self.conversion.root.as_str()),
            (
                "conversion-source-release",
                &self.conversion.source_release_id,
            ),
            ("conversion-source-file", &self.conversion.source_file_id),
            ("conversion-base", &self.conversion.base_iri),
            ("conversion-parser", &self.conversion.parser_identity),
            ("conversion-options", &self.conversion.parser_options),
            (
                "conversion-blank-nodes",
                &self.conversion.blank_node_algorithm,
            ),
            (
                "conversion-authoritative",
                self.conversion.authoritative_hash.as_str(),
            ),
            ("conversion-derived", self.conversion.derived_hash.as_str()),
            ("conversion-serialization", &self.conversion.serialization),
            ("graph-root", self.conversion.graph_root.as_str()),
            ("graph", self.graph_iri.as_str()),
        ];
        fields.extend(self.imports.iter().map(|v| ("import", v.as_str())));
        framed_root("ctxql-ontology-ownership/v1", fields)
    }
}

/// Catalog data is evidence only. Prefix rules are rejected because they could
/// manufacture owners; exact entries may only describe an already-owned IRI and
/// its already-declared authoritative artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum CatalogEvidence {
    Exact {
        ontology_iri: String,
        release_id: SourceReleaseId,
        artifact: RelativeSourcePath,
    },
    Prefix {
        prefix: String,
        replacement: String,
    },
}
impl CatalogEvidence {
    pub fn exact(
        ontology_iri: impl Into<String>,
        release_id: SourceReleaseId,
        artifact: RelativeSourcePath,
    ) -> Result<Self> {
        Ok(Self::Exact {
            ontology_iri: iri(ontology_iri, "catalog IRI")?,
            release_id,
            artifact,
        })
    }
    pub fn prefix(prefix: impl Into<String>, replacement: impl Into<String>) -> Result<Self> {
        Ok(Self::Prefix {
            prefix: iri(prefix, "catalog prefix")?,
            replacement: text(replacement, "catalog replacement")?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniverseLimits {
    pub max_releases: usize,
    pub max_ontologies: usize,
    pub max_imports: usize,
    pub max_closure_depth: usize,
}
impl Default for UniverseLimits {
    fn default() -> Self {
        Self {
            max_releases: 16,
            max_ontologies: 20_000,
            max_imports: 100_000,
            max_closure_depth: 256,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReleaseReference {
    id: SourceReleaseId,
    #[serde(serialize_with = "serialize_hash")]
    manifest_root: ContentHash,
    #[serde(serialize_with = "serialize_hash")]
    inventory_root: ContentHash,
}
impl ReleaseReference {
    pub fn id(&self) -> &SourceReleaseId {
        &self.id
    }
    pub fn manifest_root(&self) -> &ContentHash {
        &self.manifest_root
    }
    pub fn inventory_root(&self) -> &ContentHash {
        &self.inventory_root
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OntologyDependencyUniverse {
    releases: Vec<ReleaseReference>,
    ownership: Vec<OntologyOwnership>,
    catalogs: Vec<CatalogEvidence>,
    source_policy: String,
    limits_identity: String,
    analyzer_identity: String,
    algorithm_identity: String,
    #[serde(serialize_with = "serialize_hash")]
    catalog_root: ContentHash,
    #[serde(serialize_with = "serialize_hash")]
    reference_root: ContentHash,
    #[serde(serialize_with = "serialize_hash")]
    root: ContentHash,
}

impl OntologyDependencyUniverse {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        mut releases: Vec<SourceReleaseManifest>,
        mut ownership: Vec<OntologyOwnership>,
        mut catalogs: Vec<CatalogEvidence>,
        source_policy: impl Into<String>,
        limits_identity: impl Into<String>,
        analyzer_identity: impl Into<String>,
        algorithm_identity: impl Into<String>,
        limits: UniverseLimits,
    ) -> Result<Self> {
        if releases.is_empty() || releases.len() > limits.max_releases {
            return Err(UniverseError::new(
                UniverseErrorKind::LimitExceeded,
                "release count outside bounds",
            ));
        }
        if ownership.is_empty() || ownership.len() > limits.max_ontologies {
            return Err(UniverseError::new(
                UniverseErrorKind::LimitExceeded,
                "ontology count outside bounds",
            ));
        }
        releases.sort_by(|a, b| a.id().cmp(b.id()));
        if releases.windows(2).any(|w| w[0].id() == w[1].id()) {
            return Err(UniverseError::new(
                UniverseErrorKind::MissingRelease,
                "duplicate source release identity",
            ));
        }
        let release_map: BTreeMap<_, _> = releases.iter().map(|r| (r.id(), r)).collect();
        ownership.sort_by(|a, b| a.ontology_iri.cmp(&b.ontology_iri));
        if ownership
            .windows(2)
            .any(|w| w[0].ontology_iri == w[1].ontology_iri)
        {
            return Err(UniverseError::new(
                UniverseErrorKind::DuplicateOwnership,
                "ontology IRI has more than one owner",
            ));
        }
        let expected_ontology_artifacts: BTreeSet<_> = releases
            .iter()
            .flat_map(|release| {
                release
                    .inventory()
                    .entries()
                    .iter()
                    .filter(|entry| entry.role() == ArtifactRole::OntologyRdf)
                    .map(|entry| (release.id().clone(), entry.path().clone()))
            })
            .collect();
        let owned_ontology_artifacts: BTreeSet<_> = ownership
            .iter()
            .map(|owner| (owner.release_id.clone(), owner.artifact.clone()))
            .collect();
        if owned_ontology_artifacts.len() != ownership.len() {
            return Err(UniverseError::new(
                UniverseErrorKind::DuplicateOwnership,
                "ontology artifact has more than one owner",
            ));
        }
        if expected_ontology_artifacts != owned_ontology_artifacts {
            return Err(UniverseError::new(
                UniverseErrorKind::MissingArtifact,
                "ontology-bearing release inventory and ownership map differ",
            ));
        }

        let mut versions = BTreeSet::new();
        let ontology_iris: BTreeSet<_> =
            ownership.iter().map(|o| o.ontology_iri.as_str()).collect();
        for owner in &ownership {
            if !versions.insert(owner.version_iri.as_str())
                || ontology_iris.contains(owner.version_iri.as_str())
            {
                return Err(UniverseError::new(
                    UniverseErrorKind::VersionAlias,
                    "duplicate or aliased version IRI",
                ));
            }
            let release = release_map.get(&owner.release_id).ok_or_else(|| {
                UniverseError::new(
                    UniverseErrorKind::UndeclaredOwner,
                    "ownership names an undeclared release",
                )
            })?;
            let inventory_entry = release.inventory().entry(&owner.artifact).ok_or_else(|| {
                UniverseError::new(
                    UniverseErrorKind::MissingArtifact,
                    "owned authoritative artifact is absent from the release inventory",
                )
            })?;
            if inventory_entry.hash() != &owner.authoritative_hash
                || inventory_entry.role() != ArtifactRole::OntologyRdf
                || inventory_entry.media_type() != owner.media_type
            {
                return Err(UniverseError::new(
                    UniverseErrorKind::HashMismatch,
                    "ownership disagrees with authoritative classified inventory",
                ));
            }
            if let Some(artifact) = release.artifact(&owner.artifact) {
                if artifact.hash() != &owner.authoritative_hash
                    || artifact.media_type() != owner.media_type
                {
                    return Err(UniverseError::new(
                        UniverseErrorKind::HashMismatch,
                        "ownership disagrees with authoritative artifact pin",
                    ));
                }
            }
            if owner.conversion.source_release_id != owner.release_id.as_str()
                || owner.conversion.source_file_id != owner.artifact.as_str()
                || owner.conversion.authoritative_hash != owner.authoritative_hash
                || owner.conversion.graph_iri != owner.graph_iri
                || owner.conversion.ontology_iris != [owner.ontology_iri.clone()]
                || owner.conversion.version_iris != [owner.version_iri.clone()]
                || owner.conversion.imports != owner.imports
                || owner.conversion.serialization != "application/n-triples"
            {
                return Err(UniverseError::new(
                    UniverseErrorKind::ConversionFailure,
                    "ownership disagrees with the verified conversion result",
                ));
            }
        }
        let import_count = ownership
            .iter()
            .try_fold(0usize, |n, o| n.checked_add(o.imports.len()))
            .ok_or_else(|| {
                UniverseError::new(UniverseErrorKind::LimitExceeded, "import count overflow")
            })?;
        if import_count > limits.max_imports {
            return Err(UniverseError::new(
                UniverseErrorKind::LimitExceeded,
                "import count exceeded",
            ));
        }
        for owner in &ownership {
            for import in &owner.imports {
                if versions.contains(import.as_str()) {
                    return Err(UniverseError::new(
                        UniverseErrorKind::VersionAlias,
                        "imports must use exact unversioned ontology IRIs",
                    ));
                }
                if !ontology_iris.contains(import.as_str()) {
                    return Err(UniverseError::new(
                        UniverseErrorKind::UnresolvedImport,
                        format!("unresolved import {import}"),
                    ));
                }
            }
        }
        catalogs.sort_by_key(catalog_key);
        for catalog in &catalogs {
            match catalog {
                CatalogEvidence::Prefix { .. } => {
                    return Err(UniverseError::new(
                        UniverseErrorKind::CatalogRewrite,
                        "catalog prefix rewrites are not resolver authority",
                    ))
                }
                CatalogEvidence::Exact {
                    ontology_iri,
                    release_id,
                    artifact,
                } => {
                    let owner = ownership
                        .binary_search_by(|o| o.ontology_iri.as_str().cmp(ontology_iri))
                        .ok()
                        .map(|i| &ownership[i]);
                    if !owner
                        .is_some_and(|o| &o.release_id == release_id && &o.artifact == artifact)
                    {
                        return Err(UniverseError::new(
                            UniverseErrorKind::CatalogRewrite,
                            "catalog exact mapping does not match sealed ownership",
                        ));
                    }
                }
            }
        }
        detect_cycles(&ownership, limits.max_closure_depth)?;
        let source_policy = text(source_policy, "source policy identity")?;
        let limits_identity = text(limits_identity, "limits identity")?;
        let analyzer_identity = text(analyzer_identity, "analyzer identity")?;
        let algorithm_identity = text(algorithm_identity, "algorithm identity")?;
        let release_refs: Vec<_> = releases
            .iter()
            .map(|r| ReleaseReference {
                id: r.id().clone(),
                manifest_root: r.root().clone(),
                inventory_root: r.inventory().root().clone(),
            })
            .collect();
        let release_ids: Vec<String> = release_refs
            .iter()
            .map(|r| {
                format!(
                    "{}\0{}\0{}",
                    r.id.as_str(),
                    r.manifest_root.as_str(),
                    r.inventory_root.as_str()
                )
            })
            .collect();
        let owner_ids: Vec<String> = ownership
            .iter()
            .map(|o| o.identity().as_str().to_owned())
            .collect();
        let mut reference_fields: Vec<(&str, &str)> = release_ids
            .iter()
            .map(|v| ("release", v.as_str()))
            .collect();
        reference_fields.extend(owner_ids.iter().map(|v| ("ownership", v.as_str())));
        let reference_root = framed_root("ctxql-ontology-reference-universe/v1", reference_fields);
        let catalog_ids: Vec<String> = catalogs.iter().map(catalog_key).collect();
        let catalog_root = framed_root(
            "ctxql-publisher-catalog-evidence/v1",
            catalog_ids.iter().map(|v| ("mapping", v.as_str())),
        );
        let root = framed_root(
            "ctxql-ontology-dependency-universe/v1",
            [
                ("reference", reference_root.as_str()),
                ("catalog", catalog_root.as_str()),
                ("source-policy", source_policy.as_str()),
                ("limits", limits_identity.as_str()),
                ("analyzer", analyzer_identity.as_str()),
                ("algorithm", algorithm_identity.as_str()),
            ],
        );
        Ok(Self {
            releases: release_refs,
            ownership,
            catalogs,
            source_policy,
            limits_identity,
            analyzer_identity,
            algorithm_identity,
            catalog_root,
            reference_root,
            root,
        })
    }

    pub fn releases(&self) -> &[ReleaseReference] {
        &self.releases
    }
    pub fn ownership(&self) -> &[OntologyOwnership] {
        &self.ownership
    }
    pub fn catalogs(&self) -> &[CatalogEvidence] {
        &self.catalogs
    }
    pub fn source_policy(&self) -> &str {
        &self.source_policy
    }
    pub fn limits_identity(&self) -> &str {
        &self.limits_identity
    }
    pub fn analyzer_identity(&self) -> &str {
        &self.analyzer_identity
    }
    pub fn algorithm_identity(&self) -> &str {
        &self.algorithm_identity
    }
    pub fn owner(&self, ontology_iri: &str) -> Option<&OntologyOwnership> {
        self.ownership
            .binary_search_by(|o| o.ontology_iri.as_str().cmp(ontology_iri))
            .ok()
            .map(|i| &self.ownership[i])
    }
    pub fn catalog_root(&self) -> &ContentHash {
        &self.catalog_root
    }
    pub fn reference_root(&self) -> &ContentHash {
        &self.reference_root
    }
    pub fn root(&self) -> &ContentHash {
        &self.root
    }
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| {
            UniverseError::new(
                UniverseErrorKind::InvalidIdentity,
                "universe serialization failed",
            )
        })
    }

    /// Dependencies-first deterministic transitive closure. Resolution uses only
    /// the sealed exact ownership map.
    pub fn transitive_closure(&self, entries: &[String]) -> Result<Vec<String>> {
        let mut entries = entries.to_vec();
        entries.sort();
        entries.dedup();
        let mut permanent = BTreeSet::new();
        let mut active = BTreeSet::new();
        let mut output = Vec::new();
        for entry in entries {
            self.visit(
                &entry,
                &mut active,
                &mut permanent,
                &mut output,
                self.ownership.len() + 1,
            )?;
        }
        Ok(output)
    }
    fn visit(
        &self,
        iri: &str,
        active: &mut BTreeSet<String>,
        permanent: &mut BTreeSet<String>,
        output: &mut Vec<String>,
        remaining: usize,
    ) -> Result<()> {
        if permanent.contains(iri) {
            return Ok(());
        }
        if remaining == 0 {
            return Err(UniverseError::new(
                UniverseErrorKind::LimitExceeded,
                "closure depth exceeded",
            ));
        }
        if !active.insert(iri.to_owned()) {
            return Err(UniverseError::new(
                UniverseErrorKind::ImportCycle,
                "import cycle",
            ));
        }
        let owner = self.owner(iri).ok_or_else(|| {
            UniverseError::new(
                UniverseErrorKind::OutOfUniverseImport,
                format!("entry/import outside universe: {iri}"),
            )
        })?;
        for import in &owner.imports {
            self.visit(import, active, permanent, output, remaining - 1)?;
        }
        active.remove(iri);
        permanent.insert(iri.to_owned());
        output.push(iri.to_owned());
        Ok(())
    }
}

/// One import edge whose target has no exact owner in the sealed release
/// inventories. Candidate-scoped universes retain these edges as evidence and
/// reject them only when a selected closure reaches the source ontology.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct UnresolvedImportEdge {
    ontology_iri: String,
    import_iri: String,
}

impl UnresolvedImportEdge {
    pub fn ontology_iri(&self) -> &str {
        &self.ontology_iri
    }

    pub fn import_iri(&self) -> &str {
        &self.import_iri
    }
}

/// Additive dependency-universe version which commits complete release-wide
/// graph defects while applying cycle and unresolved-import rejection to the
/// selected candidate closure. `OntologyDependencyUniverse` v1 remains
/// unchanged and continues to reject those defects globally.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CandidateScopedDependencyUniverse {
    releases: Vec<ReleaseReference>,
    ownership: Vec<OntologyOwnership>,
    catalogs: Vec<CatalogEvidence>,
    unresolved_imports: Vec<UnresolvedImportEdge>,
    strongly_connected_components: Vec<Vec<String>>,
    source_policy: String,
    limits_identity: String,
    analyzer_identity: String,
    algorithm_identity: String,
    scc_algorithm_identity: String,
    max_closure_depth: usize,
    #[serde(serialize_with = "serialize_hash")]
    catalog_root: ContentHash,
    #[serde(serialize_with = "serialize_hash")]
    reference_root: ContentHash,
    #[serde(serialize_with = "serialize_hash")]
    unresolved_import_root: ContentHash,
    #[serde(serialize_with = "serialize_hash")]
    strongly_connected_components_root: ContentHash,
    #[serde(serialize_with = "serialize_hash")]
    root: ContentHash,
}

impl CandidateScopedDependencyUniverse {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        mut releases: Vec<SourceReleaseManifest>,
        mut ownership: Vec<OntologyOwnership>,
        mut catalogs: Vec<CatalogEvidence>,
        source_policy: impl Into<String>,
        limits_identity: impl Into<String>,
        analyzer_identity: impl Into<String>,
        algorithm_identity: impl Into<String>,
        scc_algorithm_identity: impl Into<String>,
        limits: UniverseLimits,
    ) -> Result<Self> {
        if releases.is_empty() || releases.len() > limits.max_releases {
            return Err(UniverseError::new(
                UniverseErrorKind::LimitExceeded,
                "release count outside bounds",
            ));
        }
        if ownership.is_empty() || ownership.len() > limits.max_ontologies {
            return Err(UniverseError::new(
                UniverseErrorKind::LimitExceeded,
                "ontology count outside bounds",
            ));
        }
        if limits.max_closure_depth == 0 {
            return Err(UniverseError::new(
                UniverseErrorKind::LimitExceeded,
                "closure depth outside bounds",
            ));
        }
        releases.sort_by(|a, b| a.id().cmp(b.id()));
        if releases.windows(2).any(|w| w[0].id() == w[1].id()) {
            return Err(UniverseError::new(
                UniverseErrorKind::MissingRelease,
                "duplicate source release identity",
            ));
        }
        let release_map: BTreeMap<_, _> = releases.iter().map(|r| (r.id(), r)).collect();
        ownership.sort_by(|a, b| a.ontology_iri.cmp(&b.ontology_iri));
        if ownership
            .windows(2)
            .any(|w| w[0].ontology_iri == w[1].ontology_iri)
        {
            return Err(UniverseError::new(
                UniverseErrorKind::DuplicateOwnership,
                "ontology IRI has more than one owner",
            ));
        }
        let expected_ontology_artifacts: BTreeSet<_> = releases
            .iter()
            .flat_map(|release| {
                release
                    .inventory()
                    .entries()
                    .iter()
                    .filter(|entry| entry.role() == ArtifactRole::OntologyRdf)
                    .map(|entry| (release.id().clone(), entry.path().clone()))
            })
            .collect();
        let owned_ontology_artifacts: BTreeSet<_> = ownership
            .iter()
            .map(|owner| (owner.release_id.clone(), owner.artifact.clone()))
            .collect();
        if owned_ontology_artifacts.len() != ownership.len() {
            return Err(UniverseError::new(
                UniverseErrorKind::DuplicateOwnership,
                "ontology artifact has more than one owner",
            ));
        }
        if expected_ontology_artifacts != owned_ontology_artifacts {
            return Err(UniverseError::new(
                UniverseErrorKind::MissingArtifact,
                "ontology-bearing release inventory and ownership map differ",
            ));
        }

        let mut versions = BTreeSet::new();
        let ontology_iris: BTreeSet<_> =
            ownership.iter().map(|o| o.ontology_iri.as_str()).collect();
        for owner in &ownership {
            if !versions.insert(owner.version_iri.as_str())
                || ontology_iris.contains(owner.version_iri.as_str())
            {
                return Err(UniverseError::new(
                    UniverseErrorKind::VersionAlias,
                    "duplicate or aliased version IRI",
                ));
            }
            let release = release_map.get(&owner.release_id).ok_or_else(|| {
                UniverseError::new(
                    UniverseErrorKind::UndeclaredOwner,
                    "ownership names an undeclared release",
                )
            })?;
            let inventory_entry = release.inventory().entry(&owner.artifact).ok_or_else(|| {
                UniverseError::new(
                    UniverseErrorKind::MissingArtifact,
                    "owned authoritative artifact is absent from the release inventory",
                )
            })?;
            if inventory_entry.hash() != &owner.authoritative_hash
                || inventory_entry.role() != ArtifactRole::OntologyRdf
                || inventory_entry.media_type() != owner.media_type
            {
                return Err(UniverseError::new(
                    UniverseErrorKind::HashMismatch,
                    "ownership disagrees with authoritative classified inventory",
                ));
            }
            if let Some(artifact) = release.artifact(&owner.artifact) {
                if artifact.hash() != &owner.authoritative_hash
                    || artifact.media_type() != owner.media_type
                {
                    return Err(UniverseError::new(
                        UniverseErrorKind::HashMismatch,
                        "ownership disagrees with authoritative artifact pin",
                    ));
                }
            }
            if owner.conversion.source_release_id != owner.release_id.as_str()
                || owner.conversion.source_file_id != owner.artifact.as_str()
                || owner.conversion.authoritative_hash != owner.authoritative_hash
                || owner.conversion.graph_iri != owner.graph_iri
                || owner.conversion.ontology_iris != [owner.ontology_iri.clone()]
                || owner.conversion.version_iris != [owner.version_iri.clone()]
                || owner.conversion.imports != owner.imports
                || owner.conversion.serialization != "application/n-triples"
            {
                return Err(UniverseError::new(
                    UniverseErrorKind::ConversionFailure,
                    "ownership disagrees with the verified conversion result",
                ));
            }
        }
        let import_count = ownership
            .iter()
            .try_fold(0usize, |n, o| n.checked_add(o.imports.len()))
            .ok_or_else(|| {
                UniverseError::new(UniverseErrorKind::LimitExceeded, "import count overflow")
            })?;
        if import_count > limits.max_imports {
            return Err(UniverseError::new(
                UniverseErrorKind::LimitExceeded,
                "import count exceeded",
            ));
        }

        let mut unresolved_imports = Vec::new();
        for owner in &ownership {
            for import in &owner.imports {
                if versions.contains(import.as_str()) {
                    return Err(UniverseError::new(
                        UniverseErrorKind::VersionAlias,
                        "imports must use exact unversioned ontology IRIs",
                    ));
                }
                if !ontology_iris.contains(import.as_str()) {
                    unresolved_imports.push(UnresolvedImportEdge {
                        ontology_iri: owner.ontology_iri.clone(),
                        import_iri: import.clone(),
                    });
                }
            }
        }
        unresolved_imports.sort();

        catalogs.sort_by_key(catalog_key);
        for catalog in &catalogs {
            match catalog {
                CatalogEvidence::Prefix { .. } => {
                    return Err(UniverseError::new(
                        UniverseErrorKind::CatalogRewrite,
                        "catalog prefix rewrites are not resolver authority",
                    ))
                }
                CatalogEvidence::Exact {
                    ontology_iri,
                    release_id,
                    artifact,
                } => {
                    let owner = ownership
                        .binary_search_by(|o| o.ontology_iri.as_str().cmp(ontology_iri))
                        .ok()
                        .map(|i| &ownership[i]);
                    if !owner
                        .is_some_and(|o| &o.release_id == release_id && &o.artifact == artifact)
                    {
                        return Err(UniverseError::new(
                            UniverseErrorKind::CatalogRewrite,
                            "catalog exact mapping does not match sealed ownership",
                        ));
                    }
                }
            }
        }

        let strongly_connected_components = strongly_connected_components(&ownership);
        let source_policy = text(source_policy, "source policy identity")?;
        let limits_identity = text(limits_identity, "limits identity")?;
        let analyzer_identity = text(analyzer_identity, "analyzer identity")?;
        let algorithm_identity = text(algorithm_identity, "algorithm identity")?;
        let scc_algorithm_identity = text(scc_algorithm_identity, "SCC algorithm identity")?;
        let release_refs: Vec<_> = releases
            .iter()
            .map(|r| ReleaseReference {
                id: r.id().clone(),
                manifest_root: r.root().clone(),
                inventory_root: r.inventory().root().clone(),
            })
            .collect();
        let release_ids: Vec<String> = release_refs
            .iter()
            .map(|r| {
                format!(
                    "{}\0{}\0{}",
                    r.id.as_str(),
                    r.manifest_root.as_str(),
                    r.inventory_root.as_str()
                )
            })
            .collect();
        let owner_ids: Vec<String> = ownership
            .iter()
            .map(|o| o.identity().as_str().to_owned())
            .collect();
        let mut reference_fields: Vec<(&str, &str)> = release_ids
            .iter()
            .map(|value| ("release", value.as_str()))
            .collect();
        reference_fields.extend(owner_ids.iter().map(|value| ("ownership", value.as_str())));
        let reference_root = framed_root(
            "ctxql-ontology-reference-universe/v2-candidate-scoped",
            reference_fields,
        );
        let catalog_ids: Vec<String> = catalogs.iter().map(catalog_key).collect();
        let catalog_root = framed_root(
            "ctxql-publisher-catalog-evidence/v1",
            catalog_ids.iter().map(|value| ("mapping", value.as_str())),
        );
        let unresolved_values = unresolved_imports
            .iter()
            .map(|edge| format!("{}\0{}", edge.ontology_iri, edge.import_iri))
            .collect::<Vec<_>>();
        let unresolved_import_root = framed_root(
            "ctxql-ontology-unresolved-imports/v1",
            unresolved_values
                .iter()
                .map(|value| ("edge", value.as_str())),
        );
        let component_values = strongly_connected_components
            .iter()
            .map(|component| component.join("\0"))
            .collect::<Vec<_>>();
        let strongly_connected_components_root = framed_root(
            "ctxql-ontology-import-scc/v1",
            component_values
                .iter()
                .map(|value| ("component", value.as_str())),
        );
        let max_closure_depth = limits.max_closure_depth.to_string();
        let root = framed_root(
            "ctxql-ontology-dependency-universe/v2-candidate-scoped",
            [
                ("reference", reference_root.as_str()),
                ("catalog", catalog_root.as_str()),
                ("unresolved-imports", unresolved_import_root.as_str()),
                (
                    "strongly-connected-components",
                    strongly_connected_components_root.as_str(),
                ),
                ("source-policy", source_policy.as_str()),
                ("limits", limits_identity.as_str()),
                ("analyzer", analyzer_identity.as_str()),
                ("algorithm", algorithm_identity.as_str()),
                ("scc-algorithm", scc_algorithm_identity.as_str()),
                ("max-closure-depth", max_closure_depth.as_str()),
            ],
        );
        Ok(Self {
            releases: release_refs,
            ownership,
            catalogs,
            unresolved_imports,
            strongly_connected_components,
            source_policy,
            limits_identity,
            analyzer_identity,
            algorithm_identity,
            scc_algorithm_identity,
            max_closure_depth: limits.max_closure_depth,
            catalog_root,
            reference_root,
            unresolved_import_root,
            strongly_connected_components_root,
            root,
        })
    }

    pub fn releases(&self) -> &[ReleaseReference] {
        &self.releases
    }

    pub fn ownership(&self) -> &[OntologyOwnership] {
        &self.ownership
    }

    pub fn catalogs(&self) -> &[CatalogEvidence] {
        &self.catalogs
    }

    pub fn unresolved_imports(&self) -> &[UnresolvedImportEdge] {
        &self.unresolved_imports
    }

    pub fn strongly_connected_components(&self) -> &[Vec<String>] {
        &self.strongly_connected_components
    }

    pub fn source_policy(&self) -> &str {
        &self.source_policy
    }

    pub fn limits_identity(&self) -> &str {
        &self.limits_identity
    }

    pub fn analyzer_identity(&self) -> &str {
        &self.analyzer_identity
    }

    pub fn algorithm_identity(&self) -> &str {
        &self.algorithm_identity
    }

    pub fn scc_algorithm_identity(&self) -> &str {
        &self.scc_algorithm_identity
    }

    pub fn owner(&self, ontology_iri: &str) -> Option<&OntologyOwnership> {
        self.ownership
            .binary_search_by(|owner| owner.ontology_iri.as_str().cmp(ontology_iri))
            .ok()
            .map(|index| &self.ownership[index])
    }

    pub fn catalog_root(&self) -> &ContentHash {
        &self.catalog_root
    }

    pub fn reference_root(&self) -> &ContentHash {
        &self.reference_root
    }

    pub fn unresolved_import_root(&self) -> &ContentHash {
        &self.unresolved_import_root
    }

    pub fn strongly_connected_components_root(&self) -> &ContentHash {
        &self.strongly_connected_components_root
    }

    pub fn root(&self) -> &ContentHash {
        &self.root
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| {
            UniverseError::new(
                UniverseErrorKind::InvalidIdentity,
                "candidate-scoped universe serialization failed",
            )
        })
    }

    /// Dependencies-first deterministic transitive closure. Every reachable
    /// import is mandatory; unresolved targets and reachable cycles fail closed.
    pub fn transitive_closure(&self, entries: &[String]) -> Result<Vec<String>> {
        let mut entries = entries.to_vec();
        entries.sort();
        entries.dedup();
        let mut permanent = BTreeSet::new();
        let mut active = BTreeSet::new();
        let mut output = Vec::new();
        for entry in entries {
            self.visit(
                &entry,
                &mut active,
                &mut permanent,
                &mut output,
                self.max_closure_depth,
            )?;
        }
        Ok(output)
    }

    fn visit(
        &self,
        iri: &str,
        active: &mut BTreeSet<String>,
        permanent: &mut BTreeSet<String>,
        output: &mut Vec<String>,
        remaining: usize,
    ) -> Result<()> {
        if permanent.contains(iri) {
            return Ok(());
        }
        if remaining == 0 {
            return Err(UniverseError::new(
                UniverseErrorKind::LimitExceeded,
                "closure depth exceeded",
            ));
        }
        if !active.insert(iri.to_owned()) {
            return Err(UniverseError::new(
                UniverseErrorKind::ImportCycle,
                format!("selected import cycle at {iri}"),
            ));
        }
        let owner = self.owner(iri).ok_or_else(|| {
            UniverseError::new(
                UniverseErrorKind::OutOfUniverseImport,
                format!("entry outside universe: {iri}"),
            )
        })?;
        for import in &owner.imports {
            if self.owner(import).is_none() {
                return Err(UniverseError::new(
                    UniverseErrorKind::UnresolvedImport,
                    format!("selected unresolved import {iri} -> {import}"),
                ));
            }
            self.visit(import, active, permanent, output, remaining - 1)?;
        }
        active.remove(iri);
        permanent.insert(iri.to_owned());
        output.push(iri.to_owned());
        Ok(())
    }
}

/// Deterministic iterative Kosaraju projection over owned import edges. All
/// components are committed; unresolved edges are represented separately.
fn strongly_connected_components(ownership: &[OntologyOwnership]) -> Vec<Vec<String>> {
    let nodes = ownership
        .iter()
        .map(|owner| owner.ontology_iri.clone())
        .collect::<Vec<_>>();
    let owned = nodes.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let edges = ownership
        .iter()
        .map(|owner| {
            (
                owner.ontology_iri.clone(),
                owner
                    .imports
                    .iter()
                    .filter(|import| owned.contains(import.as_str()))
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut visited = BTreeSet::new();
    let mut finish = Vec::new();
    for start in &nodes {
        if visited.contains(start) {
            continue;
        }
        visited.insert(start.clone());
        let mut stack = vec![(start.clone(), 0usize)];
        while let Some((node, next)) = stack.pop() {
            let outgoing = edges.get(&node).map(Vec::as_slice).unwrap_or_default();
            if next < outgoing.len() {
                stack.push((node, next + 1));
                let target = &outgoing[next];
                if visited.insert(target.clone()) {
                    stack.push((target.clone(), 0));
                }
            } else {
                finish.push(node);
            }
        }
    }

    let mut reverse = nodes
        .iter()
        .map(|node| (node.clone(), Vec::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    for (source, targets) in &edges {
        for target in targets {
            reverse
                .get_mut(target)
                .expect("owned reverse node")
                .push(source.clone());
        }
    }
    for incoming in reverse.values_mut() {
        incoming.sort();
    }

    visited.clear();
    let mut components = Vec::new();
    while let Some(start) = finish.pop() {
        if !visited.insert(start.clone()) {
            continue;
        }
        let mut component = Vec::new();
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            component.push(node.clone());
            for source in reverse.get(&node).map(Vec::as_slice).unwrap_or_default() {
                if visited.insert(source.clone()) {
                    stack.push(source.clone());
                }
            }
        }
        component.sort();
        components.push(component);
    }
    components.sort();
    components
}

fn catalog_key(catalog: &CatalogEvidence) -> String {
    match catalog {
        CatalogEvidence::Exact {
            ontology_iri,
            release_id,
            artifact,
        } => format!(
            "exact\0{ontology_iri}\0{}\0{}",
            release_id.as_str(),
            artifact.as_str()
        ),
        CatalogEvidence::Prefix {
            prefix,
            replacement,
        } => format!("prefix\0{prefix}\0{replacement}"),
    }
}

fn detect_cycles(ownership: &[OntologyOwnership], max_depth: usize) -> Result<()> {
    let map: BTreeMap<_, _> = ownership
        .iter()
        .map(|o| (o.ontology_iri.as_str(), o))
        .collect();
    let mut done = BTreeSet::new();
    let mut active = BTreeSet::new();
    fn visit<'a>(
        node: &'a str,
        map: &BTreeMap<&'a str, &'a OntologyOwnership>,
        active: &mut BTreeSet<&'a str>,
        done: &mut BTreeSet<&'a str>,
        remaining: usize,
    ) -> Result<()> {
        if done.contains(node) {
            return Ok(());
        }
        if remaining == 0 {
            return Err(UniverseError::new(
                UniverseErrorKind::LimitExceeded,
                "import depth exceeded",
            ));
        }
        if !active.insert(node) {
            return Err(UniverseError::new(
                UniverseErrorKind::ImportCycle,
                format!("cross-release import cycle at {node}"),
            ));
        }
        let owner = map
            .get(node)
            .ok_or_else(|| UniverseError::new(UniverseErrorKind::UnresolvedImport, node))?;
        for import in &owner.imports {
            visit(import, map, active, done, remaining - 1)?;
        }
        active.remove(node);
        done.insert(node);
        Ok(())
    }
    for node in map.keys().copied() {
        visit(node, &map, &mut active, &mut done, max_depth)?;
    }
    Ok(())
}
