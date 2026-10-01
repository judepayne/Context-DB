//! Offline, content-addressed ontology source-release identities.
//!
//! This module deliberately has no fetch path. Callers supply a local external
//! root and publisher metadata; all retained identities are independent of that
//! root's location.

use crate::authorized_view::framed_root;
use cdb_core::id::ContentHash;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

pub const ONTOLOGY_RELEASE_UNAPPROVED: &str = "ontology_release_unapproved";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseError {
    detail: String,
}

impl ReleaseError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
    pub fn reason_code(&self) -> &'static str {
        ONTOLOGY_RELEASE_UNAPPROVED
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
}
impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason_code(), self.detail)
    }
}
impl std::error::Error for ReleaseError {}
impl From<io::Error> for ReleaseError {
    fn from(value: io::Error) -> Self {
        Self::new(format!("source file error: {value}"))
    }
}

type Result<T> = std::result::Result<T, ReleaseError>;

fn text(label: &str, value: impl Into<String>) -> Result<String> {
    let value = value.into();
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(ReleaseError::new(format!("invalid {label}")));
    }
    Ok(value)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct SourceReleaseId(String);
impl SourceReleaseId {
    fn from_commitments<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self(
            framed_root("ctxql-source-release-id/v2", fields)
                .as_str()
                .to_owned(),
        )
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct RelativeSourcePath(String);
impl RelativeSourcePath {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = text("relative UTF-8 source path", value)?;
        if value.contains('\\')
            || value.ends_with('/')
            || value
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err(ReleaseError::new(
                "source path must be normalized and relative",
            ));
        }
        let path = Path::new(&value);
        if path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(ReleaseError::new(
                "source path must contain only normal relative components",
            ));
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn depth(&self) -> usize {
        self.0.split('/').count()
    }
}

/// Accept only an exact HTTPS publisher object URL containing the exact release
/// version as a complete path segment. Query/fragment URLs, floating aliases,
/// and bare content-negotiated ontology identifiers are intentionally excluded.
pub fn validate_version_specific_https_url(url: &str, version: &str) -> Result<()> {
    text("source URL", url)?;
    text("version", version)?;
    if !url.starts_with("https://") || url.contains('?') || url.contains('#') || url.contains('@') {
        return Err(ReleaseError::new(
            "exact HTTPS URL without query, fragment, or userinfo required",
        ));
    }
    let authority_and_path = &url[8..];
    let (host, path) = authority_and_path
        .split_once('/')
        .ok_or_else(|| ReleaseError::new("version-specific URL path required"))?;
    if host.is_empty() || host.contains(':') || path.is_empty() {
        return Err(ReleaseError::new("canonical HTTPS host and path required"));
    }
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments
        .iter()
        .any(|s| s.eq_ignore_ascii_case("latest") || s.eq_ignore_ascii_case("current"))
    {
        return Err(ReleaseError::new("floating source URL is prohibited"));
    }
    let leaf = segments.last().copied().unwrap_or_default();
    let versioned_segment = segments.contains(&version);
    let versioned_leaf = leaf
        .strip_prefix(version)
        .is_some_and(|suffix| suffix.starts_with('.'));
    if !versioned_segment && !versioned_leaf {
        return Err(ReleaseError::new(
            "source URL does not contain the exact version identity",
        ));
    }
    if leaf == version || !leaf.contains('.') || leaf.ends_with('.') {
        return Err(ReleaseError::new(
            "URL must identify a versioned artifact, not a content-negotiated identifier",
        ));
    }
    Ok(())
}

pub const ARTIFACT_CLASSIFICATION_POLICY: &str = "ctxql-artifact-classification/closed-v1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    OntologyRdf,
    PublisherCatalog,
    License,
    Notice,
    ReleaseMetadata,
    SourcePackage,
    Other,
}
impl ArtifactRole {
    pub const ALL: [Self; 7] = [
        Self::OntologyRdf,
        Self::PublisherCatalog,
        Self::License,
        Self::Notice,
        Self::ReleaseMetadata,
        Self::SourcePackage,
        Self::Other,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OntologyRdf => "ontology_rdf",
            Self::PublisherCatalog => "publisher_catalog",
            Self::License => "license",
            Self::Notice => "notice",
            Self::ReleaseMetadata => "release_metadata",
            Self::SourcePackage => "source_package",
            Self::Other => "other",
        }
    }
}

fn is_rdf_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        "application/rdf+xml"
            | "text/turtle"
            | "application/n-triples"
            | "application/trig"
            | "application/n-quads"
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactClassification {
    role: ArtifactRole,
    media_type: String,
}
impl ArtifactClassification {
    pub fn new(role: ArtifactRole, media_type: impl Into<String>) -> Result<Self> {
        let media_type = text("media type", media_type)?;
        let valid = media_type.len() <= 127
            && media_type.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'/' | b'+' | b'-' | b'.')
            })
            && media_type
                .split_once('/')
                .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && !b.contains('/'));
        if !valid {
            return Err(ReleaseError::new("invalid normalized media type"));
        }
        if (role == ArtifactRole::OntologyRdf) != is_rdf_media_type(&media_type) {
            return Err(ReleaseError::new(
                "RDF media and ontology_rdf role must agree",
            ));
        }
        Ok(Self { role, media_type })
    }
    pub fn role(&self) -> ArtifactRole {
        self.role
    }
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceArtifactPin {
    path: RelativeSourcePath,
    source_url: String,
    #[serde(serialize_with = "serialize_hash")]
    hash: ContentHash,
    size: u64,
    classification: ArtifactClassification,
}
impl SourceArtifactPin {
    pub fn new(
        path: RelativeSourcePath,
        source_url: impl Into<String>,
        version: &str,
        hash: ContentHash,
        size: u64,
        classification: ArtifactClassification,
    ) -> Result<Self> {
        let source_url = source_url.into();
        validate_version_specific_https_url(&source_url, version)?;
        if size == 0 {
            return Err(ReleaseError::new("empty source artifact"));
        }
        Ok(Self {
            path,
            source_url,
            hash,
            size,
            classification,
        })
    }
    pub fn path(&self) -> &RelativeSourcePath {
        &self.path
    }
    pub fn source_url(&self) -> &str {
        &self.source_url
    }
    pub fn hash(&self) -> &ContentHash {
        &self.hash
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn media_type(&self) -> &str {
        self.classification.media_type()
    }
    pub fn role(&self) -> ArtifactRole {
        self.classification.role()
    }
    pub fn classification(&self) -> &ArtifactClassification {
        &self.classification
    }
    pub fn identity(&self) -> ContentHash {
        framed_root(
            "ctxql-source-artifact-pin/v1",
            [
                ("path", self.path.as_str()),
                ("url", &self.source_url),
                ("hash", self.hash.as_str()),
                ("size", &self.size.to_string()),
                ("media-type", self.media_type()),
                ("role", self.role().as_str()),
            ],
        )
    }
}

fn serialize_hash<S: serde::Serializer>(
    hash: &ContentHash,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(hash.as_str())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReleaseEvidence {
    kind: EvidenceKind,
    path: RelativeSourcePath,
    #[serde(serialize_with = "serialize_hash")]
    hash: ContentHash,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    License,
    Notice,
}
impl ReleaseEvidence {
    pub fn license(path: RelativeSourcePath, hash: ContentHash) -> Self {
        Self {
            kind: EvidenceKind::License,
            path,
            hash,
        }
    }
    pub fn notice(path: RelativeSourcePath, hash: ContentHash) -> Self {
        Self {
            kind: EvidenceKind::Notice,
            path,
            hash,
        }
    }
    pub fn kind(&self) -> EvidenceKind {
        self.kind
    }
    pub fn path(&self) -> &RelativeSourcePath {
        &self.path
    }
    pub fn hash(&self) -> &ContentHash {
        &self.hash
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct LicenseEvidence(ReleaseEvidence);
impl LicenseEvidence {
    pub fn new(path: RelativeSourcePath, hash: ContentHash) -> Self {
        Self(ReleaseEvidence::license(path, hash))
    }
    pub fn as_evidence(&self) -> &ReleaseEvidence {
        &self.0
    }
}
impl From<LicenseEvidence> for ReleaseEvidence {
    fn from(value: LicenseEvidence) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NoticeEvidence(ReleaseEvidence);
impl NoticeEvidence {
    pub fn new(path: RelativeSourcePath, hash: ContentHash) -> Self {
        Self(ReleaseEvidence::notice(path, hash))
    }
    pub fn as_evidence(&self) -> &ReleaseEvidence {
        &self.0
    }
}
impl From<NoticeEvidence> for ReleaseEvidence {
    fn from(value: NoticeEvidence) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InventoryEntry {
    path: RelativeSourcePath,
    #[serde(serialize_with = "serialize_hash")]
    hash: ContentHash,
    size: u64,
    classification: ArtifactClassification,
}
impl InventoryEntry {
    pub fn new(
        path: RelativeSourcePath,
        hash: ContentHash,
        size: u64,
        classification: ArtifactClassification,
    ) -> Result<Self> {
        if size == 0 {
            return Err(ReleaseError::new("empty inventory file"));
        }
        Ok(Self {
            path,
            hash,
            size,
            classification,
        })
    }
    pub fn path(&self) -> &RelativeSourcePath {
        &self.path
    }
    pub fn hash(&self) -> &ContentHash {
        &self.hash
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn classification(&self) -> &ArtifactClassification {
        &self.classification
    }
    pub fn role(&self) -> ArtifactRole {
        self.classification.role()
    }
    pub fn media_type(&self) -> &str {
        self.classification.media_type()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompleteInventory {
    entries: Vec<InventoryEntry>,
    total_bytes: u64,
    role_counts: BTreeMap<String, u64>,
    classification_policy: String,
    #[serde(serialize_with = "serialize_hash")]
    classification_root: ContentHash,
    #[serde(serialize_with = "serialize_hash")]
    root: ContentHash,
}
impl CompleteInventory {
    pub fn new(mut entries: Vec<InventoryEntry>) -> Result<Self> {
        if entries.is_empty() {
            return Err(ReleaseError::new("complete inventory cannot be empty"));
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        if entries.windows(2).any(|w| w[0].path == w[1].path) {
            return Err(ReleaseError::new("duplicate normalized inventory path"));
        }
        let total_bytes = entries
            .iter()
            .try_fold(0u64, |n, e| n.checked_add(e.size))
            .ok_or_else(|| ReleaseError::new("inventory byte count overflow"))?;
        let mut role_counts = ArtifactRole::ALL
            .into_iter()
            .map(|role| (role.as_str().to_owned(), 0u64))
            .collect::<BTreeMap<_, _>>();
        for entry in &entries {
            *role_counts.get_mut(entry.role().as_str()).unwrap() += 1;
        }
        let identities: Vec<String> = entries
            .iter()
            .map(|e| {
                format!(
                    "{}\0{}\0{}\0{}\0{}",
                    e.path.as_str(),
                    e.hash.as_str(),
                    e.size,
                    e.role().as_str(),
                    e.media_type()
                )
            })
            .collect();
        let classification_root = framed_root(
            "ctxql-artifact-classification/v1",
            std::iter::once(("policy", ARTIFACT_CLASSIFICATION_POLICY))
                .chain(identities.iter().map(|v| ("entry", v.as_str()))),
        );
        let total_bytes_text = total_bytes.to_string();
        let root = framed_root(
            "ctxql-source-inventory/v2",
            [
                ("classification", classification_root.as_str()),
                ("total-bytes", total_bytes_text.as_str()),
            ],
        );
        Ok(Self {
            entries,
            total_bytes,
            role_counts,
            classification_policy: ARTIFACT_CLASSIFICATION_POLICY.to_owned(),
            classification_root,
            root,
        })
    }
    pub fn entries(&self) -> &[InventoryEntry] {
        &self.entries
    }
    pub fn root(&self) -> &ContentHash {
        &self.root
    }
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
    pub fn role_counts(&self) -> &BTreeMap<String, u64> {
        &self.role_counts
    }
    pub fn classification_policy(&self) -> &str {
        &self.classification_policy
    }
    pub fn classification_root(&self) -> &ContentHash {
        &self.classification_root
    }
    pub fn entry(&self, path: &RelativeSourcePath) -> Option<&InventoryEntry> {
        self.entries
            .binary_search_by(|e| e.path.cmp(path))
            .ok()
            .map(|i| &self.entries[i])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseForm {
    Archive,
    SyntheticArtifacts,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceReleaseManifest {
    schema: String,
    #[serde(rename = "source_release_id")]
    id: SourceReleaseId,
    publisher: String,
    product: String,
    #[serde(rename = "release_version")]
    version: String,
    #[serde(rename = "release_form")]
    form: ReleaseForm,
    tag: Option<String>,
    commit: Option<String>,
    tree: Option<String>,
    retrieved_at: Option<String>,
    retrieval_evidence: Option<String>,
    artifacts: Vec<SourceArtifactPin>,
    evidence: Vec<ReleaseEvidence>,
    inventory: CompleteInventory,
    safe_extraction_limits_identity: Option<String>,
    immutable_source_evidence: String,
    #[serde(rename = "manifest_root", serialize_with = "serialize_hash")]
    root: ContentHash,
}
impl SourceReleaseManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publisher: impl Into<String>,
        product: impl Into<String>,
        version: impl Into<String>,
        form: ReleaseForm,
        tag: Option<String>,
        commit: Option<String>,
        tree: Option<String>,
        retrieved_at: Option<String>,
        retrieval_evidence: Option<String>,
        mut artifacts: Vec<SourceArtifactPin>,
        mut evidence: Vec<ReleaseEvidence>,
        inventory: CompleteInventory,
        safe_extraction_limits_identity: Option<String>,
        immutable_source_evidence: impl Into<String>,
    ) -> Result<Self> {
        let publisher = text("publisher", publisher)?;
        let product = text("product", product)?;
        let version = text("version", version)?;
        if version.eq_ignore_ascii_case("latest") || version.eq_ignore_ascii_case("current") {
            return Err(ReleaseError::new("floating release version"));
        }
        if commit.is_some() != tree.is_some()
            || retrieved_at.is_some() != retrieval_evidence.is_some()
        {
            return Err(ReleaseError::new(
                "invalid nullable revision or retrieval combination",
            ));
        }
        for (label, value) in [
            ("tag", tag.as_deref()),
            ("commit", commit.as_deref()),
            ("tree", tree.as_deref()),
            ("retrieved_at", retrieved_at.as_deref()),
            ("retrieval evidence", retrieval_evidence.as_deref()),
            (
                "safe extraction limits",
                safe_extraction_limits_identity.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                text(label, value)?;
            }
        }
        let immutable_source_evidence =
            text("immutable source evidence", immutable_source_evidence)?;
        if artifacts.is_empty() {
            return Err(ReleaseError::new("release has no pinned artifacts"));
        }
        artifacts.sort_by(|a, b| a.path.cmp(&b.path));
        if artifacts.windows(2).any(|w| w[0].path == w[1].path) {
            return Err(ReleaseError::new("duplicate artifact path"));
        }
        evidence.sort_by(|a, b| a.path.cmp(&b.path));
        if evidence.windows(2).any(|w| w[0].path == w[1].path) {
            return Err(ReleaseError::new("duplicate evidence path"));
        }
        if evidence.is_empty()
            || !evidence.iter().any(|e| e.kind == EvidenceKind::License)
            || !evidence.iter().any(|e| e.kind == EvidenceKind::Notice)
        {
            return Err(ReleaseError::new(
                "both license and notice evidence are required",
            ));
        }
        for artifact in &artifacts {
            let entry = inventory
                .entry(&artifact.path)
                .ok_or_else(|| ReleaseError::new("artifact absent from complete inventory"))?;
            if entry.hash != artifact.hash
                || entry.size != artifact.size
                || entry.classification != artifact.classification
            {
                return Err(ReleaseError::new(
                    "artifact identity disagrees with inventory",
                ));
            }
        }
        for item in &evidence {
            let entry = inventory
                .entry(&item.path)
                .ok_or_else(|| ReleaseError::new("evidence absent from complete inventory"))?;
            let expected_role = match item.kind {
                EvidenceKind::License => ArtifactRole::License,
                EvidenceKind::Notice => ArtifactRole::Notice,
            };
            if entry.hash != item.hash || entry.role() != expected_role {
                return Err(ReleaseError::new(
                    "evidence identity or role disagrees with inventory",
                ));
            }
        }
        let artifact_ids: Vec<String> = artifacts
            .iter()
            .map(|a| a.identity().as_str().to_owned())
            .collect();
        let evidence_ids: Vec<String> = evidence
            .iter()
            .map(|e| format!("{:?}\0{}\0{}", e.kind, e.path.as_str(), e.hash.as_str()))
            .collect();
        let form_identity = match form {
            ReleaseForm::Archive => "archive",
            ReleaseForm::SyntheticArtifacts => "synthetic-artifacts",
        };
        let mut id_fields = vec![
            ("publisher", publisher.as_str()),
            ("product", product.as_str()),
            ("version", version.as_str()),
            ("form", form_identity),
            ("inventory", inventory.root.as_str()),
        ];
        id_fields.extend(artifact_ids.iter().map(|v| ("artifact", v.as_str())));
        id_fields.extend(evidence_ids.iter().map(|v| ("evidence", v.as_str())));
        id_fields.push(("classification-policy", inventory.classification_policy()));
        id_fields.push((
            "classification-root",
            inventory.classification_root().as_str(),
        ));
        id_fields.push((
            "immutable-source-evidence",
            immutable_source_evidence.as_str(),
        ));
        if let Some(v) = tag.as_deref() {
            id_fields.push(("tag", v));
        }
        if let Some(v) = commit.as_deref() {
            id_fields.push(("commit", v));
        }
        if let Some(v) = tree.as_deref() {
            id_fields.push(("tree", v));
        }
        if let Some(v) = retrieval_evidence.as_deref() {
            id_fields.push(("retrieval-evidence", v));
        }
        if let Some(v) = safe_extraction_limits_identity.as_deref() {
            id_fields.push(("safe-extraction-limits", v));
        }
        let id = SourceReleaseId::from_commitments(id_fields);
        let none = "null";
        let root = framed_root(
            "ctxql-source-release-manifest/v2",
            [
                ("release-id", id.as_str()),
                ("retrieved-at", retrieved_at.as_deref().unwrap_or(none)),
                (
                    "retrieval-evidence",
                    retrieval_evidence.as_deref().unwrap_or(none),
                ),
                (
                    "limits",
                    safe_extraction_limits_identity.as_deref().unwrap_or(none),
                ),
            ],
        );
        Ok(Self {
            schema: "ctxql.p6-source-release/v2".to_owned(),
            id,
            publisher,
            product,
            version,
            form,
            tag,
            commit,
            tree,
            retrieved_at,
            retrieval_evidence,
            artifacts,
            evidence,
            inventory,
            safe_extraction_limits_identity,
            immutable_source_evidence,
            root,
        })
    }
    pub fn id(&self) -> &SourceReleaseId {
        &self.id
    }
    pub fn publisher(&self) -> &str {
        &self.publisher
    }
    pub fn product(&self) -> &str {
        &self.product
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn form(&self) -> ReleaseForm {
        self.form
    }
    pub fn artifacts(&self) -> &[SourceArtifactPin] {
        &self.artifacts
    }
    pub fn evidence(&self) -> &[ReleaseEvidence] {
        &self.evidence
    }
    pub fn inventory(&self) -> &CompleteInventory {
        &self.inventory
    }
    pub fn root(&self) -> &ContentHash {
        &self.root
    }
    pub fn artifact(&self, path: &RelativeSourcePath) -> Option<&SourceArtifactPin> {
        self.artifacts
            .binary_search_by(|a| a.path.cmp(path))
            .ok()
            .map(|i| &self.artifacts[i])
    }
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)
            .map_err(|_| ReleaseError::new("manifest serialization failed"))?;
        serde_json::to_vec(&value).map_err(|_| ReleaseError::new("manifest serialization failed"))
    }
    /// Strictly verifies canonical bytes against a trusted manifest, rejecting
    /// unknown fields, reordering, duplicates, and stale content roots.
    pub fn verify_canonical_json(&self, bytes: &[u8]) -> Result<()> {
        verify_source_release_manifest_v2(bytes)?;
        if bytes != self.canonical_json()? {
            return Err(ReleaseError::new(
                "manifest does not match expected authority",
            ));
        }
        Ok(())
    }
}

/// Independently verify strict canonical v2 JSON and every inventory,
/// classification, source-release, and manifest commitment.
pub fn verify_source_release_manifest_v2(bytes: &[u8]) -> Result<()> {
    use serde_json::{Map, Value};
    fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
        value
            .as_object()
            .ok_or_else(|| ReleaseError::new(format!("invalid {label}")))
    }
    fn string<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
        map.get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| ReleaseError::new(format!("invalid {key}")))
    }
    fn exact_keys(map: &Map<String, Value>, keys: &[&str], label: &str) -> Result<()> {
        let actual: std::collections::BTreeSet<_> = map.keys().map(String::as_str).collect();
        let expected: std::collections::BTreeSet<_> = keys.iter().copied().collect();
        if actual != expected {
            return Err(ReleaseError::new(format!(
                "unknown or missing {label} field"
            )));
        }
        Ok(())
    }
    fn nullable<'a>(map: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>> {
        match map.get(key) {
            Some(Value::Null) => Ok(None),
            Some(Value::String(value)) if !value.is_empty() => Ok(Some(value)),
            _ => Err(ReleaseError::new(format!("invalid nullable {key}"))),
        }
    }

    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ReleaseError::new("invalid manifest JSON"))?;
    if serde_json::to_vec(&value).map_err(|_| ReleaseError::new("manifest serialization failed"))?
        != bytes
    {
        return Err(ReleaseError::new("noncanonical or duplicate manifest JSON"));
    }
    let root = object(&value, "manifest")?;
    exact_keys(
        root,
        &[
            "schema",
            "source_release_id",
            "publisher",
            "product",
            "release_version",
            "release_form",
            "tag",
            "commit",
            "tree",
            "retrieved_at",
            "retrieval_evidence",
            "artifacts",
            "evidence",
            "inventory",
            "safe_extraction_limits_identity",
            "immutable_source_evidence",
            "manifest_root",
        ],
        "manifest",
    )?;
    if string(root, "schema")? != "ctxql.p6-source-release/v2" {
        return Err(ReleaseError::new("wrong manifest schema"));
    }
    let tag = nullable(root, "tag")?;
    let commit = nullable(root, "commit")?;
    let tree = nullable(root, "tree")?;
    let retrieved_at = nullable(root, "retrieved_at")?;
    let retrieval_evidence = nullable(root, "retrieval_evidence")?;
    let limits = nullable(root, "safe_extraction_limits_identity")?;
    if commit.is_some() != tree.is_some() || retrieved_at.is_some() != retrieval_evidence.is_some()
    {
        return Err(ReleaseError::new(
            "invalid nullable revision or retrieval combination",
        ));
    }

    let inventory = object(
        root.get("inventory")
            .ok_or_else(|| ReleaseError::new("missing inventory"))?,
        "inventory",
    )?;
    exact_keys(
        inventory,
        &[
            "entries",
            "total_bytes",
            "role_counts",
            "classification_policy",
            "classification_root",
            "root",
        ],
        "inventory",
    )?;
    if string(inventory, "classification_policy")? != ARTIFACT_CLASSIFICATION_POLICY {
        return Err(ReleaseError::new("wrong classification policy"));
    }
    let rows = inventory
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| ReleaseError::new("invalid inventory entries"))?;
    let mut identities = Vec::new();
    let mut by_path = BTreeMap::new();
    let mut counts = ArtifactRole::ALL
        .into_iter()
        .map(|r| (r.as_str(), 0u64))
        .collect::<BTreeMap<_, _>>();
    let mut total = 0u64;
    for row in rows {
        let row = object(row, "inventory entry")?;
        exact_keys(
            row,
            &["path", "hash", "size", "classification"],
            "inventory entry",
        )?;
        let path = RelativeSourcePath::new(string(row, "path")?)?;
        let hash = ContentHash::parse(string(row, "hash")?)
            .map_err(|_| ReleaseError::new("invalid inventory hash"))?;
        let size = row
            .get("size")
            .and_then(Value::as_u64)
            .filter(|v| *v > 0)
            .ok_or_else(|| ReleaseError::new("invalid inventory size"))?;
        let classification = object(
            row.get("classification")
                .ok_or_else(|| ReleaseError::new("missing classification"))?,
            "classification",
        )?;
        exact_keys(classification, &["role", "media_type"], "classification")?;
        let role = ArtifactRole::ALL
            .into_iter()
            .find(|r| r.as_str() == string(classification, "role").unwrap_or(""))
            .ok_or_else(|| ReleaseError::new("invalid artifact role"))?;
        let classification =
            ArtifactClassification::new(role, string(classification, "media_type")?)?;
        total = total
            .checked_add(size)
            .ok_or_else(|| ReleaseError::new("inventory byte count overflow"))?;
        *counts.get_mut(role.as_str()).unwrap() += 1;
        identities.push(format!(
            "{}\0{}\0{}\0{}\0{}",
            path.as_str(),
            hash.as_str(),
            size,
            role.as_str(),
            classification.media_type()
        ));
        if by_path
            .insert(
                path.as_str().to_owned(),
                (
                    hash.as_str().to_owned(),
                    size,
                    role.as_str().to_owned(),
                    classification.media_type().to_owned(),
                ),
            )
            .is_some()
        {
            return Err(ReleaseError::new("duplicate inventory path"));
        }
    }
    let mut sorted = identities.clone();
    sorted.sort();
    if rows.is_empty() || identities != sorted {
        return Err(ReleaseError::new("noncanonical inventory order"));
    }
    let classification_root = framed_root(
        "ctxql-artifact-classification/v1",
        std::iter::once(("policy", ARTIFACT_CLASSIFICATION_POLICY))
            .chain(identities.iter().map(|v| ("entry", v.as_str()))),
    );
    if string(inventory, "classification_root")? != classification_root.as_str() {
        return Err(ReleaseError::new("stale classification root"));
    }
    let total_text = total.to_string();
    let inventory_root = framed_root(
        "ctxql-source-inventory/v2",
        [
            ("classification", classification_root.as_str()),
            ("total-bytes", total_text.as_str()),
        ],
    );
    if inventory.get("total_bytes").and_then(Value::as_u64) != Some(total)
        || string(inventory, "root")? != inventory_root.as_str()
    {
        return Err(ReleaseError::new("stale inventory totals or root"));
    }
    let role_counts = object(
        inventory
            .get("role_counts")
            .ok_or_else(|| ReleaseError::new("missing role counts"))?,
        "role counts",
    )?;
    exact_keys(
        role_counts,
        &ArtifactRole::ALL.map(ArtifactRole::as_str),
        "role counts",
    )?;
    for (role, count) in counts {
        if role_counts.get(role).and_then(Value::as_u64) != Some(count) {
            return Err(ReleaseError::new("stale role counts"));
        }
    }

    let artifacts = root
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| ReleaseError::new("invalid artifacts"))?;
    let mut artifact_ids = Vec::new();
    let mut artifact_paths = Vec::new();
    for artifact in artifacts {
        let artifact = object(artifact, "artifact")?;
        exact_keys(
            artifact,
            &["path", "source_url", "hash", "size", "classification"],
            "artifact",
        )?;
        let p = string(artifact, "path")?;
        let h = string(artifact, "hash")?;
        let size = artifact
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| ReleaseError::new("invalid artifact size"))?;
        let c = object(
            artifact.get("classification").unwrap_or(&Value::Null),
            "artifact classification",
        )?;
        exact_keys(c, &["role", "media_type"], "artifact classification")?;
        let stored = by_path
            .get(p)
            .ok_or_else(|| ReleaseError::new("artifact absent from inventory"))?;
        if stored
            != &(
                h.to_owned(),
                size,
                string(c, "role")?.to_owned(),
                string(c, "media_type")?.to_owned(),
            )
        {
            return Err(ReleaseError::new("artifact disagrees with inventory"));
        }
        validate_version_specific_https_url(
            string(artifact, "source_url")?,
            string(root, "release_version")?,
        )?;
        artifact_paths.push(p);
        artifact_ids.push(
            framed_root(
                "ctxql-source-artifact-pin/v1",
                [
                    ("path", p),
                    ("url", string(artifact, "source_url")?),
                    ("hash", h),
                    ("size", size.to_string().as_str()),
                    ("media-type", string(c, "media_type")?),
                    ("role", string(c, "role")?),
                ],
            )
            .as_str()
            .to_owned(),
        );
    }
    if artifacts.is_empty() || !artifact_paths.windows(2).all(|w| w[0] < w[1]) {
        return Err(ReleaseError::new(
            "noncanonical or duplicate artifact order",
        ));
    }
    let evidence = root
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| ReleaseError::new("invalid evidence"))?;
    let mut evidence_ids = Vec::new();
    let mut evidence_paths = Vec::new();
    let mut evidence_kinds = std::collections::BTreeSet::new();
    for item in evidence {
        let item = object(item, "evidence")?;
        exact_keys(item, &["kind", "path", "hash"], "evidence")?;
        let kind = string(item, "kind")?;
        evidence_kinds.insert(kind);
        let expected = if kind == "license" {
            ("License", "license")
        } else if kind == "notice" {
            ("Notice", "notice")
        } else {
            return Err(ReleaseError::new("invalid evidence kind"));
        };
        let stored = by_path
            .get(string(item, "path")?)
            .ok_or_else(|| ReleaseError::new("evidence absent from inventory"))?;
        if stored.0 != string(item, "hash")? || stored.2 != expected.1 {
            return Err(ReleaseError::new("evidence disagrees with inventory"));
        }
        evidence_paths.push(string(item, "path")?);
        evidence_ids.push(format!(
            "{}\0{}\0{}",
            expected.0,
            string(item, "path")?,
            string(item, "hash")?
        ));
    }
    if evidence_kinds != std::collections::BTreeSet::from(["license", "notice"])
        || !evidence_paths.windows(2).all(|w| w[0] < w[1])
    {
        return Err(ReleaseError::new(
            "noncanonical or duplicate evidence order",
        ));
    }
    let form = match string(root, "release_form")? {
        "archive" => "archive",
        "synthetic_artifacts" => "synthetic-artifacts",
        _ => return Err(ReleaseError::new("invalid release form")),
    };
    let mut fields = vec![
        ("publisher", string(root, "publisher")?),
        ("product", string(root, "product")?),
        ("version", string(root, "release_version")?),
        ("form", form),
        ("inventory", inventory_root.as_str()),
    ];
    fields.extend(artifact_ids.iter().map(|v| ("artifact", v.as_str())));
    fields.extend(evidence_ids.iter().map(|v| ("evidence", v.as_str())));
    fields.push(("classification-policy", ARTIFACT_CLASSIFICATION_POLICY));
    fields.push(("classification-root", classification_root.as_str()));
    fields.push((
        "immutable-source-evidence",
        string(root, "immutable_source_evidence")?,
    ));
    if let Some(v) = tag {
        fields.push(("tag", v));
    }
    if let Some(v) = commit {
        fields.push(("commit", v));
    }
    if let Some(v) = tree {
        fields.push(("tree", v));
    }
    if let Some(v) = retrieval_evidence {
        fields.push(("retrieval-evidence", v));
    }
    if let Some(v) = limits {
        fields.push(("safe-extraction-limits", v));
    }
    let id = SourceReleaseId::from_commitments(fields);
    if string(root, "source_release_id")? != id.as_str() {
        return Err(ReleaseError::new("stale source release ID"));
    }
    let manifest_root = framed_root(
        "ctxql-source-release-manifest/v2",
        [
            ("release-id", id.as_str()),
            ("retrieved-at", retrieved_at.unwrap_or("null")),
            ("retrieval-evidence", retrieval_evidence.unwrap_or("null")),
            ("limits", limits.unwrap_or("null")),
        ],
    );
    if string(root, "manifest_root")? != manifest_root.as_str() {
        return Err(ReleaseError::new("stale manifest root"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceVerificationLimits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_path_bytes: usize,
    pub max_path_depth: usize,
}
impl Default for SourceVerificationLimits {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_file_bytes: 64 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
            max_path_bytes: 1024,
            max_path_depth: 32,
        }
    }
}

/// Verify an explicitly listed, complete inventory beneath an external root.
/// Directory enumeration is used to prove completeness; symlinks and all
/// non-regular entries fail closed.
pub fn verify_external_inventory(
    root: &Path,
    inventory: &CompleteInventory,
    limits: SourceVerificationLimits,
) -> Result<()> {
    let root_meta = std::fs::symlink_metadata(root)?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return Err(ReleaseError::new("external root must be a real directory"));
    }
    let canonical_root = std::fs::canonicalize(root)?;
    if inventory.entries.len() > limits.max_files || inventory.total_bytes > limits.max_total_bytes
    {
        return Err(ReleaseError::new("source inventory bounds exceeded"));
    }
    let expected: BTreeMap<&str, &InventoryEntry> = inventory
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();
    let mut seen = BTreeMap::new();
    walk_and_verify(
        &canonical_root,
        &canonical_root,
        &expected,
        &mut seen,
        limits,
        0,
    )?;
    if seen.len() != expected.len() {
        return Err(ReleaseError::new("inventory omits or is missing a file"));
    }
    Ok(())
}

fn walk_and_verify<'a>(
    root: &Path,
    dir: &Path,
    expected: &BTreeMap<&'a str, &'a InventoryEntry>,
    seen: &mut BTreeMap<String, ()>,
    limits: SourceVerificationLimits,
    depth: usize,
) -> Result<()> {
    if depth > limits.max_path_depth {
        return Err(ReleaseError::new("source path depth exceeded"));
    }
    let mut children: Vec<_> = std::fs::read_dir(dir)?.collect::<std::result::Result<_, _>>()?;
    children.sort_by_key(|e| e.file_name());
    for child in children {
        let path = child.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(ReleaseError::new("source symlink prohibited"));
        }
        let canonical = std::fs::canonicalize(&path)?;
        if !canonical.starts_with(root) {
            return Err(ReleaseError::new("source path escapes external root"));
        }
        if metadata.is_dir() {
            walk_and_verify(root, &path, expected, seen, limits, depth + 1)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(ReleaseError::new("non-regular source member"));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ReleaseError::new("source path escape"))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| ReleaseError::new("non-UTF-8 source path"))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        let relative = RelativeSourcePath::new(relative)?;
        if relative.as_str().len() > limits.max_path_bytes
            || relative.depth() > limits.max_path_depth
        {
            return Err(ReleaseError::new("source path bounds exceeded"));
        }
        let entry = expected
            .get(relative.as_str())
            .ok_or_else(|| ReleaseError::new("file absent from complete inventory"))?;
        if metadata.len() != entry.size || metadata.len() > limits.max_file_bytes {
            return Err(ReleaseError::new(
                "source file size mismatch or bound exceeded",
            ));
        }
        let mut file = File::open(&path)?;
        let mut bytes = Vec::with_capacity(metadata.len().min(limits.max_file_bytes) as usize);
        file.by_ref()
            .take(limits.max_file_bytes + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != entry.size || ContentHash::of_bytes(&bytes) != entry.hash {
            return Err(ReleaseError::new("source file hash mismatch"));
        }
        if seen.insert(relative.0, ()).is_some() {
            return Err(ReleaseError::new("duplicate normalized path"));
        }
    }
    Ok(())
}

pub fn inventory_external_root(
    root: &Path,
    classifications: &BTreeMap<RelativeSourcePath, ArtifactClassification>,
    limits: SourceVerificationLimits,
) -> Result<CompleteInventory> {
    let root_meta = std::fs::symlink_metadata(root)?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return Err(ReleaseError::new("external root must be a real directory"));
    }
    let canonical = std::fs::canonicalize(root)?;
    let mut entries = Vec::new();
    collect_inventory(
        &canonical,
        &canonical,
        classifications,
        limits,
        0,
        &mut entries,
    )?;
    if entries.len() != classifications.len() {
        return Err(ReleaseError::new(
            "classification map has missing or extra paths",
        ));
    }
    CompleteInventory::new(entries)
}
fn collect_inventory(
    root: &Path,
    dir: &Path,
    classifications: &BTreeMap<RelativeSourcePath, ArtifactClassification>,
    limits: SourceVerificationLimits,
    depth: usize,
    entries: &mut Vec<InventoryEntry>,
) -> Result<()> {
    if depth > limits.max_path_depth {
        return Err(ReleaseError::new("source path depth exceeded"));
    }
    let mut children: Vec<_> = std::fs::read_dir(dir)?.collect::<std::result::Result<_, _>>()?;
    children.sort_by_key(|e| e.file_name());
    for child in children {
        let path: PathBuf = child.path();
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            return Err(ReleaseError::new("source symlink prohibited"));
        }
        if meta.is_dir() {
            collect_inventory(root, &path, classifications, limits, depth + 1, entries)?;
            continue;
        }
        if !meta.is_file() || meta.len() == 0 || meta.len() > limits.max_file_bytes {
            return Err(ReleaseError::new(
                "invalid source member or file bound exceeded",
            ));
        }
        if entries.len() >= limits.max_files {
            return Err(ReleaseError::new("source file count exceeded"));
        }
        let rel = path
            .strip_prefix(root)
            .map_err(|_| ReleaseError::new("source path escape"))?
            .to_str()
            .ok_or_else(|| ReleaseError::new("non-UTF-8 source path"))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        let rel = RelativeSourcePath::new(rel)?;
        if rel.as_str().len() > limits.max_path_bytes || rel.depth() > limits.max_path_depth {
            return Err(ReleaseError::new("source path bounds exceeded"));
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        File::open(&path)?
            .take(limits.max_file_bytes + 1)
            .read_to_end(&mut bytes)?;
        let classification = classifications
            .get(&rel)
            .ok_or_else(|| ReleaseError::new("missing explicit artifact classification"))?
            .clone();
        entries.push(InventoryEntry::new(
            rel,
            ContentHash::of_bytes(&bytes),
            bytes.len() as u64,
            classification,
        )?);
    }
    let total: u64 = entries.iter().map(|e| e.size).sum();
    if total > limits.max_total_bytes {
        return Err(ReleaseError::new("source expanded byte bound exceeded"));
    }
    Ok(())
}
