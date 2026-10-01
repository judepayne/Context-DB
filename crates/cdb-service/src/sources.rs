//! Exact-selector authorization before any content-addressed source read.
//! Trusted host provisioning only; no URI fetching, acquisition, or request paths.
use crate::config::{create_secret_file, BoundedFileRead};
use cdb_core::{
    admission::{DependencyRecord, ExportRecord, Fact, FactTerm, ResourceKind},
    claim::TypedLiteral,
    contracts::{AuthorizedSelectorResolver, GraphBackend, IoFuture, PolicyService, SourceReader},
    evidence::{EvidenceSelector, Utf8Span},
    id::{ContentHash, Iri, ResourceId, SourceId},
    recording::PolicyObservation,
    snapshot::SnapshotRef,
    source::{SourceRead, SourceReadRequest},
    CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
const PROPERTY: &str = "https://ctxql.example/evidence/v1/descriptor";
const ARTIFACT_DESCRIPTOR_SCHEMA: &str = "ctxql-acquisition-artifact-descriptor/v2";
const SOURCE_PLUS_GRAPH_ARTIFACT_DESCRIPTOR_SCHEMA: &str =
    "ctxql-acquisition-artifact-descriptor/v3";

/// A durable acquisition artifact is never represented to a caller by its
/// content hash alone. This closed descriptor binds it to the exact source
/// selector and context under which the artifact was produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionArtifactDescriptor {
    source: SourceReadRequest,
    source_fragment_hash: ContentHash,
    artifact_root: ContentHash,
    artifact_kind: String,
    context_root: ContentHash,
}
impl AcquisitionArtifactDescriptor {
    pub fn new(
        source: SourceReadRequest,
        source_fragment_hash: ContentHash,
        artifact_root: ContentHash,
        artifact_kind: impl Into<String>,
        context_root: ContentHash,
    ) -> Result<Self> {
        let artifact_kind = artifact_kind.into();
        if artifact_kind.is_empty()
            || artifact_kind.len() > 128
            || artifact_kind.chars().any(char::is_control)
        {
            return Err(Error::invalid("acquisition artifact kind"));
        }
        if source.max_bytes == 0 {
            return Err(Error::invalid("acquisition artifact source bound"));
        }
        Ok(Self {
            source,
            source_fragment_hash,
            artifact_root,
            artifact_kind,
            context_root,
        })
    }
    pub fn from_value(value: &V, max_bytes: usize) -> Result<Self> {
        value.closed(
            &[
                "schema",
                "source_id",
                "source_version",
                "source_selector",
                "source_fragment_hash",
                "artifact_root",
                "artifact_kind",
                "context_root",
                "context_access",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != ARTIFACT_DESCRIPTOR_SCHEMA
            || value.field("context_access")?.as_str()? != "source_only"
        {
            return Err(Error::invalid("acquisition artifact descriptor schema"));
        }
        let selector = value.field("source_selector")?;
        selector.closed(&["kind"], &["start", "end"])?;
        let selector = match selector.field("kind")?.as_str()? {
            "whole_document" if selector.as_object()?.len() == 1 => EvidenceSelector::WholeDocument,
            "utf8_span" => EvidenceSelector::Span(Utf8Span::new(
                usize::try_from(selector.field("start")?.u64()?).map_err(|_| Error::limit())?,
                usize::try_from(selector.field("end")?.u64()?).map_err(|_| Error::limit())?,
            )?),
            _ => return Err(Error::invalid("acquisition artifact selector")),
        };
        Self::new(
            SourceReadRequest {
                source_id: SourceId::new(value.field("source_id")?.as_str()?)?,
                version: ContentHash::parse(value.field("source_version")?.as_str()?)?,
                selector,
                max_bytes,
            },
            ContentHash::parse(value.field("source_fragment_hash")?.as_str()?)?,
            ContentHash::parse(value.field("artifact_root")?.as_str()?)?,
            value.field("artifact_kind")?.as_str()?,
            ContentHash::parse(value.field("context_root")?.as_str()?)?,
        )
    }
    pub fn projection(&self) -> V {
        let selector = match self.source.selector {
            EvidenceSelector::WholeDocument => object([("kind", V::string("whole_document"))]),
            EvidenceSelector::Span(span) => V::Object(
                [
                    ("kind".into(), V::string("utf8_span")),
                    ("start".into(), V::integer(span.start() as u64)),
                    ("end".into(), V::integer(span.end() as u64)),
                ]
                .into_iter()
                .collect(),
            ),
        };
        V::Object(
            [
                ("schema".into(), V::string(ARTIFACT_DESCRIPTOR_SCHEMA)),
                (
                    "source_id".into(),
                    V::string(self.source.source_id.as_str()),
                ),
                (
                    "source_version".into(),
                    V::string(self.source.version.as_str()),
                ),
                ("source_selector".into(), selector),
                (
                    "source_fragment_hash".into(),
                    V::string(self.source_fragment_hash.as_str()),
                ),
                (
                    "artifact_root".into(),
                    V::string(self.artifact_root.as_str()),
                ),
                ("artifact_kind".into(), V::string(&self.artifact_kind)),
                ("context_root".into(), V::string(self.context_root.as_str())),
                ("context_access".into(), V::string("source_only")),
            ]
            .into_iter()
            .collect(),
        )
    }
    pub fn artifact_root(&self) -> &ContentHash {
        &self.artifact_root
    }
    pub fn source(&self) -> &SourceReadRequest {
        &self.source
    }
    pub(crate) fn source_fragment_hash(&self) -> &ContentHash {
        &self.source_fragment_hash
    }
    pub fn context_root(&self) -> &ContentHash {
        &self.context_root
    }
    /// Derive another artifact image under the same authenticated source and
    /// capture context. Callers must authenticate the resulting complete image
    /// from durable acquisition state before it can become a grant.
    pub(crate) fn successor(
        &self,
        artifact_root: ContentHash,
        artifact_kind: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            self.source.clone(),
            self.source_fragment_hash.clone(),
            artifact_root,
            artifact_kind,
            self.context_root.clone(),
        )
    }
}

/// Separately versioned descriptor for artifacts derived from both source
/// content and disclosed graph context. The graph root is an integrity binding,
/// never a bearer capability; callers must authenticate it against registered
/// frozen work and reauthorize its claims separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePlusGraphArtifactDescriptor {
    source: SourceReadRequest,
    source_fragment_hash: ContentHash,
    artifact_root: ContentHash,
    artifact_kind: String,
    context_root: ContentHash,
    graph_context_root: ContentHash,
}
impl SourcePlusGraphArtifactDescriptor {
    pub fn new(
        source: SourceReadRequest,
        source_fragment_hash: ContentHash,
        artifact_root: ContentHash,
        artifact_kind: impl Into<String>,
        context_root: ContentHash,
        graph_context_root: ContentHash,
    ) -> Result<Self> {
        let artifact_kind = artifact_kind.into();
        if artifact_kind.is_empty()
            || artifact_kind.len() > 128
            || artifact_kind.chars().any(char::is_control)
            || source.max_bytes == 0
        {
            return Err(Error::invalid("source-plus-graph artifact descriptor"));
        }
        Ok(Self {
            source,
            source_fragment_hash,
            artifact_root,
            artifact_kind,
            context_root,
            graph_context_root,
        })
    }
    pub fn from_value(value: &V, max_bytes: usize) -> Result<Self> {
        value.closed(
            &[
                "schema",
                "source_id",
                "source_version",
                "source_selector",
                "source_fragment_hash",
                "artifact_root",
                "artifact_kind",
                "context_root",
                "graph_context_root",
                "context_access",
            ],
            &[],
        )?;
        if value.field("schema")?.as_str()? != SOURCE_PLUS_GRAPH_ARTIFACT_DESCRIPTOR_SCHEMA
            || value.field("context_access")?.as_str()? != "source_plus_graph"
        {
            return Err(Error::invalid(
                "source-plus-graph artifact descriptor schema",
            ));
        }
        let selector = parse_artifact_selector(value.field("source_selector")?)?;
        Self::new(
            SourceReadRequest {
                source_id: SourceId::new(value.field("source_id")?.as_str()?)?,
                version: ContentHash::parse(value.field("source_version")?.as_str()?)?,
                selector,
                max_bytes,
            },
            ContentHash::parse(value.field("source_fragment_hash")?.as_str()?)?,
            ContentHash::parse(value.field("artifact_root")?.as_str()?)?,
            value.field("artifact_kind")?.as_str()?,
            ContentHash::parse(value.field("context_root")?.as_str()?)?,
            ContentHash::parse(value.field("graph_context_root")?.as_str()?)?,
        )
    }
    pub fn projection(&self) -> V {
        V::Object(
            [
                (
                    "schema".into(),
                    V::string(SOURCE_PLUS_GRAPH_ARTIFACT_DESCRIPTOR_SCHEMA),
                ),
                (
                    "source_id".into(),
                    V::string(self.source.source_id.as_str()),
                ),
                (
                    "source_version".into(),
                    V::string(self.source.version.as_str()),
                ),
                (
                    "source_selector".into(),
                    artifact_selector_projection(&self.source.selector),
                ),
                (
                    "source_fragment_hash".into(),
                    V::string(self.source_fragment_hash.as_str()),
                ),
                (
                    "artifact_root".into(),
                    V::string(self.artifact_root.as_str()),
                ),
                ("artifact_kind".into(), V::string(&self.artifact_kind)),
                ("context_root".into(), V::string(self.context_root.as_str())),
                (
                    "graph_context_root".into(),
                    V::string(self.graph_context_root.as_str()),
                ),
                ("context_access".into(), V::string("source_plus_graph")),
            ]
            .into_iter()
            .collect(),
        )
    }
    pub fn source(&self) -> &SourceReadRequest {
        &self.source
    }
    pub fn source_fragment_hash(&self) -> &ContentHash {
        &self.source_fragment_hash
    }
    pub fn artifact_root(&self) -> &ContentHash {
        &self.artifact_root
    }
    pub fn context_root(&self) -> &ContentHash {
        &self.context_root
    }
    pub fn graph_context_root(&self) -> &ContentHash {
        &self.graph_context_root
    }
    #[allow(dead_code)] // Phase 2 paging integration derives restricted successors through this seam.
    pub(crate) fn successor(
        &self,
        artifact_root: ContentHash,
        artifact_kind: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            self.source.clone(),
            self.source_fragment_hash.clone(),
            artifact_root,
            artifact_kind,
            self.context_root.clone(),
            self.graph_context_root.clone(),
        )
    }
}

fn artifact_selector_projection(selector: &EvidenceSelector) -> V {
    match selector {
        EvidenceSelector::WholeDocument => object([("kind", V::string("whole_document"))]),
        EvidenceSelector::Span(span) => V::Object(
            [
                ("kind".into(), V::string("utf8_span")),
                ("start".into(), V::integer(span.start() as u64)),
                ("end".into(), V::integer(span.end() as u64)),
            ]
            .into_iter()
            .collect(),
        ),
    }
}

fn parse_artifact_selector(selector: &V) -> Result<EvidenceSelector> {
    selector.closed(&["kind"], &["start", "end"])?;
    match selector.field("kind")?.as_str()? {
        "whole_document" if selector.as_object()?.len() == 1 => Ok(EvidenceSelector::WholeDocument),
        "utf8_span" => Ok(EvidenceSelector::Span(Utf8Span::new(
            usize::try_from(selector.field("start")?.u64()?).map_err(|_| Error::limit())?,
            usize::try_from(selector.field("end")?.u64()?).map_err(|_| Error::limit())?,
        )?)),
        _ => Err(Error::invalid("acquisition artifact selector")),
    }
}

/// Opaque, issuer-bound proof that the complete descriptor image was found in
/// authenticated immutable acquisition state. A descriptor supplied by a
/// caller is never itself a read capability.
#[derive(Debug)]
pub struct AcquisitionArtifactGrant {
    issuer: Arc<()>,
    descriptor: AcquisitionArtifactDescriptor,
}

#[derive(Debug)]
pub struct SourcePlusGraphArtifactGrant {
    issuer: Arc<()>,
    descriptor: SourcePlusGraphArtifactDescriptor,
}

fn provision_artifact(
    issuer: &Arc<()>,
    descriptor: AcquisitionArtifactDescriptor,
    authenticated_image: &V,
    expected_context: &ContentHash,
) -> Result<AcquisitionArtifactGrant> {
    if descriptor.projection() != *authenticated_image
        || descriptor.context_root() != expected_context
    {
        return Err(denied());
    }
    Ok(AcquisitionArtifactGrant {
        issuer: issuer.clone(),
        descriptor,
    })
}

fn provision_source_plus_graph_artifact(
    issuer: &Arc<()>,
    descriptor: SourcePlusGraphArtifactDescriptor,
    authenticated_image: &V,
    expected_context: &ContentHash,
    expected_graph_context: &ContentHash,
) -> Result<SourcePlusGraphArtifactGrant> {
    if descriptor.projection() != *authenticated_image
        || descriptor.context_root() != expected_context
        || descriptor.graph_context_root() != expected_graph_context
    {
        return Err(denied());
    }
    Ok(SourcePlusGraphArtifactGrant {
        issuer: issuer.clone(),
        descriptor,
    })
}

fn denied() -> Error {
    Error::new(ErrorKind::Denied, "source access denied")
}
fn check_policy<P: PolicyService>(
    policy: &P,
    context: &P::Context,
    records: &[DependencyRecord],
) -> Result<()> {
    for record in records {
        if !policy.resource_allowed(context, record.id())? {
            return Err(denied());
        }
        for fact in record.facts() {
            if !policy.fact_allowed(context, record.id(), fact.predicate())? {
                return Err(denied());
            }
        }
    }
    Ok(())
}
fn object<const N: usize>(fields: [(&str, V); N]) -> V {
    V::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
fn key(value: &V) -> Result<ResourceId> {
    let hash = ContentHash::of_bytes(&value.canonical_bytes(Limits::default())?);
    ResourceId::new(format!(
        "https://ctxql.example/evidence/v1/{}",
        &hash.as_str()[7..]
    ))
}
fn source_value(request: &SourceReadRequest) -> V {
    object([("source_id", V::string(request.source_id.as_str()))])
}
fn version_value(request: &SourceReadRequest) -> V {
    object([
        ("source_id", V::string(request.source_id.as_str())),
        ("version", V::string(request.version.as_str())),
    ])
}
fn selector_value(request: &SourceReadRequest) -> V {
    selector_binding(
        request,
        match request.selector {
            EvidenceSelector::WholeDocument => object([
                ("contract", V::string("ctxql-evidence/v1")),
                ("whole_document", V::Bool(true)),
            ]),
            EvidenceSelector::Span(span) => object([
                ("contract", V::string("ctxql-evidence/v1")),
                ("utf8", span.projection()),
            ]),
        },
    )
}
fn selector_binding(request: &SourceReadRequest, selector: V) -> V {
    object([
        ("source_id", V::string(request.source_id.as_str())),
        ("version", V::string(request.version.as_str())),
        ("selector", selector),
    ])
}
fn reference_request(
    source: &cdb_core::evidence::SourceReference,
    max_bytes: usize,
) -> Result<SourceReadRequest> {
    Ok(SourceReadRequest {
        source_id: source.id().clone(),
        version: source.version().cloned().ok_or_else(denied)?,
        selector: source.selector().cloned().ok_or_else(denied)?,
        max_bytes,
    })
}
fn reference_selector_value(
    source: &cdb_core::evidence::SourceReference,
    request: &SourceReadRequest,
) -> Result<V> {
    let selectors = source
        .projection()
        .as_object()?
        .get("selectors")
        .cloned()
        .ok_or_else(denied)?;
    cdb_core::evidence::validate_selectors(&selectors)?;
    Ok(selector_binding(request, selectors))
}
fn descriptor(id: ResourceId, value: &V) -> Result<DependencyRecord> {
    DependencyRecord::new(
        "ctxql-resource/v1",
        id,
        ResourceKind::SourceDescriptor,
        vec![Fact::new(
            Iri::new(PROPERTY)?,
            FactTerm::Literal(TypedLiteral::new(
                Iri::new("http://www.w3.org/2001/XMLSchema#string")?,
                V::string(
                    String::from_utf8(value.canonical_bytes(Limits::default())?)
                        .map_err(|_| Error::invalid("descriptor encoding"))?,
                ),
                None,
            )?),
        )],
    )
}
/// Three distinct metadata grants: source identity, version identity, and exact selector.
/// A span never grants its whole document, including an empty span.
pub fn selector_records(
    request: &SourceReadRequest,
    content_hash: &ContentHash,
) -> Result<Vec<ExportRecord>> {
    selector_records_with_binding(request, content_hash, selector_value(request))
}

/// Build immutable grants for the complete acquisition selector image, including
/// line and exact-quote witnesses. This accepts only a validated SourceReference.
pub fn acquisition_selector_records(
    source: &cdb_core::evidence::SourceReference,
    max_bytes: usize,
) -> Result<Vec<ExportRecord>> {
    let request = reference_request(source, max_bytes)?;
    let content_hash = source.content_hash().ok_or_else(denied)?;
    let binding = reference_selector_value(source, &request)?;
    selector_records_with_binding(&request, content_hash, binding)
}

fn selector_records_with_binding(
    request: &SourceReadRequest,
    content_hash: &ContentHash,
    selector: V,
) -> Result<Vec<ExportRecord>> {
    let source = source_value(request);
    let version = version_value(request);
    let value = object([
        ("schema", V::string("ctxql-source-selector/v1")),
        ("binding", selector.clone()),
        ("content_hash", V::string(content_hash.as_str())),
    ]);
    Ok(vec![
        ExportRecord::Resource(descriptor(
            ResourceId::new(request.source_id.as_str())?,
            &source,
        )?),
        ExportRecord::Resource(descriptor(key(&version)?, &version)?),
        ExportRecord::Resource(descriptor(key(&selector)?, &value)?),
    ])
}
/// No public unguarded read method and deliberately no SourceReader implementation.
pub struct SourceStore {
    root: PathBuf,
    max_bytes: usize,
    reads: AtomicUsize,
}
impl SourceStore {
    pub fn open(root: PathBuf, max_bytes: usize) -> Result<Self> {
        if !root.is_absolute() || max_bytes == 0 {
            return Err(Error::invalid("source store options"));
        }
        let metadata =
            std::fs::symlink_metadata(&root).map_err(|_| Error::invalid("source root"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::invalid("source root"));
        }
        Ok(Self {
            root,
            max_bytes,
            reads: AtomicUsize::new(0),
        })
    }
    /// Trusted local provisioning; create-new or verify an already identical immutable object.
    pub fn put(&self, bytes: &[u8]) -> Result<ContentHash> {
        if bytes.len() > self.max_bytes {
            return Err(Error::limit());
        }
        let hash = ContentHash::of_bytes(bytes);
        let path = self.root.join(&hash.as_str()[7..]);
        if path.exists() {
            let existing = BoundedFileRead::new(self.max_bytes, true)?.read(&path)?;
            if existing != bytes {
                return Err(Error::new(ErrorKind::Conflict, "source object conflict"));
            }
        } else {
            create_secret_file(&path, bytes)?;
        }
        Ok(hash)
    }
    pub fn reads_started(&self) -> usize {
        self.reads.load(Ordering::Relaxed)
    }
    fn object(&self, root: &ContentHash, max_bytes: usize) -> Result<Vec<u8>> {
        if max_bytes == 0 || max_bytes > self.max_bytes {
            return Err(Error::limit());
        }
        let bytes =
            BoundedFileRead::new(max_bytes, true)?.read(&self.root.join(&root.as_str()[7..]))?;
        if ContentHash::of_bytes(&bytes) != *root {
            return Err(Error::invalid("source object mismatch"));
        }
        Ok(bytes)
    }
    fn representation(&self, request: &SourceReadRequest) -> Result<Vec<u8>> {
        let version_bytes = BoundedFileRead::new(self.max_bytes, true)?
            .read(&self.root.join(&request.version.as_str()[7..]))?;
        if ContentHash::of_bytes(&version_bytes) != request.version {
            return Err(Error::invalid("source version mismatch"));
        }
        if let Some(digest) = request
            .source_id
            .as_str()
            .strip_prefix("urn:ctxql:source:")
            .filter(|digest| !digest.starts_with("text:"))
        {
            let manifest_root = ContentHash::parse(format!("sha256:{digest}"))?;
            let reader =
                cdb_source_store::SourceObjectReader::open(self.root.clone(), self.max_bytes)?;
            let descriptor = V::parse(&reader.read_object(&manifest_root)?, Limits::default())?;
            if descriptor.field("schema")?.as_str()? == "ctxql-original-representation/v1" {
                let original = reader.read_original_manifest(&manifest_root)?;
                if original.object() != &request.version {
                    return Err(Error::invalid("original representation/version mismatch"));
                }
                return Ok(version_bytes);
            }
            let manifest = reader.read_text_manifest(&manifest_root)?;
            if manifest.version() != &request.version || manifest.version_bytes()? != version_bytes
            {
                return Err(Error::invalid("text representation/version mismatch"));
            }
            // Verify both provenance descriptors before following the converted
            // object. This is resolution under an existing source grant, never
            // provisioning a new grant or changing an admission receipt.
            reader.read_converter_manifest(manifest.converter_manifest())?;
            reader.read_original_manifest(manifest.original_manifest())?;
            return Ok(reader.read_text(&manifest)?.into_bytes());
        }
        if request
            .source_id
            .as_str()
            .starts_with("urn:ctxql:source:text:")
        {
            let descriptor = V::parse(&version_bytes, Limits::default())?;
            descriptor.closed(&["schema", "object", "converter_manifest"], &[])?;
            if descriptor.field("schema")?.as_str()? != "ctxql-text-version/v1" {
                return Err(Error::invalid("text version descriptor"));
            }
            ContentHash::parse(descriptor.field("converter_manifest")?.as_str()?)?;
            let object = ContentHash::parse(descriptor.field("object")?.as_str()?)?;
            let text = BoundedFileRead::new(self.max_bytes, true)?
                .read(&self.root.join(&object.as_str()[7..]))?;
            if ContentHash::of_bytes(&text) != object {
                return Err(Error::invalid("source object mismatch"));
            }
            Ok(text)
        } else {
            Ok(version_bytes)
        }
    }
    fn selected(
        &self,
        request: &SourceReadRequest,
        fragment_hash: &ContentHash,
    ) -> Result<SourceRead> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let bytes = self.representation(request)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| Error::invalid("source UTF-8"))?;
        let selected = match &request.selector {
            EvidenceSelector::WholeDocument => text.as_bytes(),
            EvidenceSelector::Span(span) => span
                .select(std::str::from_utf8(&bytes).map_err(|_| Error::invalid("source UTF-8"))?)?
                .as_bytes(),
        };
        if selected.len() > request.max_bytes {
            return Err(Error::limit());
        }
        if &ContentHash::of_bytes(selected) != fragment_hash {
            return Err(Error::invalid("source fragment mismatch"));
        }
        SourceRead::from_request(request, selected.to_vec())
    }
    fn selected_reference(
        &self,
        request: &SourceReadRequest,
        source: &cdb_core::evidence::SourceReference,
    ) -> Result<SourceRead> {
        let bytes = self.representation(request)?;
        if source.verify(&bytes)? != cdb_core::evidence::VerificationOutcome::Verified {
            return Err(Error::invalid("source evidence mismatch"));
        }
        let hash = source.content_hash().ok_or_else(denied)?;
        self.selected(request, hash)
    }
}
/// Exact source-selector records obtained by authorization, never deserialized
/// from a descriptor. Rechecked inside the Control mutation/publication gate.
#[derive(Clone, Default)]
pub(crate) struct SourceAuthorization {
    records: std::collections::BTreeMap<cdb_core::id::ResourceId, DependencyRecord>,
}
impl SourceAuthorization {
    pub(crate) fn extend<C>(&mut self, grant: &SelectorGrant<C>) -> Result<()> {
        for record in &grant.records {
            if self
                .records
                .get(record.id())
                .is_some_and(|previous| previous != record)
            {
                return Err(denied());
            }
            self.records.insert(record.id().clone(), record.clone());
        }
        Ok(())
    }
    pub(crate) fn check<P: PolicyService>(&self, policy: &P, context: &P::Context) -> Result<()> {
        for record in self.records.values() {
            check_policy(policy, context, std::slice::from_ref(record))?;
        }
        Ok(())
    }
}

/// Private issuer- and exact-request-bound capability, never deserialized.
pub struct SelectorGrant<C> {
    issuer: Arc<()>,
    request: SourceReadRequest,
    context: C,
    records: Vec<DependencyRecord>,
    hash: ContentHash,
}
/// Construct separately per request. Snapshot binding is write-once, never a response cache.
pub struct AuthorizedSources<B: GraphBackend, P: PolicyService> {
    backend: Arc<B>,
    policy: Arc<P>,
    principal: Arc<P::Principal>,
    store: Arc<SourceStore>,
    issuer: Arc<()>,
    snapshot: Mutex<Option<SnapshotRef>>,
    footprint: Mutex<Vec<PolicyObservation>>,
}
impl<B: GraphBackend, P: PolicyService> AuthorizedSources<B, P> {
    pub fn new(
        backend: Arc<B>,
        policy: Arc<P>,
        principal: Arc<P::Principal>,
        store: Arc<SourceStore>,
    ) -> Self {
        Self {
            backend,
            policy,
            principal,
            store,
            issuer: Arc::new(()),
            snapshot: Mutex::new(None),
            footprint: Mutex::new(vec![]),
        }
    }
    pub fn bind_snapshot(&self, snapshot: &SnapshotRef) -> Result<()> {
        let mut pin = self.snapshot.lock().map_err(|_| denied())?;
        if pin.as_ref().is_some_and(|p| p != snapshot) {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "source reader already bound",
            ));
        }
        *pin = Some(snapshot.clone());
        Ok(())
    }
    pub fn footprint(&self) -> Result<Vec<PolicyObservation>> {
        Ok(self.footprint.lock().map_err(|_| denied())?.clone())
    }
    fn check(&self, context: &P::Context, records: &[DependencyRecord]) -> Result<()> {
        check_policy(self.policy.as_ref(), context, records)
    }
    fn observe(&self, records: &[DependencyRecord]) -> Result<()> {
        let mut observations = self.footprint.lock().map_err(|_| denied())?;
        let mut seen: BTreeSet<_> = observations
            .iter()
            .map(|observation| (observation.resource.clone(), observation.predicate.clone()))
            .collect();
        for record in records {
            for predicate in std::iter::once(None).chain(
                record
                    .facts()
                    .iter()
                    .map(|fact| Some(fact.predicate().clone())),
            ) {
                if seen.insert((record.id().clone(), predicate.clone())) {
                    if observations.len() >= 10_000 {
                        return Err(Error::limit());
                    }
                    observations.push(PolicyObservation {
                        resource: record.id().clone(),
                        predicate,
                        allowed: true,
                    });
                }
            }
        }
        Ok(())
    }
    /// Convert an already authenticated immutable descriptor image into an
    /// issuer-bound capability. This is crate-private so public callers cannot
    /// bless a descriptor they constructed themselves.
    pub(crate) fn provision_acquisition_artifact(
        &self,
        descriptor: AcquisitionArtifactDescriptor,
        authenticated_image: &V,
        expected_context: &ContentHash,
    ) -> Result<AcquisitionArtifactGrant> {
        provision_artifact(
            &self.issuer,
            descriptor,
            authenticated_image,
            expected_context,
        )
    }

    /// Provision a source-plus-graph descriptor only after the complete image
    /// and both registered context roots have been authenticated by the caller.
    /// The resulting grant still performs the ordinary exact source checks on
    /// every read; graph-claim reauthorization is an additional outer boundary.
    #[allow(dead_code)] // Phase 2 integration authenticates frozen graph work before calling this seam.
    pub(crate) fn provision_source_plus_graph_artifact(
        &self,
        descriptor: SourcePlusGraphArtifactDescriptor,
        authenticated_image: &V,
        expected_context: &ContentHash,
        expected_graph_context: &ContentHash,
    ) -> Result<SourcePlusGraphArtifactGrant> {
        provision_source_plus_graph_artifact(
            &self.issuer,
            descriptor,
            authenticated_image,
            expected_context,
            expected_graph_context,
        )
    }

    pub async fn read_source_plus_graph_artifact(
        &self,
        artifact: &SourcePlusGraphArtifactGrant,
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        if !Arc::ptr_eq(&artifact.issuer, &self.issuer) {
            return Err(denied());
        }
        let descriptor = &artifact.descriptor;
        let grant = self
            .authorize_provisioned_source(&descriptor.source, &descriptor.source_fragment_hash)
            .await?;
        let read = self.resolve(&grant, &descriptor.source).await?;
        if ContentHash::of_bytes(read.bytes()) != descriptor.source_fragment_hash {
            return Err(denied());
        }
        let bytes = self.store.object(&descriptor.artifact_root, max_bytes)?;
        self.check(&grant.context, &grant.records)?;
        Ok(bytes)
    }

    pub async fn read_acquisition_artifact(
        &self,
        artifact: &AcquisitionArtifactGrant,
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        if !Arc::ptr_eq(&artifact.issuer, &self.issuer) {
            return Err(denied());
        }
        let descriptor = &artifact.descriptor;
        let grant = self
            .authorize_provisioned_source(descriptor.source(), &descriptor.source_fragment_hash)
            .await?;
        // Prove the exact inherited source selector before touching the artifact.
        let read = self.resolve(&grant, descriptor.source()).await?;
        if ContentHash::of_bytes(read.bytes()) != descriptor.source_fragment_hash {
            return Err(denied());
        }
        let bytes = self.store.object(descriptor.artifact_root(), max_bytes)?;
        // Recheck the same captured policy context after the content read.
        self.check(&grant.context, &grant.records)?;
        Ok(bytes)
    }

    async fn authorize_provisioned_source(
        &self,
        request: &SourceReadRequest,
        fragment_hash: &ContentHash,
    ) -> Result<SelectorGrant<P::Context>> {
        // The artifact image identifies the expected grants, but cannot create
        // them. Require the exact immutable source/version/selector records at
        // the caller-bound current authority snapshot before reading content.
        let pin = self
            .snapshot
            .lock()
            .map_err(|_| denied())?
            .clone()
            .ok_or_else(denied)?;
        let context = self.policy.current(&self.principal).await?;
        let snapshot = self.backend.open_snapshot(&pin).await?;
        if snapshot.identity() != &pin {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "source descriptor snapshot",
            ));
        }
        let expected = selector_records(request, fragment_hash)?;
        let mut records = Vec::with_capacity(expected.len());
        for expected_record in expected {
            let ExportRecord::Resource(expected_record) = expected_record else {
                return Err(denied());
            };
            // Deny before existence diagnostics and compare the complete
            // persisted image, not merely its content-addressed identifier.
            if !self
                .policy
                .resource_allowed(&context, expected_record.id())?
            {
                return Err(denied());
            }
            let actual = snapshot
                .resource(expected_record.id())
                .await?
                .ok_or_else(denied)?;
            self.check(&context, std::slice::from_ref(&actual))?;
            if actual != expected_record {
                return Err(denied());
            }
            records.push(actual);
        }
        Ok(SelectorGrant {
            issuer: self.issuer.clone(),
            request: request.clone(),
            context,
            records,
            hash: fragment_hash.clone(),
        })
    }

    async fn authorize_reference(
        &self,
        source: &cdb_core::evidence::SourceReference,
        max_bytes: usize,
    ) -> Result<SelectorGrant<P::Context>> {
        let request = reference_request(source, max_bytes)?;
        let pin = self
            .snapshot
            .lock()
            .map_err(|_| denied())?
            .clone()
            .ok_or_else(denied)?;
        let context = self.policy.current(&self.principal).await?;
        let snapshot = self.backend.open_snapshot(&pin).await?;
        if snapshot.identity() != &pin {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "source descriptor snapshot",
            ));
        }
        let expected = acquisition_selector_records(source, max_bytes)?;
        let mut records = Vec::with_capacity(expected.len());
        for expected_record in expected {
            let ExportRecord::Resource(expected_record) = expected_record else {
                return Err(denied());
            };
            if !self
                .policy
                .resource_allowed(&context, expected_record.id())?
            {
                return Err(denied());
            }
            let actual = snapshot
                .resource(expected_record.id())
                .await?
                .ok_or_else(denied)?;
            self.check(&context, std::slice::from_ref(&actual))?;
            if actual != expected_record {
                return Err(denied());
            }
            records.push(actual);
        }
        Ok(SelectorGrant {
            issuer: self.issuer.clone(),
            request,
            context,
            records,
            hash: source.content_hash().cloned().ok_or_else(denied)?,
        })
    }

    pub async fn authorize(
        &self,
        request: &SourceReadRequest,
    ) -> Result<SelectorGrant<P::Context>> {
        let pin = self
            .snapshot
            .lock()
            .map_err(|_| denied())?
            .clone()
            .ok_or_else(denied)?;
        let context = self.policy.current(&self.principal).await?;
        let snapshot = self.backend.open_snapshot(&pin).await?;
        if snapshot.identity() != &pin {
            return Err(Error::new(
                ErrorKind::Snapshot,
                "source descriptor snapshot",
            ));
        }
        let mut records = Vec::with_capacity(3);
        for (index, binding) in [
            source_value(request),
            version_value(request),
            selector_value(request),
        ]
        .into_iter()
        .enumerate()
        {
            let id = if index == 0 {
                ResourceId::new(request.source_id.as_str())?
            } else {
                key(&binding)?
            };
            // Denial before descriptor diagnostics, and always before reader invocation.
            if !self.policy.resource_allowed(&context, &id)? {
                return Err(denied());
            }
            let record = snapshot.resource(&id).await?.ok_or_else(denied)?;
            self.check(&context, std::slice::from_ref(&record))?;
            records.push(record);
        }
        let last = records.last().ok_or_else(denied)?;
        if last.kind() != ResourceKind::SourceDescriptor
            || last.facts().len() != 1
            || last.facts()[0].predicate().as_str() != PROPERTY
        {
            return Err(denied());
        }
        let FactTerm::Literal(literal) = last.facts()[0].term() else {
            return Err(denied());
        };
        let value = V::parse(literal.value().as_str()?.as_bytes(), Limits::default())?;
        value.closed(&["schema", "binding", "content_hash"], &[])?;
        if value.field("schema")?.as_str()? != "ctxql-source-selector/v1"
            || value.field("binding")? != &selector_value(request)
        {
            return Err(denied());
        }
        let hash = ContentHash::parse(value.field("content_hash")?.as_str()?)?;
        // Compare all three full immutable descriptor images, not just keyed presence.
        let expected = selector_records(request, &hash)?;
        for (actual, expected) in records.iter().zip(expected) {
            if ExportRecord::Resource(actual.clone()) != expected {
                return Err(denied());
            }
        }
        Ok(SelectorGrant {
            issuer: self.issuer.clone(),
            request: request.clone(),
            context,
            records,
            hash,
        })
    }
}
impl<B: GraphBackend, P: PolicyService> AuthorizedSelectorResolver for AuthorizedSources<B, P> {
    type Authorization = SelectorGrant<P::Context>;
    fn resolve<'a>(
        &'a self,
        grant: &'a Self::Authorization,
        request: &'a SourceReadRequest,
    ) -> IoFuture<'a, SourceRead> {
        Box::pin(async move {
            if !Arc::ptr_eq(&grant.issuer, &self.issuer)
                || grant.request.source_id != request.source_id
                || grant.request.version != request.version
                || grant.request.selector != request.selector
                || request.max_bytes > grant.request.max_bytes
            {
                return Err(denied());
            }
            self.check(&grant.context, &grant.records)?;
            self.observe(&grant.records)?;
            let read = self.store.selected(request, &grant.hash)?;
            self.check(&grant.context, &grant.records)?;
            Ok(read)
        })
    }
}
impl<B: GraphBackend, P: PolicyService> SourceReader for AuthorizedSources<B, P> {
    fn read<'a>(&'a self, request: &'a SourceReadRequest) -> IoFuture<'a, SourceRead> {
        Box::pin(async move {
            let grant = self.authorize(request).await?;
            self.resolve(&grant, request).await
        })
    }

    fn read_reference<'a>(
        &'a self,
        source: &'a cdb_core::evidence::SourceReference,
        max_bytes: usize,
    ) -> IoFuture<'a, SourceRead> {
        Box::pin(async move {
            let grant = self.authorize_reference(source, max_bytes).await?;
            self.check(&grant.context, &grant.records)?;
            let store = self.store.clone();
            let request = grant.request.clone();
            let reference = source.clone();
            // Exact immutable object I/O and witness verification are blocking;
            // do not run them on a Tokio executor thread. The caller still owns
            // the current-authority disclosure fence after this bounded read.
            let read =
                tokio::task::spawn_blocking(move || store.selected_reference(&request, &reference))
                    .await
                    .map_err(|_| Error::new(ErrorKind::Backend, "source read unavailable"))??;
            self.check(&grant.context, &grant.records)?;
            Ok(read)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdb_core::{evidence::Utf8Span, id::SourceId};
    use std::sync::atomic::AtomicBool;
    use tempfile::tempdir;

    struct TogglePolicy(AtomicBool);
    impl PolicyService for TogglePolicy {
        type Principal = ();
        type Context = ();

        fn current<'a>(&'a self, _: &'a Self::Principal) -> IoFuture<'a, Self::Context> {
            Box::pin(async { Ok(()) })
        }
        fn resource_allowed(&self, _: &Self::Context, _: &ResourceId) -> Result<bool> {
            Ok(self.0.load(Ordering::Relaxed))
        }
        fn fact_allowed(&self, _: &Self::Context, _: &ResourceId, _: &Iri) -> Result<bool> {
            Ok(self.0.load(Ordering::Relaxed))
        }
        fn publish<'a>(
            &'a self,
            _: &'a Self::Principal,
            _: &'a Self::Context,
            sink: &'a mut (dyn FnMut() -> Result<()> + Send),
        ) -> IoFuture<'a, ()> {
            Box::pin(async move { sink() })
        }
    }

    #[test]
    fn provisioned_artifact_denies_forged_hash_context_and_revocation() {
        let directory = tempdir().unwrap();
        let store = SourceStore::open(directory.path().canonicalize().unwrap(), 1_024).unwrap();
        let source = b"source text";
        let version = store.put(source).unwrap();
        let artifact_bytes = b"{\"schema\":\"artifact\"}";
        let artifact_root = store.put(artifact_bytes).unwrap();
        let context = ContentHash::of_bytes(b"capture");
        let descriptor = AcquisitionArtifactDescriptor::new(
            SourceReadRequest {
                source_id: SourceId::new("urn:ctxql:source:test").unwrap(),
                version,
                selector: EvidenceSelector::WholeDocument,
                max_bytes: source.len(),
            },
            ContentHash::of_bytes(source),
            artifact_root,
            "evaluation_outcomes",
            context.clone(),
        )
        .unwrap();
        let issuer = Arc::new(());
        let image = descriptor.projection();
        let successor = descriptor
            .successor(ContentHash::of_bytes(b"result"), "admission_result")
            .unwrap();
        assert_eq!(successor.source(), descriptor.source());
        assert_eq!(successor.context_root(), descriptor.context_root());
        assert_ne!(successor.artifact_root(), descriptor.artifact_root());
        let grant = provision_artifact(&issuer, descriptor.clone(), &image, &context).unwrap();
        assert_eq!(grant.descriptor, descriptor);
        assert_eq!(
            store
                .object(grant.descriptor.artifact_root(), 1_024)
                .unwrap(),
            artifact_bytes
        );

        let forged = AcquisitionArtifactDescriptor::new(
            grant.descriptor.source().clone(),
            ContentHash::of_bytes(source),
            ContentHash::of_bytes(b"forged"),
            "evaluation_outcomes",
            context.clone(),
        )
        .unwrap();
        assert_eq!(
            provision_artifact(&issuer, forged, &image, &context)
                .unwrap_err()
                .kind,
            ErrorKind::Denied
        );
        assert_eq!(
            provision_artifact(
                &issuer,
                descriptor.clone(),
                &image,
                &ContentHash::of_bytes(b"other context"),
            )
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );

        let records = selector_records(descriptor.source(), &ContentHash::of_bytes(source))
            .unwrap()
            .into_iter()
            .map(|record| match record {
                ExportRecord::Resource(record) => record,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        let policy = TogglePolicy(AtomicBool::new(true));
        check_policy(&policy, &(), &records).unwrap();
        policy.0.store(false, Ordering::Relaxed);
        assert_eq!(
            check_policy(&policy, &(), &records).unwrap_err().kind,
            ErrorKind::Denied
        );
    }

    #[test]
    fn source_plus_graph_descriptor_is_separate_and_requires_both_registered_roots() {
        let source = b"source text";
        let context = ContentHash::of_bytes(b"capture");
        let graph_context = ContentHash::of_bytes(b"graph context");
        let descriptor = SourcePlusGraphArtifactDescriptor::new(
            SourceReadRequest {
                source_id: SourceId::new("urn:ctxql:source:graph-test").unwrap(),
                version: ContentHash::of_bytes(source),
                selector: EvidenceSelector::Span(Utf8Span::new(0, source.len()).unwrap()),
                max_bytes: source.len(),
            },
            ContentHash::of_bytes(source),
            ContentHash::of_bytes(b"artifact"),
            "graph_transcript",
            context.clone(),
            graph_context.clone(),
        )
        .unwrap();
        let image = descriptor.projection();
        assert_eq!(
            SourcePlusGraphArtifactDescriptor::from_value(&image, source.len()).unwrap(),
            descriptor
        );
        assert!(AcquisitionArtifactDescriptor::from_value(&image, source.len()).is_err());
        let issuer = Arc::new(());
        let grant = provision_source_plus_graph_artifact(
            &issuer,
            descriptor.clone(),
            &image,
            &context,
            &graph_context,
        )
        .unwrap();
        assert_eq!(grant.descriptor, descriptor);
        assert_eq!(
            grant
                .descriptor
                .successor(ContentHash::of_bytes(b"page"), "graph_transcript_page")
                .unwrap()
                .graph_context_root(),
            &graph_context
        );
        assert_eq!(
            provision_source_plus_graph_artifact(
                &issuer,
                grant.descriptor.clone(),
                &image,
                &context,
                &ContentHash::of_bytes(b"other graph context"),
            )
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
        assert_eq!(
            provision_source_plus_graph_artifact(
                &issuer,
                grant.descriptor.clone(),
                &image,
                &ContentHash::of_bytes(b"other capture"),
                &graph_context,
            )
            .unwrap_err()
            .kind,
            ErrorKind::Denied
        );
    }

    #[test]
    fn rich_acquisition_selector_is_verified_and_provisioned_exactly() {
        let directory = tempdir().unwrap();
        let store = SourceStore::open(directory.path().canonicalize().unwrap(), 1_024).unwrap();
        let text = b"alpha\nbeta gamma\nomega\n";
        let object_hash = store.put(text).unwrap();
        let descriptor_bytes = object([
            (
                "converter_manifest",
                V::string(ContentHash::of_bytes(b"converter").as_str()),
            ),
            ("object", V::string(object_hash.as_str())),
            ("schema", V::string("ctxql-text-version/v1")),
        ])
        .canonical_bytes(Limits::default())
        .unwrap();
        let version = store.put(&descriptor_bytes).unwrap();
        let source_id =
            SourceId::new(format!("urn:ctxql:source:text:{}", &version.as_str()[7..])).unwrap();
        let source = cdb_core::evidence::SourceReference::from_value(&object([
            ("source_id", V::string(source_id.as_str())),
            ("kind", V::string("ctxql.source.extraction-text")),
            ("version", V::string(version.as_str())),
            ("object_hash", V::string(object_hash.as_str())),
            (
                "content_hash",
                V::string(ContentHash::of_bytes(b"beta gamma").as_str()),
            ),
            (
                "selectors",
                object([
                    ("contract", V::string("ctxql-evidence/v1")),
                    (
                        "utf8",
                        object([("start", V::integer(6)), ("end", V::integer(16))]),
                    ),
                    (
                        "line",
                        object([("start", V::integer(2)), ("end", V::integer(2))]),
                    ),
                    ("text_quote", object([("exact", V::string("beta gamma"))])),
                ]),
            ),
        ]))
        .unwrap();
        let request = reference_request(&source, 64).unwrap();
        assert_eq!(
            store.selected_reference(&request, &source).unwrap().bytes(),
            b"beta gamma"
        );
        let rich = acquisition_selector_records(&source, 64).unwrap();
        let plain = selector_records(&request, source.content_hash().unwrap()).unwrap();
        assert_ne!(
            rich[2], plain[2],
            "rich witnesses are part of exact grant identity"
        );

        let mut invalid = source.projection();
        let V::Object(fields) = &mut invalid else {
            unreachable!()
        };
        let V::Object(selectors) = fields.get_mut("selectors").unwrap() else {
            unreachable!()
        };
        selectors.insert(
            "line".into(),
            object([("start", V::integer(1)), ("end", V::integer(1))]),
        );
        let invalid = cdb_core::evidence::SourceReference::from_value(&invalid).unwrap();
        assert!(store.selected_reference(&request, &invalid).is_err());
    }

    #[test]
    fn converted_representation_chain_is_bound_to_source_and_version() {
        use cdb_source_store::{
            ConverterManifest, Normalization, OriginalRepresentationManifest,
            TextRepresentationManifest,
        };
        let directory = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store =
            SourceStore::open(directory.path().canonicalize().unwrap(), 1024 * 1024).unwrap();
        let text = b"Verified converted text";
        let object = store.put(text).unwrap();
        let converter = ConverterManifest::new(
            ContentHash::of_bytes(b"converter"),
            "v1",
            vec![],
            1000,
            1024,
            Normalization::None,
        )
        .unwrap();
        let converter_root = store.put(&converter.canonical_bytes().unwrap()).unwrap();
        let original = OriginalRepresentationManifest::new(
            ContentHash::of_bytes(b"PDF"),
            "application/pdf",
            ContentHash::of_bytes(b"acquisition"),
        )
        .unwrap();
        let original_root = store.put(&original.canonical_bytes().unwrap()).unwrap();
        let manifest =
            TextRepresentationManifest::new(object, original_root, converter_root).unwrap();
        let root = store.put(&manifest.canonical_bytes().unwrap()).unwrap();
        store.put(&manifest.version_bytes().unwrap()).unwrap();
        let mut request = SourceReadRequest {
            source_id: cdb_core::id::SourceId::new(format!(
                "urn:ctxql:source:{}",
                &root.as_str()[7..]
            ))
            .unwrap(),
            version: manifest.version().clone(),
            selector: EvidenceSelector::WholeDocument,
            max_bytes: 1024,
        };
        assert_eq!(store.representation(&request).unwrap(), text);
        request.version = store.put(b"different text").unwrap();
        assert!(store.representation(&request).is_err());
        request.version = manifest.version().clone();
        std::fs::write(
            directory
                .path()
                .join(&manifest.converter_manifest().as_str()[7..]),
            b"forged",
        )
        .unwrap();
        assert!(store.representation(&request).is_err());
    }

    #[test]
    fn p6_text_version_resolves_to_immutable_text_object() {
        let directory = tempdir().unwrap();
        let store = SourceStore::open(directory.path().canonicalize().unwrap(), 1_024).unwrap();
        let text = b"alpha beta";
        let object_hash = store.put(text).unwrap();
        let descriptor = object([
            (
                "converter_manifest",
                V::string(ContentHash::of_bytes(b"converter").as_str()),
            ),
            ("object", V::string(object_hash.as_str())),
            ("schema", V::string("ctxql-text-version/v1")),
        ])
        .canonical_bytes(Limits::default())
        .unwrap();
        let version = store.put(&descriptor).unwrap();
        let request = SourceReadRequest {
            source_id: SourceId::new(format!("urn:ctxql:source:text:{}", &version.as_str()[7..]))
                .unwrap(),
            version,
            selector: EvidenceSelector::Span(Utf8Span::new(6, 10).unwrap()),
            max_bytes: 32,
        };
        let selected = store
            .selected(&request, &ContentHash::of_bytes(b"beta"))
            .unwrap();
        assert_eq!(selected.bytes(), b"beta");
    }
}
