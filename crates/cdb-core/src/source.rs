use crate::artifact::ArtifactRef;
use crate::claim::TypedLiteral;
use crate::id::*;
use crate::snapshot::GraphPin;
use crate::{CanonicalValue as V, Error, Limits, Result, Timestamp};
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationMode {
    Import,
    Live,
}
impl PreparationMode {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "import" => Ok(Self::Import),
            "live" => Ok(Self::Live),
            _ => Err(Error::invalid("preparation mode")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Live => "live",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalSnapshot(V);
impl ExternalSnapshot {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &[
                "table_uuid",
                "snapshot_id",
                "metadata_hash",
                "files",
                "schema_id",
                "mapping_hash",
                "provider_version",
            ],
            &[],
        )?;
        ResourceId::new(v.field("table_uuid")?.as_str()?)?;
        ResourceId::new(v.field("snapshot_id")?.as_str()?)?;
        v.field("schema_id")?.u64()?;
        VersionId::new(v.field("provider_version")?.as_str()?)?;
        for k in ["metadata_hash", "mapping_hash"] {
            ContentHash::parse(v.field(k)?.as_str()?)?;
        }
        let mut paths = BTreeSet::new();
        for f in v.field("files")?.as_array()? {
            f.closed(&["path", "hash", "size"], &[])?;
            let p = f.field("path")?.as_str()?;
            if p.is_empty()
                || p.starts_with('/')
                || p.contains('\\')
                || p.contains(':')
                || p.chars().any(char::is_control)
                || p.split('/').any(|c| c.is_empty() || c == "." || c == "..")
                || !paths.insert(p)
            {
                return Err(Error::invalid("canonical relative file path"));
            }
            ContentHash::parse(f.field("hash")?.as_str()?)?;
            f.field("size")?.u64()?;
        }
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
    pub fn mapping_hash(&self) -> Result<ContentHash> {
        ContentHash::parse(self.0.field("mapping_hash")?.as_str()?)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowKey(Vec<TypedLiteral>);
impl RowKey {
    pub fn new(values: Vec<TypedLiteral>) -> Result<Self> {
        if values.is_empty() {
            return Err(Error::invalid("nonnull nonempty typed row key"));
        }
        Ok(Self(values))
    }
    pub fn from_value(v: &V) -> Result<Self> {
        Self::new(
            v.as_array()?
                .iter()
                .map(row_literal)
                .collect::<Result<_>>()?,
        )
    }
    pub fn projection(&self) -> V {
        V::Array(self.0.iter().map(row_literal_projection).collect())
    }
}
pub fn row_literal(v: &V) -> Result<TypedLiteral> {
    v.closed(&["datatype", "value", "language"], &[])?;
    TypedLiteral::new(
        Iri::new(v.field("datatype")?.as_str()?)?,
        v.field("value")?.clone(),
        crate::claim::nullable_string(v.field("language")?)?,
    )
}
pub fn row_literal_projection(l: &TypedLiteral) -> V {
    let V::Object(mut o) = l.projection() else {
        unreachable!()
    };
    o.remove("kind");
    V::Object(o)
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssertionSlot {
    name: ResourceId,
    ordinal: u64,
}
impl AssertionSlot {
    pub fn new(name: ResourceId, ordinal: u64) -> Self {
        Self { name, ordinal }
    }
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(&["name", "ordinal"], &[])?;
        Ok(Self::new(
            ResourceId::new(v.field("name")?.as_str()?)?,
            v.field("ordinal")?.u64()?,
        ))
    }
    pub fn projection(&self) -> V {
        crate::value::obj([
            ("name", V::string(self.name.as_str())),
            ("ordinal", V::integer(self.ordinal)),
        ])
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeutralRow(V);
impl NeutralRow {
    pub fn from_value(v: &V, limits: Limits) -> Result<Self> {
        v.closed(
            &[
                "source_id",
                "snapshot_ref",
                "row_key",
                "values",
                "provenance",
            ],
            &[],
        )?;
        SourceId::new(v.field("source_id")?.as_str()?)?;
        ExternalSnapshot::from_value(v.field("snapshot_ref")?)?;
        RowKey::from_value(v.field("row_key")?)?;
        for (name, value) in v.field("values")?.as_object()? {
            ResourceId::new(name)?;
            if *value != V::Null {
                row_literal(value)?;
            }
        }
        v.field("provenance")?.as_object()?;
        v.canonical_bytes(limits)?;
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparationRequest(V);
impl PreparationRequest {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &["config_ref", "local_graph_pin", "parameters"],
            &["source_ids"],
        )?;
        ArtifactRef::from_value(v.field("config_ref")?)?;
        GraphPin::from_value(v.field("local_graph_pin")?)?;
        v.field("parameters")?.as_object()?;
        if let Some(ids) = v.as_object()?.get("source_ids") {
            let mut seen = BTreeSet::new();
            for id in ids.as_array()? {
                if !seen.insert(SourceId::new(id.as_str()?)?) {
                    return Err(Error::invalid("duplicate source ID"));
                }
            }
        }
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceDeclaration(V);
impl SourceDeclaration {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &[
                "source_id",
                "provider_version",
                "mapping_ref",
                "mode",
                "capabilities",
                "selection",
                "limits",
            ],
            &[],
        )?;
        SourceId::new(v.field("source_id")?.as_str()?)?;
        VersionId::new(v.field("provider_version")?.as_str()?)?;
        ArtifactRef::from_value(v.field("mapping_ref")?)?;
        PreparationMode::parse(v.field("mode")?.as_str()?)?;
        for c in v.field("capabilities")?.as_array()? {
            ResourceId::new(c.as_str()?)?;
        }
        v.field("selection")?.as_object()?;
        for l in v.field("limits")?.as_object()?.values() {
            l.u64()?;
        }
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReadRequest {
    pub source_id: SourceId,
    pub version: ContentHash,
    pub selector: crate::evidence::EvidenceSelector,
    pub max_bytes: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRead {
    source_id: SourceId,
    version: ContentHash,
    selector: crate::evidence::EvidenceSelector,
    bytes: Vec<u8>,
}
impl SourceRead {
    /// Construct a whole-document read. For selected fragments use `from_request`.
    pub fn new(
        source_id: SourceId,
        version: ContentHash,
        bytes: Vec<u8>,
        max_bytes: usize,
    ) -> Result<Self> {
        if bytes.len() > max_bytes {
            return Err(Error::limit());
        }
        Ok(Self {
            source_id,
            version,
            selector: crate::evidence::EvidenceSelector::WholeDocument,
            bytes,
        })
    }
    /// Trusted adapter construction: bytes must be the request's selected content.
    pub fn from_request(request: &SourceReadRequest, bytes: Vec<u8>) -> Result<Self> {
        let mut read = Self::new(
            request.source_id.clone(),
            request.version.clone(),
            bytes,
            request.max_bytes,
        )?;
        read.selector = request.selector.clone();
        Ok(read)
    }
    pub fn selector(&self) -> &crate::evidence::EvidenceSelector {
        &self.selector
    }
    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }
    pub fn version(&self) -> &ContentHash {
        &self.version
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionRequest {
    pub source: SourceRead,
    pub extractor: ArtifactRef,
    pub settings: V,
    pub observed_at: Timestamp,
    pub max_candidates: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionResult {
    candidates: Vec<crate::claim::CandidateClaim>,
    provenance: V,
}
impl ExtractionResult {
    pub fn new(
        candidates: Vec<crate::claim::CandidateClaim>,
        provenance: V,
        max_candidates: usize,
    ) -> Result<Self> {
        if candidates.len() > max_candidates {
            return Err(Error::limit());
        }
        provenance.as_object()?;
        let mut ids = BTreeSet::new();
        if candidates.iter().any(|c| !ids.insert(c.id())) {
            return Err(Error::invalid("duplicate extraction ID"));
        }
        Ok(Self {
            candidates,
            provenance,
        })
    }
    pub fn candidates(&self) -> &[crate::claim::CandidateClaim] {
        &self.candidates
    }
    pub fn provenance(&self) -> &V {
        &self.provenance
    }
}
