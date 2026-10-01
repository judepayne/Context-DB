use crate::id::*;
use crate::value::obj;
use crate::{CanonicalValue as V, Error, Limits, Result};
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRef {
    iri: Iri,
    version: VersionId,
    hash: ContentHash,
}
impl ArtifactRef {
    pub fn new(iri: Iri, version: VersionId, hash: ContentHash) -> Self {
        Self { iri, version, hash }
    }
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(&["iri", "version", "hash"], &[])?;
        Ok(Self::new(
            Iri::new(v.field("iri")?.as_str()?)?,
            VersionId::new(v.field("version")?.as_str()?)?,
            ContentHash::parse(v.field("hash")?.as_str()?)?,
        ))
    }
    pub fn iri(&self) -> &Iri {
        &self.iri
    }
    pub fn version(&self) -> &VersionId {
        &self.version
    }
    pub fn hash(&self) -> &ContentHash {
        &self.hash
    }
    pub fn projection(&self) -> V {
        obj([
            ("iri", V::string(self.iri.as_str())),
            ("version", V::string(self.version.as_str())),
            ("hash", V::string(self.hash.as_str())),
        ])
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedArtifact {
    reference: ArtifactRef,
    content: Vec<u8>,
}
impl PublishedArtifact {
    pub fn new(reference: ArtifactRef, content: Vec<u8>, limits: Limits) -> Result<Self> {
        if content.len() > limits.input_bytes() {
            return Err(Error::limit());
        }
        if ContentHash::of_bytes(&content) != reference.hash {
            return Err(Error::invalid("artifact content hash mismatch"));
        }
        Ok(Self { reference, content })
    }
    pub fn reference(&self) -> &ArtifactRef {
        &self.reference
    }
    pub fn content(&self) -> &[u8] {
        &self.content
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineIdentity {
    implementation: Iri,
    version: VersionId,
    build: ContentHash,
}
impl EngineIdentity {
    pub fn new(implementation: Iri, version: VersionId, build: ContentHash) -> Self {
        Self {
            implementation,
            version,
            build,
        }
    }
    pub fn projection(&self) -> V {
        obj([
            ("implementation", V::string(self.implementation.as_str())),
            ("version", V::string(self.version.as_str())),
            ("build", V::string(self.build.as_str())),
        ])
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionManifest {
    name: ResourceId,
    version: VersionId,
    hash: ContentHash,
    content: V,
}
impl FunctionManifest {
    /// Load a retained manifest without replacing its exact published byte hash
    /// with the hash of a reserialized JSON value. `new` authors canonical bytes.
    pub fn from_published(
        name: ResourceId,
        artifact: &PublishedArtifact,
        limits: Limits,
    ) -> Result<Self> {
        Ok(Self {
            name,
            version: artifact.reference().version().clone(),
            hash: artifact.reference().hash().clone(),
            content: V::parse(artifact.content(), limits)?,
        })
    }
    pub fn new(name: ResourceId, version: VersionId, content: V, limits: Limits) -> Result<Self> {
        let hash = ContentHash::of_bytes(&content.canonical_bytes(limits)?);
        Ok(Self {
            name,
            version,
            hash,
            content,
        })
    }
    /// Validate retained summary data only. This neither verifies original published
    /// bytes nor grants an executable manifest or replay capability.
    pub fn from_retained_summary(
        name: ResourceId,
        version: VersionId,
        hash: ContentHash,
        content: V,
        limits: Limits,
    ) -> Result<Self> {
        content.canonical_bytes(limits)?;
        Ok(Self {
            name,
            version,
            hash,
            content,
        })
    }
    pub fn name(&self) -> &ResourceId {
        &self.name
    }
    pub fn version(&self) -> &VersionId {
        &self.version
    }
    pub fn hash(&self) -> &ContentHash {
        &self.hash
    }
    pub fn content(&self) -> &V {
        &self.content
    }
}
