//! Current Fluree 4.2.1 execution recording.
//!
//! V4 remains the archival format for the former `603974f` executor. V5 wraps
//! the same portable evidence shape with an explicit executor descriptor so a
//! current process cannot silently present itself as that historical backend.

use crate::{
    admission::{DependencyRecord, ExportRecord, Fact, FactTerm, ResourceKind},
    claim::TypedLiteral,
    id::{ContentHash, PrincipalId, ResourceId, RunId, VersionId},
    recording::RUN_PAYLOAD,
    recording_v4::ReplayDataV4,
    storage_origin::INTERNAL_PREFIX,
    value::obj,
    CanonicalValue as V, Error, Limits, Result,
};

pub const REPLAY_SCHEMA: &str = "ctxql-replay-data/v5";
pub const RUN_SCHEMA: &str = "ctxql-recorded-run/v5";
pub const REPLAY_ABI: &str = "ctxql-execution/v5";
pub const FLUREE_RELEASE: &str = "4.2.1";
pub const FLUREE_REVISION: &str = "82dbcec3e435d6ed1d45bc0ed929432323b6b201";
pub const BACKEND_ID: &str = "fluree-db/4.2.1@82dbcec3e435d6ed1d45bc0ed929432323b6b201";
pub const REASONER_PREFIX: &str =
    "fluree-owl2rl/4.2.1@82dbcec3e435d6ed1d45bc0ed929432323b6b201;profile=";
pub const EXECUTION_SEMANTICS: &str = "ctxql-semantic-execution/v5";
/// Raw, uncertified vocabulary identity for acquisition. This is deliberately
/// not an alias of the historical executable supported-subset profile.
pub const CURRENT_ACQUISITION_PROFILE_ID: &str =
    "ctxql-ontology-profile/fluree-4.2.1-82dbcec3e435d6ed1d45bc0ed929432323b6b201/v1-uncertified-acquisition";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionDescriptorV5 {
    wire: V,
}

impl ExecutionDescriptorV5 {
    pub fn current(
        graph_role_map_root: ContentHash,
        semantic_codec: VersionId,
        reasoner: VersionId,
        limits: Limits,
    ) -> Result<Self> {
        Self::from_value(
            &obj([
                ("backend", V::string(BACKEND_ID)),
                ("execution_semantics", V::string(EXECUTION_SEMANTICS)),
                (
                    "graph_role_map_root",
                    V::string(graph_role_map_root.as_str()),
                ),
                ("semantic_codec", V::string(semantic_codec.as_str())),
                ("reasoner", V::string(reasoner.as_str())),
            ]),
            limits,
        )
    }

    pub fn from_value(value: &V, limits: Limits) -> Result<Self> {
        value.closed(
            &[
                "backend",
                "execution_semantics",
                "graph_role_map_root",
                "semantic_codec",
                "reasoner",
            ],
            &[],
        )?;
        if value.field("backend")?.as_str()? != BACKEND_ID
            || value.field("execution_semantics")?.as_str()? != EXECUTION_SEMANTICS
        {
            return Err(Error::invalid("v5 execution backend identity"));
        }
        ContentHash::parse(value.field("graph_role_map_root")?.as_str()?)?;
        VersionId::new(value.field("semantic_codec")?.as_str()?)?;
        let reasoner = VersionId::new(value.field("reasoner")?.as_str()?)?;
        if reasoner.as_str() != "none/v1" && !reasoner.as_str().starts_with(REASONER_PREFIX) {
            return Err(Error::invalid("v5 reasoner identity"));
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
pub struct ReplayDataV5 {
    base: ReplayDataV4,
    execution: ExecutionDescriptorV5,
    wire: V,
}

impl ReplayDataV5 {
    pub fn new(base: ReplayDataV4, limits: Limits) -> Result<Self> {
        let evidence = base.semantic();
        let execution = ExecutionDescriptorV5::current(
            evidence.hash_field("graph_role_map_root")?,
            evidence.version_field("semantic_codec")?,
            evidence.version_field("reasoner")?,
            limits,
        )?;
        Self::from_value(
            &obj([
                ("schema", V::string(REPLAY_SCHEMA)),
                ("base", base.projection()),
                ("execution", execution.projection()),
            ]),
            limits,
        )
    }

    pub fn from_value(value: &V, limits: Limits) -> Result<Self> {
        value.closed(&["schema", "base", "execution"], &[])?;
        if value.field("schema")?.as_str()? != REPLAY_SCHEMA {
            return Err(Error::invalid("v5 replay schema"));
        }
        let base = ReplayDataV4::from_value(value.field("base")?, limits)?;
        let execution = ExecutionDescriptorV5::from_value(value.field("execution")?, limits)?;
        let evidence = base.semantic();
        let expected = ExecutionDescriptorV5::current(
            evidence.hash_field("graph_role_map_root")?,
            evidence.version_field("semantic_codec")?,
            evidence.version_field("reasoner")?,
            limits,
        )?;
        if execution != expected {
            return Err(Error::invalid("v5 execution descriptor mismatch"));
        }
        value.canonical_bytes(limits)?;
        Ok(Self {
            base,
            execution,
            wire: value.clone(),
        })
    }

    /// Historical portable execution body retained by V4 and V5.
    pub fn base(&self) -> &crate::recording_v3::ReplayDataV3 {
        self.base.base()
    }
    pub fn semantic(&self) -> &crate::recording_v4::SemanticEvidenceV4 {
        self.base.semantic()
    }
    pub fn control_capture(&self) -> &crate::snapshot::SnapshotRef {
        self.base.control_capture()
    }
    /// Full archival V4 evidence nested by the V5 executor descriptor.
    pub fn v4(&self) -> &ReplayDataV4 {
        &self.base
    }
    pub fn execution(&self) -> &ExecutionDescriptorV5 {
        &self.execution
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
        if self.execution != replay.execution {
            return Err(Error::invalid("v5 execution replay divergence"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunEnvelopeV5 {
    id: RunId,
    owner: PrincipalId,
    operation_hash: ContentHash,
    replay: ReplayDataV5,
}

impl RunEnvelopeV5 {
    pub fn new(
        id: RunId,
        owner: PrincipalId,
        operation_hash: ContentHash,
        replay: ReplayDataV5,
        limits: Limits,
    ) -> Result<Self> {
        let run = Self {
            id,
            owner,
            operation_hash,
            replay,
        };
        run.bytes(limits)?;
        Ok(run)
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
    pub fn replay(&self) -> &ReplayDataV5 {
        &self.replay
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
            return Err(Error::invalid("v5 run schema"));
        }
        Self::new(
            RunId::new(value.field("id")?.as_str()?)?,
            PrincipalId::new(value.field("owner")?.as_str()?)?,
            ContentHash::parse(value.field("operation_hash")?.as_str()?)?,
            ReplayDataV5::from_value(value.field("replay")?, limits)?,
            limits,
        )
    }
    pub fn bytes(&self, limits: Limits) -> Result<Vec<u8>> {
        self.projection().canonical_bytes(limits)
    }
    pub fn read(bytes: &[u8], limits: Limits) -> Result<Self> {
        Self::from_value(&V::parse(bytes, limits)?, limits)
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
                crate::id::Iri::new(RUN_PAYLOAD)?,
                FactTerm::Literal(TypedLiteral::new(
                    crate::id::Iri::new(XSD_STRING)?,
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
pub struct StoredV5(pub RunEnvelopeV5);
impl StoredV5 {
    pub fn to_record(&self, limits: Limits) -> Result<ExportRecord> {
        self.0.to_record(limits)
    }
    pub fn from_record(record: &ExportRecord, limits: Limits) -> Result<Self> {
        Ok(Self(RunEnvelopeV5::from_record(record, limits)?))
    }
}
