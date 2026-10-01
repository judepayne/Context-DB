//! Validated portable recording data. Construction and decoding confer no authority.
use crate::admission::{DependencyRecord, ExportRecord, Fact, FactTerm, ResourceKind};
use crate::artifact::ArtifactRef;
use crate::canonical::{CanonicalProjection, Domain};
use crate::claim::TypedLiteral;
use crate::id::*;
use crate::record_codec::{snapshot_from_value, snapshot_value};
use crate::replay::RecordedLanding;
use crate::snapshot::SnapshotRef;
use crate::storage_origin::INTERNAL_PREFIX;
use crate::value::obj;
use crate::{CanonicalValue as V, Error, ErrorKind, Limits, Result, Timestamp};
use std::collections::{BTreeMap, BTreeSet};

pub const REPLAY_SCHEMA: &str = "ctxql-replay-data/v2";
pub const RUN_SCHEMA: &str = "ctxql-recorded-run/v2";
pub const CATALOG_SCOPE: &str = "https://ctxql.example/storage/v1/scope/catalog";
pub const ADJACENCY_SCOPE: &str = "https://ctxql.example/storage/v1/scope/adjacency";
pub const LIFECYCLE_SCOPE: &str = "https://ctxql.example/storage/v1/scope/lifecycle";
pub const INTERPRETATION_SCOPE: &str = "https://ctxql.example/storage/v1/scope/interpretation";
pub const REQUIRED_SCOPES: [&str; 4] = [
    CATALOG_SCOPE,
    ADJACENCY_SCOPE,
    LIFECYCLE_SCOPE,
    INTERPRETATION_SCOPE,
];
pub const RUN_PAYLOAD: &str = "https://ctxql.example/storage/v1/runPayload";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingEngine {
    pub name: ResourceId,
    pub version: VersionId,
    pub build: ContentHash,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyObservation {
    pub resource: ResourceId,
    pub predicate: Option<Iri>,
    pub allowed: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadObservation {
    pub operation: ResourceId,
    pub key: V,
    pub result_hash: ContentHash,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCatalogEntry {
    pub id: ResourceId,
    pub label: Option<String>,
    pub dependencies: Vec<ResourceId>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayDataInput {
    pub snapshot: SnapshotRef,
    pub requested_snapshot: SnapshotRef,
    pub as_of: Timestamp,
    pub stale: bool,
    pub plan: CanonicalProjection,
    pub plan_hash: ContentHash,
    pub response: CanonicalProjection,
    pub response_hash: ContentHash,
    pub query: ArtifactRef,
    pub profile: Option<ArtifactRef>,
    pub config: ArtifactRef,
    pub engine: RecordingEngine,
    pub replay_abi: VersionId,
    pub landings: Vec<RecordedLanding>,
    pub catalog: Vec<PreparedCatalogEntry>,
    pub policy: Vec<PolicyObservation>,
    pub reads: Vec<ReadObservation>,
    pub scopes: Vec<ResourceId>,
    pub functions: Vec<V>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayData(ReplayDataInput);
impl ReplayDataInput {
    fn projection(&self) -> V {
        obj([
            ("schema", V::string(REPLAY_SCHEMA)),
            ("snapshot", snapshot_value(&self.snapshot)),
            (
                "requested_snapshot",
                snapshot_value(&self.requested_snapshot),
            ),
            ("as_of", V::string(self.as_of.canonical())),
            ("stale", V::Bool(self.stale)),
            ("plan", self.plan.envelope()),
            ("plan_hash", V::string(self.plan_hash.as_str())),
            ("response", self.response.envelope()),
            ("response_hash", V::string(self.response_hash.as_str())),
            ("query", self.query.projection()),
            (
                "profile",
                self.profile
                    .as_ref()
                    .map(ArtifactRef::projection)
                    .unwrap_or(V::Null),
            ),
            ("config", self.config.projection()),
            (
                "engine",
                obj([
                    ("name", V::string(self.engine.name.as_str())),
                    ("version", V::string(self.engine.version.as_str())),
                    ("build", V::string(self.engine.build.as_str())),
                ]),
            ),
            ("replay_abi", V::string(self.replay_abi.as_str())),
            (
                "landings",
                V::Array(
                    self.landings
                        .iter()
                        .map(RecordedLanding::projection)
                        .collect(),
                ),
            ),
            (
                "catalog",
                V::Array(
                    self.catalog
                        .iter()
                        .map(|c| {
                            obj([
                                ("id", V::string(c.id.as_str())),
                                ("label", c.label.as_ref().map(V::string).unwrap_or(V::Null)),
                                ("dependencies", ids(&c.dependencies)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "policy",
                V::Array(
                    self.policy
                        .iter()
                        .map(|p| {
                            obj([
                                ("resource", V::string(p.resource.as_str())),
                                (
                                    "predicate",
                                    p.predicate
                                        .as_ref()
                                        .map(|p| V::string(p.as_str()))
                                        .unwrap_or(V::Null),
                                ),
                                ("allowed", V::Bool(p.allowed)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "reads",
                V::Array(
                    self.reads
                        .iter()
                        .map(|r| {
                            obj([
                                ("operation", V::string(r.operation.as_str())),
                                ("key", r.key.clone()),
                                ("result_hash", V::string(r.result_hash.as_str())),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("scopes", ids(&self.scopes)),
            ("functions", V::Array(self.functions.clone())),
        ])
    }
}
fn ids(v: &[ResourceId]) -> V {
    V::Array(v.iter().map(|i| V::string(i.as_str())).collect())
}
fn parse_ids(v: &V) -> Result<Vec<ResourceId>> {
    v.as_array()?
        .iter()
        .map(|i| ResourceId::new(i.as_str()?))
        .collect()
}
// A bounded serialization preflight visits borrowed data before any decoder clones it.
fn bounded(v: &V, limits: Limits) -> Result<()> {
    v.canonical_bytes(limits)?;
    Ok(())
}
impl ReplayData {
    pub fn new(input: ReplayDataInput, limits: Limits) -> Result<Self> {
        // Bound each owned component before building the combined wire tree.
        let count = input
            .landings
            .len()
            .checked_add(input.catalog.len())
            .and_then(|n| n.checked_add(input.policy.len()))
            .and_then(|n| n.checked_add(input.reads.len()))
            .and_then(|n| n.checked_add(input.scopes.len()))
            .and_then(|n| n.checked_add(input.functions.len()))
            .ok_or_else(Error::limit)?;
        if count > limits.values() {
            return Err(Error::limit());
        }
        if !input.functions.is_empty() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "function summaries unsupported in P4",
            ));
        }
        let mut budget = crate::limits::Budget::new(limits);
        for bytes in [input.plan.bytes(limits)?, input.response.bytes(limits)?] {
            budget.charge(1, bytes.len(), bytes.len())?;
        }
        for r in &input.reads {
            let bytes = r.key.canonical_bytes(limits)?;
            budget.charge(1, bytes.len(), bytes.len())?;
        }
        for c in &input.catalog {
            let label_bytes = c.label.as_ref().map_or(0, String::len);
            budget.charge(c.dependencies.len(), label_bytes, label_bytes)?;
            for d in &c.dependencies {
                budget.charge(1, d.as_str().len(), d.as_str().len())?;
            }
        }
        for p in &input.policy {
            let n =
                p.resource.as_str().len() + p.predicate.as_ref().map_or(0, |p| p.as_str().len());
            budget.charge(1, n, n)?;
        }
        for landing in &input.landings {
            let bytes = landing.projection().canonical_bytes(limits)?;
            budget.charge(1, bytes.len(), bytes.len())?;
        }
        Self::from_value(&input.projection(), limits)
    }
    pub fn from_value(v: &V, limits: Limits) -> Result<Self> {
        bounded(v, limits)?;
        v.closed(
            &[
                "schema",
                "snapshot",
                "requested_snapshot",
                "as_of",
                "stale",
                "plan",
                "plan_hash",
                "response",
                "response_hash",
                "query",
                "profile",
                "config",
                "engine",
                "replay_abi",
                "landings",
                "catalog",
                "policy",
                "reads",
                "scopes",
                "functions",
            ],
            &[],
        )?;
        if v.field("schema")?.as_str()? != REPLAY_SCHEMA {
            return Err(Error::invalid("replay schema"));
        }
        if !v.field("functions")?.as_array()?.is_empty() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "function summaries unsupported in P4",
            ));
        }
        let plan = CanonicalProjection::read(&v.field("plan")?.canonical_bytes(limits)?, limits)?;
        let response =
            CanonicalProjection::read(&v.field("response")?.canonical_bytes(limits)?, limits)?;
        let plan_hash = ContentHash::parse(v.field("plan_hash")?.as_str()?)?;
        let response_hash = ContentHash::parse(v.field("response_hash")?.as_str()?)?;
        if plan.domain() != Domain::Plan
            || response.domain() != Domain::Response
            || plan.hash(limits)? != plan_hash
            || response.hash(limits)? != response_hash
        {
            return Err(Error::invalid("recorded canonical integrity"));
        }
        let snapshot = snapshot_from_value(v.field("snapshot")?, limits)?;
        let requested_snapshot = snapshot_from_value(v.field("requested_snapshot")?, limits)?;
        let stale = v.field("stale")?.as_bool()?;
        if !snapshot.same_authority(&requested_snapshot)
            || stale == (snapshot == requested_snapshot)
        {
            return Err(Error::invalid("recorded pin provenance"));
        }
        let as_of = Timestamp::parse(v.field("as_of")?.as_str()?)?;
        if v.field("as_of")? != &V::string(as_of.canonical())
            || plan.payload().field("as_of")? != v.field("as_of")?
        {
            return Err(Error::invalid("recorded cutoff"));
        }
        let artifacts = plan.payload().field("artifacts")?;
        for key in ["query", "profile", "config"] {
            if artifacts.field(key)? != v.field(key)? {
                return Err(Error::invalid("recorded artifact binding"));
            }
        }
        let query = ArtifactRef::from_value(v.field("query")?)?;
        let profile = if *v.field("profile")? == V::Null {
            None
        } else {
            Some(ArtifactRef::from_value(v.field("profile")?)?)
        };
        let config = ArtifactRef::from_value(v.field("config")?)?;
        let e = v.field("engine")?;
        e.closed(&["name", "version", "build"], &[])?;
        let engine = RecordingEngine {
            name: ResourceId::new(e.field("name")?.as_str()?)?,
            version: VersionId::new(e.field("version")?.as_str()?)?,
            build: ContentHash::parse(e.field("build")?.as_str()?)?,
        };
        let replay_abi = VersionId::new(v.field("replay_abi")?.as_str()?)?;
        let landings = v
            .field("landings")?
            .as_array()?
            .iter()
            .map(RecordedLanding::from_value)
            .collect::<Result<Vec<_>>>()?;
        let mut landing_ids = BTreeSet::new();
        let blocks = plan.payload().field("query")?.field("about")?.as_array()?;
        for landing in v.field("landings")?.as_array()? {
            let index = usize::try_from(landing.field("block_index")?.u64()?)
                .map_err(|_| Error::invalid("landing block"))?;
            let role = landing.field("role")?.as_str()?;
            let block = blocks
                .get(index)
                .ok_or_else(|| Error::invalid("landing block"))?;
            if !block
                .field(role)?
                .as_array()?
                .contains(landing.field("anchor")?)
                || !landing_ids.insert((
                    index,
                    role,
                    landing.field("anchor")?.as_str()?,
                    landing.field("id")?.as_str()?,
                ))
            {
                return Err(Error::invalid("landing identity/anchor binding"));
            }
        }
        let explain = response.payload().field("explain")?;
        if *explain != V::Null {
            let context = explain.field("evaluation_context")?;
            if context.field("as_of")? != v.field("as_of")?
                || context.field("db_time")? != &snapshot.pin().projection()
                || context.field("profile")? != v.field("profile")?
                || explain.field("seeds")? != v.field("landings")?
            {
                return Err(Error::invalid("recorded response context/landings"));
            }
        }
        // Catalogs are ordered entries, not maps: identity-only and multiple
        // label entries intentionally repeat an entity and can have no supports.
        let catalog = v
            .field("catalog")?
            .as_array()?
            .iter()
            .map(|c| {
                c.closed(&["id", "label", "dependencies"], &[])?;
                let id = ResourceId::new(c.field("id")?.as_str()?)?;
                let dependencies = parse_ids(c.field("dependencies")?)?;
                Ok(PreparedCatalogEntry {
                    id,
                    label: match c.field("label")? {
                        V::Null => None,
                        label => Some(label.as_str()?.to_owned()),
                    },
                    dependencies,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut decisions = BTreeMap::new();
        let policy = v
            .field("policy")?
            .as_array()?
            .iter()
            .map(|p| {
                p.closed(&["resource", "predicate", "allowed"], &[])?;
                let resource = ResourceId::new(p.field("resource")?.as_str()?)?;
                let predicate = if *p.field("predicate")? == V::Null {
                    None
                } else {
                    Some(Iri::new(p.field("predicate")?.as_str()?)?)
                };
                let allowed = p.field("allowed")?.as_bool()?;
                if decisions
                    .insert((resource.clone(), predicate.clone()), allowed)
                    .is_some_and(|old| old != allowed)
                {
                    return Err(Error::invalid("conflicting policy observations"));
                }
                Ok(PolicyObservation {
                    resource,
                    predicate,
                    allowed,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let reads = v
            .field("reads")?
            .as_array()?
            .iter()
            .map(|r| {
                r.closed(&["operation", "key", "result_hash"], &[])?;
                Ok(ReadObservation {
                    operation: ResourceId::new(r.field("operation")?.as_str()?)?,
                    key: r.field("key")?.clone(),
                    result_hash: ContentHash::parse(r.field("result_hash")?.as_str()?)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let scopes = parse_ids(v.field("scopes")?)?;
        if scopes.len() != 4
            || scopes.iter().collect::<BTreeSet<_>>().len() != 4
            || REQUIRED_SCOPES
                .iter()
                .any(|s| !scopes.iter().any(|id| id.as_str() == *s))
        {
            return Err(Error::invalid("mandatory recording scopes"));
        }
        Ok(Self(ReplayDataInput {
            snapshot,
            requested_snapshot,
            as_of,
            stale,
            plan,
            plan_hash,
            response,
            response_hash,
            query,
            profile,
            config,
            engine,
            replay_abi,
            landings,
            catalog,
            policy,
            reads,
            scopes,
            functions: vec![],
        }))
    }
    pub fn data(&self) -> &ReplayDataInput {
        &self.0
    }
    pub fn projection(&self) -> V {
        self.0.projection()
    }
    pub fn bytes(&self, limits: Limits) -> Result<Vec<u8>> {
        self.projection().canonical_bytes(limits)
    }
    pub fn read(bytes: &[u8], limits: Limits) -> Result<Self> {
        Self::from_value(&V::parse(bytes, limits)?, limits)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunEnvelope {
    id: RunId,
    owner: PrincipalId,
    operation_hash: ContentHash,
    replay: ReplayData,
}
impl RunEnvelope {
    pub fn new(
        id: RunId,
        owner: PrincipalId,
        operation_hash: ContentHash,
        replay: ReplayData,
        limits: Limits,
    ) -> Result<Self> {
        let out = Self {
            id,
            owner,
            operation_hash,
            replay,
        };
        out.bytes(limits)?;
        Ok(out)
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
    pub fn replay(&self) -> &ReplayData {
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
    pub fn from_value(v: &V, limits: Limits) -> Result<Self> {
        bounded(v, limits)?;
        v.closed(&["schema", "id", "owner", "operation_hash", "replay"], &[])?;
        if v.field("schema")?.as_str()? != RUN_SCHEMA {
            return Err(Error::invalid("run schema"));
        }
        Self::new(
            RunId::new(v.field("id")?.as_str()?)?,
            PrincipalId::new(v.field("owner")?.as_str()?)?,
            ContentHash::parse(v.field("operation_hash")?.as_str()?)?,
            ReplayData::from_value(v.field("replay")?, limits)?,
            limits,
        )
    }
    pub fn bytes(&self, limits: Limits) -> Result<Vec<u8>> {
        self.projection().canonical_bytes(limits)
    }
    pub fn read(bytes: &[u8], limits: Limits) -> Result<Self> {
        Self::from_value(&V::parse(bytes, limits)?, limits)
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
        let ExportRecord::Resource(r) = record else {
            return Err(Error::invalid("run resource"));
        };
        if r.kind() != ResourceKind::RunDescriptor
            || r.facts().len() != 1
            || r.facts()[0].predicate().as_str() != RUN_PAYLOAD
        {
            return Err(Error::invalid("run descriptor"));
        }
        let FactTerm::Literal(l) = r.facts()[0].term() else {
            return Err(Error::invalid("run literal"));
        };
        let p = l.projection();
        if p.field("datatype")?.as_str()? != XSD_STRING || *p.field("language")? != V::Null {
            return Err(Error::invalid("run literal type"));
        }
        let bytes = p.field("value")?.as_str()?.as_bytes();
        let run = Self::read(bytes, limits)?;
        if run.descriptor_id()? != *r.id() || run.bytes(limits)? != bytes {
            return Err(Error::invalid("run descriptor identity/canonical payload"));
        }
        Ok(run)
    }
}
