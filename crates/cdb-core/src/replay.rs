use crate::artifact::*;
use crate::evidence::EvidenceVerification;
use crate::id::*;
use crate::projection::{FunctionRootProjection, SemanticNotice};
use crate::snapshot::SnapshotRef;
use crate::{CanonicalValue as V, Error, Result, Timestamp};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayVerdict {
    Reproduced,
    ReproducedBestEffort,
    Diverged,
    NotReplayable,
}
impl ReplayVerdict {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "reproduced" => Ok(Self::Reproduced),
            "reproduced_best_effort" => Ok(Self::ReproducedBestEffort),
            "diverged" => Ok(Self::Diverged),
            "not_replayable" => Ok(Self::NotReplayable),
            _ => Err(Error::invalid("replay verdict")),
        }
    }
    pub fn aggregate(verdicts: impl IntoIterator<Item = Self>) -> Result<Self> {
        let mut out = Self::Reproduced;
        let mut any = false;
        for v in verdicts {
            any = true;
            out = match (out, v) {
                (Self::NotReplayable, _) | (_, Self::NotReplayable) => Self::NotReplayable,
                (Self::Diverged, _) | (_, Self::Diverged) => Self::Diverged,
                (Self::ReproducedBestEffort, _) | (_, Self::ReproducedBestEffort) => {
                    Self::ReproducedBestEffort
                }
                _ => Self::Reproduced,
            };
        }
        if !any {
            return Err(Error::invalid("no replay inputs"));
        }
        Ok(out)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductOutcome {
    Available,
    Reproduced,
    Missing,
    Changed,
    Denied,
    NotRequested,
    Failed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayReport {
    pub graph: ReplayVerdict,
    pub evidence: Vec<EvidenceVerification>,
    pub product: ProductOutcome,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadDependency {
    Claim(ClaimId),
    Lifecycle(ClaimId),
    Resource(ResourceId),
    Fact {
        resource: ResourceId,
        predicate: Iri,
    },
    NegativeLookup {
        descriptor: ResourceId,
    },
    Artifact(ArtifactRef),
    SourceSelector {
        descriptor: ResourceId,
        source: SourceId,
        version: ContentHash,
    },
    OrderingDescriptor(ResourceId),
}
/// Recording vocabulary, not a sealed authorization manifest or proof of instrumentation completeness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadFootprint {
    snapshot: SnapshotRef,
    used: Vec<ReadDependency>,
    requested_selectors: Vec<ResourceId>,
}
impl ReadFootprint {
    pub fn new(
        schema: &str,
        snapshot: SnapshotRef,
        used: Vec<ReadDependency>,
        requested_selectors: Vec<ResourceId>,
    ) -> Result<Self> {
        if schema != "ctxql-read-footprint/v1" {
            return Err(Error::invalid("footprint schema"));
        }
        let mut seen = std::collections::BTreeSet::new();
        if requested_selectors.iter().any(|s| !seen.insert(s)) {
            return Err(Error::invalid("duplicate requested selector"));
        }
        for id in &requested_selectors {
            if !used
                .iter()
                .any(|d| matches!(d,ReadDependency::SourceSelector{descriptor,..}if descriptor==id))
            {
                return Err(Error::invalid("requested selector missing dependency"));
            }
        }
        Ok(Self {
            snapshot,
            used,
            requested_selectors,
        })
    }
    pub fn snapshot(&self) -> &SnapshotRef {
        &self.snapshot
    }
    pub fn used(&self) -> &[ReadDependency] {
        &self.used
    }
    pub fn requested_selectors(&self) -> &[ResourceId] {
        &self.requested_selectors
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedLanding(V);
impl RecordedLanding {
    pub fn from_value(v: &V) -> Result<Self> {
        crate::projection::validate_landing(v)?;
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionCallSummary {
    manifest: FunctionManifest,
    input_hashes: Vec<ContentHash>,
    output_hashes: Vec<ContentHash>,
}
impl FunctionCallSummary {
    pub fn new(
        manifest: FunctionManifest,
        input_hashes: Vec<ContentHash>,
        output_hashes: Vec<ContentHash>,
    ) -> Result<Self> {
        if input_hashes.len() != output_hashes.len() {
            return Err(Error::invalid("incomplete function call summary"));
        }
        Ok(Self {
            manifest,
            input_hashes,
            output_hashes,
        })
    }
    pub fn roots(&self) -> Result<(FunctionRootProjection, FunctionRootProjection)> {
        Ok((
            FunctionRootProjection::new(false, &self.manifest, &self.input_hashes)?,
            FunctionRootProjection::new(true, &self.manifest, &self.output_hashes)?,
        ))
    }
    pub fn manifest(&self) -> &FunctionManifest {
        &self.manifest
    }
    pub fn input_hashes(&self) -> &[ContentHash] {
        &self.input_hashes
    }
    pub fn output_hashes(&self) -> &[ContentHash] {
        &self.output_hashes
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionRun {
    id: RunId,
    query: ArtifactRef,
    profile: Option<ArtifactRef>,
    config: ArtifactRef,
    engine: EngineIdentity,
    plan_hash: ContentHash,
    response_hash: ContentHash,
    snapshot: SnapshotRef,
    as_of: Timestamp,
    landings: Vec<RecordedLanding>,
    functions: Vec<FunctionCallSummary>,
    footprint: ReadFootprint,
}
/// Trusted record construction data. Required pins/engine are separate from plan semantics.
#[derive(Clone, Debug)]
pub struct ExecutionRunInput {
    pub schema: String,
    pub id: RunId,
    pub query: ArtifactRef,
    pub profile: Option<ArtifactRef>,
    pub config: ArtifactRef,
    pub engine: EngineIdentity,
    pub plan_hash: ContentHash,
    pub response_hash: ContentHash,
    pub snapshot: SnapshotRef,
    pub as_of: Timestamp,
    pub landings: Vec<RecordedLanding>,
    pub functions: Vec<FunctionCallSummary>,
    pub footprint: ReadFootprint,
}
impl ExecutionRun {
    pub fn new(i: ExecutionRunInput) -> Result<Self> {
        if i.schema != "ctxql-execution-run/v1" || i.footprint.snapshot() != &i.snapshot {
            return Err(Error::invalid("run schema/footprint pin"));
        }
        let mut manifests = std::collections::BTreeSet::new();
        for f in &i.functions {
            if !manifests.insert((
                f.manifest.name().clone(),
                f.manifest.version().clone(),
                f.manifest.hash().clone(),
            )) {
                return Err(Error::invalid("duplicate function manifest summary"));
            }
        }
        Ok(Self {
            id: i.id,
            query: i.query,
            profile: i.profile,
            config: i.config,
            engine: i.engine,
            plan_hash: i.plan_hash,
            response_hash: i.response_hash,
            snapshot: i.snapshot,
            as_of: i.as_of,
            landings: i.landings,
            functions: i.functions,
            footprint: i.footprint,
        })
    }
    pub fn id(&self) -> &RunId {
        &self.id
    }
    pub fn query(&self) -> &ArtifactRef {
        &self.query
    }
    pub fn profile(&self) -> Option<&ArtifactRef> {
        self.profile.as_ref()
    }
    pub fn config(&self) -> &ArtifactRef {
        &self.config
    }
    pub fn as_of(&self) -> Timestamp {
        self.as_of
    }
    pub fn engine(&self) -> &EngineIdentity {
        &self.engine
    }
    pub fn landings(&self) -> &[RecordedLanding] {
        &self.landings
    }
    pub fn functions(&self) -> &[FunctionCallSummary] {
        &self.functions
    }
    pub fn snapshot(&self) -> &SnapshotRef {
        &self.snapshot
    }
    pub fn footprint(&self) -> &ReadFootprint {
        &self.footprint
    }
    pub fn plan_hash(&self) -> &ContentHash {
        &self.plan_hash
    }
    pub fn response_hash(&self) -> &ContentHash {
        &self.response_hash
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssemblyInvocation(V);
impl AssemblyInvocation {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &[
                "schema",
                "invocation_id",
                "assembly",
                "inputs",
                "product_hash",
                "source_verifications",
            ],
            &[],
        )?;
        if v.field("schema")?.as_str()? != "ctxql-assembly-inputs/v1" {
            return Err(Error::invalid("assembly schema"));
        }
        InvocationId::new(v.field("invocation_id")?.as_str()?)?;
        crate::projection::validate_assembly(v.field("assembly")?)?;
        if *v.field("product_hash")? != V::Null {
            ContentHash::parse(v.field("product_hash")?.as_str()?)?;
        }
        let mut names = std::collections::BTreeSet::new();
        let inputs = v.field("inputs")?.as_array()?;
        if inputs.is_empty() {
            return Err(Error::invalid("assembly inputs"));
        }
        for i in inputs {
            i.closed(
                &[
                    "name",
                    "required",
                    "query",
                    "profile",
                    "plan_hash",
                    "run_id",
                    "response_hash",
                    "as_of",
                    "db_time",
                    "replay_verdict",
                    "notices",
                ],
                &[],
            )?;
            if !names.insert(ResourceId::new(i.field("name")?.as_str()?)?) {
                return Err(Error::invalid("duplicate input name"));
            }
            let required = i.field("required")?.as_bool()?;
            if *i.field("run_id")? == V::Null {
                if required {
                    return Err(Error::invalid("required input cannot be absent"));
                }
                for key in [
                    "query",
                    "profile",
                    "plan_hash",
                    "response_hash",
                    "as_of",
                    "db_time",
                    "replay_verdict",
                ] {
                    if *i.field(key)? != V::Null {
                        return Err(Error::invalid("absent input must have null references"));
                    }
                }
                if i.field("notices")?.as_array()?.is_empty() {
                    return Err(Error::invalid("absent input requires notice"));
                }
                for n in i.field("notices")?.as_array()? {
                    SemanticNotice::from_value(n)?;
                }
                continue;
            }
            for k in ["query", "profile"] {
                if *i.field(k)? != V::Null {
                    ArtifactRef::from_value(i.field(k)?)?;
                }
            }
            for k in ["plan_hash", "response_hash"] {
                ContentHash::parse(i.field(k)?.as_str()?)?;
            }
            RunId::new(i.field("run_id")?.as_str()?)?;
            Timestamp::parse(i.field("as_of")?.as_str()?)?;
            crate::snapshot::GraphPin::from_value(i.field("db_time")?)?;
            ReplayVerdict::parse(i.field("replay_verdict")?.as_str()?)?;
            for n in i.field("notices")?.as_array()? {
                SemanticNotice::from_value(n)?;
            }
        }
        for s in v.field("source_verifications")?.as_array()? {
            s.closed(&["source_id", "version", "fragment_id", "outcome"], &[])?;
            SourceId::new(s.field("source_id")?.as_str()?)?;
            if *s.field("version")? != V::Null {
                ContentHash::parse(s.field("version")?.as_str()?)?;
            }
            if *s.field("fragment_id")? != V::Null {
                FragmentId::new(s.field("fragment_id")?.as_str()?)?;
            }
            if !matches!(
                s.field("outcome")?.as_str()?,
                "verified" | "unverifiable" | "missing" | "changed" | "denied" | "not_requested"
            ) {
                return Err(Error::invalid("verification outcome"));
            }
        }
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
    pub fn validate_slots(&self, slots: &[AssemblySlot]) -> Result<()> {
        let inputs = self.0.field("inputs")?.as_array()?;
        let mut seen = std::collections::BTreeSet::new();
        for slot in slots {
            if !seen.insert(slot.name.as_str()) {
                return Err(Error::invalid("duplicate assembly slot"));
            }
            if slot.required
                && !inputs
                    .iter()
                    .any(|i| i.field("name").and_then(V::as_str) == Ok(slot.name.as_str()))
            {
                return Err(Error::invalid("missing required input"));
            }
        }
        for input in inputs {
            let slot = slots
                .iter()
                .find(|s| input.field("name").and_then(V::as_str) == Ok(s.name.as_str()))
                .ok_or_else(|| Error::invalid("unknown input slot"))?;
            if input.field("required")?.as_bool()? != slot.required
                || slot.required && *input.field("run_id")? == V::Null
            {
                return Err(Error::invalid(
                    "input required flag conflicts with manifest",
                ));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssemblySlot {
    pub name: ResourceId,
    pub required: bool,
    pub required_sections: crate::projection::ReturnSelection,
    pub capabilities: Vec<Iri>,
}

fn run_value(r: &ExecutionRun) -> V {
    use crate::value::obj;
    let dependencies = r
        .footprint()
        .used()
        .iter()
        .map(|d| {
            let (kind, value) = match d {
                ReadDependency::Claim(id) => ("claim", V::string(id.as_str())),
                ReadDependency::Lifecycle(id) => ("lifecycle", V::string(id.as_str())),
                ReadDependency::Resource(id) => ("resource", V::string(id.as_str())),
                ReadDependency::Fact {
                    resource,
                    predicate,
                } => (
                    "fact",
                    obj([
                        ("resource", V::string(resource.as_str())),
                        ("predicate", V::string(predicate.as_str())),
                    ]),
                ),
                ReadDependency::NegativeLookup { descriptor } => {
                    ("negative", V::string(descriptor.as_str()))
                }
                ReadDependency::Artifact(a) => ("artifact", a.projection()),
                ReadDependency::SourceSelector {
                    descriptor,
                    source,
                    version,
                } => (
                    "selector",
                    obj([
                        ("descriptor", V::string(descriptor.as_str())),
                        ("source", V::string(source.as_str())),
                        ("version", V::string(version.as_str())),
                    ]),
                ),
                ReadDependency::OrderingDescriptor(id) => ("ordering", V::string(id.as_str())),
            };
            obj([("kind", V::string(kind)), ("value", value)])
        })
        .collect();
    obj([
        ("schema", V::string("ctxql-execution-run/v1")),
        ("id", V::string(r.id().as_str())),
        ("query", r.query().projection()),
        (
            "profile",
            r.profile().map_or(V::Null, ArtifactRef::projection),
        ),
        ("config", r.config().projection()),
        ("engine", r.engine().projection()),
        ("plan_hash", V::string(r.plan_hash().as_str())),
        ("response_hash", V::string(r.response_hash().as_str())),
        (
            "snapshot",
            crate::record_codec::snapshot_value(r.snapshot()),
        ),
        ("as_of", V::string(r.as_of().canonical())),
        (
            "landings",
            V::Array(
                r.landings()
                    .iter()
                    .map(RecordedLanding::projection)
                    .collect(),
            ),
        ),
        (
            "functions",
            V::Array(
                r.functions()
                    .iter()
                    .map(|f| {
                        obj([
                            ("name", V::string(f.manifest().name().as_str())),
                            ("version", V::string(f.manifest().version().as_str())),
                            ("hash", V::string(f.manifest().hash().as_str())),
                            ("content", f.manifest().content().clone()),
                            (
                                "inputs",
                                V::Array(
                                    f.input_hashes()
                                        .iter()
                                        .map(|h| V::string(h.as_str()))
                                        .collect(),
                                ),
                            ),
                            (
                                "outputs",
                                V::Array(
                                    f.output_hashes()
                                        .iter()
                                        .map(|h| V::string(h.as_str()))
                                        .collect(),
                                ),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("footprint", V::Array(dependencies)),
        (
            "requested_selectors",
            V::Array(
                r.footprint()
                    .requested_selectors()
                    .iter()
                    .map(|id| V::string(id.as_str()))
                    .collect(),
            ),
        ),
    ])
}

impl ExecutionRun {
    /// Lossless v1 summary data, not a canonical semantic domain or replay seal.
    pub fn projection(&self) -> V {
        run_value(self)
    }
    pub fn bytes(&self, limits: crate::Limits) -> Result<Vec<u8>> {
        self.projection().canonical_bytes(limits)
    }
    pub fn read(bytes: &[u8], limits: crate::Limits) -> Result<Self> {
        Self::from_value(&V::parse(bytes, limits)?, limits)
    }
    pub fn from_value(v: &V, limits: crate::Limits) -> Result<Self> {
        v.canonical_bytes(limits)?;
        v.closed(
            &[
                "schema",
                "id",
                "query",
                "profile",
                "config",
                "engine",
                "plan_hash",
                "response_hash",
                "snapshot",
                "as_of",
                "landings",
                "functions",
                "footprint",
                "requested_selectors",
            ],
            &[],
        )?;
        let snapshot = crate::record_codec::snapshot_from_value(v.field("snapshot")?, limits)?;
        let e = v.field("engine")?;
        e.closed(&["implementation", "version", "build"], &[])?;
        let functions = v
            .field("functions")?
            .as_array()?
            .iter()
            .map(|f| {
                f.closed(
                    &["name", "version", "hash", "content", "inputs", "outputs"],
                    &[],
                )?;
                let hashes = |key| {
                    f.field(key)?
                        .as_array()?
                        .iter()
                        .map(|h| ContentHash::parse(h.as_str()?))
                        .collect::<Result<Vec<_>>>()
                };
                FunctionCallSummary::new(
                    FunctionManifest::from_retained_summary(
                        ResourceId::new(f.field("name")?.as_str()?)?,
                        VersionId::new(f.field("version")?.as_str()?)?,
                        ContentHash::parse(f.field("hash")?.as_str()?)?,
                        f.field("content")?.clone(),
                        limits,
                    )?,
                    hashes("inputs")?,
                    hashes("outputs")?,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let used = v
            .field("footprint")?
            .as_array()?
            .iter()
            .map(|d| {
                d.closed(&["kind", "value"], &[])?;
                let x = d.field("value")?;
                Ok(match d.field("kind")?.as_str()? {
                    "claim" => ReadDependency::Claim(ClaimId::new(x.as_str()?)?),
                    "lifecycle" => ReadDependency::Lifecycle(ClaimId::new(x.as_str()?)?),
                    "resource" => ReadDependency::Resource(ResourceId::new(x.as_str()?)?),
                    "ordering" => ReadDependency::OrderingDescriptor(ResourceId::new(x.as_str()?)?),
                    "negative" => ReadDependency::NegativeLookup {
                        descriptor: ResourceId::new(x.as_str()?)?,
                    },
                    "artifact" => ReadDependency::Artifact(ArtifactRef::from_value(x)?),
                    "fact" => {
                        x.closed(&["resource", "predicate"], &[])?;
                        ReadDependency::Fact {
                            resource: ResourceId::new(x.field("resource")?.as_str()?)?,
                            predicate: Iri::new(x.field("predicate")?.as_str()?)?,
                        }
                    }
                    "selector" => {
                        x.closed(&["descriptor", "source", "version"], &[])?;
                        ReadDependency::SourceSelector {
                            descriptor: ResourceId::new(x.field("descriptor")?.as_str()?)?,
                            source: SourceId::new(x.field("source")?.as_str()?)?,
                            version: ContentHash::parse(x.field("version")?.as_str()?)?,
                        }
                    }
                    _ => return Err(Error::invalid("read dependency kind")),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let requested = v
            .field("requested_selectors")?
            .as_array()?
            .iter()
            .map(|s| ResourceId::new(s.as_str()?))
            .collect::<Result<Vec<_>>>()?;
        Self::new(ExecutionRunInput {
            schema: v.field("schema")?.as_str()?.into(),
            id: RunId::new(v.field("id")?.as_str()?)?,
            query: ArtifactRef::from_value(v.field("query")?)?,
            profile: if *v.field("profile")? == V::Null {
                None
            } else {
                Some(ArtifactRef::from_value(v.field("profile")?)?)
            },
            config: ArtifactRef::from_value(v.field("config")?)?,
            engine: EngineIdentity::new(
                Iri::new(e.field("implementation")?.as_str()?)?,
                VersionId::new(e.field("version")?.as_str()?)?,
                ContentHash::parse(e.field("build")?.as_str()?)?,
            ),
            plan_hash: ContentHash::parse(v.field("plan_hash")?.as_str()?)?,
            response_hash: ContentHash::parse(v.field("response_hash")?.as_str()?)?,
            as_of: Timestamp::parse(v.field("as_of")?.as_str()?)?,
            landings: v
                .field("landings")?
                .as_array()?
                .iter()
                .map(RecordedLanding::from_value)
                .collect::<Result<_>>()?,
            functions,
            footprint: ReadFootprint::new(
                "ctxql-read-footprint/v1",
                snapshot.clone(),
                used,
                requested,
            )?,
            snapshot,
        })
    }
}

/// Immutable legacy summary identity. No owner, authorization or v2 seal is implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreSummaryKey(RunId);
impl CoreSummaryKey {
    pub fn new(id: RunId) -> Self {
        Self(id)
    }
    pub fn descriptor_id(&self) -> Result<ResourceId> {
        ResourceId::new(format!(
            "https://ctxql.org/legacy-runs/v1/{}",
            ContentHash::of_bytes(self.0.as_str().as_bytes()).as_str()
        ))
    }
    pub fn to_record(
        &self,
        run: &ExecutionRun,
        limits: crate::Limits,
    ) -> Result<crate::admission::ExportRecord> {
        use crate::admission::*;
        if run.id() != &self.0 {
            return Err(Error::invalid("summary key/run mismatch"));
        }
        let payload = run.projection();
        let envelope = crate::value::obj([
            ("schema", V::string("ctxql-legacy-run-summary/v1")),
            (
                "hash",
                V::string(ContentHash::of_bytes(&run.bytes(limits)?).as_str()),
            ),
            ("summary", payload),
        ]);
        let text = String::from_utf8(envelope.canonical_bytes(limits)?)
            .map_err(|_| Error::invalid("summary UTF-8"))?;
        Ok(ExportRecord::Resource(DependencyRecord::new(
            "ctxql-resource/v1",
            self.descriptor_id()?,
            ResourceKind::RunDescriptor,
            vec![Fact::new(
                Iri::new(LEGACY_RUN_PAYLOAD)?,
                FactTerm::Literal(crate::claim::TypedLiteral::new(
                    Iri::new("http://www.w3.org/2001/XMLSchema#string")?,
                    V::string(text),
                    None,
                )?),
            )],
        )?))
    }
    pub fn from_record(
        &self,
        record: &crate::admission::ExportRecord,
        limits: crate::Limits,
    ) -> Result<ExecutionRun> {
        use crate::admission::*;
        let ExportRecord::Resource(r) = record else {
            return Err(Error::invalid("summary resource"));
        };
        if r.id() != &self.descriptor_id()?
            || r.kind() != ResourceKind::RunDescriptor
            || r.facts().len() != 1
            || r.facts()[0].predicate().as_str() != LEGACY_RUN_PAYLOAD
        {
            return Err(Error::invalid("summary descriptor"));
        }
        let FactTerm::Literal(l) = r.facts()[0].term() else {
            return Err(Error::invalid("summary literal"));
        };
        let p = l.projection();
        if p.field("datatype")?.as_str()? != "http://www.w3.org/2001/XMLSchema#string"
            || *p.field("language")? != V::Null
        {
            return Err(Error::invalid("summary literal type"));
        }
        let bytes = p.field("value")?.as_str()?.as_bytes();
        let v = V::parse(bytes, limits)?;
        v.closed(&["schema", "hash", "summary"], &[])?;
        if v.field("schema")?.as_str()? != "ctxql-legacy-run-summary/v1" {
            return Err(Error::invalid("summary schema"));
        }
        let run = ExecutionRun::from_value(v.field("summary")?, limits)?;
        if ContentHash::parse(v.field("hash")?.as_str()?)?
            != ContentHash::of_bytes(&run.bytes(limits)?)
            || run.id() != &self.0
            || v.canonical_bytes(limits)? != bytes
        {
            return Err(Error::invalid("summary integrity/identity"));
        }
        Ok(run)
    }
}
pub const LEGACY_RUN_PAYLOAD: &str = "https://ctxql.org/legacy-runs/v1/payload";
