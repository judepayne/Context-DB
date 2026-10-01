//! Portable v3 evidence. Valid bytes are not execution or release authority.
use crate::admission::{DependencyRecord, ExportRecord, Fact, FactTerm, ResourceKind};
use crate::artifact::{ArtifactRef, FunctionManifest, PublishedArtifact};
use crate::claim::TypedLiteral;
use crate::id::*;
use crate::recording::{ReplayData, ReplayDataInput, RUN_PAYLOAD};
use crate::storage_origin::INTERNAL_PREFIX;
use crate::value::obj;
use crate::{CanonicalValue as V, Error, Limits, Result};
use std::collections::{BTreeMap, BTreeSet};

pub const REPLAY_SCHEMA: &str = "ctxql-replay-data/v3";
pub const RUN_SCHEMA: &str = "ctxql-recorded-run/v3";
pub const REPLAY_ABI: &str = "ctxql-execution/v3";
pub const NUMERIC_ABI: &str = "ctxql-predicate-numeric/v2";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const VIEW: &str = "https://ns.flur.ee/db#view";
const CALLBACK_PREFIX: &str = "urn:ctxql:function-callback:v1:";
const ACTION_PREFIX: &str = "urn:ctxql:function-action:v1:";

/// Operational callback identity shared by the trusted runtime and v3 decoder.
pub fn function_callback_id(
    lane: &LaneIdentityV3,
    ordinal: u64,
    limits: Limits,
) -> Result<ResourceId> {
    let value = obj([
        ("lane", lane.projection()),
        ("ordinal", V::integer(ordinal)),
    ]);
    ResourceId::new(format!(
        "{CALLBACK_PREFIX}{}",
        ContentHash::of_bytes(&value.canonical_bytes(limits)?).as_str()
    ))
}

pub fn function_action_id(callback: &ResourceId, attempt: u8, kind: &str) -> Result<ResourceId> {
    if !matches!(kind, "enqueue" | "consume")
        || !callback.as_str().starts_with(CALLBACK_PREFIX)
        || attempt == 0
    {
        return Err(Error::invalid("function action identity"));
    }
    ResourceId::new(format!(
        "{ACTION_PREFIX}{kind}:{attempt}:{}",
        callback.as_str().trim_start_matches(CALLBACK_PREFIX)
    ))
}

fn parse_function_action(action: &str) -> Result<Option<(String, u8, ContentHash)>> {
    let Some(rest) = action.strip_prefix(ACTION_PREFIX) else {
        return Ok(None);
    };
    let mut parts = rest.split(':');
    let kind = parts
        .next()
        .ok_or_else(|| Error::invalid("function action identity"))?;
    let attempt = parts
        .next()
        .ok_or_else(|| Error::invalid("function action identity"))?
        .parse::<u8>()
        .map_err(|_| Error::invalid("function action identity"))?;
    let algorithm = parts
        .next()
        .ok_or_else(|| Error::invalid("function action identity"))?;
    let digest = parts
        .next()
        .ok_or_else(|| Error::invalid("function action identity"))?;
    if parts.next().is_some() || !matches!(kind, "enqueue" | "consume") || attempt == 0 {
        return Err(Error::invalid("function action identity"));
    }
    Ok(Some((
        kind.to_owned(),
        attempt,
        ContentHash::parse(format!("{algorithm}:{digest}"))?,
    )))
}

pub fn function_action_callback(action: &ResourceId) -> Result<Option<ResourceId>> {
    parse_function_action(action.as_str())?
        .map(|(_, _, callback)| ResourceId::new(format!("{CALLBACK_PREFIX}{}", callback.as_str())))
        .transpose()
}

/// Canonical, bounded requirements checked for one actual guarded action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequirementsV3 {
    wire: V,
    hash: ContentHash,
}
impl AuthorizationRequirementsV3 {
    pub fn new(
        mut facts: Vec<(ResourceId, Iri)>,
        mut invocations: Vec<(ArtifactRef, ResourceId)>,
        limits: Limits,
    ) -> Result<Self> {
        facts.sort();
        invocations.sort_by(|(a_manifest, a_provider), (b_manifest, b_provider)| {
            (
                a_manifest.iri(),
                a_manifest.version(),
                a_manifest.hash(),
                a_provider,
            )
                .cmp(&(
                    b_manifest.iri(),
                    b_manifest.version(),
                    b_manifest.hash(),
                    b_provider,
                ))
        });
        let wire = obj([
            (
                "facts",
                V::Array(
                    facts
                        .into_iter()
                        .map(|(resource, predicate)| {
                            obj([
                                ("resource", V::string(resource.as_str())),
                                ("predicate", V::string(predicate.as_str())),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "invocations",
                V::Array(
                    invocations
                        .into_iter()
                        .map(|(manifest, provider)| {
                            obj([
                                ("manifest", manifest.projection()),
                                ("provider", V::string(provider.as_str())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]);
        Self::from_value(&wire, limits)
    }
    pub fn from_value(v: &V, limits: Limits) -> Result<Self> {
        v.closed(&["facts", "invocations"], &[])?;
        let mut previous_fact = None;
        for fact in v.field("facts")?.as_array()? {
            fact.closed(&["resource", "predicate"], &[])?;
            let key = (
                ResourceId::new(fact.field("resource")?.as_str()?)?,
                Iri::new(fact.field("predicate")?.as_str()?)?,
            );
            if previous_fact.as_ref().is_some_and(|old| old >= &key) {
                return Err(Error::invalid("requirement fact order/duplicate"));
            }
            previous_fact = Some(key);
        }
        let mut previous_invocation = None;
        for invocation in v.field("invocations")?.as_array()? {
            invocation.closed(&["manifest", "provider"], &[])?;
            let manifest = ArtifactRef::from_value(invocation.field("manifest")?)?;
            let provider = ResourceId::new(invocation.field("provider")?.as_str()?)?;
            let key = (
                manifest.iri().as_str().to_owned(),
                manifest.version().as_str().to_owned(),
                manifest.hash().as_str().to_owned(),
                provider.as_str().to_owned(),
            );
            if previous_invocation.as_ref().is_some_and(|old| old >= &key) {
                return Err(Error::invalid("requirement invocation order/duplicate"));
            }
            previous_invocation = Some(key);
        }
        let bytes = v.canonical_bytes(limits)?;
        Ok(Self {
            wire: v.clone(),
            hash: ContentHash::of_bytes(&bytes),
        })
    }
    pub fn projection(&self) -> V {
        self.wire.clone()
    }
    pub fn hash(&self) -> &ContentHash {
        &self.hash
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseEvidenceV3 {
    wire: V,
}
impl ReleaseEvidenceV3 {
    pub fn new(
        action: ResourceId,
        requirements: AuthorizationRequirementsV3,
        authorization_head: crate::snapshot::SnapshotRef,
        allowed: bool,
        limits: Limits,
    ) -> Result<Self> {
        Self::from_value(
            &obj([
                ("action", V::string(action.as_str())),
                ("requirements", requirements.projection()),
                ("requirements_hash", V::string(requirements.hash().as_str())),
                (
                    "authorization_head",
                    crate::record_codec::snapshot_value(&authorization_head),
                ),
                ("allowed", V::Bool(allowed)),
            ]),
            limits,
        )
    }
    pub fn from_value(v: &V, limits: Limits) -> Result<Self> {
        v.closed(
            &[
                "action",
                "requirements",
                "requirements_hash",
                "authorization_head",
                "allowed",
            ],
            &[],
        )?;
        ResourceId::new(v.field("action")?.as_str()?)?;
        let requirements =
            AuthorizationRequirementsV3::from_value(v.field("requirements")?, limits)?;
        if hash(v.field("requirements_hash")?)? != *requirements.hash() {
            return Err(Error::invalid("release requirements hash"));
        }
        crate::record_codec::snapshot_from_value(v.field("authorization_head")?, limits)?;
        v.field("allowed")?.as_bool()?;
        bounded(v, limits)?;
        Ok(Self { wire: v.clone() })
    }
    pub fn projection(&self) -> V {
        self.wire.clone()
    }
    pub fn requirements(&self, limits: Limits) -> Result<AuthorizationRequirementsV3> {
        AuthorizationRequirementsV3::from_value(self.wire.field("requirements")?, limits)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LanePhaseV3 {
    Preparation,
    Walk,
    Filter,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct LaneIdentityV3 {
    pub phase: LanePhaseV3,
    pub evaluation: u64,
    pub predicate: u64,
    pub attempt: u64,
    pub ordinal: u64,
}
impl LaneIdentityV3 {
    pub fn projection(self) -> V {
        obj([
            (
                "phase",
                V::string(match self.phase {
                    LanePhaseV3::Preparation => "preparation",
                    LanePhaseV3::Walk => "walk",
                    LanePhaseV3::Filter => "filter",
                }),
            ),
            ("evaluation", V::integer(self.evaluation)),
            ("predicate", V::integer(self.predicate)),
            ("attempt", V::integer(self.attempt)),
            ("ordinal", V::integer(self.ordinal)),
        ])
    }
    pub fn from_value(v: &V) -> Result<Self> {
        let (phase, evaluation, predicate, attempt, ordinal) = lane_identity(v)?;
        Ok(Self {
            phase: match phase {
                0 => LanePhaseV3::Preparation,
                1 => LanePhaseV3::Walk,
                _ => LanePhaseV3::Filter,
            },
            evaluation,
            predicate,
            attempt,
            ordinal,
        })
    }
}
/// Encode an actual read occurrence; repeated observations keep distinct ordinals.
pub fn lane_read(ordinal: u64, read: &crate::recording::ReadObservation) -> V {
    obj([
        ("ordinal", V::integer(ordinal)),
        (
            "observation",
            obj([
                ("operation", V::string(read.operation.as_str())),
                ("key", read.key.clone()),
                ("result_hash", V::string(read.result_hash.as_str())),
            ]),
        ),
    ])
}

/// All arrays are in logical order. See the closed wire vocabulary in the contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayDataV3Input {
    pub base: ReplayDataInput,
    pub lanes: Vec<V>,
    pub expected_lanes: Vec<V>,
    pub functions: Vec<V>,
    pub prepared: Vec<V>,
    pub release_evidence: Vec<V>,
    pub executor: crate::recording::RecordingEngine,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayDataV3 {
    base: ReplayData,
    wire: V,
}
fn bounded(v: &V, limits: Limits) -> Result<()> {
    v.canonical_bytes(limits).map(|_| ())
}
fn hash(v: &V) -> Result<ContentHash> {
    ContentHash::parse(v.as_str()?)
}
fn unique(values: &[V], limits: Limits) -> Result<()> {
    let mut seen = BTreeSet::new();
    for v in values {
        if !seen.insert(v.canonical_bytes(limits)?) {
            return Err(Error::invalid("duplicate recording evidence"));
        }
    }
    Ok(())
}
fn recording_footprint_hash(v: &V, limits: Limits) -> Result<ContentHash> {
    let value = obj([
        ("snapshot", v.field("snapshot")?.clone()),
        ("as_of", v.field("as_of")?.clone()),
        ("reads", v.field("reads")?.clone()),
        ("policy", v.field("policy")?.clone()),
        ("scopes", v.field("scopes")?.clone()),
        ("prepared", v.field("prepared")?.clone()),
        ("functions", v.field("functions")?.clone()),
    ]);
    Ok(ContentHash::of_bytes(&value.canonical_bytes(limits)?))
}
fn self_invocations(v: &V) -> Result<BTreeSet<(String, String, String, String)>> {
    let mut out = BTreeSet::new();
    for function in v.field("functions")?.as_array()? {
        let manifest = ArtifactRef::from_value(function.field("manifest")?)?;
        for destination in function.field("destinations")?.as_array()? {
            out.insert((
                manifest.iri().as_str().to_owned(),
                manifest.version().as_str().to_owned(),
                manifest.hash().as_str().to_owned(),
                destination.as_str()?.to_owned(),
            ));
        }
    }
    Ok(out)
}
fn lane_identity(v: &V) -> Result<(u64, u64, u64, u64, u64)> {
    v.closed(
        &["phase", "evaluation", "predicate", "attempt", "ordinal"],
        &[],
    )?;
    let phase = match v.field("phase")?.as_str()? {
        "preparation" => 0,
        "walk" => 1,
        "filter" => 2,
        _ => return Err(Error::invalid("lane phase")),
    };
    Ok((
        phase,
        v.field("evaluation")?.u64()?,
        v.field("predicate")?.u64()?,
        v.field("attempt")?.u64()?,
        v.field("ordinal")?.u64()?,
    ))
}
impl ReplayDataV3 {
    pub fn new(input: ReplayDataV3Input, limits: Limits) -> Result<Self> {
        // V2 is only a shared vocabulary validator; never accept its wire schema as V3.
        let base = ReplayData::new(input.base, limits)?;
        let V::Object(mut wire) = base.projection() else {
            unreachable!()
        };
        wire.insert("schema".into(), V::string(REPLAY_SCHEMA));
        wire.insert("numeric_abi".into(), V::string(NUMERIC_ABI));
        wire.insert(
            "executor".into(),
            obj([
                ("name", V::string(input.executor.name.as_str())),
                ("version", V::string(input.executor.version.as_str())),
                ("build", V::string(input.executor.build.as_str())),
            ]),
        );
        for (key, values) in [
            ("lanes", input.lanes),
            ("expected_lanes", input.expected_lanes),
            ("functions", input.functions),
            ("prepared", input.prepared),
            ("release_evidence", input.release_evidence),
        ] {
            wire.insert(key.into(), V::Array(values));
        }
        let footprint = recording_footprint_hash(&V::Object(wire.clone()), limits)?;
        wire.insert("final_footprint".into(), V::string(footprint.as_str()));
        Self::from_value(&V::Object(wire), limits)
    }
    pub fn from_value(v: &V, limits: Limits) -> Result<Self> {
        bounded(v, limits)?;
        if v.field("schema")?.as_str()? != REPLAY_SCHEMA
            || v.field("numeric_abi")?.as_str()? != NUMERIC_ABI
            || v.field("replay_abi")?.as_str()? != REPLAY_ABI
        {
            return Err(Error::invalid("v3 execution schema/ABI"));
        }
        let mut base = v.as_object()?.clone();
        for key in [
            "numeric_abi",
            "executor",
            "lanes",
            "expected_lanes",
            "prepared",
            "release_evidence",
            "final_footprint",
        ] {
            base.remove(key)
                .ok_or_else(|| Error::invalid("missing v3 field"))?;
        }
        base.insert("schema".into(), V::string(crate::recording::REPLAY_SCHEMA));
        base.insert("functions".into(), V::Array(vec![]));
        let base = ReplayData::from_value(&V::Object(base), limits)?;
        let executor = v.field("executor")?;
        executor.closed(&["name", "version", "build"], &[])?;
        ResourceId::new(executor.field("name")?.as_str()?)?;
        VersionId::new(executor.field("version")?.as_str()?)?;
        hash(executor.field("build")?)?;
        let base_wire = base.projection();
        let mut observations = BTreeMap::new();
        let mut assigned = BTreeSet::new();
        let mut call_counts = BTreeMap::<String, u64>::new();
        for key in ["reads", "policy", "scopes"] {
            let mut entries = BTreeSet::new();
            for entry in base_wire.field(key)?.as_array()? {
                if !entries.insert(entry.canonical_bytes(limits)?) {
                    return Err(Error::invalid("duplicate base observation"));
                }
            }
            observations.insert(key, entries);
        }
        let expected = v.field("expected_lanes")?.as_array()?;
        let lanes = v.field("lanes")?.as_array()?;
        if lanes.len() != expected.len() || lanes.is_empty() {
            return Err(Error::invalid("missing/extra lanes"));
        }
        if lane_identity(&expected[0])?.0 != 0 {
            return Err(Error::invalid("missing preparation lane"));
        }
        let mut previous = None;
        for (lane, identity) in lanes.iter().zip(expected) {
            let order = lane_identity(identity)?;
            if previous.is_some_and(|old| old >= order) {
                return Err(Error::invalid("lane order/duplicate"));
            }
            previous = Some(order);
            lane.closed(
                &[
                    "identity",
                    "closed",
                    "outcome",
                    "reads",
                    "policy",
                    "scopes",
                    "function_counts",
                ],
                &[],
            )?;
            if lane.field("identity")? != identity || !lane.field("closed")?.as_bool()? {
                return Err(Error::invalid("lane identity/closure"));
            }
            if !matches!(
                lane.field("outcome")?.as_str()?,
                "empty" | "accepted" | "rejected" | "cap_denied"
            ) {
                return Err(Error::invalid("lane outcome"));
            }
            for key in ["reads", "policy", "scopes"] {
                let entries = lane.field(key)?.as_array()?;
                unique(entries, limits)?;
                for (ordinal, entry) in entries.iter().enumerate() {
                    let observation = if key == "reads" {
                        entry.closed(&["ordinal", "observation"], &[])?;
                        if entry.field("ordinal")?.u64()?
                            != u64::try_from(ordinal).map_err(|_| Error::limit())?
                        {
                            return Err(Error::invalid("local read ordinal"));
                        }
                        entry.field("observation")?
                    } else {
                        entry
                    };
                    let bytes = observation.canonical_bytes(limits)?;
                    if !observations[key].contains(&bytes) {
                        return Err(Error::invalid("lane evidence outside base footprint"));
                    }
                    assigned.insert((key, bytes));
                }
            }
            let mut lane_functions = BTreeSet::new();
            for call in lane.field("function_counts")?.as_array()? {
                call.closed(&["count", "name"], &[])?;
                let name = call.field("name")?.as_str()?;
                ResourceId::new(name)?;
                if call.field("count")?.u64()? == 0 || !lane_functions.insert(name) {
                    return Err(Error::invalid("lane function count/duplicate"));
                }
                let total = call_counts.entry(name.to_owned()).or_default();
                *total = total
                    .checked_add(call.field("count")?.u64()?)
                    .ok_or_else(Error::limit)?;
            }
        }
        // Every base observation, including negative/empty reads, must have a lane.
        for (key, entries) in &observations {
            for bytes in entries {
                if !assigned.contains(&(*key, bytes.clone())) {
                    return Err(Error::invalid("unassigned footprint observation"));
                }
            }
        }
        let registrations = base
            .data()
            .plan
            .payload()
            .field("config")?
            .field("external_functions")?
            .as_object()?;
        let mut names = BTreeSet::new();
        let mut previous_name = None;
        for f in v.field("functions")?.as_array()? {
            f.closed(
                &[
                    "name",
                    "manifest",
                    "source",
                    "deterministic",
                    "replay",
                    "count",
                    "input_root",
                    "output_root",
                    "destinations",
                ],
                &[],
            )?;
            let name = f.field("name")?.as_str()?;
            if previous_name.is_some_and(|old| old >= name) {
                return Err(Error::invalid("function order"));
            }
            previous_name = Some(name);
            if !names.insert(name) {
                return Err(Error::invalid("duplicate function"));
            }
            let reference = ArtifactRef::from_value(f.field("manifest")?)?;
            let source = PublishedArtifact::new(
                reference.clone(),
                f.field("source")?.as_str()?.as_bytes().to_vec(),
                limits,
            )?;
            FunctionManifest::from_published(ResourceId::new(name)?, &source, limits)?;
            let registration = registrations
                .get(name)
                .ok_or_else(|| Error::invalid("unregistered function"))?;
            if registration.field("version")?.as_str()? != reference.version().as_str()
                || registration.field("manifest_uri")?.as_str()? != reference.iri().as_str()
                || registration.field("manifest_hash")?.as_str()? != reference.hash().as_str()
                || registration.field("deterministic")? != f.field("deterministic")?
            {
                return Err(Error::invalid("exact manifest registration"));
            }
            f.field("deterministic")?.as_bool()?;
            if !matches!(f.field("replay")?.as_str()?, "exact" | "unavailable") {
                return Err(Error::invalid("function replay declaration"));
            }
            if f.field("replay")?.as_str()? == "exact" && !f.field("deterministic")?.as_bool()? {
                return Err(Error::invalid("nondeterministic exact replay"));
            }
            let count = f.field("count")?.u64()?;
            let actual = call_counts.get(name).copied().unwrap_or(0);
            if actual != count || count == 0 {
                return Err(Error::invalid("function call count"));
            }
            for key in ["input_root", "output_root"] {
                hash(f.field(key)?)?;
            }
            let mut previous_destination = None;
            for destination in f.field("destinations")?.as_array()? {
                let destination = ResourceId::new(destination.as_str()?)?;
                if previous_destination
                    .as_ref()
                    .is_some_and(|old| old >= &destination)
                {
                    return Err(Error::invalid("function destination order/duplicate"));
                }
                previous_destination = Some(destination);
            }
            if f.field("destinations")?.as_array()?.is_empty() {
                return Err(Error::invalid("missing function destination"));
            }
        }
        for lane in lanes {
            for call in lane.field("function_counts")?.as_array()? {
                if !names.contains(call.field("name")?.as_str()?) {
                    return Err(Error::invalid("missing manifest"));
                }
            }
        }
        let mut prepared_ids = BTreeSet::new();
        for p in v.field("prepared")?.as_array()? {
            p.closed(
                &[
                    "identity",
                    "snapshot",
                    "as_of",
                    "selections",
                    "translator",
                    "reasoner",
                    "rules",
                    "dependencies",
                    "reads",
                ],
                &[],
            )?;
            ResourceId::new(p.field("identity")?.as_str()?)?;
            if !prepared_ids.insert(p.field("identity")?.as_str()?) {
                return Err(Error::invalid("duplicate prepared identity"));
            }
            for key in ["selections", "dependencies", "reads"] {
                unique(p.field(key)?.as_array()?, limits)?;
            }
            if p.field("snapshot")? != v.field("snapshot")?
                || p.field("as_of")? != v.field("as_of")?
            {
                return Err(Error::invalid("prepared source pin/cutoff"));
            }
            for key in ["translator", "reasoner", "rules"] {
                ArtifactRef::from_value(p.field(key)?)?;
            }
            for selection in p.field("selections")?.as_array()? {
                ArtifactRef::from_value(selection)?;
            }
            for d in p.field("dependencies")?.as_array()? {
                ResourceId::new(d.as_str()?)?;
            }
            for read in p.field("reads")?.as_array()? {
                if !observations["reads"].contains(&read.canonical_bytes(limits)?) {
                    return Err(Error::invalid("prepared read footprint"));
                }
            }
        }
        unique(v.field("prepared")?.as_array()?, limits)?;
        let footprint = recording_footprint_hash(v, limits)?;
        if hash(v.field("final_footprint")?)? != footprint {
            return Err(Error::invalid("final recording footprint binding"));
        }
        let allowed_facts = base
            .data()
            .policy
            .iter()
            .filter(|p| p.allowed)
            .map(|p| {
                (
                    p.resource.as_str().to_owned(),
                    p.predicate
                        .as_ref()
                        .map_or(VIEW, |predicate| predicate.as_str())
                        .to_owned(),
                )
            })
            .chain(
                base.data()
                    .scopes
                    .iter()
                    .map(|scope| (scope.as_str().to_owned(), VIEW.to_owned())),
            )
            .collect::<BTreeSet<_>>();
        let required_invocations = self_invocations(v)?;
        let mut evidenced_invocations = BTreeSet::new();
        let mut actions = BTreeSet::new();
        for e in v.field("release_evidence")?.as_array()? {
            let evidence = ReleaseEvidenceV3::from_value(e, limits)?;
            if !actions.insert(e.field("action")?.as_str()?) {
                return Err(Error::invalid("duplicate release action"));
            }
            let requirements = evidence.requirements(limits)?;
            for fact in requirements.projection().field("facts")?.as_array()? {
                let key = (
                    fact.field("resource")?.as_str()?.to_owned(),
                    fact.field("predicate")?.as_str()?.to_owned(),
                );
                if !allowed_facts.contains(&key) {
                    return Err(Error::invalid("release fact outside final footprint"));
                }
            }
            for invocation in requirements.projection().field("invocations")?.as_array()? {
                let manifest = ArtifactRef::from_value(invocation.field("manifest")?)?;
                let key = (
                    manifest.iri().as_str().to_owned(),
                    manifest.version().as_str().to_owned(),
                    manifest.hash().as_str().to_owned(),
                    invocation.field("provider")?.as_str()?.to_owned(),
                );
                if !required_invocations.contains(&key) {
                    return Err(Error::invalid("release invocation outside final footprint"));
                }
                if e.field("allowed")?.as_bool()? {
                    evidenced_invocations.insert(key);
                }
            }
        }
        if evidenced_invocations != required_invocations {
            return Err(Error::invalid("missing release invocation evidence"));
        }
        let replay = Self {
            base,
            wire: v.clone(),
        };
        replay.validate_release_actions(limits)?;
        Ok(replay)
    }
    pub fn data(&self) -> &ReplayDataInput {
        self.base.data()
    }
    /// Conservative complete recorded dependency footprint, excluding release heads.
    pub fn footprint_hash(&self, limits: Limits) -> Result<ContentHash> {
        let actual = recording_footprint_hash(&self.wire, limits)?;
        if hash(self.wire.field("final_footprint")?)? != actual {
            return Err(Error::invalid("final recording footprint binding"));
        }
        Ok(actual)
    }
    /// Exact durable manifest/destination bindings used for protected reopen/retry.
    pub fn original_invocations(&self) -> Result<Vec<(ArtifactRef, ResourceId)>> {
        let mut out = Vec::new();
        for function in self.wire.field("functions")?.as_array()? {
            let manifest = ArtifactRef::from_value(function.field("manifest")?)?;
            for destination in function.field("destinations")?.as_array()? {
                out.push((manifest.clone(), ResourceId::new(destination.as_str()?)?));
            }
        }
        Ok(out)
    }
    /// Complete original-positive authority encoded by this immutable recording.
    pub fn original_authorization_requirements(
        &self,
        limits: Limits,
    ) -> Result<AuthorizationRequirementsV3> {
        let facts = self
            .base
            .data()
            .policy
            .iter()
            .filter(|observation| observation.allowed)
            .map(|observation| {
                Ok((
                    observation.resource.clone(),
                    match &observation.predicate {
                        Some(predicate) => predicate.clone(),
                        None => Iri::http(VIEW)?,
                    },
                ))
            })
            .chain(
                self.base
                    .data()
                    .scopes
                    .iter()
                    .map(|scope| Ok((scope.clone(), Iri::http(VIEW)?))),
            )
            .collect::<Result<BTreeSet<_>>>()?;
        let mut invocations = BTreeMap::new();
        for (manifest, provider) in self.original_invocations()? {
            let key = (
                manifest.iri().as_str().to_owned(),
                manifest.version().as_str().to_owned(),
                manifest.hash().as_str().to_owned(),
                provider.as_str().to_owned(),
            );
            invocations.insert(key, (manifest, provider));
        }
        AuthorizationRequirementsV3::new(
            facts.into_iter().collect(),
            invocations.into_values().collect(),
            limits,
        )
    }
    pub fn release_evidence(&self, limits: Limits) -> Result<Vec<ReleaseEvidenceV3>> {
        self.wire
            .field("release_evidence")?
            .as_array()?
            .iter()
            .map(|value| ReleaseEvidenceV3::from_value(value, limits))
            .collect()
    }

    fn validate_release_actions(&self, limits: Limits) -> Result<()> {
        #[derive(Default)]
        struct Actions {
            enqueue: BTreeMap<u8, Vec<u8>>,
            consume: Option<(u8, Vec<u8>)>,
        }
        let projection = self.projection();
        let mut invocation_names = BTreeMap::<Vec<u8>, String>::new();
        for function in projection.field("functions")?.as_array()? {
            let manifest = function.field("manifest")?;
            for destination in function.field("destinations")?.as_array()? {
                let key = obj([
                    ("manifest", manifest.clone()),
                    ("provider", destination.clone()),
                ])
                .canonical_bytes(limits)?;
                if invocation_names
                    .insert(key, function.field("name")?.as_str()?.to_owned())
                    .is_some()
                {
                    return Err(Error::invalid("ambiguous function invocation binding"));
                }
            }
        }
        let mut expected = BTreeMap::<ContentHash, Vec<u8>>::new();
        let mut expected_counts = BTreeMap::<(Vec<u8>, String), u64>::new();
        for lane in projection.field("lanes")?.as_array()? {
            let identity = LaneIdentityV3::from_value(lane.field("identity")?)?;
            let lane_key = identity.projection().canonical_bytes(limits)?;
            let mut total = 0u64;
            for count in lane.field("function_counts")?.as_array()? {
                let value = count.field("count")?.u64()?;
                total = total.checked_add(value).ok_or_else(Error::limit)?;
                expected_counts.insert(
                    (lane_key.clone(), count.field("name")?.as_str()?.to_owned()),
                    value,
                );
            }
            for ordinal in 0..total {
                let callback = function_callback_id(&identity, ordinal, limits)?;
                let digest = callback
                    .as_str()
                    .strip_prefix(CALLBACK_PREFIX)
                    .ok_or_else(|| Error::invalid("function callback identity"))?;
                if expected
                    .insert(ContentHash::parse(digest)?, lane_key.clone())
                    .is_some()
                {
                    return Err(Error::invalid("duplicate function callback identity"));
                }
            }
        }
        let mut observed = BTreeMap::<ContentHash, Actions>::new();
        let mut non_callback = 0usize;
        for evidence in projection.field("release_evidence")?.as_array()? {
            let Some((kind, attempt, callback)) =
                parse_function_action(evidence.field("action")?.as_str()?)?
            else {
                non_callback = non_callback.checked_add(1).ok_or_else(Error::limit)?;
                continue;
            };
            if !expected.contains_key(&callback) || !evidence.field("allowed")?.as_bool()? {
                return Err(Error::invalid("unknown or denied function action"));
            }
            let invocations = evidence
                .field("requirements")?
                .field("invocations")?
                .as_array()?;
            if invocations.len() != 1 {
                return Err(Error::invalid("function action invocation cardinality"));
            }
            let invocation = invocations[0].canonical_bytes(limits)?;
            let actions = observed.entry(callback).or_default();
            match kind.as_str() {
                "enqueue" => {
                    if actions.enqueue.insert(attempt, invocation).is_some() {
                        return Err(Error::invalid("duplicate function enqueue attempt"));
                    }
                }
                "consume" => {
                    if actions.consume.replace((attempt, invocation)).is_some() {
                        return Err(Error::invalid("duplicate function consumption"));
                    }
                }
                _ => unreachable!(),
            }
        }
        if (!expected.is_empty() && non_callback > 1) || observed.len() != expected.len() {
            return Err(Error::invalid(
                "missing/extra function authorization action",
            ));
        }
        let mut actual_counts = BTreeMap::<(Vec<u8>, String), u64>::new();
        for (callback, actions) in observed {
            let (consume_attempt, invocation) = actions
                .consume
                .ok_or_else(|| Error::invalid("missing function consumption"))?;
            if actions.enqueue.len() != usize::from(consume_attempt)
                || !(1..=consume_attempt).all(|attempt| {
                    actions
                        .enqueue
                        .get(&attempt)
                        .is_some_and(|value| value == &invocation)
                })
            {
                return Err(Error::invalid("function enqueue/consume attempt sequence"));
            }
            let name = invocation_names
                .get(&invocation)
                .ok_or_else(|| Error::invalid("function action binding"))?
                .clone();
            let lane = expected
                .get(&callback)
                .ok_or_else(|| Error::invalid("function callback lane"))?
                .clone();
            let count = actual_counts.entry((lane, name)).or_default();
            *count = count.checked_add(1).ok_or_else(Error::limit)?;
        }
        if actual_counts != expected_counts {
            return Err(Error::invalid("function action/lane count correspondence"));
        }
        Ok(())
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
    /// Runtime replay compares the complete closed semantic trace; release heads are fresh.
    pub fn verify_semantics(&self, replay: &Self) -> Result<()> {
        let mut a = self.wire.as_object()?.clone();
        let mut b = replay.wire.as_object()?.clone();
        a.remove("release_evidence");
        b.remove("release_evidence");
        if a != b {
            return Err(Error::invalid("v3 replay divergence"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunEnvelopeV3 {
    id: RunId,
    owner: PrincipalId,
    operation_hash: ContentHash,
    replay: ReplayDataV3,
}
impl RunEnvelopeV3 {
    pub fn new(
        id: RunId,
        owner: PrincipalId,
        operation_hash: ContentHash,
        replay: ReplayDataV3,
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
    pub fn replay(&self) -> &ReplayDataV3 {
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
            ReplayDataV3::from_value(v.field("replay")?, limits)?,
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

/// Distinct storage dispatcher payload; never a V2 schema alias.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredV3(pub RunEnvelopeV3);
impl StoredV3 {
    pub fn to_record(&self, limits: Limits) -> Result<ExportRecord> {
        self.0.to_record(limits)
    }
    pub fn from_record(record: &ExportRecord, limits: Limits) -> Result<Self> {
        Ok(Self(RunEnvelopeV3::from_record(record, limits)?))
    }
}
