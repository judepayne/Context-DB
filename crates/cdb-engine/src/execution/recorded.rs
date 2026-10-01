//! Trusted-host preparation capabilities. Durable data decoding is not an authorization seal.
use super::trace::{RecordingPolicy, RecordingRawView, TraceLog};
use super::*;
use crate::{
    compiler::{load_recorded_plan, ExecutablePlan},
    diagnostics::CompileNotice,
};
use cdb_core::{
    admission::ResourceKind,
    recording::*,
    replay::{RecordedLanding, ReplayVerdict},
};

pub const REPLAY_ABI: &str = "ctxql-native-graph-replay/v1";
const BOUNDARY: &str = "ctxql-landing-boundary/v2";
pub(super) fn trace_limits(options: &ExecutionOptions) -> Result<Limits> {
    Limits::new(
        options.limits.input_bytes().min(options.max_retained_bytes),
        options.limits.depth(),
        options.limits.values().min(options.max_records),
        options.limits.work().min(options.max_work),
        options
            .limits
            .output_bytes()
            .min(options.max_retained_bytes),
    )
}
pub(super) fn engine() -> Result<RecordingEngine> {
    Ok(RecordingEngine {
        // Persisted replay identity, independent of the product/package name.
        name: ResourceId::new("ctxql-engine")?,
        version: VersionId::new(env!("CARGO_PKG_VERSION"))?,
        build: ContentHash::parse(option_env!("CDB_ENGINE_BUILD").ok_or_else(|| {
            Error::new(ErrorKind::Unsupported, "engine build identity unavailable")
        })?)?,
    })
}
pub(super) fn supported(plan: &ExecutablePlan) -> Result<()> {
    if *plan
        .projection()
        .canonical()
        .payload()
        .field("artifacts")?
        .field("query")?
        == V::Null
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "recorded query must be published",
        ));
    }
    if plan.has_custom_predicates()
        || plan
            .walk_predicates()
            .iter()
            .chain(plan.filter_predicates())
            .any(|p| {
                p.mapping().is_some()
                    || p.builtin().is_some_and(|b| {
                        matches!(
                            b.operator(),
                            crate::values::Operator::Isa
                                | crate::values::Operator::NotIsa
                                | crate::values::Operator::SubpropertyOf
                                | crate::values::Operator::NotSubpropertyOf
                                | crate::values::Operator::ContainsIsa
                                | crate::values::Operator::ContainsSubpropertyOf
                        )
                    })
            })
        || plan
            .blocks()
            .iter()
            .any(|b| b.match_mode() == crate::compiler::MatchMode::Approximate)
        || !plan
            .semantic_config()
            .field("external_functions")?
            .as_object()?
            .is_empty()
        || plan
            .semantic_config()
            .as_object()?
            .get("preparation")
            .is_some_and(|v| v.as_array().map_or(true, |a| !a.is_empty()))
    {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "recorded capability unavailable",
        ));
    }
    Ok(())
}
/// Only instrumented execution can construct this pending result. Host must guard release.
pub struct PreparedExecution<C> {
    data: ReplayData,
    context: C,
    bytes: Vec<u8>,
}
impl<C> PreparedExecution<C> {
    pub fn data(&self) -> &ReplayData {
        &self.data
    }
    pub fn context(&self) -> &C {
        &self.context
    }
    pub fn wire_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_parts(self) -> (ReplayData, C, Vec<u8>) {
        (self.data, self.context, self.bytes)
    }
}
/// Reattested pending replay, never a publication permission.
pub struct PreparedReplay<C> {
    verdict: ReplayVerdict,
    context: C,
    bytes: Vec<u8>,
    sources: Vec<cdb_core::evidence::SourceReference>,
}
impl<C> PreparedReplay<C> {
    /// Freshly evaluated returned-path sources, for separately authorized hydration.
    pub fn sources(&self) -> &[cdb_core::evidence::SourceReference] {
        &self.sources
    }
    pub fn verdict(&self) -> ReplayVerdict {
        self.verdict
    }
    pub fn context(&self) -> &C {
        &self.context
    }
    pub fn wire_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_parts(self) -> (ReplayVerdict, C, Vec<u8>) {
        (self.verdict, self.context, self.bytes)
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn prepare_recorded<B: GraphBackend, P: PolicyService>(
    draft: ValidatedDraft,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    provider: &dyn ViewProvider,
    consistency: Option<Consistency>,
    options: ExecutionOptions,
) -> Result<PreparedExecution<P::Context>> {
    let identity = engine()?;
    let log = TraceLog::new_recording(trace_limits(&options)?);
    let wrapped = RecordingPolicy::new(policy, log.clone());
    let mut mode = walk::LandingMode::Record {
        log: log.clone(),
        landings: vec![],
        notices: vec![],
        raw_count: 0,
        outcomes: vec![],
    };
    let c = compute(
        draft,
        backend,
        &wrapped,
        principal,
        provider,
        consistency,
        &options,
        Some(&mut mode),
        None,
        false,
    )
    .await?;
    log.merge_policy(&provider.evidence_footprint()?)?;
    let (policy, mut reads) = log.finish()?;
    let walk::LandingMode::Record {
        landings,
        notices,
        raw_count,
        outcomes,
        ..
    } = mode
    else {
        unreachable!()
    };
    let key = obj([
        ("raw_count", V::integer(raw_count as u64)),
        ("notices", V::Array(notices.iter().map(V::string).collect())),
        ("compile_notices", V::integer(c.plan.notices().len() as u64)),
        ("outcomes", V::Array(outcomes)),
    ]);
    reads.insert(
        0,
        ReadObservation {
            operation: ResourceId::new(BOUNDARY)?,
            result_hash: ContentHash::of_bytes(&key.canonical_bytes(options.limits)?),
            key,
        },
    );
    let artifacts = c
        .plan
        .projection()
        .canonical()
        .payload()
        .field("artifacts")?;
    let input = ReplayDataInput {
        stale: c.captured.snapshot != c.requested.snapshot,
        snapshot: c.captured.snapshot,
        requested_snapshot: c.requested.snapshot,
        as_of: c.captured.as_of,
        plan: c.plan.projection().canonical().clone(),
        plan_hash: c.plan.hash().clone(),
        response: c.response.canonical().clone(),
        response_hash: c.response.canonical().hash(options.limits)?,
        query: ArtifactRef::from_value(artifacts.field("query")?)?,
        profile: if *artifacts.field("profile")? == V::Null {
            None
        } else {
            Some(ArtifactRef::from_value(artifacts.field("profile")?)?)
        },
        config: ArtifactRef::from_value(artifacts.field("config")?)?,
        engine: identity,
        replay_abi: VersionId::new(REPLAY_ABI)?,
        landings: landings
            .iter()
            .map(RecordedLanding::from_value)
            .collect::<Result<_>>()?,
        catalog: c
            .catalog
            .into_iter()
            .map(|e| {
                Ok(PreparedCatalogEntry {
                    id: ResourceId::new(e.id.as_str())?,
                    label: e.label,
                    dependencies: e.dependencies,
                })
            })
            .collect::<Result<_>>()?,
        policy,
        reads,
        scopes: REQUIRED_SCOPES
            .iter()
            .map(|s| ResourceId::new(*s))
            .collect::<Result<_>>()?,
        functions: vec![],
    };
    options.check_interrupted()?;
    Ok(PreparedExecution {
        data: ReplayData::new(input, options.limits)?,
        context: c.context,
        bytes: c.bytes,
    })
}
struct LandingBoundary {
    raw_count: usize,
    notices: Vec<String>,
    compile_notices: usize,
    outcomes: Vec<V>,
}
fn boundary(data: &ReplayDataInput, options: &ExecutionOptions) -> Result<LandingBoundary> {
    let marker = data
        .reads
        .first()
        .ok_or_else(|| Error::invalid("missing landing boundary"))?;
    if marker.operation.as_str() != BOUNDARY
        || marker.result_hash != ContentHash::of_bytes(&marker.key.canonical_bytes(options.limits)?)
    {
        return Err(Error::invalid("landing boundary integrity"));
    }
    marker.key.closed(
        &["raw_count", "notices", "compile_notices", "outcomes"],
        &[],
    )?;
    let count =
        usize::try_from(marker.key.field("raw_count")?.u64()?).map_err(|_| Error::limit())?;
    let compile =
        usize::try_from(marker.key.field("compile_notices")?.u64()?).map_err(|_| Error::limit())?;
    if count > data.reads.len() - 1 || compile > 1 || (compile > 0 && data.profile.is_none()) {
        return Err(Error::invalid("landing boundary count"));
    }
    let notices = marker
        .key
        .field("notices")?
        .as_array()?
        .iter()
        .map(|v| Ok(v.as_str()?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    if notices
        .iter()
        .any(|s| !matches!(s.as_str(), "empty_landing" | "seed_limit"))
        || notices.windows(2).any(|w| w[0] >= w[1])
    {
        return Err(Error::invalid("landing boundary notices"));
    }
    let outcomes = marker.key.field("outcomes")?.as_array()?;
    if outcomes.len() > options.max_records {
        return Err(Error::limit());
    }
    Ok(LandingBoundary {
        raw_count: count,
        notices,
        compile_notices: compile,
        outcomes: outcomes.to_vec(),
    })
}
fn validate_landings(
    data: &ReplayDataInput,
    plan: &ExecutablePlan,
    notices: &[String],
    outcomes: &[V],
) -> Result<Vec<V>> {
    let mut previous = None;
    let mut counts = std::collections::BTreeMap::new();
    let mut out = vec![];
    for landing in &data.landings {
        let v = landing.projection();
        let block = usize::try_from(v.field("block_index")?.u64()?).map_err(|_| Error::limit())?;
        let role = v.field("role")?.as_str()?;
        let b = plan
            .blocks()
            .get(block)
            .ok_or_else(|| Error::invalid("landing block"))?;
        let anchors = match role {
            "from" => b.from(),
            "to" => b.to().ok_or_else(|| Error::invalid("landing target"))?,
            _ => return Err(Error::invalid("landing role")),
        };
        if !anchors
            .iter()
            .any(|a| a == v.field("anchor").and_then(V::as_str).unwrap_or(""))
            || v.field("score")? != &V::integer(1)
        {
            return Err(Error::invalid("landing anchor/score"));
        }
        let id = v.field("id")?.as_str()?;
        let anchor = v.field("anchor")?.as_str()?;
        if !data
            .catalog
            .iter()
            .any(|e| e.id.as_str() == id && (id == anchor || e.label.as_deref() == Some(anchor)))
        {
            return Err(Error::invalid("landing catalog binding"));
        }
        let key = (
            block,
            if role == "from" { 0 } else { 1 },
            v.field("id")?.as_str()?.to_owned(),
        );
        if previous.as_ref().is_some_and(|p| p >= &key) {
            return Err(Error::invalid("landing order/rank"));
        }
        previous = Some(key);
        let count = counts.entry((block, role.to_owned())).or_insert(0u64);
        *count += 1;
        if role == "from" && *count > plan.caps().seed_limit {
            return Err(Error::invalid("landing seed cap"));
        }
        out.push(v);
    }
    // Notices describe the authorized set BEFORE caps, not retained seeds.
    // In particular, zero retained seeds can mean either no match or a zero cap.
    let mut cursor = outcomes.iter();
    let (mut empty, mut limited) = (false, false);
    for (i, block) in plan.blocks().iter().enumerate() {
        for role in std::iter::once("from").chain(block.to().map(|_| "to")) {
            let outcome = cursor
                .next()
                .ok_or_else(|| Error::invalid("missing landing outcome"))?;
            outcome.closed(&["block_index", "role", "matched"], &[])?;
            if outcome.field("block_index")?.u64()? != i as u64
                || outcome.field("role")?.as_str()? != role
            {
                return Err(Error::invalid("landing outcome order"));
            }
            let matched = outcome.field("matched")?.u64()?;
            if matched > data.catalog.len() as u64 {
                return Err(Error::invalid("landing outcome count"));
            }
            let retained = if role == "from" {
                matched.min(plan.caps().seed_limit)
            } else {
                matched
            };
            if counts.get(&(i, role.to_owned())).copied().unwrap_or(0) != retained {
                return Err(Error::invalid("landing outcome retained count"));
            }
            empty |= matched == 0;
            limited |= role == "from" && matched > plan.caps().seed_limit;
        }
    }
    if cursor.next().is_some()
        || empty != notices.iter().any(|s| s == "empty_landing")
        || limited != notices.iter().any(|s| s == "seed_limit")
    {
        return Err(Error::invalid("landing notice binding"));
    }
    Ok(out)
}
/// Trusted host must first authorize ownership and load the authoritative durable envelope.
/// This API does not accept a completeness claim from untrusted clients.
pub async fn prepare_replay<B: GraphBackend, P: PolicyService>(
    data: &ReplayData,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    provider: &dyn ViewProvider,
    options: ExecutionOptions,
) -> Result<PreparedReplay<P::Context>> {
    prepare_replay_inner(data, backend, policy, principal, provider, options)
        .await
        .map_err(|e| match e.kind {
            ErrorKind::Denied => Error::new(ErrorKind::Denied, "access_denied"),
            ErrorKind::PolicyChanged => Error::new(ErrorKind::PolicyChanged, "policy_changed"),
            _ => e,
        })
}
async fn prepare_replay_inner<B: GraphBackend, P: PolicyService>(
    data: &ReplayData,
    backend: &B,
    policy: &P,
    principal: &P::Principal,
    provider: &dyn ViewProvider,
    options: ExecutionOptions,
) -> Result<PreparedReplay<P::Context>> {
    options.check_interrupted()?;
    data.bytes(options.limits)?;
    // Opening a generation precedes the context: projection preparation is not a grant.
    let d = data.data();
    let captured = CapturedSnapshot {
        snapshot: d.snapshot.clone(),
        as_of: d.as_of,
    };
    let prepared = provider.open(&captured, &options).await;
    let context = policy.current(principal).await?;
    // Even unsupported/corrupt prerequisites must not disclose old metadata on revocation.
    for observation in &d.policy {
        options.check_interrupted()?;
        if observation.allowed {
            let allowed = match &observation.predicate {
                Some(p) => policy.fact_allowed(&context, &observation.resource, p)?,
                None => policy.resource_allowed(&context, &observation.resource)?,
            };
            if !allowed {
                return Err(Error::new(ErrorKind::Denied, "access_denied"));
            }
        }
    }
    let result = replay_inner(d, backend, policy, &context, prepared, &options).await;
    let (verdict, response, sources) = match result {
        Ok((response, sources)) => {
            let verdict = if response.canonical().hash(options.limits)? == d.response_hash {
                ReplayVerdict::Reproduced
            } else {
                ReplayVerdict::Diverged
            };
            (verdict, Some(response), sources)
        }
        Err(e)
            if matches!(
                e.kind,
                ErrorKind::Denied
                    | ErrorKind::PolicyChanged
                    | ErrorKind::Deadline
                    | ErrorKind::Limit
            ) =>
        {
            return Err(e)
        }
        Err(_) => (ReplayVerdict::NotReplayable, None, vec![]),
    };
    let mut wire = obj([
        (
            "graph",
            V::string(match verdict {
                ReplayVerdict::Reproduced => "reproduced",
                ReplayVerdict::Diverged => "diverged",
                _ => "not_replayable",
            }),
        ),
        ("product", V::string("not_requested")),
    ])
    .as_object()?
    .clone();
    if let Some(response) = response {
        wire.insert("response".into(), response.canonical().payload().clone());
        wire.insert(
            "response_hash".into(),
            V::string(response.canonical().hash(options.limits)?.as_str()),
        );
        wire.insert("plan_hash".into(), V::string(d.plan_hash.as_str()));
    }
    options.check_interrupted()?;
    Ok(PreparedReplay {
        verdict,
        context,
        bytes: V::Object(wire).canonical_bytes(options.limits)?,
        sources,
    })
}
async fn replay_inner<B: GraphBackend, P: PolicyService>(
    d: &ReplayDataInput,
    backend: &B,
    policy: &P,
    context: &P::Context,
    prepared: Result<PreparedView>,
    options: &ExecutionOptions,
) -> Result<(
    cdb_core::projection::ResponseProjection,
    Vec<cdb_core::evidence::SourceReference>,
)> {
    if d.engine != engine()? || d.replay_abi.as_str() != REPLAY_ABI || !d.functions.is_empty() {
        return Err(Error::new(ErrorKind::Unsupported, "engine replay ABI"));
    }
    let boundary = boundary(d, options)?;
    let plan = load_recorded_plan(
        &d.plan.bytes(options.limits)?,
        &d.plan_hash,
        vec![CompileNotice::IgnoredProfileAbout; boundary.compile_notices],
        options.limits,
    )?;
    if plan.hash() != &d.plan_hash {
        return Err(Error::invalid("plan identity"));
    }
    let landings = validate_landings(d, &plan, &boundary.notices, &boundary.outcomes)?;
    let prepared = prepared?;
    if prepared.view.identity() != &d.snapshot {
        return Err(Error::new(ErrorKind::Snapshot, "recorded exact view"));
    }
    let log = TraceLog::new_replay(trace_limits(options)?, &d.policy, &d.reads[1..])?;
    let wrapped = RecordingPolicy::new(policy, log.clone());
    let snapshot = backend.open_snapshot(&d.snapshot).await?;
    if snapshot.identity() != &d.snapshot {
        return Err(Error::new(
            ErrorKind::Snapshot,
            "recorded artifact snapshot",
        ));
    }
    for value in plan
        .projection()
        .canonical()
        .payload()
        .field("artifacts")?
        .as_object()?
        .values()
    {
        if *value == V::Null {
            continue;
        }
        let reference = ArtifactRef::from_value(value)?;
        let id = ResourceId::new(reference.iri().as_str())?;
        if !wrapped.resource_allowed(context, &id)? {
            return Err(Error::new(ErrorKind::Denied, "access_denied"));
        }
        for key in ["iri", "version", "hash"] {
            if !wrapped.fact_allowed(context, &id, &property_iri(&format!("artifact.{key}"))?)? {
                return Err(Error::new(ErrorKind::Denied, "access_denied"));
            }
        }
        let artifact = snapshot
            .artifact(&reference)
            .await?
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "recorded artifact"))?;
        if artifact.reference() != &reference {
            return Err(Error::invalid("recorded artifact identity"));
        }
    }
    // Scopes must be positive and present with every fact; the original prefix proves bytes.
    for scope in REQUIRED_SCOPES {
        let id = ResourceId::new(scope)?;
        let record = prepared
            .view
            .resource(&id)?
            .ok_or_else(|| Error::invalid("recorded scope missing"))?;
        if record.kind() != ResourceKind::SourceDescriptor
            || !wrapped.resource_allowed(context, &id)?
        {
            return Err(Error::new(ErrorKind::Denied, "access_denied"));
        }
        for fact in record.facts() {
            if !wrapped.fact_allowed(context, &id, fact.predicate())? {
                return Err(Error::new(ErrorKind::Denied, "access_denied"));
            }
        }
    }
    log.verify_prefix(prepared.view.as_ref(), boundary.raw_count, || {
        options.check_interrupted()
    })?;
    let raw = RecordingRawView::new(prepared.view.as_ref(), log.clone());
    let mut work = Work {
        options,
        count: 0,
        bytes: 0,
    };
    let mut guard = authorized::Guard {
        view: &raw,
        policy: &wrapped,
        context,
        cutoff: d.as_of,
        mappings: None,
        ontology: None,
        work: &mut work,
        dependencies: super::controller::DependencyFootprint::default(),
    };
    // Empty catalog ensures replay never consults a fresh landing catalog/resolver.
    struct Empty(SnapshotRef);
    impl LandingCatalog for Empty {
        fn identity(&self) -> &SnapshotRef {
            &self.0
        }
        fn entries(&self) -> &[LandingEntry] {
            &[]
        }
    }
    let mut mode = walk::LandingMode::Replay {
        landings,
        notices: boundary.notices,
    };
    let result = walk::run(
        &plan,
        &Empty(d.snapshot.clone()),
        &mut guard,
        d.stale,
        Some(&mut mode),
        None,
    )?;
    log.finish()?;
    Ok(result)
}
