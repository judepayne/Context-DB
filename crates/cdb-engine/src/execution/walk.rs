use super::{
    authorized::{Guard, Usable},
    controller::{
        ControllerEvent, ControllerRuntime, ControllerTicket, DependencyFootprint, EvaluationJob,
        LaneIdentityV3, PredicatePhase,
    },
    obj, LandingCatalog,
};
use crate::{
    compiler::{
        BuiltinPredicate, CustomBinding, CustomProgram, CyclePolicy, Direction, ExecutablePlan,
        FieldRef, MatchMode, StoredPredicateMapping,
    },
    values::Value,
};
use cdb_core::{
    claim::*,
    contracts::{self, PolicyService},
    id::*,
    projection::*,
    CanonicalValue as V, Error, ErrorKind, ExactNumber, Lookup, Result,
};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};
#[derive(Clone)]
struct PredicateState {
    value: V,
    dependencies: DependencyFootprint,
}
#[derive(Clone)]
struct Path {
    block: usize,
    seed_rank: usize,
    seed: EntityId,
    claims: Vec<Usable>,
    endpoints: Vec<ClaimObject>,
    confidence: ExactNumber,
    grounding: Grounding,
    target: Option<EntityId>,
    states: BTreeMap<usize, PredicateState>,
}
impl Path {
    fn ids(&self) -> Vec<&ClaimId> {
        self.claims.iter().map(|c| c.claim.id()).collect()
    }
    fn wire(&self) -> V {
        obj([
            ("seed_id", V::string(self.seed.as_str())),
            (
                "node_ids",
                V::Array(
                    self.endpoints
                        .iter()
                        .filter_map(|e| {
                            if let ClaimObject::Entity(id) = e {
                                Some(V::string(id.as_str()))
                            } else {
                                None
                            }
                        })
                        .collect(),
                ),
            ),
            (
                "endpoints",
                V::Array(self.endpoints.iter().map(ClaimObject::endpoint).collect()),
            ),
            (
                "claim_ids",
                V::Array(self.ids().iter().map(|id| V::string(id.as_str())).collect()),
            ),
            ("depth", V::integer(self.claims.len() as u64)),
            (
                "reached_target",
                self.target
                    .as_ref()
                    .map(|id| V::string(id.as_str()))
                    .unwrap_or(V::Null),
            ),
            ("block_index", V::integer(self.block as u64)),
            (
                "scores",
                obj([
                    ("accumulated_confidence", V::Number(self.confidence.clone())),
                    ("grounding_level", V::string(self.grounding.as_str())),
                ]),
            ),
        ])
    }
}
fn tier(g: Grounding) -> u8 {
    match g {
        Grounding::ClaimOnly => 0,
        Grounding::SourceLineageAvailable => 1,
        Grounding::SourceSpansAvailable => 2,
    }
}
fn field<P: PolicyService>(
    p: &BuiltinPredicate,
    c: &Usable,
    depth: usize,
    g: &mut Guard<'_, '_, P>,
) -> Result<Value> {
    read_field(p.field(), p.mapping(), c, depth, g)
}
fn read_field<P: PolicyService>(
    field: &FieldRef,
    mapping: Option<&StoredPredicateMapping>,
    c: &Usable,
    depth: usize,
    g: &mut Guard<'_, '_, P>,
) -> Result<Value> {
    if let Some(mapping) = mapping {
        return g.mapped(c.claim.id(), mapping, field);
    }
    if field.metadata_key() == "depth" {
        return Ok(Value::Number(ExactNumber::from_u64(depth as u64)));
    }
    let response = c.claim.response(c.state);
    let meta = response.field("meta")?;
    let value = if let Some(key) = field.extension_key() {
        meta.field("ext")?.as_object()?.get(key)
    } else {
        meta.as_object()?.get(field.metadata_key())
    };
    field.value(value.map(Lookup::Present).unwrap_or(Lookup::Missing))
}
fn initial_states<P: PolicyService>(
    plan: &ExecutablePlan,
    g: &mut Guard<'_, '_, P>,
) -> Result<BTreeMap<usize, PredicateState>> {
    let mut states = BTreeMap::new();
    for p in plan.walk_predicates() {
        if let Some(custom) = p.custom() {
            let state = V::Object(custom.program().init.clone());
            g.work.retain(&state)?;
            states.insert(
                p.index(),
                PredicateState {
                    value: state,
                    dependencies: DependencyFootprint::default(),
                },
            );
        }
    }
    Ok(states)
}
fn custom_bindings<P: PolicyService>(
    custom: &CustomProgram,
    claims: &[&Usable],
    attempt: usize,
    g: &mut Guard<'_, '_, P>,
) -> Result<BTreeMap<String, Value>> {
    let mut bindings = BTreeMap::new();
    for (name, binding) in custom.bindings() {
        g.work.tick(1)?;
        let value = match binding {
            CustomBinding::Constant(v) => {
                g.work.retain(v)?;
                Value::from_json(v)?
            }
            CustomBinding::Field(f, mapping) if f.is_path() => {
                g.work.tick(claims.len())?;
                Value::List(
                    claims
                        .iter()
                        .enumerate()
                        .map(|(i, c)| read_field(f, mapping.as_ref(), c, i + 1, g))
                        .collect::<Result<_>>()?,
                )
            }
            CustomBinding::Field(f, mapping) => read_field(
                f,
                mapping.as_ref(),
                claims
                    .get(attempt)
                    .ok_or_else(|| Error::invalid("custom claim attempt"))?,
                attempt + 1,
                g,
            )?,
        };
        g.work.tick(value_work(&value)?)?;
        bindings.insert(name.clone(), value);
    }
    Ok(bindings)
}
fn value_work(value: &Value) -> Result<usize> {
    match value {
        Value::List(values) => values.iter().try_fold(1usize, |n, v| {
            n.checked_add(value_work(v)?).ok_or_else(Error::limit)
        }),
        Value::String(s) => s.len().checked_add(1).ok_or_else(Error::limit),
        _ => Ok(1),
    }
}
fn evaluate<P: PolicyService>(
    p: &BuiltinPredicate,
    value: &Value,
    g: &mut Guard<'_, '_, P>,
) -> Result<bool> {
    g.work.tick(
        value_work(value)?
            .checked_mul(value_work(p.operand())?)
            .ok_or_else(Error::limit)?,
    )?;
    use crate::values::Operator::*;
    let (kind, negative, list) = match p.operator() {
        Isa => (super::OntologyKind::Class, false, false),
        NotIsa => (super::OntologyKind::Class, true, false),
        SubpropertyOf => (super::OntologyKind::Property, false, false),
        NotSubpropertyOf => (super::OntologyKind::Property, true, false),
        ContainsIsa => (super::OntologyKind::Class, false, true),
        ContainsSubpropertyOf => (super::OntologyKind::Property, false, true),
        _ => {
            return crate::values::evaluate_with_limits(
                p.operator(),
                value,
                p.operand(),
                g.work.options.limits,
            )
        }
    };
    let Value::String(target) = p.operand() else {
        return Err(Error::invalid("ontology target IRI"));
    };
    Iri::new(target)?;
    let values: &[Value] = if list {
        let Value::List(values) = value else {
            return Err(Error::invalid("ontology containment list"));
        };
        values
    } else {
        std::slice::from_ref(value)
    };
    let mut matched = false;
    for value in values {
        match value {
            Value::Missing => (),
            Value::String(actual) => {
                Iri::new(actual)?;
                // Provider capability and complete authorized absence evidence are
                // required even for exact equality; there is no exact-only fallback.
                matched |= g.ontology(kind, actual, target)?;
            }
            _ => return Err(Error::invalid("ontology source IRI")),
        }
    }
    if list {
        Ok(matched)
    } else if matches!(value, Value::Missing) {
        Ok(false)
    } else {
        Ok(if negative { !matched } else { matched })
    }
}
fn notice(notices: &mut BTreeSet<String>, code: &str) {
    notices.insert(code.into());
}
pub(super) enum LandingMode {
    Record {
        log: super::trace::TraceLog,
        landings: Vec<V>,
        notices: Vec<String>,
        raw_count: usize,
        outcomes: Vec<V>,
    },
    Replay {
        landings: Vec<V>,
        notices: Vec<String>,
    },
}
impl LandingMode {
    pub(super) fn log(&self) -> Option<super::trace::TraceLog> {
        match self {
            Self::Record { log, .. } => Some(log.clone()),
            _ => None,
        }
    }
}

struct WalkEvaluation {
    ordinal: u64,
    claim: Usable,
    endpoint: ClaimObject,
    predicate: usize,
    proposed: BTreeMap<usize, PredicateState>,
    passes: bool,
    pending: Option<(ControllerTicket, LaneIdentityV3, usize, DependencyFootprint)>,
}

fn notify(runtime: Option<&dyn ControllerRuntime>, event: ControllerEvent) -> Result<()> {
    runtime.map_or(Ok(()), |runtime| runtime.event(event))
}
fn read_lane(
    phase: PredicatePhase,
    evaluation_ordinal: u64,
    predicate_index: u64,
    attempt: u64,
) -> LaneIdentityV3 {
    LaneIdentityV3 {
        phase,
        evaluation_ordinal,
        predicate_index,
        attempt,
    }
}
fn lane_outcome(passed: bool) -> super::trace::LaneOutcomeV3 {
    if passed {
        super::trace::LaneOutcomeV3::Accepted
    } else {
        super::trace::LaneOutcomeV3::Rejected
    }
}
#[allow(clippy::too_many_arguments)]
fn advance_walk<P: PolicyService>(
    task: &mut WalkEvaluation,
    parent: &Path,
    plan: &ExecutablePlan,
    g: &mut Guard<'_, '_, P>,
    runtime: Option<&dyn ControllerRuntime>,
    limits: crate::predicates::EvaluationLimits,
    pending_bytes: &mut usize,
) -> Result<()> {
    while task.passes && task.predicate < plan.walk_predicates().len() {
        let predicate = &plan.walk_predicates()[task.predicate];
        let lane = read_lane(
            PredicatePhase::Walk,
            task.ordinal,
            u64::try_from(predicate.index()).map_err(|_| Error::limit())?,
            0,
        );
        notify(runtime, ControllerEvent::ReadLane(lane.clone()))?;
        if let Some(custom) = predicate.custom() {
            let runtime = runtime
                .ok_or_else(|| Error::new(ErrorKind::Unsupported, "custom runtime unavailable"))?;
            g.work.tick(parent.claims.len() + 1)?;
            let claims = parent
                .claims
                .iter()
                .chain(std::iter::once(&task.claim))
                .collect::<Vec<_>>();
            g.reset_dependencies();
            let bindings = custom_bindings(custom, &claims, claims.len() - 1, g)?;
            let mut argument_dependencies = g.take_dependencies();
            for claim in &claims {
                argument_dependencies.extend(&claim.dependencies);
            }
            let state = parent
                .states
                .get(&predicate.index())
                .ok_or_else(|| Error::invalid("custom state identity"))?
                .clone();
            let mut next_dependencies = state.dependencies.clone();
            next_dependencies.extend(&argument_dependencies);
            let job = EvaluationJob {
                lane: lane.clone(),
                program: custom.program().clone(),
                state: state.value,
                bindings,
                argument_dependencies,
                state_dependencies: state.dependencies,
                limits,
            };
            let bytes = job.retained_bytes(g.work.options.limits)?;
            let bounds = runtime.bounds().validate()?;
            if bytes > bounds.max_pending_bytes
                || pending_bytes
                    .checked_add(bytes)
                    .is_none_or(|n| n > bounds.max_pending_bytes)
            {
                return Err(Error::limit());
            }
            runtime.event(ControllerEvent::Submitted(lane.clone()))?;
            let ticket = match runtime.submit(job) {
                Ok(ticket) => ticket,
                Err(error) => {
                    runtime.event(ControllerEvent::AdmissionRejected(lane.clone()))?;
                    return Err(error);
                }
            };
            if ticket.lane() != &lane {
                return Err(Error::invalid("controller ticket lane"));
            }
            *pending_bytes = pending_bytes.checked_add(bytes).ok_or_else(Error::limit)?;
            task.pending = Some((ticket, lane, bytes, next_dependencies));
            return Ok(());
        }
        let p = predicate.builtin().ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "custom predicate runtime unavailable",
            )
        })?;
        g.work.tick(1)?;
        let value = if p.field().is_path() {
            g.work.tick(parent.claims.len() + 1)?;
            Value::List(
                parent
                    .claims
                    .iter()
                    .chain(std::iter::once(&task.claim))
                    .enumerate()
                    .map(|(i, claim)| field(p, claim, i + 1, g))
                    .collect::<Result<Vec<_>>>()?,
            )
        } else {
            field(p, &task.claim, parent.claims.len() + 1, g)?
        };
        task.passes = evaluate(p, &value, g)?;
        notify(
            runtime,
            ControllerEvent::LaneClosed(lane, lane_outcome(task.passes)),
        )?;
        task.predicate += 1;
    }
    Ok(())
}

pub(super) fn run<P: PolicyService>(
    plan: &ExecutablePlan,
    catalog: &dyn LandingCatalog,
    g: &mut Guard<'_, '_, P>,
    stale: bool,
    mode: Option<&mut LandingMode>,
    runtime: Option<&dyn ControllerRuntime>,
) -> Result<(ResponseProjection, Vec<cdb_core::evidence::SourceReference>)> {
    run_controller(
        plan,
        catalog,
        g,
        stale,
        mode,
        runtime,
        crate::predicates::EvaluationLimits::default(),
    )
}

pub(super) fn run_controller<P: PolicyService>(
    plan: &ExecutablePlan,
    catalog: &dyn LandingCatalog,
    g: &mut Guard<'_, '_, P>,
    stale: bool,
    mode: Option<&mut LandingMode>,
    runtime: Option<&dyn ControllerRuntime>,
    evaluation_limits: crate::predicates::EvaluationLimits,
) -> Result<(ResponseProjection, Vec<cdb_core::evidence::SourceReference>)> {
    let caps = plan.caps();
    let mut notices = BTreeSet::new();
    if stale {
        notice(&mut notices, "stale_snapshot");
    }
    for _ in plan.notices() {
        notice(&mut notices, "ignored_profile_about");
    }
    if catalog.entries().len() > g.work.options.max_records {
        return Err(Error::limit());
    }
    for entry in catalog.entries() {
        g.work.retain(&obj([
            ("id", V::string(entry.id.as_str())),
            (
                "label",
                entry.label.as_ref().map(V::string).unwrap_or(V::Null),
            ),
            (
                "dependencies",
                V::Array(
                    entry
                        .dependencies
                        .iter()
                        .map(|id| V::string(id.as_str()))
                        .collect(),
                ),
            ),
        ]))?;
    }
    let mut landings = vec![];
    let mut outcomes = vec![];
    let mut frontier = vec![];
    let mut targets = vec![];
    if let Some(LandingMode::Replay {
        landings: saved,
        notices: saved_notices,
    }) = &mode
    {
        landings = saved.clone();
        notices.extend(saved_notices.iter().cloned());
        targets = vec![BTreeSet::new(); plan.blocks().len()];
        let mut ranks = BTreeMap::<usize, usize>::new();
        for landing in &landings {
            g.work.retain(landing)?;
            let block = usize::try_from(landing.field("block_index")?.u64()?)
                .map_err(|_| Error::limit())?;
            let id = EntityId::new(landing.field("id")?.as_str()?)?;
            if landing.field("role")?.as_str()? == "to" {
                targets[block].insert(id);
            } else {
                if frontier.len() >= g.work.options.max_frontier {
                    return Err(Error::limit());
                }
                let rank = ranks.entry(block).or_default();
                frontier.push(Path {
                    block,
                    seed_rank: *rank,
                    seed: id.clone(),
                    claims: vec![],
                    endpoints: vec![ClaimObject::Entity(id)],
                    confidence: ExactNumber::from_u64(1),
                    grounding: Grounding::SourceSpansAvailable,
                    target: None,
                    states: initial_states(plan, g)?,
                });
                *rank += 1;
            }
        }
    } else {
        for (block, b) in plan.blocks().iter().enumerate() {
            let mut target_set = BTreeSet::new();
            for (role, anchors) in [("from", Some(b.from())), ("to", b.to())] {
                let Some(anchors) = anchors else {
                    continue;
                };
                let mut landed = BTreeMap::<EntityId, (String, u64, usize)>::new();
                match b.match_mode() {
                    MatchMode::Exact => {
                        // Borrow a bounded index rather than rescanning the
                        // entire catalog for each exact anchor.
                        let mut exact =
                            BTreeMap::<&str, Vec<&crate::execution::LandingEntry>>::new();
                        for entry in catalog.entries() {
                            g.work.tick(1)?;
                            exact.entry(entry.id.as_str()).or_default().push(entry);
                            if let Some(label) = entry.label.as_deref() {
                                if label != entry.id.as_str() {
                                    exact.entry(label).or_default().push(entry);
                                }
                            }
                        }
                        for (anchor_index, anchor) in anchors.iter().enumerate() {
                            g.work.tick(1)?;
                            for entry in exact.get(anchor.as_str()).into_iter().flatten() {
                                g.work.tick(1)?;
                                let mut allowed =
                                    catalog.entries_are_authorized() || g.entity(&entry.id)?;
                                if !catalog.entries_are_authorized() {
                                    for dependency in &entry.dependencies {
                                        allowed &= g.resource(dependency)?;
                                    }
                                }
                                if allowed {
                                    landed
                                        .entry(entry.id.clone())
                                        .or_insert_with(|| (anchor.clone(), 1, anchor_index));
                                }
                            }
                        }
                    }
                    MatchMode::Approximate => {
                        let landing = plan.semantic_config().field("landing")?;
                        let unicode = landing.field("unicode_version")?.as_array()?;
                        let config = crate::lexical::Config::new(
                            landing.field("resolver")?.as_str()?,
                            (
                                u8::try_from(unicode[0].u64()?)
                                    .map_err(|_| Error::invalid("Unicode version"))?,
                                u8::try_from(unicode[1].u64()?)
                                    .map_err(|_| Error::invalid("Unicode version"))?,
                                u8::try_from(unicode[2].u64()?)
                                    .map_err(|_| Error::invalid("Unicode version"))?,
                            ),
                            landing.field("minimum_overlap")?.u64()?,
                        )?;
                        let mut candidates =
                            BTreeMap::<EntityId, (Vec<String>, BTreeSet<ResourceId>)>::new();
                        for entry in catalog.entries() {
                            let candidate = candidates.entry(entry.id.clone()).or_default();
                            if let Some(label) = &entry.label {
                                candidate.0.push(label.clone());
                            }
                            candidate.1.extend(entry.dependencies.iter().cloned());
                        }
                        for (id, (labels, dependencies)) in candidates {
                            // Whole catalog/ranking input is authorized before scoring and
                            // before seed limits. A hidden candidate cannot be pruned into a
                            // different public ranking or negative result.
                            if !catalog.entries_are_authorized() && !g.entity(&id)? {
                                return Err(Error::new(
                                    ErrorKind::Denied,
                                    "lexical candidate unavailable",
                                ));
                            }
                            if !catalog.entries_are_authorized() {
                                for dependency in dependencies {
                                    if !g.resource(&dependency)? {
                                        return Err(Error::new(
                                            ErrorKind::Denied,
                                            "lexical dependency unavailable",
                                        ));
                                    }
                                }
                            }
                            let resource = ResourceId::new(id.as_str())?;
                            for (anchor_index, anchor) in anchors.iter().enumerate() {
                                g.work
                                    .tick(labels.len().checked_add(1).ok_or_else(Error::limit)?)?;
                                if let Some(score) = crate::lexical::score(
                                    anchor,
                                    &resource,
                                    &labels,
                                    config,
                                    g.work.options.limits,
                                )? {
                                    let replace = landed.get(&id).is_none_or(|(_, best, first)| {
                                        score > *best || (score == *best && anchor_index < *first)
                                    });
                                    if replace {
                                        landed.insert(
                                            id.clone(),
                                            (anchor.clone(), score, anchor_index),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                if matches!(&mode, Some(LandingMode::Record { .. })) {
                    let outcome = obj([
                        ("block_index", V::integer(block as u64)),
                        ("role", V::string(role)),
                        ("matched", V::integer(landed.len() as u64)),
                    ]);
                    g.work.retain(&outcome)?;
                    outcomes.push(outcome);
                }
                if landed.is_empty() {
                    notice(&mut notices, "empty_landing");
                }
                if role == "from" && landed.len() as u64 > caps.seed_limit {
                    notice(&mut notices, "seed_limit");
                }
                let mut landed = landed.into_iter().collect::<Vec<_>>();
                landed.sort_by(|(a_id, (_, a_score, _)), (b_id, (_, b_score, _))| {
                    b_score.cmp(a_score).then(a_id.cmp(b_id))
                });
                for (rank, (id, (anchor, score, _))) in landed.into_iter().enumerate() {
                    if role == "from" && rank as u64 >= caps.seed_limit {
                        continue;
                    }
                    landings.push(obj([
                        ("block_index", V::integer(block as u64)),
                        ("role", V::string(role)),
                        ("anchor", V::string(anchor)),
                        ("id", V::string(id.as_str())),
                        ("score", V::integer(score)),
                    ]));
                    if role == "to" {
                        target_set.insert(id);
                    } else {
                        if frontier.len() >= g.work.options.max_frontier {
                            return Err(Error::limit());
                        }
                        frontier.push(Path {
                            block,
                            seed_rank: rank,
                            seed: id.clone(),
                            claims: vec![],
                            endpoints: vec![ClaimObject::Entity(id)],
                            confidence: ExactNumber::from_u64(1),
                            grounding: Grounding::SourceSpansAvailable,
                            target: None,
                            states: initial_states(plan, g)?,
                        });
                    }
                }
            }
            targets.push(target_set);
        }
    }
    if let Some(LandingMode::Record {
        log,
        landings: saved,
        notices: saved_notices,
        raw_count,
        outcomes: saved_outcomes,
    }) = mode
    {
        *saved = landings.clone();
        *saved_outcomes = outcomes;
        *saved_notices = notices
            .iter()
            .filter(|s| matches!(s.as_str(), "empty_landing" | "seed_limit"))
            .cloned()
            .collect();
        *raw_count = log.observations()?.1.len();
    }
    let mut retained = vec![];
    let mut unique = BTreeSet::new();
    let (mut examined, mut eligible, mut traversed) = (0u64, 0u64, 0u64);
    let mut evaluation_ordinal = 0u64;
    let direction = match plan.direction() {
        Direction::Outgoing => contracts::Direction::Outgoing,
        Direction::Incoming => contracts::Direction::Incoming,
        Direction::Both => contracts::Direction::Both,
    };
    notify(runtime, ControllerEvent::TraversalStarted)?;
    while !frontier.is_empty() {
        if frontier.len() > g.work.options.max_frontier {
            return Err(Error::limit());
        }
        frontier.sort_by(|a, b| {
            a.claims
                .len()
                .cmp(&b.claims.len())
                .then(a.block.cmp(&b.block))
                .then(a.seed_rank.cmp(&b.seed_rank))
                .then(a.ids().cmp(&b.ids()))
        });
        let mut next = vec![];
        for parent in frontier {
            let enumeration = read_lane(PredicatePhase::Walk, evaluation_ordinal, u64::MAX, 0);
            evaluation_ordinal = evaluation_ordinal.checked_add(1).ok_or_else(Error::limit)?;
            notify(runtime, ControllerEvent::ReadLane(enumeration.clone()))?;
            g.work.tick(1)?;
            if parent.claims.len() as u64 >= caps.max_depth {
                notice(&mut notices, "max_depth");
                notify(
                    runtime,
                    ControllerEvent::LaneClosed(
                        enumeration.clone(),
                        super::trace::LaneOutcomeV3::Empty,
                    ),
                )?;
                continue;
            }
            let Some(ClaimObject::Entity(node)) = parent.endpoints.last() else {
                notify(
                    runtime,
                    ControllerEvent::LaneClosed(
                        enumeration.clone(),
                        super::trace::LaneOutcomeV3::Empty,
                    ),
                )?;
                continue;
            };
            let raw = g.pages(|v, s, c| v.incident(node, direction, s, c))?;
            let mut candidates = vec![];
            let mut seen = BTreeSet::new();
            for c in raw {
                g.work.retain(&c.response(LifecycleState::Active))?;
                if !seen.insert(c.id().clone()) {
                    continue;
                }
                if let Some(c) = g.usable(c)? {
                    candidates.push(c);
                }
            }
            // Fallible bounded insertion ordering preserves arithmetic failures instead of hiding them.
            for i in 1..candidates.len() {
                let mut j = i;
                while j > 0 {
                    g.work.tick(1)?;
                    let a = &candidates[j - 1].claim;
                    let b = &candidates[j].claim;
                    let order = b
                        .candidate()
                        .confidence()
                        .number()
                        .checked_cmp(a.candidate().confidence().number())?
                        .then(b.transaction_time().cmp(&a.transaction_time()))
                        .then(a.id().cmp(b.id()));
                    if order != Ordering::Greater {
                        break;
                    }
                    candidates.swap(j - 1, j);
                    j -= 1;
                }
            }
            let mut tasks = vec![];
            for c in candidates {
                g.work.tick(1)?;
                examined = examined.checked_add(1).ok_or_else(Error::limit)?;
                let candidate = c.claim.candidate();
                let endpoint =
                    if candidate.subject() == node && plan.direction() != Direction::Incoming {
                        candidate.object().clone()
                    } else if matches!(candidate.object(),ClaimObject::Entity(e) if e==node)
                        && plan.direction() != Direction::Outgoing
                    {
                        ClaimObject::Entity(candidate.subject().clone())
                    } else {
                        return Err(Error::invalid("incident orientation"));
                    };
                let cycle = match plan.cycle_policy() {
                    CyclePolicy::AllowRepeatedClaim => false,
                    CyclePolicy::NoRepeatedClaim => parent.ids().contains(&c.claim.id()),
                    CyclePolicy::NoRepeatedNode => parent.endpoints.contains(&endpoint),
                };
                if cycle {
                    continue;
                }
                let ordinal = evaluation_ordinal;
                evaluation_ordinal = evaluation_ordinal.checked_add(1).ok_or_else(Error::limit)?;
                tasks.push(WalkEvaluation {
                    ordinal,
                    claim: c,
                    endpoint,
                    predicate: 0,
                    proposed: BTreeMap::new(),
                    passes: true,
                    pending: None,
                });
            }
            notify(
                runtime,
                ControllerEvent::LaneClosed(
                    enumeration,
                    if tasks.is_empty() {
                        super::trace::LaneOutcomeV3::Empty
                    } else {
                        super::trace::LaneOutcomeV3::Accepted
                    },
                ),
            )?;
            let window = runtime.map_or(1, |r| r.bounds().max_outstanding);
            let mut pending_bytes = 0usize;
            let mut admitted = 0usize;
            let mut reduced = 0usize;
            let mut passing = 0u64;
            while reduced < tasks.len() {
                while admitted < tasks.len() && admitted - reduced < window {
                    notify(
                        runtime,
                        ControllerEvent::EvaluationOpened {
                            phase: PredicatePhase::Walk,
                            ordinal: tasks[admitted].ordinal,
                        },
                    )?;
                    advance_walk(
                        &mut tasks[admitted],
                        &parent,
                        plan,
                        g,
                        runtime,
                        evaluation_limits,
                        &mut pending_bytes,
                    )?;
                    admitted += 1;
                }
                loop {
                    if let Some((ticket, lane, bytes, dependencies)) = tasks[reduced].pending.take()
                    {
                        let runtime = runtime.ok_or_else(|| {
                            Error::new(ErrorKind::Unsupported, "custom runtime unavailable")
                        })?;
                        let completion = runtime.wait(ticket);
                        runtime.event(ControllerEvent::Completed(completion.lane.clone()))?;
                        if completion.lane != lane {
                            return Err(Error::invalid("controller completion lane"));
                        }
                        pending_bytes = pending_bytes
                            .checked_sub(bytes)
                            .ok_or_else(|| Error::invalid("controller byte accounting"))?;
                        let outcome = completion.outcome?;
                        g.work.retain(&outcome.next)?;
                        if outcome.keep {
                            let predicate = &plan.walk_predicates()[tasks[reduced].predicate];
                            tasks[reduced].proposed.insert(
                                predicate.index(),
                                PredicateState {
                                    value: outcome.next,
                                    dependencies,
                                },
                            );
                            tasks[reduced].predicate += 1;
                        } else {
                            tasks[reduced].passes = false;
                        }
                        runtime.event(ControllerEvent::LaneClosed(
                            lane.clone(),
                            lane_outcome(outcome.keep),
                        ))?;
                        runtime.event(ControllerEvent::Reduced(lane))?;
                        advance_walk(
                            &mut tasks[reduced],
                            &parent,
                            plan,
                            g,
                            Some(runtime),
                            evaluation_limits,
                            &mut pending_bytes,
                        )?;
                        continue;
                    }
                    break;
                }
                let task = &tasks[reduced];
                let mut admission = super::trace::LaneOutcomeV3::Rejected;
                if task.passes && task.predicate == plan.walk_predicates().len() {
                    eligible = eligible.checked_add(1).ok_or_else(Error::limit)?;
                    admission = super::trace::LaneOutcomeV3::CapDenied;
                    if passing >= caps.fanout_limit {
                        notice(&mut notices, "fanout_limit");
                    } else {
                        passing += 1;
                        if !unique.contains(task.claim.claim.id())
                            && unique.len() as u64 >= caps.max_claims
                        {
                            notice(&mut notices, "max_claims");
                        } else {
                            admission = super::trace::LaneOutcomeV3::Accepted;
                            unique.insert(task.claim.claim.id().clone());
                            traversed = traversed.checked_add(1).ok_or_else(Error::limit)?;
                            for state in parent.states.values() {
                                g.work.retain(&state.value)?;
                            }
                            let candidate = task.claim.claim.candidate();
                            let mut path = parent.clone();
                            path.states = task.proposed.clone();
                            path.confidence = path
                                .confidence
                                .checked_mul(candidate.confidence().number())?;
                            if tier(candidate.grounding()) < tier(path.grounding) {
                                path.grounding = candidate.grounding();
                            }
                            path.target = if let ClaimObject::Entity(e) = &task.endpoint {
                                targets[path.block].get(e).cloned()
                            } else {
                                None
                            };
                            path.endpoints.push(task.endpoint.clone());
                            path.claims.push(task.claim.clone());
                            g.work.retain(&path.wire())?;
                            if plan.blocks()[path.block].to().is_none() || path.target.is_some() {
                                if retained.len() >= g.work.options.max_paths {
                                    return Err(Error::limit());
                                }
                                for state in path.states.values() {
                                    g.work.retain(&state.value)?;
                                }
                                retained.push(path.clone());
                            }
                            if matches!(task.endpoint, ClaimObject::Entity(_)) {
                                if next.len() >= g.work.options.max_frontier {
                                    return Err(Error::limit());
                                }
                                next.push(path);
                            }
                        }
                    }
                }
                notify(
                    runtime,
                    ControllerEvent::EvaluationClosed {
                        phase: PredicatePhase::Walk,
                        ordinal: task.ordinal,
                        outcome: admission,
                    },
                )?;
                reduced += 1;
            }
        }
        frontier = next;
    }
    let mut filtered = vec![];
    for path in retained {
        let filter_ordinal = evaluation_ordinal;
        evaluation_ordinal = evaluation_ordinal.checked_add(1).ok_or_else(Error::limit)?;
        notify(
            runtime,
            ControllerEvent::EvaluationOpened {
                phase: PredicatePhase::Filter,
                ordinal: filter_ordinal,
            },
        )?;
        let mut passes = true;
        for predicate in plan.filter_predicates() {
            if let Some(custom) = predicate.custom() {
                // A failed builtin must not trigger later custom effects, while
                // legacy builtin-only filters still validate all later values.
                if !passes {
                    continue;
                }
                let runtime = runtime.ok_or_else(|| {
                    Error::new(ErrorKind::Unsupported, "custom runtime unavailable")
                })?;
                let bare = custom
                    .bindings()
                    .values()
                    .any(|b| matches!(b, CustomBinding::Field(f, _) if !f.is_path()));
                let attempts = if bare { path.claims.len() } else { 1 };
                g.work.tick(path.claims.len() + 1)?;
                let claims = path.claims.iter().collect::<Vec<_>>();
                let mut accepted = false;
                for attempt in 0..attempts {
                    let state = V::Object(custom.program().init.clone());
                    g.work.retain(&state)?;
                    let lane = LaneIdentityV3 {
                        phase: PredicatePhase::Filter,
                        evaluation_ordinal: filter_ordinal,
                        predicate_index: u64::try_from(predicate.index())
                            .map_err(|_| Error::limit())?,
                        attempt: u64::try_from(attempt).map_err(|_| Error::limit())?,
                    };
                    runtime.event(ControllerEvent::ReadLane(lane.clone()))?;
                    g.reset_dependencies();
                    let bindings = custom_bindings(custom, &claims, attempt, g)?;
                    let mut argument_dependencies = g.take_dependencies();
                    for claim in &claims {
                        argument_dependencies.extend(&claim.dependencies);
                    }
                    let job = EvaluationJob {
                        lane: lane.clone(),
                        program: custom.program().clone(),
                        state,
                        bindings,
                        argument_dependencies,
                        state_dependencies: DependencyFootprint::default(),
                        limits: evaluation_limits,
                    };
                    if job.retained_bytes(g.work.options.limits)?
                        > runtime.bounds().validate()?.max_pending_bytes
                    {
                        return Err(Error::limit());
                    }
                    runtime.event(ControllerEvent::Submitted(lane.clone()))?;
                    let ticket = match runtime.submit(job) {
                        Ok(ticket) => ticket,
                        Err(error) => {
                            runtime.event(ControllerEvent::AdmissionRejected(lane.clone()))?;
                            return Err(error);
                        }
                    };
                    if ticket.lane() != &lane {
                        return Err(Error::invalid("controller ticket lane"));
                    }
                    let completion = runtime.wait(ticket);
                    runtime.event(ControllerEvent::Completed(completion.lane.clone()))?;
                    if completion.lane != lane {
                        return Err(Error::invalid("controller completion lane"));
                    }
                    let outcome = completion.outcome?;
                    g.work.retain(&outcome.next)?;
                    runtime.event(ControllerEvent::LaneClosed(
                        lane.clone(),
                        lane_outcome(outcome.keep),
                    ))?;
                    runtime.event(ControllerEvent::Reduced(lane))?;
                    if outcome.keep {
                        accepted = true;
                        break;
                    }
                }
                passes = accepted;
                if !passes {
                    break;
                }
                continue;
            }
            let p = predicate.builtin().ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    "custom predicate runtime unavailable",
                )
            })?;
            let lane = read_lane(
                PredicatePhase::Filter,
                filter_ordinal,
                u64::try_from(predicate.index()).map_err(|_| Error::limit())?,
                0,
            );
            notify(runtime, ControllerEvent::ReadLane(lane.clone()))?;
            g.work.tick(path.claims.len() + 1)?;
            let values = path
                .claims
                .iter()
                .enumerate()
                .map(|(i, c)| field(p, c, i + 1, g))
                .collect::<Result<Vec<_>>>()?;
            let mut accepted = false;
            if p.field().is_path() {
                accepted = evaluate(p, &Value::List(values), g)?;
            } else {
                for value in values {
                    accepted |= evaluate(p, &value, g)?;
                }
            }
            passes &= accepted;
            notify(
                runtime,
                ControllerEvent::LaneClosed(lane, lane_outcome(accepted)),
            )?;
        }
        notify(
            runtime,
            ControllerEvent::EvaluationClosed {
                phase: PredicatePhase::Filter,
                ordinal: filter_ordinal,
                outcome: lane_outcome(passes),
            },
        )?;
        if passes {
            filtered.push(path);
        }
    }
    notify(runtime, ControllerEvent::FinalizationStarted)?;
    for i in 1..filtered.len() {
        let mut j = i;
        while j > 0 {
            g.work.tick(1)?;
            if rank(&filtered[j - 1], &filtered[j])? != Ordering::Greater {
                break;
            }
            filtered.swap(j - 1, j);
            j -= 1;
        }
    }
    if filtered.len() as u64 > caps.path_limit {
        notice(&mut notices, "path_limit");
    }
    filtered.truncate(usize::try_from(caps.path_limit).unwrap_or(usize::MAX));
    let mut claims = BTreeMap::new();
    let mut paths = vec![];
    for path in &filtered {
        paths.push(PathProjection::from_value(&path.wire())?);
        for c in &path.claims {
            claims.insert(c.claim.id().clone(), c.clone());
        }
    }
    let lifecycle = claims
        .iter()
        .map(|(id, c)| {
            obj([
                ("claim_id", V::string(id.as_str())),
                ("rule", V::string("ctxql-execution/v1:lifecycle")),
                ("state", V::string(c.state.as_str())),
                (
                    "supporting_ids",
                    V::Array(c.supports.iter().map(|id| V::string(id.as_str())).collect()),
                ),
            ])
        })
        .collect();
    let explain = ExplainProjection::from_value(&obj([
        (
            "evaluation_context",
            obj([
                ("as_of", V::string(plan.as_of().canonical())),
                ("db_time", g.view.identity().pin().projection()),
                (
                    "profile",
                    plan.projection()
                        .canonical()
                        .payload()
                        .field("artifacts")?
                        .field("profile")?
                        .clone(),
                ),
                ("bounds", plan.normalized_query().field("bounds")?.clone()),
            ]),
        ),
        ("seeds", V::Array(landings)),
        ("ontology_resolution", V::Array(vec![])),
        (
            "traversal_stats",
            obj([
                ("examined", V::integer(examined)),
                ("eligible", V::integer(eligible)),
                ("traversed", V::integer(traversed)),
                ("unique_traversed", V::integer(unique.len() as u64)),
                ("returned_paths", V::integer(paths.len() as u64)),
            ]),
        ),
        ("lifecycle", V::Array(lifecycle)),
    ]))?;
    let status = if notices.is_empty() {
        GraphStatus::Ready
    } else {
        GraphStatus::ReadyWithWarnings
    };
    let mut sources = BTreeMap::new();
    for c in claims.values() {
        for source in c.claim.candidate().lineage().sources() {
            sources.insert(
                source.projection().canonical_bytes(g.work.options.limits)?,
                source.clone(),
            );
        }
    }
    let response = ResponseProjection::new(
        plan.selection(),
        status,
        if stale {
            vec!["stale_snapshot".into()]
        } else {
            vec![]
        },
        notices
            .into_iter()
            .map(|s| Ok(SemanticNotice::new(ResourceId::new(s)?, obj([]))))
            .collect::<Result<Vec<_>>>()?,
        claims
            .into_values()
            .map(|c| ResponseClaim::new(c.claim, c.state))
            .collect(),
        paths,
        Some(explain),
    )?;
    Ok((response, sources.into_values().collect()))
}
fn rank(a: &Path, b: &Path) -> Result<Ordering> {
    Ok(a.claims
        .len()
        .cmp(&b.claims.len())
        .then(b.confidence.checked_cmp(&a.confidence)?)
        .then(tier(b.grounding).cmp(&tier(a.grounding)))
        .then_with(|| {
            b.claims
                .iter()
                .map(|c| c.claim.transaction_time())
                .cmp(a.claims.iter().map(|c| c.claim.transaction_time()))
        })
        .then(a.ids().cmp(&b.ids()))
        .then(a.block.cmp(&b.block))
        .then(a.seed.cmp(&b.seed)))
}
