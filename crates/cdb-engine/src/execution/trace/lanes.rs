use super::{obj, policy_bytes};
use cdb_core::{
    id::{Iri, ResourceId},
    limits::Budget,
    recording::{PolicyObservation, ReadObservation},
    recording_v3::{lane_read, LaneIdentityV3, LanePhaseV3},
    CanonicalValue as V, Error, Limits, Result,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaneOutcomeV3 {
    Empty,
    Accepted,
    Rejected,
    CapDenied,
}
impl LaneOutcomeV3 {
    fn name(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::CapDenied => "cap_denied",
        }
    }
    fn parse(value: &V) -> Result<Self> {
        match value.as_str()? {
            "empty" => Ok(Self::Empty),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            "cap_denied" => Ok(Self::CapDenied),
            _ => Err(Error::invalid("lane outcome")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionCountV3 {
    pub name: ResourceId,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneTraceV3 {
    pub identity: LaneIdentityV3,
    pub outcome: LaneOutcomeV3,
    pub reads: Vec<ReadObservation>,
    pub policy: Vec<PolicyObservation>,
    pub scopes: Vec<ResourceId>,
    pub function_counts: Vec<FunctionCountV3>,
}
impl LaneTraceV3 {
    pub fn projection(&self) -> V {
        V::Object(
            [
                ("identity".into(), self.identity.projection()),
                ("closed".into(), V::Bool(true)),
                ("outcome".into(), V::string(self.outcome.name())),
                (
                    "reads".into(),
                    V::Array(
                        self.reads
                            .iter()
                            .enumerate()
                            .map(|(ordinal, read)| {
                                lane_read(
                                    u64::try_from(ordinal).expect("read ordinal fits u64"),
                                    read,
                                )
                            })
                            .collect(),
                    ),
                ),
                (
                    "policy".into(),
                    V::Array(self.policy.iter().map(policy_value).collect()),
                ),
                (
                    "scopes".into(),
                    V::Array(
                        self.scopes
                            .iter()
                            .map(|scope| V::string(scope.as_str()))
                            .collect(),
                    ),
                ),
                (
                    "function_counts".into(),
                    V::Array(
                        self.function_counts
                            .iter()
                            .map(|call| {
                                obj([
                                    ("count", V::integer(call.count)),
                                    ("name", V::string(call.name.as_str())),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]
            .into_iter()
            .collect(),
        )
    }

    pub fn from_value(value: &V) -> Result<Self> {
        value.closed(
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
        if !value.field("closed")?.as_bool()? {
            return Err(Error::invalid("unclosed lane"));
        }
        let mut reads = Vec::new();
        for (ordinal, entry) in value.field("reads")?.as_array()?.iter().enumerate() {
            entry.closed(&["ordinal", "observation"], &[])?;
            if entry.field("ordinal")?.u64()?
                != u64::try_from(ordinal).map_err(|_| Error::limit())?
            {
                return Err(Error::invalid("local read ordinal"));
            }
            reads.push(read_from_value(entry.field("observation")?)?);
        }
        let policy = value
            .field("policy")?
            .as_array()?
            .iter()
            .map(policy_from_value)
            .collect::<Result<Vec<_>>>()?;
        ensure_unique_policy(&policy)?;
        let scopes = value
            .field("scopes")?
            .as_array()?
            .iter()
            .map(|v| ResourceId::new(v.as_str()?))
            .collect::<Result<Vec<_>>>()?;
        ensure_unique(&scopes, "duplicate lane scope")?;
        let mut function_counts = Vec::new();
        for call in value.field("function_counts")?.as_array()? {
            call.closed(&["count", "name"], &[])?;
            let count = call.field("count")?.u64()?;
            if count == 0 {
                return Err(Error::invalid("zero function count"));
            }
            function_counts.push(FunctionCountV3 {
                name: ResourceId::new(call.field("name")?.as_str()?)?,
                count,
            });
        }
        ensure_function_order(&function_counts)?;
        Ok(Self {
            identity: LaneIdentityV3::from_value(value.field("identity")?)?,
            outcome: LaneOutcomeV3::parse(value.field("outcome")?)?,
            reads,
            policy,
            scopes,
            function_counts,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceDataV3 {
    pub policy: Vec<PolicyObservation>,
    pub reads: Vec<ReadObservation>,
    pub scopes: Vec<ResourceId>,
    pub lanes: Vec<LaneTraceV3>,
    pub expected_lanes: Vec<LaneIdentityV3>,
}
impl TraceDataV3 {
    pub fn lane_values(&self) -> Vec<V> {
        self.lanes.iter().map(LaneTraceV3::projection).collect()
    }
    pub fn expected_lane_values(&self) -> Vec<V> {
        self.expected_lanes
            .iter()
            .map(|lane| lane.projection())
            .collect()
    }
    pub fn from_values(
        policy: Vec<PolicyObservation>,
        reads: Vec<ReadObservation>,
        scopes: Vec<ResourceId>,
        lanes: &[V],
        expected_lanes: &[V],
    ) -> Result<Self> {
        let lanes = lanes
            .iter()
            .map(LaneTraceV3::from_value)
            .collect::<Result<Vec<_>>>()?;
        let expected_lanes = expected_lanes
            .iter()
            .map(LaneIdentityV3::from_value)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            policy,
            reads,
            scopes,
            lanes,
            expected_lanes,
        })
    }
}

#[derive(Clone)]
struct LaneProgress {
    expected: Option<LaneTraceV3>,
    reads: Vec<ReadObservation>,
    policy: Vec<PolicyObservation>,
    scopes: Vec<ResourceId>,
    outcome: Option<LaneOutcomeV3>,
    function_counts: Vec<FunctionCountV3>,
    read_position: usize,
    encountered_policy: BTreeSet<(ResourceId, Option<Iri>)>,
    encountered_scopes: BTreeSet<ResourceId>,
}

pub(super) struct LaneState {
    limits: Limits,
    budget: Budget,
    replay: bool,
    base_policy: Vec<PolicyObservation>,
    base_reads: Vec<ReadObservation>,
    base_scopes: Vec<ResourceId>,
    lanes: BTreeMap<LaneIdentityV3, LaneProgress>,
    expected_lanes: Vec<LaneIdentityV3>,
    entered: BTreeSet<LaneIdentityV3>,
    current: Option<LaneIdentityV3>,
    diverged: bool,
}
impl LaneState {
    pub(super) fn recording(limits: Limits) -> Self {
        Self {
            limits,
            budget: Budget::new(limits),
            replay: false,
            base_policy: vec![],
            base_reads: vec![],
            base_scopes: vec![],
            lanes: BTreeMap::new(),
            expected_lanes: vec![],
            entered: BTreeSet::new(),
            current: None,
            diverged: false,
        }
    }

    pub(super) fn replay(limits: Limits, data: &TraceDataV3) -> Result<Self> {
        ensure_unique_policy(&data.policy)?;
        if data
            .reads
            .iter()
            .enumerate()
            .any(|(i, read)| data.reads[..i].contains(read))
        {
            return Err(Error::invalid("duplicate base read"));
        }
        ensure_unique(&data.scopes, "duplicate base scope")?;
        ensure_strict_order(&data.expected_lanes, "expected lane order/duplicate")?;
        let mut state = Self::recording(limits);
        state.replay = true;
        state.base_policy = data.policy.clone();
        state.base_reads = data.reads.clone();
        state.base_scopes = data.scopes.clone();
        state.expected_lanes = data.expected_lanes.clone();
        for lane in &data.lanes {
            if state
                .lanes
                .insert(lane.identity, LaneProgress::replay(lane.clone()))
                .is_some()
            {
                return Err(Error::invalid("duplicate lane"));
            }
        }
        if state.lanes.keys().copied().collect::<Vec<_>>() != state.expected_lanes
            || state.expected_lanes.first().map(|lane| lane.phase) != Some(LanePhaseV3::Preparation)
        {
            return Err(Error::invalid("missing/extra lanes"));
        }
        for lane in &data.lanes {
            if lane
                .reads
                .iter()
                .any(|read| !state.base_reads.contains(read))
                || lane
                    .policy
                    .iter()
                    .any(|policy| !state.base_policy.contains(policy))
                || lane
                    .scopes
                    .iter()
                    .any(|scope| !state.base_scopes.contains(scope))
            {
                return Err(Error::invalid("lane evidence outside base footprint"));
            }
        }
        if state
            .base_reads
            .iter()
            .any(|read| !data.lanes.iter().any(|lane| lane.reads.contains(read)))
            || state
                .base_policy
                .iter()
                .any(|policy| !data.lanes.iter().any(|lane| lane.policy.contains(policy)))
            || state
                .base_scopes
                .iter()
                .any(|scope| !data.lanes.iter().any(|lane| lane.scopes.contains(scope)))
        {
            return Err(Error::invalid("unassigned base observation"));
        }
        for p in &state.base_policy {
            state.budget.charge(1, policy_bytes(p), policy_bytes(p))?;
        }
        for r in &state.base_reads {
            let n = read_bytes(r, limits)?;
            state.budget.charge(1, n, n)?;
        }
        for s in &state.base_scopes {
            let n = s.as_str().len();
            state.budget.charge(1, n, n)?;
        }
        for lane in &data.lanes {
            let n = lane.projection().canonical_bytes(limits)?.len();
            state.budget.charge(1, n, n)?;
        }
        Ok(state)
    }

    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.budget.charge(1, bytes, bytes)
    }

    pub(super) fn enter(&mut self, identity: LaneIdentityV3) -> Result<()> {
        if self.entered.contains(&identity) {
            return Err(Error::invalid("duplicate lane enter"));
        }
        if self.replay {
            if !self.lanes.contains_key(&identity) {
                return Err(Error::invalid("unexpected lane"));
            }
        } else {
            let n = identity.projection().canonical_bytes(self.limits)?.len();
            self.charge(n)?;
            self.lanes.insert(identity, LaneProgress::recording());
        }
        self.entered.insert(identity);
        self.current = Some(identity);
        Ok(())
    }
    pub(super) fn resume(&mut self, identity: LaneIdentityV3) -> Result<()> {
        let lane = self
            .lanes
            .get(&identity)
            .ok_or_else(|| Error::invalid("unknown lane"))?;
        if lane.outcome.is_some() {
            return Err(Error::invalid("closed lane"));
        }
        if !self.entered.contains(&identity) {
            return Err(Error::invalid("lane not entered"));
        }
        self.current = Some(identity);
        Ok(())
    }
    fn current_mut(&mut self) -> Result<&mut LaneProgress> {
        let id = self
            .current
            .ok_or_else(|| Error::invalid("no active lane"))?;
        self.lanes
            .get_mut(&id)
            .ok_or_else(|| Error::invalid("unknown lane"))
    }
    pub(super) fn prepare_raw(&self, operation: &ResourceId, key: &V) -> Result<()> {
        let id = self
            .current
            .ok_or_else(|| Error::invalid("no active lane"))?;
        let lane = self
            .lanes
            .get(&id)
            .ok_or_else(|| Error::invalid("unknown lane"))?;
        if lane.outcome.is_some() {
            return Err(Error::invalid("closed lane"));
        }
        if self.replay {
            let expected = lane
                .expected
                .as_ref()
                .unwrap()
                .reads
                .get(lane.read_position)
                .ok_or_else(|| Error::invalid("extra RAW observation"))?;
            if &expected.operation != operation || &expected.key != key {
                return Err(Error::invalid("RAW request divergence"));
            }
        }
        Ok(())
    }
    pub(super) fn complete_raw(
        &mut self,
        read: ReadObservation,
        result_bytes: usize,
    ) -> Result<()> {
        if self.replay {
            let lane = self.current_mut()?;
            let expected = &lane.expected.as_ref().unwrap().reads[lane.read_position];
            if expected.result_hash != read.result_hash {
                return Err(Error::invalid("RAW result divergence"));
            }
            lane.read_position += 1;
        } else {
            let base_new = !self.base_reads.contains(&read);
            let n = read_bytes(&read, self.limits)?
                .checked_add(result_bytes)
                .ok_or_else(Error::limit)?;
            self.charge(n)?;
            if base_new {
                self.base_reads.push(read.clone());
            }
            self.current_mut()?.reads.push(read);
        }
        Ok(())
    }
    pub(super) fn policy(
        &mut self,
        resource: &ResourceId,
        predicate: Option<&Iri>,
        call: impl FnOnce() -> Result<bool>,
    ) -> Result<bool> {
        let key = (resource.clone(), predicate.cloned());
        if self.replay {
            let lane = self.current_mut()?;
            let expected = lane
                .expected
                .as_ref()
                .unwrap()
                .policy
                .iter()
                .find(|p| p.resource == key.0 && p.predicate == key.1)
                .ok_or_else(|| Error::invalid("unknown policy observation"))?;
            lane.encountered_policy.insert(key);
            return Ok(expected.allowed);
        }
        let allowed = call()?;
        let observation = PolicyObservation {
            resource: resource.clone(),
            predicate: predicate.cloned(),
            allowed,
        };
        let base_new =
            match self.base_policy.iter().find(|p| {
                p.resource == observation.resource && p.predicate == observation.predicate
            }) {
                Some(old) if old.allowed != allowed => {
                    return Err(Error::new(
                        cdb_core::ErrorKind::PolicyChanged,
                        "contradictory policy decision",
                    ))
                }
                Some(_) => false,
                None => true,
            };
        let lane_new =
            !self.current_mut()?.policy.iter().any(|p| {
                p.resource == observation.resource && p.predicate == observation.predicate
            });
        if base_new || lane_new {
            let unit = policy_bytes(&observation);
            let n = unit
                .checked_mul(usize::from(base_new) + usize::from(lane_new))
                .ok_or_else(Error::limit)?;
            self.charge(n)?;
        }
        if base_new {
            self.base_policy.push(observation.clone());
        }
        if lane_new {
            self.current_mut()?.policy.push(observation);
        }
        Ok(allowed)
    }
    pub(super) fn scope(&mut self, scope: &ResourceId) -> Result<()> {
        if self.replay {
            let lane = self.current_mut()?;
            if !lane.expected.as_ref().unwrap().scopes.contains(scope) {
                return Err(Error::invalid("unknown scope observation"));
            }
            lane.encountered_scopes.insert(scope.clone());
        } else {
            let base_new = !self.base_scopes.contains(scope);
            let lane_new = !self.current_mut()?.scopes.contains(scope);
            if base_new || lane_new {
                let n = scope
                    .as_str()
                    .len()
                    .checked_mul(usize::from(base_new) + usize::from(lane_new))
                    .ok_or_else(Error::limit)?;
                self.charge(n)?;
            }
            if base_new {
                self.base_scopes.push(scope.clone());
            }
            if lane_new {
                self.current_mut()?.scopes.push(scope.clone());
            }
        }
        Ok(())
    }
    pub(super) fn close(
        &mut self,
        outcome: LaneOutcomeV3,
        mut counts: Vec<FunctionCountV3>,
        defer_divergence: bool,
    ) -> Result<()> {
        counts.sort_by(|a, b| a.name.cmp(&b.name));
        ensure_function_order(&counts)?;
        let id = self
            .current
            .ok_or_else(|| Error::invalid("no active lane"))?;
        let lane = self
            .lanes
            .get(&id)
            .ok_or_else(|| Error::invalid("unknown lane"))?;
        if lane.outcome.is_some() {
            return Err(Error::invalid("lane already closed"));
        }
        let diverged = if self.replay {
            let expected = lane.expected.as_ref().unwrap();
            expected.outcome != outcome || expected.function_counts != counts
        } else {
            false
        };
        if diverged && !defer_divergence {
            return Err(Error::invalid("lane close divergence"));
        }
        if !self.replay {
            let bytes = counts.iter().try_fold(1usize, |n, c| {
                n.checked_add(c.name.as_str().len())
                    .and_then(|n| n.checked_add(8))
                    .ok_or_else(Error::limit)
            })?;
            self.charge(bytes)?;
        }
        let lane = self.lanes.get_mut(&id).expect("lane checked");
        lane.outcome = Some(outcome);
        lane.function_counts = counts;
        self.current = None;
        self.diverged |= diverged;
        Ok(())
    }
    pub(super) fn remaining_reads(&self, identity: LaneIdentityV3) -> Result<Vec<ReadObservation>> {
        let lane = self
            .lanes
            .get(&identity)
            .ok_or_else(|| Error::invalid("unknown lane"))?;
        let expected = lane
            .expected
            .as_ref()
            .ok_or_else(|| Error::invalid("not replay"))?;
        Ok(expected.reads[lane.read_position..].to_vec())
    }
    pub(super) fn finish(&self) -> Result<TraceDataV3> {
        let actual = self.entered.iter().copied().collect::<Vec<_>>();
        if actual.first().map(|lane| lane.phase) != Some(LanePhaseV3::Preparation)
            || (self.replay && actual != self.expected_lanes)
        {
            return Err(Error::invalid("missing/extra lanes"));
        }
        if self.lanes.values().any(|lane| lane.outcome.is_none()) {
            return Err(Error::invalid("unclosed lane"));
        }
        let mut lanes = Vec::new();
        for (identity, lane) in &self.lanes {
            if self.replay {
                let expected = lane.expected.as_ref().unwrap();
                if lane.read_position != expected.reads.len()
                    || lane.encountered_policy.len() != expected.policy.len()
                    || lane.encountered_scopes.len() != expected.scopes.len()
                {
                    return Err(Error::invalid("missing lane observations"));
                }
                lanes.push(expected.clone());
            } else {
                lanes.push(LaneTraceV3 {
                    identity: *identity,
                    outcome: lane.outcome.unwrap(),
                    reads: lane.reads.clone(),
                    policy: lane.policy.clone(),
                    scopes: lane.scopes.clone(),
                    function_counts: lane.function_counts.clone(),
                });
            }
        }
        if self.diverged {
            return Err(Error::invalid("lane close divergence"));
        }
        Ok(TraceDataV3 {
            policy: self.base_policy.clone(),
            reads: self.base_reads.clone(),
            scopes: self.base_scopes.clone(),
            lanes,
            expected_lanes: actual,
        })
    }
}
impl LaneProgress {
    fn recording() -> Self {
        Self {
            expected: None,
            reads: vec![],
            policy: vec![],
            scopes: vec![],
            outcome: None,
            function_counts: vec![],
            read_position: 0,
            encountered_policy: BTreeSet::new(),
            encountered_scopes: BTreeSet::new(),
        }
    }
    fn replay(expected: LaneTraceV3) -> Self {
        Self {
            expected: Some(expected),
            ..Self::recording()
        }
    }
}
fn policy_value(p: &PolicyObservation) -> V {
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
}
fn policy_from_value(v: &V) -> Result<PolicyObservation> {
    v.closed(&["resource", "predicate", "allowed"], &[])?;
    Ok(PolicyObservation {
        resource: ResourceId::new(v.field("resource")?.as_str()?)?,
        predicate: if *v.field("predicate")? == V::Null {
            None
        } else {
            Some(Iri::new(v.field("predicate")?.as_str()?)?)
        },
        allowed: v.field("allowed")?.as_bool()?,
    })
}
fn read_from_value(v: &V) -> Result<ReadObservation> {
    v.closed(&["operation", "key", "result_hash"], &[])?;
    Ok(ReadObservation {
        operation: ResourceId::new(v.field("operation")?.as_str()?)?,
        key: v.field("key")?.clone(),
        result_hash: cdb_core::id::ContentHash::parse(v.field("result_hash")?.as_str()?)?,
    })
}
fn read_bytes(r: &ReadObservation, limits: Limits) -> Result<usize> {
    r.key
        .canonical_bytes(limits)?
        .len()
        .checked_add(r.operation.as_str().len())
        .and_then(|n| n.checked_add(r.result_hash.as_str().len()))
        .ok_or_else(Error::limit)
}
fn ensure_unique<T: Ord + Clone>(values: &[T], message: &'static str) -> Result<()> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|v| !seen.insert(v.clone())) {
        Err(Error::invalid(message))
    } else {
        Ok(())
    }
}
fn ensure_unique_policy(values: &[PolicyObservation]) -> Result<()> {
    let mut seen = BTreeMap::new();
    for p in values {
        if seen
            .insert((p.resource.clone(), p.predicate.clone()), p.allowed)
            .is_some()
        {
            return Err(Error::invalid("duplicate base policy"));
        }
    }
    Ok(())
}
fn ensure_strict_order<T: Ord>(values: &[T], message: &'static str) -> Result<()> {
    if values.windows(2).any(|w| w[0] >= w[1]) {
        Err(Error::invalid(message))
    } else {
        Ok(())
    }
}
fn ensure_function_order(values: &[FunctionCountV3]) -> Result<()> {
    if values.iter().any(|c| c.count == 0) || values.windows(2).any(|w| w[0].name >= w[1].name) {
        Err(Error::invalid("function count order/duplicate"))
    } else {
        Ok(())
    }
}
