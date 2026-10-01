//! Bounded delayed encounter-index assignment. Physical completion order is not
//! function identity. Only completed logical evaluation groups advance the head.
#[cfg(test)]
mod tests;
use cdb_core::{
    artifact::{FunctionManifest, PublishedArtifact},
    function_manifest::ExternalFunctionManifest,
    function_stream::FunctionRootStream,
    id::{ContentHash, ResourceId},
    projection::FunctionCallProjection,
    recording_v3::{LaneIdentityV3, LanePhaseV3},
    CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EffectGroup {
    pub phase: LanePhaseV3,
    pub evaluation: u64,
}
impl From<LaneIdentityV3> for EffectGroup {
    fn from(lane: LaneIdentityV3) -> Self {
        Self {
            phase: lane.phase,
            evaluation: lane.evaluation,
        }
    }
}
#[derive(Clone, Copy)]
pub struct EffectLimits {
    pub max_groups: usize,
    pub max_calls: u64,
    pub max_pending_bytes: usize,
    /// Reserved exclusively for the earliest group, independent of tail pressure.
    pub head_bytes: usize,
    pub values: Limits,
}
#[derive(Clone)]
pub struct EffectLedger(Arc<Mutex<State>>);
struct State {
    limits: EffectLimits,
    groups: VecDeque<Group>,
    last_group: Option<EffectGroup>,
    functions: BTreeMap<String, Function>,
    total_calls: u64,
    tail_bytes: usize,
    head_bytes: usize,
    failure: Option<Error>,
    finished: bool,
}
struct Group {
    id: EffectGroup,
    closed: bool,
    last_call: Option<(LaneIdentityV3, u64)>,
    calls: VecDeque<Call>,
}
struct Call {
    lane: LaneIdentityV3,
    ordinal: u64,
    name: String,
    input: V,
    output: Option<V>,
    reserved: usize,
    head: bool,
    owner: Option<Box<dyn Send>>,
}
struct Function {
    manifest: Arc<ExternalFunctionManifest>,
    identity: FunctionManifest,
    provider: ResourceId,
    input: FunctionRootStream,
    output: FunctionRootStream,
    count: u64,
}
pub struct CompletedFunction {
    pub manifest: Arc<ExternalFunctionManifest>,
    pub provider: ResourceId,
    pub count: u64,
    pub input_root: ContentHash,
    pub output_root: ContentHash,
}
impl CompletedFunction {
    pub fn recording_value(&self, limits: Limits) -> Result<V> {
        let source = std::str::from_utf8(self.manifest.exact_bytes())
            .map_err(|_| Error::invalid("function manifest source utf-8"))?;
        let value = V::Object(
            [
                ("name", V::string(self.manifest.name().as_str())),
                ("manifest", self.manifest.artifact().projection()),
                ("source", V::string(source)),
                ("deterministic", V::Bool(self.manifest.deterministic())),
                (
                    "replay",
                    V::string(if self.manifest.deterministic() {
                        "exact"
                    } else {
                        "unavailable"
                    }),
                ),
                ("count", V::integer(self.count)),
                ("input_root", V::string(self.input_root.as_str())),
                ("output_root", V::string(self.output_root.as_str())),
                (
                    "destinations",
                    V::Array(vec![V::string(self.provider.as_str())]),
                ),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
        );
        value.canonical_bytes(limits)?;
        Ok(value)
    }
}
/// Dropping an unfinished call is a sticky failure, never an omitted observation.
pub struct PendingEffect {
    ledger: EffectLedger,
    group: EffectGroup,
    lane: LaneIdentityV3,
    ordinal: u64,
    max_output: usize,
    completed: bool,
}
impl Drop for PendingEffect {
    fn drop(&mut self) {
        if !self.completed {
            self.ledger.fail(Error::new(
                ErrorKind::Deadline,
                "unfinished function effect",
            ));
        }
    }
}
impl PendingEffect {
    pub fn complete(mut self, output: &V) -> Result<()> {
        self.complete_owned_inner(output, None)
    }
    pub fn complete_owned(mut self, output: &V, owner: Box<dyn Send>) -> Result<()> {
        self.complete_owned_inner(output, Some(owner))
    }
    fn complete_owned_inner(&mut self, output: &V, owner: Option<Box<dyn Send>>) -> Result<()> {
        let result = self.ledger.complete(
            self.group,
            self.lane,
            self.ordinal,
            output,
            self.max_output,
            owner,
        );
        self.completed = true;
        if let Err(error) = &result {
            self.ledger.fail(error.clone());
        }
        result
    }
}
impl EffectLedger {
    pub fn new(
        limits: EffectLimits,
        bindings: Vec<(Arc<ExternalFunctionManifest>, ResourceId)>,
    ) -> Result<Self> {
        if limits.max_groups == 0
            || limits.head_bytes == 0
            || limits.head_bytes > limits.max_pending_bytes
        {
            return Err(Error::limit());
        }
        let mut functions = BTreeMap::new();
        for (manifest, provider) in bindings {
            let source = PublishedArtifact::new(
                manifest.artifact().clone(),
                manifest.exact_bytes().to_vec(),
                limits.values,
            )?;
            let identity =
                FunctionManifest::from_published(manifest.name().clone(), &source, limits.values)?;
            if identity.version() != manifest.version() {
                return Err(Error::invalid("function and manifest version mismatch"));
            }
            let function = Function {
                input: FunctionRootStream::new(false, &identity, limits.values, limits.max_calls)?,
                output: FunctionRootStream::new(true, &identity, limits.values, limits.max_calls)?,
                identity,
                manifest: manifest.clone(),
                provider,
                count: 0,
            };
            if functions
                .insert(manifest.name().as_str().to_owned(), function)
                .is_some()
            {
                return Err(Error::invalid("duplicate function binding"));
            }
        }
        Ok(Self(Arc::new(Mutex::new(State {
            limits,
            groups: VecDeque::new(),
            last_group: None,
            functions,
            total_calls: 0,
            tail_bytes: 0,
            head_bytes: 0,
            failure: None,
            finished: false,
        }))))
    }
    fn fail(&self, error: Error) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.failure.is_none() {
            state.failure = Some(error);
        }
    }
    /// Controller calls this in semantic candidate order, including zero-call groups.
    pub fn open_group(&self, id: EffectGroup) -> Result<()> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.check()?;
        if state.groups.len() >= state.limits.max_groups {
            return Err(Error::limit());
        }
        if state.last_group.is_some_and(|old| old >= id) {
            return Err(Error::invalid("effect group order"));
        }
        state.groups.push_back(Group {
            id,
            closed: false,
            last_call: None,
            calls: VecDeque::new(),
        });
        state.last_group = Some(id);
        Ok(())
    }
    /// Reserve both argument and worst-case output BEFORE broker disclosure.
    pub fn begin(
        &self,
        lane: LaneIdentityV3,
        ordinal: u64,
        name: &str,
        input: &V,
        max_output: usize,
    ) -> Result<PendingEffect> {
        let result = self.begin_inner(lane, ordinal, name, input, max_output);
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }
    fn begin_inner(
        &self,
        lane: LaneIdentityV3,
        ordinal: u64,
        name: &str,
        input: &V,
        max_output: usize,
    ) -> Result<PendingEffect> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.check()?;
        if !state.functions.contains_key(name) {
            return Err(Error::invalid("unbound recorded function"));
        }
        let reserved = input
            .canonical_bytes(state.limits.values)?
            .len()
            .checked_add(max_output)
            .and_then(|n| n.checked_add(name.len()))
            .and_then(|n| n.checked_add(128))
            .ok_or_else(Error::limit)?;
        let group = EffectGroup::from(lane);
        let position = state
            .groups
            .iter()
            .position(|g| g.id == group)
            .ok_or_else(|| Error::invalid("unknown effect group"))?;
        let entry = &state.groups[position];
        if entry.closed || entry.last_call.is_some_and(|old| old >= (lane, ordinal)) {
            return Err(Error::invalid("effect callback order"));
        }
        let expected = match entry.last_call {
            Some((old, n)) if old == lane => n.checked_add(1).ok_or_else(Error::limit)?,
            _ => 0,
        };
        if ordinal != expected {
            return Err(Error::invalid("effect callback ordinal"));
        }
        let head = position == 0;
        let held = if head {
            state.head_bytes
        } else {
            state.tail_bytes
        };
        let maximum = if head {
            state.limits.head_bytes
        } else {
            state.limits.max_pending_bytes - state.limits.head_bytes
        };
        let bytes = held.checked_add(reserved).ok_or_else(Error::limit)?;
        let count = state.total_calls.checked_add(1).ok_or_else(Error::limit)?;
        if bytes > maximum || count > state.limits.max_calls {
            return Err(Error::limit());
        }
        state.total_calls = count;
        if head {
            state.head_bytes = bytes;
        } else {
            state.tail_bytes = bytes;
        }
        let entry = &mut state.groups[position];
        entry.last_call = Some((lane, ordinal));
        entry.calls.push_back(Call {
            lane,
            ordinal,
            name: name.to_owned(),
            input: input.clone(),
            output: None,
            reserved,
            head,
            owner: None,
        });
        Ok(PendingEffect {
            ledger: self.clone(),
            group,
            lane,
            ordinal,
            max_output,
            completed: false,
        })
    }
    fn complete(
        &self,
        group: EffectGroup,
        lane: LaneIdentityV3,
        ordinal: u64,
        output: &V,
        max_output: usize,
        owner: Option<Box<dyn Send>>,
    ) -> Result<()> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.check()?;
        if output.canonical_bytes(state.limits.values)?.len() > max_output {
            return Err(Error::limit());
        }
        let call = state
            .groups
            .iter_mut()
            .find(|g| g.id == group)
            .and_then(|g| {
                g.calls
                    .iter_mut()
                    .find(|c| c.lane == lane && c.ordinal == ordinal)
            })
            .ok_or_else(|| Error::invalid("missing effect completion"))?;
        if call.output.is_some() {
            return Err(Error::invalid("duplicate effect completion"));
        }
        call.output = Some(output.clone());
        call.owner = owner;
        state.drain()
    }
    /// Close only after ALL reached predicates/attempts in the candidate complete.
    pub fn close_group(&self, id: EffectGroup) -> Result<()> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.check()?;
        let group = state
            .groups
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or_else(|| Error::invalid("unknown effect group"))?;
        if group.closed || group.calls.iter().any(|c| c.output.is_none()) {
            return Err(Error::invalid("unclosed effect callback"));
        }
        group.closed = true;
        state.drain()
    }
    pub fn pending_bytes(&self) -> Result<usize> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.check()?;
        state
            .head_bytes
            .checked_add(state.tail_bytes)
            .ok_or_else(Error::limit)
    }
    pub fn finish(&self) -> Result<Vec<CompletedFunction>> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.check()?;
        if !state.groups.is_empty() || state.tail_bytes != 0 || state.head_bytes != 0 {
            return Err(Error::invalid("unclosed effect groups"));
        }
        state.finished = true;
        std::mem::take(&mut state.functions)
            .into_values()
            .filter(|f| f.count != 0)
            .map(|f| {
                Ok(CompletedFunction {
                    manifest: f.manifest,
                    provider: f.provider,
                    count: f.count,
                    input_root: f.input.finish()?,
                    output_root: f.output.finish()?,
                })
            })
            .collect()
    }
}
impl State {
    fn check(&self) -> Result<()> {
        if self.finished {
            return Err(Error::invalid("effect ledger finished"));
        }
        self.failure.clone().map_or(Ok(()), Err)
    }
    fn drain(&mut self) -> Result<()> {
        loop {
            let Some(group) = self.groups.front_mut() else {
                return Ok(());
            };
            if group.calls.front().is_some_and(|c| c.output.is_some()) {
                let call = group.calls.pop_front().expect("completed head");
                let function = self
                    .functions
                    .get_mut(&call.name)
                    .expect("validated binding");
                let input = FunctionCallProjection::new(
                    false,
                    &function.identity,
                    function.count,
                    call.input,
                )?
                .canonical()
                .hash(self.limits.values)?;
                let output = FunctionCallProjection::new(
                    true,
                    &function.identity,
                    function.count,
                    call.output.expect("completed output"),
                )?
                .canonical()
                .hash(self.limits.values)?;
                function.input.push(&input)?;
                function.output.push(&output)?;
                function.count = function.count.checked_add(1).ok_or_else(Error::limit)?;
                if call.head {
                    self.head_bytes -= call.reserved;
                } else {
                    self.tail_bytes -= call.reserved;
                }
            } else if group.closed && group.calls.is_empty() {
                self.groups.pop_front();
            } else {
                return Ok(());
            }
        }
    }
}
