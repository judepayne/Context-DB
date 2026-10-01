//! Bounded tracing data, never an authorization seal.
mod lanes;
pub use cdb_core::recording_v3::{LaneIdentityV3, LanePhaseV3};
pub use lanes::{FunctionCountV3, LaneOutcomeV3, LaneTraceV3, TraceDataV3};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    fn id() -> ResourceId {
        ResourceId::new("urn:test:r").unwrap()
    }
    fn snapshot() -> SnapshotRef {
        SnapshotRef::new(
            BackendId::new("urn:test:backend").unwrap(),
            GraphPin::new(
                AuthorityId::new("urn:test:authority").unwrap(),
                GraphId::new("urn:test:graph").unwrap(),
                VersionId::new("1").unwrap(),
                id(),
            ),
        )
    }
    struct Raw(SnapshotRef);
    impl RawQueryView for Raw {
        fn identity(&self) -> &SnapshotRef {
            &self.0
        }
        fn claim(&self, _: &ClaimId) -> Result<Option<AdmittedClaim>> {
            Ok(None)
        }
        fn entity(&self, _: &EntityId) -> Result<Option<Vec<DependencyRecord>>> {
            Ok(Some(vec![]))
        }
        fn resource(&self, _: &ResourceId) -> Result<Option<DependencyRecord>> {
            Ok(None)
        }
        fn incident(
            &self,
            _: &EntityId,
            _: Direction,
            size: PageSize,
            _: Option<&PageCursor>,
        ) -> Result<Page<AdmittedClaim>> {
            Page::new(vec![], self.0.clone(), None, size)
        }
        fn lifecycle(
            &self,
            _: &ClaimId,
            size: PageSize,
            _: Option<&PageCursor>,
        ) -> Result<Page<ExportRecord>> {
            Page::new(vec![], self.0.clone(), None, size)
        }
    }
    struct Policy(AtomicBool);
    impl PolicyService for Policy {
        type Principal = ();
        type Context = ();
        fn current<'a>(&'a self, _: &'a ()) -> IoFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn resource_allowed(&self, _: &(), _: &ResourceId) -> Result<bool> {
            Ok(self.0.load(Ordering::SeqCst))
        }
        fn fact_allowed(&self, c: &(), r: &ResourceId, _: &Iri) -> Result<bool> {
            self.resource_allowed(c, r)
        }
        fn publish<'a>(
            &'a self,
            _: &'a (),
            _: &'a (),
            sink: &'a mut (dyn FnMut() -> Result<()> + Send),
        ) -> IoFuture<'a, ()> {
            Box::pin(async move { sink() })
        }
    }
    #[test]
    fn negative_empty_cursor_identity() {
        let raw = Raw(snapshot());
        let log = TraceLog::new_recording(Limits::default());
        let v = RecordingRawView::new(&raw, log.clone());
        assert_eq!(v.identity(), raw.identity());
        v.resource(&id()).unwrap();
        v.claim(&ClaimId::new("urn:test:c").unwrap()).unwrap();
        v.entity(&EntityId::new("urn:test:e").unwrap()).unwrap();
        let c = PageCursor::new(snapshot(), id(), VersionId::new("2").unwrap());
        v.incident(
            &EntityId::new("urn:test:e").unwrap(),
            Direction::Incoming,
            PageSize::new(2).unwrap(),
            Some(&c),
        )
        .unwrap();
        v.lifecycle(
            &ClaimId::new("urn:test:c").unwrap(),
            PageSize::new(3).unwrap(),
            None,
        )
        .unwrap();
        let (_, r) = log.finish().unwrap();
        assert_eq!(r.len(), 5);
        let replay = TraceLog::new_replay(Limits::default(), &[], &r).unwrap();
        replay.verify_prefix(&raw, 5, || Ok(())).unwrap();
        replay.finish().unwrap();
        assert_ne!(r[0].result_hash, r[2].result_hash);
        assert_eq!(r[3].key.field("cursor").unwrap(), &cursor(Some(&c)));
        assert_eq!(
            r[3].key.field("direction").unwrap().as_str().unwrap(),
            "incoming"
        );
    }
    #[test]
    fn overbudget() {
        let log = TraceLog::new_recording(Limits::new(20, 64, 1000, 1000, 1000).unwrap());
        assert!(!log.policy(&id(), None, || Ok(false)).unwrap());
        assert_eq!(
            log.policy(&ResourceId::new("urn:test:other").unwrap(), None, || Ok(
                false
            ))
            .unwrap_err()
            .kind,
            ErrorKind::Limit
        );
        assert!(log.finish().is_err());
        let log = TraceLog::new_recording(Limits::new(1000, 64, 0, 1000, 1000).unwrap());
        assert_eq!(
            log.policy(&id(), None, || Ok(false)).unwrap_err().kind,
            ErrorKind::Limit
        );
    }
    #[test]
    fn late_grant_frozen() {
        let p = Policy(AtomicBool::new(false));
        let log = TraceLog::new_recording(Limits::default());
        let w = RecordingPolicy::new(&p, log.clone());
        let pred = Iri::new("urn:test:p").unwrap();
        assert!(!w.resource_allowed(&(), &id()).unwrap());
        assert!(!w.fact_allowed(&(), &id(), &pred).unwrap());
        let (ps, rs) = log.finish().unwrap();
        p.0.store(true, Ordering::SeqCst);
        let replay = TraceLog::new_replay(Limits::default(), &ps, &rs).unwrap();
        let w = RecordingPolicy::new(&p, replay.clone());
        assert!(!w.resource_allowed(&(), &id()).unwrap());
        assert!(!w.fact_allowed(&(), &id(), &pred).unwrap());
        replay.finish().unwrap();
    }
    #[test]
    fn revoked_true() {
        let p = Policy(AtomicBool::new(false));
        let obs = PolicyObservation {
            resource: id(),
            predicate: None,
            allowed: true,
        };
        let log = TraceLog::new_replay(Limits::default(), &[obs], &[]).unwrap();
        assert_eq!(
            RecordingPolicy::new(&p, log)
                .resource_allowed(&(), &id())
                .unwrap_err()
                .kind,
            ErrorKind::Denied
        );
    }
    #[test]
    fn conflict() {
        let log = TraceLog::new_recording(Limits::default());
        log.policy(&id(), None, || Ok(false)).unwrap();
        log.policy(&id(), None, || Ok(false)).unwrap();
        assert_eq!(log.observations().unwrap().0.len(), 1);
        assert_eq!(
            log.policy(&id(), None, || Ok(true)).unwrap_err().kind,
            ErrorKind::PolicyChanged
        );
        assert!(log.finish().is_err());
    }
    #[test]
    fn raw_mismatch_missing_and_failure() {
        let raw = Raw(snapshot());
        let log = TraceLog::new_recording(Limits::default());
        RecordingRawView::new(&raw, log.clone())
            .resource(&id())
            .unwrap();
        let (p, r) = log.finish().unwrap();
        let replay = TraceLog::new_replay(Limits::default(), &p, &r).unwrap();
        assert!(replay.finish().is_err());
        let replay = TraceLog::new_replay(Limits::default(), &p, &r).unwrap();
        let w = RecordingRawView::new(&raw, replay.clone());
        w.resource(&id()).unwrap();
        replay.finish().unwrap();
        assert!(w.resource(&id()).is_err());
        let mut changed = r.clone();
        changed[0].result_hash = ContentHash::of_bytes(b"different");
        let replay = TraceLog::new_replay(Limits::default(), &p, &changed).unwrap();
        assert!(RecordingRawView::new(&raw, replay.clone())
            .resource(&id())
            .is_err());
        assert!(replay.finish().is_err());
        let replay = TraceLog::new_replay(Limits::default(), &p, &r).unwrap();
        assert!(RecordingRawView::new(&raw, replay)
            .resource(&ResourceId::new("urn:test:other").unwrap())
            .is_err());
        let log = TraceLog::new_recording(Limits::default());
        let result: Result<()> = log.raw(
            "resource",
            V::Null,
            || Err(Error::invalid("adapter failed")),
            |_, _| Ok(V::Null),
        );
        assert!(result.is_err());
        assert!(log.finish().is_err());
    }

    fn lane(phase: LanePhaseV3, evaluation: u64) -> LaneIdentityV3 {
        LaneIdentityV3 {
            phase,
            evaluation,
            predicate: 0,
            attempt: 0,
            ordinal: 0,
        }
    }

    #[test]
    fn v3_out_of_order_resume_retains_repeated_negative_reads() {
        let raw = Raw(snapshot());
        let prep = lane(LanePhaseV3::Preparation, 0);
        let later = lane(LanePhaseV3::Walk, 2);
        let log = TraceLog::new_recording_v3(Limits::default());
        log.enter_lane(later).unwrap();
        let view = RecordingRawView::new(&raw, log.clone());
        view.resource(&id()).unwrap();
        log.enter_lane(prep).unwrap();
        log.close_lane(LaneOutcomeV3::Empty, vec![]).unwrap();
        log.resume_lane(later).unwrap();
        view.resource(&id()).unwrap();
        log.close_lane(LaneOutcomeV3::Rejected, vec![]).unwrap();
        let trace = log.finish_v3().unwrap();
        assert_eq!(trace.expected_lanes, vec![prep, later]);
        assert_eq!(trace.reads.len(), 1, "base reads are deduplicated");
        assert_eq!(trace.lanes[1].reads.len(), 2, "occurrences remain ordered");

        let replay = TraceLog::new_replay_v3(Limits::default(), &trace).unwrap();
        replay.enter_lane(prep).unwrap();
        replay.close_lane(LaneOutcomeV3::Empty, vec![]).unwrap();
        replay.enter_lane(later).unwrap();
        let view = RecordingRawView::new(&raw, replay.clone());
        view.resource(&id()).unwrap();
        view.resource(&id()).unwrap();
        replay.close_lane(LaneOutcomeV3::Rejected, vec![]).unwrap();
        replay.finish_v3().unwrap();
    }

    #[test]
    fn v3_frozen_false_and_true_never_consult_current_policy() {
        let policy = Policy(AtomicBool::new(false));
        let prep = lane(LanePhaseV3::Preparation, 0);
        let log = TraceLog::new_recording_v3(Limits::default());
        log.enter_lane(prep).unwrap();
        let wrapped = RecordingPolicy::new(&policy, log.clone());
        assert!(!wrapped.resource_allowed(&(), &id()).unwrap());
        policy.0.store(true, Ordering::SeqCst);
        let predicate = Iri::new("urn:test:p").unwrap();
        assert!(wrapped.fact_allowed(&(), &id(), &predicate).unwrap());
        log.close_lane(LaneOutcomeV3::Accepted, vec![]).unwrap();
        let trace = log.finish_v3().unwrap();

        let replay = TraceLog::new_replay_v3(Limits::default(), &trace).unwrap();
        replay.enter_lane(prep).unwrap();
        let wrapped = RecordingPolicy::new(&policy, replay.clone());
        assert!(!wrapped.resource_allowed(&(), &id()).unwrap());
        policy.0.store(false, Ordering::SeqCst);
        assert!(wrapped.fact_allowed(&(), &id(), &predicate).unwrap());
        replay.close_lane(LaneOutcomeV3::Accepted, vec![]).unwrap();
        replay.finish_v3().unwrap();
    }

    #[test]
    fn v3_rejects_missing_extra_policy_and_lanes() {
        let prep = lane(LanePhaseV3::Preparation, 0);
        let walk = lane(LanePhaseV3::Walk, 1);
        let policy = Policy(AtomicBool::new(false));
        let log = TraceLog::new_recording_v3(Limits::default());
        log.enter_lane(prep).unwrap();
        RecordingPolicy::new(&policy, log.clone())
            .resource_allowed(&(), &id())
            .unwrap();
        log.observe_scope(&ResourceId::new("urn:test:scope").unwrap())
            .unwrap();
        log.close_lane(LaneOutcomeV3::Empty, vec![]).unwrap();
        log.enter_lane(walk).unwrap();
        log.close_lane(LaneOutcomeV3::Empty, vec![]).unwrap();
        let trace = log.finish_v3().unwrap();

        let missing = TraceLog::new_replay_v3(Limits::default(), &trace).unwrap();
        missing.enter_lane(prep).unwrap();
        missing.close_lane(LaneOutcomeV3::Empty, vec![]).unwrap();
        assert!(missing.finish_v3().is_err());

        let missing_policy = TraceLog::new_replay_v3(Limits::default(), &trace).unwrap();
        missing_policy.enter_lane(prep).unwrap();
        missing_policy
            .close_lane(LaneOutcomeV3::Empty, vec![])
            .unwrap();
        missing_policy.enter_lane(walk).unwrap();
        missing_policy
            .close_lane(LaneOutcomeV3::Empty, vec![])
            .unwrap();
        assert!(missing_policy.finish_v3().is_err());

        let extra_policy = TraceLog::new_replay_v3(Limits::default(), &trace).unwrap();
        extra_policy.enter_lane(prep).unwrap();
        let predicate = Iri::new("urn:test:extra").unwrap();
        assert!(RecordingPolicy::new(&policy, extra_policy.clone())
            .fact_allowed(&(), &id(), &predicate)
            .is_err());
        assert!(
            extra_policy.finish_v3().is_err(),
            "policy failure is sticky"
        );

        let extra_scope = TraceLog::new_replay_v3(Limits::default(), &trace).unwrap();
        extra_scope.enter_lane(prep).unwrap();
        assert!(extra_scope
            .observe_scope(&ResourceId::new("urn:test:extra-scope").unwrap())
            .is_err());

        let extra = TraceLog::new_replay_v3(Limits::default(), &trace).unwrap();
        assert!(extra.enter_lane(lane(LanePhaseV3::Filter, 9)).is_err());
        assert!(extra.finish_v3().is_err(), "lane failure is sticky");

        let unclosed = TraceLog::new_recording_v3(Limits::default());
        unclosed.enter_lane(prep).unwrap();
        assert!(unclosed.finish_v3().is_err());
    }

    #[test]
    fn v3_preparation_replay_verifies_saved_raw_without_resolver() {
        let raw = Raw(snapshot());
        let prep = lane(LanePhaseV3::Preparation, 0);
        let log = TraceLog::new_recording_v3(Limits::default());
        log.enter_lane(prep).unwrap();
        RecordingRawView::new(&raw, log.clone())
            .resource(&id())
            .unwrap();
        log.close_lane(LaneOutcomeV3::Empty, vec![]).unwrap();
        let trace = log.finish_v3().unwrap();

        let replay = TraceLog::new_replay_v3(Limits::default(), &trace).unwrap();
        replay.enter_lane(prep).unwrap();
        let mut checks = 0;
        replay
            .verify_preparation_lane(&raw, prep, || {
                checks += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(checks, 1);
        replay.close_lane(LaneOutcomeV3::Empty, vec![]).unwrap();
        replay.finish_v3().unwrap();
    }

    #[test]
    fn v3_byte_failure_is_sticky() {
        let limits = Limits::new(64, 64, 100, 10_000, 10_000).unwrap();
        let log = TraceLog::new_recording_v3(limits);
        assert_eq!(
            log.enter_lane(lane(LanePhaseV3::Preparation, 0))
                .unwrap_err()
                .kind,
            ErrorKind::Limit
        );
        assert_eq!(log.finish_v3().unwrap_err().kind, ErrorKind::Limit);
    }
}

use cdb_core::{
    admission::*,
    claim::AdmittedClaim,
    contracts::*,
    id::*,
    limits::Budget,
    record_codec::{encode_record, snapshot_value},
    recording::{PolicyObservation, ReadObservation},
    snapshot::*,
    CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone)]
pub struct TraceLog(Arc<Mutex<State>>);
struct State {
    limits: Limits,
    budget: Budget,
    policy: Vec<PolicyObservation>,
    reads: Vec<ReadObservation>,
    replay: bool,
    position: usize,
    failure: Option<Error>,
    v3: Option<lanes::LaneState>,
}
impl TraceLog {
    pub fn new_recording(limits: Limits) -> Self {
        Self(Arc::new(Mutex::new(State {
            limits,
            budget: Budget::new(limits),
            policy: vec![],
            reads: vec![],
            replay: false,
            position: 0,
            failure: None,
            v3: None,
        })))
    }
    pub fn new_replay(
        limits: Limits,
        policy: &[PolicyObservation],
        reads: &[ReadObservation],
    ) -> Result<Self> {
        let log = Self::new_recording(limits);
        {
            let mut s = log.lock()?;
            for p in policy {
                s.charge(policy_bytes(p))?;
                if let Some(old) = s
                    .policy
                    .iter()
                    .find(|x| x.resource == p.resource && x.predicate == p.predicate)
                {
                    if old.allowed != p.allowed {
                        return Err(Error::new(
                            ErrorKind::PolicyChanged,
                            "contradictory policy trace",
                        ));
                    }
                } else {
                    s.policy.push(p.clone());
                }
            }
            for r in reads {
                let n = r
                    .key
                    .canonical_bytes(limits)?
                    .len()
                    .checked_add(r.operation.as_str().len())
                    .and_then(|n| n.checked_add(r.result_hash.as_str().len()))
                    .ok_or_else(Error::limit)?;
                s.charge(n)?;
                s.reads.push(r.clone());
            }
            s.replay = true;
        }
        Ok(log)
    }
    /// Start a lane-aware v3 recording. V2 constructors and behavior are unchanged.
    pub fn new_recording_v3(limits: Limits) -> Self {
        let log = Self::new_recording(limits);
        log.0.lock().expect("new trace mutex").v3 = Some(lanes::LaneState::recording(limits));
        log
    }
    /// Start v3 replay from validated typed trace data.
    pub fn new_replay_v3(limits: Limits, data: &TraceDataV3) -> Result<Self> {
        let log = Self::new_recording(limits);
        log.0
            .lock()
            .map_err(|_| Error::invalid("trace mutex poisoned"))?
            .v3 = Some(lanes::LaneState::replay(limits, data)?);
        Ok(log)
    }
    /// Register an actual controller-issued lane and make it active.
    pub fn enter_lane(&self, identity: LaneIdentityV3) -> Result<()> {
        self.v3_mut(|v3| v3.enter(identity))
    }
    /// Resume a previously entered open lane; scheduling/arrival order is irrelevant.
    pub fn resume_lane(&self, identity: LaneIdentityV3) -> Result<()> {
        self.v3_mut(|v3| v3.resume(identity))
    }
    /// Close the active lane with its semantic outcome and compact call counts.
    pub fn close_lane(
        &self,
        outcome: LaneOutcomeV3,
        function_counts: Vec<FunctionCountV3>,
    ) -> Result<()> {
        self.v3_mut(|v3| v3.close(outcome, function_counts, false))
    }
    /// Replay execution may need to finish actual effects after a semantic lane
    /// mismatch. The mismatch remains sticky and is returned by `finish_v3`.
    pub fn close_lane_deferred(
        &self,
        outcome: LaneOutcomeV3,
        function_counts: Vec<FunctionCountV3>,
    ) -> Result<()> {
        self.v3_mut(|v3| v3.close(outcome, function_counts, true))
    }
    /// Import native preparation observations into the active preparation lane.
    /// Recording and replay use the same ordered request/result identities.
    pub fn import_preparation_reads(&self, reads: &[ReadObservation]) -> Result<()> {
        for read in reads {
            self.v3_mut(|v3| {
                v3.prepare_raw(&read.operation, &read.key)?;
                v3.complete_raw(read.clone(), 0)
            })?;
        }
        Ok(())
    }

    /// Attach a completeness scope to the active lane (deduplicated in lane and base).
    pub fn observe_scope(&self, scope: &ResourceId) -> Result<()> {
        self.v3_mut(|v3| v3.scope(scope))
    }
    /// Finish the complete v3 trace. Missing/extra observations and lanes are fatal.
    pub fn finish_v3(&self) -> Result<TraceDataV3> {
        let mut s = self.lock()?;
        let result =
            s.v3.as_ref()
                .ok_or_else(|| Error::invalid("not a v3 trace"))?
                .finish();
        if let Err(error) = &result {
            s.failure = Some(error.clone());
        }
        result
    }
    /// Replay preparation RAW operations directly against the saved keys/results.
    /// This deliberately has no landing/resolver callback.
    pub fn verify_preparation_lane<VW: RawQueryView + ?Sized>(
        &self,
        view: &VW,
        identity: LaneIdentityV3,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        if identity.phase != LanePhaseV3::Preparation {
            return Err(Error::invalid("preparation lane required"));
        }
        self.resume_lane(identity)?;
        let reads = {
            let s = self.lock()?;
            s.v3.as_ref()
                .ok_or_else(|| Error::invalid("not a v3 trace"))?
                .remaining_reads(identity)?
        };
        self.verify_saved_reads(view, reads, &mut check)
    }
    fn v3_mut<T>(&self, call: impl FnOnce(&mut lanes::LaneState) -> Result<T>) -> Result<T> {
        let mut s = self.lock()?;
        let result = call(
            s.v3.as_mut()
                .ok_or_else(|| Error::invalid("not a v3 trace"))?,
        );
        if let Err(error) = &result {
            s.failure = Some(error.clone());
        }
        result
    }
    /// Merge audited source observations through the same contradiction/budget checks.
    pub fn merge_policy(&self, observations: &[PolicyObservation]) -> Result<()> {
        for p in observations {
            if !p.allowed {
                return Err(Error::invalid("evidence footprint must be positive"));
            }
            self.policy(&p.resource, p.predicate.as_ref(), || Ok(true))?;
        }
        Ok(())
    }
    /// Verify original preparation/landing dependencies by exact RAW keys, not resolution.
    pub fn verify_prefix<VW: RawQueryView + ?Sized>(
        &self,
        view: &VW,
        count: usize,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let reads = {
            let s = self.lock()?;
            if !s.replay || s.position != 0 || count > s.reads.len() {
                return Err(Error::invalid("RAW prefix boundary"));
            }
            s.reads[..count].to_vec()
        };
        self.verify_saved_reads(view, reads, &mut check)
    }
    fn verify_saved_reads<VW: RawQueryView + ?Sized>(
        &self,
        view: &VW,
        reads: Vec<ReadObservation>,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let raw = RecordingRawView::new(view, self.clone());
        for r in reads {
            check()?;
            let operation = r
                .operation
                .as_str()
                .strip_prefix("https://ctxql.example/trace/v1/")
                .ok_or_else(|| Error::invalid("RAW operation"))?;
            match operation {
                "claim" => {
                    raw.claim(&ClaimId::new(r.key.field("id")?.as_str()?)?)?;
                }
                "entity" => {
                    raw.entity(&EntityId::new(r.key.field("id")?.as_str()?)?)?;
                }
                "resource" => {
                    raw.resource(&ResourceId::new(r.key.field("id")?.as_str()?)?)?;
                }
                "incident" | "lifecycle" => {
                    let size = PageSize::new(
                        r.key
                            .field("size")?
                            .as_str()?
                            .parse()
                            .map_err(|_| Error::invalid("RAW size"))?,
                    )?;
                    let c = r.key.field("cursor")?;
                    let c = if *c == V::Null {
                        None
                    } else {
                        c.closed(&["snapshot", "stream", "position"], &[])?;
                        Some(PageCursor::new(
                            cdb_core::record_codec::snapshot_from_value(
                                c.field("snapshot")?,
                                self.lock()?.limits,
                            )?,
                            ResourceId::new(c.field("stream")?.as_str()?)?,
                            VersionId::new(c.field("position")?.as_str()?)?,
                        ))
                    };
                    let id = r.key.field("request")?.field("id")?.as_str()?;
                    if operation == "incident" {
                        let direction = match r.key.field("direction")?.as_str()? {
                            "incoming" => Direction::Incoming,
                            "outgoing" => Direction::Outgoing,
                            "both" => Direction::Both,
                            _ => return Err(Error::invalid("RAW direction")),
                        };
                        raw.incident(&EntityId::new(id)?, direction, size, c.as_ref())?;
                    } else {
                        raw.lifecycle(&ClaimId::new(id)?, size, c.as_ref())?;
                    }
                }
                _ => return Err(Error::invalid("RAW operation")),
            }
        }
        Ok(())
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        let s = self
            .0
            .lock()
            .map_err(|_| Error::invalid("trace mutex poisoned"))?;
        if let Some(e) = &s.failure {
            return Err(e.clone());
        }
        Ok(s)
    }
    pub fn observations(&self) -> Result<(Vec<PolicyObservation>, Vec<ReadObservation>)> {
        let s = self.lock()?;
        Ok((s.policy.clone(), s.reads.clone()))
    }
    pub fn finish(&self) -> Result<(Vec<PolicyObservation>, Vec<ReadObservation>)> {
        let mut s = self.lock()?;
        if s.v3.is_some() {
            return Err(Error::invalid("use finish_v3 for v3 trace"));
        }
        if s.replay && s.position != s.reads.len() {
            let e = Error::invalid("missing RAW observations");
            s.failure = Some(e.clone());
            return Err(e);
        }
        Ok((s.policy.clone(), s.reads.clone()))
    }
    fn raw<T>(
        &self,
        operation: &str,
        key: V,
        call: impl FnOnce() -> Result<T>,
        value: impl FnOnce(&T, Limits) -> Result<V>,
    ) -> Result<T> {
        let mut s = self.lock()?;
        let result = (|| {
            let key_bytes = key.canonical_bytes(s.limits)?.len();
            let operation = ResourceId::new(format!("https://ctxql.example/trace/v1/{operation}"))?;
            if let Some(v3) = &s.v3 {
                v3.prepare_raw(&operation, &key)?;
            }
            // Check the request before invoking the adapter.
            if s.v3.is_none() && s.replay {
                let expected = s
                    .reads
                    .get(s.position)
                    .ok_or_else(|| Error::invalid("extra RAW observation"))?;
                if expected.operation != operation || expected.key != key {
                    return Err(Error::invalid("RAW request divergence"));
                }
            }
            let output = call()?;
            let bytes = value(&output, s.limits)?.canonical_bytes(s.limits)?;
            let result_hash = ContentHash::of_bytes(&bytes);
            if let Some(v3) = &mut s.v3 {
                v3.complete_raw(
                    ReadObservation {
                        operation,
                        key,
                        result_hash,
                    },
                    bytes.len(),
                )?;
            } else if s.replay {
                if s.reads[s.position].result_hash != result_hash {
                    return Err(Error::invalid("RAW result divergence"));
                }
                s.position += 1;
            } else {
                s.charge(
                    key_bytes
                        .checked_add(operation.as_str().len())
                        .and_then(|n| n.checked_add(result_hash.as_str().len()))
                        .and_then(|n| n.checked_add(bytes.len()))
                        .ok_or_else(Error::limit)?,
                )?;
                s.reads.push(ReadObservation {
                    operation,
                    key,
                    result_hash,
                });
            }
            Ok(output)
        })();
        if let Err(e) = &result {
            s.failure = Some(e.clone());
        }
        result
    }
    fn policy(
        &self,
        resource: &ResourceId,
        predicate: Option<&Iri>,
        call: impl FnOnce() -> Result<bool>,
    ) -> Result<bool> {
        let mut s = self.lock()?;
        let result = (|| {
            if let Some(v3) = &mut s.v3 {
                return v3.policy(resource, predicate, call);
            }
            let old = s
                .policy
                .iter()
                .find(|p| &p.resource == resource && p.predicate.as_ref() == predicate)
                .map(|p| p.allowed);
            if s.replay {
                match old {
                    Some(false) => Ok(false),
                    Some(true) => {
                        if call()? {
                            Ok(true)
                        } else {
                            Err(Error::new(ErrorKind::Denied, "recorded permission revoked"))
                        }
                    }
                    None => Err(Error::invalid("unknown policy observation")),
                }
            } else {
                let allowed = call()?;
                if let Some(old) = old {
                    if old != allowed {
                        return Err(Error::new(
                            ErrorKind::PolicyChanged,
                            "contradictory policy decision",
                        ));
                    }
                } else {
                    s.charge(
                        resource
                            .as_str()
                            .len()
                            .checked_add(predicate.map_or(0, |p| p.as_str().len()))
                            .and_then(|n| n.checked_add(1))
                            .ok_or_else(Error::limit)?,
                    )?;
                    s.policy.push(PolicyObservation {
                        resource: resource.clone(),
                        predicate: predicate.cloned(),
                        allowed,
                    });
                }
                Ok(allowed)
            }
        })();
        if let Err(e) = &result {
            s.failure = Some(e.clone());
        }
        result
    }
}
impl State {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.budget.charge(1, bytes, bytes)
    }
}
fn obj<const N: usize>(fields: [(&str, V); N]) -> V {
    V::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
fn policy_bytes(p: &PolicyObservation) -> usize {
    p.resource
        .as_str()
        .len()
        .saturating_add(p.predicate.as_ref().map_or(0, |p| p.as_str().len()))
        .saturating_add(1)
}
fn cursor(c: Option<&PageCursor>) -> V {
    c.map(|c| {
        obj([
            ("snapshot", snapshot_value(c.snapshot())),
            ("stream", V::string(c.stream().as_str())),
            ("position", V::string(c.position().as_str())),
        ])
    })
    .unwrap_or(V::Null)
}
fn record(r: &ExportRecord, limits: Limits) -> Result<V> {
    V::parse(&encode_record(r, limits)?, limits)
}
fn claim(c: &AdmittedClaim, limits: Limits) -> Result<V> {
    c.candidate().projection().canonical_bytes(limits)?;
    record(&ExportRecord::Claim(Box::new(c.clone())), limits)
}
fn resource(r: &DependencyRecord, limits: Limits) -> Result<V> {
    r.projection().canonical_bytes(limits)?;
    record(&ExportRecord::Resource(r.clone()), limits)
}
fn items<T>(rows: &[T], limits: Limits, encode: impl Fn(&T, Limits) -> Result<V>) -> Result<V> {
    if rows.len() > limits.values() {
        return Err(Error::limit());
    }
    let mut budget = Budget::new(limits);
    let mut values = Vec::new();
    for row in rows {
        let v = encode(row, limits)?;
        let n = v.canonical_bytes(limits)?.len();
        budget.charge(1, n, n)?;
        values.push(v);
    }
    Ok(V::Array(values))
}
fn page<T>(p: &Page<T>, limits: Limits, encode: impl Fn(&T, Limits) -> Result<V>) -> Result<V> {
    Ok(obj([
        ("snapshot", snapshot_value(p.snapshot())),
        ("items", items(p.items(), limits, encode)?),
        ("next", cursor(p.next())),
    ]))
}
pub struct RecordingRawView<'a, T: RawQueryView + ?Sized> {
    view: &'a T,
    log: TraceLog,
}
impl<'a, T: RawQueryView + ?Sized> RecordingRawView<'a, T> {
    pub fn new(view: &'a T, log: TraceLog) -> Self {
        Self { view, log }
    }
    fn key(&self, id: &str) -> V {
        obj([
            ("snapshot", snapshot_value(self.identity())),
            ("id", V::string(id)),
        ])
    }
    fn page_key(&self, id: &str, size: PageSize, c: Option<&PageCursor>, direction: V) -> V {
        obj([
            ("request", self.key(id)),
            ("size", V::string(size.get().to_string())),
            ("cursor", cursor(c)),
            ("direction", direction),
        ])
    }
}
impl<T: RawQueryView + ?Sized> RawQueryView for RecordingRawView<'_, T> {
    fn identity(&self) -> &SnapshotRef {
        self.view.identity()
    }
    fn claim(&self, id: &ClaimId) -> Result<Option<AdmittedClaim>> {
        self.log.raw(
            "claim",
            self.key(id.as_str()),
            || self.view.claim(id),
            |r, l| {
                r.as_ref()
                    .map(|r| claim(r, l))
                    .transpose()
                    .map(|r| r.unwrap_or(V::Null))
            },
        )
    }
    fn claim_is_pre_authorized(&self, id: &ClaimId) -> bool {
        self.view.claim_is_pre_authorized(id)
    }
    fn entity(&self, id: &EntityId) -> Result<Option<Vec<DependencyRecord>>> {
        self.log.raw(
            "entity",
            self.key(id.as_str()),
            || self.view.entity(id),
            |r, l| {
                r.as_ref()
                    .map(|r| items(r, l, resource))
                    .transpose()
                    .map(|r| r.unwrap_or(V::Null))
            },
        )
    }
    fn resource(&self, id: &ResourceId) -> Result<Option<DependencyRecord>> {
        self.log.raw(
            "resource",
            self.key(id.as_str()),
            || self.view.resource(id),
            |r, l| {
                r.as_ref()
                    .map(|r| resource(r, l))
                    .transpose()
                    .map(|r| r.unwrap_or(V::Null))
            },
        )
    }
    fn incident(
        &self,
        id: &EntityId,
        direction: Direction,
        size: PageSize,
        c: Option<&PageCursor>,
    ) -> Result<Page<AdmittedClaim>> {
        let d = V::string(match direction {
            Direction::Outgoing => "outgoing",
            Direction::Incoming => "incoming",
            Direction::Both => "both",
        });
        self.log.raw(
            "incident",
            self.page_key(id.as_str(), size, c, d),
            || self.view.incident(id, direction, size, c),
            |r, l| page(r, l, claim),
        )
    }
    fn lifecycle(
        &self,
        id: &ClaimId,
        size: PageSize,
        c: Option<&PageCursor>,
    ) -> Result<Page<ExportRecord>> {
        self.log.raw(
            "lifecycle",
            self.page_key(id.as_str(), size, c, V::Null),
            || self.view.lifecycle(id, size, c),
            |r, l| page(r, l, record),
        )
    }
}
pub struct RecordingPolicy<'a, P: PolicyService + ?Sized> {
    policy: &'a P,
    log: TraceLog,
}
impl<'a, P: PolicyService + ?Sized> RecordingPolicy<'a, P> {
    pub fn new(policy: &'a P, log: TraceLog) -> Self {
        Self { policy, log }
    }
}
impl<P: PolicyService + ?Sized> PolicyService for RecordingPolicy<'_, P> {
    type Principal = P::Principal;
    type Context = P::Context;
    fn current<'a>(&'a self, principal: &'a Self::Principal) -> IoFuture<'a, Self::Context> {
        self.policy.current(principal)
    }
    fn resource_allowed(&self, context: &Self::Context, resource: &ResourceId) -> Result<bool> {
        self.log.policy(resource, None, || {
            self.policy.resource_allowed(context, resource)
        })
    }
    fn fact_allowed(
        &self,
        context: &Self::Context,
        resource: &ResourceId,
        predicate: &Iri,
    ) -> Result<bool> {
        self.log.policy(resource, Some(predicate), || {
            self.policy.fact_allowed(context, resource, predicate)
        })
    }
    fn publish<'a>(
        &'a self,
        principal: &'a Self::Principal,
        context: &'a Self::Context,
        sink: &'a mut (dyn FnMut() -> Result<()> + Send),
    ) -> IoFuture<'a, ()> {
        self.policy.publish(principal, context, sink)
    }
}
