//! Focused engine v3 composition; durable publication remains a service/backend concern.
use cdb_core::{
    admission::*,
    artifact::PublishedArtifact,
    claim::ClaimObject,
    contracts::*,
    id::*,
    recording::{RecordingEngine, REQUIRED_SCOPES},
    recording_v3::{ReplayDataV3, ReplayDataV3Input},
    replay::ReplayVerdict,
    snapshot::SnapshotRef,
    CanonicalValue as V, Result,
};
use cdb_engine::{
    compiler::{compile, CompilerCapabilities, QuerySource},
    execution::{
        capture_execution, prepare_recorded_v3, prepare_replay_v3, recording_trace_v3,
        replay_trace_v3, ControllerBounds, ControllerEvent, ControllerRuntime, ControllerTicket,
        EvaluationCompletion, EvaluationJob, ExecutionOptions, LandingCatalog, LandingEntry,
        PreparedView, ViewProvider,
    },
    options::CompileOptions,
    predicates::EvaluationLimits,
};
use cdb_testkit::reference_fixture::{artifact, FixtureBuilder, ReferenceFixture};
use std::sync::{Arc, Mutex};

fn executor() -> RecordingEngine {
    RecordingEngine {
        name: ResourceId::new("urn:test:native-executor").unwrap(),
        version: VersionId::new("1").unwrap(),
        build: ContentHash::of_bytes(b"test-native-executor"),
    }
}

fn core_lane(
    identity: &cdb_engine::execution::LaneIdentityV3,
) -> cdb_core::recording_v3::LaneIdentityV3 {
    cdb_core::recording_v3::LaneIdentityV3 {
        phase: match identity.phase {
            cdb_engine::execution::PredicatePhase::Walk => {
                cdb_core::recording_v3::LanePhaseV3::Walk
            }
            cdb_engine::execution::PredicatePhase::Filter => {
                cdb_core::recording_v3::LanePhaseV3::Filter
            }
        },
        evaluation: identity.evaluation_ordinal,
        predicate: identity.predicate_index,
        attempt: identity.attempt,
        ordinal: 0,
    }
}

struct TraceController {
    trace: cdb_engine::execution::trace::TraceLog,
    events: Mutex<Vec<ControllerEvent>>,
}
impl TraceController {
    fn close_finalization(&self) -> Result<()> {
        let lane = cdb_core::recording_v3::LaneIdentityV3 {
            phase: cdb_core::recording_v3::LanePhaseV3::Preparation,
            evaluation: 1,
            predicate: 0,
            attempt: 0,
            ordinal: 0,
        };
        self.trace.resume_lane(lane)?;
        self.trace.close_lane(
            cdb_engine::execution::trace::LaneOutcomeV3::Accepted,
            vec![],
        )
    }
}
impl ControllerRuntime for TraceController {
    fn validate(
        &self,
        _: &cdb_engine::predicates::Program,
        _: &[String],
        _: EvaluationLimits,
    ) -> Result<()> {
        Ok(())
    }
    fn bounds(&self) -> ControllerBounds {
        ControllerBounds {
            max_outstanding: 1,
            max_pending_bytes: 1024 * 1024,
        }
    }
    fn submit(&self, _: EvaluationJob) -> Result<ControllerTicket> {
        unreachable!("test has no custom predicates")
    }
    fn wait(&self, _: ControllerTicket) -> EvaluationCompletion {
        unreachable!("test has no custom predicates")
    }
    fn event(&self, event: ControllerEvent) -> Result<()> {
        let saved = event.clone();
        use cdb_core::recording_v3::{LaneIdentityV3, LanePhaseV3};
        use cdb_engine::execution::trace::LaneOutcomeV3;
        match event {
            ControllerEvent::TraversalStarted => {
                let lane = LaneIdentityV3 {
                    phase: LanePhaseV3::Preparation,
                    evaluation: 0,
                    predicate: 0,
                    attempt: 0,
                    ordinal: 0,
                };
                self.trace.resume_lane(lane)?;
                self.trace.close_lane(LaneOutcomeV3::Accepted, vec![])?;
            }
            ControllerEvent::FinalizationStarted => self.trace.enter_lane(LaneIdentityV3 {
                phase: LanePhaseV3::Preparation,
                evaluation: 1,
                predicate: 0,
                attempt: 0,
                ordinal: 0,
            })?,
            ControllerEvent::ReadLane(identity) => {
                self.trace.enter_lane(core_lane(&identity))?;
            }
            ControllerEvent::LaneClosed(identity, outcome) => {
                self.trace.resume_lane(core_lane(&identity))?;
                self.trace.close_lane(outcome, vec![])?;
            }
            ControllerEvent::EvaluationClosed {
                phase,
                ordinal,
                outcome,
            } => {
                let phase = match phase {
                    cdb_engine::execution::PredicatePhase::Walk => LanePhaseV3::Walk,
                    cdb_engine::execution::PredicatePhase::Filter => LanePhaseV3::Filter,
                };
                self.trace.enter_lane(LaneIdentityV3 {
                    phase,
                    evaluation: ordinal,
                    predicate: u64::MAX,
                    attempt: u64::MAX,
                    ordinal: 1,
                })?;
                self.trace.close_lane(outcome, vec![])?;
            }
            _ => {}
        }
        self.events.lock().unwrap().push(saved);
        Ok(())
    }
}

struct Catalog {
    pin: SnapshotRef,
    entries: Vec<LandingEntry>,
    panic_entries: bool,
}
impl LandingCatalog for Catalog {
    fn identity(&self) -> &SnapshotRef {
        &self.pin
    }
    fn entries(&self) -> &[LandingEntry] {
        assert!(!self.panic_entries, "replay landing resolver invoked");
        &self.entries
    }
}
struct Provider<'a> {
    fixture: &'a ReferenceFixture,
    controller: &'a TraceController,
    replay: bool,
}
impl ViewProvider for Provider<'_> {
    fn controller_runtime(&self) -> Option<&dyn ControllerRuntime> {
        Some(self.controller)
    }
    fn open<'a>(
        &'a self,
        captured: &'a cdb_core::contracts::CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        Box::pin(async move {
            let prepared = self.fixture.open(captured, options).await?;
            let entries = if self.replay {
                vec![]
            } else {
                prepared
                    .landing
                    .entries()
                    .iter()
                    .filter(|entry| entry.label.is_some())
                    .cloned()
                    .collect()
            };
            Ok(PreparedView {
                view: prepared.view,
                landing: Arc::new(Catalog {
                    pin: captured.snapshot.clone(),
                    entries,
                    panic_entries: self.replay,
                }),
            })
        })
    }
}

async fn fixture() -> (ReferenceFixture, PublishedArtifact) {
    let query = artifact(
        "https://e/v3-query",
        br#"{"about":[{"from":["A"],"match":"exact"}],"bounds":{"max_depth":1},"return":{"explain":true}}"#,
    )
    .unwrap();
    let mut builder = FixtureBuilder::new();
    builder.entity("https://e/A", Some("A")).unwrap();
    builder.entity("https://e/B", Some("B")).unwrap();
    builder
        .edge(
            "https://e/ab",
            "https://e/A",
            ClaimObject::Entity(EntityId::new("https://e/B").unwrap()),
            "0.8",
        )
        .unwrap();
    for scope in REQUIRED_SCOPES {
        builder.resource(
            DependencyRecord::new(
                "ctxql-resource/v1",
                ResourceId::new(scope).unwrap(),
                ResourceKind::SourceDescriptor,
                vec![Fact::new(
                    Iri::new("https://e/scope-kind").unwrap(),
                    FactTerm::Literal(
                        cdb_core::claim::TypedLiteral::new(
                            Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
                            V::string("complete"),
                            None,
                        )
                        .unwrap(),
                    ),
                )],
            )
            .unwrap(),
        );
    }
    builder.artifact(query.clone());
    (builder.build().await.unwrap(), query)
}

#[tokio::test]
async fn v3_records_and_replays_actual_trace_without_landing_resolution() {
    let (fixture, query) = fixture().await;
    let options = ExecutionOptions::default();
    let draft = compile(
        QuerySource::published(&query),
        None,
        &fixture.config,
        CompileOptions::default(),
    )
    .unwrap();
    let capture = capture_execution(&fixture.backend, draft.requested_as_of())
        .await
        .unwrap();
    let trace = recording_trace_v3(&options).unwrap();
    let controller = TraceController {
        trace: trace.clone(),
        events: Mutex::new(vec![]),
    };
    let pending = prepare_recorded_v3(
        draft,
        &fixture.backend,
        &fixture.backend,
        &fixture.principal,
        &capture,
        &Provider {
            fixture: &fixture,
            controller: &controller,
            replay: false,
        },
        options.clone(),
        trace.clone(),
    )
    .await
    .unwrap();
    controller.close_finalization().unwrap();
    let prepared = pending.finish(&trace, &options).unwrap();
    assert!(!prepared.base().reads.is_empty());
    assert_eq!(prepared.base().scopes.len(), REQUIRED_SCOPES.len());
    let executor = executor();
    let (base, recorded_trace, _, _) = prepared.into_parts();
    let replay = ReplayDataV3::new(
        ReplayDataV3Input {
            base,
            lanes: recorded_trace.lane_values(),
            expected_lanes: recorded_trace.expected_lane_values(),
            functions: vec![],
            prepared: vec![],
            release_evidence: vec![],
            executor: executor.clone(),
        },
        options.limits,
    )
    .unwrap();

    let replay_trace = replay_trace_v3(&replay, &options).unwrap();
    let replay_controller = TraceController {
        trace: replay_trace.clone(),
        events: Mutex::new(vec![]),
    };
    let pending = prepare_replay_v3(
        &replay,
        &fixture.backend,
        &fixture.backend,
        &fixture.principal,
        &Provider {
            fixture: &fixture,
            controller: &replay_controller,
            replay: true,
        },
        CompilerCapabilities::default(),
        &executor,
        options.clone(),
        replay_trace.clone(),
    )
    .await
    .unwrap();
    replay_controller.close_finalization().unwrap();
    let replayed = pending.finish(&replay_trace, &options).unwrap();
    assert_eq!(replayed.verdict(), ReplayVerdict::Reproduced);
}
