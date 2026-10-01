//! Focused bounded-controller equivalence and ordering tests.
use cdb_core::{
    claim::ClaimObject,
    contracts::{CapturedSnapshot, IoFuture},
    id::EntityId,
    CanonicalValue as V, Error, ErrorKind, Limits, Result,
};
use cdb_engine::{
    compiler::{compile_with_compiler_capabilities, CompilerCapabilities, QuerySource},
    execution::{
        ControllerBounds, ControllerEvent, ControllerRuntime, ControllerTicket,
        EvaluationCompletion, EvaluationJob, ExecutionOptions, PreparedView, ViewProvider,
    },
    options::CompileOptions,
    predicates::{EvaluationLimits, FunctionCallback, PredicateExecutor},
    values::Value,
};
use cdb_service::predicates::NativePredicateExecutor;
use cdb_testkit::reference_fixture::{artifact, FixtureBuilder, ReferenceFixture, CONFIG};
use serde_json::{json, Value as Json};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::Duration,
};

static EXECUTOR: NativePredicateExecutor = NativePredicateExecutor;

struct NoEffects;
impl FunctionCallback for NoEffects {
    fn call(&self, _: &str, _: &[Value]) -> Result<Value> {
        Err(Error::new(ErrorKind::Unsupported, "test callback disabled"))
    }
    fn check_interrupted(&self) -> Result<()> {
        Ok(())
    }
}

struct TicketPayload {
    handle: JoinHandle<Result<cdb_engine::predicates::Outcome>>,
}

struct DelayedRuntime {
    window: usize,
    active: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
    submitted: AtomicUsize,
    physical_completion: Arc<Mutex<Vec<u64>>>,
    events: Mutex<Vec<ControllerEvent>>,
}
impl DelayedRuntime {
    fn new(window: usize) -> Self {
        Self {
            window,
            active: Arc::new(AtomicUsize::new(0)),
            maximum: Arc::new(AtomicUsize::new(0)),
            submitted: AtomicUsize::new(0),
            physical_completion: Arc::new(Mutex::new(vec![])),
            events: Mutex::new(vec![]),
        }
    }
    fn submitted(&self) -> usize {
        self.submitted.load(Ordering::SeqCst)
    }
}
impl ControllerRuntime for DelayedRuntime {
    fn validate(
        &self,
        program: &cdb_engine::predicates::Program,
        bindings: &[String],
        limits: EvaluationLimits,
    ) -> Result<()> {
        EXECUTOR.validate(program, bindings, limits)
    }
    fn bounds(&self) -> ControllerBounds {
        ControllerBounds {
            max_outstanding: self.window,
            max_pending_bytes: 8 * 1024 * 1024,
        }
    }
    fn submit(&self, job: EvaluationJob) -> Result<ControllerTicket> {
        self.submitted.fetch_add(1, Ordering::SeqCst);
        let active = self.active.clone();
        let maximum = self.maximum.clone();
        let completions = self.physical_completion.clone();
        let lane = job.lane.clone();
        let worker_lane = lane.clone();
        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
        maximum.fetch_max(now, Ordering::SeqCst);
        let handle = std::thread::spawn(move || {
            // Later logical lanes finish first within each bounded batch.
            std::thread::sleep(Duration::from_millis(
                24u64.saturating_sub(worker_lane.evaluation_ordinal % 24),
            ));
            let result = EXECUTOR.evaluate(
                &job.program,
                &job.state,
                &job.bindings,
                Arc::new(NoEffects),
                job.limits,
            );
            completions
                .lock()
                .unwrap()
                .push(worker_lane.evaluation_ordinal);
            active.fetch_sub(1, Ordering::SeqCst);
            result
        });
        Ok(ControllerTicket::new(lane, TicketPayload { handle }))
    }
    fn wait(&self, ticket: ControllerTicket) -> EvaluationCompletion {
        let lane = ticket.lane().clone();
        let payload = ticket.into_payload::<TicketPayload>().unwrap();
        EvaluationCompletion {
            lane,
            outcome: payload.handle.join().unwrap(),
        }
    }
    fn event(&self, event: ControllerEvent) -> Result<()> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}

struct Provider<'a> {
    fixture: &'a ReferenceFixture,
    runtime: &'a dyn ControllerRuntime,
}
impl ViewProvider for Provider<'_> {
    fn controller_runtime(&self) -> Option<&dyn ControllerRuntime> {
        Some(self.runtime)
    }
    fn open<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        self.fixture.open(captured, options)
    }
}

fn native(task: impl std::future::Future<Output = ()> + Send + 'static) {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(task)
    })
    .join()
    .unwrap();
}

async fn fixture() -> ReferenceFixture {
    let config = artifact(
        "https://e/controller-config",
        CONFIG
            .replace(
                "\"cycle_policy\"",
                "\"predicate_numeric\":\"ctxql-predicate-numeric/v2\",\"cycle_policy\"",
            )
            .as_bytes(),
    )
    .unwrap();
    let mut builder = FixtureBuilder::new();
    builder.artifact(config.clone());
    builder.entity("https://e/A", Some("A")).unwrap();
    for index in 0..12 {
        builder
            .entity(
                &format!("https://e/N{index:02}"),
                Some(&format!("N{index:02}")),
            )
            .unwrap();
        builder
            .edge(
                &format!("https://e/c{index:02}"),
                "https://e/A",
                ClaimObject::Entity(EntityId::new(format!("https://e/N{index:02}")).unwrap()),
                &format!("0.{:02}", 99 - index),
            )
            .unwrap();
    }
    let mut fixture = builder.build().await.unwrap();
    fixture.config = config;
    fixture
}

async fn run(
    fixture: &ReferenceFixture,
    runtime: &dyn ControllerRuntime,
    walk: Json,
    filter: Json,
    bounds: Json,
) -> Result<V> {
    let source = json!({
        "about":[{"from":["A"],"match":"exact"}],
        "bounds":bounds,
        "walk":{"predicates":walk},
        "filter":{"predicates":filter}
    })
    .to_string();
    let draft = compile_with_compiler_capabilities(
        QuerySource::inline(source.as_bytes()),
        None,
        &fixture.config,
        CompileOptions::default(),
        CompilerCapabilities {
            custom_predicates: true,
            ..Default::default()
        },
    )?;
    let mut bytes = vec![];
    cdb_engine::execution::execute(
        draft,
        &fixture.backend,
        &fixture.backend,
        &fixture.principal,
        &Provider { fixture, runtime },
        ExecutionOptions::default(),
        &mut |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        },
    )
    .await?;
    V::parse(&bytes, Limits::default())
}

#[test]
fn delayed_windows_are_canonically_identical_and_reduce_in_lane_order() {
    native(async {
        let fixture = fixture().await;
        let walk = json!([{
            "init":{"n":0},
            "bind":{"id":"meta:claim_id"},
            "next":{"n":"state.n + 1"},
            "keep":"next.n == 1 && id != \"never\""
        }]);
        let filter = json!([{
            "init":{"n":0},
            "bind":{"id":"meta:claim_id","confidence":"meta:confidence"},
            "next":{"n":"state.n + 1"},
            "keep":"next.n == 1 && id.ends_with(\"00\") && confidence == 0.99"
        }]);
        let mut oracle = None;
        for window in [1, 8, 32] {
            let runtime = DelayedRuntime::new(window);
            let value = run(
                &fixture,
                &runtime,
                walk.clone(),
                filter.clone(),
                json!({"max_depth":1}),
            )
            .await
            .unwrap();
            let bytes = value.canonical_bytes(Limits::default()).unwrap();
            if let Some(expected) = &oracle {
                assert_eq!(&bytes, expected);
            } else {
                oracle = Some(bytes);
            }
            let reduced = runtime
                .events
                .lock()
                .unwrap()
                .iter()
                .filter_map(|event| match event {
                    ControllerEvent::Reduced(lane) => Some(lane.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert!(reduced.windows(2).all(|pair| pair[0] <= pair[1]));
            if window > 1 {
                assert!(runtime.maximum.load(Ordering::SeqCst) > 1);
                let physical = runtime.physical_completion.lock().unwrap();
                assert!(physical.windows(2).any(|pair| pair[0] > pair[1]));
            }
        }
    });
}

#[test]
fn reducer_preserves_caps_and_short_circuits_later_custom_effects() {
    native(async {
        let fixture = fixture().await;
        for window in [1, 8, 32] {
            let runtime = DelayedRuntime::new(window);
            let value = run(
                &fixture,
                &runtime,
                json!([{"keep":"true"}]),
                json!([]),
                json!({"max_depth":1,"fanout_limit":3,"max_claims":2}),
            )
            .await
            .unwrap();
            assert_eq!(
                runtime.submitted(),
                12,
                "cap-denied evaluations are retained"
            );
            assert_eq!(value.field("paths").unwrap().as_array().unwrap().len(), 2);

            let runtime = DelayedRuntime::new(window);
            let value = run(
                &fixture,
                &runtime,
                json!([{"keep":"false"},{"keep":"throw \"later predicate ran\"; true"}]),
                json!([]),
                json!({"max_depth":1}),
            )
            .await
            .unwrap();
            assert_eq!(runtime.submitted(), 12);
            assert!(value.field("paths").unwrap().as_array().unwrap().is_empty());
        }
    });
}

#[test]
fn rejected_admission_fails_without_waiting() {
    struct Reject;
    impl ControllerRuntime for Reject {
        fn validate(
            &self,
            program: &cdb_engine::predicates::Program,
            bindings: &[String],
            limits: EvaluationLimits,
        ) -> Result<()> {
            EXECUTOR.validate(program, bindings, limits)
        }
        fn bounds(&self) -> ControllerBounds {
            ControllerBounds {
                max_outstanding: 1,
                max_pending_bytes: 1024 * 1024,
            }
        }
        fn submit(&self, _: EvaluationJob) -> Result<ControllerTicket> {
            Err(Error::limit())
        }
        fn wait(&self, _: ControllerTicket) -> EvaluationCompletion {
            panic!("rejected ticket cannot be waited")
        }
    }
    native(async {
        let fixture = fixture().await;
        let error = run(
            &fixture,
            &Reject,
            json!([{"keep":"true"}]),
            json!([]),
            json!({"max_depth":1}),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Limit);
    });
}
