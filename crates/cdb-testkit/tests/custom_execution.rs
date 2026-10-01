//! Serial traversal semantics with real native Rhai and an explicit memory graph.
//! Not broker, durable v3, or native service acceptance.
use cdb_core::{
    claim::ClaimObject,
    contracts::{CapturedSnapshot, IoFuture},
    id::EntityId,
    CanonicalValue as V, ErrorKind, Limits, Result,
};
use cdb_engine::{
    compiler::{compile_with_compiler_capabilities, CompilerCapabilities, QuerySource},
    execution::{execute, ExecutionOptions, LocalPredicateRuntime, PreparedView, ViewProvider},
    options::CompileOptions,
    predicates::EvaluationLimits,
};
use cdb_service::predicates::NativePredicateExecutor;
use cdb_testkit::reference_fixture::{artifact, FixtureBuilder, ReferenceFixture, CONFIG};
use serde_json::{json, Value};

struct Local<'a>(&'a ReferenceFixture);
static EXECUTOR: NativePredicateExecutor = NativePredicateExecutor;
impl ViewProvider for Local<'_> {
    fn local_predicates(&self) -> Option<LocalPredicateRuntime<'_>> {
        Some(LocalPredicateRuntime {
            executor: &EXECUTOR,
            limits: EvaluationLimits::default(),
        })
    }
    fn open<'a>(
        &'a self,
        captured: &'a CapturedSnapshot,
        options: &'a ExecutionOptions,
    ) -> IoFuture<'a, PreparedView> {
        self.0.open(captured, options)
    }
}
fn native(task: impl std::future::Future<Output = ()> + Send + 'static) {
    // Own this thread and its private graph-I/O runtime; no shared server async
    // worker is blocked by native predicate evaluation.
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
        "https://e/custom-config",
        CONFIG
            .replace(
                "\"cycle_policy\"",
                "\"predicate_numeric\":\"ctxql-predicate-numeric/v2\",\"cycle_policy\"",
            )
            .as_bytes(),
    )
    .unwrap();
    let mut b = FixtureBuilder::new();
    b.artifact(config.clone());
    for id in ["A", "B", "C", "D", "E"] {
        b.entity(&format!("https://e/{id}"), Some(id)).unwrap();
    }
    for (id, s, o, confidence) in [
        ("c1", "A", "B", "0.9"),
        ("c2", "A", "C", "0.8"),
        ("c3", "B", "D", "0.7"),
        ("c4", "C", "D", "0.6"),
        ("c5", "D", "E", "0.5"),
    ] {
        b.edge(
            &format!("https://e/{id}"),
            &format!("https://e/{s}"),
            ClaimObject::Entity(EntityId::new(format!("https://e/{o}")).unwrap()),
            confidence,
        )
        .unwrap();
    }
    let mut f = b.build().await.unwrap();
    f.config = config;
    f
}
async fn run(f: &ReferenceFixture, walk: Value, filter: Value, bounds: Value) -> Result<V> {
    let source=json!({"about":[{"from":["A"],"match":"exact"}],"bounds":bounds,"walk":{"predicates":walk},"filter":{"predicates":filter}}).to_string();
    let draft = compile_with_compiler_capabilities(
        QuerySource::inline(source.as_bytes()),
        None,
        &f.config,
        CompileOptions::default(),
        CompilerCapabilities {
            custom_predicates: true,
            ..Default::default()
        },
    )?;
    let mut bytes = vec![];
    let result = execute(
        draft,
        &f.backend,
        &f.backend,
        &f.principal,
        &Local(f),
        ExecutionOptions::default(),
        &mut |b| {
            bytes.extend_from_slice(b);
            Ok(())
        },
    )
    .await;
    if result.is_err() {
        assert!(bytes.is_empty(), "failed execution released bytes");
    }
    result?;
    V::parse(&bytes, Limits::default())
}
fn paths(v: &V) -> Vec<Vec<String>> {
    v.field("paths")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            p.field("claim_ids")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().rsplit('/').next().unwrap().to_owned())
                .collect()
        })
        .collect()
}
fn counter() -> Value {
    json!({"init":{"n":0,"untouched":99},"next":{"n":"state.n + 1"},"keep":"next.n <= 2 && next.untouched == 99"})
}
#[test]
fn denied_binding_metadata_never_reaches_native_evaluation() {
    native(async {
        let f = fixture().await;
        let property = cdb_engine::execution::property_iri("confidence").unwrap();
        let policy = json!({"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[
            {"@id":"https://e/allow","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":true},
            {"@id":"https://e/deny","@type":["https://ns.flur.ee/db#AccessPolicy","https://fixture.example/Reader"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#onProperty":property.as_str(),"https://ns.flur.ee/db#allow":false}
        ]}).to_string();
        f.backend
            .set_policy(
                cdb_core::policy::PolicySet::parse(policy.as_bytes(), Limits::default()).unwrap(),
            )
            .unwrap();
        let result = run(&f, json!([{"bind":{"confidence":"meta:confidence"},"keep":"throw \"must not evaluate denied claim\"; true"}]), json!([]), json!({"max_depth":2})).await.unwrap();
        assert!(paths(&result).is_empty());
    });
}
#[test]
fn state_is_path_local_and_only_all_pass_children_commit() {
    native(async {
        let f = fixture().await;
        let v = run(
            &f,
            json!([counter(), counter()]),
            json!([]),
            json!({"max_depth":3}),
        )
        .await
        .unwrap();
        let p = paths(&v);
        assert_eq!(p.len(), 4);
        assert!(p.contains(&vec!["c1".into(), "c3".into()]));
        assert!(p.contains(&vec!["c2".into(), "c4".into()]));
        let v = run(
            &f,
            json!([counter(),{"bind":{"id":"meta:claim_id"},"keep":"id != \"https://e/c1\""}]),
            json!([]),
            json!({"max_depth":3}),
        )
        .await
        .unwrap();
        assert_eq!(paths(&v), vec![vec!["c2"], vec!["c2", "c4"]]);
    });
}
#[test]
fn cap_denial_does_not_commit_state_and_later_predicates_are_not_called() {
    native(async {
        let f = fixture().await;
        let v = run(
            &f,
            json!([counter()]),
            json!([]),
            json!({"max_depth":3,"fanout_limit":1}),
        )
        .await
        .unwrap();
        assert_eq!(paths(&v), vec![vec!["c1"], vec!["c1", "c3"]]);
        let v = run(
            &f,
            json!([{"keep":"false"},{"keep":"fn:external(\"forbidden\")"}]),
            json!([]),
            json!({"max_depth":3}),
        )
        .await
        .unwrap();
        assert!(paths(&v).is_empty());
    });
}
#[test]
fn filter_attempts_have_fresh_state_and_same_claim_bindings() {
    native(async {
        let f = fixture().await;
        let filter = json!([{"init":{"n":0},"bind":{"id":"meta:claim_id","confidence":"meta:confidence"},"next":{"n":"state.n + 1"},"keep":"next.n == 1 && id == \"https://e/c3\" && confidence == 0.7"}]);
        let v = run(&f, json!([]), filter, json!({"max_depth":2}))
            .await
            .unwrap();
        assert_eq!(paths(&v), vec![vec!["c1", "c3"]]);
        let v=run(&f,json!([]),json!([{"bind":{"id":"meta:claim_id","confidence":"meta:confidence"},"keep":"id == \"https://e/c1\" && confidence == 0.7"}]),json!({"max_depth":2})).await.unwrap();
        assert!(paths(&v).is_empty());
    });
}
#[test]
fn path_bindings_include_prospective_candidate_and_filter_state_is_discarded() {
    native(async {
        let f = fixture().await;
        let v=run(&f,json!([{"bind":{"ids":"path.meta:claim_id","depth":"meta:depth"},"keep":"ids.len() == depth && depth <= 2"}]),json!([{"init":{"n":0},"next":{"n":"state.n + 1"},"keep":"next.n == 1"}]),json!({"max_depth":3})).await.unwrap();
        assert_eq!(paths(&v).len(), 4);
    });
}
#[test]
fn external_calls_fail_closed_even_if_caught_and_builtin_errors_remain_eager() {
    native(async {
        let f = fixture().await;
        let err = run(
            &f,
            json!([{"keep":"try { fn:external(\"forbidden\"); } catch (_) {} true"}]),
            json!([]),
            json!({"max_depth":1}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Unsupported);
        let err=run(&f,json!([]),json!([["meta:claim_id","exists",false],{"keep":"fn:external(\"unreachable\")"},["meta:object_id",">",1]]),json!({"max_depth":1})).await.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Invalid);
    });
}
