use cdb_core::{CanonicalValue as C, Error, ExactNumber, Result};
use cdb_engine::{
    predicates::{EvaluationLimits, FunctionCallback, PredicateExecutor, Program},
    values::Value,
};
use cdb_service::predicates::{
    pool::{JobClass, NativePredicatePool, PoolLimits},
    NativePredicateExecutor,
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
struct Host {
    calls: AtomicUsize,
    deny: bool,
}
impl FunctionCallback for Host {
    fn check_interrupted(&self) -> Result<()> {
        Ok(())
    }
    fn call(&self, _: &str, args: &[Value]) -> Result<Value> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.deny {
            Err(Error::invalid("denied"))
        } else {
            Ok(args.first().cloned().unwrap_or(Value::Bool(true)))
        }
    }
}
fn host(deny: bool) -> Arc<Host> {
    Arc::new(Host {
        calls: AtomicUsize::new(0),
        deny,
    })
}
fn program(keep: &str) -> Program {
    Program {
        init: BTreeMap::new(),
        lets: BTreeMap::new(),
        next: BTreeMap::new(),
        keep: keep.into(),
    }
}
fn evaluate(p: &Program, h: Arc<Host>) -> Result<cdb_engine::predicates::Outcome> {
    NativePredicateExecutor.evaluate(
        p,
        &C::Object(p.init.clone()),
        &BTreeMap::new(),
        h,
        EvaluationLimits::default(),
    )
}
#[test]
fn native_numbers_and_syntax() {
    for source in [
        "0.1 + 0.2 == 0.3",
        "1 / 3 == 0",
        "1.0 / 3.0 == 0.3333333333333333333333333333",
        "let a = [1,2]; let sum=0; for x in a {sum += x;} sum == 3",
        "let f = |x| x + 1; f.call(2) == 3",
        "switch 2 { 1 => false, 2 => true, _ => false }",
    ] {
        assert!(
            evaluate(&program(source), host(false)).unwrap().keep,
            "{source}"
        );
    }
    assert!(evaluate(&program("1e-28 == 0"), host(false)).is_err());
}
#[test]
fn native_int_identity_survives_let_boundaries() {
    let mut p = program("[10, 20][index] == 20 && index.type_of() == 1.type_of()");
    p.lets.insert("index".into(), "1".into());
    assert!(evaluate(&p, host(false)).unwrap().keep);
}

#[test]
fn typed_host_denial_survives_script_catch() {
    struct Denied;
    impl FunctionCallback for Denied {
        fn check_interrupted(&self) -> Result<()> {
            Ok(())
        }
        fn call(&self, _: &str, _: &[Value]) -> Result<Value> {
            Err(Error::new(cdb_core::ErrorKind::Denied, "denied"))
        }
    }
    let failure = NativePredicateExecutor
        .evaluate(
            &program("try { fn:external(\"f\"); } catch (_) {} true"),
            &C::Object(BTreeMap::new()),
            &BTreeMap::new(),
            Arc::new(Denied),
            EvaluationLimits::default(),
        )
        .unwrap_err();
    assert_eq!(failure.kind, cdb_core::ErrorKind::Denied, "{failure:?}");
}

#[test]
fn topology_and_unoptimized_dead_names() {
    let mut p = program("b == 3");
    p.lets.insert("b".into(), "a + 1".into());
    p.lets.insert("a".into(), "fn f(x) { x + 1 } f(1)".into());
    assert!(evaluate(&p, host(false)).unwrap().keep);
    p.lets
        .insert("a".into(), "if false {unknown} else {2}".into());
    assert!(evaluate(&p, host(false)).is_err());
    p.lets.insert("a".into(), "b".into());
    assert!(evaluate(&p, host(false)).is_err());
    p.lets.insert("a".into(), "let b = 2; b".into());
    assert!(evaluate(&p, host(false)).unwrap().keep);
}
#[test]
fn independent_next_and_fresh_attempts() {
    let mut p = program("state.a == 1 && next.a == 2 && next.b == 1");
    p.init
        .insert("a".into(), C::Number(ExactNumber::parse("1").unwrap()));
    p.init.insert("b".into(), C::Null);
    p.next.insert("a".into(), "state.a + 1".into());
    p.next.insert("b".into(), "state.a".into());
    assert!(evaluate(&p, host(false)).unwrap().keep);
    assert!(evaluate(&p, host(false)).unwrap().keep);
    p.next.insert("b".into(), "next.a".into());
    assert!(evaluate(&p, host(false)).is_err());
}
#[test]
fn callbacks_nested_and_sticky() {
    let h = host(false);
    assert!(
        evaluate(
            &program("for x in 0..3 { fn:external(\"echo\", [x]); } true"),
            h.clone()
        )
        .unwrap()
        .keep
    );
    assert_eq!(h.calls.load(Ordering::SeqCst), 3);
    assert!(evaluate(
        &program("try { fn:external(\"denied\"); } catch(e) {} true"),
        host(true)
    )
    .is_err());
    assert!(evaluate(&program("let x = `text fn:external ${fn:external(\"echo\", 1)}`; x == \"text fn:external 1\""),host(false)).unwrap().keep);
    for source in [
        "ctxql_internal_external(\"x\")",
        "Fn(\"ctxql_internal_external\").call(\"x\")",
        "let fn:external = 1; true",
    ] {
        assert!(evaluate(&program(source), host(false)).is_err());
    }
}
#[test]
fn ingress_and_budgets() {
    let mut p = program("true");
    p.init.insert(
        "n".into(),
        C::Number(ExactNumber::parse("0.00000000000000000000000000001").unwrap()),
    );
    assert!(evaluate(&p, host(false)).is_err());
    let mut limits = EvaluationLimits {
        max_calls: 0,
        ..EvaluationLimits::default()
    };
    assert!(NativePredicateExecutor
        .validate(&program("true"), &[], limits)
        .is_err());
    limits = EvaluationLimits::default();
    limits.max_operations = 40;
    assert!(NativePredicateExecutor
        .evaluate(
            &program("loop {}"),
            &C::Object(BTreeMap::new()),
            &BTreeMap::new(),
            host(false),
            limits
        )
        .is_err());
    assert!(evaluate(&program("1"), host(false)).is_err());
}

#[test]
fn optimizer_host_parity() {
    for level in [
        rhai::OptimizationLevel::None,
        rhai::OptimizationLevel::Simple,
        rhai::OptimizationLevel::Full,
    ] {
        let mut p = program("b == 0.3 && fn:external(\"echo\", true)");
        p.lets
            .insert("b".into(), "fn add(x) { x + 0.2 } add(a)".into());
        p.lets.insert("a".into(), "0.1".into());
        let h = host(false);
        assert!(
            NativePredicateExecutor
                .evaluate_with_optimization(
                    &p,
                    &C::Object(BTreeMap::new()),
                    &BTreeMap::new(),
                    h.clone(),
                    EvaluationLimits::default(),
                    level
                )
                .unwrap()
                .keep
        );
        assert_eq!(h.calls.load(Ordering::SeqCst), 1);
        p.keep = "try {fn:external(\"deny\");} catch(e) {} true".into();
        assert!(NativePredicateExecutor
            .evaluate_with_optimization(
                &p,
                &C::Object(BTreeMap::new()),
                &BTreeMap::new(),
                host(true),
                EvaluationLimits::default(),
                level
            )
            .is_err());
    }
}

#[test]
fn pool_classification_admission_and_worker_lane() {
    let limits = EvaluationLimits::default();
    assert_eq!(
        cdb_service::predicates::classify_program(&program("true"), &[], limits).unwrap(),
        JobClass::LocalOnly
    );
    assert_eq!(
        cdb_service::predicates::classify_program(
            &program("let f = || fn:external(\"echo\", true); f.call()"),
            &[],
            limits
        )
        .unwrap(),
        JobClass::CallCapable
    );
    struct ThreadHost(Arc<std::sync::Mutex<Option<String>>>);
    impl FunctionCallback for ThreadHost {
        fn check_interrupted(&self) -> Result<()> {
            Ok(())
        }
        fn call(&self, _: &str, _: &[Value]) -> Result<Value> {
            *self.0.lock().unwrap() = thread::current().name().map(str::to_owned);
            Ok(Value::Bool(true))
        }
    }
    let pool = NativePredicatePool::new(PoolLimits {
        local_workers: 1,
        call_workers: 1,
        max_jobs: 2,
        max_bytes: 4096,
    })
    .unwrap();
    let observed = Arc::new(std::sync::Mutex::new(None));
    let outcome = pool
        .evaluate(
            program("fn:external(\"echo\", true)"),
            C::Object(BTreeMap::new()),
            BTreeMap::new(),
            Arc::new(ThreadHost(observed.clone())),
            limits,
        )
        .unwrap();
    assert!(outcome.keep);
    assert!(observed
        .lock()
        .unwrap()
        .as_deref()
        .unwrap()
        .starts_with("ctxql-predicate-call-"));
    let tiny = NativePredicatePool::new(PoolLimits {
        local_workers: 1,
        call_workers: 1,
        max_jobs: 1,
        max_bytes: 1,
    })
    .unwrap();
    assert_eq!(
        tiny.evaluate(
            program("true"),
            C::Object(BTreeMap::new()),
            BTreeMap::new(),
            host(false),
            limits
        )
        .unwrap_err()
        .kind,
        cdb_core::ErrorKind::Limit
    );
}

#[test]
fn pool_cancellation_with_both_lanes_occupied_and_owned_drain() {
    struct Cancel(Arc<AtomicBool>);
    impl FunctionCallback for Cancel {
        fn check_interrupted(&self) -> Result<()> {
            if self.0.load(Ordering::SeqCst) {
                Err(Error::new(cdb_core::ErrorKind::Deadline, "cancelled"))
            } else {
                Ok(())
            }
        }
        fn call(&self, _: &str, _: &[Value]) -> Result<Value> {
            Ok(Value::Bool(true))
        }
    }
    let pool = Arc::new(
        NativePredicatePool::new(PoolLimits {
            local_workers: 1,
            call_workers: 1,
            max_jobs: 2,
            max_bytes: 4096,
        })
        .unwrap(),
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut joins = Vec::new();
    for source in ["loop {}", "fn:external(\"echo\", true); loop {}"] {
        let pool = pool.clone();
        let cancelled = cancelled.clone();
        joins.push(thread::spawn(move || {
            pool.evaluate(
                program(source),
                C::Object(BTreeMap::new()),
                BTreeMap::new(),
                Arc::new(Cancel(cancelled)),
                EvaluationLimits {
                    max_operations: u64::MAX,
                    ..EvaluationLimits::default()
                },
            )
        }));
    }
    thread::sleep(Duration::from_millis(30));
    assert_eq!(
        pool.evaluate(
            program("true"),
            C::Object(BTreeMap::new()),
            BTreeMap::new(),
            host(false),
            EvaluationLimits::default()
        )
        .unwrap_err()
        .kind,
        cdb_core::ErrorKind::Limit
    );
    cancelled.store(true, Ordering::SeqCst);
    for join in joins {
        assert_eq!(
            join.join().unwrap().unwrap_err().kind,
            cdb_core::ErrorKind::Deadline
        );
    }
    drop(pool);
}
