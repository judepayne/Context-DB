//! Native Decimal predicate executor. Constructed Rhai engines never leave their worker.
mod adapt;
pub mod pool;
mod program;
mod values;

use cdb_core::{CanonicalValue as C, Error, Result};
use cdb_engine::{
    predicates::{EvaluationLimits, FunctionCallback, Outcome, PredicateExecutor, Program},
    values::Value,
};
use pool::JobClass;
use rhai::{Dynamic, Engine, OptimizationLevel, Scope, AST};
use std::{
    any::TypeId,
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
pub(crate) use values::canonical as canonical_value;

/// Stateless synchronous implementation. Production callers should use
/// [`pool::NativePredicatePool`] so Rhai never blocks a Tokio executor thread.
#[derive(Clone, Copy, Default)]
pub struct NativePredicateExecutor;

fn error(e: impl std::fmt::Display) -> Error {
    Error::invalid(format!("predicate: {e}"))
}
fn check_limits(l: EvaluationLimits) -> Result<()> {
    if [
        l.max_source_bytes,
        l.max_depth,
        l.max_state_bytes,
        l.max_value_nodes,
        l.max_collection_len,
        l.max_calls,
        l.max_argument_bytes,
        l.max_result_bytes,
    ]
    .contains(&0)
        || l.max_operations == 0
    {
        return Err(Error::limit());
    }
    Ok(())
}
fn engine(l: EvaluationLimits) -> Engine {
    let mut e = Engine::new();
    values::register(&mut e);
    e.set_optimization_level(OptimizationLevel::None);
    for name in ["eval", "import", "export", "Fn", "print", "debug"] {
        e.disable_symbol(name);
    }
    e.set_max_operations(l.max_operations);
    e.set_max_expr_depths(l.max_depth, l.max_depth);
    e.set_max_call_levels(l.max_depth);
    e.set_max_variables(l.max_value_nodes);
    e.set_max_functions(l.max_collection_len);
    e.set_max_string_size(l.max_result_bytes);
    e.set_max_array_size(l.max_collection_len);
    e.set_max_map_size(l.max_collection_len);
    e
}
struct Prepared {
    order: Vec<String>,
    lets: BTreeMap<String, AST>,
    next: BTreeMap<String, AST>,
    keep: AST,
    call_capable: bool,
}
fn prepare(p: &Program, names: &[String], l: EvaluationLimits, e: &Engine) -> Result<Prepared> {
    check_limits(l)?;
    let mut env = BTreeSet::from(["state".to_owned()]);
    for n in names {
        if program::reserved(n) || !env.insert(n.clone()) {
            return Err(error("binding collision"));
        }
    }
    for n in p.lets.keys() {
        if program::reserved(n) || env.contains(n) {
            return Err(error("LET collision"));
        }
    }
    let mut bytes = 0usize;
    let mut nodes = 0usize;
    let mut call_capable = false;
    let mut compile = |s: &str, allowed: &BTreeSet<String>| -> Result<(AST, BTreeSet<String>)> {
        bytes = bytes.checked_add(s.len()).ok_or_else(Error::limit)?;
        if bytes > l.max_source_bytes {
            return Err(Error::limit());
        }
        let adapted = adapt::lower(s).map_err(error)?;
        let a = program::analyze(
            e,
            &adapted.source,
            program::Limits {
                source_bytes: l.max_source_bytes.saturating_mul(24),
                nodes: l.max_value_nodes,
                depth: l.max_depth,
            },
        )
        .map_err(error)?;
        nodes = nodes.checked_add(a.nodes).ok_or_else(Error::limit)?;
        if nodes > l.max_value_nodes {
            return Err(Error::limit());
        }
        // The generated identifier cannot occur in authored code. Searching the
        // lowered text is deliberately conservative and also catches callbacks
        // nested in closures or otherwise opaque AST payloads.
        if adapted.source.contains("ctxql_internal_external") {
            call_capable = true;
        }
        for free in &a.free_variables {
            if !allowed.contains(free) {
                return Err(error(format!("unknown dependency: {free}")));
            }
        }
        Ok((a.ast, a.free_variables))
    };
    let mut all = env.clone();
    all.extend(p.lets.keys().cloned());
    let mut deps = BTreeMap::new();
    let mut lets = BTreeMap::new();
    for (n, s) in &p.lets {
        let (a, f) = compile(s, &all)?;
        deps.insert(
            n.clone(),
            f.into_iter()
                .filter(|v| p.lets.contains_key(v))
                .collect::<BTreeSet<_>>(),
        );
        lets.insert(n.clone(), a);
    }
    let mut order = Vec::new();
    while !deps.is_empty() {
        let n = deps
            .iter()
            .find(|(_, d)| d.is_empty())
            .map(|(n, _)| n.clone())
            .ok_or_else(|| error("LET cycle"))?;
        deps.remove(&n);
        for d in deps.values_mut() {
            d.remove(&n);
        }
        order.push(n);
    }
    let mut next = BTreeMap::new();
    for (n, s) in &p.next {
        if !p.init.contains_key(n) {
            return Err(error("NEXT key absent from INIT"));
        }
        next.insert(n.clone(), compile(s, &all)?.0);
    }
    all.insert("next".into());
    let keep = compile(&p.keep, &all)?.0;
    let _ = state_dynamic(&C::Object(p.init.clone()), l)?;
    Ok(Prepared {
        order,
        lets,
        next,
        keep,
        call_capable,
    })
}
fn state_dynamic(s: &C, l: EvaluationLimits) -> Result<Dynamic> {
    if !matches!(s, C::Object(_)) {
        return Err(error("state must be object"));
    }
    let mut budget = l;
    budget.max_result_bytes = l.max_state_bytes;
    let result = values::ingress(&Value::from_json(s)?, budget)?;
    if s.canonical_bytes(cdb_core::Limits::default())?.len() > l.max_state_bytes {
        return Err(Error::limit());
    }
    Ok(result)
}
fn scope(env: &BTreeMap<String, Dynamic>) -> Scope<'static> {
    let mut scope = Scope::new();
    for (name, value) in env {
        scope.push_constant_dynamic(name.clone(), value.clone());
    }
    scope
}

pub fn classify_program(p: &Program, names: &[String], l: EvaluationLimits) -> Result<JobClass> {
    let prepared = prepare(p, names, l, &engine(l))?;
    Ok(if prepared.call_capable {
        JobClass::CallCapable
    } else {
        JobClass::LocalOnly
    })
}
pub(crate) fn job_bytes(
    p: &Program,
    state: &C,
    bindings: &BTreeMap<String, Value>,
) -> Result<usize> {
    let source = p
        .keep
        .len()
        .checked_add(p.lets.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>())
        .and_then(|n| n.checked_add(p.next.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()))
        .ok_or_else(Error::limit)?;
    let state = state.canonical_bytes(cdb_core::Limits::default())?.len();
    bindings.iter().try_fold(
        source.checked_add(state).ok_or_else(Error::limit)?,
        |total, (name, value)| {
            let total = total.checked_add(name.len()).ok_or_else(Error::limit)?;
            total
                .checked_add(values::measure(value)?)
                .ok_or_else(Error::limit)
        },
    )
}

impl PredicateExecutor for NativePredicateExecutor {
    fn validate(&self, p: &Program, names: &[String], l: EvaluationLimits) -> Result<()> {
        prepare(p, names, l, &engine(l)).map(|_| ())
    }
    fn evaluate(
        &self,
        p: &Program,
        state: &C,
        bindings: &BTreeMap<String, Value>,
        host: Arc<dyn FunctionCallback>,
        l: EvaluationLimits,
    ) -> Result<Outcome> {
        self.evaluate_with_optimization(p, state, bindings, host, l, OptimizationLevel::None)
    }
}
impl NativePredicateExecutor {
    pub fn evaluate_with_optimization(
        &self,
        p: &Program,
        state: &C,
        bindings: &BTreeMap<String, Value>,
        host: Arc<dyn FunctionCallback>,
        l: EvaluationLimits,
        level: OptimizationLevel,
    ) -> Result<Outcome> {
        check_limits(l)?;
        host.check_interrupted()?;
        let mut e = engine(l);
        let mut prepared = prepare(p, &bindings.keys().cloned().collect::<Vec<_>>(), l, &e)?;
        for ast in prepared
            .lets
            .values_mut()
            .chain(prepared.next.values_mut())
            .chain(std::iter::once(&mut prepared.keep))
        {
            *ast = e.optimize_ast(&Scope::new(), ast.clone(), level);
        }
        let sticky = Arc::new(Mutex::new(None::<Error>));
        let calls = Arc::new(AtomicUsize::new(0));
        let operations = Arc::new(AtomicU64::new(0));
        let sticky_progress = sticky.clone();
        let progress_host = host.clone();
        e.on_progress(move |_| {
            let failure = if operations.fetch_add(1, Ordering::Relaxed) >= l.max_operations {
                Some(Error::limit())
            } else {
                progress_host.check_interrupted().err()
            };
            if let Some(failure) = failure {
                let mut first = sticky_progress.lock().unwrap_or_else(|e| e.into_inner());
                if first.is_none() {
                    *first = Some(failure);
                }
                Some(Dynamic::from("predicate interrupted or exhausted"))
            } else {
                None
            }
        });
        for arity in 1..=16 {
            let sticky_call = sticky.clone();
            let callback_host = host.clone();
            let calls = calls.clone();
            e.register_raw_fn(
                "ctxql_internal_external",
                vec![TypeId::of::<Dynamic>(); arity],
                move |_, args| -> std::result::Result<Dynamic, Box<rhai::EvalAltResult>> {
                    let invoke = || -> Result<Dynamic> {
                        if calls.fetch_add(1, Ordering::Relaxed) >= l.max_calls {
                            return Err(Error::limit());
                        }
                        callback_host.check_interrupted()?;
                        let name = args[0]
                            .clone()
                            .try_cast::<rhai::ImmutableString>()
                            .ok_or_else(|| error("callback name must be string"))?;
                        let mut bound = l;
                        bound.max_result_bytes = l.max_argument_bytes;
                        let array =
                            Dynamic::from_array(args[1..].iter().map(|v| (**v).clone()).collect());
                        let Value::List(arguments) = values::egress(&array, bound)? else {
                            unreachable!()
                        };
                        let result = callback_host.call(&name, &arguments)?;
                        callback_host.check_interrupted()?;
                        values::ingress(&result, l)
                    };
                    invoke().map_err(|failure| {
                        let mut first = sticky_call.lock().unwrap_or_else(|e| e.into_inner());
                        if first.is_none() {
                            *first = Some(failure.clone());
                        }
                        failure.to_string().into()
                    })
                },
            );
        }
        let mut env = BTreeMap::new();
        for (name, value) in bindings {
            env.insert(name.clone(), values::ingress(value, l)?);
        }
        let native_state = state_dynamic(state, l)?;
        env.insert("state".into(), native_state.clone());
        let run = |ast: &AST, env: &BTreeMap<String, Dynamic>| -> Result<Dynamic> {
            host.check_interrupted()?;
            let evaluated = e
                .eval_ast_with_scope::<Dynamic>(&mut scope(env), ast)
                .map_err(error);
            if let Some(failure) = sticky.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                return Err(failure);
            }
            host.check_interrupted()?;
            let value = evaluated?;
            values::egress(&value, l)?;
            Ok(value)
        };
        for name in prepared.order {
            let value = run(&prepared.lets[&name], &env)?;
            env.insert(name, value);
        }
        let mut native_next = native_state.clone_cast::<rhai::Map>();
        for (name, ast) in prepared.next {
            native_next.insert(name.into(), run(&ast, &env)?);
        }
        let native_next = Dynamic::from_map(native_next);
        let next_value = values::egress(&native_next, l)?;
        let next = values::canonical(&next_value)?;
        let _ = state_dynamic(&next, l)?;
        env.insert("next".into(), native_next);
        let keep_value = run(&prepared.keep, &env)?;
        if !keep_value.is::<bool>() {
            return Err(error("KEEP requires boolean"));
        }
        Ok(Outcome {
            keep: keep_value.clone_cast::<bool>(),
            next,
        })
    }
}
