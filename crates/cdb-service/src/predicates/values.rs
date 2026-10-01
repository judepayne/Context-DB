//! Owned, bounded native values. No external Dynamic or function pointer enters.
use cdb_core::{CanonicalValue as C, Error, ExactNumber, Result};
use cdb_engine::{predicates::EvaluationLimits, values::Value};
use rhai::{Array, Dynamic, ImmutableString, Map, INT};
use rust_decimal::Decimal;

#[derive(Clone, Debug)]
struct Opaque(Value);

pub fn ingress(value: &Value, limits: EvaluationLimits) -> Result<Dynamic> {
    let mut budget = Budget::new(limits);
    input(value, &mut budget, 0)
}
pub fn egress(value: &Dynamic, limits: EvaluationLimits) -> Result<Value> {
    let mut budget = Budget::new(limits);
    output(value, &mut budget, 0)
}
pub fn measure(value: &Value) -> Result<usize> {
    fn walk(value: &Value) -> Result<usize> {
        let payload = match value {
            Value::Null | Value::Bool(_) | Value::Missing => 8,
            Value::Number(n) => n.token().len(),
            Value::String(s) => s.len(),
            Value::List(items) => items.iter().try_fold(8usize, |n, v| {
                n.checked_add(walk(v)?).ok_or_else(Error::limit)
            })?,
            Value::Object(value) => value.canonical_bytes(cdb_core::Limits::default())?.len(),
            Value::Literal(value) => value
                .value()
                .canonical_bytes(cdb_core::Limits::default())?
                .len()
                .checked_add(value.datatype().as_str().len())
                .ok_or_else(Error::limit)?,
            Value::Timestamp(_) | Value::Grounding(_) => 32,
        };
        payload.checked_add(8).ok_or_else(Error::limit)
    }
    walk(value)
}
struct Budget {
    limits: EvaluationLimits,
    nodes: usize,
    bytes: usize,
}
impl Budget {
    fn new(limits: EvaluationLimits) -> Self {
        Self {
            limits,
            nodes: 0,
            bytes: 0,
        }
    }
    fn charge(&mut self, depth: usize, len: usize, bytes: usize) -> Result<()> {
        self.nodes = self.nodes.checked_add(1).ok_or_else(Error::limit)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(Error::limit)?;
        if depth > self.limits.max_depth
            || len > self.limits.max_collection_len
            || self.nodes > self.limits.max_value_nodes
            || self.bytes > self.limits.max_result_bytes
        {
            return Err(Error::limit());
        }
        Ok(())
    }
}
fn input(v: &Value, b: &mut Budget, d: usize) -> Result<Dynamic> {
    b.charge(d, 0, 8)?;
    Ok(match v {
        Value::Null => Dynamic::UNIT,
        Value::Bool(v) => Dynamic::from_bool(*v),
        Value::Number(n) => {
            let token = n.token();
            b.charge(d, 0, token.len())?;
            let decimal = Decimal::from_str_exact(&token)
                .map_err(|_| Error::invalid("unrepresentable Decimal ingress"))?;
            if ExactNumber::parse(&decimal.to_string())? != *n {
                return Err(Error::invalid("lossy Decimal ingress"));
            }
            Dynamic::from(decimal)
        }
        Value::String(s) => {
            b.charge(d, 0, s.len())?;
            Dynamic::from(s.clone())
        }
        Value::List(a) => {
            b.charge(d, a.len(), 0)?;
            Dynamic::from_array(
                a.iter()
                    .map(|v| input(v, b, d + 1))
                    .collect::<Result<Array>>()?,
            )
        }
        Value::Object(C::Object(o)) => {
            b.charge(d, o.len(), 0)?;
            let mut map = Map::new();
            for (k, v) in o {
                b.charge(d, 0, k.len())?;
                map.insert(k.clone().into(), input(&Value::from_json(v)?, b, d + 1)?);
            }
            Dynamic::from_map(map)
        }
        Value::Object(v) => input(&Value::from_json(v)?, b, d + 1)?,
        Value::Literal(l) => {
            let dt = l.datatype().as_str();
            if matches!(l.value(), C::Number(_))
                || dt.ends_with("#float")
                || dt.ends_with("#double")
            {
                input(&Value::Number(l.exact_numeric()?), b, d + 1)?
            } else if dt.ends_with("#string") || dt.ends_with("#boolean") {
                input(&Value::from_json(l.value())?, b, d + 1)?
            } else if dt == "http://www.w3.org/2001/XMLSchema#dateTime" {
                Dynamic::from(Opaque(Value::Timestamp(cdb_core::Timestamp::parse(
                    l.value().as_str()?,
                )?)))
            } else {
                return Err(Error::invalid("unsupported literal ingress"));
            }
        }
        Value::Missing | Value::Timestamp(_) | Value::Grounding(_) => {
            Dynamic::from(Opaque(v.clone()))
        }
    })
}
fn output(v: &Dynamic, b: &mut Budget, d: usize) -> Result<Value> {
    b.charge(d, 0, 8)?;
    Ok(if v.is_unit() {
        Value::Null
    } else if v.is::<bool>() {
        Value::Bool(v.clone_cast())
    } else if v.is::<INT>() {
        Value::Number(ExactNumber::parse(&v.clone_cast::<INT>().to_string())?)
    } else if v.is::<Decimal>() {
        Value::Number(ExactNumber::parse(&v.clone_cast::<Decimal>().to_string())?)
    } else if v.is::<ImmutableString>() {
        let s = v.clone_cast::<ImmutableString>();
        b.charge(d, 0, s.len())?;
        Value::String(s.to_string())
    } else if v.is::<Opaque>() {
        v.clone_cast::<Opaque>().0
    } else if v.is::<Array>() {
        let a = v.clone_cast::<Array>();
        b.charge(d, a.len(), 0)?;
        Value::List(
            a.iter()
                .map(|v| output(v, b, d + 1))
                .collect::<Result<_>>()?,
        )
    } else if v.is::<Map>() {
        let m = v.clone_cast::<Map>();
        b.charge(d, m.len(), 0)?;
        let mut o = std::collections::BTreeMap::new();
        for (k, v) in m {
            b.charge(d, 0, k.len())?;
            o.insert(k.to_string(), canonical(&output(&v, b, d + 1)?)?);
        }
        Value::Object(C::Object(o))
    } else {
        return Err(Error::invalid(
            "unsupported native result (including function pointers)",
        ));
    })
}
pub fn canonical(v: &Value) -> Result<C> {
    Ok(match v {
        Value::Null => C::Null,
        Value::Bool(v) => C::Bool(*v),
        Value::Number(v) => C::Number(v.clone()),
        Value::String(v) => C::String(v.clone()),
        Value::List(v) => C::Array(v.iter().map(canonical).collect::<Result<_>>()?),
        Value::Object(v) => v.clone(),
        _ => {
            return Err(Error::invalid(
                "typed value cannot enter canonical predicate state",
            ));
        }
    })
}

/// Only pure typed comparisons; opaque wrappers never expose mutable host data.
pub fn register(engine: &mut rhai::Engine) {
    engine.register_fn("exists", |v: Dynamic| {
        !v.is::<Opaque>() || !matches!(v.clone_cast::<Opaque>().0, Value::Missing)
    });
    engine.register_fn("==", |a: Opaque, b: Opaque| a.0 == b.0);
    engine.register_fn("!=", |a: Opaque, b: Opaque| a.0 != b.0);
    for (symbol, op) in [
        ("<", cdb_engine::values::Operator::Lt),
        ("<=", cdb_engine::values::Operator::Le),
        (">", cdb_engine::values::Operator::Gt),
        (">=", cdb_engine::values::Operator::Ge),
    ] {
        engine.register_fn(
            symbol,
            move |a: Opaque, b: Opaque| -> std::result::Result<bool, Box<rhai::EvalAltResult>> {
                cdb_engine::values::evaluate(op, &a.0, &b.0).map_err(|e| e.to_string().into())
            },
        );
    }
}
