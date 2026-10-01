//! Pure C3a evaluation. Lists retain missing entries; typed literals retain identity.
use crate::diagnostics::unsupported;
use cdb_core::{
    claim::{Grounding, TypedLiteral},
    CanonicalValue as V, Error, ExactNumber, Lookup, Result, Timestamp,
};
use std::cmp::Ordering;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Missing,
    Null,
    Bool(bool),
    Number(ExactNumber),
    String(String),
    Timestamp(Timestamp),
    Grounding(Grounding),
    Literal(TypedLiteral),
    List(Vec<Value>),
    /// Only exists can inspect opaque metadata without a provider.
    Object(V),
}
impl Value {
    pub fn from_lookup(value: Lookup<'_>) -> Result<Self> {
        match value {
            Lookup::Missing => Ok(Self::Missing),
            Lookup::Present(v) => Self::from_json(v),
        }
    }
    pub fn from_json(v: &V) -> Result<Self> {
        Ok(match v {
            V::Null => Self::Null,
            V::Bool(b) => Self::Bool(*b),
            V::Number(n) => Self::Number(n.clone()),
            V::String(s) => Self::String(s.clone()),
            V::Array(a) => Self::List(a.iter().map(Self::from_json).collect::<Result<_>>()?),
            V::Object(o) if o.get("kind") == Some(&V::string("literal")) => {
                Self::Literal(TypedLiteral::from_value(v)?)
            }
            V::Object(_) => Self::Object(v.clone()),
        })
    }
    fn scalar(&self) -> Result<Self> {
        if let Self::Literal(l) = self {
            let dt = l.datatype().as_str();
            if dt == "http://www.w3.org/2001/XMLSchema#dateTime" {
                return Ok(Self::Timestamp(Timestamp::parse(l.value().as_str()?)?));
            }
            if matches!(l.value(), V::Number(_))
                || dt.ends_with("#float")
                || dt.ends_with("#double")
            {
                return Ok(Self::Number(l.exact_numeric()?));
            }
            if dt == "http://www.w3.org/2001/XMLSchema#string"
                || dt == "http://www.w3.org/2001/XMLSchema#boolean"
            {
                return Self::from_json(l.value());
            }
            return Err(unsupported("opaque typed literal comparison"));
        }
        match self {
            Self::Object(_) => Err(unsupported("opaque object comparison")),
            Self::List(_) => Err(Error::invalid("scalar required")),
            _ => Ok(self.clone()),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operator {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    In,
    NotIn,
    Contains,
    ContainsAny,
    Exists,
    Isa,
    NotIsa,
    SubpropertyOf,
    NotSubpropertyOf,
    ContainsIsa,
    ContainsSubpropertyOf,
}
impl Operator {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "=" => Self::Eq,
            "!=" => Self::Ne,
            ">" => Self::Gt,
            ">=" => Self::Ge,
            "<" => Self::Lt,
            "<=" => Self::Le,
            "in" => Self::In,
            "not_in" => Self::NotIn,
            "contains" => Self::Contains,
            "contains_any" => Self::ContainsAny,
            "exists" => Self::Exists,
            "isa" => Self::Isa,
            "not_isa" => Self::NotIsa,
            "subproperty_of" => Self::SubpropertyOf,
            "not_subproperty_of" => Self::NotSubpropertyOf,
            "contains_isa" => Self::ContainsIsa,
            "contains_subproperty_of" => Self::ContainsSubpropertyOf,
            _ => return Err(Error::invalid("unknown operator")),
        })
    }
}
fn rank(g: Grounding) -> u8 {
    match g {
        Grounding::ClaimOnly => 0,
        Grounding::SourceLineageAvailable => 1,
        Grounding::SourceSpansAvailable => 2,
    }
}
fn compare(a: &Value, b: &Value, ordering: bool) -> Result<Option<Ordering>> {
    let (a, b) = (a.scalar()?, b.scalar()?);
    if matches!(a, Value::Missing) || matches!(b, Value::Missing) {
        return Ok(None);
    }
    if matches!(a, Value::Null) || matches!(b, Value::Null) {
        if ordering {
            return Err(Error::invalid("null ordering"));
        }
        return Ok(if a == b { Some(Ordering::Equal) } else { None });
    }
    Ok(Some(match (&a, &b) {
        (Value::Number(a), Value::Number(b)) => a.checked_cmp(b)?,
        (Value::String(a), Value::String(b)) => a.cmp(b),
        (Value::Bool(a), Value::Bool(b)) if !ordering => a.cmp(b),
        (Value::Timestamp(a), Value::Timestamp(b)) => a.cmp(b),
        (Value::Grounding(a), Value::Grounding(b)) => rank(*a).cmp(&rank(*b)),
        _ => return Err(Error::invalid("incompatible predicate types")),
    }))
}
fn validate_list(list: &[Value]) -> Result<()> {
    let mut exemplar = None;
    for value in list {
        value.scalar()?;
        if !matches!(value, Value::Null | Value::Missing) {
            if let Some(first) = exemplar {
                compare(first, value, false)?;
            } else {
                exemplar = Some(value);
            }
        }
    }
    Ok(())
}
fn membership(needle: &Value, list: &[Value]) -> Result<bool> {
    needle.scalar()?;
    validate_list(list)?;
    // Validate every element, including a list whose first element matches.
    let mut matched = false;
    for item in list {
        matched |= compare(needle, item, false)? == Some(Ordering::Equal);
    }
    Ok(matched)
}
/// No lookup, clocks, coercion, graph reads or short-circuit suppression of list errors.
pub fn evaluate(op: Operator, left: &Value, right: &Value) -> Result<bool> {
    evaluate_with_limits(op, left, right, cdb_core::Limits::default())
}
/// Explicit operational ceiling for pure list comparisons; never changes a successful answer.
pub fn evaluate_with_limits(
    op: Operator,
    left: &Value,
    right: &Value,
    limits: cdb_core::Limits,
) -> Result<bool> {
    let size = |v: &Value| match v {
        Value::List(a) => a.len().saturating_add(1),
        _ => 1,
    };
    let work = size(left)
        .checked_mul(size(right))
        .ok_or_else(Error::limit)?;
    if work > limits.work() {
        return Err(Error::limit());
    }
    if op == Operator::Exists {
        let Value::Bool(want) = right else {
            return Err(Error::invalid("exists boolean operand"));
        };
        return Ok(*want != matches!(left, Value::Missing));
    }
    if matches!(left, Value::Missing) {
        return Ok(false);
    }
    match op {
        Operator::Eq | Operator::Ne => {
            let equal = compare(left, right, false)? == Some(Ordering::Equal);
            Ok(if op == Operator::Eq { equal } else { !equal })
        }
        Operator::Gt | Operator::Ge | Operator::Lt | Operator::Le => {
            let c = compare(left, right, true)?;
            Ok(match op {
                Operator::Gt => c == Some(Ordering::Greater),
                Operator::Ge => matches!(c, Some(Ordering::Greater | Ordering::Equal)),
                Operator::Lt => c == Some(Ordering::Less),
                _ => matches!(c, Some(Ordering::Less | Ordering::Equal)),
            })
        }
        Operator::In | Operator::NotIn => {
            let Value::List(list) = right else {
                return Err(Error::invalid("membership list operand"));
            };
            let matched = membership(left, list)?;
            Ok(if op == Operator::In {
                matched
            } else {
                !matched
            })
        }
        Operator::Contains => match left {
            Value::List(list) => membership(right, list),
            _ => match (left.scalar()?, right.scalar()?) {
                (Value::String(a), Value::String(b)) => Ok(a.contains(&b)),
                _ => Err(Error::invalid("contains string/string or list/scalar")),
            },
        },
        Operator::ContainsAny => {
            let (Value::List(a), Value::List(b)) = (left, right) else {
                return Err(Error::invalid("contains_any list/list"));
            };
            // Cross validate even when one side is empty, and never hide a late mismatch.
            validate_list(a)?;
            validate_list(b)?;
            let mut matched = false;
            for v in a {
                matched |= membership(v, b)?;
            }
            Ok(matched)
        }
        Operator::Exists => unreachable!(),
        Operator::Isa
        | Operator::NotIsa
        | Operator::SubpropertyOf
        | Operator::NotSubpropertyOf
        | Operator::ContainsIsa
        | Operator::ContainsSubpropertyOf => Err(unsupported("prepared ontology required")),
    }
}
