use cdb_core::{
    claim::{Grounding, TypedLiteral},
    id::Iri,
    CanonicalValue as V, ErrorKind, ExactNumber, Lookup, Timestamp,
};
use cdb_engine::values::{evaluate, Operator as O, Value};
fn n(s: &str) -> Value {
    Value::Number(ExactNumber::parse(s).unwrap())
}
fn s(s: &str) -> Value {
    Value::String(s.into())
}
#[test]
fn all_operator_truth_table() {
    for (id, op, a, b, expected) in [
        ("eq", O::Eq, n("1"), n("1.0"), true),
        ("ne", O::Ne, n("1"), n("2"), true),
        ("gt", O::Gt, n("2"), n("1"), true),
        ("ge", O::Ge, n("1"), n("1"), true),
        ("lt", O::Lt, n("1"), n("2"), true),
        ("le", O::Le, n("1"), n("1"), true),
        ("in", O::In, n("1"), Value::List(vec![n("0"), n("1")]), true),
        (
            "not_in",
            O::NotIn,
            n("2"),
            Value::List(vec![n("0"), n("1")]),
            true,
        ),
        ("substring", O::Contains, s("Aé"), s("é"), true),
        ("empty-substring", O::Contains, s("A"), s(""), true),
        (
            "contains-list",
            O::Contains,
            Value::List(vec![n("1")]),
            n("1"),
            true,
        ),
        (
            "intersection",
            O::ContainsAny,
            Value::List(vec![n("1")]),
            Value::List(vec![n("1")]),
            true,
        ),
        (
            "empty-intersection",
            O::ContainsAny,
            Value::List(vec![n("1")]),
            Value::List(vec![]),
            false,
        ),
        (
            "exists-null",
            O::Exists,
            Value::Null,
            Value::Bool(true),
            true,
        ),
    ] {
        assert_eq!(evaluate(op, &a, &b).unwrap(), expected, "{id}");
    }
}
#[test]
fn missing_null_and_no_coercion() {
    assert_eq!(Value::from_lookup(Lookup::Missing).unwrap(), Value::Missing);
    assert_eq!(
        Value::from_lookup(Lookup::Present(&V::Null)).unwrap(),
        Value::Null
    );
    for op in [
        O::Eq,
        O::Ne,
        O::Gt,
        O::Ge,
        O::Lt,
        O::Le,
        O::In,
        O::NotIn,
        O::Contains,
        O::ContainsAny,
    ] {
        assert!(!evaluate(op, &Value::Missing, &Value::Null).unwrap());
    }
    assert!(evaluate(O::Exists, &Value::Missing, &Value::Bool(false)).unwrap());
    assert!(evaluate(O::Eq, &Value::Null, &Value::Null).unwrap());
    assert!(!evaluate(O::Eq, &Value::Null, &n("1")).unwrap());
    assert!(evaluate(O::Ne, &Value::Null, &n("1")).unwrap());
    assert!(evaluate(O::Gt, &Value::Null, &n("1")).is_err());
    for other in [s("1"), Value::Bool(true)] {
        assert_eq!(
            evaluate(O::Eq, &n("1"), &other).unwrap_err().kind,
            ErrorKind::Invalid
        );
    }
    assert!(evaluate(O::Exists, &Value::Null, &n("1")).is_err());
}
#[test]
fn full_validation_including_late_and_empty_list_cases() {
    let bad = Value::List(vec![n("1"), s("late")]);
    for (op, a, b) in [
        (O::In, n("1"), bad.clone()),
        (O::NotIn, n("1"), bad.clone()),
        (O::Contains, bad.clone(), n("1")),
        (O::ContainsAny, bad.clone(), Value::List(vec![n("1")])),
        (O::ContainsAny, bad.clone(), Value::List(vec![])),
        (O::In, Value::Null, bad),
    ] {
        assert!(evaluate(op, &a, &b).is_err());
    }
    assert!(evaluate(
        O::Contains,
        &Value::List(vec![Value::Missing, Value::Null, n("1")]),
        &n("1")
    )
    .unwrap());
    assert!(!evaluate(
        O::Contains,
        &Value::List(vec![Value::Missing]),
        &Value::Null
    )
    .unwrap());
}
#[test]
fn exact_numbers_large_decimals_and_overflow() {
    assert!(evaluate(O::Gt, &n("9007199254740993"), &n("9007199254740992")).unwrap());
    assert!(evaluate(O::Eq, &n("0.10"), &n("1e-1")).unwrap());
    assert!(evaluate(O::Eq, &n("-0.0"), &n("0")).unwrap());
    assert!(ExactNumber::parse("1e1025").is_err());
    assert!(ExactNumber::parse(&"9".repeat(129)).is_err());
    assert!(ExactNumber::parse("1e1024")
        .unwrap()
        .checked_mul(&ExactNumber::parse("10").unwrap())
        .is_err());
}
#[test]
fn typed_literal_identity_and_mathematical_comparison() {
    let integer = TypedLiteral::new(
        Iri::new("http://www.w3.org/2001/XMLSchema#integer").unwrap(),
        V::integer(1),
        None,
    )
    .unwrap();
    let decimal = TypedLiteral::new(
        Iri::new("http://www.w3.org/2001/XMLSchema#decimal").unwrap(),
        V::integer(1),
        None,
    )
    .unwrap();
    assert_ne!(integer, decimal);
    assert!(evaluate(O::Eq, &Value::Literal(integer), &Value::Literal(decimal)).unwrap());
    let double = TypedLiteral::from_value(&V::parse(br#"{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#double","value":{"format":"binary64","bits":"3fb999999999999a"},"language":null}"#,cdb_core::Limits::default()).unwrap()).unwrap();
    assert!(!evaluate(O::Eq, &Value::Literal(double), &n("0.1")).unwrap());
    for (datatype, value, expected) in [
        ("string", V::string("x"), s("x")),
        ("boolean", V::Bool(true), Value::Bool(true)),
    ] {
        let literal = TypedLiteral::new(
            Iri::new(format!("http://www.w3.org/2001/XMLSchema#{datatype}")).unwrap(),
            value,
            None,
        )
        .unwrap();
        assert!(evaluate(O::Eq, &Value::Literal(literal), &expected).unwrap());
    }
}
#[test]
fn timestamps_grounding_unicode_and_opaque() {
    let a = Value::Timestamp(Timestamp::parse("2026-03-31T00:00:00Z").unwrap());
    let b = Value::Timestamp(Timestamp::parse("2026-03-31T01:00:00+01:00").unwrap());
    assert!(evaluate(O::Eq, &a, &b).unwrap());
    assert!(evaluate(
        O::Gt,
        &Value::Grounding(Grounding::SourceSpansAvailable),
        &Value::Grounding(Grounding::SourceLineageAvailable)
    )
    .unwrap());
    assert!(evaluate(
        O::Gt,
        &Value::Grounding(Grounding::SourceLineageAvailable),
        &Value::Grounding(Grounding::ClaimOnly)
    )
    .unwrap());
    assert!(!evaluate(O::Eq, &s("é"), &s("e\u{301}")).unwrap());
    assert!(!evaluate(O::Eq, &s("A"), &s("a")).unwrap());
    let object = Value::from_json(&V::Object(Default::default())).unwrap();
    assert!(evaluate(O::Exists, &object, &Value::Bool(true)).unwrap());
    assert_eq!(
        evaluate(O::Eq, &object, &object).unwrap_err().kind,
        ErrorKind::Unsupported
    );
}
#[test]
fn list_work_is_bounded() {
    let a = Value::List(vec![n("1"); 1001]);
    assert_eq!(
        evaluate(O::ContainsAny, &a, &a).unwrap_err().kind,
        ErrorKind::Limit
    );
}
