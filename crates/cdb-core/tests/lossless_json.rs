use cdb_core::{CanonicalValue as V, Limits, Lookup};
fn parse(s: &str) -> V {
    V::parse(s.as_bytes(), Limits::default()).unwrap()
}
#[test]
fn no_float_bridge_or_private_number_spoof() {
    let v = parse(
        r#"{"n":9007199254740993,"d":0.10000000000000000000000001,"$serde_json::private::Number":"1e999999"}"#,
    );
    assert_eq!(
        v.field("n").unwrap().as_number().unwrap().token(),
        "9007199254740993"
    );
    assert_eq!(
        v.field("d").unwrap().as_number().unwrap().token(),
        "0.10000000000000000000000001"
    );
    assert!(v
        .field("$serde_json::private::Number")
        .unwrap()
        .as_str()
        .is_ok());
    assert_eq!(
        v,
        V::parse(
            &v.canonical_bytes(Limits::default()).unwrap(),
            Limits::default()
        )
        .unwrap()
    );
}
#[test]
fn duplicate_decoded_keys_at_every_depth() {
    for s in [
        r#"{"a":1,"\u0061":2}"#,
        r#"[{"x":{"a":0,"a":1}}]"#,
        r#"{"\ud83d\ude42":1,"🙂":2}"#,
    ] {
        assert!(V::parse(s.as_bytes(), Limits::default()).is_err());
    }
    assert!(V::object(vec![("x".into(), V::Null), ("x".into(), V::Bool(false))]).is_err());
}
#[test]
fn unicode_and_escaping() {
    let v = parse("{\"𐀀\":1,\"\":2,\"s\":\"/é\\n\\u0001\"}");
    assert_eq!(
        String::from_utf8(v.canonical_bytes(Limits::default()).unwrap()).unwrap(),
        "{\"s\":\"/é\\n\\u0001\",\"\":2,\"𐀀\":1}"
    );
    for s in [
        r#""\ud800""#,
        r#""\udc00""#,
        r#"[1,]"#,
        r#"{"x":0,}"#,
        r#"NaN"#,
    ] {
        assert!(V::parse(s.as_bytes(), Limits::default()).is_err());
    }
    assert!(V::parse(&[b'"', 255, b'"'], Limits::default()).is_err());
}
#[test]
fn missing_is_not_null_and_strings_not_timestamps() {
    let v = parse(r#"{"x":null,"t":"2026-01-01T01:00:00+01:00"}"#);
    assert_eq!(v.lookup("absent").unwrap(), Lookup::Missing);
    assert_eq!(v.lookup("x").unwrap(), Lookup::Present(&V::Null));
    assert_eq!(
        v.field("t").unwrap().as_str().unwrap(),
        "2026-01-01T01:00:00+01:00"
    );
}
#[test]
fn budgets_fail_without_partial_output() {
    let zero = Limits::new(0, 0, 0, 0, 0).unwrap();
    assert!(V::parse(b"null", zero).is_err());
    assert!(V::Null.canonical_bytes(zero).is_err());
    let small = Limits::new(1000, 1, 100, 1000, 3).unwrap();
    assert!(V::parse(b"[[[]]]", small).is_err());
    assert!(parse("[1,2]").canonical_bytes(small).is_err());
    let a = Limits::new(1000, 16, 100, 1000, 1000).unwrap();
    let b = Limits::new(2000, 32, 200, 2000, 2000).unwrap();
    assert_eq!(
        parse("[1,2]").canonical_bytes(a).unwrap(),
        parse("[1,2]").canonical_bytes(b).unwrap()
    );
}
