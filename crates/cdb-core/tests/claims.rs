mod common;
use cdb_core::{claim::*, id::Iri, CanonicalValue as V, Timestamp};
use common::*;
#[test]
fn typed_identity_and_lossless_roundtrip() {
    let a = candidate("a");
    assert_eq!(CandidateClaim::from_value(&a.projection()).unwrap(), a);
    let integer = TypedLiteral::new(
        Iri::new("http://www.w3.org/2001/XMLSchema#integer").unwrap(),
        json("1"),
        None,
    )
    .unwrap();
    let decimal = TypedLiteral::new(
        Iri::new("http://www.w3.org/2001/XMLSchema#decimal").unwrap(),
        json("1.0"),
        None,
    )
    .unwrap();
    assert_ne!(integer, decimal);
    assert_eq!(
        integer.exact_numeric().unwrap(),
        decimal.exact_numeric().unwrap()
    );
    let text = TypedLiteral::new(
        Iri::new("http://www.w3.org/2001/XMLSchema#string").unwrap(),
        V::string("https://example.org/node"),
        None,
    )
    .unwrap();
    assert!(matches!(
        ClaimObject::from_value(&text.projection()).unwrap(),
        ClaimObject::Literal(_)
    ));
    let lang = TypedLiteral::new(
        Iri::new("http://www.w3.org/1999/02/22-rdf-syntax-ns#langString").unwrap(),
        V::string("café 東京"),
        Some("fr-CA".into()),
    )
    .unwrap();
    assert_eq!(TypedLiteral::from_value(&lang.projection()).unwrap(), lang);
}
#[test]
fn binary_bits_identity_survives_conversion_failure() {
    let l = TypedLiteral::new(
        Iri::new("http://www.w3.org/2001/XMLSchema#double").unwrap(),
        json(r#"{"format":"binary64","bits":"0000000000000001"}"#),
        None,
    )
    .unwrap();
    assert!(l.exact_numeric().is_err());
    assert_eq!(TypedLiteral::from_value(&l.projection()).unwrap(), l);
    for bits in ["7ff0000000000000", "7ff8000000000001", "3FF0000000000000"] {
        assert!(TypedLiteral::new(
            Iri::new("http://www.w3.org/2001/XMLSchema#double").unwrap(),
            json(&format!(r#"{{"format":"binary64","bits":"{bits}"}}"#)),
            None
        )
        .is_err());
    }
}
#[test]
fn no_admission_timestamp_or_default_lifecycle() {
    let mut c = candidate("c").projection();
    set(
        &mut c,
        "transaction_time",
        V::string("1900-01-01T00:00:00Z"),
    );
    assert!(CandidateClaim::from_value(&c).is_err());
    let a = AdmittedClaim::assign(candidate("c"), Timestamp::from_millis(10).unwrap());
    let r = a.response(LifecycleState::Retracted);
    assert_eq!(
        r.field("meta")
            .unwrap()
            .field("lifecycle_state")
            .unwrap()
            .as_str()
            .unwrap(),
        "retracted"
    );
}
#[test]
fn strict_required_fields_grounding_extensions_and_datatypes() {
    let base = candidate("c").projection();
    for key in [
        "confidence",
        "subject_type",
        "relation_type",
        "grounding_level",
    ] {
        let V::Object(mut o) = base.clone() else {
            unreachable!()
        };
        o.remove(key);
        assert!(CandidateClaim::from_value(&V::Object(o)).is_err());
    }
    let mut c = base.clone();
    set(&mut c, "confidence", json("1.0000000000000000001"));
    assert!(CandidateClaim::from_value(&c).is_err());
    set(&mut c, "confidence", json("1"));
    set(
        &mut c,
        "grounding_level",
        V::string("source_spans_available"),
    );
    assert!(CandidateClaim::from_value(&c).is_err());
    let mut c = base;
    set(&mut c, "ext", json(r#"{"transaction_time":"forged"}"#));
    assert!(CandidateClaim::from_value(&c).is_err());
    assert!(TypedLiteral::new(
        Iri::new("http://www.w3.org/2001/XMLSchema#integer").unwrap(),
        json("0.5"),
        None
    )
    .is_err());
}
#[test]
fn temporal_extensions_preserve_absence() {
    let mut c = candidate("c").projection();
    set(
        &mut c,
        "source_observed_at",
        V::string("1900-01-01T01:00:00+01:00"),
    );
    let c = CandidateClaim::from_value(&c).unwrap();
    let r = AdmittedClaim::assign(c, Timestamp::from_millis(0).unwrap())
        .response(LifecycleState::Active);
    let t = r
        .field("meta")
        .unwrap()
        .field("ext")
        .unwrap()
        .field("ctxql.core.temporal/v1")
        .unwrap();
    assert!(t.field("valid_time").is_err());
    assert_eq!(
        t.field("source_observed_at").unwrap().as_str().unwrap(),
        "1900-01-01T00:00:00.000Z"
    );
}
