use cdb_core::{CanonicalValue as V, Limits, Lookup};
use cdb_engine::{compiler::FieldRef, values::Value};
#[test]
fn explicit_registry_and_exact_extension_keys() {
    for name in [
        "meta:claim_id",
        "meta:subject_id",
        "meta:object_id",
        "meta:relation",
        "meta:relation_type",
        "meta:subject_type",
        "meta:object_type",
        "meta:claim_type",
        "meta:confidence",
        "meta:grounding_level",
        "meta:transaction_time",
        "meta:lifecycle_state",
        "meta:lineage",
        "meta:ext",
        "meta:depth",
    ] {
        assert!(FieldRef::parse(name).is_ok(), "{name}");
    }
    for name in [
        "meta:unknown",
        "meta.ext.risk",
        "meta:ext:",
        "path.path.meta:depth",
        "bound:x",
        "meta:ext:bad\u{0}",
    ] {
        assert!(FieldRef::parse(name).is_err(), "{name}");
    }
    for key in [
        "source_authority",
        "bank:source_authority",
        "ctxql.core.temporal/v1",
    ] {
        let f = FieldRef::parse(&format!("path.meta:ext:{key}")).unwrap();
        assert_eq!(f.extension_key(), Some(key));
        assert!(f.is_path());
        assert_eq!(f.value(Lookup::Missing).unwrap(), Value::Missing);
        assert_eq!(f.value(Lookup::Present(&V::Null)).unwrap(), Value::Null);
    }
}
#[test]
fn typed_literals_preserved_by_field_conversion() {
    let raw = V::parse(br#"{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#decimal","value":9007199254740993,"language":null}"#,Limits::default()).unwrap();
    let typed = FieldRef::parse("meta:confidence")
        .unwrap()
        .value(Lookup::Present(&raw))
        .unwrap();
    assert!(matches!(typed, Value::Literal(_)));
    let Value::Literal(literal) = typed else {
        unreachable!()
    };
    assert_eq!(literal.projection(), raw);
}
