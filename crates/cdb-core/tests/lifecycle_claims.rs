mod common;
use cdb_core::{admission::*, claim::*, id::*, CanonicalValue as V, Limits};
use common::*;
use std::collections::BTreeSet;

fn assertion(id: &str, target: &str, relation: &str, reference: &str) -> LifecycleAssertion {
    let mut value = candidate(id).projection();
    set(&mut value, "subject_id", V::string(target));
    set(&mut value, "relation", V::string(relation));
    set(&mut value, "object_id", V::string(reference));
    LifecycleAssertion::from_value(&value).unwrap()
}
#[test]
fn lifecycle_claims_are_referenceable_claims_in_the_same_batch() {
    let first = assertion("a", "target", "ctxql:contradicted_by", "other");
    let second = assertion("b", "a", "ctxql:superseded_by", "other");
    let batch = AdmissionBatch::new(
        vec![],
        vec![first, second],
        vec![],
        vec![],
        json("{}"),
        Limits::default(),
    )
    .unwrap();
    batch
        .validate_claim_references(&BTreeSet::from([
            ClaimId::new("target").unwrap(),
            ClaimId::new("other").unwrap(),
        ]))
        .unwrap();
    assert!(batch
        .validate_claim_references(&BTreeSet::from([ClaimId::new("target").unwrap()]))
        .is_err());
}
#[test]
fn wrapper_uses_closed_ordinary_claim_validation_and_hashes_all_metadata() {
    let a = assertion("a", "target", "ctxql:retracted_by", "event");
    let mut value = a.projection();
    for key in [
        "confidence",
        "relation_type",
        "subject_type",
        "object_type",
        "claim_type",
        "grounding_level",
    ] {
        let V::Object(mut missing) = value.clone() else {
            unreachable!()
        };
        missing.remove(key);
        assert!(LifecycleAssertion::from_value(&V::Object(missing)).is_err());
    }
    set(&mut value, "ext", json(r#"{"note":"different"}"#));
    let b = LifecycleAssertion::from_value(&value).unwrap();
    let digest = |l| {
        AdmissionBatch::new(
            vec![],
            vec![l],
            vec![],
            vec![],
            json("{}"),
            Limits::default(),
        )
        .unwrap()
        .digest()
        .clone()
    };
    assert_ne!(digest(a.clone()), digest(b));
    for key in ["transaction_time", "lifecycle_state", "unknown"] {
        let mut invalid = a.projection();
        set(&mut invalid, key, V::string("invalid"));
        assert!(LifecycleAssertion::from_value(&invalid).is_err());
    }
    let mut literal = a.projection();
    set(
        &mut literal,
        "object_id",
        json(
            r#"{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#string","value":"event","language":null}"#,
        ),
    );
    assert!(LifecycleAssertion::from_value(&literal).is_err());
    // The removed lossy id/target/state/replacement wire is deliberately not accepted.
    assert!(LifecycleAssertion::from_value(&json(
        r#"{"id":"a","target":"target","state":"retracted","replacement":null}"#
    ))
    .is_err());
}
