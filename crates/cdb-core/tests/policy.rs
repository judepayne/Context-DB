mod common;
use cdb_core::{id::Iri, policy::PolicySet, Error, ErrorKind, Limits};
use common::*;
use std::collections::BTreeSet;
fn rule(id: &str, allow: bool, required: bool, target: &str) -> String {
    format!(
        r#"{{"@id":"https://example.org/{id}","@type":["https://ns.flur.ee/db#AccessPolicy","https://example.org/member"],"https://ns.flur.ee/db#action":"https://ns.flur.ee/db#view","https://ns.flur.ee/db#allow":{allow},"https://ns.flur.ee/db#required":{required}{target}}}"#
    )
}
fn policies(rules: &[String]) -> PolicySet {
    PolicySet::parse(
        format!(
            r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{}]}}"#,
            rules.join(",")
        )
        .as_bytes(),
        Limits::default(),
    )
    .unwrap()
}
fn allows(p: &PolicySet, classes: Option<&BTreeSet<Iri>>) -> bool {
    p.allows(
        true,
        &BTreeSet::from([Iri::http("https://example.org/member").unwrap()]),
        &Iri::http("https://example.org/schema").unwrap(),
        &Iri::http("http://www.w3.org/2000/01/rdf-schema#subClassOf").unwrap(),
        classes,
    )
}
#[test]
fn required_subset_before_deny_permutations_no_schema_bypass() {
    let a = rule("allow", true, true, "");
    let d = rule("deny", false, false, "");
    for rules in [vec![a.clone(), d.clone()], vec![d.clone(), a.clone()]] {
        assert!(allows(&policies(&rules), Some(&BTreeSet::new())));
    }
    assert!(!allows(
        &policies(&[rule("deny", false, true, ""), a]),
        Some(&BTreeSet::new())
    ));
    assert!(!allows(&policies(&[d]), Some(&BTreeSet::new())));
    assert!(!allows(&policies(&[]), Some(&BTreeSet::new())));
}
#[test]
fn current_classes_and_missing_resource() {
    let p = policies(&[rule(
        "allow",
        true,
        false,
        ",\"https://ns.flur.ee/db#onClass\":\"https://example.org/current\"",
    )]);
    assert!(!allows(&p, None));
    assert!(!allows(&p, Some(&BTreeSet::new())));
    assert!(allows(
        &p,
        Some(&BTreeSet::from([
            Iri::http("https://example.org/current").unwrap()
        ]))
    ));
}
#[test]
fn strict_whole_set_and_untrusted_roles_not_handles() {
    let good = rule("allow", true, false, "");
    for extra in [
        ",\"https://ns.flur.ee/db#query\":{}",
        ",\"unknown\":1",
        ",\"https://ns.flur.ee/db#onSubject\":[]",
    ] {
        let bad = rule("bad", true, false, extra);
        let s = format!(
            r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{good},{bad}]}}"#
        );
        assert!(PolicySet::parse(s.as_bytes(), Limits::default()).is_err());
    }
    assert!(PolicySet::from_value(&json(r#"{"roles":["admin"]}"#)).is_err());
    let duplicate = format!(
        r#"{{"contract":"ctxql-static-policy/v1","guard":"ctxql-guard/v1","policies":[{good},{good}]}}"#
    );
    assert!(PolicySet::parse(duplicate.as_bytes(), Limits::default()).is_err());
}
#[test]
fn public_errors_redact_internal_sentinels() {
    for kind in [
        ErrorKind::Denied,
        ErrorKind::PolicyChanged,
        ErrorKind::Backend,
        ErrorKind::Invalid,
    ] {
        let error = Error::new(kind, "secret-ID /private/path sha256:secret source body");
        let public = error.public_json();
        for secret in ["secret", "private", "sha256", "body"] {
            assert!(!public.contains(secret));
        }
    }
}
