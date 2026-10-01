mod common;
use cdb_core::{canonical::*, CanonicalValue as V, Limits};
use common::*;
fn read(v: &V) -> cdb_core::Result<CanonicalProjection> {
    CanonicalProjection::read(&v.canonical_bytes(Limits::default())?, Limits::default())
}
#[test]
fn every_closed_domain_rejects_missing_extra_null_unknown() {
    for name in [
        "plan",
        "response",
        "input-root",
        "output-root",
        "decimal-input",
        "decimal-output",
        "structured-product",
        "text-product",
        "structured-claim",
    ] {
        let base = fixture(name);
        let mut extra = base.clone();
        let payload = extra.field("payload").unwrap().clone();
        let mut payload = payload;
        set(&mut payload, "timing", V::integer(1));
        set(&mut extra, "payload", payload);
        assert!(read(&extra).is_err(), "{name}");
        let V::Object(o) = base.field("payload").unwrap() else {
            unreachable!()
        };
        for key in o.keys() {
            let mut p = o.clone();
            p.remove(key);
            let mut v = base.clone();
            set(&mut v, "payload", V::Object(p));
            assert!(read(&v).is_err(), "{name}/{key}");
        }
        let mut bad = base.clone();
        set(&mut bad, "version", V::string("ctxql-canonical/v2"));
        assert!(read(&bad).is_err());
        set(&mut bad, "version", V::string("ctxql-canonical/v1"));
        set(&mut bad, "domain", V::string("ctxql.arbitrary"));
        assert!(read(&bad).is_err());
    }
}
#[test]
fn plan_as_of_and_semantic_config_sensitivity() {
    let base = fixture("plan");
    let p = read(&base).unwrap();
    let mut payload = base.field("payload").unwrap().clone();
    set(&mut payload, "as_of", V::string("1970-01-01T00:00:00.000Z"));
    assert!(CanonicalProjection::from_payload(Domain::Plan, payload).is_err());
    let mut payload = base.field("payload").unwrap().clone();
    let mut config = payload.field("config").unwrap().clone();
    let mut defaults = config.field("defaults").unwrap().clone();
    set(&mut defaults, "seed_limit", V::integer(3));
    set(&mut config, "defaults", defaults);
    set(&mut payload, "config", config);
    let changed = CanonicalProjection::from_payload(Domain::Plan, payload).unwrap();
    assert_ne!(
        p.hash(Limits::default()).unwrap(),
        changed.hash(Limits::default()).unwrap()
    );
    assert_eq!(
        p.hash(Limits::default()).unwrap(),
        p.hash(Limits::new(100000, 64, 10000, 100000, 100000).unwrap())
            .unwrap()
    );
}
#[test]
fn response_selected_empty_not_null_status_notices_sensitive() {
    let base = fixture("response");
    let p = read(&base).unwrap();
    let mut payload = p.payload().clone();
    set(&mut payload, "claims", V::Null);
    assert!(CanonicalProjection::from_payload(Domain::Response, payload).is_err());
    let mut payload = p.payload().clone();
    set(
        &mut payload,
        "graph_status",
        V::string("ready_with_warnings"),
    );
    assert_ne!(
        p.hash(Limits::default()).unwrap(),
        CanonicalProjection::from_payload(Domain::Response, payload)
            .unwrap()
            .hash(Limits::default())
            .unwrap()
    );
    let mut payload = p.payload().clone();
    set(
        &mut payload,
        "notices",
        json(r#"[{"code":"truncated","details":{"cap":2}}]"#),
    );
    assert_ne!(
        p.hash(Limits::default()).unwrap(),
        CanonicalProjection::from_payload(Domain::Response, payload)
            .unwrap()
            .hash(Limits::default())
            .unwrap()
    );
}
#[test]
fn structured_identity_and_product_provenance_checks() {
    let base = fixture("structured-claim");
    let mut p = base.field("payload").unwrap().clone();
    set(&mut p, "occurrence", V::string("batch"));
    assert!(CanonicalProjection::from_payload(Domain::StructuredClaim, p.clone()).is_err());
    set(&mut p, "mode", V::string("import"));
    assert!(CanonicalProjection::from_payload(Domain::StructuredClaim, p).is_ok());
    let base = fixture("text-product");
    let mut p = base.field("payload").unwrap().clone();
    set(&mut p, "content", V::string("x\r\n"));
    assert!(CanonicalProjection::from_payload(Domain::TextProduct, p).is_err());
    let base = fixture("structured-product");
    let mut p = base.field("payload").unwrap().clone();
    set(
        &mut p,
        "citations",
        json(r#"[{"input_name":"primary","claim_id":"invented","source_index":0}]"#),
    );
    assert!(CanonicalProjection::from_payload(Domain::StructuredProduct, p).is_err());
}
