mod common;
use cdb_core::{canonical::CanonicalProjection, Limits};
use common::*;
#[test]
fn six_unchanged_p0_goldens() {
    let f = json(include_str!(
        "../../../fixtures/conformance/canonical/bytes-v1.json"
    ));
    let vectors = f.field("vectors").unwrap().as_array().unwrap();
    assert_eq!(vectors.len(), 6);
    for v in vectors {
        let envelope = v
            .field("normalized_envelope")
            .unwrap()
            .canonical_bytes(Limits::default())
            .unwrap();
        let p = CanonicalProjection::read(&envelope, Limits::default()).unwrap();
        assert_eq!(
            std::str::from_utf8(&p.bytes(Limits::default()).unwrap()).unwrap(),
            v.field("canonical_utf8").unwrap().as_str().unwrap()
        );
        assert_eq!(
            p.hash(Limits::default()).unwrap().as_str(),
            v.field("sha256").unwrap().as_str().unwrap()
        );
    }
}
#[test]
fn independent_all_nine_domain_goldens() {
    let f = json(include_str!(
        "../../../fixtures/conformance/p1/bytes-v1.json"
    ));
    let mut domains = std::collections::BTreeSet::new();
    for v in f.field("vectors").unwrap().as_array().unwrap() {
        let bytes = v
            .field("canonical_utf8")
            .unwrap()
            .as_str()
            .unwrap()
            .as_bytes();
        let p = CanonicalProjection::read(bytes, Limits::default()).unwrap();
        assert_eq!(p.bytes(Limits::default()).unwrap(), bytes);
        assert_eq!(
            p.hash(Limits::default()).unwrap().as_str(),
            v.field("sha256").unwrap().as_str().unwrap()
        );
        domains.insert(p.domain().as_str());
    }
    assert_eq!(domains.len(), 9);
}
