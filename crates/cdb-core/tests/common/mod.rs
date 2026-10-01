#![allow(dead_code)]
use cdb_core::{CanonicalValue as V, Limits};
pub fn json(s: &str) -> V {
    V::parse(s.as_bytes(), Limits::default()).unwrap()
}
pub fn candidate(id: &str) -> cdb_core::claim::CandidateClaim {
    let mut v = json(
        r#"{"claim_id":"c","subject_id":"subject","relation":"urn:rel","object_id":{"kind":"literal","datatype":"http://www.w3.org/2001/XMLSchema#decimal","value":0.1,"language":null},"relation_type":"urn:relation-type","subject_type":"urn:subject-type","object_type":"urn:object-type","claim_type":"urn:claim-type","confidence":0.75,"grounding_level":"claim_only"}"#,
    );
    set(&mut v, "claim_id", V::string(id));
    cdb_core::claim::CandidateClaim::from_value(&v).unwrap()
}
pub fn set(v: &mut V, k: &str, x: V) {
    let V::Object(o) = v else { panic!("object") };
    o.insert(k.into(), x);
}
pub fn fixture(name: &str) -> V {
    let all = json(include_str!(
        "../../../../fixtures/conformance/p1/bytes-v1.json"
    ));
    let v = all
        .field("vectors")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v.field("id").unwrap().as_str().unwrap() == name)
        .unwrap();
    json(v.field("canonical_utf8").unwrap().as_str().unwrap())
}
pub fn pin(rev: &str) -> cdb_core::snapshot::SnapshotRef {
    use cdb_core::{id::*, snapshot::*};
    SnapshotRef::new(
        BackendId::new("memory").unwrap(),
        GraphPin::new(
            AuthorityId::new("memory:test").unwrap(),
            GraphId::new("g").unwrap(),
            VersionId::new(rev).unwrap(),
            ResourceId::new(format!("receipt:{rev}")).unwrap(),
        ),
    )
}
