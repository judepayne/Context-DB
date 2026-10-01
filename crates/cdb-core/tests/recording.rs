mod common;
use cdb_core::{
    artifact::ArtifactRef, canonical::CanonicalProjection, id::*, recording::*,
    CanonicalValue as V, ErrorKind, Limits,
};
use common::*;
fn input() -> ReplayDataInput {
    let l = Limits::default();
    let mut p = fixture("plan");
    let V::Object(root) = &mut p else {
        unreachable!()
    };
    let V::Object(payload) = root.get_mut("payload").unwrap() else {
        unreachable!()
    };
    let V::Object(a) = payload.get_mut("artifacts").unwrap() else {
        unreachable!()
    };
    a.insert("query".into(), a["config"].clone());
    let plan = CanonicalProjection::read(&p.canonical_bytes(l).unwrap(), l).unwrap();
    let config = ArtifactRef::from_value(
        plan.payload()
            .field("artifacts")
            .unwrap()
            .field("config")
            .unwrap(),
    )
    .unwrap();
    ReplayDataInput {
        snapshot: pin("1"),
        requested_snapshot: pin("1"),
        as_of: cdb_core::Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
        stale: false,
        // Independent Python hashlib over the existing vector with query=config binding.
        plan_hash: ContentHash::parse(
            "sha256:c62caf74fbecd39100be7fa9fbcbcea7f9c0bb84815814c125fcfc61bc9fe5a3",
        )
        .unwrap(),
        plan,
        response: CanonicalProjection::read(&fixture("response").canonical_bytes(l).unwrap(), l)
            .unwrap(),
        response_hash: ContentHash::parse(
            "sha256:17489b4f791a43e0a36b1af79ea9eacd60e7ecbfda760516503be24ca0dba55a",
        )
        .unwrap(),
        query: config.clone(),
        config,
        profile: None,
        engine: RecordingEngine {
            name: ResourceId::new("engine").unwrap(),
            version: VersionId::new("1").unwrap(),
            build: ContentHash::of_bytes(b"engine"),
        },
        replay_abi: VersionId::new("native/v1").unwrap(),
        landings: vec![],
        catalog: vec![],
        policy: vec![],
        reads: vec![],
        scopes: REQUIRED_SCOPES
            .iter()
            .map(|s| ResourceId::new(*s).unwrap())
            .collect(),
        functions: vec![],
    }
}
#[test]
fn canonical_roundtrip_and_reserved_record() {
    let l = Limits::default();
    let replay = ReplayData::new(input(), l).unwrap();
    assert_eq!(
        ReplayData::read(&replay.bytes(l).unwrap(), l).unwrap(),
        replay
    );
    let run = RunEnvelope::new(
        RunId::new("a/b").unwrap(),
        PrincipalId::new("owner").unwrap(),
        ContentHash::of_bytes(b"operation"),
        replay.clone(),
        l,
    )
    .unwrap();
    let bytes = run.bytes(l).unwrap();
    assert_eq!(
        run.integrity_hash(l).unwrap(),
        ContentHash::of_bytes(&bytes)
    );
    assert_eq!(RunEnvelope::read(&bytes, l).unwrap(), run);
    let record = run.to_record(l).unwrap();
    let stored = cdb_core::record_codec::encode_record(&record, l).unwrap();
    assert_eq!(
        RunEnvelope::from_record(
            &cdb_core::record_codec::decode_record(&stored, l).unwrap(),
            l
        )
        .unwrap(),
        run
    );
    let other = RunEnvelope::new(
        RunId::new("a%2Fb").unwrap(),
        PrincipalId::new("owner").unwrap(),
        ContentHash::of_bytes(b"operation"),
        replay,
        l,
    )
    .unwrap();
    assert_ne!(run.descriptor_id().unwrap(), other.descriptor_id().unwrap());
}
#[test]
fn tampered_hashes_payloads_pins_cutoff() {
    let l = Limits::default();
    for key in ["plan_hash", "response_hash", "as_of", "stale", "snapshot"] {
        let mut v = ReplayData::new(input(), l).unwrap().projection();
        let replacement = match key {
            "as_of" => V::string("1970-01-01T00:00:00.000Z"),
            "stale" => V::Bool(true),
            "snapshot" => cdb_core::record_codec::snapshot_value(&pin("2")),
            _ => V::string(ContentHash::of_bytes(b"bad").as_str()),
        };
        set(&mut v, key, replacement);
        assert!(ReplayData::from_value(&v, l).is_err(), "{key}");
    }
    for key in ["plan", "response"] {
        let mut v = ReplayData::new(input(), l).unwrap().projection();
        let mut envelope = v.field(key).unwrap().clone();
        let mut payload = envelope.field("payload").unwrap().clone();
        set(
            &mut payload,
            if key == "plan" {
                "as_of"
            } else {
                "graph_status"
            },
            V::string("altered"),
        );
        set(&mut envelope, "payload", payload);
        set(&mut v, key, envelope);
        assert!(ReplayData::from_value(&v, l).is_err());
    }
}
#[test]
fn strict_versions_fields_and_unsupported_functions() {
    let l = Limits::default();
    let base = ReplayData::new(input(), l).unwrap().projection();
    for (key, value) in [
        ("schema", V::string("ctxql-replay-data/v3")),
        ("unknown", V::Null),
    ] {
        let mut v = base.clone();
        set(&mut v, key, value);
        assert!(ReplayData::from_value(&v, l).is_err());
    }
    let mut v = base;
    set(&mut v, "functions", V::Array(vec![V::Null]));
    assert_eq!(
        ReplayData::from_value(&v, l).unwrap_err().kind,
        ErrorKind::Unsupported
    );
}
#[test]
fn bounds_and_required_scopes() {
    let l = Limits::default();
    let data = ReplayData::new(input(), l).unwrap();
    let tiny = Limits::new(10, 2, 3, 10, 10).unwrap();
    assert_eq!(
        ReplayData::read(&data.bytes(l).unwrap(), tiny)
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    assert!(ReplayData::new(input(), tiny).is_err());
    let mut i = input();
    i.scopes.pop();
    assert!(ReplayData::new(i, l).is_err());
}
#[test]
fn ordered_observations_and_conflicts() {
    let l = Limits::default();
    let mut i = input();
    let p = PolicyObservation {
        resource: ResourceId::new("resource").unwrap(),
        predicate: None,
        allowed: true,
    };
    i.policy = vec![p.clone(), p.clone()];
    i.reads = vec![ReadObservation {
        operation: ResourceId::new("lookup").unwrap(),
        key: V::string("negative"),
        result_hash: ContentHash::of_bytes(b"null"),
    }];
    let d = ReplayData::new(i.clone(), l).unwrap();
    assert_eq!(d.data().policy, i.policy);
    assert_eq!(d.data().reads, i.reads);
    i.policy[1].allowed = false;
    assert!(ReplayData::new(i, l).is_err());
}
#[test]
fn exact_artifact_binding() {
    let l = Limits::default();
    let mut i = input();
    i.query = ArtifactRef::new(
        i.query.iri().clone(),
        VersionId::new("other").unwrap(),
        i.query.hash().clone(),
    );
    assert!(ReplayData::new(i, l).is_err());
    let mut i = input();
    i.profile = Some(i.config.clone());
    assert!(ReplayData::new(i, l).is_err());
    let mut i = input();
    i.config = ArtifactRef::new(
        i.config.iri().clone(),
        i.config.version().clone(),
        ContentHash::of_bytes(b"altered"),
    );
    assert!(ReplayData::new(i, l).is_err());
}

#[test]
fn catalogs_are_lossless_ordered_entries_not_identity_maps() {
    let mut data = input();
    let id = ResourceId::new("entity:A").unwrap();
    data.catalog = vec![
        PreparedCatalogEntry {
            id: id.clone(),
            label: None,
            dependencies: vec![],
        },
        PreparedCatalogEntry {
            id: id.clone(),
            label: Some("".into()),
            dependencies: vec![],
        },
        PreparedCatalogEntry {
            id: id.clone(),
            label: Some("Name".into()),
            dependencies: vec![id.clone(), id.clone()],
        },
        PreparedCatalogEntry {
            id,
            label: None,
            dependencies: vec![],
        },
    ];
    let expected = data.catalog.clone();
    let data = ReplayData::new(data, Limits::default()).unwrap();
    let restored =
        ReplayData::read(&data.bytes(Limits::default()).unwrap(), Limits::default()).unwrap();
    assert_eq!(restored.data().catalog, expected);
}
