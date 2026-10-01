mod common;
use cdb_core::{
    artifact::ArtifactRef,
    canonical::CanonicalProjection,
    id::*,
    recording::{RecordingEngine, ReplayDataInput, REQUIRED_SCOPES},
    recording_v3::*,
    CanonicalValue as V, Limits,
};
use common::*;
fn base_input() -> ReplayDataInput {
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

fn object<const N: usize>(entries: [(&str, V); N]) -> V {
    V::Object(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn input() -> ReplayDataV3Input {
    let mut base = base_input();
    base.replay_abi = VersionId::new(REPLAY_ABI).unwrap();
    let identity = object([
        ("phase", V::string("preparation")),
        ("evaluation", V::integer(0)),
        ("predicate", V::integer(0)),
        ("attempt", V::integer(0)),
        ("ordinal", V::integer(0)),
    ]);
    let lane = object([
        ("identity", identity.clone()),
        ("closed", V::Bool(true)),
        ("outcome", V::string("empty")),
        ("reads", V::Array(vec![])),
        ("policy", V::Array(vec![])),
        (
            "scopes",
            V::Array(base.scopes.iter().map(|s| V::string(s.as_str())).collect()),
        ),
        ("function_counts", V::Array(vec![])),
    ]);
    ReplayDataV3Input {
        executor: base.engine.clone(),
        base,
        lanes: vec![lane],
        expected_lanes: vec![identity],
        functions: vec![],
        prepared: vec![],
        release_evidence: vec![],
    }
}
#[test]
fn roundtrip_flat_schema_and_storage_identity() {
    let l = Limits::default();
    let replay = ReplayDataV3::new(input(), l).unwrap();
    assert_eq!(
        replay,
        ReplayDataV3::read(&replay.bytes(l).unwrap(), l).unwrap()
    );
    assert_eq!(
        replay
            .projection()
            .field("schema")
            .unwrap()
            .as_str()
            .unwrap(),
        REPLAY_SCHEMA
    );
    assert!(replay.projection().field("base").is_err());
    let run = RunEnvelopeV3::new(
        RunId::new("a/b").unwrap(),
        PrincipalId::new("owner").unwrap(),
        ContentHash::of_bytes(b"operation"),
        replay,
        l,
    )
    .unwrap();
    let stored = StoredV3(run.clone());
    let record = stored.to_record(l).unwrap();
    let bytes = cdb_core::record_codec::encode_record(&record, l).unwrap();
    assert_eq!(
        StoredV3::from_record(
            &cdb_core::record_codec::decode_record(&bytes, l).unwrap(),
            l
        )
        .unwrap(),
        stored
    );
    assert_eq!(RunEnvelopeV3::read(&run.bytes(l).unwrap(), l).unwrap(), run);
    assert_eq!(
        run.integrity_hash(l).unwrap(),
        ContentHash::of_bytes(&run.bytes(l).unwrap())
    );
    let other = RunEnvelopeV3::new(
        run.id().clone(),
        run.owner().clone(),
        ContentHash::of_bytes(b"other"),
        run.replay().clone(),
        l,
    )
    .unwrap();
    assert_eq!(run.descriptor_id().unwrap(), other.descriptor_id().unwrap());
    assert_ne!(
        run.integrity_hash(l).unwrap(),
        other.integrity_hash(l).unwrap()
    );
    assert_eq!(
        run.replay().data().plan_hash,
        other.replay().data().plan_hash
    );
    assert!(cdb_core::recording::RunEnvelope::from_record(&record, l).is_err());
}
#[test]
fn missing_extra_wrong_schema_and_budget_reject() {
    let l = Limits::default();
    let replay = ReplayDataV3::new(input(), l).unwrap();
    let wire = replay.projection();
    for key in wire.as_object().unwrap().keys() {
        let V::Object(mut v) = wire.clone() else {
            unreachable!()
        };
        v.remove(key);
        assert!(
            ReplayDataV3::from_value(&V::Object(v), l).is_err(),
            "missing {key}"
        );
    }
    for (key, value) in [
        ("schema", V::string("ctxql-replay-data/v2")),
        ("unexpected", V::Null),
        ("numeric_abi", V::string("ctxql-predicate-numeric/v1")),
        ("replay_abi", V::string("native/v1")),
        ("functions", V::Array(vec![V::Null])),
        ("lanes", V::Array(vec![])),
        ("expected_lanes", V::Array(vec![])),
        ("as_of", V::string("1970-01-01T00:00:00.000Z")),
        (
            "snapshot",
            cdb_core::record_codec::snapshot_value(&pin("2")),
        ),
        (
            "plan_hash",
            V::string(ContentHash::of_bytes(b"bad").as_str()),
        ),
    ] {
        let mut v = wire.clone();
        set(&mut v, key, value);
        assert!(ReplayDataV3::from_value(&v, l).is_err(), "{key}");
    }
    let tiny = Limits::new(10, 2, 3, 10, 10).unwrap();
    assert!(ReplayDataV3::new(input(), tiny).is_err());
    assert!(ReplayDataV3::read(&replay.bytes(l).unwrap(), tiny).is_err());
    let mut i = input();
    i.base.functions.push(V::Null);
    assert!(ReplayDataV3::new(i, l).is_err());
}
#[test]
fn closed_empty_negative_footprint_and_lane_duplicates() {
    let l = Limits::default();
    for key in ["closed", "identity", "outcome", "scopes", "function_counts"] {
        let mut i = input();
        set(&mut i.lanes[0], key, V::Null);
        assert!(ReplayDataV3::new(i, l).is_err(), "{key}");
    }
    let mut i = input();
    i.lanes.push(i.lanes[0].clone());
    i.expected_lanes.push(i.expected_lanes[0].clone());
    assert!(ReplayDataV3::new(i, l).is_err());
    let mut i = input();
    i.base.reads.push(cdb_core::recording::ReadObservation {
        operation: ResourceId::new("lookup").unwrap(),
        key: V::string("missing"),
        result_hash: ContentHash::of_bytes(b"null"),
    });
    assert!(ReplayDataV3::new(i.clone(), l).is_err());
    let read = object([
        ("operation", V::string("lookup")),
        ("key", V::string("missing")),
        (
            "result_hash",
            V::string(ContentHash::of_bytes(b"null").as_str()),
        ),
    ]);
    set(
        &mut i.lanes[0],
        "reads",
        V::Array(vec![
            object([("ordinal", V::integer(0)), ("observation", read.clone())]),
            object([("ordinal", V::integer(1)), ("observation", read)]),
        ]),
    );
    let original = ReplayDataV3::new(i, l).unwrap();
    assert_eq!(
        ReplayDataV3::read(&original.bytes(l).unwrap(), l).unwrap(),
        original
    );
}
#[test]
fn release_heads_are_integrity_bound_not_semantic_roots() {
    let l = Limits::default();
    let mut i = input();
    let requirements = AuthorizationRequirementsV3::new(vec![], vec![], l).unwrap();
    i.release_evidence.push(
        ReleaseEvidenceV3::new(
            ResourceId::new("release:1").unwrap(),
            requirements,
            pin("1"),
            true,
            l,
        )
        .unwrap()
        .projection(),
    );
    let a = ReplayDataV3::new(i.clone(), l).unwrap();
    set(
        &mut i.release_evidence[0],
        "authorization_head",
        cdb_core::record_codec::snapshot_value(&pin("2")),
    );
    let b = ReplayDataV3::new(i.clone(), l).unwrap();
    a.verify_semantics(&b).unwrap();
    assert_eq!(a.data().plan_hash, b.data().plan_hash);
    assert_eq!(a.data().response_hash, b.data().response_hash);
    assert_ne!(a.bytes(l).unwrap(), b.bytes(l).unwrap());
    i.release_evidence.push(i.release_evidence[0].clone());
    assert!(ReplayDataV3::new(i, l).is_err());
}

#[test]
fn actual_action_requirements_can_be_earlier_subsets_and_are_tamper_checked() {
    let l = Limits::default();
    let mut i = input();
    let view = Iri::http("https://ns.flur.ee/db#view").unwrap();
    let first = AuthorizationRequirementsV3::new(
        vec![(ResourceId::new(REQUIRED_SCOPES[0]).unwrap(), view.clone())],
        vec![],
        l,
    )
    .unwrap();
    let later = AuthorizationRequirementsV3::new(
        vec![
            (ResourceId::new(REQUIRED_SCOPES[0]).unwrap(), view.clone()),
            (ResourceId::new(REQUIRED_SCOPES[1]).unwrap(), view),
        ],
        vec![],
        l,
    )
    .unwrap();
    assert_ne!(first.hash(), later.hash());
    for (action, requirements) in [("release:early", first), ("release:later", later)] {
        i.release_evidence.push(
            ReleaseEvidenceV3::new(
                ResourceId::new(action).unwrap(),
                requirements,
                pin("1"),
                true,
                l,
            )
            .unwrap()
            .projection(),
        );
    }
    let replay = ReplayDataV3::new(i, l).unwrap();
    assert_eq!(replay.release_evidence(l).unwrap().len(), 2);
    let mut tampered = replay.projection();
    let V::Object(root) = &mut tampered else {
        unreachable!()
    };
    let V::Array(evidence) = root.get_mut("release_evidence").unwrap() else {
        unreachable!()
    };
    set(
        &mut evidence[0],
        "requirements_hash",
        V::string(ContentHash::of_bytes(b"tampered").as_str()),
    );
    assert!(ReplayDataV3::from_value(&tampered, l).is_err());
    let tiny = Limits::new(32, 2, 8, 16, 16).unwrap();
    assert!(AuthorizationRequirementsV3::new(
        vec![(
            ResourceId::new("resource-that-exceeds-the-small-byte-budget").unwrap(),
            Iri::http("https://example.test/predicate").unwrap(),
        )],
        vec![],
        tiny,
    )
    .is_err());
}

fn with_function() -> ReplayDataV3Input {
    let l = Limits::default();
    let mut i = input();
    let source = " { \"kind\" : \"test\" } ";
    let reference = ArtifactRef::new(
        Iri::new("urn:function:manifest").unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(source.as_bytes()),
    );
    let mut plan = i.base.plan.envelope();
    let V::Object(root) = &mut plan else {
        unreachable!()
    };
    let V::Object(payload) = root.get_mut("payload").unwrap() else {
        unreachable!()
    };
    let V::Object(config) = payload.get_mut("config").unwrap() else {
        unreachable!()
    };
    config.insert(
        "external_functions".into(),
        object([(
            "fn:test",
            object([
                ("version", V::string("1")),
                ("manifest_uri", V::string(reference.iri().as_str())),
                ("manifest_hash", V::string(reference.hash().as_str())),
                ("deterministic", V::Bool(true)),
            ]),
        )]),
    );
    i.base.plan = CanonicalProjection::read(&plan.canonical_bytes(l).unwrap(), l).unwrap();
    i.base.plan_hash = i.base.plan.hash(l).unwrap();
    set(
        &mut i.lanes[0],
        "function_counts",
        V::Array(vec![object([
            ("name", V::string("fn:test")),
            ("count", V::integer(1)),
        ])]),
    );
    i.functions.push(object([
        ("name", V::string("fn:test")),
        ("manifest", reference.projection()),
        ("source", V::string(source)),
        ("deterministic", V::Bool(true)),
        ("replay", V::string("exact")),
        ("count", V::integer(1)),
        (
            "input_root",
            V::string(ContentHash::of_bytes(b"input root").as_str()),
        ),
        (
            "output_root",
            V::string(ContentHash::of_bytes(b"output root").as_str()),
        ),
        (
            "destinations",
            V::Array(vec![V::string("destination:original")]),
        ),
    ]));
    let requirements = AuthorizationRequirementsV3::new(
        vec![],
        vec![(reference, ResourceId::new("destination:original").unwrap())],
        l,
    )
    .unwrap();
    let identity = LaneIdentityV3::from_value(&i.expected_lanes[0]).unwrap();
    let callback = function_callback_id(&identity, 0, l).unwrap();
    for kind in ["enqueue", "consume"] {
        i.release_evidence.push(
            ReleaseEvidenceV3::new(
                function_action_id(&callback, 1, kind).unwrap(),
                requirements.clone(),
                pin("1"),
                true,
                l,
            )
            .unwrap()
            .projection(),
        );
    }
    i.release_evidence.push(
        ReleaseEvidenceV3::new(
            ResourceId::new("release:function").unwrap(),
            requirements,
            pin("1"),
            true,
            l,
        )
        .unwrap()
        .projection(),
    );
    i
}
#[test]
fn original_authorization_requirements_are_stored_derived_and_exact() {
    let l = Limits::default();
    let mut i = with_function();
    let allowed_resource = ResourceId::new("urn:allowed:resource").unwrap();
    let allowed_fact = ResourceId::new("urn:allowed:fact").unwrap();
    let predicate = Iri::http("https://example.test/property").unwrap();
    i.base.policy = vec![
        cdb_core::recording::PolicyObservation {
            resource: allowed_resource.clone(),
            predicate: None,
            allowed: true,
        },
        cdb_core::recording::PolicyObservation {
            resource: allowed_fact.clone(),
            predicate: Some(predicate.clone()),
            allowed: true,
        },
        cdb_core::recording::PolicyObservation {
            resource: ResourceId::new("urn:denied").unwrap(),
            predicate: None,
            allowed: false,
        },
    ];
    set(
        &mut i.lanes[0],
        "policy",
        V::Array(vec![
            object([
                ("resource", V::string(allowed_resource.as_str())),
                ("predicate", V::Null),
                ("allowed", V::Bool(true)),
            ]),
            object([
                ("resource", V::string(allowed_fact.as_str())),
                ("predicate", V::string(predicate.as_str())),
                ("allowed", V::Bool(true)),
            ]),
            object([
                ("resource", V::string("urn:denied")),
                ("predicate", V::Null),
                ("allowed", V::Bool(false)),
            ]),
        ]),
    );
    let manifest = ArtifactRef::from_value(i.functions[0].field("manifest").unwrap()).unwrap();
    let replay = ReplayDataV3::new(i, l).unwrap();
    let view = Iri::http("https://ns.flur.ee/db#view").unwrap();
    let expected = AuthorizationRequirementsV3::new(
        REQUIRED_SCOPES
            .iter()
            .map(|scope| (ResourceId::new(*scope).unwrap(), view.clone()))
            .chain([(allowed_resource, view.clone()), (allowed_fact, predicate)])
            .collect(),
        vec![(manifest, ResourceId::new("destination:original").unwrap())],
        l,
    )
    .unwrap();
    assert_eq!(
        replay.original_authorization_requirements(l).unwrap(),
        expected
    );
}

#[test]
fn exact_noncanonical_manifest_source_compact_counts_and_tamper() {
    let l = Limits::default();
    let i = with_function();
    let replay = ReplayDataV3::new(i.clone(), l).unwrap();
    let mut missing_consumption = i.clone();
    missing_consumption.release_evidence.remove(1);
    assert!(ReplayDataV3::new(missing_consumption, l).is_err());
    let mut missing_enqueue = i.clone();
    missing_enqueue.release_evidence.remove(0);
    assert!(ReplayDataV3::new(missing_enqueue, l).is_err());
    assert!(replay.bytes(l).unwrap().len() < 20_000);
    assert_eq!(
        ReplayDataV3::read(&replay.bytes(l).unwrap(), l).unwrap(),
        replay
    );
    for (key, value) in [
        ("source", V::string("{}")),
        ("name", V::string("fn:missing")),
        ("count", V::integer(2)),
        ("deterministic", V::Bool(false)),
        ("replay", V::string("invented")),
        ("input_root", V::string("bad")),
        ("unknown", V::Null),
    ] {
        let mut altered = i.clone();
        set(&mut altered.functions[0], key, value);
        assert!(ReplayDataV3::new(altered, l).is_err(), "{key}");
    }
    let mut missing = i.clone();
    missing.functions.clear();
    assert!(ReplayDataV3::new(missing, l).is_err());
    let mut extra = i.clone();
    extra.functions.push(extra.functions[0].clone());
    assert!(ReplayDataV3::new(extra, l).is_err());
    let mut altered = i;
    set(
        &mut altered.functions[0],
        "output_root",
        V::string(ContentHash::of_bytes(b"changed output").as_str()),
    );
    let changed = ReplayDataV3::new(altered, l).unwrap();
    assert!(replay.verify_semantics(&changed).is_err());
}

#[test]
fn prepared_source_selection_and_final_footprint_validation() {
    let l = Limits::default();
    let mut i = input();
    i.prepared.push(object([
        ("identity", V::string("interpretation:1")),
        (
            "snapshot",
            cdb_core::record_codec::snapshot_value(&i.base.snapshot),
        ),
        ("as_of", V::string(i.base.as_of.canonical())),
        ("selections", V::Array(vec![i.base.config.projection()])),
        ("translator", i.base.config.projection()),
        ("reasoner", i.base.config.projection()),
        ("rules", i.base.config.projection()),
        ("dependencies", V::Array(vec![])),
        ("reads", V::Array(vec![])),
    ]));
    let good = ReplayDataV3::new(i.clone(), l).unwrap();
    assert_eq!(
        ReplayDataV3::read(&good.bytes(l).unwrap(), l).unwrap(),
        good
    );
    for key in i.prepared[0].as_object().unwrap().keys() {
        let mut changed = i.clone();
        let V::Object(p) = &mut changed.prepared[0] else {
            unreachable!()
        };
        p.remove(key);
        assert!(
            ReplayDataV3::new(changed, l).is_err(),
            "missing prepared {key}"
        );
    }
    let mut changed = i.clone();
    set(
        &mut changed.prepared[0],
        "snapshot",
        cdb_core::record_codec::snapshot_value(&pin("2")),
    );
    assert!(ReplayDataV3::new(changed, l).is_err());
    let mut changed = i.clone();
    changed.prepared.push(changed.prepared[0].clone());
    assert!(ReplayDataV3::new(changed, l).is_err());
    let mut wire = good.projection();
    set(
        &mut wire,
        "final_footprint",
        V::string(ContentHash::of_bytes(b"unbound").as_str()),
    );
    assert!(ReplayDataV3::from_value(&wire, l).is_err());
    let malformed = object([
        ("facts", V::Array(vec![V::Null])),
        ("invocations", V::Array(vec![])),
    ]);
    assert!(AuthorizationRequirementsV3::from_value(&malformed, l).is_err());
}
#[test]
fn typed_lane_identity_and_unknown_ordinal_reject() {
    let identity = LaneIdentityV3 {
        phase: LanePhaseV3::Walk,
        evaluation: 3,
        predicate: 1,
        attempt: 0,
        ordinal: 4,
    };
    assert_eq!(
        LaneIdentityV3::from_value(&identity.projection()).unwrap(),
        identity
    );
    let mut i = input();
    let read = cdb_core::recording::ReadObservation {
        operation: ResourceId::new("lookup").unwrap(),
        key: V::Null,
        result_hash: ContentHash::of_bytes(b"null"),
    };
    i.base.reads.push(read.clone());
    set(
        &mut i.lanes[0],
        "reads",
        V::Array(vec![lane_read(1, &read)]),
    );
    assert!(ReplayDataV3::new(i, Limits::default()).is_err());
}
