mod common;

use cdb_core::{
    artifact::ArtifactRef,
    canonical::CanonicalProjection,
    contracts::{CapturedSnapshot, ExecutionCaptures},
    id::*,
    record_codec::{decode_record, encode_record},
    recording::{RecordingEngine, ReplayDataInput, REQUIRED_SCOPES},
    recording_v3::{ReplayDataV3, ReplayDataV3Input, REPLAY_ABI as REPLAY_ABI_V3},
    recording_v4::{
        PreparedSemanticMappingDescriptor, ReplayDataV4, RunEnvelopeV4, SemanticEvidenceV4,
        SemanticEvidenceV4Input, SemanticPolicyModeV4, StoredV4, SupportedSubsetEvidenceV4,
        SupportedSubsetEvidenceV4Input, ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID, REPLAY_SCHEMA,
        RUN_SCHEMA,
    },
    recording_v5::{ReplayDataV5, RunEnvelopeV5, BACKEND_ID, REASONER_PREFIX},
    snapshot::{GraphPin, SnapshotRef},
    CanonicalValue as V, Limits, Timestamp,
};
use common::fixture;

fn hash(label: &str) -> ContentHash {
    ContentHash::of_bytes(label.as_bytes())
}

fn hashes(labels: &[&str]) -> Vec<ContentHash> {
    let mut values = labels.iter().map(|label| hash(label)).collect::<Vec<_>>();
    values.sort();
    values
}

fn pin(backend: &str, authority: &str, graph: &str, revision: &str, receipt: &str) -> SnapshotRef {
    SnapshotRef::new(
        BackendId::new(backend).unwrap(),
        GraphPin::new(
            AuthorityId::new(authority).unwrap(),
            GraphId::new(graph).unwrap(),
            VersionId::new(revision).unwrap(),
            ResourceId::new(receipt).unwrap(),
        ),
    )
}

fn semantic_capture() -> SnapshotRef {
    pin(
        "semantic",
        "semantic-authority",
        "semantic:main",
        "7",
        "bafy-semantic-capture",
    )
}

fn control_capture() -> SnapshotRef {
    pin(
        "control",
        "control-authority",
        "control:main",
        "11",
        "bafy-control-capture",
    )
}

fn mapping(capture: SnapshotRef, prepared: ContentHash) -> PreparedSemanticMappingDescriptor {
    PreparedSemanticMappingDescriptor::new(
        capture,
        VersionId::new("ctxql-semantic-mapping/v1").unwrap(),
        hash("mapping-definitions"),
        2,
        hash("mapping-resolvers"),
        1,
        hash("mapping-values"),
        3,
        hash("mapping-dependencies"),
        prepared,
        Limits::default(),
    )
    .unwrap()
}

fn evidence() -> SemanticEvidenceV4 {
    let capture = semantic_capture();
    let prepared = hash("prepared");
    SemanticEvidenceV4::new(
        SemanticEvidenceV4Input {
            capture: capture.clone(),
            requested_as_of: Some(Timestamp::parse("2026-09-16T00:00:00.000Z").unwrap()),
            policy_mode: SemanticPolicyModeV4::Configured,
            policy_dependency_root: hash("policy"),
            policy_source_observation: ResourceId::new("policy-observation").unwrap(),
            principal: PrincipalId::new("reader").unwrap(),
            action: Iri::new("urn:ctxql:view").unwrap(),
            historical_config_root: hash("config"),
            graph_role_map_root: hash("roles"),
            configuration_graph: Iri::new("urn:graph:config").unwrap(),
            governed_data_graphs: vec![
                Iri::new("urn:graph:claims").unwrap(),
                Iri::new("urn:graph:data").unwrap(),
            ],
            claim_graphs: vec![Iri::new("urn:graph:claims").unwrap()],
            schema_source: Iri::new("urn:graph:schema-a").unwrap(),
            schema_graphs: vec![
                Iri::new("urn:graph:schema-a").unwrap(),
                Iri::new("urn:graph:schema-b").unwrap(),
            ],
            follow_owl_imports: true,
            data_root: hash("data"),
            schema_root: hash("schema"),
            data_commitments: hashes(&["data-1", "data-2", "data-3"]),
            schema_commitments: hashes(&["schema-1", "schema-2", "schema-3", "schema-4"]),
            visible_support_ids: vec![
                Iri::new("urn:claim:1").unwrap(),
                Iri::new("urn:claim:2").unwrap(),
            ],
            authorized_data_quads: 3,
            authorized_schema_quads: 4,
            visible_supports: 2,
            authorized_premise_root: hash("premises"),
            execution_manifest_root: hash("manifest"),
            ontology_profile: VersionId::new("ctxql-direct-owl2rl-profile/v2").unwrap(),
            full_ontology_bundle_root: hash("ontology-bundle"),
            ontology_profile_result_root: hash("ontology-profile-result"),
            reasoner_input_root: hash("reasoner-input"),
            structural_mapping_algorithm: VersionId::new("ctxql-structural-node-mapping/v1")
                .unwrap(),
            profile_limits_identity: hash("profile-limits"),
            materialization_limits_identity: hash("materialization-limits"),
            reasoning_limits_identity: hash("reasoning-limits"),
            prepared_root: prepared.clone(),
            semantic_codec: VersionId::new("ctxql-semantic-rdf/v1").unwrap(),
            commitment_algorithm: VersionId::new("ctxql-source-quad-commitment/sha256-v1").unwrap(),
            extraction_algorithm: VersionId::new("ctxql-authorized-view-extraction/v1").unwrap(),
            materializer: VersionId::new("ctxql-fluree-authorized-union/v1").unwrap(),
            reasoner: VersionId::new("fluree-owl2rl/4.2-603974f").unwrap(),
            budget_identity: hash("budget"),
            diagnostics_root: hash("diagnostics"),
            completeness_selector: "complete".into(),
            completeness_evidence: hash("complete"),
            mapping: mapping(capture, prepared),
            supported_subset: None,
        },
        Limits::default(),
    )
    .unwrap()
}

fn supported_subset() -> SupportedSubsetEvidenceV4 {
    SupportedSubsetEvidenceV4::new(
        SupportedSubsetEvidenceV4Input {
            construct_audit_root: hash("construct-audit"),
            executable_profile_root: hash("executable-profile"),
            reasoned_family_inventory_root: hash("reasoned-family-inventory"),
            declaration_evidence_root: hash("declaration-evidence"),
            uninterpreted_non_interference_root: hash("uninterpreted-non-interference"),
            parity_matrix_root: hash("parity-matrix"),
            reasoned_category_root: hash("reasoned-category"),
            declaration_category_root: hash("declaration-category"),
            retained_annotation_category_root: hash("annotation-category"),
            retained_uninterpreted_category_root: hash("uninterpreted-category"),
            registry_root: hash("registry"),
            family_root: hash("family"),
            component_root: hash("component"),
            source_occurrence_root: hash("source-occurrence"),
            annotation_policy_root: hash("annotation-policy"),
            semantic_coverage_root: hash("semantic-coverage"),
            caveat_set_root: hash("caveats"),
            ontology_c0_input_root: hash("ontology-c0"),
        },
        Limits::default(),
    )
    .unwrap()
}

fn base_input(snapshot: SnapshotRef) -> ReplayDataInput {
    let limits = Limits::default();
    let mut plan_value = fixture("plan");
    let V::Object(root) = &mut plan_value else {
        unreachable!()
    };
    let V::Object(payload) = root.get_mut("payload").unwrap() else {
        unreachable!()
    };
    let V::Object(artifacts) = payload.get_mut("artifacts").unwrap() else {
        unreachable!()
    };
    artifacts.insert("query".into(), artifacts["config"].clone());
    let plan =
        CanonicalProjection::read(&plan_value.canonical_bytes(limits).unwrap(), limits).unwrap();
    let config = ArtifactRef::from_value(
        plan.payload()
            .field("artifacts")
            .unwrap()
            .field("config")
            .unwrap(),
    )
    .unwrap();
    ReplayDataInput {
        snapshot: snapshot.clone(),
        requested_snapshot: snapshot,
        as_of: Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
        stale: false,
        plan_hash: ContentHash::parse(
            "sha256:c62caf74fbecd39100be7fa9fbcbcea7f9c0bb84815814c125fcfc61bc9fe5a3",
        )
        .unwrap(),
        plan,
        response: CanonicalProjection::read(
            &fixture("response").canonical_bytes(limits).unwrap(),
            limits,
        )
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
            build: hash("engine"),
        },
        replay_abi: VersionId::new(REPLAY_ABI_V3).unwrap(),
        landings: vec![],
        catalog: vec![],
        policy: vec![],
        reads: vec![],
        scopes: REQUIRED_SCOPES
            .iter()
            .map(|scope| ResourceId::new(*scope).unwrap())
            .collect(),
        functions: vec![],
    }
}

fn base_replay() -> ReplayDataV3 {
    let base = base_input(semantic_capture());
    let identity = V::object([
        ("phase".into(), V::string("preparation")),
        ("evaluation".into(), V::integer(0)),
        ("predicate".into(), V::integer(0)),
        ("attempt".into(), V::integer(0)),
        ("ordinal".into(), V::integer(0)),
    ])
    .unwrap();
    let lane = V::object([
        ("identity".into(), identity.clone()),
        ("closed".into(), V::Bool(true)),
        ("outcome".into(), V::string("empty")),
        ("reads".into(), V::Array(vec![])),
        ("policy".into(), V::Array(vec![])),
        (
            "scopes".into(),
            V::Array(
                base.scopes
                    .iter()
                    .map(|scope| V::string(scope.as_str()))
                    .collect(),
            ),
        ),
        ("function_counts".into(), V::Array(vec![])),
    ])
    .unwrap();
    let executor = base.engine.clone();
    ReplayDataV3::new(
        ReplayDataV3Input {
            base,
            lanes: vec![lane],
            expected_lanes: vec![identity],
            functions: vec![],
            prepared: vec![],
            release_evidence: vec![],
            executor,
        },
        Limits::default(),
    )
    .unwrap()
}

fn replay() -> ReplayDataV4 {
    let semantic = evidence();
    let captures = ExecutionCaptures::new(
        CapturedSnapshot {
            as_of: Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
            snapshot: semantic_capture(),
        },
        control_capture(),
    );
    ReplayDataV4::new(base_replay(), semantic, &captures, Limits::default()).unwrap()
}

fn run() -> RunEnvelopeV4 {
    RunEnvelopeV4::new(
        RunId::new("v4/run").unwrap(),
        PrincipalId::new("reader").unwrap(),
        hash("operation"),
        replay(),
        Limits::default(),
    )
    .unwrap()
}

fn current_replay() -> ReplayDataV4 {
    let mut semantic = evidence().projection();
    let V::Object(fields) = &mut semantic else {
        unreachable!()
    };
    fields.insert("reasoner".into(), V::string("none/v1"));
    fields.insert("materializer".into(), V::string("none/v1"));
    let semantic = SemanticEvidenceV4::from_value(&semantic, Limits::default()).unwrap();
    let captures = ExecutionCaptures::new(
        CapturedSnapshot {
            as_of: Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
            snapshot: semantic_capture(),
        },
        control_capture(),
    );
    ReplayDataV4::new(base_replay(), semantic, &captures, Limits::default()).unwrap()
}

fn remove_field(value: &V, field: &str) -> V {
    let mut changed = value.clone();
    let V::Object(fields) = &mut changed else {
        unreachable!()
    };
    fields.remove(field);
    changed
}

fn replace_field(value: &V, field: &str, replacement: V) -> V {
    let mut changed = value.clone();
    let V::Object(fields) = &mut changed else {
        unreachable!()
    };
    fields.insert(field.into(), replacement);
    changed
}

#[test]
fn mapping_descriptor_round_trip_closed_schema_and_all_required_fields() {
    let limits = Limits::default();
    let descriptor = mapping(semantic_capture(), hash("prepared"));
    let bytes = descriptor.projection().canonical_bytes(limits).unwrap();
    let decoded =
        PreparedSemanticMappingDescriptor::from_value(&V::parse(&bytes, limits).unwrap(), limits)
            .unwrap();
    assert_eq!(decoded, descriptor);

    let fields = [
        "capture",
        "algorithm",
        "definition_root",
        "definition_count",
        "resolver_root",
        "resolver_count",
        "value_root",
        "value_count",
        "dependency_root",
        "prepared_ontology_root",
    ];
    for field in fields {
        assert!(
            PreparedSemanticMappingDescriptor::from_value(
                &remove_field(&descriptor.projection(), field),
                limits
            )
            .is_err(),
            "missing mapping field {field} was accepted"
        );
    }
    let unknown = replace_field(&descriptor.projection(), "rdf", V::Null);
    assert!(PreparedSemanticMappingDescriptor::from_value(&unknown, limits).is_err());
}

#[test]
fn mapping_descriptor_rejects_none_count_root_and_bound_mutations() {
    let limits = Limits::default();
    let none =
        PreparedSemanticMappingDescriptor::none(semantic_capture(), hash("prepared"), limits)
            .unwrap();
    for field in ["definition_count", "resolver_count", "value_count"] {
        assert!(
            PreparedSemanticMappingDescriptor::from_value(
                &replace_field(&none.projection(), field, V::integer(1)),
                limits,
            )
            .is_err(),
            "nonzero none count {field} was accepted"
        );
    }
    for field in [
        "definition_root",
        "resolver_root",
        "value_root",
        "dependency_root",
    ] {
        assert!(
            PreparedSemanticMappingDescriptor::from_value(
                &replace_field(&none.projection(), field, V::string(hash(field).as_str())),
                limits,
            )
            .is_err(),
            "non-sentinel none root {field} was accepted"
        );
    }

    let configured = mapping(semantic_capture(), hash("prepared")).projection();
    for field in [
        "definition_root",
        "resolver_root",
        "value_root",
        "dependency_root",
        "prepared_ontology_root",
    ] {
        assert!(
            PreparedSemanticMappingDescriptor::from_value(
                &replace_field(&configured, field, V::string("not-a-hash")),
                limits,
            )
            .is_err(),
            "malformed mapping root {field} was accepted"
        );
    }
    assert!(PreparedSemanticMappingDescriptor::from_value(
        &replace_field(&configured, "definition_count", V::integer(0)),
        limits,
    )
    .is_err());
    assert!(PreparedSemanticMappingDescriptor::from_value(
        &replace_field(&configured, "resolver_count", V::integer(3)),
        limits,
    )
    .is_err());
    assert!(PreparedSemanticMappingDescriptor::from_value(
        &replace_field(&configured, "algorithm", V::string("")),
        limits,
    )
    .is_err());
    let tiny = Limits::new(64, 64, 1, 100, 1024).unwrap();
    assert!(PreparedSemanticMappingDescriptor::from_value(&configured, tiny).is_err());
}

#[test]
fn semantic_evidence_round_trip_closed_schema_and_no_rdf_payload() {
    let limits = Limits::default();
    let evidence = evidence();
    let bytes = evidence.projection().canonical_bytes(limits).unwrap();
    assert_eq!(
        SemanticEvidenceV4::from_value(&V::parse(&bytes, limits).unwrap(), limits).unwrap(),
        evidence
    );
    let text = String::from_utf8(bytes).unwrap();
    for forbidden in ["source_quads", "exact_terms", "inferred_facts", "sandbox"] {
        assert!(!text.contains(forbidden));
    }

    let fields = evidence
        .projection()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for required in [
        "ontology_profile",
        "full_ontology_bundle_root",
        "ontology_profile_result_root",
        "reasoner_input_root",
        "structural_mapping_algorithm",
        "profile_limits_identity",
        "materialization_limits_identity",
        "reasoning_limits_identity",
        "budget_identity",
    ] {
        assert!(fields.iter().any(|field| field == required));
    }
    for field in fields {
        assert!(
            SemanticEvidenceV4::from_value(&remove_field(&evidence.projection(), &field), limits,)
                .is_err(),
            "missing semantic field {field} was accepted"
        );
    }
    assert!(SemanticEvidenceV4::from_value(
        &replace_field(&evidence.projection(), "rdf", V::Array(vec![])),
        limits,
    )
    .is_err());
}

#[test]
fn semantic_evidence_rejects_field_mutations_that_break_bindings_and_invariants() {
    let limits = Limits::default();
    let original = evidence().projection();

    let malformed = [
        ("policy_mode", V::string("future")),
        ("policy_dependency_root", V::string("not-a-hash")),
        ("policy_source_observation", V::string("")),
        ("principal", V::string("")),
        ("action", V::string("relative")),
        ("semantic_codec", V::string("")),
        ("ontology_profile", V::string("")),
        ("full_ontology_bundle_root", V::string("not-a-hash")),
        ("ontology_profile_result_root", V::string("not-a-hash")),
        ("reasoner_input_root", V::string("not-a-hash")),
        ("structural_mapping_algorithm", V::string("")),
        ("profile_limits_identity", V::string("not-a-hash")),
        ("materialization_limits_identity", V::string("not-a-hash")),
        ("reasoning_limits_identity", V::string("not-a-hash")),
        ("budget_identity", V::string("not-a-hash")),
        ("follow_owl_imports", V::string("true")),
        ("authorized_data_quads", V::integer(99)),
        ("authorized_schema_quads", V::integer(99)),
        ("visible_supports", V::integer(99)),
        ("completeness_selector", V::string("changed")),
    ];
    for (field, value) in malformed {
        assert!(
            SemanticEvidenceV4::from_value(&replace_field(&original, field, value), limits,)
                .is_err(),
            "invalid semantic field {field} was accepted"
        );
    }

    for field in [
        "governed_data_graphs",
        "claim_graphs",
        "schema_graphs",
        "data_commitments",
        "schema_commitments",
        "visible_support_ids",
    ] {
        let values = original.field(field).unwrap().as_array().unwrap();
        let duplicate = V::Array(vec![values[0].clone(), values[0].clone()]);
        let mut changed = replace_field(&original, field, duplicate);
        let V::Object(root) = &mut changed else {
            unreachable!()
        };
        match field {
            "data_commitments" => {
                root.insert("authorized_data_quads".into(), V::integer(2));
            }
            "schema_commitments" => {
                root.insert("authorized_schema_quads".into(), V::integer(2));
            }
            "visible_support_ids" => {
                root.insert("visible_supports".into(), V::integer(2));
            }
            _ => {}
        }
        assert!(
            SemanticEvidenceV4::from_value(&changed, limits).is_err(),
            "duplicate or unordered semantic selector {field} was accepted"
        );
    }

    let overlap = replace_field(
        &original,
        "configuration_graph",
        V::string("urn:graph:data"),
    );
    assert!(SemanticEvidenceV4::from_value(&overlap, limits).is_err());

    let mut unbound = original.clone();
    let V::Object(fields) = &mut unbound else {
        unreachable!()
    };
    let V::Object(mapping) = fields.get_mut("mapping").unwrap() else {
        unreachable!()
    };
    mapping.insert(
        "prepared_ontology_root".into(),
        V::string(hash("different-prepared").as_str()),
    );
    assert!(SemanticEvidenceV4::from_value(&unbound, limits).is_err());

    let tiny = Limits::new(64, 64, 2, 100, 1024).unwrap();
    assert!(SemanticEvidenceV4::from_value(&original, tiny).is_err());
}

#[test]
fn replay_v5_round_trip_binds_current_backend_and_rejects_mismatch() {
    let limits = Limits::default();
    let replay = ReplayDataV5::new(current_replay(), limits).unwrap();
    assert_eq!(
        ReplayDataV5::read(&replay.bytes(limits).unwrap(), limits).unwrap(),
        replay
    );
    assert_eq!(
        replay
            .execution()
            .projection()
            .field("backend")
            .unwrap()
            .as_str()
            .unwrap(),
        BACKEND_ID
    );
    assert_eq!(
        replay
            .execution()
            .projection()
            .field("reasoner")
            .unwrap()
            .as_str()
            .unwrap(),
        "none/v1"
    );
    assert!(!replay
        .bytes(limits)
        .unwrap()
        .windows(7)
        .any(|bytes| bytes == b"603974f"));

    let run = RunEnvelopeV5::new(
        RunId::new("v5/run").unwrap(),
        PrincipalId::new("reader").unwrap(),
        hash("v5-operation"),
        replay.clone(),
        limits,
    )
    .unwrap();
    assert_eq!(
        RunEnvelopeV5::read(&run.bytes(limits).unwrap(), limits).unwrap(),
        run
    );
    replay
        .verify_semantics(&ReplayDataV5::read(&replay.bytes(limits).unwrap(), limits).unwrap())
        .unwrap();

    let mut changed = replay.projection();
    let V::Object(root) = &mut changed else {
        unreachable!()
    };
    let V::Object(execution) = root.get_mut("execution").unwrap() else {
        unreachable!()
    };
    execution.insert("backend".into(), V::string("fluree-db/4.2@603974f"));
    assert!(ReplayDataV5::from_value(&changed, limits).is_err());

    let mut old_reasoner = current_replay().semantic().projection();
    let V::Object(fields) = &mut old_reasoner else {
        unreachable!()
    };
    fields.insert(
        "reasoner".into(),
        V::string("fluree-owl2rl/4.2-603974f;profile=old"),
    );
    let old = SemanticEvidenceV4::from_value(&old_reasoner, limits).unwrap();
    let captures = ExecutionCaptures::new(
        CapturedSnapshot {
            as_of: Timestamp::parse("1969-12-31T23:59:59.999Z").unwrap(),
            snapshot: semantic_capture(),
        },
        control_capture(),
    );
    assert!(ReplayDataV5::new(
        ReplayDataV4::new(base_replay(), old, &captures, limits).unwrap(),
        limits
    )
    .is_err());
    assert!(REASONER_PREFIX.contains("82dbcec3e435d6ed1d45bc0ed929432323b6b201"));
}

#[test]
fn replay_v4_round_trip_closed_schema_dual_capture_and_semantic_mutation() {
    let limits = Limits::default();
    let replay = replay();
    let bytes = replay.bytes(limits).unwrap();
    assert_eq!(ReplayDataV4::read(&bytes, limits).unwrap(), replay);
    assert_eq!(
        replay
            .projection()
            .field("schema")
            .unwrap()
            .as_str()
            .unwrap(),
        REPLAY_SCHEMA
    );
    assert_eq!(replay.control_capture(), &control_capture());

    for field in ["schema", "base", "semantic", "control_capture"] {
        assert!(
            ReplayDataV4::from_value(&remove_field(&replay.projection(), field), limits,).is_err(),
            "missing replay field {field} was accepted"
        );
    }
    assert!(ReplayDataV4::from_value(
        &replace_field(&replay.projection(), "unknown", V::Null),
        limits,
    )
    .is_err());
    assert!(ReplayDataV4::from_value(
        &replace_field(
            &replay.projection(),
            "schema",
            V::string("ctxql-replay-data/v3")
        ),
        limits,
    )
    .is_err());
    assert!(ReplayDataV4::from_value(
        &replace_field(
            &replay.projection(),
            "control_capture",
            cdb_core::record_codec::snapshot_value(&semantic_capture()),
        ),
        limits,
    )
    .is_err());

    let mut changed = replay.projection();
    let V::Object(root) = &mut changed else {
        unreachable!()
    };
    let V::Object(semantic) = root.get_mut("semantic").unwrap() else {
        unreachable!()
    };
    semantic.insert(
        "diagnostics_root".into(),
        V::string(hash("other-diagnostics").as_str()),
    );
    let changed = ReplayDataV4::from_value(&changed, limits).unwrap();
    assert!(replay.verify_semantics(&changed).is_err());
}

#[test]
fn run_v4_and_stored_record_round_trip_closed_schema_and_identity_mutations() {
    let limits = Limits::default();
    let run = run();
    assert_eq!(
        RunEnvelopeV4::read(&run.bytes(limits).unwrap(), limits).unwrap(),
        run
    );
    assert_eq!(
        run.projection().field("schema").unwrap().as_str().unwrap(),
        RUN_SCHEMA
    );
    assert_eq!(
        run.integrity_hash(limits).unwrap(),
        hash_bytes(&run.bytes(limits).unwrap())
    );

    for field in ["schema", "id", "owner", "operation_hash", "replay"] {
        assert!(
            RunEnvelopeV4::from_value(&remove_field(&run.projection(), field), limits,).is_err(),
            "missing run field {field} was accepted"
        );
    }
    for (field, value) in [
        ("schema", V::string("ctxql-recorded-run/v3")),
        ("id", V::string("")),
        ("owner", V::string("")),
        ("operation_hash", V::string("not-a-hash")),
    ] {
        assert!(
            RunEnvelopeV4::from_value(&replace_field(&run.projection(), field, value), limits,)
                .is_err(),
            "invalid run field {field} was accepted"
        );
    }
    assert!(RunEnvelopeV4::from_value(
        &replace_field(&run.projection(), "unknown", V::Null),
        limits,
    )
    .is_err());

    let stored = StoredV4(run.clone());
    let record = stored.to_record(limits).unwrap();
    let record_bytes = encode_record(&record, limits).unwrap();
    assert_eq!(
        StoredV4::from_record(&decode_record(&record_bytes, limits).unwrap(), limits).unwrap(),
        stored
    );

    let mut wrong_record = record.clone();
    let cdb_core::admission::ExportRecord::Resource(resource) = &mut wrong_record else {
        unreachable!()
    };
    *resource = cdb_core::admission::DependencyRecord::new(
        "ctxql-resource/v1",
        ResourceId::new("urn:wrong-descriptor").unwrap(),
        resource.kind(),
        resource.facts().to_vec(),
    )
    .unwrap();
    assert!(StoredV4::from_record(&wrong_record, limits).is_err());
}

fn hash_bytes(bytes: &[u8]) -> ContentHash {
    ContentHash::of_bytes(bytes)
}

#[test]
fn supported_subset_is_closed_conditional_and_bound_to_exact_v3_identity() {
    let limits = Limits::default();
    let subset = supported_subset();
    let mut v3 = evidence().projection();
    let V::Object(fields) = &mut v3 else {
        unreachable!()
    };
    fields.insert(
        "ontology_profile".into(),
        V::string(ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID),
    );
    fields.insert("supported_subset".into(), subset.projection());
    let parsed = SemanticEvidenceV4::from_value(&v3, limits).unwrap();
    assert_eq!(
        parsed.supported_subset(limits).unwrap(),
        Some(subset.clone())
    );

    let mut missing = v3.clone();
    let V::Object(fields) = &mut missing else {
        unreachable!()
    };
    fields.remove("supported_subset");
    assert!(SemanticEvidenceV4::from_value(&missing, limits).is_err());

    let mut unexpected = evidence().projection();
    let V::Object(fields) = &mut unexpected else {
        unreachable!()
    };
    fields.insert("supported_subset".into(), subset.projection());
    assert!(SemanticEvidenceV4::from_value(&unexpected, limits).is_err());

    let mut malformed = v3;
    let V::Object(fields) = &mut malformed else {
        unreachable!()
    };
    let V::Object(subset_fields) = fields.get_mut("supported_subset").unwrap() else {
        unreachable!()
    };
    subset_fields.insert("result_label".into(), V::string("owl_rl"));
    assert!(SemanticEvidenceV4::from_value(&malformed, limits).is_err());
}

#[test]
fn profile_v2_recording_bytes_are_frozen_before_supported_subset_extension() {
    let limits = Limits::default();
    let semantic = evidence().projection().canonical_bytes(limits).unwrap();
    let replay = replay().bytes(limits).unwrap();
    let run = run().bytes(limits).unwrap();

    assert_eq!(
        hash_bytes(&semantic).as_str(),
        "sha256:859323d7b5031c0971399aaf10d7db1caedce81807b74af3c8aa2f156e25592f"
    );
    assert_eq!(
        hash_bytes(&replay).as_str(),
        "sha256:4181d7c1c9576531e280dbe4d3f25d0d8d408940cb8f510db7ac1289d1c7b51f"
    );
    assert_eq!(
        hash_bytes(&run).as_str(),
        "sha256:7a3b921eb3475d97d14fcffc8b5a6045b2152dd546f442aa369dafc5a9f809dd"
    );
}
