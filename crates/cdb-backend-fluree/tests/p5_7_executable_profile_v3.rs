#[path = "../src/executable_profile_v3.rs"]
mod executable_profile_v3;

use cdb_core::{id::ContentHash, Limits};
use executable_profile_v3::{
    CategoryCommitmentV3, CategoryCommitmentsV3, ExecutableProfileManifestV3,
    ExecutableProfileManifestV3Input, CONSTRUCT_AUDIT_ROOT_PREDICATE,
    EXECUTABLE_PROFILE_ROOT_PREDICATE, EXECUTABLE_PROFILE_V3_MANIFEST_PREDICATE,
    EXECUTABLE_PROFILE_V3_SCHEMA, ONTOLOGY_PROFILE_PREDICATE, ONTOLOGY_PROFILE_V3_RESULT_LABEL,
    ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID, PINNED_FLUREE_REVISION,
};

fn hash(label: &str) -> ContentHash {
    ContentHash::of_bytes(label.as_bytes())
}

fn category(label: &str, count: u64) -> CategoryCommitmentV3 {
    CategoryCommitmentV3 {
        count,
        root: hash(&format!("{label}-root")),
        occurrence_root: hash(&format!("{label}-occurrences")),
    }
}

fn input() -> ExecutableProfileManifestV3Input {
    ExecutableProfileManifestV3Input {
        selected_scope: "FND/Relations/Relations".into(),
        scope_authority_root: hash("scope-authority"),
        acquisition_authority_root: hash("acquisition-authority"),
        selected_source_release_id:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        selected_source_file_id: "fibo/FND/Relations/Relations.rdf".into(),
        selected_ontology_iri: "https://spec.edmcouncil.org/fibo/ontology/FND/Relations/Relations/"
            .into(),
        source_member_root: hash("source-members"),
        source_closure_root: hash("source-closure"),
        dependency_universe_root: hash("universe"),
        full_bundle_root: hash("bundle"),
        full_bundle_count: 100,
        construct_audit_root: hash("audit"),
        source_entry_root: hash("sources"),
        categories: CategoryCommitmentsV3 {
            reasoned: category("reasoned", 60),
            inference_inert_declaration: category("declaration", 5),
            retained_annotation: category("annotation", 20),
            retained_uninterpreted_semantic: category("uninterpreted", 15),
        },
        annotation_policy_root: hash("annotation-policy"),
        registry_root: hash("registry"),
        family_root: hash("families"),
        component_projection_root: hash("components"),
        source_occurrence_root: hash("source-occurrences"),
        reasoned_family_inventory_root: hash("reasoner-inventory"),
        declaration_evidence_root: hash("declaration-evidence"),
        uninterpreted_non_interference_root: hash("non-interference"),
        parity_matrix_root: hash("parity"),
        final_gate3_semantic_coverage_root: hash("coverage"),
        caveat_set_root: hash("caveats"),
        ontology_c0_input_root: hash("c0"),
        ontology_c0_input_count: 80,
        profile_limits_identity: hash("profile-limits"),
        dependency_limits_identity: hash("dependency-limits"),
    }
}

#[test]
fn canonical_manifest_round_trips_and_has_no_self_root() {
    let limits = Limits::default();
    let manifest = ExecutableProfileManifestV3::new(input(), limits).unwrap();
    let bytes = manifest.canonical_bytes(limits).unwrap();
    let reparsed = ExecutableProfileManifestV3::from_canonical_bytes(&bytes, limits).unwrap();

    assert_eq!(manifest, reparsed);
    assert_eq!(manifest.input(), &input());
    assert_eq!(manifest.projection(), reparsed.projection());
    assert_eq!(
        manifest.root(limits).unwrap(),
        ContentHash::of_bytes(&bytes)
    );
    assert_eq!(
        EXECUTABLE_PROFILE_V3_MANIFEST_PREDICATE,
        "https://ctxql.example/semantic-rdf/v2/executableProfileManifest"
    );
    assert_eq!(
        ONTOLOGY_PROFILE_PREDICATE,
        "https://ctxql.example/semantic-rdf/v2/ontologyProfile"
    );
    assert_eq!(
        CONSTRUCT_AUDIT_ROOT_PREDICATE,
        "https://ctxql.example/semantic-rdf/v2/constructAuditRoot"
    );
    assert_eq!(
        EXECUTABLE_PROFILE_ROOT_PREDICATE,
        "https://ctxql.example/semantic-rdf/v2/executableProfileRoot"
    );
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.contains(EXECUTABLE_PROFILE_V3_SCHEMA));
    assert!(text.contains(ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID));
    assert!(text.contains(ONTOLOGY_PROFILE_V3_RESULT_LABEL));
    assert!(text.contains(PINNED_FLUREE_REVISION));
    assert!(text.contains("final_gate3_semantic_coverage_root"));
    assert!(!text.contains("\"semantic_coverage_root\""));
    assert!(!text.contains("executable_profile_root"));
    assert!(!text.contains("ontology_rdf"));
}

#[test]
fn equivalent_noncanonical_json_is_rejected() {
    let limits = Limits::default();
    let manifest = ExecutableProfileManifestV3::new(input(), limits).unwrap();
    let mut bytes = b"\n".to_vec();
    bytes.extend(manifest.canonical_bytes(limits).unwrap());
    assert!(ExecutableProfileManifestV3::from_canonical_bytes(&bytes, limits).is_err());
}

#[test]
fn unknown_missing_and_self_root_fields_are_rejected() {
    let limits = Limits::default();
    let manifest = ExecutableProfileManifestV3::new(input(), limits).unwrap();
    let bytes = manifest.canonical_bytes(limits).unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    json.as_object_mut()
        .unwrap()
        .insert("unknown".into(), serde_json::Value::Bool(true));
    assert!(ExecutableProfileManifestV3::from_canonical_bytes(
        &serde_json::to_vec(&json).unwrap(),
        limits
    )
    .is_err());

    json.as_object_mut().unwrap().remove("unknown");
    json.as_object_mut().unwrap().insert(
        "executable_profile_root".into(),
        serde_json::Value::String(hash("self").as_str().into()),
    );
    assert!(ExecutableProfileManifestV3::from_canonical_bytes(
        &serde_json::to_vec(&json).unwrap(),
        limits
    )
    .is_err());

    json.as_object_mut()
        .unwrap()
        .remove("executable_profile_root");
    let final_coverage = json
        .as_object_mut()
        .unwrap()
        .remove("final_gate3_semantic_coverage_root")
        .unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("semantic_coverage_root".into(), final_coverage);
    assert!(ExecutableProfileManifestV3::from_canonical_bytes(
        &serde_json::to_vec(&json).unwrap(),
        limits
    )
    .is_err());

    json.as_object_mut()
        .unwrap()
        .remove("semantic_coverage_root");
    json.as_object_mut().unwrap().remove("construct_audit_root");
    assert!(ExecutableProfileManifestV3::from_canonical_bytes(
        &serde_json::to_vec(&json).unwrap(),
        limits
    )
    .is_err());
}

#[test]
fn identities_counts_and_scope_syntax_fail_closed() {
    let limits = Limits::default();

    let mut changed = input();
    changed.selected_scope = String::new();
    assert!(ExecutableProfileManifestV3::new(changed, limits).is_err());

    let mut changed = input();
    changed.full_bundle_count = 101;
    assert!(ExecutableProfileManifestV3::new(changed, limits).is_err());

    let mut changed = input();
    changed.ontology_c0_input_count = 79;
    assert!(ExecutableProfileManifestV3::new(changed, limits).is_err());

    let manifest = ExecutableProfileManifestV3::new(input(), limits).unwrap();
    let bytes = manifest.canonical_bytes(limits).unwrap();
    for (field, replacement) in [
        ("profile", "ctxql-ontology-profile/other/v1"),
        ("result_label", "owl_rl"),
        ("fluree_revision", "other"),
        ("schema", "ctxql.executable-profile-v3/v2"),
    ] {
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert(field.into(), serde_json::Value::String(replacement.into()));
        assert!(ExecutableProfileManifestV3::from_canonical_bytes(
            &serde_json::to_vec(&json).unwrap(),
            limits
        )
        .is_err());
    }
}

#[test]
fn every_recording_commitment_comes_from_manifest_and_root() {
    let limits = Limits::default();
    let source = input();
    let manifest = ExecutableProfileManifestV3::new(source.clone(), limits).unwrap();
    let recording = manifest.recording_input(limits).unwrap();

    assert_eq!(recording.construct_audit_root, source.construct_audit_root);
    assert_eq!(
        recording.executable_profile_root,
        manifest.root(limits).unwrap()
    );
    assert_eq!(
        recording.reasoned_family_inventory_root,
        source.reasoned_family_inventory_root
    );
    assert_eq!(
        recording.declaration_evidence_root,
        source.declaration_evidence_root
    );
    assert_eq!(
        recording.uninterpreted_non_interference_root,
        source.uninterpreted_non_interference_root
    );
    assert_eq!(recording.parity_matrix_root, source.parity_matrix_root);
    assert_eq!(
        recording.reasoned_category_root,
        source.categories.reasoned.root
    );
    assert_eq!(
        recording.declaration_category_root,
        source.categories.inference_inert_declaration.root
    );
    assert_eq!(
        recording.retained_annotation_category_root,
        source.categories.retained_annotation.root
    );
    assert_eq!(
        recording.retained_uninterpreted_category_root,
        source.categories.retained_uninterpreted_semantic.root
    );
    assert_eq!(recording.registry_root, source.registry_root);
    assert_eq!(recording.family_root, source.family_root);
    assert_eq!(recording.component_root, source.component_projection_root);
    assert_eq!(
        recording.source_occurrence_root,
        source.source_occurrence_root
    );
    assert_eq!(
        recording.annotation_policy_root,
        source.annotation_policy_root
    );
    assert_eq!(
        recording.semantic_coverage_root,
        source.final_gate3_semantic_coverage_root
    );
    assert_eq!(recording.caveat_set_root, source.caveat_set_root);
    assert_eq!(
        recording.ontology_c0_input_root,
        source.ontology_c0_input_root
    );
}

#[test]
fn schema_fixture_is_closed_and_names_the_same_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_7/executable-profile-v3.schema.json"
    ))
    .unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["schema"]["const"],
        EXECUTABLE_PROFILE_V3_SCHEMA
    );
    assert_eq!(
        schema["properties"]["profile"]["const"],
        ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID
    );
    let required = schema["required"].as_array().unwrap();
    assert!(required
        .iter()
        .any(|field| field == "final_gate3_semantic_coverage_root"));
    assert!(required
        .iter()
        .all(|field| field != "semantic_coverage_root" && field != "executable_profile_root"));
}
