mod support;

use cdb_backend_fluree::{
    authorized_view::{
        build_reasoner_input, quad_root, AuthorizedViewManifest, ExactTerm,
        OntologyProfileDescriptor, RdfNodeId, ReasoningDescriptor, SemanticCaptureDescriptor,
        SourceQuad,
    },
    executable_profile_v3::{
        CategoryCommitmentV3, CategoryCommitmentsV3, ExecutableProfileManifestV3,
        ExecutableProfileManifestV3Input, CONSTRUCT_AUDIT_ROOT_PREDICATE,
        EXECUTABLE_PROFILE_ROOT_PREDICATE, EXECUTABLE_PROFILE_V3_MANIFEST_PREDICATE,
        ONTOLOGY_PROFILE_PREDICATE,
    },
    ontology_construct_audit::{
        audit_ontology_closure, reconstruct_historical_audit_closure, ConstructAuditLimits,
    },
    ontology_profile_v2::STRUCTURAL_MAPPING_ALGORITHM,
    ontology_profile_v3::{
        classify_ontology_closure_v3_supported_subset,
        verify_historical_ontology_bundle_v3_supported_subset, OntologyMemberCategory,
        OntologyProfileV3Limits, ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID,
    },
    reasoning_sandbox::{reason_authorized_manifest, SandboxLimits},
    semantic_preparation::{resolve_historical_ontology_activation, HistoricalOntologyActivation},
};
use cdb_core::{id::ContentHash, Limits};
use std::collections::BTreeSet;

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const LEDGER_CONFIG: &str = "https://ns.flur.ee/db#LedgerConfig";

fn hash(value: &str) -> ContentHash {
    ContentHash::of_bytes(value.as_bytes())
}

fn category(value: &str, count: u64) -> CategoryCommitmentV3 {
    CategoryCommitmentV3 {
        count,
        root: hash(&format!("{value}-root")),
        occurrence_root: hash(&format!("{value}-occurrences")),
    }
}

fn manifest_input(bundle_root: ContentHash, bundle_count: u64) -> ExecutableProfileManifestV3Input {
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
        full_bundle_root: bundle_root.clone(),
        full_bundle_count: bundle_count,
        construct_audit_root: hash("audit"),
        source_entry_root: hash("source-entry"),
        categories: CategoryCommitmentsV3 {
            reasoned: category("reasoned", bundle_count),
            inference_inert_declaration: category("declaration", 0),
            retained_annotation: category("annotation", 0),
            retained_uninterpreted_semantic: category("uninterpreted", 0),
        },
        annotation_policy_root: hash("annotations"),
        registry_root: hash("registry"),
        family_root: hash("families"),
        component_projection_root: hash("components"),
        source_occurrence_root: hash("occurrences"),
        reasoned_family_inventory_root: hash("inventory"),
        declaration_evidence_root: hash("declarations"),
        uninterpreted_non_interference_root: hash("non-interference"),
        parity_matrix_root: hash("parity"),
        final_gate3_semantic_coverage_root: hash("coverage"),
        caveat_set_root: hash("caveats"),
        ontology_c0_input_root: bundle_root,
        ontology_c0_input_count: bundle_count,
        profile_limits_identity: hash("profile-limits"),
        dependency_limits_identity: hash("dependency-limits"),
    }
}

fn literal_quad(predicate: &str, lexical: String) -> SourceQuad {
    SourceQuad {
        graph: "urn:test:config-graph".into(),
        subject: RdfNodeId::Iri("urn:test:config".into()),
        predicate: predicate.into(),
        object: ExactTerm::Literal {
            lexical,
            datatype: XSD_STRING.into(),
            language: None,
        },
    }
}

fn activation(manifest: &ExecutableProfileManifestV3) -> BTreeSet<SourceQuad> {
    let limits = Limits::default();
    let mut config = BTreeSet::from([SourceQuad {
        graph: "urn:test:config-graph".into(),
        subject: RdfNodeId::Iri("urn:test:config".into()),
        predicate: RDF_TYPE.into(),
        object: ExactTerm::Iri(LEDGER_CONFIG.into()),
    }]);
    config.insert(literal_quad(
        ONTOLOGY_PROFILE_PREDICATE,
        ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID.into(),
    ));
    config.insert(literal_quad(
        CONSTRUCT_AUDIT_ROOT_PREDICATE,
        manifest.input().construct_audit_root.as_str().into(),
    ));
    config.insert(literal_quad(
        EXECUTABLE_PROFILE_ROOT_PREDICATE,
        manifest.root(limits).unwrap().as_str().into(),
    ));
    config.insert(literal_quad(
        EXECUTABLE_PROFILE_V3_MANIFEST_PREDICATE,
        String::from_utf8(manifest.canonical_bytes(limits).unwrap()).unwrap(),
    ));
    config
}

#[test]
fn activation_is_exact_closed_and_root_verified() {
    let limits = Limits::default();
    assert_eq!(
        resolve_historical_ontology_activation(&BTreeSet::new(), limits).unwrap(),
        HistoricalOntologyActivation::ProfileV2Default
    );
    let manifest =
        ExecutableProfileManifestV3::new(manifest_input(hash("bundle"), 1), limits).unwrap();
    let config = activation(&manifest);
    assert!(matches!(
        resolve_historical_ontology_activation(&config, limits).unwrap(),
        HistoricalOntologyActivation::ProfileV3 { manifest: actual, .. } if *actual == manifest
    ));

    for predicate in [
        CONSTRUCT_AUDIT_ROOT_PREDICATE,
        EXECUTABLE_PROFILE_ROOT_PREDICATE,
        EXECUTABLE_PROFILE_V3_MANIFEST_PREDICATE,
    ] {
        let partial = config
            .iter()
            .filter(|quad| quad.predicate != predicate)
            .cloned()
            .collect();
        assert_eq!(
            resolve_historical_ontology_activation(&partial, limits).unwrap_err(),
            "ontology_configuration_invalid"
        );
    }

    let mut wrong_root = config.clone();
    wrong_root.retain(|quad| quad.predicate != EXECUTABLE_PROFILE_ROOT_PREDICATE);
    wrong_root.insert(literal_quad(
        EXECUTABLE_PROFILE_ROOT_PREDICATE,
        hash("wrong").as_str().into(),
    ));
    assert_eq!(
        resolve_historical_ontology_activation(&wrong_root, limits).unwrap_err(),
        "ontology_configuration_invalid"
    );

    let mut superseded = config;
    superseded.retain(|quad| quad.predicate != ONTOLOGY_PROFILE_PREDICATE);
    superseded.insert(literal_quad(
        ONTOLOGY_PROFILE_PREDICATE,
        cdb_backend_fluree::ontology_profile_v3::ONTOLOGY_PROFILE_V3_SUPERSEDED_ID.into(),
    ));
    assert_eq!(
        resolve_historical_ontology_activation(&superseded, limits).unwrap_err(),
        "ontology_profile_unsupported"
    );
}

fn sealed_v3_manifest() -> AuthorizedViewManifest {
    let schema = BTreeSet::from([SourceQuad {
        graph: "urn:test:schema".into(),
        subject: RdfNodeId::Iri("urn:test:C".into()),
        predicate: RDF_TYPE.into(),
        object: ExactTerm::Iri("http://www.w3.org/2002/07/owl#Class".into()),
    }]);
    let capture = SemanticCaptureDescriptor {
        ledger: "ctxql/test:main".into(),
        requested_as_of: "t:1".into(),
        t: 1,
        commit_cid: "fluree:db:sha256:test".into(),
    };
    let reasoner_input = build_reasoner_input(&capture, &BTreeSet::new(), &schema).unwrap();
    let limits = Limits::default();
    let input = manifest_input(quad_root(&schema), schema.len() as u64);
    let profile_limits = input.profile_limits_identity.clone();
    let supported = ExecutableProfileManifestV3::new(input, limits).unwrap();
    AuthorizedViewManifest::seal_profiled_v3(
        capture,
        ReasoningDescriptor {
            schema_source: "urn:test:schema".into(),
            follow_owl_imports: false,
            schema_graphs: BTreeSet::from(["urn:test:schema".into()]),
        },
        BTreeSet::new(),
        schema.clone(),
        reasoner_input,
        STRUCTURAL_MAPPING_ALGORITHM.into(),
        profile_limits,
        BTreeSet::new(),
        hash("historical-config"),
        OntologyProfileDescriptor {
            identity: ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID.into(),
            full_bundle_root: quad_root(&schema),
            result_root: hash("certified-result"),
        },
        schema,
        supported,
        hash("policy"),
        "complete",
    )
    .unwrap()
}

#[test]
fn historical_bundle_is_reclassified_from_ledger_terms_and_manifest_roots() {
    let bundle = BTreeSet::from([SourceQuad {
        graph: "urn:test:schema".into(),
        subject: RdfNodeId::Iri("urn:test:C".into()),
        predicate: RDF_TYPE.into(),
        object: ExactTerm::Iri("http://www.w3.org/2002/07/owl#Class".into()),
    }]);
    let profile_limits = OntologyProfileV3Limits::default();
    let dependency_root = hash("universe");
    let closure = reconstruct_historical_audit_closure(&bundle, dependency_root.clone()).unwrap();
    let audit = audit_ontology_closure(&closure, ConstructAuditLimits::default()).unwrap();
    let analysis =
        classify_ontology_closure_v3_supported_subset(&closure, &audit, profile_limits).unwrap();
    let mut input = manifest_input(quad_root(&bundle), bundle.len() as u64);
    input.dependency_universe_root = dependency_root;
    input.annotation_policy_root = analysis.annotation_policy_root.clone();
    input.registry_root = analysis.registry_root.clone();
    input.caveat_set_root = analysis.caveat_set_root.clone();
    input.ontology_c0_input_root = analysis.ontology_c0_input_root.clone();
    input.ontology_c0_input_count = analysis.ontology_c0_input.len() as u64;
    input.profile_limits_identity = analysis.limits_identity.clone();
    for (category, commitment) in [
        (
            OntologyMemberCategory::Reasoned,
            &mut input.categories.reasoned,
        ),
        (
            OntologyMemberCategory::InferenceInertDeclaration,
            &mut input.categories.inference_inert_declaration,
        ),
        (
            OntologyMemberCategory::RetainedAnnotation,
            &mut input.categories.retained_annotation,
        ),
        (
            OntologyMemberCategory::RetainedUninterpretedSemantic,
            &mut input.categories.retained_uninterpreted_semantic,
        ),
    ] {
        commitment.count = analysis.category_counts[&category] as u64;
        commitment.root = analysis.category_roots[&category].clone();
    }
    let manifest = ExecutableProfileManifestV3::new(input, Limits::default()).unwrap();
    let verified =
        verify_historical_ontology_bundle_v3_supported_subset(&bundle, &manifest, profile_limits)
            .unwrap();
    assert_eq!(verified.ontology_c0_input, analysis.ontology_c0_input);

    let mut substituted = bundle;
    substituted.insert(SourceQuad {
        graph: "urn:test:schema".into(),
        subject: RdfNodeId::Iri("urn:test:D".into()),
        predicate: RDF_TYPE.into(),
        object: ExactTerm::Iri("http://www.w3.org/2002/07/owl#Class".into()),
    });
    assert_eq!(
        verify_historical_ontology_bundle_v3_supported_subset(
            &substituted,
            &manifest,
            profile_limits,
        )
        .unwrap_err()
        .public_code,
        "ontology_semantic_coverage_mismatch"
    );
}

#[test]
fn v3_authorized_manifest_binds_executable_manifest_without_changing_v2_sealing() {
    let manifest = sealed_v3_manifest();
    manifest.validate().unwrap();
    assert!(manifest.supported_subset.is_some());

    let mut substituted = manifest.clone();
    substituted.supported_subset = None;
    assert_eq!(
        substituted.validate().unwrap_err(),
        "authorized_manifest_invalid"
    );

    let mut substituted_c0 = manifest;
    substituted_c0.supported_subset_c0 = Some(BTreeSet::new());
    assert_eq!(
        substituted_c0.validate().unwrap_err(),
        "authorized_manifest_invalid"
    );
}

#[tokio::test]
async fn v3_sandbox_uses_only_the_sealed_input_and_empty_schema_overlay() {
    let archival = sealed_v3_manifest();
    let error = reason_authorized_manifest(&archival, SandboxLimits::default())
        .await
        .expect_err("the archival profile must not run through the current executor");
    assert_eq!(error.kind, cdb_core::ErrorKind::Unsupported);

    let manifest = support::seal_for_current_reasoner(&archival);
    let prepared = reason_authorized_manifest(&manifest, SandboxLimits::default())
        .await
        .unwrap();
    let descriptor = prepared
        .descriptor(
            cdb_core::snapshot::SnapshotRef::new(
                cdb_core::id::BackendId::new("fluree").unwrap(),
                cdb_core::snapshot::GraphPin::new(
                    cdb_core::id::AuthorityId::new("test").unwrap(),
                    cdb_core::id::GraphId::new("ctxql/test:main").unwrap(),
                    cdb_core::id::VersionId::new("1").unwrap(),
                    cdb_core::id::ResourceId::new("fluree:db:sha256:test").unwrap(),
                ),
            ),
            &manifest,
        )
        .unwrap();
    assert_eq!(
        descriptor.materializer.as_str(),
        "ctxql-fluree-authorized-union/current-4.2.1-supported-reasoning/v1"
    );
}
