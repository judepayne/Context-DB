use cdb_backend_fluree::{
    authorized_view::{quad_root, ExactTerm, RdfNodeId, SourceQuad},
    official_bootstrap::{prepare_official_profile, PROFILE},
    ontology_profile_load::{
        load_file_once, verify_read_only_reopen, OntologyProfileLoadLimits, OntologyProfileLoadPlan,
    },
    ontology_profile_v3::ONTOLOGY_PROFILE_V3_RESULT_LABEL,
    reasoning_sandbox::{reason_authorized_manifest, SandboxLimits},
    semantic_policy::SemanticPolicyMode,
    semantic_preparation::{
        prepare_historical_authorized_view, reconstruct_recorded_authorized_view, ExtractionLimits,
        PreparedAuthorizedView,
    },
    FlureeSemanticLedger, SemanticLedgerOptions,
};
use cdb_core::{
    id::{AuthorityId, BackendId, ContentHash, GraphId, Iri, PrincipalId, ResourceId, VersionId},
    recording_v4::{
        PreparedSemanticMappingDescriptor, SemanticEvidenceV4, SemanticEvidenceV4Input,
        SemanticPolicyModeV4, SupportedSubsetEvidenceV4,
    },
    Limits,
};
use fluree_db_api::{FlureeBuilder, GraphDb, NameServiceMode};
use fluree_db_nameservice::file::FileNameService;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

async fn official_readback_fingerprint(
    path: &Path,
    ledger_id: &str,
) -> (ContentHash, usize, Value) {
    let nameservice = NameServiceMode::ReadOnly(Arc::new(FileNameService::new(path)));
    let reader = FlureeBuilder::file(path.to_string_lossy().into_owned())
        .without_indexing()
        .build_client_with_nameservice(nameservice)
        .await
        .unwrap();
    let ledger = reader.ledger(ledger_id).await.unwrap();
    let value = reader
        .query(
            &GraphDb::from_ledger_state(&ledger),
            "SELECT ?graph ?s ?p ?o WHERE { GRAPH ?graph { ?s ?p ?o } } ORDER BY ?graph ?s ?p ?o",
        )
        .await
        .unwrap()
        .to_sparql_json(&ledger.snapshot)
        .unwrap();
    let rows = value["results"]["bindings"].as_array().unwrap().len();
    let root = ContentHash::of_bytes(&serde_json::to_vec(&value).unwrap());
    (root, rows, value)
}

fn source_quads_from_sparql(
    value: &Value,
    ontology_graphs: &BTreeSet<String>,
) -> BTreeSet<SourceQuad> {
    value["results"]["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|binding| {
            let graph = binding["graph"]["value"].as_str()?.to_owned();
            ontology_graphs.contains(&graph).then(|| {
                let subject_value = binding["s"]["value"].as_str().unwrap();
                let subject = if binding["s"]["type"] == "bnode" {
                    RdfNodeId::ScopedBlankNode(format!("_:{subject_value}"))
                } else {
                    RdfNodeId::Iri(subject_value.into())
                };
                let object_value = binding["o"]["value"].as_str().unwrap();
                let object = match binding["o"]["type"].as_str().unwrap() {
                    "uri" => ExactTerm::Iri(object_value.into()),
                    "bnode" => ExactTerm::ScopedBlankNode(format!("_:{object_value}")),
                    _ => {
                        let language = binding["o"]["xml:lang"].as_str().map(str::to_owned);
                        ExactTerm::Literal {
                            lexical: object_value.into(),
                            datatype: binding["o"]["datatype"]
                                .as_str()
                                .unwrap_or(if language.is_some() {
                                    "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString"
                                } else {
                                    "http://www.w3.org/2001/XMLSchema#string"
                                })
                                .into(),
                            language,
                        }
                    }
                };
                SourceQuad {
                    graph,
                    subject,
                    predicate: binding["p"]["value"].as_str().unwrap().into(),
                    object,
                }
            })
        })
        .collect()
}

async fn official_preparation_fingerprint(
    path: &Path,
    receipt: &cdb_backend_fluree::ontology_profile_load::OntologyProfileLoadReceipt,
) -> (
    ContentHash,
    ContentHash,
    ContentHash,
    usize,
    ContentHash,
    ContentHash,
) {
    let nameservice = NameServiceMode::ReadOnly(Arc::new(FileNameService::new(path)));
    let fluree = Arc::new(
        FlureeBuilder::file(path.to_string_lossy().into_owned())
            .without_indexing()
            .build_client_with_nameservice(nameservice)
            .await
            .unwrap(),
    );
    let semantic = FlureeSemanticLedger::open(
        fluree,
        SemanticLedgerOptions {
            backend: BackendId::new("fluree:semantic").unwrap(),
            authority: AuthorityId::new("semantic:authority").unwrap(),
            ledger: GraphId::new(&receipt.ledger).unwrap(),
        },
    )
    .await
    .unwrap();
    let capture = semantic.capture_at_t(receipt.t, None, None).await.unwrap();
    assert_eq!(capture.snapshot().pin().receipt().as_str(), receipt.cid);
    let authorized = prepare_historical_authorized_view(
        &semantic,
        &capture,
        "did:example:p5-7",
        "ctxql:query",
        ExtractionLimits::default(),
    )
    .await
    .unwrap();
    assert!(authorized.manifest.supported_subset.is_some());
    let prepared = reason_authorized_manifest(&authorized.manifest, SandboxLimits::default())
        .await
        .unwrap();
    let stored_c0_root = quad_root(
        authorized
            .manifest
            .supported_subset_c0
            .as_ref()
            .expect("verified v3 stored C0"),
    );
    (
        authorized.manifest.execution_manifest_root.0,
        prepared.prepared_root,
        prepared.diagnostics_root,
        prepared.inferred_facts.len(),
        authorized.manifest.ontology_profile.full_bundle_root,
        stored_c0_root,
    )
}

fn recording_evidence(
    authorized: &PreparedAuthorizedView,
    prepared: &cdb_backend_fluree::reasoning_sandbox::PreparedOntology,
    capture: &cdb_core::snapshot::SnapshotRef,
) -> SemanticEvidenceV4 {
    let limits = Limits::default();
    let descriptor = prepared
        .descriptor(capture.clone(), &authorized.manifest)
        .unwrap();
    let mapping = PreparedSemanticMappingDescriptor::none(
        capture.clone(),
        descriptor.prepared_root.clone(),
        limits,
    )
    .unwrap();
    let supported_subset = authorized
        .manifest
        .supported_subset
        .as_ref()
        .map(|manifest| {
            SupportedSubsetEvidenceV4::new(manifest.recording_input(limits).unwrap(), limits)
                .unwrap()
        });
    let commitments = |quads: &BTreeSet<SourceQuad>| {
        let mut values = quads
            .iter()
            .map(SourceQuad::commitment_hash)
            .collect::<Vec<_>>();
        values.sort();
        values
    };
    SemanticEvidenceV4::new(
        SemanticEvidenceV4Input {
            capture: capture.clone(),
            requested_as_of: None,
            policy_mode: match authorized.policy_basis.mode {
                SemanticPolicyMode::Unrestricted => SemanticPolicyModeV4::Unrestricted,
                SemanticPolicyMode::Configured => SemanticPolicyModeV4::Configured,
            },
            policy_dependency_root: authorized.policy_basis.dependency_root.clone(),
            policy_source_observation: ResourceId::new(&authorized.policy_basis.source_observation)
                .unwrap(),
            principal: PrincipalId::new(&authorized.policy_basis.principal).unwrap(),
            action: Iri::new(&authorized.policy_basis.action).unwrap(),
            historical_config_root: authorized.manifest.historical_config_root.clone(),
            graph_role_map_root: authorized.graph_role_map_root.clone(),
            configuration_graph: Iri::new(&authorized.configuration_graph).unwrap(),
            governed_data_graphs: authorized
                .governed_data_graphs
                .iter()
                .map(|value| Iri::new(value).unwrap())
                .collect(),
            claim_graphs: authorized
                .claim_graphs
                .iter()
                .map(|value| Iri::new(value).unwrap())
                .collect(),
            schema_source: Iri::new(&authorized.manifest.reasoning.schema_source).unwrap(),
            schema_graphs: authorized
                .manifest
                .reasoning
                .schema_graphs
                .iter()
                .map(|value| Iri::new(value).unwrap())
                .collect(),
            follow_owl_imports: authorized.manifest.reasoning.follow_owl_imports,
            data_root: authorized.manifest.data_root.clone(),
            schema_root: authorized.manifest.schema_root.clone(),
            data_commitments: commitments(&authorized.manifest.data_quads),
            schema_commitments: commitments(&authorized.manifest.schema_quads),
            visible_support_ids: authorized
                .manifest
                .visible_supports
                .iter()
                .map(|value| Iri::new(value).unwrap())
                .collect(),
            authorized_data_quads: authorized.manifest.authorized_counts.data_quads as u64,
            authorized_schema_quads: authorized.manifest.authorized_counts.schema_quads as u64,
            visible_supports: authorized.manifest.authorized_counts.visible_supports as u64,
            authorized_premise_root: authorized.manifest.authorized_premise_root.0.clone(),
            execution_manifest_root: authorized.manifest.execution_manifest_root.0.clone(),
            ontology_profile: descriptor.ontology_profile,
            full_ontology_bundle_root: descriptor.full_ontology_bundle_root,
            ontology_profile_result_root: descriptor.ontology_profile_result_root,
            reasoner_input_root: descriptor.reasoner_input_root,
            structural_mapping_algorithm: descriptor.structural_mapping_algorithm,
            profile_limits_identity: descriptor.profile_limits_identity,
            materialization_limits_identity: descriptor.materialization_limits_identity,
            reasoning_limits_identity: descriptor.reasoning_limits_identity,
            prepared_root: descriptor.prepared_root,
            semantic_codec: VersionId::new("ctxql-semantic-rdf/v1").unwrap(),
            commitment_algorithm: VersionId::new("ctxql-source-quad-commitment/sha256-v2").unwrap(),
            extraction_algorithm: VersionId::new("ctxql-authorized-view-extraction/v2").unwrap(),
            materializer: descriptor.materializer,
            reasoner: descriptor.reasoner,
            budget_identity: descriptor.budget_identity,
            diagnostics_root: descriptor.diagnostics_root,
            completeness_selector: authorized.manifest.protected_completeness.clone(),
            completeness_evidence: descriptor.completeness_root,
            mapping,
            supported_subset,
        },
        limits,
    )
    .unwrap()
}

async fn verify_official_recording_replay(
    path: &Path,
    receipt: &cdb_backend_fluree::ontology_profile_load::OntologyProfileLoadReceipt,
) {
    let nameservice = NameServiceMode::ReadOnly(Arc::new(FileNameService::new(path)));
    let fluree = Arc::new(
        FlureeBuilder::file(path.to_string_lossy().into_owned())
            .without_indexing()
            .build_client_with_nameservice(nameservice)
            .await
            .unwrap(),
    );
    let semantic = FlureeSemanticLedger::open(
        fluree,
        SemanticLedgerOptions {
            backend: BackendId::new("fluree:semantic").unwrap(),
            authority: AuthorityId::new("semantic:authority").unwrap(),
            ledger: GraphId::new(&receipt.ledger).unwrap(),
        },
    )
    .await
    .unwrap();
    let capture = semantic.capture_at_t(receipt.t, None, None).await.unwrap();
    let original = prepare_historical_authorized_view(
        &semantic,
        &capture,
        "did:example:p5-7",
        "ctxql:query",
        ExtractionLimits::default(),
    )
    .await
    .unwrap();
    let original_reasoned =
        reason_authorized_manifest(&original.manifest, SandboxLimits::default())
            .await
            .unwrap();
    let evidence = recording_evidence(&original, &original_reasoned, capture.snapshot());
    let replayed = reconstruct_recorded_authorized_view(
        &semantic,
        &capture,
        &evidence,
        ExtractionLimits::default(),
        Limits::default(),
    )
    .await
    .unwrap();
    let replayed_reasoned =
        reason_authorized_manifest(&replayed.manifest, SandboxLimits::default())
            .await
            .unwrap();
    assert_eq!(
        replayed.manifest.supported_subset,
        original.manifest.supported_subset
    );
    assert_eq!(
        replayed.manifest.supported_subset_c0,
        original.manifest.supported_subset_c0
    );
    assert_eq!(
        replayed.manifest.execution_manifest_root,
        original.manifest.execution_manifest_root
    );
    assert_eq!(replayed_reasoned, original_reasoned);
}

#[derive(Serialize)]
struct OfficialLoadReceipt {
    scope: String,
    ledger: String,
    t: i64,
    cid: String,
    full_bundle_root: String,
    executable_profile_root: String,
    ontology_quad_count: usize,
    transaction_quad_count: usize,
    transaction_bytes: usize,
    structural_node_count: usize,
    structural_mapping_root: String,
    visible_graph_readback_root: String,
    stored_bundle_root: String,
    stored_c0_root: String,
    execution_manifest_root: String,
    prepared_root: String,
    diagnostics_root: String,
    inferred_fact_count: usize,
    double_read_only_reopen_equal: bool,
    poc_storage_projection_blindly_blessed: bool,
    final_profile_identity: &'static str,
    final_result_label: &'static str,
    scope_authority_root: String,
    acquisition_authority_root: String,
    selected_source_release_id: String,
    selected_source_file_id: String,
    selected_ontology_iri: String,
    source_member_root: String,
    source_closure_root: String,
    dependency_universe_root: String,
    dependency_limits_identity: String,
    source_occurrence_root: String,
    reasoned_family_inventory_root: String,
    declaration_evidence_root: String,
    uninterpreted_non_interference_root: String,
    parity_matrix_root: String,
    final_semantic_coverage_root: String,
    final_result_root: String,
}

#[test]
#[ignore = "requires exact external Relations and Agreements ontology caches"]
fn official_relations_and_agreements_fit_one_transaction_and_two_reopens() {
    std::thread::Builder::new()
        .name("p5-7-official-load-reopen".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(
                    official_relations_and_agreements_fit_one_transaction_and_two_reopens_impl(),
                );
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn official_relations_and_agreements_fit_one_transaction_and_two_reopens_impl() {
    let relations_cache = PathBuf::from(
        std::env::var("CTXQL_P6_REFERENCE_CACHE")
            .unwrap_or_else(|_| "/tmp/ctxql-p6-reference-cache".into()),
    );
    let agreements_cache = PathBuf::from(
        std::env::var("CTXQL_P5_7_AGREEMENTS_CACHE")
            .unwrap_or_else(|_| "/tmp/ctxql-p5-7-reference-cache".into()),
    );
    assert!(relations_cache.is_absolute() && agreements_cache.is_absolute());
    let profiles = [
        (
            "FND/Relations/Relations",
            relations_cache.as_path(),
            include_str!("../../../fixtures/conformance/p5_7/official-relations-closure.json"),
            "ctxql/p5-7-official-relations:main",
        ),
        (
            "FND/Agreements/Agreements",
            agreements_cache.as_path(),
            include_str!("../../../fixtures/conformance/p5_7/official-agreements-closure.json"),
            "ctxql/p5-7-official-agreements:main",
        ),
    ];
    let mut receipts = Vec::new();
    for (scope, cache, fixture, ledger) in profiles {
        let (bundle, certified) = prepare_official_profile(cache, fixture, scope).unwrap();
        let manifest = certified.manifest().clone();
        let executable_profile_root = manifest.root(Limits::default()).unwrap();
        let full_bundle_root = manifest.input().full_bundle_root.clone();
        let final_semantic_coverage_root = certified.semantic_coverage_root().clone();
        let final_result_root = certified.result_root().clone();

        // A source substitution is rejected before a writer creates any ledger.
        let negative_directory = tempfile::tempdir().unwrap();
        let mut substituted = bundle.clone();
        substituted.pop_first();
        let negative_ledger = format!("{ledger}-source-mismatch");
        let error = load_file_once(
            negative_directory.path(),
            OntologyProfileLoadPlan {
                ledger: negative_ledger.clone(),
                source_closure: substituted,
                config_graph: format!("urn:fluree:{negative_ledger}#config"),
                config_subject: "urn:ctxql:p5-7:negative-config".into(),
                certified_profile: certified.clone(),
                limits: OntologyProfileLoadLimits::default(),
            },
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("certified source closure mismatch"));
        assert_eq!(fs::read_dir(negative_directory.path()).unwrap().count(), 0);

        let directory = tempfile::tempdir().unwrap();
        let receipt = load_file_once(
            directory.path(),
            OntologyProfileLoadPlan {
                ledger: ledger.into(),
                source_closure: bundle.clone(),
                config_graph: format!("urn:fluree:{ledger}#config"),
                config_subject: format!("urn:ctxql:p5-7:{}:ledger", scope.replace('/', "-")),
                certified_profile: certified,
                limits: OntologyProfileLoadLimits::default(),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{scope}: {error}"));
        assert_eq!(receipt.t, 1, "{scope}");
        assert_eq!(receipt.ontology_quad_count, bundle.len(), "{scope}");
        assert!(
            receipt.transaction_quad_count > bundle.len() + 4,
            "{scope} includes bounded configuration, graph roles, and POC claim/policy support"
        );

        verify_read_only_reopen(directory.path(), &receipt)
            .await
            .unwrap();
        let first = official_readback_fingerprint(directory.path(), ledger).await;
        let ontology_graphs = bundle
            .iter()
            .map(|quad| quad.graph.clone())
            .collect::<BTreeSet<_>>();
        let readback_bundle = source_quads_from_sparql(&first.2, &ontology_graphs);
        assert_eq!(
            readback_bundle.len(),
            bundle.len(),
            "{scope} ontology count"
        );
        let readback_root = quad_root(&readback_bundle);
        // Intentional POC limitation: the source-exact root remains in the
        // executable manifest, while replay blesses and binds this complete
        // Fluree storage projection even when exact term spellings differ.
        assert_eq!(readback_bundle.len(), bundle.len(), "{scope}");
        assert_ne!(
            readback_root, full_bundle_root,
            "{scope} exercises the POC storage-projection caveat"
        );
        let first_prepared = official_preparation_fingerprint(directory.path(), &receipt).await;
        verify_read_only_reopen(directory.path(), &receipt)
            .await
            .unwrap();
        let second = official_readback_fingerprint(directory.path(), ledger).await;
        let second_prepared = official_preparation_fingerprint(directory.path(), &receipt).await;
        verify_official_recording_replay(directory.path(), &receipt).await;
        assert_eq!(first_prepared, second_prepared, "{scope} prepared roots");
        assert_eq!(
            first_prepared.4, readback_root,
            "{scope} stored bundle root"
        );
        assert_eq!(first.0, second.0, "{scope} readback root");
        assert_eq!(first.1, second.1, "{scope} readback count");
        // Fluree deliberately omits its system configuration graph from a
        // variable GRAPH scan. The ontology plus the three POC support-graph
        // statements are visible and stable; activation is checked through the
        // dedicated historical configuration resolver.
        assert_eq!(first.1, receipt.ontology_quad_count + 3, "{scope}");
        assert!(first.1 < receipt.transaction_quad_count, "{scope}");
        receipts.push(OfficialLoadReceipt {
            scope: scope.into(),
            ledger: receipt.ledger,
            t: receipt.t,
            cid: receipt.cid,
            full_bundle_root: full_bundle_root.as_str().into(),
            executable_profile_root: executable_profile_root.as_str().into(),
            ontology_quad_count: receipt.ontology_quad_count,
            transaction_quad_count: receipt.transaction_quad_count,
            transaction_bytes: receipt.transaction_bytes,
            structural_node_count: receipt.structural_node_count,
            structural_mapping_root: receipt.structural_mapping_root.as_str().into(),
            visible_graph_readback_root: first.0.as_str().into(),
            stored_bundle_root: readback_root.as_str().into(),
            stored_c0_root: first_prepared.5.as_str().into(),
            execution_manifest_root: first_prepared.0.as_str().into(),
            prepared_root: first_prepared.1.as_str().into(),
            diagnostics_root: first_prepared.2.as_str().into(),
            inferred_fact_count: first_prepared.3,
            double_read_only_reopen_equal: true,
            poc_storage_projection_blindly_blessed: true,
            final_profile_identity: PROFILE,
            final_result_label: ONTOLOGY_PROFILE_V3_RESULT_LABEL,
            scope_authority_root: manifest.input().scope_authority_root.as_str().into(),
            acquisition_authority_root: manifest.input().acquisition_authority_root.as_str().into(),
            selected_source_release_id: manifest.input().selected_source_release_id.clone(),
            selected_source_file_id: manifest.input().selected_source_file_id.clone(),
            selected_ontology_iri: manifest.input().selected_ontology_iri.clone(),
            source_member_root: manifest.input().source_member_root.as_str().into(),
            source_closure_root: manifest.input().source_closure_root.as_str().into(),
            dependency_universe_root: manifest.input().dependency_universe_root.as_str().into(),
            dependency_limits_identity: manifest.input().dependency_limits_identity.as_str().into(),
            source_occurrence_root: manifest.input().source_occurrence_root.as_str().into(),
            reasoned_family_inventory_root: manifest
                .input()
                .reasoned_family_inventory_root
                .as_str()
                .into(),
            declaration_evidence_root: manifest.input().declaration_evidence_root.as_str().into(),
            uninterpreted_non_interference_root: manifest
                .input()
                .uninterpreted_non_interference_root
                .as_str()
                .into(),
            parity_matrix_root: manifest.input().parity_matrix_root.as_str().into(),
            final_semantic_coverage_root: final_semantic_coverage_root.as_str().into(),
            final_result_root: final_result_root.as_str().into(),
        });
    }

    if let Ok(path) = std::env::var("CTXQL_P5_7_LOAD_RECEIPTS") {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        serde_json::to_writer_pretty(&mut output, &receipts).unwrap();
        output.write_all(b"\n").unwrap();
    }
}
