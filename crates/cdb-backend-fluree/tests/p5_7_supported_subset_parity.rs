use cdb_backend_fluree::{
    authorized_view::SourceQuad,
    ontology_construct_audit::{
        audit_ontology_closure, build_audited_closure_from_conversions, ConstructAuditLimits,
    },
    ontology_conversion::{convert_rdfxml, ConversionLimits, ConversionRequest},
    ontology_dependency_universe::ConversionPin,
    ontology_profile_v3::{
        classify_ontology_closure_v3_supported_subset, uninterpreted_family_ids,
        OntologyMemberCategory, OntologyProfileV3Limits, OntologyProfileV3Result,
        ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID, RELATIONS_SCOPE,
    },
};
use cdb_core::id::ContentHash;
use fluree_db_api::{FlureeBuilder, LedgerState, Novelty};
use fluree_db_core::{FlakeValue, GraphDbRef, LedgerSnapshot};
use fluree_db_reasoner::{
    reason_owl2rl, ReasoningBudget, ReasoningCache, ReasoningOptions, ReasoningResult,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

const EX: &str = "http://example.org/";

type IriTriple = (String, String, String);

fn genesis(id: &str) -> LedgerState {
    LedgerState::new(LedgerSnapshot::genesis(id), Novelty::new(0))
}

async fn reason_fixture(
    id: &str,
    component: &str,
) -> (LedgerState, std::sync::Arc<ReasoningResult>) {
    let turtle = format!(
        r#"
@prefix ex: <{EX}> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
ex:Employee rdfs:subClassOf ex:Person .
ex:parent owl:inverseOf ex:child .
ex:alice a ex:Employee ; ex:parent ex:bob .
{component}
"#
    );
    let ledger = FlureeBuilder::memory()
        .build_memory()
        .stage_owned(genesis(id))
        .upsert_turtle(&turtle)
        .execute()
        .await
        .expect("parity fixture must load")
        .ledger;
    let result = reason_owl2rl(
        GraphDbRef::new(&ledger.snapshot, 0, ledger.novelty.as_ref(), ledger.t()),
        &ReasoningOptions::with_budget(ReasoningBudget::unlimited()),
        &ReasoningCache::new(1),
    )
    .await
    .expect("pinned reasoner must accept retained component");
    (ledger, result)
}

async fn reason_quads(
    id: &str,
    quads: &BTreeSet<SourceQuad>,
) -> (LedgerState, std::sync::Arc<ReasoningResult>) {
    let turtle = quads
        .iter()
        .map(SourceQuad::turtle)
        .collect::<Vec<_>>()
        .join("\n");
    let ledger = FlureeBuilder::memory()
        .build_memory()
        .stage_owned(genesis(id))
        .upsert_turtle(&turtle)
        .execute()
        .await
        .expect("official parity fixture must load")
        .ledger;
    let result = reason_owl2rl(
        GraphDbRef::new(&ledger.snapshot, 0, ledger.novelty.as_ref(), ledger.t()),
        &ReasoningOptions::with_budget(ReasoningBudget::unlimited()),
        &ReasoningCache::new(1),
    )
    .await
    .expect("pinned reasoner must accept official profile input");
    (ledger, result)
}

fn inferred_iri_triples(ledger: &LedgerState, result: &ReasoningResult) -> BTreeSet<IriTriple> {
    result
        .overlay
        .flakes_spot()
        .iter()
        .filter_map(|flake| {
            let FlakeValue::Ref(object) = &flake.o else {
                return None;
            };
            let subject = ledger.snapshot.decode_sid(&flake.s)?;
            let predicate = ledger.snapshot.decode_sid(&flake.p)?;
            let object = ledger.snapshot.decode_sid(object)?;
            if subject.starts_with("_:") || object.starts_with("_:") {
                return None;
            }
            Some((subject, predicate, object))
        })
        .collect()
}

fn normalized_diagnostics(
    result: &ReasoningResult,
) -> (usize, bool, Option<String>, BTreeMap<String, usize>) {
    (
        result.diagnostics.facts_derived,
        result.diagnostics.capped,
        result.diagnostics.capped_reason.clone(),
        result
            .diagnostics
            .rules_fired
            .iter()
            .map(|(rule, count)| (rule.clone(), *count))
            .collect(),
    )
}

fn family_components() -> Vec<(&'static str, &'static str)> {
    vec![
        ("unqualified-min-cardinality-zero/v1", "ex:C rdfs:subClassOf [ a owl:Restriction ; owl:onProperty ex:p ; owl:minCardinality \"0\"^^xsd:nonNegativeInteger ] ."),
        ("qualified-min-cardinality-class-zero/v1", "ex:C rdfs:subClassOf [ a owl:Restriction ; owl:onProperty ex:p ; owl:minQualifiedCardinality \"0\"^^xsd:nonNegativeInteger ; owl:onClass ex:D ] ."),
        ("qualified-min-cardinality-class-two/v1", "ex:C rdfs:subClassOf [ a owl:Restriction ; owl:onProperty ex:p ; owl:minQualifiedCardinality \"2\"^^xsd:nonNegativeInteger ; owl:onClass ex:D ] ."),
        ("qualified-min-cardinality-class-three/v1", "ex:C rdfs:subClassOf [ a owl:Restriction ; owl:onProperty ex:p ; owl:minQualifiedCardinality \"3\"^^xsd:nonNegativeInteger ; owl:onClass ex:D ] ."),
        ("qualified-min-cardinality-data-zero/v1", "ex:C rdfs:subClassOf [ a owl:Restriction ; owl:onProperty ex:p ; owl:minQualifiedCardinality \"0\"^^xsd:nonNegativeInteger ; owl:onDataRange xsd:string ] ."),
        ("qualified-exact-cardinality-class-one/v1", "ex:C rdfs:subClassOf [ a owl:Restriction ; owl:onProperty ex:p ; owl:qualifiedCardinality \"1\"^^xsd:nonNegativeInteger ; owl:onClass ex:D ] ."),
        ("qualified-exact-cardinality-class-two/v1", "ex:C rdfs:subClassOf [ a owl:Restriction ; owl:onProperty ex:p ; owl:qualifiedCardinality \"2\"^^xsd:nonNegativeInteger ; owl:onClass ex:D ] ."),
        ("qualified-exact-cardinality-data-one/v1", "ex:C rdfs:subClassOf [ a owl:Restriction ; owl:onProperty ex:p ; owl:qualifiedCardinality \"1\"^^xsd:nonNegativeInteger ; owl:onDataRange xsd:string ] ."),
        ("qualified-max-cardinality-data-one/v1", "ex:C rdfs:subClassOf [ a owl:Restriction ; owl:onProperty ex:p ; owl:maxQualifiedCardinality \"1\"^^xsd:nonNegativeInteger ; owl:onDataRange xsd:string ] ."),
        ("datatype-standalone-declaration/v1", "ex:Code a rdfs:Datatype ."),
        ("datatype-union-expression/v1", "ex:Code a rdfs:Datatype ; owl:equivalentClass [ a rdfs:Datatype ; owl:unionOf ( xsd:string xsd:anyURI ) ] ."),
        ("datatype-decimal-inclusive-facets/v1", "ex:p rdfs:range [ a rdfs:Datatype ; owl:onDatatype xsd:decimal ; owl:withRestrictions ( [ xsd:minInclusive \"0\"^^xsd:decimal ] [ xsd:maxInclusive \"10\"^^xsd:decimal ] ) ] ."),
        ("class-disjointness-edge/v1", "ex:C owl:disjointWith ex:D ."),
        ("property-disjointness-edge/v1", "ex:p owl:propertyDisjointWith ex:q ."),
    ]
}

#[tokio::test]
async fn every_registered_family_is_directly_inference_inert() {
    let registered = uninterpreted_family_ids()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let fixtures = family_components();
    assert_eq!(
        fixtures
            .iter()
            .map(|(family, _)| *family)
            .collect::<BTreeSet<_>>(),
        registered
    );
    let (baseline_ledger, baseline) = reason_fixture("ctxql/p5-7-parity-baseline:main", "").await;
    let baseline_facts = inferred_iri_triples(&baseline_ledger, &baseline);
    let baseline_diagnostics = normalized_diagnostics(&baseline);
    for (index, (family, component)) in fixtures.into_iter().enumerate() {
        let (ledger, result) =
            reason_fixture(&format!("ctxql/p5-7-parity-{index}:main"), component).await;
        assert_eq!(
            inferred_iri_triples(&ledger, &result),
            baseline_facts,
            "{family} changed supported inferred facts"
        );
        assert_eq!(
            normalized_diagnostics(&result),
            baseline_diagnostics,
            "{family} changed normalized diagnostics"
        );
    }
}

fn rdf(body: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
 xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"
 xmlns:owl="http://www.w3.org/2002/07/owl#" xmlns:ex="urn:test:">
 <owl:Ontology rdf:about="urn:test:ontology"><owl:versionIRI rdf:resource="urn:test:ontology/v1"/></owl:Ontology>
 {body}
</rdf:RDF>"#
    )
    .into_bytes()
}

#[test]
fn tiny_synthetic_closure_cannot_claim_official_scope_authority() {
    use cdb_backend_fluree::ontology_profile_v3::{
        TrustedAcquisitionAuthorityV3, TrustedOntologyScopeAuthorityV3,
        TrustedOntologySourceMemberV3, ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH,
    };
    let bytes = rdf(r#"<owl:Class rdf:about="urn:test:C"/>"#);
    let conversion = convert_rdfxml(ConversionRequest {
        authoritative_bytes: &bytes,
        source_release_id:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        source_file_id: "certification.rdf",
        base_iri: "urn:test:ontology",
        graph_iri: "urn:test:graph",
        limits: ConversionLimits::default(),
    })
    .unwrap();
    let pin = ConversionPin::from_result(&conversion, &bytes).unwrap();
    let closure =
        build_audited_closure_from_conversions(vec![("urn:test:ontology".into(), pin, conversion)])
            .unwrap();
    let audit = audit_ontology_closure(&closure, ConstructAuditLimits::default()).unwrap();
    let error = TrustedOntologyScopeAuthorityV3::verify(
        RELATIONS_SCOPE.into(),
        "sha256:203a6a9d6e7a5d7ee855f299ad99a11ca5f1ac1d5e61f0ff293619d1526f13b2".into(),
        "fibo/FND/Relations/Relations.rdf".into(),
        "https://spec.edmcouncil.org/fibo/ontology/FND/Relations/Relations/".into(),
        TrustedAcquisitionAuthorityV3::from_canonical_bytes(include_bytes!(
            "../../../fixtures/conformance/p5_7/official-relations-closure.json"
        ))
        .unwrap(),
        ContentHash::of_bytes(b"candidate-scoped-dependency-limits-v2"),
        vec![TrustedOntologySourceMemberV3 {
            source_release_id:
                "sha256:203a6a9d6e7a5d7ee855f299ad99a11ca5f1ac1d5e61f0ff293619d1526f13b2".into(),
            source_file_id: "fibo/FND/Relations/Relations.rdf".into(),
            ontology_iri: "https://spec.edmcouncil.org/fibo/ontology/FND/Relations/Relations/"
                .into(),
            authoritative_hash: ContentHash::of_bytes(b"official authoritative bytes"),
            conversion_root: ContentHash::of_bytes(b"official conversion"),
            graph: "https://spec.edmcouncil.org/fibo/ontology/FND/Relations/Relations/".into(),
            graph_root: ContentHash::of_bytes(b"official graph"),
        }],
        &closure,
        &audit,
    )
    .unwrap_err();
    assert_eq!(error.public_code, ONTOLOGY_SEMANTIC_COVERAGE_MISMATCH);
    assert_eq!(error.reason, "scope_authority_members_mismatch");
}

#[derive(Deserialize)]
struct ApplicabilityMatrix {
    schema: String,
    profile: String,
    fluree_revision: String,
    rows: Vec<ApplicabilityRow>,
}

#[derive(Deserialize)]
struct ApplicabilityRow {
    family: String,
    interaction: String,
    direct_with_without: bool,
    sealed_required: bool,
}

#[test]
fn applicability_matrix_is_closed_over_every_registered_family() {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_7/parity-applicability-matrix.json"
    ))
    .unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_7/parity-applicability-matrix.schema.json"
    ))
    .unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["schema"]["const"],
        "ctxql.p5-7-parity-applicability-matrix/v1"
    );
    assert_eq!(schema["properties"]["rows"]["minItems"], 14);
    assert_eq!(schema["properties"]["rows"]["maxItems"], 14);
    let matrix: ApplicabilityMatrix = serde_json::from_value(value).unwrap();
    assert_eq!(matrix.schema, "ctxql.p5-7-parity-applicability-matrix/v1");
    assert_eq!(matrix.profile, ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID);
    assert_eq!(
        matrix.fluree_revision,
        "603974fad5c13efed9d147d214d613849fb43c73"
    );
    assert_eq!(matrix.rows.len(), 14);
    assert_eq!(
        matrix
            .rows
            .iter()
            .map(|row| row.family.as_str())
            .collect::<BTreeSet<_>>(),
        uninterpreted_family_ids()
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    assert!(matrix.rows.iter().all(|row| {
        !row.interaction.is_empty() && row.direct_with_without && row.sealed_required
    }));
}

#[derive(Deserialize)]
struct OfficialClosure {
    files: Vec<OfficialFile>,
}

#[derive(Deserialize)]
struct OfficialFile {
    path: String,
    bytes: usize,
    sha256: String,
}

fn official_identity(file: &OfficialFile) -> (&'static str, String, String) {
    if let Some(name) = file
        .path
        .strip_prefix("commons/")
        .and_then(|path| path.strip_suffix(".rdf"))
    {
        (
            "sha256:07f8a4aba315edd5eb3373b406ea0b9bc48d1bd9d12c142206972f91b79785bb",
            format!("https://www.omg.org/spec/Commons/20250801/{name}.rdf"),
            format!("https://www.omg.org/spec/Commons/{name}/"),
        )
    } else {
        let relative = file.path.strip_prefix("fibo/").unwrap();
        let ontology = relative.strip_suffix(".rdf").unwrap();
        (
            "sha256:203a6a9d6e7a5d7ee855f299ad99a11ca5f1ac1d5e61f0ff293619d1526f13b2",
            format!("https://spec.edmcouncil.org/fibo/ontology/master/2026Q2/{relative}"),
            format!("https://spec.edmcouncil.org/fibo/ontology/{ontology}/"),
        )
    }
}

fn official_analysis(root: &Path, manifest: &str) -> OntologyProfileV3Result {
    let manifest: OfficialClosure = serde_json::from_str(manifest).unwrap();
    let mut conversions = Vec::new();
    for file in &manifest.files {
        let bytes = fs::read(root.join(&file.path)).unwrap();
        assert_eq!(bytes.len(), file.bytes);
        assert_eq!(&ContentHash::of_bytes(&bytes).as_str()[7..], file.sha256);
        let (release, base, graph) = official_identity(file);
        let conversion = convert_rdfxml(ConversionRequest {
            authoritative_bytes: &bytes,
            source_release_id: release,
            source_file_id: &file.path,
            base_iri: &base,
            graph_iri: &graph,
            limits: ConversionLimits {
                max_input_bytes: 128 * 1024 * 1024,
                max_input_triples: 1_000_000,
                max_output_bytes: 256 * 1024 * 1024,
                max_blank_nodes: 200_000,
                max_canonicalization_work: 50_000_000,
            },
        })
        .unwrap();
        let pin = ConversionPin::from_result(&conversion, &bytes).unwrap();
        conversions.push((graph, pin, conversion));
    }
    let closure = build_audited_closure_from_conversions(conversions).unwrap();
    let audit = audit_ontology_closure(
        &closure,
        ConstructAuditLimits {
            max_bundle_quads: 500_000,
            max_source_occurrences: 1_000_000,
            max_structural_work: 50_000_000,
            max_issues: 500_000,
            max_serialized_output_bytes: 256 * 1024 * 1024,
            ..ConstructAuditLimits::default()
        },
    )
    .unwrap();
    classify_ontology_closure_v3_supported_subset(
        &closure,
        &audit,
        OntologyProfileV3Limits::default(),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "requires exact external Relations and Agreements ontology caches"]
async fn complete_official_scopes_are_directly_inference_inert() {
    let cases = [
        (
            "relations",
            std::env::var("CTXQL_P6_REFERENCE_CACHE").unwrap(),
            include_str!("../../../fixtures/conformance/p5_7/official-relations-closure.json"),
        ),
        (
            "agreements",
            std::env::var("CTXQL_P5_7_AGREEMENTS_CACHE").unwrap(),
            include_str!("../../../fixtures/conformance/p5_7/official-agreements-closure.json"),
        ),
    ];
    for (scope, root, manifest) in cases {
        let analysis = official_analysis(Path::new(&root), manifest);
        let baseline = analysis.categories[&OntologyMemberCategory::Reasoned]
            .union(&analysis.categories[&OntologyMemberCategory::InferenceInertDeclaration])
            .cloned()
            .collect::<BTreeSet<_>>();
        let (full_ledger, full) = reason_quads(
            &format!("ctxql/p5-7-{scope}-full:main"),
            &analysis.ontology_c0_input,
        )
        .await;
        let (baseline_ledger, absent) =
            reason_quads(&format!("ctxql/p5-7-{scope}-absent:main"), &baseline).await;
        assert_eq!(
            inferred_iri_triples(&full_ledger, &full),
            inferred_iri_triples(&baseline_ledger, &absent),
            "{scope} uninterpreted components changed supported inferred facts"
        );
        // Official normalization omits internal blank-node rule counters: retaining
        // a component intentionally makes Fluree visit its structural subclass
        // edges, while the public IRI-only supported fact set above must remain
        // identical. Capped state and the count of public inferred facts remain
        // stable and are the externally meaningful diagnostic projection.
        assert_eq!(
            (
                inferred_iri_triples(&full_ledger, &full).len(),
                full.diagnostics.capped,
                full.diagnostics.capped_reason.clone(),
            ),
            (
                inferred_iri_triples(&baseline_ledger, &absent).len(),
                absent.diagnostics.capped,
                absent.diagnostics.capped_reason.clone(),
            ),
            "{scope} uninterpreted components changed normalized public diagnostics"
        );
    }
}
