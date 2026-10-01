use cdb_backend_fluree::{
    ontology_construct_audit::{
        audit_ontology_closure, build_audited_closure_from_conversions, ConstructAuditLimits,
    },
    ontology_conversion::{convert_rdfxml, ConversionLimits, ConversionRequest},
    ontology_dependency_universe::ConversionPin,
    ontology_profile_v2::{classify_ontology_bundle_v2, OntologyProfileLimits},
    ontology_profile_v3::{
        classify_ontology_closure_v3_supported_subset, semantic_caveats, uninterpreted_families,
        uninterpreted_family_ids, OntologyMemberCategory, OntologyProfileV3Limits,
        ONTOLOGY_PROFILE_V3_ANALYSIS_ID, ONTOLOGY_PROFILE_V3_ANALYSIS_LABEL,
        ONTOLOGY_PROFILE_V3_SUPERSEDED_ID, ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID,
        ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED, ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED,
    },
};
use cdb_core::id::ContentHash;
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeSet, fs, io::Write, path::Path};

fn rdf(body: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
 xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"
 xmlns:owl="http://www.w3.org/2002/07/owl#"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema#"
 xmlns:skos="http://www.w3.org/2004/02/skos/core#"
 xmlns:dct="http://purl.org/dc/terms/"
 xmlns:ex="urn:test:">
 <owl:Ontology rdf:about="urn:test:ontology">
  <owl:versionIRI rdf:resource="urn:test:ontology/v1"/>
 </owl:Ontology>
 {body}
</rdf:RDF>"#
    )
    .into_bytes()
}

fn audited(
    body: &str,
) -> (
    cdb_backend_fluree::ontology_construct_audit::AuditedOntologyClosure,
    cdb_backend_fluree::ontology_construct_audit::ConstructAuditResult,
) {
    let bytes = rdf(body);
    let conversion = convert_rdfxml(ConversionRequest {
        authoritative_bytes: &bytes,
        source_release_id:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        source_file_id: "synthetic.rdf",
        base_iri: "urn:test:ontology",
        graph_iri: "urn:test:graph",
        limits: ConversionLimits::default(),
    })
    .unwrap();
    let pin = ConversionPin::from_result(&conversion, &bytes).unwrap();
    let closure = build_audited_closure_from_conversions(vec![(
        "urn:test:ontology".to_owned(),
        pin,
        conversion,
    )])
    .unwrap();
    let audit = audit_ontology_closure(
        &closure,
        ConstructAuditLimits {
            max_bundle_quads: 10_000,
            max_source_occurrences: 10_000,
            max_structural_work: 1_000_000,
            max_issues: 10_000,
            max_serialized_output_bytes: 16 * 1024 * 1024,
            ..ConstructAuditLimits::default()
        },
    )
    .unwrap();
    (closure, audit)
}

fn classify(body: &str) -> cdb_backend_fluree::ontology_profile_v3::OntologyProfileV3Result {
    let (closure, audit) = audited(body);
    classify_ontology_closure_v3_supported_subset(
        &closure,
        &audit,
        OntologyProfileV3Limits::default(),
    )
    .unwrap()
}

#[test]
fn exact_identity_four_categories_and_component_helpers_are_committed() {
    let result = classify(
        r#"
<owl:Class rdf:about="urn:test:C">
 <rdfs:subClassOf>
  <owl:Restriction>
   <owl:onProperty rdf:resource="urn:test:p"/>
   <owl:minCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">0</owl:minCardinality>
  </owl:Restriction>
 </rdfs:subClassOf>
 <skos:definition>class C</skos:definition>
</owl:Class>
<owl:Class rdf:about="urn:test:D"><rdfs:subClassOf rdf:resource="urn:test:C"/></owl:Class>
<owl:NamedIndividual rdf:about="urn:test:i"/>
"#,
    );
    assert_eq!(result.identity, ONTOLOGY_PROFILE_V3_ANALYSIS_ID);
    assert_ne!(result.identity, ONTOLOGY_PROFILE_V3_SUPPORTED_SUBSET_ID);
    assert_ne!(result.identity, ONTOLOGY_PROFILE_V3_SUPERSEDED_ID);
    assert_eq!(result.result_label, ONTOLOGY_PROFILE_V3_ANALYSIS_LABEL);
    assert_eq!(result.components.len(), 1);
    assert_eq!(
        result.components[0].family_id,
        "unqualified-min-cardinality-zero/v1"
    );
    assert_eq!(result.components[0].quads.len(), 4);
    assert!(result.components[0]
        .quads
        .iter()
        .any(|quad| quad.predicate.ends_with("subClassOf")));
    assert!(result.components[0]
        .quads
        .iter()
        .any(|quad| quad.predicate.ends_with("onProperty")));
    assert_eq!(
        result.category_counts.values().sum::<usize>(),
        result.full_bundle.len()
    );
    assert_eq!(
        result.categories[&OntologyMemberCategory::InferenceInertDeclaration].len(),
        1
    );
    assert_eq!(
        result.categories[&OntologyMemberCategory::RetainedAnnotation]
            .iter()
            .filter(|quad| quad.predicate.ends_with("definition"))
            .count(),
        1
    );
    assert!(result
        .ontology_c0_input
        .is_disjoint(&result.categories[&OntologyMemberCategory::RetainedAnnotation]));
    for category in [
        OntologyMemberCategory::Reasoned,
        OntologyMemberCategory::InferenceInertDeclaration,
        OntologyMemberCategory::RetainedUninterpretedSemantic,
    ] {
        assert!(result.categories[&category].is_subset(&result.ontology_c0_input));
    }
}

#[test]
fn exact_annotation_shapes_are_retained_but_wrong_shapes_fail_closed() {
    let accepted = classify(
        r#"
<owl:Class rdf:about="urn:test:C">
 <dct:source rdf:datatype="http://www.w3.org/2001/XMLSchema#anyURI">https://example.test/source</dct:source>
 <skos:definition xml:lang="en">definition</skos:definition>
 <skos:note>note</skos:note>
 <rdfs:seeAlso rdf:datatype="http://www.w3.org/2001/XMLSchema#anyURI">https://example.test/more</rdfs:seeAlso>
</owl:Class>
"#,
    );
    let annotations = &accepted.categories[&OntologyMemberCategory::RetainedAnnotation];
    assert_eq!(
        annotations
            .iter()
            .filter(|quad| quad.predicate.ends_with("source"))
            .count(),
        1
    );
    assert_eq!(
        annotations
            .iter()
            .filter(|quad| quad.predicate.ends_with("definition"))
            .count(),
        1
    );
    assert_eq!(
        annotations
            .iter()
            .filter(|quad| quad.predicate.ends_with("note"))
            .count(),
        1
    );
    assert_eq!(
        annotations
            .iter()
            .filter(|quad| quad.predicate.ends_with("seeAlso"))
            .count(),
        1
    );

    let newly_admitted = classify(
        r#"
<owl:Class rdf:about="urn:test:metadata">
 <dct:abstract>abstract</dct:abstract>
 <dct:contributor>contributor</dct:contributor>
 <dct:issued rdf:datatype="http://www.w3.org/2001/XMLSchema#dateTime">2026-06-01T00:00:00Z</dct:issued>
 <dct:license>license text</dct:license>
 <dct:license rdf:datatype="http://www.w3.org/2001/XMLSchema#anyURI">https://example.test/license</dct:license>
 <dct:modified rdf:datatype="http://www.w3.org/2001/XMLSchema#dateTime">2026-06-02T00:00:00Z</dct:modified>
 <dct:references rdf:resource="https://example.test/reference"/>
 <dct:title>title</dct:title>
 <skos:changeNote>change</skos:changeNote>
 <skos:example>example</skos:example>
 <skos:prefLabel>preferred</skos:prefLabel>
 <skos:scopeNote>scope</skos:scopeNote>
</owl:Class>
"#,
    );
    let newly_admitted_annotations =
        &newly_admitted.categories[&OntologyMemberCategory::RetainedAnnotation];
    assert_eq!(
        newly_admitted_annotations
            .iter()
            .filter(|quad| {
                quad.predicate.starts_with("http://purl.org/dc/terms/")
                    || quad
                        .predicate
                        .starts_with("http://www.w3.org/2004/02/skos/core#")
            })
            .count(),
        12
    );

    for (body, reason) in [
        (
            r#"<owl:Class rdf:about="urn:test:C"><skos:definition rdf:datatype="http://www.w3.org/2001/XMLSchema#integer">7</skos:definition></owl:Class>"#,
            "annotation_shape_unregistered",
        ),
        (
            r#"<owl:Class rdf:about="urn:test:C"><skos:scopeNote xml:lang="en">wrong language form</skos:scopeNote></owl:Class>"#,
            "annotation_shape_unregistered",
        ),
        (
            r#"<owl:Class rdf:about="urn:test:C"><dct:references>wrong literal form</dct:references></owl:Class>"#,
            "annotation_shape_unregistered",
        ),
        (
            r#"<owl:Class rdf:about="urn:test:C"><dct:issued rdf:datatype="http://www.w3.org/2001/XMLSchema#date">2026-06-01</dct:issued></owl:Class>"#,
            "annotation_shape_unregistered",
        ),
        (
            r#"<owl:Class rdf:about="urn:test:C"><skos:altLabel>not registered</skos:altLabel></owl:Class>"#,
            "annotation_predicate_unregistered",
        ),
        (
            r#"<owl:Class><skos:scopeNote>blank subject</skos:scopeNote></owl:Class>"#,
            "construct_audit_contains_invalid_structure",
        ),
    ] {
        let (closure, audit) = audited(body);
        let error = classify_ontology_closure_v3_supported_subset(
            &closure,
            &audit,
            OntologyProfileV3Limits::default(),
        )
        .unwrap_err();
        assert_eq!(
            error.public_code,
            ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED
        );
        assert_eq!(error.reason, reason);
    }
}

#[test]
fn registered_data_range_and_disjointness_shapes_are_atomic() {
    let result = classify(
        r#"
<owl:Class rdf:about="urn:test:C">
 <rdfs:subClassOf>
  <owl:Restriction>
   <owl:onProperty rdf:resource="urn:test:p"/>
   <owl:maxQualifiedCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">1</owl:maxQualifiedCardinality>
   <owl:onDataRange rdf:resource="http://www.w3.org/2001/XMLSchema#string"/>
  </owl:Restriction>
 </rdfs:subClassOf>
 <owl:disjointWith rdf:resource="urn:test:D"/>
</owl:Class>
<owl:ObjectProperty rdf:about="urn:test:p"><owl:propertyDisjointWith rdf:resource="urn:test:q"/></owl:ObjectProperty>
"#,
    );
    let families = result
        .components
        .iter()
        .map(|component| component.family_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        families,
        BTreeSet::from([
            "qualified-max-cardinality-data-one/v1",
            "class-disjointness-edge/v1",
            "property-disjointness-edge/v1",
        ])
    );
}

#[test]
fn agreements_cardinality_shapes_are_exact_registered_families() {
    let result = classify(
        r#"
<owl:Class rdf:about="urn:test:min-two"><rdfs:subClassOf><owl:Restriction>
 <owl:onProperty rdf:resource="urn:test:p"/>
 <owl:minQualifiedCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">2</owl:minQualifiedCardinality>
 <owl:onClass rdf:resource="urn:test:PartyRole"/>
</owl:Restriction></rdfs:subClassOf></owl:Class>
<owl:Class rdf:about="urn:test:min-three"><rdfs:subClassOf><owl:Restriction>
 <owl:onProperty rdf:resource="urn:test:p"/>
 <owl:minQualifiedCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">3</owl:minQualifiedCardinality>
 <owl:onClass rdf:resource="urn:test:PartyRole"/>
</owl:Restriction></rdfs:subClassOf></owl:Class>
<owl:Class rdf:about="urn:test:exact-two"><rdfs:subClassOf><owl:Restriction>
 <owl:onProperty rdf:resource="urn:test:p"/>
 <owl:qualifiedCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">2</owl:qualifiedCardinality>
 <owl:onClass rdf:resource="urn:test:PartyRole"/>
</owl:Restriction></rdfs:subClassOf></owl:Class>
<owl:Class rdf:about="urn:test:nested"><rdfs:subClassOf><owl:Restriction>
 <owl:onProperty rdf:resource="urn:test:outer"/>
 <owl:someValuesFrom><owl:Restriction>
  <owl:onProperty rdf:resource="urn:test:inner"/>
  <owl:minQualifiedCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">0</owl:minQualifiedCardinality>
  <owl:onClass rdf:resource="urn:test:Agreement"/>
 </owl:Restriction></owl:someValuesFrom>
</owl:Restriction></rdfs:subClassOf></owl:Class>
"#,
    );
    assert_eq!(
        result
            .components
            .iter()
            .map(|component| component.family_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "qualified-min-cardinality-class-two/v1",
            "qualified-min-cardinality-class-three/v1",
            "qualified-exact-cardinality-class-two/v1",
            "qualified-min-cardinality-class-zero/v1",
        ])
    );

    let (closure, audit) = audited(
        r#"<owl:Class rdf:about="urn:test:C"><rdfs:subClassOf><owl:Restriction>
 <owl:onProperty rdf:resource="urn:test:p"/>
 <owl:minQualifiedCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">4</owl:minQualifiedCardinality>
 <owl:onClass rdf:resource="urn:test:PartyRole"/>
</owl:Restriction></rdfs:subClassOf></owl:Class>"#,
    );
    let error = classify_ontology_closure_v3_supported_subset(
        &closure,
        &audit,
        OntologyProfileV3Limits::default(),
    )
    .unwrap_err();
    assert_eq!(
        error.public_code,
        ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED
    );
    assert_eq!(error.reason, "restriction_shape_unregistered");
}

#[test]
fn audit_and_shape_substitution_fail_closed() {
    let (closure, mut audit) = audited(
        r#"<owl:Class rdf:about="urn:test:C"><rdfs:subClassOf rdf:resource="urn:test:D"/></owl:Class>"#,
    );
    let original = classify_ontology_closure_v3_supported_subset(
        &closure,
        &audit,
        OntologyProfileV3Limits::default(),
    )
    .unwrap();
    assert!(original.verify_integrity(&closure, &audit, OntologyProfileV3Limits::default()));
    let mut substituted_result = original.clone();
    substituted_result.semantic_coverage_root = ContentHash::of_bytes(b"substituted-coverage");
    assert!(!substituted_result.verify_integrity(
        &closure,
        &audit,
        OntologyProfileV3Limits::default()
    ));

    audit.construct_audit_root = ContentHash::of_bytes(b"substituted");
    let error = classify_ontology_closure_v3_supported_subset(
        &closure,
        &audit,
        OntologyProfileV3Limits::default(),
    )
    .unwrap_err();
    assert_eq!(error.public_code, ONTOLOGY_UNINTERPRETED_SEMANTICS_CHANGED);

    let (closure, audit) = audited(
        r#"
<owl:Class rdf:about="urn:test:C"><rdfs:subClassOf><owl:Restriction>
 <owl:onProperty rdf:resource="urn:test:p"/>
 <owl:minCardinality rdf:datatype="http://www.w3.org/2001/XMLSchema#nonNegativeInteger">1</owl:minCardinality>
</owl:Restriction></rdfs:subClassOf></owl:Class>
"#,
    );
    let error = classify_ontology_closure_v3_supported_subset(
        &closure,
        &audit,
        OntologyProfileV3Limits::default(),
    )
    .unwrap_err();
    assert_eq!(
        error.public_code,
        ONTOLOGY_UNINTERPRETED_SEMANTICS_UNREGISTERED
    );
    assert_eq!(error.reason, "restriction_shape_unregistered");
}

#[test]
fn caveats_and_registry_are_closed_and_ordered() {
    assert_eq!(semantic_caveats().len(), 8);
    assert_eq!(
        semantic_caveats()
            .iter()
            .map(|caveat| caveat.code)
            .collect::<Vec<_>>(),
        vec![
            "minimum_exact_cardinalities_not_enforced",
            "data_range_datatype_facets_not_enforced",
            "disjointness_violations_not_detected",
            "uninterpreted_axioms_excluded_from_admission",
            "answers_may_be_incomplete",
            "no_fibo_compliance_inference",
            "poc_revision_profile_specific",
            "fluree_storage_projection_blindly_blessed",
        ]
    );
    let families = uninterpreted_family_ids();
    assert_eq!(families.len(), 14);
    assert_eq!(families.iter().copied().collect::<BTreeSet<_>>().len(), 14);
}

#[test]
fn checked_in_policy_fixtures_match_the_implemented_closed_sets() {
    let registry: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_7/uninterpreted-semantics-registry.json"
    ))
    .unwrap();
    let implemented = uninterpreted_families()
        .iter()
        .map(|family| (family.id, family.shape))
        .collect::<Vec<_>>();
    let fixture = registry["families"]
        .as_array()
        .unwrap()
        .iter()
        .map(|family| {
            (
                family["id"].as_str().unwrap(),
                family["shape"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(fixture, implemented);

    let annotations: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_7/retained-annotation-policy.json"
    ))
    .unwrap();
    let caveats: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_7/caveat-set.json"
    ))
    .unwrap();
    let result = classify(r#"<owl:Class rdf:about="urn:test:C"/>"#);
    assert_eq!(
        registry["registry_root"].as_str().unwrap(),
        result.registry_root.as_str()
    );
    assert_eq!(
        annotations["annotation_policy_root"].as_str().unwrap(),
        result.annotation_policy_root.as_str()
    );
    assert_eq!(
        caveats["caveat_set_root"].as_str().unwrap(),
        result.caveat_set_root.as_str()
    );
    assert_eq!(
        caveats["caveats"]
            .as_array()
            .unwrap()
            .iter()
            .map(|caveat| (
                caveat["code"].as_str().unwrap(),
                caveat["text"].as_str().unwrap(),
            ))
            .collect::<Vec<_>>(),
        semantic_caveats()
            .iter()
            .map(|caveat| (caveat.code, caveat.text))
            .collect::<Vec<_>>()
    );
}

#[test]
fn running_v3_does_not_change_profile_v2_results() {
    let (closure, audit) = audited(
        r#"<owl:Class rdf:about="urn:test:C"><rdfs:subClassOf rdf:resource="urn:test:D"/></owl:Class>"#,
    );
    let before =
        classify_ontology_bundle_v2(&closure.bundle, OntologyProfileLimits::default()).unwrap();
    classify_ontology_closure_v3_supported_subset(
        &closure,
        &audit,
        OntologyProfileV3Limits::default(),
    )
    .unwrap();
    let after =
        classify_ontology_bundle_v2(&closure.bundle, OntologyProfileLimits::default()).unwrap();
    assert_eq!(before, after);
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

#[test]
#[ignore = "requires the exact external official ontology cache"]
fn official_relations_profile_v3_admits_exact_registered_metadata() {
    let root = std::env::var("CTXQL_P6_REFERENCE_CACHE").unwrap();
    let root = Path::new(&root);
    assert!(root.is_absolute());
    let manifest: OfficialClosure = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_7/official-relations-closure.json"
    ))
    .unwrap();
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
    assert_eq!(closure.bundle.len(), 3_503);
    let unregistered_metadata = closure
        .bundle
        .iter()
        .filter(|quad| {
            (quad.predicate.starts_with("http://purl.org/dc/terms/")
                && quad.predicate != "http://purl.org/dc/terms/source")
                || (quad
                    .predicate
                    .starts_with("http://www.w3.org/2004/02/skos/core#")
                    && !matches!(
                        quad.predicate.as_str(),
                        "http://www.w3.org/2004/02/skos/core#definition"
                            | "http://www.w3.org/2004/02/skos/core#note"
                    ))
        })
        .count();
    assert_eq!(unregistered_metadata, 227);
    let result = classify_ontology_closure_v3_supported_subset(
        &closure,
        &audit,
        OntologyProfileV3Limits::default(),
    )
    .unwrap();
    assert_eq!(result.identity, ONTOLOGY_PROFILE_V3_ANALYSIS_ID);
    let admitted_metadata = result.categories[&OntologyMemberCategory::RetainedAnnotation]
        .iter()
        .filter(|quad| {
            (quad.predicate.starts_with("http://purl.org/dc/terms/")
                && quad.predicate != "http://purl.org/dc/terms/source")
                || (quad
                    .predicate
                    .starts_with("http://www.w3.org/2004/02/skos/core#")
                    && !matches!(
                        quad.predicate.as_str(),
                        "http://www.w3.org/2004/02/skos/core#definition"
                            | "http://www.w3.org/2004/02/skos/core#note"
                    ))
        })
        .count();
    assert_eq!(admitted_metadata, unregistered_metadata);
    assert_eq!(
        result.category_counts.values().sum::<usize>(),
        closure.bundle.len()
    );
    if let Ok(path) = std::env::var("CTXQL_P5_7_RELATIONS_PROFILE_REPORT") {
        let report = json!({
            "schema": "ctxql.p5-7-profile-v3-analysis/v1",
            "scope": "FND/Relations/Relations",
            "identity": result.identity,
            "result_label": result.result_label,
            "full_bundle_count": result.full_bundle.len(),
            "full_bundle_root": result.full_bundle_root.as_str(),
            "category_counts": result.category_counts.iter().map(|(category, count)|
                (format!("{category:?}"), *count)
            ).collect::<std::collections::BTreeMap<_, _>>(),
            "category_roots": result.category_roots.iter().map(|(category, root)|
                (format!("{category:?}"), root.as_str())
            ).collect::<std::collections::BTreeMap<_, _>>(),
            "category_occurrence_roots": result.category_occurrence_roots.iter().map(|(category, root)|
                (format!("{category:?}"), root.as_str())
            ).collect::<std::collections::BTreeMap<_, _>>(),
            "component_count": result.components.len(),
            "component_projection_root": result.component_projection_root.as_str(),
            "registry_root": result.registry_root.as_str(),
            "family_root": result.family_root.as_str(),
            "annotation_policy_root": result.annotation_policy_root.as_str(),
            "caveat_set_root": result.caveat_set_root.as_str(),
            "semantic_coverage_root": result.semantic_coverage_root.as_str(),
            "ontology_c0_input_count": result.ontology_c0_input.len(),
            "ontology_c0_input_root": result.ontology_c0_input_root.as_str(),
            "audit_root": result.audit_root.as_str(),
            "source_entry_root": result.source_entry_root.as_str(),
            "limits_identity": result.limits_identity.as_str(),
            "result_root": result.result_root.as_str(),
            "official_bytes_in_report": false
        });
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("profile report path must be create-new");
        output
            .write_all((serde_json::to_string_pretty(&report).unwrap() + "\n").as_bytes())
            .unwrap();
    }
    println!("P5_7_PROFILE_V3_ANALYZED admitted_metadata_occurrences={admitted_metadata}");
}

#[test]
#[ignore = "requires the exact external Agreements ontology cache"]
fn official_agreements_profile_v3_is_total_and_meaningful() {
    let root = std::env::var("CTXQL_P5_7_AGREEMENTS_CACHE").unwrap();
    let root = Path::new(&root);
    assert!(root.is_absolute());
    let manifest: OfficialClosure = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p5_7/official-agreements-closure.json"
    ))
    .unwrap();
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
    let result = classify_ontology_closure_v3_supported_subset(
        &closure,
        &audit,
        OntologyProfileV3Limits::default(),
    )
    .unwrap();
    assert_eq!(result.identity, ONTOLOGY_PROFILE_V3_ANALYSIS_ID);
    assert_eq!(
        result.category_counts.values().sum::<usize>(),
        closure.bundle.len()
    );
    let annotations = &result.categories[&OntologyMemberCategory::RetainedAnnotation];
    assert!(result.ontology_c0_input.is_disjoint(annotations));
    assert_eq!(
        result.ontology_c0_input.len() + annotations.len(),
        result.full_bundle.len()
    );
    for term in [
        "https://spec.edmcouncil.org/fibo/ontology/FND/Agreements/Agreements/Agreement",
        "https://spec.edmcouncil.org/fibo/ontology/FND/Agreements/Agreements/hasObligation",
        "https://spec.edmcouncil.org/fibo/ontology/FND/Agreements/Agreements/isObligationOf",
    ] {
        assert!(result
            .full_bundle
            .iter()
            .any(|quad| quad.subject.as_iri() == Some(term)));
    }
    if let Ok(path) = std::env::var("CTXQL_P5_7_PROFILE_REPORT") {
        let report = json!({
            "schema": "ctxql.p5-7-profile-v3-analysis/v1",
            "scope": "FND/Agreements/Agreements",
            "identity": result.identity,
            "result_label": result.result_label,
            "full_bundle_count": result.full_bundle.len(),
            "full_bundle_root": result.full_bundle_root.as_str(),
            "category_counts": result.category_counts.iter().map(|(category, count)|
                (format!("{category:?}"), *count)
            ).collect::<std::collections::BTreeMap<_, _>>(),
            "category_roots": result.category_roots.iter().map(|(category, root)|
                (format!("{category:?}"), root.as_str())
            ).collect::<std::collections::BTreeMap<_, _>>(),
            "category_occurrence_roots": result.category_occurrence_roots.iter().map(|(category, root)|
                (format!("{category:?}"), root.as_str())
            ).collect::<std::collections::BTreeMap<_, _>>(),
            "component_count": result.components.len(),
            "component_projection_root": result.component_projection_root.as_str(),
            "registry_root": result.registry_root.as_str(),
            "family_root": result.family_root.as_str(),
            "annotation_policy_root": result.annotation_policy_root.as_str(),
            "caveat_set_root": result.caveat_set_root.as_str(),
            "semantic_coverage_root": result.semantic_coverage_root.as_str(),
            "ontology_c0_input_count": result.ontology_c0_input.len(),
            "ontology_c0_input_root": result.ontology_c0_input_root.as_str(),
            "audit_root": result.audit_root.as_str(),
            "source_entry_root": result.source_entry_root.as_str(),
            "limits_identity": result.limits_identity.as_str(),
            "result_root": result.result_root.as_str(),
            "official_bytes_in_report": false
        });
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("profile report path must be create-new");
        output
            .write_all((serde_json::to_string_pretty(&report).unwrap() + "\n").as_bytes())
            .unwrap();
    }
    println!(
        "P5_7_AGREEMENTS_PROFILE quads={} reasoned={} declarations={} annotations={} uninterpreted={} bundle_root={} component_root={} family_root={} coverage_root={} c0_root={} result_root={}",
        result.full_bundle.len(),
        result.category_counts[&OntologyMemberCategory::Reasoned],
        result.category_counts[&OntologyMemberCategory::InferenceInertDeclaration],
        result.category_counts[&OntologyMemberCategory::RetainedAnnotation],
        result.category_counts[&OntologyMemberCategory::RetainedUninterpretedSemantic],
        result.full_bundle_root.as_str(),
        result.component_projection_root.as_str(),
        result.family_root.as_str(),
        result.semantic_coverage_root.as_str(),
        result.ontology_c0_input_root.as_str(),
        result.result_root.as_str(),
    );
}
