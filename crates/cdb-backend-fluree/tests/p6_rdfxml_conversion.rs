use cdb_backend_fluree::{
    authorized_view::{ExactTerm, RdfNodeId, SourceQuad},
    ontology_conversion::{
        convert_rdfxml, ConversionErrorKind, ConversionLimits, ConversionRequest,
    },
    ontology_profile_v2::{analyze_ontology_bundle_v2, OntologyProfileLimits},
};
use cdb_core::id::ContentHash;
use fluree_graph_ir::{GraphCollectorSink, Term};
use fluree_graph_turtle::{parse_with_options, ParserOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

struct OfficialFile {
    relative: String,
    release: String,
    base: String,
    graph: String,
    bytes: usize,
    sha256: String,
}

fn request<'a>(bytes: &'a [u8]) -> ConversionRequest<'a> {
    ConversionRequest {
        authoritative_bytes: bytes,
        source_release_id: "publisher:product:release-1",
        source_file_id: "ontology/example.rdf",
        base_iri: "https://example.test/base/",
        graph_iri: "urn:graph:ontology",
        limits: ConversionLimits {
            max_input_bytes: 64 * 1024,
            max_input_triples: 100,
            max_output_bytes: 128 * 1024,
            max_blank_nodes: 8,
            max_canonicalization_work: 1_000_000,
        },
    }
}

#[test]
fn preserves_relative_iris_imports_literals_and_fluree_reparses() {
    let xml = format!(
        r#"<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="{RDF}" xmlns:owl="http://www.w3.org/2002/07/owl#"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema#" xmlns:e="https://example.test/v#"
 xml:base="https://example.test/base/" xml:lang="en-GB">
 <owl:Ontology rdf:about="ontology"><owl:imports rdf:resource="../dependency"/></owl:Ontology>
 <rdf:Description rdf:about="subject">
  <e:label>snowman ☃&#10;next</e:label>
  <e:number rdf:datatype="http://www.w3.org/2001/XMLSchema#decimal">01.2300</e:number>
 </rdf:Description>
</rdf:RDF>"#
    );
    let result = convert_rdfxml(request(xml.as_bytes())).unwrap();

    assert!(result
        .turtle
        .contains("<https://example.test/base/subject>"));
    assert!(result.turtle.contains("<https://example.test/dependency>"));
    assert!(result.turtle.contains("\"snowman ☃\\nnext\"@en-GB"));
    assert!(result
        .turtle
        .contains("\"01.2300\"^^<http://www.w3.org/2001/XMLSchema#decimal>"));
    assert_eq!(result.input_triple_count, result.output_triple_count);
    assert_eq!(result.duplicate_input_triple_count, 0);
    assert_ne!(result.original_hash, result.derived_hash);

    let mut sink = GraphCollectorSink::new();
    parse_with_options(&result.turtle, &mut sink, ParserOptions::conformant()).unwrap();
    let reparsed: BTreeSet<_> = sink
        .into_graph()
        .iter()
        .map(|triple| SourceQuad {
            graph: result.graph_iri.clone(),
            subject: match &triple.s {
                Term::Iri(iri) => RdfNodeId::Iri(iri.to_string()),
                Term::BlankNode(blank) => {
                    RdfNodeId::ScopedBlankNode(format!("_:{}", blank.as_str()))
                }
                Term::Literal { .. } => panic!("literal RDF subject"),
            },
            predicate: match &triple.p {
                Term::Iri(iri) => iri.to_string(),
                _ => panic!("non-IRI RDF predicate"),
            },
            object: match &triple.o {
                Term::Iri(iri) => ExactTerm::Iri(iri.to_string()),
                Term::BlankNode(blank) => {
                    ExactTerm::ScopedBlankNode(format!("_:{}", blank.as_str()))
                }
                Term::Literal {
                    value,
                    datatype,
                    language,
                } => ExactTerm::Literal {
                    lexical: value.lexical(),
                    datatype: datatype.as_iri().to_owned(),
                    language: language.as_ref().map(ToString::to_string),
                },
            },
        })
        .collect();
    assert_eq!(reparsed, result.quads);
}

#[test]
fn canonicalizes_explicit_generated_shared_nested_nodes_and_collections() {
    let first = format!(
        r#"<rdf:RDF xmlns:rdf="{RDF}" xmlns:e="urn:e:">
 <rdf:Description rdf:nodeID="named"><e:child><rdf:Description><e:value>v</e:value></rdf:Description></e:child></rdf:Description>
 <rdf:Description rdf:about="urn:s"><e:left rdf:nodeID="named"/><e:list rdf:parseType="Collection"><rdf:Description rdf:about="urn:a"/><rdf:Description rdf:about="urn:b"/></e:list></rdf:Description>
</rdf:RDF>"#
    );
    let reordered = format!(
        r#"<rdf:RDF xmlns:rdf="{RDF}" xmlns:e="urn:e:">
 <rdf:Description rdf:about="urn:s"><e:list rdf:parseType="Collection"><rdf:Description rdf:about="urn:a"/><rdf:Description rdf:about="urn:b"/></e:list><e:left rdf:nodeID="different"/></rdf:Description>
 <rdf:Description rdf:nodeID="different"><e:child><rdf:Description><e:value>v</e:value></rdf:Description></e:child></rdf:Description>
</rdf:RDF>"#
    );
    let a = convert_rdfxml(request(first.as_bytes())).unwrap();
    let b = convert_rdfxml(request(reordered.as_bytes())).unwrap();

    assert_eq!(a.turtle, b.turtle);
    assert_eq!(a.graph_root, b.graph_root);
    assert!(a.turtle.contains(&format!("<{RDF}first>")));
    assert!(a.turtle.contains(&format!("<{RDF}rest>")));
    let labels: Vec<_> = a
        .quads
        .iter()
        .filter_map(|quad| match &quad.subject {
            RdfNodeId::ScopedBlankNode(label) => Some(label),
            RdfNodeId::Iri(_) => None,
        })
        .collect();
    assert!(!labels.is_empty());
    assert!(labels.iter().all(|label| label.starts_with("_:c")));
}

#[test]
fn stable_identity_not_cache_path_and_graph_scopes_blank_nodes() {
    let xml = format!(
        r#"<rdf:RDF xmlns:rdf="{RDF}" xmlns:e="urn:e:"><rdf:Description><e:p rdf:resource="urn:o"/></rdf:Description></rdf:RDF>"#
    );
    let a = convert_rdfxml(request(xml.as_bytes())).unwrap();
    let b = convert_rdfxml(request(xml.as_bytes())).unwrap();
    assert_eq!(a, b);

    let mut other_graph = request(xml.as_bytes());
    other_graph.graph_iri = "urn:graph:other";
    let c = convert_rdfxml(other_graph).unwrap();
    assert_ne!(a.turtle, c.turtle);
    assert_ne!(a.graph_root, c.graph_root);
}

#[test]
fn accepts_bounded_internal_entities_but_rejects_external_or_unsafe_entities() {
    let safe = format!(
        r#"<!DOCTYPE rdf:RDF [<!ENTITY e "https://example.test/v#">]>
<rdf:RDF xmlns:rdf="{RDF}" xmlns:e="&e;"><rdf:Description rdf:about="urn:s"><e:p rdf:resource="urn:o"/></rdf:Description></rdf:RDF>"#
    );
    assert_eq!(
        convert_rdfxml(request(safe.as_bytes()))
            .unwrap()
            .output_triple_count,
        1
    );

    for xml in [
        format!(
            r#"<!DOCTYPE rdf:RDF SYSTEM "https://attacker.test/external.dtd"><rdf:RDF xmlns:rdf="{RDF}"/>"#
        ),
        format!(
            r#"<!DOCTYPE rdf:RDF [<!ENTITY x SYSTEM "file:///etc/passwd">]><rdf:RDF xmlns:rdf="{RDF}"/>"#
        ),
        format!(r#"<!DOCTYPE rdf:RDF [<!ENTITY x "&x;&x;">]><rdf:RDF xmlns:rdf="{RDF}"/>"#),
        format!(r#"<!ENTITY x "boom"><rdf:RDF xmlns:rdf="{RDF}"/>"#),
    ] {
        let error = convert_rdfxml(request(xml.as_bytes())).unwrap_err();
        assert_eq!(error.kind, ConversionErrorKind::Security);
        assert_eq!(
            error.public_code,
            "rdfxml_external_or_unsafe_entity_forbidden"
        );
    }
    let malformed = format!(r#"<rdf:RDF xmlns:rdf="{RDF}"><rdf:Description>"#);
    assert_eq!(
        convert_rdfxml(request(malformed.as_bytes()))
            .unwrap_err()
            .kind,
        ConversionErrorKind::Malformed
    );
}

#[test]
fn enforces_input_triple_output_blank_and_work_bounds() {
    let xml = format!(
        r#"<rdf:RDF xmlns:rdf="{RDF}" xmlns:e="urn:e:">
      <rdf:Description rdf:about="urn:s"><e:p>one</e:p><e:p>two</e:p></rdf:Description>
    </rdf:RDF>"#
    );
    let mut bytes = request(xml.as_bytes());
    bytes.limits.max_input_bytes = 1;
    assert_eq!(
        convert_rdfxml(bytes).unwrap_err().kind,
        ConversionErrorKind::Limit
    );

    let mut triples = request(xml.as_bytes());
    triples.limits.max_input_triples = 1;
    assert_eq!(
        convert_rdfxml(triples).unwrap_err().public_code,
        "rdfxml_triple_limit_exceeded"
    );

    let mut output = request(xml.as_bytes());
    output.limits.max_output_bytes = 1;
    assert_eq!(
        convert_rdfxml(output).unwrap_err().public_code,
        "rdfxml_output_byte_limit_exceeded"
    );

    let blanks_xml = format!(
        r#"<rdf:RDF xmlns:rdf="{RDF}" xmlns:e="urn:e:"><rdf:Description><e:p><rdf:Description/></e:p></rdf:Description></rdf:RDF>"#
    );
    let mut blanks = request(blanks_xml.as_bytes());
    blanks.limits.max_blank_nodes = 1;
    assert_eq!(
        convert_rdfxml(blanks).unwrap_err().public_code,
        "rdfxml_blank_node_limit_exceeded"
    );

    let mut work = request(blanks_xml.as_bytes());
    work.limits.max_canonicalization_work = 1;
    assert_eq!(
        convert_rdfxml(work).unwrap_err().public_code,
        "rdfxml_canonicalization_work_limit_exceeded"
    );

    let expanded_xml = format!(
        r#"<!DOCTYPE rdf:RDF [<!ENTITY x "012345678901234567890123456789">]>
<rdf:RDF xmlns:rdf="{RDF}" xmlns:e="urn:e:"><rdf:Description rdf:about="urn:s"><e:p>&x;&x;&x;&x;</e:p></rdf:Description></rdf:RDF>"#
    );
    let mut expansion = request(expanded_xml.as_bytes());
    expansion.limits.max_output_bytes = expanded_xml.len();
    assert_eq!(
        convert_rdfxml(expansion).unwrap_err().public_code,
        "rdfxml_entity_expansion_limit_exceeded"
    );
}

#[test]
fn large_symmetric_blank_group_fails_before_recursive_permutation() {
    let descriptions = (0..1_000)
        .map(|_| "<rdf:Description><e:p rdf:resource=\"urn:same\"/></rdf:Description>")
        .collect::<String>();
    let xml = format!(r#"<rdf:RDF xmlns:rdf="{RDF}" xmlns:e="urn:e:">{descriptions}</rdf:RDF>"#);
    let mut request = request(xml.as_bytes());
    request.limits.max_input_bytes = xml.len() + 1;
    request.limits.max_input_triples = 2_000;
    request.limits.max_blank_nodes = 2_000;
    request.limits.max_canonicalization_work = 20_000_000;
    assert_eq!(
        convert_rdfxml(request).unwrap_err().public_code,
        "rdfxml_canonicalization_work_limit_exceeded"
    );
}

#[test]
fn structural_refinement_scales_beyond_the_old_global_factorial_bound() {
    let descriptions = (0..32)
        .map(|index| {
            format!(
                "<rdf:Description><e:index>{index}</e:index><e:target rdf:resource=\"urn:item:{index}\"/></rdf:Description>"
            )
        })
        .collect::<String>();
    let xml = format!(r#"<rdf:RDF xmlns:rdf="{RDF}" xmlns:e="urn:e:">{descriptions}</rdf:RDF>"#);
    let mut request = request(xml.as_bytes());
    request.limits.max_blank_nodes = 64;
    request.limits.max_canonicalization_work = 1_000_000;
    let result = convert_rdfxml(request).unwrap();
    assert_eq!(result.output_triple_count, 64);
    assert!(result.canonicalization_work < 1_000_000);
}

fn official_files() -> Vec<OfficialFile> {
    let commons = [
        (
            "AnnotationVocabulary",
            23_277,
            "0f31efad729e9c5dc260d4cca8cb92c69ec25a4554ead4c866903f652e3789f7",
        ),
        (
            "BusinessAuthorizations",
            15_719,
            "603b9985b7553c49cd5e9adfd055dab8c4fb1b3d88a6db51e031d6df9cef12d3",
        ),
        (
            "Classifiers",
            10_348,
            "766312bdb13a27cdc6fe722d5be3c815135a284dbb5e6990455cc655aecad6e9",
        ),
        (
            "CodesAndCodeSets",
            6_153,
            "272ea377f588ed30759c37a2b0455a8b04643c8114ebf35ad31656c039d09150",
        ),
        (
            "Collections",
            12_677,
            "44450edbe870cad6fa406319ecb21fed6a27824904e865b1d683f8bfd2a03553",
        ),
        (
            "ContextualDesignators",
            10_469,
            "aa1c6c1d403a79b04b5f1cf65d1cd993b64d87aee51b9f7a3889ea06f01a96a8",
        ),
        (
            "DatesAndTimes",
            32_303,
            "29f48874c004475893202d0359ca1deb9e44e87d6e1a382e12e57c0fc86f90e7",
        ),
        (
            "Designators",
            16_423,
            "6475c00a66050560c11560c91e824118aaa4f13f9e0d62e8eddaf2eb6a447eca",
        ),
        (
            "Documents",
            17_703,
            "958264c82c7011097cf6da6352464dc094a9d1cada1d37a41ff26ed763f91a5c",
        ),
        (
            "Identifiers",
            6_920,
            "c5ed5f3551ff4d0a711bd50ff6a7388383a1cf33a27bc1661e54f6bf7a75987a",
        ),
        (
            "Locations",
            32_882,
            "0d6a8eedb4461f4256ea61f03506e882bdadc8b1ca2024493eb6585b3e574c31",
        ),
        (
            "Organizations",
            32_334,
            "3a1ab7e936b656fff8aa8beb44d30ddc02aaa6f6eac5353d4157e355ef164eb7",
        ),
        (
            "PartiesAndSituations",
            30_432,
            "1c207e4f04e51fee7d06bbee1e5c53ae90f04374da3568e0470699d8f20cc1f3",
        ),
        (
            "QuantitiesAndUnits",
            72_711,
            "b1fbe90e6c4b23cd7c7485fbe06b94d373b598ece83f074c05b82b8bcc399d7f",
        ),
        (
            "RegulatoryAgencies",
            14_118,
            "cd309406734bb8ba01a5626d1af7b5c8dc6bb3ab3a275e3faac791e5dd460d55",
        ),
        (
            "RolesAndCompositions",
            10_625,
            "81d40576c2afa3f1a9fabd0b08f67a31e1a82bead9467782d8450d7b331275fc",
        ),
        (
            "TextDatatype",
            5_976,
            "d29a6e24bffb67fd6a4fe9955880fb9e8bd2f858a12d3e846fc45fd571bd8314",
        ),
    ];
    let mut files = commons
        .into_iter()
        .map(|(name, bytes, sha256)| OfficialFile {
            relative: format!("commons/{name}.rdf"),
            release: "sha256:omg-commons-1.3".to_owned(),
            base: format!("https://www.omg.org/spec/Commons/20250801/{name}.rdf"),
            graph: format!("https://www.omg.org/spec/Commons/{name}/"),
            bytes,
            sha256: sha256.to_owned(),
        })
        .collect::<Vec<_>>();
    files.extend([
        OfficialFile {
            relative: "fibo/FND/Relations/Relations.rdf".to_owned(),
            release: "sha256:fibo-q2-2026".to_owned(),
            base: "https://spec.edmcouncil.org/fibo/ontology/master/2026Q2/FND/Relations/Relations.rdf".to_owned(),
            graph: "https://spec.edmcouncil.org/fibo/ontology/FND/Relations/Relations/".to_owned(),
            bytes: 23_946,
            sha256: "53e66c732bb0a593a0a976df08b2d80e3ac0e12c197aed58671c660f8cc427c5".to_owned(),
        },
        OfficialFile {
            relative: "fibo/FND/Utilities/AnnotationVocabulary.rdf".to_owned(),
            release: "sha256:fibo-q2-2026".to_owned(),
            base: "https://spec.edmcouncil.org/fibo/ontology/master/2026Q2/FND/Utilities/AnnotationVocabulary.rdf".to_owned(),
            graph: "https://spec.edmcouncil.org/fibo/ontology/FND/Utilities/AnnotationVocabulary/".to_owned(),
            bytes: 10_870,
            sha256: "fe863cf8a5bf58a3cff8a59d8555b00acf22a02096998c3189e0ec9f912c6e71".to_owned(),
        },
    ]);
    files
}

fn verify_all_fibo_ontologies_reach_annotation_vocabulary() {
    let report = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/conformance/ontology/fibo-reference-analysis.json");
    let bytes = fs::read(report).unwrap();
    assert_eq!(
        ContentHash::of_bytes(&bytes).as_str(),
        "sha256:7cea098980331aa5c7940bc0ca53696f96d35262c25c7d27d3b6009adf551a43"
    );
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let rows = value["ontology_analysis"]["ontology_files"]
        .as_array()
        .unwrap();
    let mut imports = BTreeMap::new();
    for row in rows {
        let targets = row["imports"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        for ontology in row["ontology_iris"].as_array().unwrap() {
            assert!(imports
                .insert(ontology.as_str().unwrap().to_owned(), targets.clone())
                .is_none());
        }
    }
    assert_eq!(imports.len(), 295);
    let target = "https://spec.edmcouncil.org/fibo/ontology/FND/Utilities/AnnotationVocabulary/";
    let reaches = imports
        .keys()
        .filter(|seed| {
            let mut seen = BTreeSet::new();
            let mut pending = vec![(*seed).clone()];
            while let Some(iri) = pending.pop() {
                if !seen.insert(iri.clone()) {
                    continue;
                }
                if let Some(next) = imports.get(&iri) {
                    pending.extend(next.iter().cloned());
                }
            }
            seen.contains(target)
        })
        .count();
    assert_eq!(reaches, 295);
}

#[test]
#[ignore = "requires the external official ontology cache; never ordinary CI"]
fn official_selected_rdfxml_files_convert_exactly() {
    let root = std::env::var("CTXQL_P6_REFERENCE_CACHE")
        .expect("CTXQL_P6_REFERENCE_CACHE must name the absolute external cache");
    let root = Path::new(&root);
    assert!(root.is_absolute());
    let files = official_files();
    let mut total_authoritative_bytes = 0usize;
    let mut inventory_material = Vec::new();
    let mut total_triples = 0usize;
    let mut total_output_bytes = 0usize;
    let mut bundle = BTreeSet::new();
    for file in &files {
        let bytes = fs::read(root.join(&file.relative)).unwrap();
        assert_eq!(bytes.len(), file.bytes, "{} byte count", file.relative);
        let hash = ContentHash::of_bytes(&bytes);
        assert_eq!(&hash.as_str()[7..], file.sha256, "{} hash", file.relative);
        total_authoritative_bytes += bytes.len();
        inventory_material.extend_from_slice(file.relative.as_bytes());
        inventory_material.push(0);
        inventory_material.extend_from_slice(file.sha256.as_bytes());
        inventory_material.push(b'\n');
        let result = convert_rdfxml(ConversionRequest {
            authoritative_bytes: &bytes,
            source_release_id: &file.release,
            source_file_id: &file.relative,
            base_iri: &file.base,
            graph_iri: &file.graph,
            limits: ConversionLimits::default(),
        })
        .unwrap_or_else(|error| panic!("{}: {error}", file.relative));
        assert!(!result.quads.is_empty(), "{}", file.relative);
        total_triples += result.output_triple_count;
        total_output_bytes += result.turtle.len();
        bundle.extend(result.quads);
    }
    assert_eq!(total_authoritative_bytes, 385_886);
    assert_eq!(
        ContentHash::of_bytes(&inventory_material).as_str(),
        "sha256:d1a3bfb36743cc745b12f48bcdd2bfe01ba359643362682b04444ea36fc9b51d"
    );
    verify_all_fibo_ontologies_reach_annotation_vocabulary();
    let named_individual = "http://www.w3.org/2002/07/owl#NamedIndividual";
    assert!(bundle.iter().any(|quad| {
        quad.graph
            == "https://spec.edmcouncil.org/fibo/ontology/FND/Utilities/AnnotationVocabulary/"
            && quad.predicate == RDF_TYPE
            && quad.object == ExactTerm::Iri(named_individual.to_owned())
    }));
    println!(
        "verified_official_closure files={} bytes={} inventory_root=sha256:d1a3bfb36743cc745b12f48bcdd2bfe01ba359643362682b04444ea36fc9b51d fibo_reachability=295/295 blocking_construct={named_individual}",
        files.len(), total_authoritative_bytes
    );
    assert!(total_triples > 1_000);
    assert!(total_output_bytes > 100_000);
    let failure = analyze_ontology_bundle_v2(
        &bundle,
        OntologyProfileLimits {
            max_bundle_quads: 500_000,
            ..OntologyProfileLimits::default()
        },
    )
    .expect_err("official closure unexpectedly passed P5.6 profile v2");
    assert!(failure.issues.iter().any(|issue| {
        issue.reason == "ontology_reserved_type_unsupported"
            && issue.graph.as_deref()
                == Some(
                    "https://spec.edmcouncil.org/fibo/ontology/FND/Utilities/AnnotationVocabulary/",
                )
            && issue.predicate.as_deref() == Some(RDF_TYPE)
    }));
    panic!(
        "Gate B blocked after exact-byte verification: ontology_reserved_type_unsupported for {named_individual}"
    );
}

#[test]
fn reports_duplicates_before_set_normalization_without_pruning() {
    let xml = format!(
        r#"<rdf:RDF xmlns:rdf="{RDF}" xmlns:e="urn:e:">
      <rdf:Description rdf:about="urn:s"><e:p rdf:resource="urn:o"/><e:p rdf:resource="urn:o"/></rdf:Description>
    </rdf:RDF>"#
    );
    let result = convert_rdfxml(request(xml.as_bytes())).unwrap();
    assert_eq!(result.input_triple_count, 2);
    assert_eq!(result.duplicate_input_triple_count, 1);
    assert_eq!(result.output_triple_count, 1);
    assert!(matches!(
        result.quads.iter().next().unwrap().object,
        ExactTerm::Iri(_)
    ));
}
