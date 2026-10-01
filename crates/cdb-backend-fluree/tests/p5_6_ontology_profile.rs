use cdb_backend_fluree::{
    authorized_view::{ExactTerm, RdfNodeId, SourceQuad},
    ontology_profile_v2::{
        analyze_ontology_bundle_v2, OntologyProfileLimits, ONTOLOGY_PROFILE_V2_ID,
    },
};
use std::collections::BTreeSet;

const G: &str = "urn:graph:schema";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_FIRST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
const RDF_REST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
const RDF_NIL: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";
const RESTRICTION: &str = "http://www.w3.org/2002/07/owl#Restriction";
const ON_PROPERTY: &str = "http://www.w3.org/2002/07/owl#onProperty";
const SOME: &str = "http://www.w3.org/2002/07/owl#someValuesFrom";
const EQUIVALENT_CLASS: &str = "http://www.w3.org/2002/07/owl#equivalentClass";
const CHAIN: &str = "http://www.w3.org/2002/07/owl#propertyChainAxiom";
const KEY: &str = "http://www.w3.org/2002/07/owl#hasKey";
const MAX: &str = "http://www.w3.org/2002/07/owl#maxCardinality";

fn iri(value: &str) -> RdfNodeId {
    RdfNodeId::Iri(value.into())
}
fn blank(value: &str) -> RdfNodeId {
    RdfNodeId::ScopedBlankNode(value.into())
}
fn iri_term(value: &str) -> ExactTerm {
    ExactTerm::Iri(value.into())
}
fn blank_term(value: &str) -> ExactTerm {
    ExactTerm::ScopedBlankNode(value.into())
}
fn quad(graph: &str, subject: RdfNodeId, predicate: &str, object: ExactTerm) -> SourceQuad {
    SourceQuad {
        graph: graph.into(),
        subject,
        predicate: predicate.into(),
        object,
    }
}

fn list(head: &str, members: &[&str]) -> BTreeSet<SourceQuad> {
    let mut result = BTreeSet::new();
    for (index, member) in members.iter().enumerate() {
        let cell = if index == 0 {
            head.to_owned()
        } else {
            format!("{head}-{index}")
        };
        let next = if index + 1 == members.len() {
            iri_term(RDF_NIL)
        } else {
            blank_term(&format!("{head}-{}", index + 1))
        };
        result.insert(quad(G, blank(&cell), RDF_FIRST, iri_term(member)));
        result.insert(quad(G, blank(&cell), RDF_REST, next));
    }
    result
}

fn supported_bundle() -> BTreeSet<SourceQuad> {
    let mut bundle = BTreeSet::from([
        quad(G, iri("urn:p:ancestor"), CHAIN, blank_term("_:fdb-chain")),
        quad(G, iri("urn:class:Person"), KEY, blank_term("_:fdb-key")),
        quad(
            G,
            blank("_:fdb-restriction"),
            RDF_TYPE,
            iri_term(RESTRICTION),
        ),
        quad(
            G,
            blank("_:fdb-restriction"),
            ON_PROPERTY,
            iri_term("urn:p:parent"),
        ),
        quad(
            G,
            blank("_:fdb-restriction"),
            SOME,
            iri_term("urn:class:Person"),
        ),
        quad(
            G,
            iri("urn:class:Parent"),
            EQUIVALENT_CLASS,
            blank_term("_:fdb-restriction"),
        ),
    ]);
    bundle.extend(list("_:fdb-chain", &["urn:p:parent", "urn:p:parent"]));
    bundle.extend(list("_:fdb-key", &["urn:p:identifier"]));
    bundle
}

#[test]
fn complete_compound_bundle_is_order_independent_and_revision_bound() {
    let bundle = supported_bundle();
    let result = analyze_ontology_bundle_v2(&bundle, OntologyProfileLimits::default()).unwrap();
    assert_eq!(result.identity, ONTOLOGY_PROFILE_V2_ID);
    assert_eq!(result.full_bundle, bundle);
    assert_eq!(result.reasoner_projection.quads.len(), bundle.len());

    let reordered = bundle.iter().rev().cloned().collect::<BTreeSet<_>>();
    let second = analyze_ontology_bundle_v2(&reordered, OntologyProfileLimits::default()).unwrap();
    assert_eq!(result.full_bundle_root, second.full_bundle_root);
    assert_eq!(result.result_root, second.result_root);
    assert_eq!(
        result.reasoner_projection.root,
        second.reasoner_projection.root
    );
}

#[test]
fn malformed_and_unsupported_neighbors_fail_whole_bundle() {
    let mut duplicate = supported_bundle();
    duplicate.insert(quad(
        G,
        blank("_:fdb-chain"),
        RDF_FIRST,
        iri_term("urn:p:other"),
    ));
    assert_eq!(
        analyze_ontology_bundle_v2(&duplicate, OntologyProfileLimits::default())
            .unwrap_err()
            .public_code,
        "ontology_configuration_invalid"
    );

    let mut unsupported = supported_bundle();
    unsupported.insert(quad(
        G,
        iri("urn:p:a"),
        "http://www.w3.org/2002/07/owl#equivalentProperty",
        iri_term("urn:p:b"),
    ));
    assert_eq!(
        analyze_ontology_bundle_v2(&unsupported, OntologyProfileLimits::default())
            .unwrap_err()
            .public_code,
        "ontology_profile_unsupported"
    );
}

#[test]
fn structural_nodes_are_graph_scoped_and_cardinality_is_exactly_one() {
    let mut crossing = supported_bundle();
    crossing.insert(quad(
        "urn:graph:other",
        blank("_:fdb-chain"),
        RDF_FIRST,
        iri_term("urn:p:parent"),
    ));
    let error = analyze_ontology_bundle_v2(&crossing, OntologyProfileLimits::default())
        .expect_err("same structural identity in two graphs must fail");
    assert_eq!(
        error.issues[0].reason,
        "ontology_structural_node_cross_graph"
    );

    let cardinality = BTreeSet::from([
        quad(
            G,
            iri("urn:class:cardinality"),
            RDF_TYPE,
            iri_term(RESTRICTION),
        ),
        quad(
            G,
            iri("urn:class:cardinality"),
            ON_PROPERTY,
            iri_term("urn:p:value"),
        ),
        quad(
            G,
            iri("urn:class:cardinality"),
            MAX,
            ExactTerm::Literal {
                lexical: "2".into(),
                datatype: "http://www.w3.org/2001/XMLSchema#nonNegativeInteger".into(),
                language: None,
            },
        ),
    ]);
    assert_eq!(
        analyze_ontology_bundle_v2(&cardinality, OntologyProfileLimits::default())
            .unwrap_err()
            .public_code,
        "ontology_profile_unsupported"
    );
}

#[test]
fn all_native_long_cardinality_datatypes_and_only_owned_facets_are_accepted() {
    let datatypes = [
        "integer",
        "long",
        "int",
        "short",
        "byte",
        "unsignedLong",
        "unsignedInt",
        "unsignedShort",
        "unsignedByte",
        "nonNegativeInteger",
        "positiveInteger",
    ];
    let mut bundle = BTreeSet::new();
    for (index, datatype) in datatypes.into_iter().enumerate() {
        let restriction = format!("urn:class:cardinality:{index}");
        bundle.insert(quad(G, iri(&restriction), RDF_TYPE, iri_term(RESTRICTION)));
        bundle.insert(quad(
            G,
            iri(&restriction),
            ON_PROPERTY,
            iri_term("urn:p:value"),
        ));
        bundle.insert(quad(
            G,
            iri(&restriction),
            MAX,
            ExactTerm::Literal {
                lexical: "+01".into(),
                datatype: format!("http://www.w3.org/2001/XMLSchema#{datatype}"),
                language: None,
            },
        ));
    }
    analyze_ontology_bundle_v2(&bundle, OntologyProfileLimits::default())
        .expect("every integer-family datatype materialized as FlakeValue::Long must match");

    let orphan = BTreeSet::from([quad(
        G,
        iri("urn:class:orphan"),
        ON_PROPERTY,
        iri_term("urn:p:value"),
    )]);
    let error = analyze_ontology_bundle_v2(&orphan, OntologyProfileLimits::default())
        .expect_err("an unowned reserved facet must fail before reasoning");
    assert_eq!(
        error.issues[0].reason,
        "ontology_restriction_marker_missing"
    );

    let malformed_metadata = BTreeSet::from([quad(
        G,
        iri("urn:ontology"),
        "http://www.w3.org/2002/07/owl#versionIRI",
        ExactTerm::Literal {
            lexical: "not-an-iri".into(),
            datatype: "http://www.w3.org/2001/XMLSchema#string".into(),
            language: None,
        },
    )]);
    let error = analyze_ontology_bundle_v2(&malformed_metadata, OntologyProfileLimits::default())
        .expect_err("reserved metadata object shape must be validated");
    assert_eq!(error.issues[0].reason, "ontology_metadata_object_invalid");
}

#[test]
fn list_and_expression_limits_fail_before_reasoning() {
    let bundle = supported_bundle();
    let error = analyze_ontology_bundle_v2(
        &bundle,
        OntologyProfileLimits {
            max_list_length: 1,
            ..OntologyProfileLimits::default()
        },
    )
    .expect_err("two-element chain exceeds committed bound");
    assert_eq!(error.public_code, "ontology_profile_limit_exceeded");
}
