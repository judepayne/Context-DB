use cdb_backend_fluree::{
    authorized_view::{
        AuthorizedViewManifest, ExactTerm, OntologyProfileDescriptor, ReasoningDescriptor,
        SemanticCaptureDescriptor, SourceQuad,
    },
    ontology_profile::{
        classify_member, classify_ontology_bundle, OntologyMemberClass, ONTOLOGY_PROFILE_ID,
    },
};
use cdb_core::id::ContentHash;
use std::collections::BTreeSet;

const G: &str = "http://example.org/schema";
const EX: &str = "http://example.org/";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDFS: &str = "http://www.w3.org/2000/01/rdf-schema#";
const OWL: &str = "http://www.w3.org/2002/07/owl#";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

const OFFLINE_CORPUS: &str = include_str!("fixtures/p5_5_ontology_profile.ttl");

fn iri(subject: &str, predicate: &str, object: &str) -> SourceQuad {
    SourceQuad {
        graph: G.into(),
        subject: subject.into(),
        predicate: predicate.into(),
        object: ExactTerm::Iri(object.into()),
    }
}

fn literal(subject: &str, predicate: &str, value: &str) -> SourceQuad {
    SourceQuad {
        graph: G.into(),
        subject: subject.into(),
        predicate: predicate.into(),
        object: ExactTerm::Literal {
            lexical: value.into(),
            datatype: XSD_STRING.into(),
            language: None,
        },
    }
}

#[test]
fn offline_corpus_is_synthetic_and_network_independent() {
    assert!(OFFLINE_CORPUS.contains("Synthetic offline Gate F corpus"));
    assert!(OFFLINE_CORPUS.contains("owl:SymmetricProperty"));
    assert!(!OFFLINE_CORPUS.contains("http://www.omg.org"));
}

#[test]
fn revision_bound_supported_matrix_is_executable() {
    let supported = [
        iri(
            &format!("{EX}Manager"),
            &format!("{RDFS}subClassOf"),
            &format!("{EX}Person"),
        ),
        iri(
            &format!("{EX}manages"),
            &format!("{RDFS}subPropertyOf"),
            &format!("{EX}knows"),
        ),
        iri(
            &format!("{EX}manages"),
            &format!("{RDFS}domain"),
            &format!("{EX}Manager"),
        ),
        iri(
            &format!("{EX}manages"),
            &format!("{RDFS}range"),
            &format!("{EX}Person"),
        ),
        iri(
            &format!("{EX}parent"),
            &format!("{OWL}inverseOf"),
            &format!("{EX}child"),
        ),
        iri(
            &format!("{EX}Manager"),
            &format!("{OWL}equivalentClass"),
            &format!("{EX}Supervisor"),
        ),
        iri(
            &format!("{EX}a"),
            &format!("{OWL}sameAs"),
            &format!("{EX}b"),
        ),
        iri(G, &format!("{OWL}imports"), "http://example.org/import"),
        iri(&format!("{EX}employee"), RDF_TYPE, &format!("{EX}Person")),
    ];
    for quad in supported {
        assert_eq!(
            classify_member(&quad),
            OntologyMemberClass::SupportedPremise
        );
    }
    for characteristic in [
        "SymmetricProperty",
        "TransitiveProperty",
        "FunctionalProperty",
        "InverseFunctionalProperty",
    ] {
        assert_eq!(
            classify_member(&iri(
                &format!("{EX}p"),
                RDF_TYPE,
                &format!("{OWL}{characteristic}"),
            )),
            OntologyMemberClass::SupportedPremise
        );
    }
}

#[test]
fn harmless_metadata_is_committed_but_not_a_schema_premise() {
    let premise = iri(
        &format!("{EX}Manager"),
        &format!("{RDFS}subClassOf"),
        &format!("{EX}Person"),
    );
    let label = literal(&format!("{EX}Manager"), &format!("{RDFS}label"), "Manager");
    let version = literal(G, &format!("{OWL}versionInfo"), "fixture-v1");
    let bundle = BTreeSet::from([premise.clone(), label.clone(), version.clone()]);
    let result = classify_ontology_bundle(&bundle).unwrap();
    assert_eq!(result.identity, ONTOLOGY_PROFILE_ID);
    assert_eq!(result.supported, BTreeSet::from([premise.clone()]));
    assert_eq!(result.harmless, BTreeSet::from([label, version.clone()]));
    assert_ne!(
        result.full_bundle_root,
        cdb_backend_fluree::authorized_view::quad_root(&result.supported)
    );
    let changed_metadata = classify_ontology_bundle(&BTreeSet::from([
        premise,
        literal(&format!("{EX}Manager"), &format!("{RDFS}label"), "Lead"),
        version,
    ]))
    .unwrap();
    assert_eq!(result.supported, changed_metadata.supported);
    assert_ne!(result.full_bundle_root, changed_metadata.full_bundle_root);
    assert_ne!(result.result_root, changed_metadata.result_root);
}

#[test]
fn unsupported_semantics_fail_with_stable_reason() {
    let unsupported = [
        iri(
            &format!("{EX}Restriction"),
            RDF_TYPE,
            &format!("{OWL}Restriction"),
        ),
        iri(
            &format!("{EX}Restriction"),
            &format!("{OWL}onProperty"),
            &format!("{EX}p"),
        ),
        iri(
            &format!("{EX}Restriction"),
            &format!("{OWL}someValuesFrom"),
            &format!("{EX}C"),
        ),
        iri(
            &format!("{EX}p"),
            &format!("{OWL}propertyChainAxiom"),
            &format!("{EX}list"),
        ),
        iri(
            &format!("{EX}C"),
            &format!("{OWL}hasKey"),
            &format!("{EX}list"),
        ),
        literal(
            &format!("{EX}Restriction"),
            &format!("{OWL}cardinality"),
            "1",
        ),
        iri(
            &format!("{EX}A"),
            &format!("{OWL}disjointWith"),
            &format!("{EX}B"),
        ),
        iri(
            &format!("{EX}p"),
            &format!("{OWL}equivalentProperty"),
            &format!("{EX}q"),
        ),
        iri(
            &format!("{EX}list"),
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#first",
            &format!("{EX}p"),
        ),
    ];
    for quad in unsupported {
        assert_eq!(
            classify_ontology_bundle(&BTreeSet::from([quad])).unwrap_err(),
            "ontology_profile_unsupported"
        );
    }
}

#[test]
fn malformed_reserved_shapes_fail_closed() {
    for predicate in [
        RDF_TYPE,
        "http://www.w3.org/2000/01/rdf-schema#subClassOf",
        "http://www.w3.org/2002/07/owl#inverseOf",
        "http://www.w3.org/2002/07/owl#imports",
    ] {
        assert_eq!(
            classify_ontology_bundle(&BTreeSet::from([literal(
                &format!("{EX}subject"),
                predicate,
                "not-an-iri",
            )]))
            .unwrap_err(),
            "ontology_configuration_invalid"
        );
    }
}

#[test]
fn profile_result_is_bound_into_the_protected_e0_seal() {
    let bundle = BTreeSet::from([iri(
        &format!("{EX}C"),
        &format!("{RDFS}subClassOf"),
        &format!("{EX}D"),
    )]);
    let profile = classify_ontology_bundle(&bundle).unwrap();
    let seal = |result_root| {
        AuthorizedViewManifest::seal_profiled(
            SemanticCaptureDescriptor {
                ledger: "ctxql/profile:main".into(),
                requested_as_of: "t:1".into(),
                t: 1,
                commit_cid: "bafy-profile".into(),
            },
            ReasoningDescriptor {
                schema_source: G.into(),
                follow_owl_imports: false,
                schema_graphs: BTreeSet::from([G.into()]),
            },
            BTreeSet::new(),
            profile.supported.clone(),
            BTreeSet::new(),
            ContentHash::of_bytes(b"configuration"),
            OntologyProfileDescriptor {
                identity: ONTOLOGY_PROFILE_ID.into(),
                full_bundle_root: profile.full_bundle_root.clone(),
                result_root,
            },
            ContentHash::of_bytes(b"policy"),
            "terminal-profile-test",
        )
    };
    let first = seal(profile.result_root.clone());
    let changed = seal(ContentHash::of_bytes(b"changed-profile-result"));
    assert_eq!(
        first.authorized_premise_root,
        changed.authorized_premise_root
    );
    assert_ne!(
        first.execution_manifest_root,
        changed.execution_manifest_root
    );
    assert!(first.validate().is_ok());
}

#[test]
fn unknown_application_iris_remain_open_and_roots_are_set_deterministic() {
    let a = iri(
        &format!("{EX}s"),
        &format!("{EX}customPredicate"),
        &format!("{EX}o"),
    );
    let b = iri(
        &format!("{EX}C"),
        &format!("{RDFS}subClassOf"),
        &format!("{EX}D"),
    );
    let first = classify_ontology_bundle(&BTreeSet::from([a.clone(), b.clone()])).unwrap();
    let deduplicated =
        classify_ontology_bundle(&BTreeSet::from([b.clone(), a.clone(), a])).unwrap();
    assert_eq!(first, deduplicated);

    // Import resolution happens before Gate F; the classifier remains finite
    // and deterministic over the deduplicated complete closure, including a cycle.
    let import_ab = iri(
        "http://example.org/schema-a",
        &format!("{OWL}imports"),
        "http://example.org/schema-b",
    );
    let import_ba = iri(
        "http://example.org/schema-b",
        &format!("{OWL}imports"),
        "http://example.org/schema-a",
    );
    let cycle = classify_ontology_bundle(&BTreeSet::from([
        import_ab.clone(),
        import_ba.clone(),
        import_ab,
    ]))
    .unwrap();
    assert_eq!(cycle.supported.len(), 2);

    let changed = classify_ontology_bundle(&BTreeSet::from([
        b,
        iri(
            &format!("{EX}s"),
            &format!("{EX}customPredicate"),
            &format!("{EX}changed"),
        ),
    ]))
    .unwrap();
    assert_ne!(first.full_bundle_root, changed.full_bundle_root);
    assert_ne!(first.result_root, changed.result_root);
}
