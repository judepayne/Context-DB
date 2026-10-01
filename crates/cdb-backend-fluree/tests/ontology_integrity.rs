use cdb_backend_fluree::{
    authorized_view::{ExactTerm, RdfNodeId, SourceQuad},
    official_bootstrap::native_ontology_quads,
    ontology_conversion::structural_quad_commitment,
    ontology_profile_load::{load_raw_file_once, OntologyProfileLoadLimits, RawOntologyLoadPlan},
};
use std::collections::BTreeSet;

fn iri(value: &str) -> RdfNodeId {
    RdfNodeId::Iri(value.into())
}

fn blank(value: &str) -> RdfNodeId {
    RdfNodeId::ScopedBlankNode(value.into())
}

fn object_blank(value: &str) -> ExactTerm {
    ExactTerm::ScopedBlankNode(value.into())
}

fn commitment(quads: BTreeSet<SourceQuad>) -> String {
    structural_quad_commitment(&quads, 32, 10_000)
        .unwrap()
        .root
        .as_str()
        .to_owned()
}

fn fixture(subject_blank: &str, object_blank_label: &str) -> BTreeSet<SourceQuad> {
    BTreeSet::from([
        SourceQuad {
            graph: "urn:test:g".into(),
            subject: iri("urn:test:s"),
            predicate: "urn:test:p".into(),
            object: object_blank(object_blank_label),
        },
        SourceQuad {
            graph: "urn:test:g".into(),
            subject: blank(subject_blank),
            predicate: "urn:test:value".into(),
            object: ExactTerm::Literal {
                lexical: "alpha".into(),
                datatype: "http://www.w3.org/2001/XMLSchema#string".into(),
                language: None,
            },
        },
        SourceQuad {
            graph: "urn:test:g".into(),
            subject: blank(object_blank_label),
            predicate: "urn:test:next".into(),
            object: object_blank(subject_blank),
        },
    ])
}

#[test]
fn blank_node_renaming_preserves_loaded_content_commitment() {
    assert_eq!(
        commitment(fixture("_:a", "_:b")),
        commitment(fixture("_:x", "_:y"))
    );
}

#[test]
fn equal_count_literal_substitution_changes_loaded_content_commitment() {
    let original = fixture("_:a", "_:b");
    let mut mutated = original.clone();
    let old = mutated
        .iter()
        .find(|quad| quad.predicate == "urn:test:value")
        .unwrap()
        .clone();
    mutated.remove(&old);
    let mut replacement = old;
    replacement.object = ExactTerm::Literal {
        lexical: "omega".into(),
        datatype: "http://www.w3.org/2001/XMLSchema#string".into(),
        language: None,
    };
    mutated.insert(replacement);
    assert_eq!(original.len(), mutated.len());
    assert_ne!(commitment(original), commitment(mutated));
}

#[tokio::test]
async fn native_readback_is_compared_independently_of_source_blank_labels() {
    let expected = fixture("_:source-a", "_:source-b");
    let directory = tempfile::tempdir().unwrap();
    let receipt = load_raw_file_once(
        directory.path(),
        RawOntologyLoadPlan {
            ledger: "ctxql/test:ontology".into(),
            source_quads: expected.clone(),
            limits: OntologyProfileLoadLimits {
                max_quads: 32,
                max_transaction_bytes: 64 * 1024,
                max_structural_nodes: 32,
            },
        },
    )
    .await
    .unwrap();
    let reader =
        fluree_db_api::FlureeBuilder::file(directory.path().to_string_lossy().into_owned())
            .without_indexing()
            .build()
            .unwrap();
    let detail = reader
        .graph(&receipt.ledger)
        .commit_t(receipt.t)
        .execute()
        .await
        .unwrap();
    let actual = native_ontology_quads(&detail).unwrap();
    assert_eq!(expected.len(), actual.len());
    assert_eq!(commitment(expected), commitment(actual));
}

#[test]
fn graph_scope_and_literal_metadata_are_integrity_bearing() {
    let original = fixture("_:a", "_:b");
    let mut moved = original.clone();
    let old = moved.iter().next().unwrap().clone();
    moved.remove(&old);
    let mut replacement = old;
    replacement.graph = "urn:test:unexpected".into();
    moved.insert(replacement);
    assert_ne!(commitment(original.clone()), commitment(moved));

    let mut language_changed = original.clone();
    let old = language_changed
        .iter()
        .find(|quad| quad.predicate == "urn:test:value")
        .unwrap()
        .clone();
    language_changed.remove(&old);
    let mut replacement = old;
    replacement.object = ExactTerm::Literal {
        lexical: "alpha".into(),
        datatype: "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString".into(),
        language: Some("en".into()),
    };
    language_changed.insert(replacement);
    assert_ne!(commitment(original), commitment(language_changed));
}
