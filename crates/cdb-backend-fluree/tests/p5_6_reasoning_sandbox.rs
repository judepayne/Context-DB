use cdb_backend_fluree::{
    authorized_view::{
        build_reasoner_input, AuthorizedViewManifest, ExactTerm, OntologyProfileDescriptor,
        RdfNodeId, ReasoningDescriptor, SemanticCaptureDescriptor, SourceQuad,
        STRUCTURAL_NODE_IRI_PREFIX,
    },
    current_reasoning_profile::classify_current_reasoning_profile,
    ontology_profile_v2::{OntologyProfileLimits, STRUCTURAL_MAPPING_ALGORITHM},
    reasoning_sandbox::{reason_authorized_manifest, PreparedFact, SandboxLimits},
};
use cdb_core::id::ContentHash;
use std::collections::BTreeSet;

const G: &str = "urn:graph:schema";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const OWL_ONTOLOGY: &str = "http://www.w3.org/2002/07/owl#Ontology";
const SUBPROPERTY: &str = "http://www.w3.org/2000/01/rdf-schema#subPropertyOf";

fn iri_quad(graph: &str, subject: &str, predicate: &str, object: &str) -> SourceQuad {
    SourceQuad {
        graph: graph.into(),
        subject: RdfNodeId::Iri(subject.into()),
        predicate: predicate.into(),
        object: ExactTerm::Iri(object.into()),
    }
}

fn manifest(data: BTreeSet<SourceQuad>) -> AuthorizedViewManifest {
    manifest_with_schema(
        data,
        BTreeSet::from([
            iri_quad(G, G, RDF_TYPE, OWL_ONTOLOGY),
            iri_quad(G, "urn:p:narrow", SUBPROPERTY, "urn:p:broad"),
        ]),
    )
}

fn manifest_with_schema(
    data: BTreeSet<SourceQuad>,
    schema: BTreeSet<SourceQuad>,
) -> AuthorizedViewManifest {
    let capture = SemanticCaptureDescriptor {
        ledger: "ctxql/p5-6-sandbox:main".into(),
        requested_as_of: "t:1".into(),
        t: 1,
        commit_cid: "bafy-p5-6-sandbox".into(),
    };
    let profile =
        classify_current_reasoning_profile(&schema, OntologyProfileLimits::default()).unwrap();
    let input = build_reasoner_input(&capture, &data, &profile.reasoner_projection.quads).unwrap();
    AuthorizedViewManifest::seal_profiled_v2(
        capture,
        ReasoningDescriptor {
            schema_source: G.into(),
            follow_owl_imports: false,
            schema_graphs: BTreeSet::from([G.into()]),
        },
        data,
        schema,
        input,
        STRUCTURAL_MAPPING_ALGORITHM.into(),
        profile.limits_identity.clone(),
        BTreeSet::new(),
        ContentHash::of_bytes(b"p5-6-config"),
        OntologyProfileDescriptor {
            identity: profile.identity.into(),
            full_bundle_root: profile.full_bundle_root,
            result_root: profile.result_root,
        },
        ContentHash::of_bytes(b"p5-6-policy"),
        "ctxql-p5-6-complete/v1",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sealed_v2_manifest_preserves_exact_inferred_literal_object() {
    let literal = ExactTerm::Literal {
        lexical: "0.800".into(),
        datatype: "http://www.w3.org/2001/XMLSchema#decimal".into(),
        language: None,
    };
    let data = BTreeSet::from([SourceQuad {
        graph: "urn:graph:data".into(),
        subject: RdfNodeId::Iri("urn:entity:alice".into()),
        predicate: "urn:p:narrow".into(),
        object: literal.clone(),
    }]);
    let manifest = manifest(data);
    let first = reason_authorized_manifest(&manifest, SandboxLimits::default())
        .await
        .unwrap();
    assert_eq!(
        manifest.ontology_profile.identity,
        cdb_backend_fluree::current_reasoning_profile::CURRENT_REASONING_PROFILE_ID
    );
    assert!(first.inferred_facts.contains(&PreparedFact {
        subject: "urn:entity:alice".into(),
        predicate: "urn:p:broad".into(),
        object: literal,
    }));
    let descriptor = first
        .descriptor(
            cdb_core::snapshot::SnapshotRef::new(
                cdb_core::id::BackendId::new("semantic").unwrap(),
                cdb_core::snapshot::GraphPin::new(
                    cdb_core::id::AuthorityId::new("semantic-authority").unwrap(),
                    cdb_core::id::GraphId::new("ctxql/p5-6-sandbox:main").unwrap(),
                    cdb_core::id::VersionId::new("1").unwrap(),
                    cdb_core::id::ResourceId::new("bafy-p5-6-sandbox").unwrap(),
                ),
            ),
            &manifest,
        )
        .unwrap();
    assert_eq!(descriptor.reasoner_input_root, manifest.reasoner_input_root);
    assert_eq!(
        descriptor.reasoner.as_str(),
        format!(
            "{}{}",
            cdb_backend_fluree::backend_identity::REASONER_PREFIX,
            cdb_backend_fluree::current_reasoning_profile::CURRENT_REASONING_PROFILE_ID
        )
    );
    assert_eq!(
        descriptor.materializer.as_str(),
        "ctxql-fluree-authorized-union/current-4.2.1-supported-reasoning/v1"
    );

    let second = reason_authorized_manifest(&manifest, SandboxLimits::default())
        .await
        .unwrap();
    assert_eq!(first.inferred_facts, second.inferred_facts);
    assert_eq!(first.prepared_root, second.prepared_root);
    assert_eq!(first.diagnostics, second.diagnostics);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compound_blank_node_structure_is_mapped_and_reasoned_exactly() {
    let rdf_first = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
    let rdf_rest = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
    let rdf_nil = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";
    let chain = "http://www.w3.org/2002/07/owl#propertyChainAxiom";
    let schema = BTreeSet::from([
        iri_quad(G, G, RDF_TYPE, OWL_ONTOLOGY),
        SourceQuad {
            graph: G.into(),
            subject: RdfNodeId::Iri("urn:p:ancestor".into()),
            predicate: chain.into(),
            object: ExactTerm::ScopedBlankNode("_:fdb-head".into()),
        },
        SourceQuad {
            graph: G.into(),
            subject: RdfNodeId::ScopedBlankNode("_:fdb-head".into()),
            predicate: rdf_first.into(),
            object: ExactTerm::Iri("urn:p:parent".into()),
        },
        SourceQuad {
            graph: G.into(),
            subject: RdfNodeId::ScopedBlankNode("_:fdb-head".into()),
            predicate: rdf_rest.into(),
            object: ExactTerm::ScopedBlankNode("_:fdb-tail".into()),
        },
        SourceQuad {
            graph: G.into(),
            subject: RdfNodeId::ScopedBlankNode("_:fdb-tail".into()),
            predicate: rdf_first.into(),
            object: ExactTerm::Iri("urn:p:parent".into()),
        },
        SourceQuad {
            graph: G.into(),
            subject: RdfNodeId::ScopedBlankNode("_:fdb-tail".into()),
            predicate: rdf_rest.into(),
            object: ExactTerm::Iri(rdf_nil.into()),
        },
    ]);
    let data = BTreeSet::from([
        iri_quad(
            "urn:graph:data",
            "urn:entity:a",
            "urn:p:parent",
            "urn:entity:b",
        ),
        iri_quad(
            "urn:graph:data",
            "urn:entity:b",
            "urn:p:parent",
            "urn:entity:c",
        ),
    ]);
    let manifest = manifest_with_schema(data, schema);
    assert!(manifest
        .reasoner_input_quads
        .iter()
        .all(|quad| quad.subject_iri().is_some()
            && !matches!(quad.object, ExactTerm::ScopedBlankNode(_))));
    let prepared = reason_authorized_manifest(&manifest, SandboxLimits::default())
        .await
        .unwrap();
    assert!(
        prepared.inferred_facts.contains(&PreparedFact {
            subject: "urn:entity:a".into(),
            predicate: "urn:p:ancestor".into(),
            object: ExactTerm::Iri("urn:entity:c".into()),
        }),
        "prepared reasoning result: {prepared:?}; input: {:?}",
        manifest.reasoner_input_quads
    );
    assert!(prepared.inferred_facts.iter().all(|fact| {
        !fact.subject.starts_with("urn:ctxql:sandbox-struct:")
            && fact
                .object
                .as_iri()
                .is_none_or(|value| !value.starts_with("urn:ctxql:sandbox-struct:"))
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_cardinality_integer_family_matches_native_materialization() {
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
    let mut schema = BTreeSet::from([iri_quad(G, G, RDF_TYPE, OWL_ONTOLOGY)]);
    let mut data = BTreeSet::new();
    for (index, datatype) in datatypes.into_iter().enumerate() {
        let restriction = format!("urn:class:cardinality:{index}");
        let property = format!("urn:p:cardinality:{index}");
        schema.insert(iri_quad(
            G,
            &restriction,
            RDF_TYPE,
            "http://www.w3.org/2002/07/owl#Restriction",
        ));
        schema.insert(iri_quad(
            G,
            &restriction,
            "http://www.w3.org/2002/07/owl#onProperty",
            &property,
        ));
        schema.insert(SourceQuad {
            graph: G.into(),
            subject: RdfNodeId::Iri(restriction.clone()),
            predicate: "http://www.w3.org/2002/07/owl#maxCardinality".into(),
            object: ExactTerm::Literal {
                lexical: "1".into(),
                datatype: format!("http://www.w3.org/2001/XMLSchema#{datatype}"),
                language: None,
            },
        });
        let subject = format!("urn:entity:cardinality:{index}");
        data.insert(iri_quad("urn:graph:data", &subject, RDF_TYPE, &restriction));
        data.insert(iri_quad(
            "urn:graph:data",
            &subject,
            &property,
            &format!("urn:object:{index}:a"),
        ));
        data.insert(iri_quad(
            "urn:graph:data",
            &subject,
            &property,
            &format!("urn:object:{index}:b"),
        ));
    }
    let manifest = manifest_with_schema(data, schema);
    let prepared = reason_authorized_manifest(&manifest, SandboxLimits::default())
        .await
        .unwrap();
    for index in 0..datatypes.len() {
        let left = format!("urn:object:{index}:a");
        let right = format!("urn:object:{index}:b");
        assert!(
            prepared.inferred_iri_triples.contains(&(
                left.clone(),
                "http://www.w3.org/2002/07/owl#sameAs".into(),
                right.clone(),
            )) || prepared.inferred_iri_triples.contains(&(
                right,
                "http://www.w3.org/2002/07/owl#sameAs".into(),
                left,
            )),
            "production C0 did not materialize datatype index {index}"
        );
    }
}

#[test]
fn authored_structural_namespace_is_rejected_without_suppressing_generated_nodes() {
    let capture = SemanticCaptureDescriptor {
        ledger: "ctxql/p5-6-structural-prefix:main".into(),
        requested_as_of: "t:1".into(),
        t: 1,
        commit_cid: "bafy-p5-6-structural-prefix".into(),
    };
    let reserved = format!("{STRUCTURAL_NODE_IRI_PREFIX}authored");
    let ordinary = "urn:ordinary";
    let cases = [
        SourceQuad {
            graph: "urn:graph:data".into(),
            subject: RdfNodeId::Iri(reserved.clone()),
            predicate: "urn:p".into(),
            object: ExactTerm::Iri(ordinary.into()),
        },
        SourceQuad {
            graph: "urn:graph:data".into(),
            subject: RdfNodeId::Iri(ordinary.into()),
            predicate: reserved.clone(),
            object: ExactTerm::Iri(ordinary.into()),
        },
        SourceQuad {
            graph: "urn:graph:data".into(),
            subject: RdfNodeId::Iri(ordinary.into()),
            predicate: "urn:p".into(),
            object: ExactTerm::Iri(reserved.clone()),
        },
        SourceQuad {
            graph: reserved.clone(),
            subject: RdfNodeId::Iri(ordinary.into()),
            predicate: "urn:p".into(),
            object: ExactTerm::Iri(ordinary.into()),
        },
    ];
    for authored in cases {
        let error = build_reasoner_input(&capture, &BTreeSet::from([authored]), &BTreeSet::new())
            .expect_err("the sandbox structural namespace is backend-reserved");
        assert_eq!(error, "structural_node_mapping_collision");
    }

    let structural = BTreeSet::from([SourceQuad {
        graph: G.into(),
        subject: RdfNodeId::ScopedBlankNode("_:fdb-generated".into()),
        predicate: "urn:p:structural".into(),
        object: ExactTerm::Iri(ordinary.into()),
    }]);
    let generated = build_reasoner_input(&capture, &BTreeSet::new(), &structural).unwrap();
    assert!(generated.iter().any(|quad| quad
        .subject
        .as_iri()
        .is_some_and(|value| value.starts_with(STRUCTURAL_NODE_IRI_PREFIX))));

    let mut sealed = manifest(BTreeSet::from([iri_quad(
        "urn:graph:data",
        "urn:entity",
        "urn:p:narrow",
        "urn:object",
    )]));
    sealed.data_quads.insert(SourceQuad {
        graph: "urn:graph:data".into(),
        subject: RdfNodeId::Iri(reserved),
        predicate: "urn:p".into(),
        object: ExactTerm::Iri(ordinary.into()),
    });
    assert_eq!(
        sealed.validate().unwrap_err(),
        "structural_node_mapping_collision"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archival_profile_identity_is_decodable_but_never_executed_as_current() {
    let mut archival = manifest(BTreeSet::new());
    archival.ontology_profile.identity =
        cdb_backend_fluree::ontology_profile_v2::ONTOLOGY_PROFILE_V2_ID.into();
    let error = reason_authorized_manifest(&archival, SandboxLimits::default())
        .await
        .expect_err("603974f profile must not run through the 4.2.1 executor");
    assert_eq!(error.kind, cdb_core::ErrorKind::Unsupported);
    assert_eq!(
        error.message,
        cdb_backend_fluree::backend_identity::HISTORICAL_EXECUTOR_UNAVAILABLE
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manifest_mutation_is_rejected_before_materialization() {
    let mut manifest = manifest(BTreeSet::new());
    manifest.reasoner_input_root = ContentHash::of_bytes(b"mutated");
    let error = reason_authorized_manifest(&manifest, SandboxLimits::default())
        .await
        .expect_err("mutated protected input must fail");
    assert_eq!(error.kind, cdb_core::ErrorKind::Invalid);
}
