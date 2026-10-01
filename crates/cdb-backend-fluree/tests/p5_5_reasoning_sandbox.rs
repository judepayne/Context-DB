mod support;

use cdb_backend_fluree::{
    authorized_view::{
        framed_root, AuthorizedViewManifest, ExactTerm, ReasoningDescriptor,
        SemanticCaptureDescriptor, SourceQuad,
    },
    reasoning_sandbox::{reason_authorized_manifest, SandboxLimits},
};
use cdb_core::{
    id::{AuthorityId, BackendId, GraphId, ResourceId, VersionId},
    snapshot::{GraphPin, SnapshotRef},
};
use fluree_db_reasoner::ReasoningBudget;
use std::{collections::BTreeSet, time::Duration};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDFS_SUBCLASS: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
const OWL_ONTOLOGY: &str = "http://www.w3.org/2002/07/owl#Ontology";

fn iri(graph: &str, subject: &str, predicate: &str, object: &str) -> SourceQuad {
    SourceQuad {
        graph: graph.into(),
        subject: subject.into(),
        predicate: predicate.into(),
        object: ExactTerm::Iri(object.into()),
    }
}

#[tokio::test]
async fn manifest_only_reasoning_freezes_portable_descriptor_and_local_indexes() {
    let schema = "http://example.org/schema";
    let data = "http://example.org/data";
    let manager = "http://example.org/Manager";
    let person = "http://example.org/Person";
    let alice = "http://example.org/alice";
    let manifest = AuthorizedViewManifest::seal(
        SemanticCaptureDescriptor {
            ledger: "semantic:main".into(),
            requested_as_of: "t:1".into(),
            t: 1,
            commit_cid: "bafy-semantic".into(),
        },
        ReasoningDescriptor {
            schema_source: schema.into(),
            follow_owl_imports: false,
            schema_graphs: BTreeSet::from([schema.into()]),
        },
        BTreeSet::from([iri(data, alice, RDF_TYPE, manager)]),
        BTreeSet::from([
            iri(schema, schema, RDF_TYPE, OWL_ONTOLOGY),
            iri(schema, manager, RDFS_SUBCLASS, person),
        ]),
        BTreeSet::new(),
        framed_root("config/v1", [("schema", schema)]),
        framed_root("policy/v1", [("mode", "unrestricted")]),
        "terminal:v1",
    );
    let manifest = support::seal_for_current_reasoner(&manifest);
    let prepared = reason_authorized_manifest(
        &manifest,
        SandboxLimits {
            max_input_facts: 32,
            max_input_bytes: 64 * 1024,
            materialization_timeout: Duration::from_secs(2),
            reasoning: ReasoningBudget::new(Duration::from_secs(2), 1024, 1024 * 1024),
            budget_identity: "seconds=2;facts=1024;memory=1048576".into(),
        },
    )
    .await
    .unwrap();
    assert!(prepared.entails_class(manager, person));
    assert!(prepared.has_type(alice, person));
    assert!(prepared.iri_objects(alice, RDF_TYPE).contains(person));

    let snapshot = SnapshotRef::new(
        BackendId::new("fluree:semantic").unwrap(),
        GraphPin::new(
            AuthorityId::new("semantic:authority").unwrap(),
            GraphId::new("semantic:main").unwrap(),
            VersionId::new("1").unwrap(),
            ResourceId::new("bafy-semantic").unwrap(),
        ),
    );
    let descriptor = prepared.descriptor(snapshot.clone(), &manifest).unwrap();
    assert_eq!(descriptor.capture, snapshot);
    assert_eq!(
        descriptor.authorized_premise_root,
        manifest.authorized_premise_root.0
    );
    assert_eq!(
        descriptor.execution_manifest_root,
        manifest.execution_manifest_root.0
    );
    assert_eq!(descriptor.prepared_root, prepared.prepared_root);
}
