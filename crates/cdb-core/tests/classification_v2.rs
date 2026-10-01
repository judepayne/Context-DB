use cdb_core::{
    claim::CandidateClaim,
    classification::{
        ClassificationMetadata, ClassificationOrigin, ClassificationRef, EndpointClassification,
        EndpointClassificationStatus, EXTENSION_KEY, RDFS_CLASS, UNCLASSIFIED_ENTITY,
    },
    id::{ContentHash, Iri, ResourceId},
    CanonicalValue as V, Limits,
};

fn obj<const N: usize>(fields: [(&str, V); N]) -> V {
    V::object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value)),
    )
    .unwrap()
}

fn entry(iri: &str, reference: &str) -> ClassificationRef {
    ClassificationRef::new(
        Iri::new(iri).unwrap(),
        ClassificationOrigin::Extracted,
        ResourceId::new(reference).unwrap(),
    )
}

fn endpoint(
    status: EndpointClassificationStatus,
    classes: Vec<ClassificationRef>,
) -> EndpointClassification {
    EndpointClassification::new(status, classes).unwrap()
}

fn metadata(
    subject: EndpointClassification,
    object: EndpointClassification,
) -> ClassificationMetadata {
    ClassificationMetadata::new(
        ContentHash::of_bytes(b"frozen leaf evaluation"),
        subject,
        object,
    )
}

fn relation_claim(
    metadata: ClassificationMetadata,
    subject_type: &str,
    object_type: &str,
) -> CandidateClaim {
    let value = obj([
        ("claim_id", V::string("urn:claim:relation")),
        ("subject_id", V::string("urn:entity:subject")),
        ("relation", V::string("urn:relation:borrower")),
        ("object_id", V::string("urn:entity:object")),
        ("relation_type", V::string("urn:type:relation")),
        ("subject_type", V::string(subject_type)),
        ("object_type", V::string(object_type)),
        ("claim_type", V::string("urn:type:claim")),
        ("confidence", V::Number(cdb_core::ExactNumber::from_u64(1))),
        ("grounding_level", V::string("claim_only")),
        ("ext", obj([(EXTENSION_KEY, metadata.projection())])),
    ]);
    CandidateClaim::from_value(&value).unwrap()
}

#[test]
fn two_classes_have_order_independent_representative_and_bytes() {
    let z = entry("urn:class:Z", "window:1#class:z");
    let a = entry("urn:class:A", "window:1#class:a");
    let left = metadata(
        endpoint(
            EndpointClassificationStatus::Classified,
            vec![z.clone(), a.clone()],
        ),
        endpoint(EndpointClassificationStatus::Unclassified, vec![]),
    );
    let right = metadata(
        endpoint(EndpointClassificationStatus::Classified, vec![a, z]),
        endpoint(EndpointClassificationStatus::Unclassified, vec![]),
    );
    assert_eq!(left, right);
    assert_eq!(left.subject().representative(), "urn:class:A");
    assert_eq!(
        left.projection()
            .canonical_bytes(Limits::default())
            .unwrap(),
        right
            .projection()
            .canonical_bytes(Limits::default())
            .unwrap()
    );
}

#[test]
fn unclassified_entity_endpoints_are_valid_without_type_assertions() {
    let claim = relation_claim(
        metadata(
            endpoint(EndpointClassificationStatus::Unclassified, vec![]),
            endpoint(EndpointClassificationStatus::Unclassified, vec![]),
        ),
        UNCLASSIFIED_ENTITY,
        UNCLASSIFIED_ENTITY,
    );
    let parsed = claim.classification_metadata().unwrap().unwrap();
    assert!(parsed.subject().classes().is_empty());
    assert!(parsed.object().classes().is_empty());
}

#[test]
fn classification_is_frozen_in_prior_canonical_claim_bytes() {
    let prior = relation_claim(
        metadata(
            endpoint(
                EndpointClassificationStatus::Classified,
                vec![entry("urn:class:B", "passage:1#b")],
            ),
            endpoint(EndpointClassificationStatus::Unclassified, vec![]),
        ),
        "urn:class:B",
        UNCLASSIFIED_ENTITY,
    );
    let prior_bytes = prior
        .projection()
        .canonical_bytes(Limits::default())
        .unwrap();
    let _later = relation_claim(
        metadata(
            endpoint(
                EndpointClassificationStatus::Classified,
                vec![
                    entry("urn:class:A", "passage:2#a"),
                    entry("urn:class:B", "passage:1#b"),
                ],
            ),
            endpoint(EndpointClassificationStatus::Unclassified, vec![]),
        ),
        "urn:class:A",
        UNCLASSIFIED_ENTITY,
    );
    assert_eq!(
        prior_bytes,
        prior
            .projection()
            .canonical_bytes(Limits::default())
            .unwrap()
    );
}

#[test]
fn closed_metadata_rejects_unsorted_or_unknown_content() {
    let mut value = metadata(
        endpoint(
            EndpointClassificationStatus::Classified,
            vec![entry("urn:class:A", "component:a")],
        ),
        endpoint(EndpointClassificationStatus::Unclassified, vec![]),
    )
    .projection();
    let V::Object(root) = &mut value else {
        panic!("metadata object")
    };
    root.insert("extra".into(), V::Null);
    assert!(ClassificationMetadata::from_value(&value).is_err());

    let mut value = metadata(
        endpoint(
            EndpointClassificationStatus::Classified,
            vec![entry("urn:class:A", "component:a")],
        ),
        endpoint(EndpointClassificationStatus::Unclassified, vec![]),
    )
    .projection();
    let V::Object(root) = &mut value else {
        panic!("metadata object")
    };
    let V::Object(subject) = root.get_mut("subject").unwrap() else {
        panic!("subject")
    };
    let V::Array(classes) = subject.get_mut("classes").unwrap() else {
        panic!("classes")
    };
    classes.push(entry("urn:class:0", "component:0").projection());
    assert!(ClassificationMetadata::from_value(&value).is_err());
}

#[test]
fn explicit_type_object_uses_rdfs_class_metadata_not_business_classification() {
    let metadata = metadata(
        endpoint(
            EndpointClassificationStatus::Classified,
            vec![entry("urn:class:A", "component:a")],
        ),
        endpoint(EndpointClassificationStatus::Unclassified, vec![]),
    );
    let value = obj([
        ("claim_id", V::string("urn:claim:type")),
        ("subject_id", V::string("urn:entity:subject")),
        (
            "relation",
            V::string("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
        ),
        ("object_id", V::string("urn:class:A")),
        ("relation_type", V::string("urn:type:relation")),
        ("subject_type", V::string("urn:class:A")),
        ("object_type", V::string(RDFS_CLASS)),
        ("claim_type", V::string("urn:type:claim")),
        ("confidence", V::Number(cdb_core::ExactNumber::from_u64(1))),
        ("grounding_level", V::string("claim_only")),
        ("ext", obj([(EXTENSION_KEY, metadata.projection())])),
    ]);
    assert!(CandidateClaim::from_value(&value).is_ok());
}
