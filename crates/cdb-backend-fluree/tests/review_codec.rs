use cdb_backend_fluree::review_codec::{
    decode_review, encode_review, ExactReviewTerm, RdfReviewDocument, ReviewCodecLimits,
    ReviewFact, NS, RECORD_MARKER,
};
use cdb_core::{
    id::{ClaimId, ContentHash},
    review::{ReviewAssertionIntent, ReviewRecord, ReviewRecordId, VocabularyVerdict},
};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const GRAPH: &str = "urn:graph:acquisition-review";

fn literal(local: &str, value: &str) -> ReviewFact {
    ReviewFact {
        graph: GRAPH.into(),
        predicate: format!("{NS}{local}"),
        object: ExactReviewTerm::Literal {
            lexical: value.into(),
            datatype: XSD_STRING.into(),
            language: None,
        },
    }
}
fn iri(local: &str, value: &str) -> ReviewFact {
    ReviewFact {
        graph: GRAPH.into(),
        predicate: if local == "type" {
            RDF_TYPE.into()
        } else {
            format!("{NS}{local}")
        },
        object: ExactReviewTerm::Iri(value.into()),
    }
}

fn record() -> ReviewRecord {
    ReviewRecord::new(
        ReviewRecordId::new("urn:review:a3").unwrap(),
        "passage-1/attribute/a3",
        "source:document-06",
        ContentHash::of_bytes(b"outcome-a3"),
        VocabularyVerdict::Valid,
        ReviewAssertionIntent::None,
        vec!["semantic_fit_uncertain".into()],
        vec!["urn:test:acq:effectiveOn".into()],
        vec!["urn:test:acq:CreditAgreement".into()],
        vec!["urn:test:acq:effectiveOn".into()],
        vec!["urn:test:acq:CreditAgreement".into()],
        vec![ClaimId::new("urn:claim:accepted-support").unwrap()],
    )
    .unwrap()
}

#[test]
fn review_codec_roundtrips_exact_fixed_facts() {
    let expected = record();
    let document = RdfReviewDocument {
        graph: GRAPH.into(),
        review_iri: expected.id().as_str().into(),
        facts: vec![
            iri("type", RECORD_MARKER),
            literal("componentRef", expected.component_ref()),
            literal("sourceRef", expected.source_ref()),
            literal("artifactRoot", expected.artifact_root().as_str()),
            literal("vocabularyVerdict", "valid"),
            literal("assertionIntent", "none"),
            literal("reasonCode", "semantic_fit_uncertain"),
            literal("proposedPredicate", "urn:test:acq:effectiveOn"),
            literal("proposedType", "urn:test:acq:CreditAgreement"),
            iri("resolvedPredicate", "urn:test:acq:effectiveOn"),
            iri("resolvedType", "urn:test:acq:CreditAgreement"),
            iri("acceptedClaim", "urn:claim:accepted-support"),
        ],
    };
    assert_eq!(
        decode_review(&document, ReviewCodecLimits::default()).unwrap(),
        expected
    );
}

#[test]
fn suggestions_are_literals_and_never_business_predicates_or_native_types() {
    let encoded = encode_review(&record(), GRAPH, ReviewCodecLimits::default()).unwrap();
    let object = encoded.as_object().unwrap();
    assert_eq!(object.get("@type").unwrap(), RECORD_MARKER);
    assert!(!object.contains_key("urn:test:acq:effectiveOn"));
    assert!(!object.contains_key("urn:test:acq:CreditAgreement"));

    let proposed_predicate = object[&format!("{NS}proposedPredicate")]
        .as_array()
        .unwrap();
    assert_eq!(proposed_predicate[0]["@value"], "urn:test:acq:effectiveOn");
    assert_eq!(proposed_predicate[0]["@type"], XSD_STRING);
    let proposed_type = object[&format!("{NS}proposedType")].as_array().unwrap();
    assert_eq!(proposed_type[0]["@value"], "urn:test:acq:CreditAgreement");
    assert_eq!(object["@type"], RECORD_MARKER);
}

#[test]
fn decoder_rejects_suggested_predicate_encoded_as_an_iri() {
    let mut document = RdfReviewDocument {
        graph: GRAPH.into(),
        review_iri: "urn:review:bad".into(),
        facts: vec![
            iri("type", RECORD_MARKER),
            literal("componentRef", "a2"),
            literal("sourceRef", "source:1"),
            literal("artifactRoot", ContentHash::of_bytes(b"artifact").as_str()),
            literal("vocabularyVerdict", "rejected"),
            literal("assertionIntent", "none"),
            iri("proposedPredicate", "urn:model:suggestion"),
        ],
    };
    assert!(decode_review(&document, ReviewCodecLimits::default()).is_err());
    document.facts.push(iri("type", "urn:model:SuggestedClass"));
    assert!(decode_review(&document, ReviewCodecLimits::default()).is_err());
}
