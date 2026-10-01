use cdb_backend_fluree::semantic_codec::{
    decode_claim, ExactRdfTerm, MetadataFact, RdfClaimDocument, SemanticCodecLimits, NS,
};
use cdb_core::{admission::ExportRecord, Timestamp};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_JSON: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON";
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";

fn iri(graph: &str, local: &str, value: &str) -> MetadataFact {
    MetadataFact {
        graph: graph.into(),
        predicate: if local == "type" {
            RDF_TYPE.into()
        } else {
            format!("{NS}{local}")
        },
        object: ExactRdfTerm::Iri(value.into()),
    }
}

fn literal(graph: &str, local: &str, lexical: &str, datatype: &str) -> MetadataFact {
    MetadataFact {
        graph: graph.into(),
        predicate: format!("{NS}{local}"),
        object: ExactRdfTerm::Literal {
            lexical: lexical.into(),
            datatype: datatype.into(),
            language: None,
        },
    }
}

fn document(predicate: &str, object: ExactRdfTerm) -> RdfClaimDocument {
    let graph = "urn:graph:claims";
    RdfClaimDocument {
        graph: graph.into(),
        claim_iri: "urn:claim:1".into(),
        subject_iri: "urn:entity:alice".into(),
        predicate_iri: predicate.into(),
        object,
        metadata: vec![
            iri(graph, "type", &format!("{NS}Claim")),
            iri(graph, "relationType", "urn:type:Relation"),
            iri(graph, "subjectType", "urn:type:Entity"),
            iri(graph, "objectType", "urn:type:Entity"),
            iri(graph, "claimType", "urn:type:Assertion"),
            literal(graph, "confidence", "0.800", &format!("{XSD}decimal")),
            iri(graph, "groundingLevel", &format!("{NS}ClaimOnly")),
            literal(
                graph,
                "lineage",
                r#"{"schema":"ctxql.lineage.v1","sources":[]}"#,
                RDF_JSON,
            ),
            literal(graph, "extensions", "{}", RDF_JSON),
        ],
        attachment_transaction_time: Timestamp::parse("2026-09-16T12:00:00.000Z").unwrap(),
    }
}

#[test]
fn strict_codec_emits_one_exact_claim_record() {
    let record = decode_claim(
        &document(
            "urn:relation:knows",
            ExactRdfTerm::Literal {
                lexical: "bonjour".into(),
                datatype: "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString".into(),
                language: Some("fr".into()),
            },
        ),
        SemanticCodecLimits::default(),
    )
    .unwrap();
    let ExportRecord::Claim(claim) = record else {
        panic!("ordinary claim must not become lifecycle");
    };
    assert_eq!(claim.id().as_str(), "urn:claim:1");
    assert_eq!(
        claim.transaction_time().canonical(),
        "2026-09-16T12:00:00.000Z"
    );
}

#[test]
fn asserted_type_storage_edge_decodes_as_rdf_type() {
    let record = decode_claim(
        &document(
            &format!("{NS}assertedType"),
            ExactRdfTerm::Iri("urn:type:organization".into()),
        ),
        SemanticCodecLimits::default(),
    )
    .unwrap();
    let ExportRecord::Claim(claim) = record else {
        panic!("type assertion must remain a claim");
    };
    assert_eq!(claim.candidate().relation().as_str(), RDF_TYPE);
}

#[test]
fn lifecycle_claim_emits_only_lifecycle_record() {
    let mut input = document(
        &format!("{NS}superseded_by"),
        ExactRdfTerm::Iri("urn:claim:replacement".into()),
    );
    input.subject_iri = "urn:claim:target".into();
    let record = decode_claim(&input, SemanticCodecLimits::default()).unwrap();
    let ExportRecord::Lifecycle { assertion, .. } = record else {
        panic!("lifecycle claim must not be duplicated as an ordinary claim");
    };
    assert_eq!(assertion.target().as_str(), "urn:claim:target");
    assert_eq!(
        assertion.referenced_claim().unwrap().as_str(),
        "urn:claim:replacement"
    );
}

#[test]
fn marked_malformed_claims_fail_closed() {
    let mut duplicate = document(
        "urn:relation:knows",
        ExactRdfTerm::Iri("urn:entity:bob".into()),
    );
    duplicate.metadata.push(iri(
        "urn:graph:claims",
        "claimType",
        "urn:type:OtherAssertion",
    ));
    assert_eq!(
        decode_claim(&duplicate, SemanticCodecLimits::default())
            .unwrap_err()
            .message,
        "claim_profile_invalid"
    );

    let mut noncanonical = document(
        "urn:relation:knows",
        ExactRdfTerm::Iri("urn:entity:bob".into()),
    );
    let extensions = noncanonical
        .metadata
        .iter_mut()
        .find(|fact| fact.predicate == format!("{NS}extensions"))
        .unwrap();
    extensions.object = ExactRdfTerm::Literal {
        lexical: "{ }".into(),
        datatype: RDF_JSON.into(),
        language: None,
    };
    assert_eq!(
        decode_claim(&noncanonical, SemanticCodecLimits::default())
            .unwrap_err()
            .message,
        "claim_profile_invalid"
    );
}
