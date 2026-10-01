use cdb_backend_fluree::semantic_codec::{
    decode_claim, encode_claim, ExactRdfTerm, MetadataFact, RdfClaimDocument, SemanticCodecLimits,
    NS,
};
use cdb_core::{
    admission::ExportRecord,
    claim::CandidateClaim,
    classification::{EXTENSION_KEY, REPRESENTATIVE_ALGORITHM, UNCLASSIFIED_ENTITY},
    CanonicalValue as V, Limits, Timestamp,
};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_JSON: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON";
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";

fn extension() -> String {
    format!(
        r#"{{"{EXTENSION_KEY}":{{"frozen_context_root":"sha256:94417d92c6558068b6adf9a6a088eea1456f5e31f76cc18e529f943f434b3e24","object":{{"classes":[],"status":"unclassified"}},"representative_algorithm":"{REPRESENTATIVE_ALGORITHM}","subject":{{"classes":[],"status":"unclassified"}}}}}}"#
    )
}

fn candidate() -> CandidateClaim {
    let json = format!(
        r#"{{"claim_id":"urn:claim:classification","subject_id":"urn:entity:a","relation":"urn:relation:connected","object_id":"urn:entity:b","relation_type":"urn:type:relation","subject_type":"{UNCLASSIFIED_ENTITY}","object_type":"{UNCLASSIFIED_ENTITY}","claim_type":"urn:type:claim","confidence":1,"grounding_level":"claim_only","ext":{}}}"#,
        extension()
    );
    CandidateClaim::from_value(&V::parse(json.as_bytes(), Limits::default()).unwrap()).unwrap()
}

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

#[test]
fn unclassified_marker_is_annotation_only_and_codec_roundtrips_metadata() {
    let claim = candidate();
    let encoded = encode_claim(&claim, "urn:graph:claims", SemanticCodecLimits::default()).unwrap();
    assert!(
        encoded.get("@type").is_none(),
        "representative marker became a native type"
    );

    let graph = "urn:graph:claims";
    let document = RdfClaimDocument {
        graph: graph.into(),
        claim_iri: claim.id().as_str().into(),
        subject_iri: claim.subject().as_str().into(),
        predicate_iri: claim.relation().as_str().into(),
        object: ExactRdfTerm::Iri("urn:entity:b".into()),
        metadata: vec![
            iri(graph, "type", &format!("{NS}Claim")),
            iri(graph, "relationType", "urn:type:relation"),
            iri(graph, "subjectType", UNCLASSIFIED_ENTITY),
            iri(graph, "objectType", UNCLASSIFIED_ENTITY),
            iri(graph, "claimType", "urn:type:claim"),
            literal(graph, "confidence", "1", &format!("{XSD}decimal")),
            iri(graph, "groundingLevel", &format!("{NS}ClaimOnly")),
            literal(
                graph,
                "lineage",
                r#"{"schema":"ctxql.lineage.v1","sources":[]}"#,
                RDF_JSON,
            ),
            literal(graph, "extensions", &extension(), RDF_JSON),
        ],
        attachment_transaction_time: Timestamp::parse("2026-09-26T00:00:00.000Z").unwrap(),
    };
    let ExportRecord::Claim(decoded) =
        decode_claim(&document, SemanticCodecLimits::default()).unwrap()
    else {
        panic!("ordinary claim")
    };
    assert_eq!(
        decoded
            .candidate()
            .projection()
            .canonical_bytes(Limits::default())
            .unwrap(),
        claim
            .projection()
            .canonical_bytes(Limits::default())
            .unwrap()
    );
}
