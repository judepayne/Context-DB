use cdb_backend_fluree::semantic_codec::{
    decode_claim, encode_bundle, ExactRdfTerm, MetadataFact, RdfClaimDocument, SemanticCodecLimits,
    NS,
};
use cdb_core::{admission::ExportRecord, claim::CandidateClaim, CanonicalValue, Limits, Timestamp};
use fluree_db_api::{Fluree, FlureeBuilder, GraphDb, LedgerState, Novelty};
use fluree_db_core::LedgerSnapshot;
use serde_json::Value;

const GRAPH: &str = "urn:ctxql:p6:claims";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_JSON: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON";
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";

fn candidate(id: &str, subject: &str, object: &str, relation: &str) -> CandidateClaim {
    let json = format!(
        r#"{{"claim_id":"{id}","claim_type":"urn:type:claim","confidence":0.875,"ext":{{"ctxql.p6.bundle":"bundle-1"}},"grounding_level":"claim_only","lineage":{{"schema":"ctxql.lineage.v1","sources":[]}},"object_id":"{object}","object_type":"urn:type:entity","relation":"{relation}","relation_type":"urn:type:relation","subject_id":"{subject}","subject_type":"urn:type:entity"}}"#
    );
    let value = CanonicalValue::parse(json.as_bytes(), Limits::default()).unwrap();
    CandidateClaim::from_value(&value).unwrap()
}

async fn sparql(fluree: &Fluree, ledger: &LedgerState, query: &str) -> Value {
    fluree
        .query(&GraphDb::from_ledger_state(ledger), query)
        .await
        .unwrap()
        .to_sparql_json(&ledger.snapshot)
        .unwrap()
}

fn bound(row: &Value, name: &str) -> String {
    row[name]["value"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn rdf_type_claim_uses_native_type_plus_annotatable_storage_edge() {
    let class = "urn:type:organization";
    let expected = candidate("urn:claim:type-one", "urn:entity:typed", class, RDF_TYPE);
    let transaction = encode_bundle(
        std::slice::from_ref(&expected),
        GRAPH,
        SemanticCodecLimits::default(),
    )
    .unwrap();
    let fluree = FlureeBuilder::memory().build_memory();
    let genesis = LedgerState::new(LedgerSnapshot::genesis("p6-r1-type:main"), Novelty::new(0));
    let committed = fluree.insert(genesis, &transaction).await.unwrap().ledger;

    let native = sparql(
        &fluree,
        &committed,
        &format!("SELECT ?class WHERE {{ GRAPH <{GRAPH}> {{ <urn:entity:typed> a ?class . }} }}"),
    )
    .await;
    assert_eq!(native["results"]["bindings"][0]["class"]["value"], class);

    let annotated = sparql(
        &fluree,
        &committed,
        &format!(
            "PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> SELECT ?p WHERE {{ GRAPH <{GRAPH}> {{ <urn:claim:type-one> rdf:reifies <<( <urn:entity:typed> ?p <{class}> )>> . }} }}"
        ),
    )
    .await;
    assert_eq!(
        annotated["results"]["bindings"][0]["p"]["value"],
        format!("{NS}assertedType")
    );
}

#[tokio::test]
async fn connected_bundle_is_one_transaction_and_exactly_decodes_after_lost_ack() {
    let expected = vec![
        candidate(
            "urn:claim:one",
            "urn:entity:a",
            "urn:entity:b",
            "urn:relation:knows",
        ),
        candidate(
            "urn:claim:two",
            "urn:entity:b",
            "urn:entity:c",
            "urn:relation:owns",
        ),
    ];
    let transaction = encode_bundle(&expected, GRAPH, SemanticCodecLimits::default()).unwrap();
    let fluree = FlureeBuilder::memory().build_memory();
    let genesis = LedgerState::new(LedgerSnapshot::genesis("p6-r1:main"), Novelty::new(0));

    // This is the only semantic write: a complete connected bundle is one
    // native transaction. Treat the returned acknowledgement as lost below.
    let committed = fluree.insert(genesis, &transaction).await.unwrap().ledger;
    assert_eq!(committed.t(), 1);
    let committed_cid = committed.head_commit_id.clone().unwrap();

    let query = format!(
        r#"
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        PREFIX c: <{NS}>
        SELECT ?claim ?s ?p ?o ?relationType ?subjectType ?objectType ?claimType
               ?confidence ?grounding ?lineage ?extensions
        WHERE {{
          GRAPH <{GRAPH}> {{
            ?claim rdf:reifies <<( ?s ?p ?o )>> ;
              rdf:type c:Claim ;
              c:relationType ?relationType ;
              c:subjectType ?subjectType ;
              c:objectType ?objectType ;
              c:claimType ?claimType ;
              c:confidence ?confidence ;
              c:groundingLevel ?grounding ;
              c:lineage ?lineage ;
              c:extensions ?extensions .
          }}
        }} ORDER BY ?claim
        "#
    );
    let rows = sparql(&fluree, &committed, &query).await;
    let rows = rows["results"]["bindings"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "no partial bundle may be visible");

    let observed = rows
        .iter()
        .map(|row| {
            let claim = bound(row, "claim");
            let metadata = vec![
                MetadataFact {
                    graph: GRAPH.into(),
                    predicate: RDF_TYPE.into(),
                    object: ExactRdfTerm::Iri(format!("{NS}Claim")),
                },
                MetadataFact {
                    graph: GRAPH.into(),
                    predicate: format!("{NS}relationType"),
                    object: ExactRdfTerm::Iri(bound(row, "relationType")),
                },
                MetadataFact {
                    graph: GRAPH.into(),
                    predicate: format!("{NS}subjectType"),
                    object: ExactRdfTerm::Iri(bound(row, "subjectType")),
                },
                MetadataFact {
                    graph: GRAPH.into(),
                    predicate: format!("{NS}objectType"),
                    object: ExactRdfTerm::Iri(bound(row, "objectType")),
                },
                MetadataFact {
                    graph: GRAPH.into(),
                    predicate: format!("{NS}claimType"),
                    object: ExactRdfTerm::Iri(bound(row, "claimType")),
                },
                MetadataFact {
                    graph: GRAPH.into(),
                    predicate: format!("{NS}confidence"),
                    object: ExactRdfTerm::Literal {
                        lexical: bound(row, "confidence"),
                        datatype: format!("{XSD}decimal"),
                        language: None,
                    },
                },
                MetadataFact {
                    graph: GRAPH.into(),
                    predicate: format!("{NS}groundingLevel"),
                    object: ExactRdfTerm::Iri(bound(row, "grounding")),
                },
                MetadataFact {
                    graph: GRAPH.into(),
                    predicate: format!("{NS}lineage"),
                    object: ExactRdfTerm::Literal {
                        lexical: bound(row, "lineage"),
                        datatype: RDF_JSON.into(),
                        language: None,
                    },
                },
                MetadataFact {
                    graph: GRAPH.into(),
                    predicate: format!("{NS}extensions"),
                    object: ExactRdfTerm::Literal {
                        lexical: bound(row, "extensions"),
                        datatype: RDF_JSON.into(),
                        language: None,
                    },
                },
            ];
            let document = RdfClaimDocument {
                graph: GRAPH.into(),
                claim_iri: claim,
                subject_iri: bound(row, "s"),
                predicate_iri: bound(row, "p"),
                object: ExactRdfTerm::Iri(bound(row, "o")),
                metadata,
                attachment_transaction_time: Timestamp::parse("2026-09-22T00:00:00.000Z").unwrap(),
            };
            match decode_claim(&document, SemanticCodecLimits::default()).unwrap() {
                ExportRecord::Claim(claim) => claim.candidate().clone(),
                _ => panic!("ordinary claim decoded as a non-claim record"),
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        observed, expected,
        "canonical readback must equal pre-write claims"
    );

    // Lost-ack recovery uses exact immutable history rather than blind retry:
    // the original transaction and CID remain resolvable and contain both IDs.
    let detail = fluree
        .graph("p6-r1:main")
        .commit_t(1)
        .execute()
        .await
        .unwrap();
    assert_eq!(detail.id, committed_cid.to_string());
    let history_claims = detail
        .flakes
        .iter()
        .filter(|flake| flake.p.contains("reifiesSubject"))
        .count();
    assert_eq!(history_claims, 2);
}
