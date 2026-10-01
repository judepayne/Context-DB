//! Trusted, test-only Semantic Ledger fixture writer.
//!
//! Production service code must only open this ledger through its read-only
//! semantic adapter. Keeping creation here prevents a semantic mutation handle
//! from becoming part of either the service or backend public API.
use serde_json::{json, Value};
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticHead {
    pub t: i64,
    pub cid: Option<String>,
}

pub const LEDGER: &str = "semantic:public-parity";
pub const EX: &str = "http://example.org/";
pub const VISIBLE_CLAIM: &str = "http://example.org/claim/visible";
pub const HIDDEN_CLAIM: &str = "http://example.org/claim/hidden";

fn annotation(id: &str) -> Value {
    json!({
        "@id": id,
        "@type": "ctxql:Claim",
        "ctxql:relationType": {"@id": "ex:SocialRelation"},
        "ctxql:subjectType": {"@id": "ex:Person"},
        "ctxql:objectType": {"@id": "ex:Person"},
        "ctxql:claimType": {"@id": "ex:Observed"},
        "ctxql:confidence": {"@value": "0.800", "@type": "xsd:decimal"},
        "ctxql:groundingLevel": {"@id": "ctxql:SourceLineageAvailable"},
        "ctxql:lineage": {"@value": "{\"schema\":\"ctxql.lineage.v1\",\"sources\":[{\"kind\":\"urn:ctxql:source-kind\",\"source_id\":\"source-1\"}]}", "@type": "rdf:JSON"},
        "ctxql:extensions": {"@value": "{}", "@type": "rdf:JSON"}
    })
}

pub fn instance_config(_root: &Path) -> String {
    format!(
        r#"schema="ctxql-instance/v3"
projection="projection"
credential-file="credentials.json"
source-root="sources"
[semantic]
path="semantic"
ledger="{LEDGER}"
backend="semantic-public"
authority="semantic-public-authority"
graph="semantic-public-graph"
[control]
path="control"
ledger="control:public-parity"
backend="control-public"
authority="control-public-authority"
graph="control-public-graph"
[limits]
deadline_seconds=120
session_ttl_seconds=300
"#
    )
}

pub async fn write_trusted_semantic_fixture(root: &Path) -> SemanticHead {
    let writer =
        fluree_db_api::FlureeBuilder::file(root.join("semantic").to_string_lossy().into_owned())
            .without_indexing()
            .build()
            .expect("semantic fixture store");
    let ledger = writer
        .create_ledger(LEDGER)
        .await
        .expect("semantic fixture ledger");
    let config_graph = fluree_db_core::graph_registry::config_graph_iri(LEDGER);
    let fixture = format!(
        r#"@prefix ctxql: <https://ctxql.example/semantic-rdf/v1/> .
@prefix f: <https://ns.flur.ee/db#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix ex: <{EX}> .
GRAPH <{config_graph}> {{
  <urn:config> rdf:type f:LedgerConfig ;
    f:reasoningDefaults <urn:reasoning> ;
    f:policyDefaults <urn:policy-defaults> ;
    ctxql:governedDataGraph <urn:claims>, <urn:data> ;
    ctxql:claimGraph <urn:claims> ;
    ctxql:infrastructureGraph <urn:schema> .
  <urn:reasoning> f:reasoningModes f:owl2rl ;
    f:schemaSource <urn:schema-ref> ; f:followOwlImports true .
  <urn:schema-ref> rdf:type f:GraphRef ; f:graphSource <urn:schema-source> .
  <urn:schema-source> f:graphSelector <urn:schema> .
  <urn:policy-defaults> f:defaultAllow true ; f:policyClass ex:PublicPolicy ;
    f:policySource <urn:policy-ref> .
  <urn:policy-ref> rdf:type f:GraphRef ; f:graphSource <urn:policy-source> .
  <urn:policy-source> f:graphSelector <urn:policy> .
}}
GRAPH <urn:policy> {{
  <urn:deny-hidden> rdf:type f:AccessPolicy, ex:PublicPolicy ; f:action f:view ;
    f:onSubject <{HIDDEN_CLAIM}> ; f:allow false .
}}
GRAPH <urn:claims> {{ <urn:claim-placeholder> <urn:unused> <urn:value> . }}
GRAPH <urn:data> {{ ex:alice <urn:p:stored> <urn:value:stored> . }}
GRAPH <urn:schema> {{
  <urn:schema> rdf:type owl:Ontology .
  <urn:p:stored> rdfs:subPropertyOf <urn:p:reasoned> .
}}"#
    );
    let ledger = writer
        .stage_owned(ledger)
        .upsert_turtle(&fixture)
        .execute()
        .await
        .expect("trusted semantic fixture transaction")
        .ledger;
    let ledger = writer
        .insert(
            ledger,
            &json!({
                "@context": {
                    "ex": EX,
                    "ctxql": "https://ctxql.example/semantic-rdf/v1/",
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#"
                },
                "@graph": [
                    {"@id": "ex:alice", "@graph": "urn:claims", "ex:knows": {
                        "@id": "ex:bob", "@annotation": annotation(VISIBLE_CLAIM)
                    }},
                    {"@id": "ex:alice", "@graph": "urn:claims", "ex:knows": {
                        "@id": "ex:mallory", "@annotation": annotation(HIDDEN_CLAIM)
                    }}
                ]
            }),
        )
        .await
        .expect("trusted annotated claims transaction")
        .ledger;
    SemanticHead {
        t: ledger.t(),
        cid: ledger.head_commit_id.as_ref().map(ToString::to_string),
    }
}

#[allow(dead_code)]
pub async fn write_later_granted_claim(root: &Path) -> SemanticHead {
    let writer =
        fluree_db_api::FlureeBuilder::file(root.join("semantic").to_string_lossy().into_owned())
            .without_indexing()
            .build()
            .expect("semantic fixture writer");
    let ledger = writer
        .ledger(LEDGER)
        .await
        .expect("semantic fixture ledger");
    let ledger = writer
        .insert(
            ledger,
            &json!({
                "@context": {
                    "ex": EX,
                    "ctxql": "https://ctxql.example/semantic-rdf/v1/",
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#"
                },
                "@id": "ex:alice",
                "@graph": "urn:claims",
                "ex:knows": {
                    "@id": "ex:carol",
                    "@annotation": annotation("http://example.org/claim/later-granted")
                }
            }),
        )
        .await
        .expect("trusted later grant transaction")
        .ledger;
    SemanticHead {
        t: ledger.t(),
        cid: ledger.head_commit_id.as_ref().map(ToString::to_string),
    }
}

#[allow(dead_code)]
pub async fn revoke_visible_claim(root: &Path) -> SemanticHead {
    let writer =
        fluree_db_api::FlureeBuilder::file(root.join("semantic").to_string_lossy().into_owned())
            .without_indexing()
            .build()
            .expect("semantic fixture writer");
    let ledger = writer
        .ledger(LEDGER)
        .await
        .expect("semantic fixture ledger");
    let ledger = writer
        .stage_owned(ledger)
        .upsert_turtle(&format!(
            r#"@prefix f: <https://ns.flur.ee/db#> .
@prefix ex: <{EX}> .
GRAPH <urn:policy> {{
  <urn:deny-visible-later> a f:AccessPolicy, ex:PublicPolicy ; f:action f:view ;
    f:onSubject <{VISIBLE_CLAIM}> ; f:allow false .
}}"#
        ))
        .execute()
        .await
        .expect("trusted current revocation transaction")
        .ledger;
    SemanticHead {
        t: ledger.t(),
        cid: ledger.head_commit_id.as_ref().map(ToString::to_string),
    }
}

pub async fn read_semantic_head(root: &Path) -> SemanticHead {
    let reader =
        fluree_db_api::FlureeBuilder::file(root.join("semantic").to_string_lossy().into_owned())
            .without_indexing()
            .build()
            .expect("semantic fixture reader");
    let ledger = reader
        .ledger(LEDGER)
        .await
        .expect("semantic fixture ledger");
    SemanticHead {
        t: ledger.t(),
        cid: ledger.head_commit_id.as_ref().map(ToString::to_string),
    }
}
