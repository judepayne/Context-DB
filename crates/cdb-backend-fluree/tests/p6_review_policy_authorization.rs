use cdb_backend_fluree::{
    semantic_preparation::{authorize_review_records, ExtractionLimits},
    FlureeSemanticLedger, SemanticLedgerOptions,
};
use cdb_core::{
    id::{AuthorityId, BackendId, GraphId},
    review::ReviewRecordId,
};
use fluree_db_api::{Fluree, FlureeBuilder, LedgerState, Novelty};
use fluree_db_core::LedgerSnapshot;
use std::sync::Arc;

const NS: &str = "https://ctxql.example/semantic-rdf/v1/";
const REVIEW: &str = "urn:p6:review-policy:review";
const CLAIMS: &str = "urn:p6:review-policy:claims";
const DATA: &str = "urn:p6:review-policy:data";
const SCHEMA: &str = "urn:p6:review-policy:schema";
const POLICY: &str = "urn:p6:review-policy:policy";
const ALLOWED: &str = "urn:p6:review-policy:record:allowed";
const PARTIAL: &str = "urn:p6:review-policy:record:partial";
const PRINCIPAL: &str = "did:example:review-reader";
const VIEW: &str = "https://ns.flur.ee/db#view";

fn options(ledger: &str) -> SemanticLedgerOptions {
    SemanticLedgerOptions {
        backend: BackendId::new("fluree:semantic").unwrap(),
        authority: AuthorityId::new("semantic:authority").unwrap(),
        ledger: GraphId::new(ledger).unwrap(),
    }
}

async fn fixture() -> (Arc<Fluree>, LedgerState, FlureeSemanticLedger) {
    let ledger_id = "ctxql/p6-review-policy:main";
    let config_graph = format!("urn:fluree:{ledger_id}#config");
    let fluree = Arc::new(FlureeBuilder::memory().build_memory());
    let state = fluree
        .stage_owned(LedgerState::new(
            LedgerSnapshot::genesis(ledger_id),
            Novelty::new(0),
        ))
        .upsert_turtle(&format!(
            r#"
            @prefix f: <https://ns.flur.ee/db#> .
            @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
            @prefix owl: <http://www.w3.org/2002/07/owl#> .
            @prefix ex: <urn:p6:review-policy:> .
            @prefix ctxql: <{NS}> .
            GRAPH <{config_graph}> {{
              <urn:p6:config> rdf:type f:LedgerConfig ;
                f:reasoningDefaults <urn:p6:reasoning> ;
                f:policyDefaults <urn:p6:policy-defaults> ;
                ctxql:governedDataGraph <{CLAIMS}>, <{DATA}> ;
                ctxql:claimGraph <{CLAIMS}> ;
                ctxql:reviewGraph <{REVIEW}> ;
                ctxql:infrastructureGraph <{SCHEMA}> .
              <urn:p6:reasoning> f:reasoningModes f:owl2rl ;
                f:schemaSource <urn:p6:schema-ref> ; f:followOwlImports false .
              <urn:p6:schema-ref> rdf:type f:GraphRef ; f:graphSource <urn:p6:schema-source> .
              <urn:p6:schema-source> f:graphSelector <{SCHEMA}> .
              <urn:p6:policy-defaults> f:defaultAllow true ; f:policySource <urn:p6:policy-ref> .
              <urn:p6:policy-ref> rdf:type f:GraphRef ; f:graphSource <urn:p6:policy-source> .
              <urn:p6:policy-source> f:graphSelector <{POLICY}> .
            }}
            GRAPH <{POLICY}> {{
              <{PRINCIPAL}> f:policyClass ex:ReviewPolicy .
              <urn:p6:deny-secret-field> rdf:type f:AccessPolicy, ex:ReviewPolicy ;
                f:action f:view ; f:onProperty ex:secret ; f:allow false .
            }}
            GRAPH <{SCHEMA}> {{ <{SCHEMA}> rdf:type owl:Ontology . }}
            GRAPH <{CLAIMS}> {{ <urn:p6:claim-sentinel> ex:value "claim" . }}
            GRAPH <{DATA}> {{ <urn:p6:data-sentinel> ex:value "data" . }}
            GRAPH <{REVIEW}> {{
              <{ALLOWED}> rdf:type ctxql:ReviewRecord ; ex:public "visible" .
              <{PARTIAL}> rdf:type ctxql:ReviewRecord ; ex:public "visible" ; ex:secret "hidden" .
            }}
            "#
        ))
        .execute()
        .await
        .unwrap()
        .ledger;
    let reader = FlureeSemanticLedger::open(Arc::clone(&fluree), options(ledger_id))
        .await
        .unwrap();
    (fluree, state, reader)
}

fn id(value: &str) -> ReviewRecordId {
    ReviewRecordId::new(value).unwrap()
}

#[tokio::test]
async fn configured_native_policy_allows_only_complete_exact_review_records() {
    let (_fluree, state, reader) = fixture().await;
    let capture = reader.capture_at_t(state.t(), None, None).await.unwrap();

    let allowed = authorize_review_records(
        &reader,
        capture.snapshot(),
        REVIEW,
        &[id(ALLOWED)],
        PRINCIPAL,
        VIEW,
        ExtractionLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(allowed.len(), 2);
    assert!(allowed
        .iter()
        .all(|quad| quad.subject.as_iri() == Some(ALLOWED) && quad.graph == REVIEW));

    let denied = authorize_review_records(
        &reader,
        capture.snapshot(),
        REVIEW,
        &[id(PARTIAL)],
        PRINCIPAL,
        VIEW,
        ExtractionLimits::default(),
    )
    .await
    .unwrap_err();
    let absent = authorize_review_records(
        &reader,
        capture.snapshot(),
        REVIEW,
        &[id("urn:p6:review-policy:record:absent")],
        PRINCIPAL,
        VIEW,
        ExtractionLimits::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(denied, "review_authorization_denied");
    assert_eq!(
        absent, denied,
        "denial must not disclose existence or field counts"
    );
}

#[tokio::test]
async fn current_native_revocation_denies_a_record_at_an_old_receipt() {
    let (fluree, state, reader) = fixture().await;
    let capture = reader.capture_at_t(state.t(), None, None).await.unwrap();
    authorize_review_records(
        &reader,
        capture.snapshot(),
        REVIEW,
        &[id(ALLOWED)],
        PRINCIPAL,
        VIEW,
        ExtractionLimits::default(),
    )
    .await
    .unwrap();

    fluree
        .stage_owned(state)
        .upsert_turtle(&format!(
            r#"
            @prefix f: <https://ns.flur.ee/db#> .
            @prefix ex: <urn:p6:review-policy:> .
            GRAPH <{POLICY}> {{
              <urn:p6:revoke-allowed> a f:AccessPolicy, ex:ReviewPolicy ;
                f:action f:view ; f:onSubject <{ALLOWED}> ; f:allow false .
            }}
            "#
        ))
        .execute()
        .await
        .unwrap();

    assert_eq!(
        authorize_review_records(
            &reader,
            capture.snapshot(),
            REVIEW,
            &[id(ALLOWED)],
            PRINCIPAL,
            VIEW,
            ExtractionLimits::default(),
        )
        .await
        .unwrap_err(),
        "review_authorization_denied"
    );
}
