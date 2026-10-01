use cdb_backend_fluree::{
    semantic_preparation::{
        export_historical_semantic_records, prepare_historical_authorized_view, ExtractionLimits,
    },
    FlureeSemanticLedger, SemanticLedgerOptions,
};
use cdb_core::id::{AuthorityId, BackendId, GraphId};
use fluree_db_api::{Fluree, FlureeBuilder, LedgerState, Novelty};
use fluree_db_core::LedgerSnapshot;
use std::sync::Arc;

const NS: &str = "https://ctxql.example/semantic-rdf/v1/";
const CLAIMS: &str = "urn:p6:graph:claims";
const DATA: &str = "urn:p6:graph:data";
const REVIEW: &str = "urn:p6:graph:review";
const SCHEMA: &str = "urn:p6:graph:schema";
const POLICY: &str = "urn:p6:graph:policy";
const REJECTED: &str = "urn:p6:rejected-proposal";
const REJECTED_PREDICATE: &str = "urn:p6:must-not-be-a-business-predicate";

fn options(ledger: &str) -> SemanticLedgerOptions {
    SemanticLedgerOptions {
        backend: BackendId::new("fluree:semantic").unwrap(),
        authority: AuthorityId::new("semantic:authority").unwrap(),
        ledger: GraphId::new(ledger).unwrap(),
    }
}

async fn fixture(review_role: &str) -> (Arc<Fluree>, LedgerState, String) {
    let ledger_id = "ctxql/p6-review-graph-isolation:main";
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
            @prefix ctxql: <{NS}> .
            GRAPH <{config_graph}> {{
              <urn:p6:config> rdf:type f:LedgerConfig ;
                f:reasoningDefaults <urn:p6:reasoning> ;
                f:policyDefaults <urn:p6:policy-defaults> ;
                ctxql:governedDataGraph <{CLAIMS}>, <{DATA}> ;
                ctxql:claimGraph <{CLAIMS}> ;
                ctxql:reviewGraph <{review_role}> ;
                ctxql:infrastructureGraph <{SCHEMA}> .
              <urn:p6:reasoning> f:reasoningModes f:owl2rl ;
                f:schemaSource <urn:p6:schema-ref> ; f:followOwlImports false .
              <urn:p6:schema-ref> rdf:type f:GraphRef ; f:graphSource <urn:p6:schema-source> .
              <urn:p6:schema-source> f:graphSelector <{SCHEMA}> .
              <urn:p6:policy-defaults> f:defaultAllow true ; f:policySource <urn:p6:policy-ref> .
              <urn:p6:policy-ref> rdf:type f:GraphRef ; f:graphSource <urn:p6:policy-source> .
              <urn:p6:policy-source> f:graphSelector <{POLICY}> .
            }}
            GRAPH <{POLICY}> {{ <did:example:review-test> f:policyClass <urn:p6:Policy> . }}
            GRAPH <{SCHEMA}> {{ <{SCHEMA}> rdf:type owl:Ontology . }}
            GRAPH <{CLAIMS}> {{ <urn:p6:claim-graph-sentinel> <urn:p6:sentinel> "claim" . }}
            GRAPH <{DATA}> {{ <urn:p6:business> <urn:p6:name> "business" . }}
            GRAPH <{REVIEW}> {{
              <{REJECTED}> rdf:type ctxql:Claim ;
                <{REJECTED_PREDICATE}> <urn:p6:secret-review-object> .
            }}
            "#
        ))
        .execute()
        .await
        .unwrap()
        .ledger;
    (fluree, state, ledger_id.to_owned())
}

#[tokio::test]
async fn review_role_never_enters_business_preparation_reasoning_or_export() {
    let (fluree, state, ledger_id) = fixture(REVIEW).await;
    let reader = FlureeSemanticLedger::open(Arc::clone(&fluree), options(&ledger_id))
        .await
        .unwrap();
    let capture = reader.capture_at_t(state.t(), None, None).await.unwrap();

    let prepared = prepare_historical_authorized_view(
        &reader,
        &capture,
        "did:example:review-test",
        "https://ns.flur.ee/db#view",
        ExtractionLimits::default(),
    )
    .await
    .unwrap();

    assert_eq!(
        prepared.review_graphs,
        [REVIEW.to_owned()].into_iter().collect()
    );
    assert!(!prepared.governed_data_graphs.contains(REVIEW));
    assert!(!prepared.claim_graphs.contains(REVIEW));
    for quad in prepared
        .manifest
        .data_quads
        .iter()
        .chain(&prepared.manifest.schema_quads)
        .chain(&prepared.manifest.reasoner_input_quads)
    {
        assert_ne!(quad.graph, REVIEW);
        assert_ne!(quad.subject.as_iri(), Some(REJECTED));
        assert_ne!(quad.predicate, REJECTED_PREDICATE);
    }

    let exported =
        export_historical_semantic_records(&reader, &capture, ExtractionLimits::default())
            .await
            .unwrap();
    assert!(
        exported.is_empty(),
        "review records are not business exports"
    );
}

#[tokio::test]
async fn review_role_overlap_with_any_business_or_infrastructure_role_fails_closed() {
    let config_graph = "urn:fluree:ctxql/p6-review-graph-isolation:main#config";
    for overlapping_role in [DATA, CLAIMS, SCHEMA, config_graph] {
        let (fluree, state, ledger_id) = fixture(overlapping_role).await;
        let reader = FlureeSemanticLedger::open(fluree, options(&ledger_id))
            .await
            .unwrap();
        let capture = reader.capture_at_t(state.t(), None, None).await.unwrap();
        assert_eq!(
            prepare_historical_authorized_view(
                &reader,
                &capture,
                "did:example:review-test",
                "https://ns.flur.ee/db#view",
                ExtractionLimits::default(),
            )
            .await
            .unwrap_err(),
            "graph_role_map_invalid",
            "overlap with {overlapping_role} must fail preparation",
        );
        assert_eq!(
            export_historical_semantic_records(&reader, &capture, ExtractionLimits::default())
                .await
                .unwrap_err(),
            "graph_role_map_invalid",
            "overlap with {overlapping_role} must fail business export",
        );
    }
}
