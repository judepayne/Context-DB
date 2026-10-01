use fluree_db_api::{FlureeBuilder, LedgerState, Novelty};
use fluree_db_core::LedgerSnapshot;
use serde_json::json;

fn genesis(ledger: &str) -> LedgerState {
    LedgerState::new(LedgerSnapshot::genesis(ledger), Novelty::new(0))
}

#[tokio::test]
#[ignore = "expected native policy-before-inference failure"]
async fn policy_hidden_premise_must_not_contribute_to_reasoning() {
    let fluree = FlureeBuilder::memory().build_memory();
    let ledger_id = "ctxql/p5-5-gate-e:main";
    let committed = fluree
        .insert(
            genesis(ledger_id),
            &json!({
                "@context": {
                    "ex": "http://example.org/",
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "owl": "http://www.w3.org/2002/07/owl#"
                },
                "@graph": [
                    {"@id": "ex:hasAncestor", "@type": "owl:TransitiveProperty"},
                    {"@id": "ex:alice", "ex:hasAncestor": {"@id": "ex:bob"}},
                    {"@id": "ex:bob", "ex:hasAncestor": {"@id": "ex:carol"}}
                ]
            }),
        )
        .await
        .expect("seed transitive chain")
        .ledger;

    let direct_hidden = json!({
        "@context": {"ex": "http://example.org/", "f": "https://ns.flur.ee/db#"},
        "from": ledger_id,
        "opts": {
            "policy": [{"@id": "ex:deny-bob", "@type": "f:AccessPolicy", "f:action": "f:view",
                "f:onSubject": [{"@id": "http://example.org/bob"}], "f:allow": false}],
            "default-allow": true
        },
        "select": "?o",
        "where": {"@id": "ex:bob", "ex:hasAncestor": "?o"}
    });
    let hidden_result = fluree
        .query_connection(&direct_hidden)
        .await
        .expect("policy query");
    let hidden_json = hidden_result
        .to_jsonld(&committed.snapshot)
        .expect("format hidden result");
    assert_eq!(
        hidden_json,
        json!([]),
        "test policy must hide the second premise"
    );

    let inferred = json!({
        "@context": {"ex": "http://example.org/", "f": "https://ns.flur.ee/db#"},
        "from": ledger_id,
        "opts": {
            "policy": [{"@id": "ex:deny-bob", "@type": "f:AccessPolicy", "f:action": "f:view",
                "f:onSubject": [{"@id": "http://example.org/bob"}], "f:allow": false}],
            "default-allow": true
        },
        "reasoning": "owl2rl",
        "select": "?o",
        "where": {"@id": "ex:alice", "ex:hasAncestor": "?o"}
    });
    let inferred_result = fluree
        .query_connection(&inferred)
        .await
        .expect("policy plus reasoner query");
    let inferred_json = inferred_result
        .to_jsonld(&committed.snapshot)
        .expect("format inferred result");
    let values = inferred_json.as_array().expect("result array");
    assert_eq!(
        values,
        &[json!("ex:bob")],
        "a premise hidden by policy must not derive ex:alice ex:hasAncestor ex:carol"
    );
}
