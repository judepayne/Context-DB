use cdb_backend_fluree::{
    semantic_policy::{
        resolve_current_semantic_authority, verify_semantic_authority_current, SemanticPolicyMode,
    },
    FlureeSemanticLedger, SemanticLedgerOptions,
};
use cdb_core::id::{AuthorityId, BackendId, GraphId};
use fluree_db_api::{Fluree, FlureeBuilder, LedgerState, Novelty};
use fluree_db_core::LedgerSnapshot;
use std::sync::Arc;

fn genesis(ledger: &str) -> LedgerState {
    LedgerState::new(LedgerSnapshot::genesis(ledger), Novelty::new(0))
}

async fn apply(fluree: &Fluree, ledger: LedgerState, trig: &str) -> LedgerState {
    fluree
        .stage_owned(ledger)
        .upsert_turtle(trig)
        .execute()
        .await
        .unwrap()
        .ledger
}

fn options(ledger: &str) -> SemanticLedgerOptions {
    SemanticLedgerOptions {
        backend: BackendId::new("fluree:semantic").unwrap(),
        authority: AuthorityId::new("semantic:authority").unwrap(),
        ledger: GraphId::new(ledger).unwrap(),
    }
}

#[tokio::test]
async fn no_policy_is_explicit_and_configured_policy_is_bound_to_the_same_ledger() {
    let fluree = Arc::new(FlureeBuilder::memory().build_memory());
    let ledger_id = "ctxql/p5-5-policy:main";
    let state = apply(&fluree, genesis(ledger_id), "<urn:s> <urn:p> <urn:o> .").await;
    let reader = FlureeSemanticLedger::open(Arc::clone(&fluree), options(ledger_id))
        .await
        .unwrap();
    exercise_policy_changes(fluree, state, reader).await;
}

#[tokio::test]
async fn file_authority_cache_observes_policy_changes_and_fails_closed_when_missing() {
    let directory = tempfile::tempdir().unwrap();
    let fluree = Arc::new(
        FlureeBuilder::file(directory.path().to_str().unwrap())
            .without_indexing()
            .build()
            .unwrap(),
    );
    let ledger_id = "ctxql/p5-5-policy:main";
    let state = fluree.create_ledger(ledger_id).await.unwrap();
    let state = apply(&fluree, state, "<urn:s> <urn:p> <urn:o> .").await;
    let reader = FlureeSemanticLedger::open_file(directory.path(), options(ledger_id))
        .await
        .unwrap();
    exercise_policy_changes(fluree, state, reader.clone()).await;
    let alice = resolve_current_semantic_authority(&reader, "did:example:alice", "ctxql:query")
        .await
        .unwrap();
    let repeated = resolve_current_semantic_authority(&reader, "did:example:alice", "ctxql:query")
        .await
        .unwrap();
    assert_eq!(alice.basis, repeated.basis);
    assert!(Arc::ptr_eq(
        &alice.enforcer().unwrap(),
        &repeated.enforcer().unwrap()
    ));
    let bob = resolve_current_semantic_authority(&reader, "did:example:bob", "ctxql:query")
        .await
        .unwrap();
    assert_eq!(bob.basis.principal, "did:example:bob");
    let action = resolve_current_semantic_authority(&reader, "did:example:bob", "ctxql:other")
        .await
        .unwrap();
    assert_eq!(action.basis.action, "ctxql:other");
    std::fs::rename(
        directory.path().join("ns@v2"),
        directory.path().join("offline-ns"),
    )
    .unwrap();
    assert!(
        resolve_current_semantic_authority(&reader, "did:example:bob", "ctxql:other")
            .await
            .is_err()
    );
}

async fn exercise_policy_changes(
    fluree: Arc<Fluree>,
    state: LedgerState,
    reader: FlureeSemanticLedger,
) {
    let ledger_id = "ctxql/p5-5-policy:main";
    let unrestricted =
        resolve_current_semantic_authority(&reader, "did:example:alice", "ctxql:query")
            .await
            .unwrap();
    assert_eq!(unrestricted.basis.mode, SemanticPolicyMode::Unrestricted);
    assert!(unrestricted.enforcer().is_none());

    let unrelated = apply(&fluree, state, "<urn:later> <urn:p> <urn:o> .").await;
    let still_unrestricted =
        resolve_current_semantic_authority(&reader, "did:example:alice", "ctxql:query")
            .await
            .unwrap();
    assert_eq!(
        unrestricted.basis.dependency_root,
        still_unrestricted.basis.dependency_root
    );

    let config_graph = format!("urn:fluree:{ledger_id}#config");
    let policy_graph = "http://example.org/graphs/policy";
    let configured_state = apply(
        &fluree,
        unrelated,
        &format!(
            r#"
            @prefix ex: <http://example.org/> .
            @prefix f: <https://ns.flur.ee/db#> .
            @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
            GRAPH <{config_graph}> {{
              <urn:config> rdf:type f:LedgerConfig ; f:policyDefaults <urn:defaults> .
              <urn:defaults> f:defaultAllow true ; f:policyClass ex:Policy ;
                f:policySource <urn:policy-ref> .
              <urn:policy-ref> rdf:type f:GraphRef ; f:graphSource <urn:policy-source> .
              <urn:policy-source> f:graphSelector <{policy_graph}> .
            }}
            GRAPH <{policy_graph}> {{
              <urn:deny> rdf:type f:AccessPolicy, ex:Policy ; f:action f:view ;
                f:onSubject <urn:hidden> ; f:allow false .
            }}
            "#
        ),
    )
    .await;
    let configured =
        resolve_current_semantic_authority(&reader, "did:example:alice", "ctxql:query")
            .await
            .unwrap();
    assert_eq!(configured.basis.mode, SemanticPolicyMode::Configured);
    assert!(configured.enforcer().is_some());
    assert_ne!(
        unrestricted.basis.dependency_root,
        configured.basis.dependency_root
    );
    verify_semantic_authority_current(&reader, &configured.basis)
        .await
        .unwrap();

    // Freshness compares enforcement dependencies, not the moving ledger
    // head. This is the production fence used at extraction and service sinks.
    let unrelated_after_configuration = apply(
        &fluree,
        configured_state,
        "<urn:unrelated-after-policy> <urn:p> <urn:o> .",
    )
    .await;
    verify_semantic_authority_current(&reader, &configured.basis)
        .await
        .unwrap();

    apply(
        &fluree,
        unrelated_after_configuration,
        &format!(
            r#"@prefix f: <https://ns.flur.ee/db#> .
               @prefix ex: <http://example.org/> .
               GRAPH <{policy_graph}> {{
                 <urn:deny-later> a f:AccessPolicy, ex:Policy ; f:action f:view ;
                   f:onSubject <urn:later-hidden> ; f:allow false .
               }}"#
        ),
    )
    .await;
    assert_eq!(
        verify_semantic_authority_current(&reader, &configured.basis).await,
        Err("semantic_policy_changed".into())
    );
}
