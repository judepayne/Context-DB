mod support;

use cdb_backend_fluree::{
    authorized_view::{AuthorizedViewManifest, ExactTerm, SourceQuad},
    reasoning_sandbox::{reason_authorized_manifest, SandboxLimits},
    semantic_policy::SemanticPolicyMode,
    semantic_preparation::{
        export_historical_semantic_records, prepare_historical_authorized_view, ExtractionLimits,
    },
    FlureeSemanticLedger, SemanticLedgerOptions,
};
use cdb_core::{
    admission::ExportRecord,
    contracts::SemanticProjectionSource,
    id::{AuthorityId, BackendId, GraphId},
    snapshot::PageSize,
};
use fluree_db_api::{Fluree, FlureeBuilder, LedgerState, Novelty};
use fluree_db_core::LedgerSnapshot;
use fluree_db_reasoner::ReasoningBudget;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

const NS: &str = "https://ctxql.example/semantic-rdf/v1/";
const EX: &str = "http://example.org/";
const CLAIMS: &str = "http://example.org/graphs/claims";
const DATA: &str = "http://example.org/graphs/data";
const SCHEMA_A: &str = "http://example.org/graphs/schema-a";
const SCHEMA_B: &str = "http://example.org/graphs/schema-b";
const POLICY: &str = "http://example.org/graphs/policy";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

fn genesis(ledger: &str) -> LedgerState {
    LedgerState::new(LedgerSnapshot::genesis(ledger), Novelty::new(0))
}

async fn trig(fluree: &Fluree, state: LedgerState, value: &str) -> LedgerState {
    fluree
        .stage_owned(state)
        .upsert_turtle(value)
        .execute()
        .await
        .unwrap()
        .ledger
}

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

fn options(ledger: &str) -> SemanticLedgerOptions {
    SemanticLedgerOptions {
        backend: BackendId::new("fluree:semantic").unwrap(),
        authority: AuthorityId::new("semantic:authority").unwrap(),
        ledger: GraphId::new(ledger).unwrap(),
    }
}

#[test]
fn historical_preparation_is_source_exact_and_hidden_sibling_noninterfering() {
    std::thread::Builder::new()
        .name("p5-5-semantic-preparation".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(historical_preparation_is_source_exact_impl());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn historical_preparation_is_source_exact_impl() {
    let fluree = Arc::new(FlureeBuilder::memory().build_memory());
    let ledger_id = "ctxql/p5-5-production-e0:main";
    let config_graph = format!("urn:fluree:{ledger_id}#config");
    let state = trig(
        &fluree,
        genesis(ledger_id),
        &format!(
            r#"
            @prefix f: <https://ns.flur.ee/db#> .
            @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
            @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
            @prefix owl: <http://www.w3.org/2002/07/owl#> .
            @prefix ex: <{EX}> .
            @prefix ctxql: <{NS}> .
            GRAPH <{config_graph}> {{
              <urn:config> rdf:type f:LedgerConfig ;
                f:reasoningDefaults <urn:reasoning> ;
                f:policyDefaults <urn:policy-defaults> ;
                ctxql:governedDataGraph <{CLAIMS}>, <{DATA}> ;
                ctxql:claimGraph <{CLAIMS}> ;
                ctxql:infrastructureGraph <{SCHEMA_A}>, <{SCHEMA_B}> .
              <urn:reasoning> f:reasoningModes f:owl2rl ;
                f:schemaSource <urn:schema-ref> ; f:followOwlImports true .
              <urn:schema-ref> rdf:type f:GraphRef ; f:graphSource <urn:schema-source> .
              <urn:schema-source> f:graphSelector <{SCHEMA_A}> .
              <urn:policy-defaults> f:defaultAllow true ;
                f:policySource <urn:policy-ref> .
              <urn:policy-ref> rdf:type f:GraphRef ; f:graphSource <urn:policy-source> .
              <urn:policy-source> f:graphSelector <{POLICY}> .
            }}
            GRAPH <{POLICY}> {{
              <did:example:alice> f:policyClass ex:E0Policy .
              <did:example:bob> f:policyClass ex:OtherPolicy .
              <urn:deny-hidden> rdf:type f:AccessPolicy, ex:E0Policy ; f:action f:view ;
                f:onSubject <{EX}claim/hidden>, <{EX}claim/hidden-extra> ; f:allow false .
            }}
            GRAPH <{SCHEMA_A}> {{ <{SCHEMA_A}> rdf:type owl:Ontology ; owl:imports <{SCHEMA_B}> . }}
            GRAPH <{SCHEMA_B}> {{ <{SCHEMA_B}> rdf:type owl:Ontology . ex:Manager rdfs:subClassOf ex:Person . }}
            GRAPH <{DATA}> {{ ex:alice rdf:type ex:Manager . }}
            "#
        ),
    )
    .await;
    let first = fluree
        .insert(
            state,
            &json!({
                "@context": {
                    "ex": EX,
                    "ctxql": NS,
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#"
                },
                "@graph": [
                    {"@id": "ex:alice", "@graph": CLAIMS, "ex:knows": {
                        "@id": "ex:bob", "@annotation": annotation("ex:claim/visible")
                    }},
                    {"@id": "ex:alice", "@graph": CLAIMS, "ex:knows": {
                        "@id": "ex:bob", "@annotation": annotation("ex:claim/hidden")
                    }}
                ]
            }),
        )
        .await
        .unwrap()
        .ledger;
    let second = fluree
        .insert(
            first.clone(),
            &json!({
                "@context": {
                    "ex": EX,
                    "ctxql": NS,
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#"
                },
                "@id": "ex:alice",
                "@graph": CLAIMS,
                "ex:knows": {"@id": "ex:bob", "@annotation": annotation("ex:claim/hidden-extra")}
            }),
        )
        .await
        .unwrap()
        .ledger;

    let reader = FlureeSemanticLedger::open(Arc::clone(&fluree), options(ledger_id))
        .await
        .unwrap();
    let first_capture = reader.capture_at_t(first.t(), None, None).await.unwrap();
    let second_capture = reader.capture_at_t(second.t(), None, None).await.unwrap();
    let one = prepare_historical_authorized_view(
        &reader,
        &first_capture,
        "did:example:alice",
        "ctxql:query",
        ExtractionLimits::default(),
    )
    .await
    .unwrap();
    let two = prepare_historical_authorized_view(
        &reader,
        &second_capture,
        "did:example:alice",
        "ctxql:query",
        ExtractionLimits::default(),
    )
    .await
    .unwrap();
    let batched_limits = ExtractionLimits {
        page_size: 1,
        ..ExtractionLimits::default()
    };
    let differently_batched = prepare_historical_authorized_view(
        &reader,
        &first_capture,
        "did:example:alice",
        "ctxql:query",
        batched_limits,
    )
    .await
    .unwrap();
    assert_ne!(
        one.operational_stats(),
        differently_batched.operational_stats()
    );
    assert_eq!(
        one.manifest.authorized_premise_root,
        differently_batched.manifest.authorized_premise_root
    );
    assert_eq!(
        one.manifest.execution_manifest_root,
        differently_batched.manifest.execution_manifest_root
    );
    let mut different_completeness = ExtractionLimits::default();
    different_completeness.max_rows += 1;
    let differently_bounded = prepare_historical_authorized_view(
        &reader,
        &first_capture,
        "did:example:alice",
        "ctxql:query",
        different_completeness,
    )
    .await
    .unwrap();
    assert_eq!(
        one.manifest.authorized_premise_root,
        differently_bounded.manifest.authorized_premise_root
    );
    assert_ne!(
        one.manifest.execution_manifest_root,
        differently_bounded.manifest.execution_manifest_root
    );
    let mut changed_data = one.manifest.data_quads.clone();
    changed_data.insert(SourceQuad {
        graph: DATA.into(),
        subject: format!("{EX}carol").into(),
        predicate: RDF_TYPE.into(),
        object: ExactTerm::Iri(format!("{EX}Person")),
    });
    let member_changed = AuthorizedViewManifest::seal(
        one.manifest.capture.clone(),
        one.manifest.reasoning.clone(),
        changed_data,
        one.manifest.schema_quads.clone(),
        one.manifest.visible_supports.clone(),
        one.manifest.historical_config_root.clone(),
        one.manifest.policy_dependency_root.clone(),
        &one.manifest.protected_completeness,
    );
    assert_ne!(
        one.manifest.authorized_premise_root,
        member_changed.authorized_premise_root
    );
    assert_ne!(
        one.manifest.execution_manifest_root,
        member_changed.execution_manifest_root
    );

    assert_eq!(one.manifest.data_quads, two.manifest.data_quads);
    assert_eq!(one.manifest.schema_quads, two.manifest.schema_quads);
    assert_eq!(one.manifest.visible_supports, two.manifest.visible_supports);
    assert_eq!(
        one.manifest.authorized_counts,
        two.manifest.authorized_counts
    );
    assert_eq!(
        one.manifest.authorized_premise_root,
        two.manifest.authorized_premise_root
    );
    assert_ne!(
        one.manifest.execution_manifest_root,
        two.manifest.execution_manifest_root
    );
    assert!(one
        .manifest
        .visible_supports
        .contains(&format!("{EX}claim/visible")));
    assert!(!one
        .manifest
        .visible_supports
        .contains(&format!("{EX}claim/hidden")));
    assert_eq!(one.authorized_claims.len(), 1);
    assert_eq!(one.policy_basis.mode, SemanticPolicyMode::Configured);

    let bob = prepare_historical_authorized_view(
        &reader,
        &first_capture,
        "did:example:bob",
        "ctxql:query",
        ExtractionLimits::default(),
    )
    .await
    .unwrap();
    assert!(bob
        .manifest
        .visible_supports
        .contains(&format!("{EX}claim/hidden")));
    assert_eq!(bob.authorized_claims.len(), 2);
    assert_ne!(
        one.manifest.authorized_premise_root, bob.manifest.authorized_premise_root,
        "the verified principal must select its own same-ledger policy"
    );

    // Production E0 output is the only C0 input. Policy/configuration RDF,
    // claim metadata and hidden support identities are not sandbox premises;
    // harmless ontology declarations remain bundle commitments only.
    assert!(one
        .manifest
        .data_quads
        .iter()
        .all(|quad| quad.graph != POLICY && quad.graph != config_graph));
    assert!(one
        .manifest
        .data_quads
        .iter()
        .all(|quad| !quad.subject.as_source_label().contains("claim/hidden")));
    assert!(one.manifest.schema_quads.iter().all(|quad| {
        quad.predicate != RDF_TYPE
            || quad.object == ExactTerm::Iri("http://www.w3.org/2002/07/owl#Ontology".into())
    }));
    let sandbox_limits = || SandboxLimits {
        max_input_facts: 1_024,
        max_input_bytes: 1_024 * 1_024,
        materialization_timeout: Duration::from_secs(2),
        reasoning: ReasoningBudget::new(Duration::from_secs(2), 1_024, 1_024 * 1_024),
        budget_identity: "seconds=2;facts=1024;memory=1048576".into(),
    };
    let current_one = support::seal_for_current_reasoner(&one.manifest);
    let prepared_one = reason_authorized_manifest(&current_one, sandbox_limits())
        .await
        .unwrap();
    assert!(prepared_one.has_type(&format!("{EX}alice"), &format!("{EX}Person")));

    // A separately opened production reader must construct byte-identical E0
    // roots and deterministic C0 results from the same exact capture.
    let independent_reader = FlureeSemanticLedger::open(Arc::clone(&fluree), options(ledger_id))
        .await
        .unwrap();
    let independent_capture = independent_reader
        .capture_at_t(first.t(), None, None)
        .await
        .unwrap();
    let independent = prepare_historical_authorized_view(
        &independent_reader,
        &independent_capture,
        "did:example:alice",
        "ctxql:query",
        ExtractionLimits::default(),
    )
    .await
    .unwrap();
    let current_independent = support::seal_for_current_reasoner(&independent.manifest);
    let prepared_independent = reason_authorized_manifest(&current_independent, sandbox_limits())
        .await
        .unwrap();
    assert_eq!(one.manifest, independent.manifest);
    assert_eq!(
        prepared_one.prepared_root,
        prepared_independent.prepared_root
    );
    assert_eq!(
        prepared_one.inferred_iri_triples,
        prepared_independent.inferred_iri_triples
    );

    let complete_one =
        export_historical_semantic_records(&reader, &first_capture, ExtractionLimits::default())
            .await
            .unwrap();
    let complete_two =
        export_historical_semantic_records(&reader, &second_capture, ExtractionLimits::default())
            .await
            .unwrap();
    assert_eq!(complete_one.len(), 2);
    assert_eq!(complete_two.len(), 3);
    let current_projection_capture = SemanticProjectionSource::capture(&reader, None)
        .await
        .unwrap();
    assert_eq!(
        current_projection_capture.snapshot,
        *second_capture.snapshot()
    );
    assert!(current_projection_capture.as_of.millis() > 1_700_000_000_000);
    assert!(
        SemanticProjectionSource::capture(&reader, Some(current_projection_capture.as_of))
            .await
            .is_err()
    );
    let projection_snapshot =
        SemanticProjectionSource::open_snapshot(&reader, second_capture.snapshot())
            .await
            .unwrap();
    assert_eq!(projection_snapshot.identity(), second_capture.snapshot());
    let page = projection_snapshot
        .export(None, PageSize::new(10).unwrap())
        .await
        .unwrap();
    assert!(page.complete());
    assert_eq!(page.items(), complete_two);
    assert!(complete_two.iter().any(|record| {
        matches!(record, ExportRecord::Claim(claim) if claim.id().as_str() == format!("{EX}claim/hidden-extra"))
    }));
    let ExportRecord::Claim(claim) = &one.authorized_claims[0] else {
        panic!("expected proposition claim");
    };
    assert_eq!(claim.id().as_str(), format!("{EX}claim/visible"));
    assert!(
        claim.transaction_time().millis() > 1_700_000_000_000,
        "claim transaction time must come from Fluree commit history, not an epoch placeholder"
    );

    // Ontology infrastructure is authorized as one source-authoritative
    // bundle. Hiding even a harmless member denies the closure rather than
    // pruning an axiom and continuing with a principal-specific ontology.
    trig(
        &fluree,
        second,
        &format!(
            r#"@prefix f: <https://ns.flur.ee/db#> .
               @prefix ex: <{EX}> .
               GRAPH <{POLICY}> {{
                 <urn:deny-schema-member> a f:AccessPolicy, ex:E0Policy ;
                   f:action f:view ; f:onSubject <{SCHEMA_B}> ; f:allow false .
               }}"#
        ),
    )
    .await;
    assert_eq!(
        prepare_historical_authorized_view(
            &reader,
            &first_capture,
            "did:example:alice",
            "ctxql:query",
            ExtractionLimits::default(),
        )
        .await
        .unwrap_err(),
        "ontology_authorization_denied"
    );
}

async fn minimal_claim_ledger(fluree: &Fluree, ledger_id: &str) -> LedgerState {
    let config_graph = format!("urn:fluree:{ledger_id}#config");
    trig(
        fluree,
        genesis(ledger_id),
        &format!(
            r#"
            @prefix f: <https://ns.flur.ee/db#> .
            @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
            @prefix owl: <http://www.w3.org/2002/07/owl#> .
            @prefix ctxql: <{NS}> .
            GRAPH <{config_graph}> {{
              <urn:config> rdf:type f:LedgerConfig ;
                f:reasoningDefaults <urn:reasoning> ;
                f:policyDefaults <urn:policy-defaults> ;
                ctxql:governedDataGraph <{CLAIMS}> ;
                ctxql:claimGraph <{CLAIMS}> ;
                ctxql:infrastructureGraph <{SCHEMA_A}> .
              <urn:reasoning> f:reasoningModes f:owl2rl ;
                f:schemaSource <urn:schema-ref> ; f:followOwlImports false .
              <urn:schema-ref> rdf:type f:GraphRef ; f:graphSource <urn:schema-source> .
              <urn:schema-source> f:graphSelector <{SCHEMA_A}> .
              <urn:policy-defaults> f:defaultAllow true ; f:policyClass <{EX}LifecyclePolicy> ;
                f:policySource <urn:policy-ref> .
              <urn:policy-ref> rdf:type f:GraphRef ; f:graphSource <urn:policy-source> .
              <urn:policy-source> f:graphSelector <{POLICY}> .
            }}
            GRAPH <{POLICY}> {{
              <urn:deny-hidden-lifecycle> rdf:type f:AccessPolicy, <{EX}LifecyclePolicy> ;
                f:action f:view ; f:onSubject <{EX}claim/contradiction> ; f:allow false .
            }}
            GRAPH <{SCHEMA_A}> {{ <{SCHEMA_A}> rdf:type owl:Ontology . }}
            "#
        ),
    )
    .await
}

#[tokio::test]
async fn detached_superseded_claim_reconstructs_original_attachment_and_time_once() {
    let fluree = Arc::new(FlureeBuilder::memory().build_memory());
    let ledger_id = "ctxql/p5-5-detached-superseded:main";
    let state = minimal_claim_ledger(&fluree, ledger_id).await;
    let asserted = fluree
        .insert(
            state,
            &json!({
                "@context": {
                    "ex": EX, "ctxql": NS,
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#"
                },
                "@graph": [
                    {"@id": "ex:alice", "@graph": CLAIMS, "ex:knows": {
                        "@id": "ex:bob", "@annotation": annotation("ex:claim/original")
                    }},
                    {"@id": "ex:alice", "@graph": CLAIMS, "ex:knows": {
                        "@id": "ex:bob", "@annotation": annotation("ex:claim/replacement")
                    }}
                ]
            }),
        )
        .await
        .unwrap()
        .ledger;
    let transitioned = fluree
        .update(
            asserted,
            &json!({
                "@context": {
                    "ex": EX, "ctxql": NS,
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#"
                },
                "delete": {
                    "@id": "ex:alice", "@graph": CLAIMS, "ex:knows": {
                        "@id": "ex:bob", "@annotation": {"@id": "ex:claim/original"}
                    }
                },
                "insert": {
                    "@id": "ex:claim/original", "@graph": CLAIMS,
                    "ctxql:superseded_by": {
                        "@id": "ex:claim/replacement",
                        "@annotation": annotation("ex:claim/supersession")
                    }
                }
            }),
        )
        .await
        .unwrap()
        .ledger;
    let contradicted = fluree
        .insert(
            transitioned.clone(),
            &json!({
                "@context": {
                    "ex": EX, "ctxql": NS,
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#"
                },
                "@id": "ex:claim/replacement", "@graph": CLAIMS,
                "ctxql:contradicted_by": {
                    "@id": "ex:claim/original",
                    "@annotation": annotation("ex:claim/contradiction")
                }
            }),
        )
        .await
        .unwrap()
        .ledger;
    let reader = FlureeSemanticLedger::open(Arc::clone(&fluree), options(ledger_id))
        .await
        .unwrap();
    let capture = reader
        .capture_at_t(contradicted.t(), None, None)
        .await
        .unwrap();
    let records =
        export_historical_semantic_records(&reader, &capture, ExtractionLimits::default())
            .await
            .unwrap();
    assert_eq!(
        records.len(),
        4,
        "lifecycle claims are exported only by their wrappers"
    );
    let original = records
        .iter()
        .find_map(|record| match record {
            ExportRecord::Claim(claim) if claim.id().as_str() == format!("{EX}claim/original") => {
                Some(claim)
            }
            _ => None,
        })
        .expect("detached original claim");
    let lifecycle = records
        .iter()
        .find_map(|record| match record {
            ExportRecord::Lifecycle {
                assertion,
                transaction_time,
            } if assertion.candidate().relation().as_str() == "ctxql:superseded_by" => {
                Some((assertion, transaction_time))
            }
            _ => None,
        })
        .expect("supersession lifecycle");
    assert_eq!(lifecycle.0.target().as_str(), original.id().as_str());
    assert!(original.transaction_time() < *lifecycle.1);

    let before_capture = reader
        .capture_at_t(transitioned.t(), None, None)
        .await
        .unwrap();
    let before = prepare_historical_authorized_view(
        &reader,
        &before_capture,
        "did:example:alice",
        "ctxql:query",
        ExtractionLimits::default(),
    )
    .await
    .unwrap();
    let after = prepare_historical_authorized_view(
        &reader,
        &capture,
        "did:example:alice",
        "ctxql:query",
        ExtractionLimits::default(),
    )
    .await
    .unwrap();
    assert!(!after
        .manifest
        .visible_supports
        .contains(&format!("{EX}claim/contradiction")));
    assert!(before
        .manifest
        .visible_supports
        .contains(&format!("{EX}claim/supersession")));
    assert!(before.manifest.data_quads.iter().all(|quad| {
        ![
            format!("{NS}superseded_by"),
            format!("{NS}retracted_by"),
            format!("{NS}contradicted_by"),
        ]
        .contains(&quad.predicate)
    }));
    assert_eq!(
        before.manifest.authorized_premise_root, after.manifest.authorized_premise_root,
        "a wholly hidden lifecycle assertion cannot change authorized premises"
    );
    assert_ne!(
        before.manifest.execution_manifest_root, after.manifest.execution_manifest_root,
        "the protected root still binds the later exact capture"
    );
}

#[tokio::test]
async fn final_support_retraction_requires_base_edge_cascade_in_transition_transaction() {
    let fluree = Arc::new(FlureeBuilder::memory().build_memory());
    let ledger_id = "ctxql/p5-5-detached-retracted:main";
    let state = minimal_claim_ledger(&fluree, ledger_id).await;
    let asserted = fluree
        .insert(
            state,
            &json!({
                "@context": {
                    "ex": EX, "ctxql": NS,
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#"
                },
                "@id": "ex:alice", "@graph": CLAIMS,
                "ex:knows": {
                    "@id": "ex:bob", "@annotation": annotation("ex:claim/final")
                }
            }),
        )
        .await
        .unwrap()
        .ledger;
    let transitioned = fluree
        .update(
            asserted,
            &json!({
                "@context": {
                    "ex": EX, "ctxql": NS,
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#"
                },
                "delete": {
                    "@id": "ex:alice", "@graph": CLAIMS,
                    "ex:knows": {"@id": "ex:bob"}
                },
                "insert": {
                    "@id": "ex:claim/final", "@graph": CLAIMS,
                    "ctxql:retracted_by": {
                        "@id": "ex:event/retraction",
                        "@annotation": annotation("ex:claim/retraction")
                    }
                }
            }),
        )
        .await
        .unwrap()
        .ledger;
    let reader = FlureeSemanticLedger::open(Arc::clone(&fluree), options(ledger_id))
        .await
        .unwrap();
    let capture = reader
        .capture_at_t(transitioned.t(), None, None)
        .await
        .unwrap();
    let records =
        export_historical_semantic_records(&reader, &capture, ExtractionLimits::default())
            .await
            .unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| {
        matches!(record, ExportRecord::Claim(claim) if claim.id().as_str() == format!("{EX}claim/final"))
    }));
    assert!(records.iter().any(|record| {
        matches!(record, ExportRecord::Lifecycle { assertion, .. }
            if assertion.candidate().relation().as_str() == "ctxql:retracted_by"
                && assertion.target().as_str() == format!("{EX}claim/final"))
    }));
}
