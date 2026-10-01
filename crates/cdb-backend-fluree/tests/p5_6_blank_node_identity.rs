use fluree_db_api::{Fluree, FlureeBuilder, LedgerState, NameServiceMode, Novelty};
use fluree_db_core::{
    comparator::IndexType,
    range::{RangeMatch, RangeTest},
    FlakeValue, GraphDbRef, LedgerSnapshot,
};
use fluree_db_nameservice::file::FileNameService;
use fluree_db_reasoner::{
    collect_list_elements, reason_owl2rl, ReasoningBudget, ReasoningCache, ReasoningOptions,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

const RDF_FIRST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
const RDF_REST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
const CHAIN: &str = "http://example.org/chain";

fn genesis(id: &str) -> LedgerState {
    LedgerState::new(LedgerSnapshot::genesis(id), Novelty::new(0))
}

async fn apply(fluree: &Fluree, ledger: LedgerState, trig: &str) -> LedgerState {
    fluree
        .stage_owned(ledger)
        .upsert_turtle(trig)
        .execute()
        .await
        .expect("blank-node characterization fixture")
        .ledger
}

async fn structural_blank_labels(ledger: &LedgerState) -> BTreeSet<String> {
    let mut labels = BTreeSet::new();
    for index in [
        IndexType::Spot,
        IndexType::Psot,
        IndexType::Post,
        IndexType::Opst,
    ] {
        let mut from_index = BTreeSet::new();
        let flakes = GraphDbRef::new(&ledger.snapshot, 0, ledger.novelty.as_ref(), ledger.t())
            .range(index, RangeTest::Eq, RangeMatch::default())
            .await
            .expect("full index scan");
        for flake in flakes {
            if let Some(value) = ledger.snapshot.decode_sid(&flake.s) {
                if value.starts_with("_:fdb-") {
                    from_index.insert(value);
                }
            }
            if let FlakeValue::Ref(object) = &flake.o {
                if let Some(value) = ledger.snapshot.decode_sid(object) {
                    if value.starts_with("_:fdb-") {
                        from_index.insert(value);
                    }
                }
            }
        }
        if labels.is_empty() {
            labels = from_index;
        } else {
            assert_eq!(labels, from_index, "index/row order must not change labels");
        }
    }
    labels
}

async fn derived_chain(ledger: &LedgerState) -> bool {
    let result = reason_owl2rl(
        GraphDbRef::new(&ledger.snapshot, 0, ledger.novelty.as_ref(), ledger.t()),
        &ReasoningOptions::with_budget(ReasoningBudget::unlimited()),
        &ReasoningCache::new(1),
    )
    .await
    .expect("direct reasoner");
    result.overlay.flakes_spot().iter().any(|flake| {
        ledger.snapshot.decode_sid(&flake.s).as_deref() == Some("http://example.org/a")
            && ledger.snapshot.decode_sid(&flake.p).as_deref() == Some(CHAIN)
            && matches!(&flake.o, FlakeValue::Ref(o) if ledger.snapshot.decode_sid(o).as_deref() == Some("http://example.org/c"))
    })
}

#[tokio::test]
async fn stable_labels_survive_repeated_index_orders_retry_and_exact_historical_state() {
    let fluree = FlureeBuilder::memory().build_memory();
    let first = apply(
        &fluree,
        genesis("ctxql/p5-6-blank-stability:main"),
        r#"
@prefix ex: <http://example.org/> . @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
ex:R a owl:Restriction ; owl:onProperty ex:p ; owl:someValuesFrom ex:C .
ex:chain owl:propertyChainAxiom _:head .
_:head rdf:first ex:p ; rdf:rest _:tail . _:tail rdf:first ex:q ; rdf:rest rdf:nil .
ex:a ex:p ex:b . ex:b ex:q ex:c .
"#,
    )
    .await;
    let exact_capture = first.clone();
    let labels = structural_blank_labels(&first).await;
    assert!(labels.len() >= 2);
    assert!(labels.iter().all(|label| label.starts_with("_:fdb-")));
    assert_eq!(labels, structural_blank_labels(&first).await);
    assert_eq!(labels, structural_blank_labels(&exact_capture).await);
    assert!(derived_chain(&first).await);
    assert!(derived_chain(&first).await, "retry sees the same structure");

    let advanced = apply(
        &fluree,
        first,
        "@prefix ex: <http://example.org/> . ex:unrelated ex:value ex:later .",
    )
    .await;
    assert!(advanced.t() >= exact_capture.t());
    assert_eq!(
        labels,
        structural_blank_labels(&exact_capture).await,
        "later semantic-head advancement cannot mutate the retained exact capture"
    );
}

#[tokio::test]
async fn stable_labels_survive_durable_read_only_process_style_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_string_lossy().into_owned();
    let ledger_id = "ctxql/p5-6-blank-durable:main";
    let labels = {
        let writer = FlureeBuilder::file(path.clone())
            .without_indexing()
            .build()
            .unwrap();
        writer.create_ledger(ledger_id).await.unwrap();
        writer
            .graph(ledger_id)
            .transact()
            .sparql_update(
                r#"
PREFIX ex: <http://example.org/> PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
INSERT DATA {
  ex:chain owl:propertyChainAxiom _:head .
  _:head rdf:first ex:p ; rdf:rest _:tail .
  _:tail rdf:first ex:q ; rdf:rest rdf:nil .
}
"#,
            )
            .commit()
            .await
            .unwrap();
        let ledger = writer.ledger(ledger_id).await.unwrap();
        structural_blank_labels(&ledger).await
    };
    assert_eq!(labels.len(), 2);

    let nameservice = NameServiceMode::ReadOnly(Arc::new(FileNameService::new(directory.path())));
    let reader = FlureeBuilder::file(path)
        .without_indexing()
        .build_client_with_nameservice(nameservice)
        .await
        .unwrap();
    let reopened = reader.ledger(ledger_id).await.unwrap();
    assert_eq!(labels, structural_blank_labels(&reopened).await);
}

#[tokio::test]
async fn graph_scope_is_part_of_structural_identity() {
    let fluree = FlureeBuilder::memory().build_memory();
    let ledger = apply(
        &fluree,
        genesis("ctxql/p5-6-blank-graphs:main"),
        r#"
@prefix ex: <http://example.org/> . @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
GRAPH <http://example.org/g1> { _:cell1 rdf:first ex:A ; rdf:rest rdf:nil . }
GRAPH <http://example.org/g2> { _:cell2 rdf:first ex:A ; rdf:rest rdf:nil . }
"#,
    )
    .await;
    let mut scoped: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for graph in ["http://example.org/g1", "http://example.org/g2"] {
        let graph_id = ledger
            .snapshot
            .graph_registry
            .graph_id_for_iri(graph)
            .expect("graph id");
        let flakes = GraphDbRef::new(
            &ledger.snapshot,
            graph_id,
            ledger.novelty.as_ref(),
            ledger.t(),
        )
        .range(IndexType::Spot, RangeTest::Eq, RangeMatch::default())
        .await
        .expect("graph scan");
        for flake in flakes {
            if ledger.snapshot.decode_sid(&flake.p).as_deref() == Some(RDF_FIRST) {
                let subject = ledger.snapshot.decode_sid(&flake.s).expect("blank label");
                scoped.entry(graph.into()).or_default().insert(subject);
            }
        }
    }
    assert_eq!(scoped.len(), 2);
    let commitments: BTreeSet<_> = scoped
        .iter()
        .flat_map(|(graph, labels)| {
            labels
                .iter()
                .map(move |label| (graph.clone(), label.clone()))
        })
        .collect();
    assert_eq!(
        commitments.len(),
        2,
        "graph plus stable label is collision-free"
    );
}

#[tokio::test]
async fn default_collection_ingest_is_not_a_reasoner_visible_rdf_spine() {
    let fluree = FlureeBuilder::memory().build_memory();
    let default_shape = apply(
        &fluree,
        genesis("ctxql/p5-6-default-list:main"),
        r#"
@prefix ex: <http://example.org/> . @prefix owl: <http://www.w3.org/2002/07/owl#> .
ex:chain owl:propertyChainAxiom (ex:p ex:q) . ex:a ex:p ex:b . ex:b ex:q ex:c .
"#,
    )
    .await;
    assert!(!derived_chain(&default_shape).await);
    let default_flakes = GraphDbRef::new(
        &default_shape.snapshot,
        0,
        default_shape.novelty.as_ref(),
        default_shape.t(),
    )
    .range(IndexType::Spot, RangeTest::Eq, RangeMatch::default())
    .await
    .expect("default-shape scan");
    assert!(
        !default_flakes.iter().any(|flake| {
            matches!(
                default_shape.snapshot.decode_sid(&flake.p).as_deref(),
                Some(RDF_FIRST | RDF_REST)
            )
        }),
        "default Turtle ingestion stores indexed list metadata, not rdf:first/rest"
    );

    let explicit_shape = apply(
        &fluree,
        genesis("ctxql/p5-6-explicit-list:main"),
        r#"
@prefix ex: <http://example.org/> . @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
ex:chain owl:propertyChainAxiom _:head . _:head rdf:first ex:p ; rdf:rest _:tail .
_:tail rdf:first ex:q ; rdf:rest rdf:nil . ex:a ex:p ex:b . ex:b ex:q ex:c .
"#,
    )
    .await;
    let explicit_flakes = GraphDbRef::new(
        &explicit_shape.snapshot,
        0,
        explicit_shape.novelty.as_ref(),
        explicit_shape.t(),
    )
    .range(IndexType::Spot, RangeTest::Eq, RangeMatch::default())
    .await
    .expect("explicit-shape scan");
    let chain_axiom = explicit_flakes
        .iter()
        .find(|flake| {
            explicit_shape.snapshot.decode_sid(&flake.p).as_deref()
                == Some("http://www.w3.org/2002/07/owl#propertyChainAxiom")
        })
        .expect("chain axiom");
    let FlakeValue::Ref(head) = &chain_axiom.o else {
        panic!("reference list head")
    };
    let members = collect_list_elements(
        GraphDbRef::new(
            &explicit_shape.snapshot,
            0,
            explicit_shape.novelty.as_ref(),
            explicit_shape.t(),
        ),
        head,
    )
    .await
    .expect("explicit spine traversal");
    assert_eq!(members.len(), 2);
    assert!(derived_chain(&explicit_shape).await);
}
