use fluree_db_api::{Fluree, FlureeBuilder, GraphDb, LedgerState, NameServiceMode, Novelty};
use fluree_db_core::LedgerSnapshot;
use fluree_db_nameservice::file::FileNameService;
use serde_json::{json, Value};
use std::sync::Arc;

const EX: &str = "http://example.org/";

fn genesis(ledger: &str) -> LedgerState {
    LedgerState::new(LedgerSnapshot::genesis(ledger), Novelty::new(0))
}

fn context() -> Value {
    json!({
        "ex": EX,
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
    })
}

async fn sparql(fluree: &Fluree, ledger: &LedgerState, query: &str) -> Value {
    let db = GraphDb::from_ledger_state(ledger);
    fluree
        .query(&db, query)
        .await
        .expect("query")
        .to_sparql_json(&ledger.snapshot)
        .expect("SPARQL JSON")
}

fn bindings(value: &Value) -> &[Value] {
    value["results"]["bindings"]
        .as_array()
        .expect("bindings array")
}

#[tokio::test]
async fn explicit_parallel_annotations_preserve_identity_values_and_multiplicity() {
    let fluree = FlureeBuilder::memory().build_memory();
    let ledger = genesis("ctxql/p5-5-gate-a:main");
    let committed = fluree
        .insert(
            ledger,
            &json!({
                "@context": context(),
                "@graph": [
                    {
                        "@id": "ex:alice",
                        "ex:worksFor": {
                            "@id": "ex:acme",
                            "@annotation": {
                                "@id": "ex:claim/one",
                                "ex:role": {"@id": "ex:Engineer"},
                                "ex:confidence": {"@value": "0.800", "@type": "xsd:decimal"},
                                "ex:label": {"@value": "premier", "@language": "fr"}
                            }
                        }
                    },
                    {
                        "@id": "ex:alice",
                        "ex:worksFor": {
                            "@id": "ex:acme",
                            "@annotation": {
                                "@id": "ex:claim/two",
                                "ex:role": {"@id": "ex:Manager"},
                                "ex:confidence": {"@value": "1.0", "@type": "xsd:decimal"},
                                "ex:label": {"@value": "second", "@language": "en"}
                            }
                        }
                    }
                ]
            }),
        )
        .await
        .expect("annotated insert")
        .ledger;

    let occurrences = sparql(
        &fluree,
        &committed,
        r#"
            PREFIX ex: <http://example.org/>
            SELECT ?ann ?role ?confidence ?label WHERE {
              ex:alice ex:worksFor ex:acme ~ ?ann {|
                ex:role ?role ; ex:confidence ?confidence ; ex:label ?label
              |} .
            }
            ORDER BY ?ann
        "#,
    )
    .await;
    let rows = bindings(&occurrences);
    assert_eq!(rows.len(), 2, "one row per explicit reifier");
    assert_eq!(rows[0]["ann"]["value"], format!("{EX}claim/one"));
    assert_eq!(rows[0]["role"]["value"], format!("{EX}Engineer"));
    assert_eq!(rows[0]["confidence"]["value"], "0.800");
    assert_eq!(
        rows[0]["confidence"]["datatype"],
        "http://www.w3.org/2001/XMLSchema#decimal"
    );
    assert_eq!(rows[0]["label"]["xml:lang"], "fr");

    let rooted = sparql(
        &fluree,
        &committed,
        r#"
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX ex: <http://example.org/>
            SELECT ?s ?o WHERE {
              ex:claim/one rdf:reifies <<( ?s ex:worksFor ?o )>> .
            }
        "#,
    )
    .await;
    assert_eq!(bindings(&rooted).len(), 1, "public rdf:reifies lookup");

    let bare = sparql(
        &fluree,
        &committed,
        r#"PREFIX ex: <http://example.org/> SELECT ?o WHERE { ex:alice ex:worksFor ?o . }"#,
    )
    .await;
    assert_eq!(
        bindings(&bare).len(),
        1,
        "bare RDF edge retains set cardinality"
    );

    let idempotent = fluree
        .insert(
            committed.clone(),
            &json!({
                "@context": context(),
                "@id": "ex:alice",
                "ex:worksFor": {
                    "@id": "ex:acme",
                    "@annotation": {
                        "@id": "ex:claim/one",
                        "ex:role": {"@id": "ex:Engineer"},
                        "ex:confidence": {"@value": "0.800", "@type": "xsd:decimal"},
                        "ex:label": {"@value": "premier", "@language": "fr"}
                    }
                }
            }),
        )
        .await
        .expect("idempotent explicit reassert")
        .ledger;
    assert_eq!(bindings(&sparql(&fluree, &idempotent, r#"PREFIX ex: <http://example.org/> SELECT ?ann WHERE { ex:alice ex:worksFor ex:acme ~ ?ann {| ex:role ?role |} . }"#).await).len(), 2);

    let err = fluree
        .insert(
            idempotent,
            &json!({
                "@context": context(),
                "@id": "ex:carol",
                "ex:worksFor": {
                    "@id": "ex:globex",
                    "@annotation": {"@id": "ex:claim/one", "ex:role": {"@id": "ex:Director"}}
                }
            }),
        )
        .await
        .expect_err("one reifier cannot target two live edges");
    let message = format!("{err:?} {err}");
    assert!(message.contains("multi-target") || message.contains("reify exactly one edge"));
}

#[tokio::test]
async fn public_sparql_annotations_survive_read_only_reopen_and_exact_history() {
    let dir = tempfile::tempdir().expect("temporary durable ledger");
    let path = dir.path().to_string_lossy().into_owned();
    let ledger_id = "ctxql/p5-5-gate-a-durable:main";
    let first_cid = {
        let writer = FlureeBuilder::file(path.clone())
            .without_indexing()
            .build()
            .expect("durable writer");
        writer
            .create_ledger(ledger_id)
            .await
            .expect("create ledger");
        let insert = r#"
            PREFIX ex: <http://example.org/>
            PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
            INSERT DATA {
              ex:alice ex:worksFor ex:acme ~ ex:claim/one {|
                ex:role ex:Engineer ;
                ex:confidence "0.800"^^xsd:decimal ;
                ex:label "premier"@fr ;
                ex:code "001"^^ex:Code
              |} .
              ex:alice ex:worksFor ex:acme ~ ex:claim/two {| ex:role ex:Manager |} .
            }
        "#;
        writer
            .graph(ledger_id)
            .transact()
            .sparql_update(insert)
            .commit()
            .await
            .expect("SPARQL annotation insert");
        let first = writer.ledger(ledger_id).await.expect("first head");
        let cid = first
            .head_commit_id
            .as_ref()
            .expect("first CID")
            .to_string();
        writer
            .update(
                first,
                &json!({
                    "@context": context(),
                    "delete": {
                        "@id": "ex:alice",
                        "ex:worksFor": {
                            "@id": "ex:acme",
                            "@annotation": {"@id": "ex:claim/one"}
                        }
                    }
                }),
            )
            .await
            .expect("detach SPARQL-authored annotation by explicit id");
        cid
    };

    let nameservice = NameServiceMode::ReadOnly(Arc::new(FileNameService::new(dir.path())));
    let reader = FlureeBuilder::file(path)
        .without_indexing()
        .build_client_with_nameservice(nameservice)
        .await
        .expect("read-only client");
    let current = reader
        .ledger(ledger_id)
        .await
        .expect("reopened current head");
    let current_rows = sparql(
        &reader,
        &current,
        r#"PREFIX ex: <http://example.org/>
           SELECT ?ann WHERE {
             ex:alice ex:worksFor ex:acme ~ ?ann {| ex:role ?role |} .
           } ORDER BY ?ann"#,
    )
    .await;
    assert_eq!(bindings(&current_rows).len(), 1);
    assert_eq!(
        current_rows["results"]["bindings"][0]["ann"]["value"],
        format!("{EX}claim/two")
    );

    let detail = reader
        .graph(ledger_id)
        .commit_t(1)
        .execute()
        .await
        .expect("resolve exact first commit");
    assert_eq!(detail.id, first_cid);
    let historical = reader
        .ledger_view_at(ledger_id, 1)
        .await
        .expect("reconstruct exact first view");
    let historical_db = GraphDb::from_historical(&historical);
    let historical_rows = reader
        .query(
            &historical_db,
            r#"PREFIX ex: <http://example.org/>
               SELECT ?ann ?confidence ?label ?code WHERE {
                 ex:alice ex:worksFor ex:acme ~ ?ann {|
                   ex:confidence ?confidence ; ex:label ?label ; ex:code ?code
                 |} .
               }"#,
        )
        .await
        .expect("historical annotation query")
        .to_sparql_json(&historical.snapshot)
        .expect("historical SPARQL JSON");
    let rows = bindings(&historical_rows);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["ann"]["value"], format!("{EX}claim/one"));
    assert_eq!(rows[0]["confidence"]["value"], "0.800");
    assert_eq!(rows[0]["label"]["xml:lang"], "fr");
    assert_eq!(rows[0]["code"]["value"], "001");
}

#[tokio::test]
async fn named_graph_detachment_preserves_siblings_and_historical_view() {
    let fluree = FlureeBuilder::memory().build_memory();
    let ledger = genesis("ctxql/p5-5-gate-a-history:main");
    let first = fluree
        .insert(
            ledger,
            &json!({
                "@context": context(),
                "@graph": [
                    {"@id": "ex:alice", "@graph": "ex:claims", "ex:knows": {
                        "@id": "ex:bob", "@annotation": {"@id": "ex:claim/a", "ex:source": "A"}
                    }},
                    {"@id": "ex:alice", "@graph": "ex:claims", "ex:knows": {
                        "@id": "ex:bob", "@annotation": {"@id": "ex:claim/b", "ex:source": "B"}
                    }}
                ]
            }),
        )
        .await
        .expect("named graph annotations")
        .ledger;

    let detached = fluree
        .update(
            first.clone(),
            &json!({
                "@context": context(),
                "delete": {
                    "@id": "ex:alice",
                    "@graph": "ex:claims",
                    "ex:knows": {"@id": "ex:bob", "@annotation": {"@id": "ex:claim/a"}}
                }
            }),
        )
        .await
        .expect("detach by explicit id")
        .ledger;

    let query = r#"
        PREFIX ex: <http://example.org/>
        SELECT ?ann WHERE { GRAPH ex:claims { ex:alice ex:knows ex:bob ~ ?ann {| ex:source ?source |} . } }
        ORDER BY ?ann
    "#;
    let before = sparql(&fluree, &first, query).await;
    let after = sparql(&fluree, &detached, query).await;
    assert_eq!(
        bindings(&before).len(),
        2,
        "retained historical state has both supports"
    );
    assert_eq!(
        bindings(&after).len(),
        1,
        "detachment preserves one sibling"
    );
    assert_eq!(bindings(&after)[0]["ann"]["value"], format!("{EX}claim/b"));

    let bare = sparql(
        &fluree,
        &detached,
        r#"PREFIX ex: <http://example.org/> SELECT ?o WHERE { GRAPH ex:claims { ex:alice ex:knows ?o . } }"#,
    )
    .await;
    assert_eq!(
        bindings(&bare).len(),
        1,
        "base edge remains while sibling support exists"
    );

    let deleted = fluree
        .update(
            detached,
            &json!({
                "@context": context(),
                "delete": {"@id": "ex:alice", "@graph": "ex:claims", "ex:knows": {"@id": "ex:bob"}}
            }),
        )
        .await
        .expect("delete base edge")
        .ledger;
    assert!(bindings(&sparql(&fluree, &deleted, query).await).is_empty());
}
