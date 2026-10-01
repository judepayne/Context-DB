// Included in reads::tests to reuse its ordinary native admission helpers.
fn inventory_entity_claim(
    component: &str,
    subject: &str,
    predicate: &str,
    object: &str,
) -> cdb_core::claim::CandidateClaim {
    let mut value =
        semantic_literal_claim(component, subject, predicate, "placeholder").projection();
    let V::Object(fields) = &mut value else {
        unreachable!()
    };
    fields.insert("object_id".into(), V::string(object));
    fields.insert("object_type".into(), V::string("urn:type:entity"));
    let provisional = cdb_core::claim::CandidateClaim::from_value(&value).unwrap();
    let id = stable_acquisition_v2_claim_id(&provisional, Limits::default()).unwrap();
    let V::Object(fields) = &mut value else {
        unreachable!()
    };
    fields.insert("claim_id".into(), V::string(id.as_str()));
    cdb_core::claim::CandidateClaim::from_value(&value).unwrap()
}

#[tokio::test]
#[ignore = "run exactly through the serial native-test wrapper"]
async fn inventory_pages_count_union_preserve_names_and_recheck_authority() {
    use serde_json::json;
    const TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
    let fixture = AcquisitionV2Fixture::create().await.unwrap();
    let token = fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let service = Service::open(fixture.config().unwrap()).await.unwrap();
    let reference = publish_artifact(
        &service,
        &token,
        "https://ctxql.example/test/inventory-resource",
        include_bytes!("../../../../fixtures/conformance/graph-workspace/config.json"),
    )
    .await;
    service.shutdown().await.unwrap();
    drop(service);
    admit_claims(
        &fixture,
        vec![
            inventory_entity_claim(
                "inventory:a-type",
                "urn:inventory:a",
                TYPE,
                "urn:class:Party",
            ),
            inventory_entity_claim(
                "inventory:a-type-duplicate",
                "urn:inventory:a",
                TYPE,
                "urn:class:Party",
            ),
            inventory_entity_claim(
                "inventory:a-type-other",
                "urn:inventory:a",
                TYPE,
                "urn:class:Organization",
            ),
            inventory_entity_claim(
                "inventory:b-type",
                "urn:inventory:b",
                TYPE,
                "urn:class:Organization",
            ),
            semantic_literal_claim("inventory:a-name", "urn:inventory:a", LABEL, "Same Name"),
            semantic_literal_claim("inventory:b-name", "urn:inventory:b", LABEL, "Same Name"),
            inventory_entity_claim(
                "inventory:address",
                "urn:inventory:a",
                "urn:relation:address",
                "urn:inventory:address",
            ),
            semantic_literal_claim(
                "inventory:address-text",
                "urn:inventory:address",
                "urn:relation:addressText",
                "1 Test Street",
            ),
            semantic_literal_claim(
                "inventory:untyped",
                "urn:inventory:untyped",
                LABEL,
                "Untyped Party",
            ),
        ],
        "chat-inventory",
    )
    .await;
    let reads = ChatReadResources::open(chat_config(&fixture, &reference, None), token)
        .await
        .unwrap();
    reads.begin_turn();
    let cancel = || Arc::new(AtomicBool::new(false));
    let original_head = SemanticProjectionSource::head(reads.semantic.as_ref())
        .await
        .unwrap();
    let run =
        |query: serde_json::Value| serde_json::to_vec(&json!({"query":query.to_string()})).unwrap();
    let classes = reads
        .dispatch_tool(
            "ctxql_graph_query",
            &run(json!({
                "schema":"ctxql.chat-inventory/v1","operation":"classes"
            })),
            cancel(),
        )
        .await
        .unwrap();
    assert_eq!(classes["total"], 2, "{classes}");
    assert_eq!(classes["entries"][0]["entity_count"], 2);
    assert_eq!(classes["entries"][1]["entity_count"], 1);
    let mut query = json!({"schema":"ctxql.chat-inventory/v1","operation":"entities",
        "classes":["urn:class:Party","urn:class:Organization"],
        "relations":["urn:relation:address"],"page_size":1});
    let first = reads
        .dispatch_tool("ctxql_graph_query", &run(query.clone()), cancel())
        .await
        .unwrap();
    assert_eq!(first["total"], 2, "{first}");
    assert_eq!(first["entities_with_relations"], 1);
    assert_eq!(first["entries"][0]["iri"], "urn:inventory:a");
    assert_eq!(first["entries"][0]["names"][0], "Same Name");
    assert!(first["evidence"]["claims"]
        .as_array()
        .unwrap()
        .iter()
        .any(|claim| claim["object"]["value"] == "1 Test Street"));
    assert!(!first["next_cursor"].is_null());
    query["cursor"] = first["next_cursor"].clone();
    // Tampering with a genuine cursor may not skip to an apparently final page.
    let mut tampered = query.clone();
    tampered["cursor"]["offset"] = json!(2);
    let tampered = reads
        .dispatch_tool("ctxql_graph_query", &run(tampered), cancel())
        .await
        .unwrap();
    assert_eq!(tampered["status"], "invalid");
    let mut changed = query.clone();
    changed["classes"] = json!(["urn:class:Party"]);
    let changed = reads
        .dispatch_tool("ctxql_graph_query", &run(changed), cancel())
        .await
        .unwrap();
    assert_eq!(changed["status"], "inventory_changed");
    let second = reads
        .dispatch_tool("ctxql_graph_query", &run(query.clone()), cancel())
        .await
        .unwrap();
    assert_eq!(second["entries"][0]["iri"], "urn:inventory:b");
    assert_eq!(second["total"], 2);
    assert!(second["next_cursor"].is_null());
    assert_eq!(
        SemanticProjectionSource::head(reads.semantic.as_ref())
            .await
            .unwrap(),
        original_head
    );
    // Completed chains cannot replay an earlier cursor. Start a fresh chain
    // before testing revocation of a genuinely current continuation.
    let replay = reads
        .dispatch_tool("ctxql_graph_query", &run(query.clone()), cancel())
        .await
        .unwrap();
    assert_eq!(replay["status"], "invalid");
    query.as_object_mut().unwrap().remove("cursor");
    let restarted = reads
        .dispatch_tool("ctxql_graph_query", &run(query.clone()), cancel())
        .await
        .unwrap();
    query["cursor"] = restarted["next_cursor"].clone();
    // Revoking the published configuration also invalidates pagination access.
    set_subject_denial(
        &reads,
        "https://ctxql.example/test/inventory-resource",
        "inventory-revoke",
    )
    .await;
    let denied = reads
        .dispatch_tool("ctxql_graph_query", &run(query), cancel())
        .await
        .unwrap();
    assert_eq!(denied["status"], "denied", "{denied}");
}
