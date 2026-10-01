use cdb_acquisition::proposals::{
    ComponentErrorCode, EntityRef, ProposalLimits, RelationObject, SemanticFit, SourceMode,
};
use cdb_provider_pi::proposal_protocol::{
    parse_proposals, parse_proposals_v2, parse_proposals_v3, ProposalParseContext,
    ProposalParseError,
};
use serde_json::{json, Value};

fn context<'a>(ranges: &'a [String], documents: &'a [String]) -> ProposalParseContext<'a> {
    ProposalParseContext {
        passage_namespace: "passage-7",
        issued_ranges: ranges,
        document_handles: documents,
    }
}

fn evidence() -> Value {
    json!({"range":"h1","quote":"Orion borrows from Acme.","occurrence":0})
}

fn term(text: &str) -> Value {
    json!({"suggestions":[{"text":text,"note":""}],"selected":0})
}

fn class(id: &str) -> Value {
    json!({
        "id": id,
        "term": term("urn:test:Borrower"),
        "evidence": [evidence()],
        "source_mode": "affirmative",
        "fit": "supported",
        "fit_note": "Grounded by the borrowing clause"
    })
}

fn entity(id: &str) -> Value {
    json!({
        "id": id,
        "name": "Orion",
        "aliases": [{"name":"Facility Orion","evidence":evidence()}],
        "known_entity": null,
        "evidence": [evidence()],
        "classes": [class("c1")]
    })
}

fn attribute(id: &str) -> Value {
    json!({
        "id": id,
        "subject": {"kind":"local","id":"e1"},
        "predicate": term("urn:test:executedOn"),
        "value": {"lexical":"2022-12-06","datatype":term("http://www.w3.org/2001/XMLSchema#date")},
        "evidence": [evidence()],
        "source_mode": "affirmative",
        "qualifiers": [],
        "fit": "supported",
        "fit_note": ""
    })
}

fn relation(id: &str, object: Value) -> Value {
    json!({
        "id": id,
        "subject": {"kind":"document","handle":"doc-entity-1"},
        "predicate": {"suggestions":[
            {"text":"has borrower","note":"label"},
            {"text":"urn:test:hasBorrower","note":"IRI"}
        ],"selected":1},
        "object": object,
        "evidence": [evidence()],
        "source_mode": "conditional",
        "qualifiers": ["if funded"],
        "fit": "uncertain",
        "fit_note": "Condition cannot be represented"
    })
}

fn envelope() -> Value {
    json!({
        "schema":"ctxql-extraction-proposals/v2",
        "no_claims":false,
        "entities":[entity("e1")],
        "attributes":[attribute("a1")],
        "relations":[
            relation("r1", json!({"kind":"known","iri":"urn:test:Acme"})),
            relation("r2", json!({"kind":"unresolved","text":"the lender"}))
        ]
    })
}

fn envelope_v3() -> Value {
    let mut value = envelope();
    value["schema"] = json!("ctxql-extraction-proposals/v3");
    for entity in value["entities"].as_array_mut().unwrap() {
        for class in entity["classes"].as_array_mut().unwrap() {
            class.as_object_mut().unwrap().remove("id");
        }
    }
    for attribute in value["attributes"].as_array_mut().unwrap() {
        attribute.as_object_mut().unwrap().remove("id");
    }
    for relation in value["relations"].as_array_mut().unwrap() {
        relation.as_object_mut().unwrap().remove("id");
    }
    value
}

#[test]
fn parses_closed_bounded_v2_types_and_reference_variants() {
    let ranges = vec!["h1".to_owned()];
    let documents = vec!["doc-entity-1".to_owned()];
    let parsed = parse_proposals_v2(
        &envelope().to_string(),
        &context(&ranges, &documents),
        &ProposalLimits::default(),
    )
    .unwrap();

    assert_eq!(parsed.passage_namespace, "passage-7");
    assert_eq!(parsed.component_count(), 5);
    let entity = parsed.entities[0].parsed().unwrap();
    assert_eq!(
        entity.classes[0].parsed().unwrap().source_mode,
        SourceMode::Affirmative
    );
    assert_eq!(entity.aliases[0].parsed().unwrap().evidence.occurrence, 0);
    assert_eq!(
        parsed.attributes[0].parsed().unwrap().value.lexical,
        "2022-12-06"
    );
    let relation = parsed.relations[0].parsed().unwrap();
    assert_eq!(relation.fit, SemanticFit::Uncertain);
    assert!(
        matches!(relation.subject, EntityRef::Document { ref handle } if handle == "doc-entity-1")
    );
    assert!(matches!(
        relation.object,
        RelationObject::Entity(EntityRef::Known { ref proposed_iri }) if proposed_iri == "urn:test:Acme"
    ));
    assert!(matches!(
        parsed.relations[1].parsed().unwrap().object,
        RelationObject::Unresolved { ref text } if text == "the lender"
    ));
}

#[test]
fn v3_assigns_deterministic_structural_ids_and_preserves_scoped_entity_refs() {
    let ranges = vec!["h1".to_owned()];
    let documents = vec!["doc-entity-1".to_owned()];
    let wire = envelope_v3().to_string();
    let first = parse_proposals_v3(
        &wire,
        &context(&ranges, &documents),
        &ProposalLimits::default(),
    )
    .unwrap();
    let second = parse_proposals(
        &wire,
        &context(&ranges, &documents),
        &ProposalLimits::default(),
    )
    .unwrap();

    assert_eq!(first, second);
    assert_eq!(
        first.entities[0].parsed().unwrap().classes[0]
            .parsed()
            .unwrap()
            .id,
        "host/classification/0/0"
    );
    assert_eq!(first.attributes[0].parsed().unwrap().id, "host/attribute/0");
    assert_eq!(first.relations[0].parsed().unwrap().id, "host/relation/0");
    assert!(matches!(
        first.attributes[0].parsed().unwrap().subject,
        EntityRef::Local { ref passage_namespace, ref id }
            if passage_namespace == "passage-7" && id == "e1"
    ));

    let other_context = ProposalParseContext {
        passage_namespace: "passage-8",
        issued_ranges: &ranges,
        document_handles: &documents,
    };
    let other = parse_proposals_v3(&wire, &other_context, &ProposalLimits::default()).unwrap();
    assert_eq!(other.attributes[0].parsed().unwrap().id, "host/attribute/0");
    assert!(matches!(
        other.attributes[0].parsed().unwrap().subject,
        EntityRef::Local { ref passage_namespace, ref id }
            if passage_namespace == "passage-8" && id == "e1"
    ));
}

#[test]
fn v3_rejects_model_component_ids_and_bad_entity_labels() {
    let ranges = vec!["h1".to_owned()];
    let documents = vec!["doc-entity-1".to_owned()];
    let ctx = context(&ranges, &documents);

    let mut supplied = envelope_v3();
    supplied["entities"][0]["classes"][0]["id"] = json!("model-class");
    supplied["attributes"][0]["id"] = json!("model-attribute");
    supplied["relations"][0]["id"] = json!("model-relation");
    let parsed =
        parse_proposals_v3(&supplied.to_string(), &ctx, &ProposalLimits::default()).unwrap();
    assert_eq!(
        parsed.entities[0].parsed().unwrap().classes[0]
            .value
            .as_ref()
            .unwrap_err()
            .code,
        ComponentErrorCode::UnknownField
    );
    assert_eq!(
        parsed.attributes[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::UnknownField
    );
    assert_eq!(
        parsed.relations[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::UnknownField
    );

    let mut duplicate = envelope_v3();
    duplicate["entities"] = json!([entity("e1"), entity("e1")]);
    for entity in duplicate["entities"].as_array_mut().unwrap() {
        for class in entity["classes"].as_array_mut().unwrap() {
            class.as_object_mut().unwrap().remove("id");
        }
    }
    let parsed =
        parse_proposals_v3(&duplicate.to_string(), &ctx, &ProposalLimits::default()).unwrap();
    assert!(parsed.entities.iter().all(|entity| {
        entity.value.as_ref().unwrap_err().code == ComponentErrorCode::DuplicateId
    }));
    assert_eq!(
        parsed.attributes[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::UnresolvedReference
    );

    let mut missing = envelope_v3();
    missing["entities"][0].as_object_mut().unwrap().remove("id");
    let parsed =
        parse_proposals_v3(&missing.to_string(), &ctx, &ProposalLimits::default()).unwrap();
    assert_eq!(
        parsed.entities[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::MissingField
    );
    assert_eq!(
        parsed.attributes[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::UnresolvedReference
    );

    let mut unknown = envelope_v3();
    unknown["relations"][0]["object"] = json!({"kind":"local","id":"not-declared"});
    let parsed =
        parse_proposals_v3(&unknown.to_string(), &ctx, &ProposalLimits::default()).unwrap();
    assert_eq!(
        parsed.relations[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::UnresolvedReference
    );

    let mut collision = envelope_v3();
    collision["entities"][0]["id"] = json!("host/attribute/0");
    let parsed =
        parse_proposals_v3(&collision.to_string(), &ctx, &ProposalLimits::default()).unwrap();
    assert_eq!(
        parsed.entities[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::DuplicateId
    );
}

#[test]
fn captured_duplicate_v2_ids_are_not_silently_repaired_but_v3_positions_are_unique() {
    let original: Value = serde_json::from_str(include_str!(
        "../../../fixtures/conformance/p6/proposals-v3/markdown-06-original-v2.json"
    ))
    .unwrap();
    fn collect_ranges(value: &Value, ranges: &mut std::collections::BTreeSet<String>) {
        match value {
            Value::Array(values) => {
                for value in values {
                    collect_ranges(value, ranges);
                }
            }
            Value::Object(object) => {
                if let Some(range) = object.get("range").and_then(Value::as_str) {
                    ranges.insert(range.to_owned());
                }
                for value in object.values() {
                    collect_ranges(value, ranges);
                }
            }
            _ => {}
        }
    }
    let mut range_set = std::collections::BTreeSet::new();
    collect_ranges(&original, &mut range_set);
    let ranges: Vec<String> = range_set.into_iter().collect();
    let documents = Vec::new();
    let ctx = context(&ranges, &documents);

    let old = parse_proposals_v2(&original.to_string(), &ctx, &ProposalLimits::default()).unwrap();
    let old_duplicate_classes = old
        .entities
        .iter()
        .filter_map(|entity| entity.parsed())
        .flat_map(|entity| &entity.classes)
        .filter(|class| class.value.as_ref().unwrap_err().code == ComponentErrorCode::DuplicateId)
        .count();
    assert_eq!(old_duplicate_classes, 9);

    let mut v3 = original;
    v3["schema"] = json!("ctxql-extraction-proposals/v3");
    for entity in v3["entities"].as_array_mut().unwrap() {
        for class in entity["classes"].as_array_mut().unwrap() {
            class.as_object_mut().unwrap().remove("id");
        }
    }
    for attribute in v3["attributes"].as_array_mut().unwrap() {
        attribute.as_object_mut().unwrap().remove("id");
    }
    for relation in v3["relations"].as_array_mut().unwrap() {
        relation.as_object_mut().unwrap().remove("id");
    }
    let first = parse_proposals_v3(&v3.to_string(), &ctx, &ProposalLimits::default()).unwrap();
    let second = parse_proposals_v3(&v3.to_string(), &ctx, &ProposalLimits::default()).unwrap();
    assert_eq!(first, second);
    assert!(first
        .entities
        .iter()
        .filter_map(|entity| entity.parsed())
        .flat_map(|entity| &entity.classes)
        .all(|class| class.value.is_ok()));
    assert!(first
        .attributes
        .iter()
        .all(|attribute| attribute.value.is_ok()));
    assert!(first
        .relations
        .iter()
        .all(|relation| relation.value.is_ok()));
    assert_eq!(
        first.entities[1].parsed().unwrap().classes[1]
            .parsed()
            .unwrap()
            .id,
        "host/classification/1/1"
    );
    assert_eq!(
        first.attributes[10].parsed().unwrap().id,
        "host/attribute/10"
    );
    assert_eq!(first.relations[4].parsed().unwrap().id, "host/relation/4");
}

#[test]
fn duplicate_json_keys_fail_closed_at_envelope_and_nested_boundaries() {
    let ranges = vec!["h1".to_owned()];
    let documents = vec!["doc-entity-1".to_owned()];
    let ctx = context(&ranges, &documents);
    let top = r#"{"schema":"ctxql-extraction-proposals/v2","schema":"ctxql-extraction-proposals/v2","no_claims":true,"entities":[],"attributes":[],"relations":[]}"#;
    assert!(matches!(
        parse_proposals_v2(top, &ctx, &ProposalLimits::default()),
        Err(ProposalParseError::Json(message)) if message.contains("duplicate JSON key")
    ));

    let nested = r#"{"schema":"ctxql-extraction-proposals/v2","no_claims":false,"entities":[{"id":"e1","id":"e2","name":"x","aliases":[],"known_entity":null,"evidence":[],"classes":[]}],"attributes":[],"relations":[]}"#;
    assert!(matches!(
        parse_proposals_v2(nested, &ctx, &ProposalLimits::default()),
        Err(ProposalParseError::Json(message)) if message.contains("duplicate JSON key")
    ));
}

#[test]
fn malformed_component_is_retained_without_erasing_valid_siblings() {
    let ranges = vec!["h1".to_owned()];
    let documents = vec!["doc-entity-1".to_owned()];
    let mut value = envelope();
    value["attributes"] = json!([
        attribute("a1"),
        {
            "id":"bad",
            "subject":{"kind":"local","id":"e1"},
            "predicate":term("urn:test:p"),
            "value":{"lexical":"x","datatype":term("urn:test:type")},
            "evidence":[],"source_mode":"affirmative","qualifiers":[],
            "fit":"supported","fit_note":"","surprise":true
        }
    ]);
    let parsed = parse_proposals_v2(
        &value.to_string(),
        &context(&ranges, &documents),
        &ProposalLimits::default(),
    )
    .unwrap();
    assert!(parsed.attributes[0].value.is_ok());
    assert_eq!(
        parsed.attributes[1].value.as_ref().unwrap_err().code,
        ComponentErrorCode::UnknownField
    );
    assert!(parsed.attributes[1].original_json.contains("surprise"));
}

#[test]
fn malformed_alias_is_retained_without_erasing_its_entity() {
    let ranges = vec!["h1".to_owned()];
    let documents = vec!["doc-entity-1".to_owned()];
    let mut value = envelope();
    value["entities"][0]["aliases"] = json!([{"name":"Facility Orion","evidence":[evidence()]}]);
    let parsed = parse_proposals_v2(
        &value.to_string(),
        &context(&ranges, &documents),
        &ProposalLimits::default(),
    )
    .unwrap();
    let entity = parsed.entities[0].parsed().unwrap();
    assert_eq!(entity.id, "e1");
    assert_eq!(
        entity.aliases[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::InvalidType
    );
}

#[test]
fn malformed_classification_and_unissued_evidence_are_isolated() {
    let ranges = vec!["h1".to_owned()];
    let documents = vec!["doc-entity-1".to_owned()];
    let mut value = envelope();
    value["entities"][0]["classes"] = json!([
        class("c1"),
        {
            "id":"bad-class","term":term("urn:test:Other"),"evidence":[],
            "source_mode":"invented","fit":"supported","fit_note":""
        }
    ]);
    value["attributes"][0]["evidence"][0]["range"] = json!("model-made-range");
    let parsed = parse_proposals_v2(
        &value.to_string(),
        &context(&ranges, &documents),
        &ProposalLimits::default(),
    )
    .unwrap();

    let entity = parsed.entities[0].parsed().unwrap();
    assert!(entity.classes[0].value.is_ok());
    assert_eq!(
        entity.classes[1].value.as_ref().unwrap_err().code,
        ComponentErrorCode::InvalidValue
    );
    assert_eq!(
        parsed.attributes[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::UnresolvedReference
    );
}

#[test]
fn unknown_envelope_fields_and_inconsistent_no_claims_are_protocol_errors() {
    let ranges = vec!["h1".to_owned()];
    let documents = Vec::new();
    let ctx = context(&ranges, &documents);
    let mut unknown = envelope();
    unknown["extra"] = json!(1);
    assert_eq!(
        parse_proposals_v2(&unknown.to_string(), &ctx, &ProposalLimits::default()),
        Err(ProposalParseError::Envelope("unknown_field"))
    );

    let inconsistent = json!({
        "schema":"ctxql-extraction-proposals/v2","no_claims":false,
        "entities":[],"attributes":[],"relations":[]
    });
    assert_eq!(
        parse_proposals_v2(&inconsistent.to_string(), &ctx, &ProposalLimits::default()),
        Err(ProposalParseError::Envelope("no_claims_inconsistent"))
    );
    let empty = json!({
        "schema":"ctxql-extraction-proposals/v2","no_claims":true,
        "entities":[],"attributes":[],"relations":[]
    });
    assert!(
        parse_proposals_v2(&empty.to_string(), &ctx, &ProposalLimits::default())
            .unwrap()
            .no_claims
    );
}

#[test]
fn duplicate_ids_and_dangling_or_unissued_references_are_component_failures() {
    let ranges = vec!["h1".to_owned()];
    let documents = vec!["doc-entity-1".to_owned()];
    let mut value = envelope();
    value["entities"] = json!([entity("same"), entity("same")]);
    value["attributes"] = json!([attribute("a1")]);
    value["attributes"][0]["subject"]["id"] = json!("same");
    value["relations"] = json!([
        relation("r1", json!({"kind":"local","id":"missing"})),
        relation("r2", json!({"kind":"document","handle":"model-made"}))
    ]);
    let parsed = parse_proposals_v2(
        &value.to_string(),
        &context(&ranges, &documents),
        &ProposalLimits::default(),
    )
    .unwrap();
    assert!(parsed.entities.iter().all(|component| {
        component.value.as_ref().unwrap_err().code == ComponentErrorCode::DuplicateId
    }));
    assert_eq!(
        parsed.attributes[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::UnresolvedReference
    );
    assert!(parsed.relations.iter().all(|component| {
        component.value.as_ref().unwrap_err().code == ComponentErrorCode::UnresolvedReference
    }));
}

#[test]
fn enforces_response_array_field_and_selection_bounds() {
    let ranges = vec!["h1".to_owned()];
    let documents = vec!["doc-entity-1".to_owned()];
    let ctx = context(&ranges, &documents);

    let limits = ProposalLimits {
        max_entities: 0,
        ..ProposalLimits::default()
    };
    assert_eq!(
        parse_proposals_v2(&envelope().to_string(), &ctx, &limits),
        Err(ProposalParseError::Limit("entities"))
    );

    let mut value = envelope();
    value["attributes"][0]["predicate"]["selected"] = json!(9);
    let parsed = parse_proposals_v2(&value.to_string(), &ctx, &ProposalLimits::default()).unwrap();
    assert_eq!(
        parsed.attributes[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::InvalidValue
    );

    let mut value = envelope();
    value["entities"][0]["name"] = json!("x".repeat(1025));
    let parsed = parse_proposals_v2(&value.to_string(), &ctx, &ProposalLimits::default()).unwrap();
    assert_eq!(
        parsed.entities[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::InvalidValue
    );
}
