//! Semantic parity against the last successful source-only Markdown06 response.
//! The fixture is historical JSON; the derived text is a test input, not a model capture.
use cdb_acquisition::proposals::ProposalLimits;
use cdb_provider_pi::proposal_protocol::{parse_proposals_v3, ProposalParseContext};
use cdb_provider_pi::proposal_text::parse_proposals_text;
use serde_json::Value;
use std::collections::BTreeSet;

fn field(out: &mut String, label: &str, value: &str) {
    out.push_str(label);
    out.push(':');
    if !value.is_empty() {
        out.push(' ');
        out.push_str(value);
    }
    out.push('\n');
}
fn reference(value: &Value) -> String {
    let kind = value["kind"].as_str().unwrap();
    let key = match kind {
        "local" => "id",
        "document" => "handle",
        "known" => "iri",
        "unresolved" => "text",
        _ => panic!("unexpected fixture reference"),
    };
    format!("{kind} {}", value[key].as_str().unwrap())
}
fn choice(out: &mut String, label: &str, value: &Value) {
    for suggestion in value["suggestions"].as_array().unwrap() {
        field(out, label, suggestion["text"].as_str().unwrap());
        field(
            out,
            &format!("{label} note"),
            suggestion["note"].as_str().unwrap(),
        );
    }
    field(
        out,
        &format!("{label} selected"),
        &value["selected"]
            .as_u64()
            .map_or("none".into(), |n| n.to_string()),
    );
}
fn evidence(out: &mut String, items: &[Value], ranges: &mut BTreeSet<String>) {
    for item in items {
        out.push_str("EVIDENCE:\n");
        let range = item["range"].as_str().unwrap();
        ranges.insert(range.into());
        field(out, "Range", range);
        field(
            out,
            "Occurrence",
            &item["occurrence"].as_u64().unwrap().to_string(),
        );
        field(out, "Quote", item["quote"].as_str().unwrap());
    }
    out.push_str("---\n");
}
fn claim(
    out: &mut String,
    kind: &str,
    value: &Value,
    parent: Option<&str>,
    ranges: &mut BTreeSet<String>,
) {
    out.push_str("CLAIM:\n");
    field(out, "Kind", kind);
    field(
        out,
        "Subject",
        &parent.map_or_else(|| reference(&value["subject"]), |id| format!("local {id}")),
    );
    if kind == "classification" {
        choice(out, "Term", &value["term"]);
    } else {
        choice(out, "Predicate", &value["predicate"]);
        if kind == "attribute" {
            field(out, "Value", value["value"]["lexical"].as_str().unwrap());
            choice(out, "Datatype", &value["value"]["datatype"]);
        } else {
            field(out, "Object", &reference(&value["object"]));
        }
    }
    out.push_str("CLAIM_METADATA:\n");
    field(out, "Source mode", value["source_mode"].as_str().unwrap());
    field(out, "Fit", value["fit"].as_str().unwrap());
    field(out, "Fit note", value["fit_note"].as_str().unwrap());
    if let Some(qualifiers) = value["qualifiers"].as_array() {
        for qualifier in qualifiers {
            field(out, "Qualifier", qualifier.as_str().unwrap());
        }
    }
    evidence(out, value["evidence"].as_array().unwrap(), ranges);
}

#[test]
fn last_successful_markdown06_response_has_lossless_text_semantic_parity() {
    let raw = include_str!("../../../fixtures/conformance/p6/extraction-text/markdown-06-v3.json");
    let wire: Value = serde_json::from_str(raw).unwrap();
    let mut text = String::new();
    let mut ranges = BTreeSet::new();
    for entity in wire["entities"].as_array().unwrap() {
        let id = entity["id"].as_str().unwrap();
        text.push_str("ENTITY:\n");
        field(&mut text, "Id", id);
        field(&mut text, "Name", entity["name"].as_str().unwrap());
        field(
            &mut text,
            "Known entity",
            &entity["known_entity"]
                .as_str()
                .map_or("none".into(), |iri| format!("iri {iri}")),
        );
        evidence(
            &mut text,
            entity["evidence"].as_array().unwrap(),
            &mut ranges,
        );
        for alias in entity["aliases"].as_array().unwrap() {
            text.push_str("ALIAS:\n");
            field(&mut text, "Entity", id);
            field(&mut text, "Name", alias["name"].as_str().unwrap());
            evidence(
                &mut text,
                std::slice::from_ref(&alias["evidence"]),
                &mut ranges,
            );
        }
        for class in entity["classes"].as_array().unwrap() {
            claim(&mut text, "classification", class, Some(id), &mut ranges);
        }
    }
    for attribute in wire["attributes"].as_array().unwrap() {
        claim(&mut text, "attribute", attribute, None, &mut ranges);
    }
    for relation in wire["relations"].as_array().unwrap() {
        claim(&mut text, "relation", relation, None, &mut ranges);
    }
    let ranges: Vec<_> = ranges.into_iter().collect();
    let context = ProposalParseContext {
        passage_namespace: "baseline-parity",
        issued_ranges: &ranges,
        document_handles: &[],
    };
    let limits = ProposalLimits::default();
    let mut expected = parse_proposals_v3(raw, &context, &limits).unwrap();
    let mut actual = parse_proposals_text(&text, &context, &limits).unwrap();
    assert!(actual.diagnostics.is_empty());
    assert_eq!(actual.envelope.component_count(), 56);
    for component in &mut actual.envelope.entities {
        assert!(component
            .original_text
            .take()
            .unwrap()
            .starts_with("ENTITY:\n"));
        if let Ok(entity) = &mut component.value {
            for alias in &mut entity.aliases {
                assert!(alias.original_text.take().unwrap().starts_with("ALIAS:\n"));
            }
            for class in &mut entity.classes {
                assert!(class.original_text.take().unwrap().starts_with("CLAIM:\n"));
            }
        }
    }
    for attribute in &mut actual.envelope.attributes {
        assert!(attribute
            .original_text
            .take()
            .unwrap()
            .starts_with("CLAIM:\n"));
    }
    for relation in &mut actual.envelope.relations {
        assert!(relation
            .original_text
            .take()
            .unwrap()
            .starts_with("CLAIM:\n"));
    }
    // Compare typed meaning, not JSON object key order: service dependency
    // unification enables serde_json/preserve_order while provider-only tests
    // may use sorted maps. Raw text retention is asserted separately above.
    for envelope in [&mut actual.envelope, &mut expected] {
        for component in &mut envelope.entities {
            component.original_json.clear();
            if let Ok(entity) = &mut component.value {
                for alias in &mut entity.aliases {
                    alias.original_json.clear();
                }
                for class in &mut entity.classes {
                    class.original_json.clear();
                }
            }
        }
        for component in &mut envelope.attributes {
            component.original_json.clear();
        }
        for component in &mut envelope.relations {
            component.original_json.clear();
        }
    }
    assert_eq!(actual.envelope, expected);
}
