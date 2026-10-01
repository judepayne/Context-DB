use cdb_provider_pi::ontology_bridge::{OntologyToolError, OntologyToolHost};
use cdb_service::ontology_briefing::{
    build_ontology_briefing, loan_briefing_seed_manifest, OntologyBriefingContext,
    OntologyBriefingLimits, OntologyBriefingSeedManifest,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone)]
struct FixtureHost {
    capture: &'static str,
    terms: BTreeMap<String, Value>,
}

impl OntologyToolHost for FixtureHost {
    fn lookup(&self, request: &Value) -> Result<Value, OntologyToolError> {
        let operation = request["operation"]
            .as_str()
            .ok_or(OntologyToolError::Denied)?;
        let query = request["query"].as_str().ok_or(OntologyToolError::Denied)?;
        let query_lower = query.to_lowercase();
        let terms: Vec<Value> = match operation {
            "describe" => self.terms.get(query).cloned().into_iter().collect(),
            "search" => self
                .terms
                .values()
                .filter(|term| {
                    let text = format!(
                        "{} {} {}",
                        term["iri"].as_str().unwrap_or_default(),
                        term["labels"]
                            .as_array()
                            .unwrap_or(&Vec::new())
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" "),
                        term["aliases"]
                            .as_array()
                            .unwrap_or(&Vec::new())
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                    .to_lowercase();
                    query_lower
                        .split_whitespace()
                        .all(|token| text.contains(token))
                })
                .take(20)
                .cloned()
                .collect(),
            _ => return Err(OntologyToolError::Denied),
        };
        Ok(json!({
            "schema":"ctxql-extraction-vocabulary-response/v2",
            "capture":self.capture,
            "page":{"limit":20,"truncated":false,"cursor":null},
            "terms":terms
        }))
    }
}

#[allow(clippy::too_many_arguments)] // Fixture helper exposes each ontology term field.
fn term(
    iri: &str,
    kind: &str,
    label: &str,
    definition: &str,
    supers: &[&str],
    domains: &[&str],
    ranges: &[&str],
    complete: bool,
    imported: bool,
) -> Value {
    json!({
        "iri":iri,
        "kind":kind,
        "declarations":[],
        "status":"loaded_uncertified",
        "deprecated":false,
        "extraction_eligible":true,
        "approved_inventory_member":true,
        "imported":imported,
        "inventory_members":[if imported {"imports/Commons.rdf"} else {"fixture.rdf"}],
        "source_graphs":[if imported {"urn:test:imports"} else {"urn:test:primary"}],
        "super_terms":supers,
        "labels":[label],
        "definitions":[definition],
        "aliases":[],
        "constraints":{
            "domains":domains.iter().map(|iri| json!({"iri":iri,"provenance":"fixture","source_graphs":["urn:test:primary"]})).collect::<Vec<_>>(),
            "ranges":ranges.iter().map(|iri| json!({"iri":iri,"provenance":"fixture","source_graphs":["urn:test:primary"]})).collect::<Vec<_>>(),
            "anonymous_domain_present":!complete,
            "anonymous_range_present":false,
            "anonymous_super_present":false,
            "unsupported_expression_present":false,
            "complete":complete
        }
    })
}

fn manifest() -> OntologyBriefingSeedManifest {
    OntologyBriefingSeedManifest::from_json(
        br#"{"schema":"ctxql-ontology-briefing-seeds/v1","topic":"synthetic-loans","seeds":[{"iri":"urn:test:Loan","kind":"class","priority":1},{"iri":"urn:test:hasDateValue","kind":"datatype_property","priority":2}]}"#,
    )
    .unwrap()
}

fn host(definition: &str) -> FixtureHost {
    let terms = [
        term(
            "urn:test:Loan",
            "class",
            "Loan",
            "A loan.",
            &["urn:test:Agreement"],
            &[],
            &[],
            true,
            false,
        ),
        term(
            "urn:test:Agreement",
            "class",
            "Agreement",
            "An agreement.",
            &["urn:test:Cycle"],
            &[],
            &[],
            true,
            false,
        ),
        term(
            "urn:test:Cycle",
            "class",
            "Cycle",
            "Cycle node.",
            &["urn:test:Agreement"],
            &[],
            &[],
            false,
            false,
        ),
        term(
            "urn:test:Date",
            "class",
            "Date",
            "A date.",
            &[],
            &[],
            &[],
            true,
            true,
        ),
        term(
            "http://www.w3.org/2001/XMLSchema#string",
            "datatype",
            "string",
            "",
            &[],
            &[],
            &[],
            true,
            false,
        ),
        term(
            "urn:test:hasDateValue",
            "datatype_property",
            "has date value",
            definition,
            &[],
            &["urn:test:Date"],
            &["http://www.w3.org/2001/XMLSchema#string"],
            true,
            true,
        ),
        term(
            "urn:test:hasMaturityDate",
            "object_property",
            "has maturity date",
            "Relates a loan to its maturity date.",
            &[],
            &["urn:test:Loan"],
            &["urn:test:Date"],
            true,
            false,
        ),
    ]
    .into_iter()
    .map(|term| (term["iri"].as_str().unwrap().to_owned(), term))
    .collect();
    FixtureHost {
        capture: "sha256:fixture-capture",
        terms,
    }
}

fn context<'a>() -> OntologyBriefingContext<'a> {
    OntologyBriefingContext {
        passage: "The Loan has maturity date 2027-02-03.",
        title: Some("Loan terms"),
        headings: &["Maturity Date"],
        grounded_entity_names: &["Example Loan"],
    }
}

#[test]
fn includes_imported_datatype_property_and_lexical_nonseed_with_exact_definitions() {
    let result = build_ontology_briefing(
        &host("The exact source definition."),
        &manifest(),
        &context(),
        &OntologyBriefingLimits::default(),
    )
    .unwrap();
    let groups = result
        .rendering
        .pointer("/selection/groups")
        .unwrap()
        .as_array()
        .unwrap();
    let imported = groups
        .iter()
        .find(|group| group["iri"] == "urn:test:hasDateValue")
        .unwrap();
    assert_eq!(imported["term"]["kind"], "datatype_property");
    assert_eq!(imported["term"]["imported"], true);
    assert_eq!(
        imported["term"]["definitions"][0],
        "The exact source definition."
    );
    let lexical = groups
        .iter()
        .find(|group| group["iri"] == "urn:test:hasMaturityDate")
        .unwrap();
    assert_eq!(lexical["tier"], "lexical");
    assert_eq!(result.commitment, result.provenance["commitment"]);
}

#[test]
fn ancestor_cycles_terminate_and_incomplete_origin_paths_are_explicit() {
    let result = build_ontology_briefing(
        &host("Definition."),
        &manifest(),
        &context(),
        &OntologyBriefingLimits::default(),
    )
    .unwrap();
    let loan = result.rendering["selection"]["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["iri"] == "urn:test:Loan")
        .unwrap();
    assert_eq!(loan["inherited_metadata"]["complete"], false);
    assert!(
        loan["inherited_metadata"]["visited_nodes"]
            .as_u64()
            .unwrap()
            <= 3
    );
    let date_value = result.rendering["selection"]["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["iri"] == "urn:test:hasDateValue")
        .unwrap();
    assert_eq!(
        date_value["inherited_metadata"]["direct_constraints"][0]["origin"],
        "direct"
    );
    assert_eq!(
        date_value["inherited_metadata"]["direct_constraints"][0]["origin_path"][0],
        "urn:test:hasDateValue"
    );
}

#[test]
fn whole_group_budget_omission_is_deterministic() {
    let limits = OntologyBriefingLimits {
        max_serialized_bytes: 6_000,
        ..OntologyBriefingLimits::default()
    };
    let first =
        build_ontology_briefing(&host("Definition."), &manifest(), &context(), &limits).unwrap();
    let second =
        build_ontology_briefing(&host("Definition."), &manifest(), &context(), &limits).unwrap();
    assert_eq!(first.rendered_bytes, second.rendered_bytes);
    assert_eq!(
        first.rendering["selection"]["omitted"],
        second.rendering["selection"]["omitted"]
    );
    assert!(!first.rendering["selection"]["omitted"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(first.rendering["selection"]["groups"]
        .as_array()
        .unwrap()
        .iter()
        .all(|group| {
            group["tier"] == "seed"
                || !first.rendering["selection"]["omitted"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|omitted| omitted["iri"] == group["iri"])
        }));
}

#[test]
fn authoritative_definition_and_context_changes_affect_commitment() {
    let before = build_ontology_briefing(
        &host("Definition one."),
        &manifest(),
        &context(),
        &OntologyBriefingLimits::default(),
    )
    .unwrap();
    let after = build_ontology_briefing(
        &host("Definition two."),
        &manifest(),
        &context(),
        &OntologyBriefingLimits::default(),
    )
    .unwrap();
    assert_ne!(before.commitment, after.commitment);
    assert!(String::from_utf8(after.rendered_bytes)
        .unwrap()
        .contains("Definition two."));

    let changed_context = OntologyBriefingContext {
        passage: "The Loan has maturity date 2027-02-04.",
        ..context()
    };
    let context_changed = build_ontology_briefing(
        &host("Definition one."),
        &manifest(),
        &changed_context,
        &OntologyBriefingLimits::default(),
    )
    .unwrap();
    assert_ne!(before.commitment, context_changed.commitment);
}

#[test]
fn checked_in_loan_manifest_is_valid_and_topic_wide() {
    let manifest = loan_briefing_seed_manifest().unwrap();
    assert_eq!(manifest.topic, "loan-agreements");
    assert!(manifest
        .seeds
        .iter()
        .any(|seed| seed.iri.ends_with("/CreditAgreement")));
    assert!(manifest
        .seeds
        .iter()
        .any(|seed| seed.iri.ends_with("/hasDateValue")));
}

#[test]
fn missing_synthetic_seed_is_diagnostic_not_an_official_seed_fallback() {
    let missing = OntologyBriefingSeedManifest::from_json(br#"{"schema":"ctxql-ontology-briefing-seeds/v1","topic":"replacement","seeds":[{"iri":"urn:test:Absent","kind":"class","priority":1}]}"#).unwrap();
    let result = build_ontology_briefing(
        &host("Definition."),
        &missing,
        &OntologyBriefingContext {
            passage: "nothing",
            ..OntologyBriefingContext::default()
        },
        &OntologyBriefingLimits::default(),
    )
    .unwrap();
    assert_eq!(
        result.rendering["selection"]["diagnostics"][0]["code"],
        "configured_seed_missing"
    );
    assert!(!String::from_utf8(result.rendered_bytes)
        .unwrap()
        .contains("CreditAgreement"));
}
