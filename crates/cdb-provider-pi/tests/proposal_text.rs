use cdb_acquisition::proposals::{
    ComponentErrorCode, EntityRef, ProposalLimits, RelationObject, SourceMode,
};
use cdb_provider_pi::proposal_protocol::{
    parse_proposals_v3, ProposalParseContext, ProposalParseError,
};
use cdb_provider_pi::proposal_text::{parse_proposals_text, TEXT_PROPOSAL_PROTOCOL};
use serde_json::json;

fn context<'a>(ranges: &'a [String], documents: &'a [String]) -> ProposalParseContext<'a> {
    ProposalParseContext {
        passage_namespace: "passage-7",
        issued_ranges: ranges,
        document_handles: documents,
    }
}

fn parse(text: &str) -> cdb_provider_pi::proposal_text::TextProposalEnvelope {
    let ranges = vec!["h1".to_owned()];
    let documents = vec!["doc-1".to_owned()];
    parse_proposals_text(
        text,
        &context(&ranges, &documents),
        &ProposalLimits::default(),
    )
    .unwrap()
}

fn entity(id: &str, name: &str) -> String {
    format!(
        "ENTITY:\nId: {id}\nName: {name}\nKnown entity: none\nEVIDENCE:\nRange: h1\nOccurrence: 0\nQuote: {name}\n---"
    )
}

fn relation(subject: &str, object: &str, quote: &str) -> String {
    format!(
        "CLAIM:\nKind: relation\nSubject: {subject}\nPredicate: urn:test:p\nPredicate note:\nPredicate selected: 0\nObject: {object}\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nEVIDENCE:\nRange: h1\nOccurrence: 0\nQuote: {quote}\n---"
    )
}

#[test]
fn sentinel_words_in_scalar_values_are_not_control_lines() {
    let parsed = parse(&entity("e1", "NO_CLAIMS"));
    assert_eq!(
        parsed.envelope.entities[0].parsed().unwrap().name,
        "NO_CLAIMS"
    );
}

#[test]
fn malformed_duplicate_id_fields_do_not_redirect_references_to_a_sibling() {
    let bad = entity("e1", "Bad").replace("Name: Bad", "Id: e2\nName: Bad");
    let text = format!(
        "{bad}\n{}\n{}",
        entity("e2", "Good"),
        relation("local e2", "known urn:test:target", "quote")
    );
    let parsed = parse(&text);
    assert!(parsed
        .envelope
        .entities
        .iter()
        .all(|component| component.parsed().is_none()));
    assert!(parsed.envelope.relations[0].parsed().is_none());
}

#[test]
fn orphan_classifications_cannot_bypass_total_component_limit() {
    let text = "CLAIM:\nKind: classification\nSubject: local missing\nTerm: urn:test:Class\nTerm note:\nTerm selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\n---";
    let limits = ProposalLimits {
        max_components: 1,
        ..ProposalLimits::default()
    };
    assert!(matches!(
        parse_proposals_text(&format!("{text}\n{text}"), &context(&[], &[]), &limits),
        Err(ProposalParseError::Limit("components"))
    ));
}

#[test]
fn exposes_protocol_and_parses_every_record_type_and_reference_variant() {
    assert_eq!(TEXT_PROPOSAL_PROTOCOL, "ctxql-extraction-text/v1");
    let text = include_str!("../../../fixtures/conformance/p6/extraction-text/valid-all.txt");
    let parsed = parse(text);
    assert!(parsed.diagnostics.is_empty());
    assert_eq!(parsed.envelope.entities.len(), 1);
    assert_eq!(parsed.envelope.attributes.len(), 1);
    assert_eq!(parsed.envelope.relations.len(), 2);

    let entity_proposal = parsed.envelope.entities[0].parsed().unwrap();
    assert_eq!(entity_proposal.aliases.len(), 1);
    assert_eq!(entity_proposal.classes.len(), 1);
    assert_eq!(
        entity_proposal.classes[0]
            .parsed()
            .unwrap()
            .term
            .suggestions
            .len(),
        2
    );
    assert_eq!(
        entity_proposal.classes[0].parsed().unwrap().id,
        "host/classification/0/0"
    );
    assert_eq!(
        entity_proposal.known_entity.as_deref(),
        Some("urn:test:Orion")
    );
    assert!(entity_proposal.aliases[0]
        .original_text
        .as_deref()
        .unwrap()
        .contains("Name: Orion | \"Facility\": {A} \\\\ B"));

    let attribute = parsed.envelope.attributes[0].parsed().unwrap();
    assert!(matches!(attribute.subject, EntityRef::Document { ref handle } if handle == "doc-1"));
    assert_eq!(attribute.predicate.selected, None);
    assert_eq!(attribute.qualifiers, ["according to schedule"]);
    assert_eq!(attribute.evidence[0].quote, "---");
    assert_eq!(
        attribute.value.lexical,
        "literal: | \"quoted\" {braced} \\\\ slash"
    );

    let relation = parsed.envelope.relations[0].parsed().unwrap();
    assert!(
        matches!(relation.object, RelationObject::Entity(EntityRef::Known { ref proposed_iri }) if proposed_iri == "urn:test:Acme")
    );
    assert_eq!(relation.source_mode, SourceMode::Conditional);
    assert!(matches!(
        parsed.envelope.relations[1].parsed().unwrap().object,
        RelationObject::Unresolved { ref text } if text == "the lender: {unknown}"
    ));
    assert!(parsed.envelope.entities[0].original_json.starts_with('{'));
    assert_eq!(
        parsed.envelope.entities[0].original_text.as_deref(),
        Some("ENTITY:\nId: e1\nName: Orion\nKnown entity: iri urn:test:Orion\nEVIDENCE:\nRange: h1\nOccurrence: 1\nQuote: Orion\n---")
    );
}

#[test]
fn no_claims_is_exact_and_json_components_have_no_original_text() {
    let sentinel = include_str!("../../../fixtures/conformance/p6/extraction-text/no-claims.txt");
    assert!(parse(sentinel).envelope.no_claims);
    assert!(matches!(
        parse_proposals_text(" NO_CLAIMS", &context(&[], &[]), &ProposalLimits::default()),
        Err(ProposalParseError::Envelope("text_framing"))
    ));

    let wire = json!({
        "schema":"ctxql-extraction-proposals/v3", "no_claims":false,
        "entities":[{"id":"e","name":"E","aliases":[],"known_entity":null,"evidence":[],"classes":[]}],
        "attributes":[],"relations":[]
    })
    .to_string();
    let parsed = parse_proposals_v3(&wire, &context(&[], &[]), &ProposalLimits::default()).unwrap();
    assert_eq!(parsed.entities[0].original_text, None);
}

#[test]
fn lf_crlf_and_utf8_byte_bounds_are_strict() {
    let lf = format!("{}\n", entity("e", "€"));
    let crlf = lf.replace('\n', "\r\n");
    assert_eq!(parse(&lf).envelope.entities[0].parsed().unwrap().name, "€");
    assert_eq!(
        parse(&crlf).envelope.entities[0].parsed().unwrap().name,
        "€"
    );

    let ranges = vec!["h1".to_owned()];
    let limits = ProposalLimits {
        max_label_bytes: 2,
        ..ProposalLimits::default()
    };
    let parsed = parse_proposals_text(&lf, &context(&ranges, &[]), &limits).unwrap();
    assert_eq!(
        parsed.envelope.entities[0].value.as_ref().unwrap_err().code,
        ComponentErrorCode::InvalidValue
    );
    assert!(matches!(
        parse_proposals_text(
            &lf.replace("\nName", "\r\nName"),
            &context(&ranges, &[]),
            &ProposalLimits::default()
        ),
        Err(ProposalParseError::Envelope("mixed_line_endings"))
    ));
}

#[test]
fn invalid_component_slots_and_good_siblings_keep_structural_numbering() {
    let bad_attribute = "CLAIM:\nKind: attribute\nSubject: local e\nPredicate: urn:test:p\nPredicate selected: 0\nValue: x\nDatatype: urn:test:t\nDatatype note:\nDatatype selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\n---";
    let good_attribute = "CLAIM:\nKind: attribute\nSubject: local e\nPredicate: urn:test:p\nPredicate note:\nPredicate selected: 0\nValue: x\nDatatype: urn:test:t\nDatatype note:\nDatatype selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\n---";
    let text = format!(
        "{}\n{}\n{}\n{}",
        entity("e", "E"),
        bad_attribute,
        good_attribute,
        relation("local e", "local e", "E")
    );
    let parsed = parse(&text);
    assert_eq!(parsed.envelope.attributes.len(), 2);
    assert_eq!(
        parsed.envelope.attributes[0]
            .value
            .as_ref()
            .unwrap_err()
            .code,
        ComponentErrorCode::MissingField
    );
    assert_eq!(
        parsed.envelope.attributes[1].parsed().unwrap().id,
        "host/attribute/1"
    );
    assert_eq!(
        parsed.envelope.relations[0].parsed().unwrap().id,
        "host/relation/0"
    );
}

#[test]
fn unknown_fields_are_isolated_but_claim_kind_and_framing_fail_globally() {
    let bad = "CLAIM:\nKind: relation\nSubject: local e\nSurprise: x\n---";
    let text = format!(
        "{}\n{}\n{}",
        entity("e", "E"),
        bad,
        relation("local e", "local e", "E")
    );
    let parsed = parse(&text);
    assert_eq!(
        parsed.envelope.relations[0]
            .value
            .as_ref()
            .unwrap_err()
            .code,
        ComponentErrorCode::UnknownField
    );
    assert!(parsed.envelope.relations[1].value.is_ok());

    for malformed in [
        "CLAIM:\nSubject: local e\n---",
        "CLAIM:\nKind: invented\n---",
        "ENTITY:\nId: e\nENTITY:\nId: f\n---",
        "ENTITY:\nId: e",
        "PROSE:\nx\n---",
    ] {
        assert!(
            parse_proposals_text(malformed, &context(&[], &[]), &ProposalLimits::default())
                .is_err(),
            "{malformed}"
        );
    }
}

#[test]
fn forward_dependants_resolve_but_duplicates_and_orphans_fail_closed() {
    let alias = "ALIAS:\nEntity: e\nName: E alias\nEVIDENCE:\nRange: h1\nOccurrence: 0\nQuote: E alias\n---";
    let class = "CLAIM:\nKind: classification\nSubject: local e\nTerm: urn:test:C\nTerm note:\nTerm selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\n---";
    let forward = parse(&format!("{alias}\n{class}\n{}", entity("e", "E")));
    let entity_proposal = forward.envelope.entities[0].parsed().unwrap();
    assert_eq!(entity_proposal.aliases.len(), 1);
    assert_eq!(entity_proposal.classes.len(), 1);

    let duplicate = parse(&format!(
        "{}\n{}\n{alias}\n{class}",
        entity("e", "One"),
        entity("e", "Two")
    ));
    assert!(duplicate.envelope.entities.iter().all(|component| component
        .value
        .as_ref()
        .unwrap_err()
        .code
        == ComponentErrorCode::DuplicateId));
    assert_eq!(duplicate.diagnostics.len(), 2);
    assert!(duplicate
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.code == ComponentErrorCode::UnresolvedReference));
    assert_eq!(duplicate.diagnostics[0].record_index, 2);

    let orphan = parse(&alias.replace("Entity: e", "Entity: missing"));
    assert_eq!(
        orphan.diagnostics[0].code,
        ComponentErrorCode::UnresolvedReference
    );
    assert_eq!(
        orphan.diagnostics[0].original_text,
        alias.replace("Entity: e", "Entity: missing")
    );
}

#[test]
fn physical_record_limit_precedes_semantic_array_limits() {
    let text = (0..769)
        .map(|index| entity(&format!("e{index}"), "E"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        parse_proposals_text(
            &text,
            &context(&["h1".to_owned()], &[]),
            &ProposalLimits::default()
        ),
        Err(ProposalParseError::Limit("physical_records"))
    );
}

#[test]
fn accepts_every_metadata_enum_and_rejects_illegal_class_qualifiers() {
    for source_mode in [
        "affirmative",
        "negative",
        "conditional",
        "attributed",
        "hypothetical",
        "unknown",
    ] {
        for fit in ["supported", "uncertain", "not_evaluated"] {
            let record = relation("known urn:test:S", "unresolved object", "support")
                .replace(
                    "Source mode: affirmative",
                    &format!("Source mode: {source_mode}"),
                )
                .replace("Fit: supported", &format!("Fit: {fit}"));
            assert!(parse(&record).envelope.relations[0].value.is_ok());
        }
    }

    let class = "CLAIM:\nKind: classification\nSubject: local e\nTerm: urn:test:C\nTerm note:\nTerm selected: 0\nCLAIM_METADATA:\nSource mode: affirmative\nFit: supported\nFit note:\nQualifier: illegal\n---";
    let parsed = parse(&format!("{}\n{class}", entity("e", "E")));
    assert_eq!(
        parsed.envelope.entities[0].parsed().unwrap().classes[0]
            .value
            .as_ref()
            .unwrap_err()
            .code,
        ComponentErrorCode::InvalidValue
    );
}

#[test]
fn text_and_v3_json_are_semantically_equivalent() {
    let text = format!(
        "{}\n{}",
        entity("e", "E"),
        relation("local e", "document doc-1", "E")
    );
    let text_parsed = parse(&text).envelope;
    let json_wire = json!({
        "schema":"ctxql-extraction-proposals/v3","no_claims":false,
        "entities":[{"id":"e","name":"E","aliases":[],"known_entity":null,
            "evidence":[{"range":"h1","occurrence":0,"quote":"E"}],"classes":[]}],
        "attributes":[],
        "relations":[{"subject":{"kind":"local","id":"e"},
            "predicate":{"suggestions":[{"text":"urn:test:p","note":""}],"selected":0},
            "object":{"kind":"document","handle":"doc-1"},
            "evidence":[{"range":"h1","occurrence":0,"quote":"E"}],
            "source_mode":"affirmative","qualifiers":[],"fit":"supported","fit_note":""}]
    })
    .to_string();
    let ranges = vec!["h1".to_owned()];
    let documents = vec!["doc-1".to_owned()];
    let json_parsed = parse_proposals_v3(
        &json_wire,
        &context(&ranges, &documents),
        &ProposalLimits::default(),
    )
    .unwrap();

    assert_eq!(text_parsed.entities[0].value, json_parsed.entities[0].value);
    assert_eq!(
        text_parsed.relations[0].value,
        json_parsed.relations[0].value
    );
}
