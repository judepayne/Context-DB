//! Strict parsers for versioned `ctxql-extraction-proposals` envelopes.
//!
//! Historical v2 preserves model-provided component IDs. Wire v3 accepts
//! model labels only for entities and assigns all claim-component IDs in Rust.
//! This is intentionally separate from the historical CLAIM/FACT grammars.

use cdb_acquisition::proposals::{
    AliasProposal, AttributeProposal, ClassificationProposal, ComponentError, ComponentErrorCode,
    EntityProposal, EntityRef, Evidence, LiteralProposal, ProposalComponent, ProposalEnvelopeV2,
    ProposalLimits, RelationObject, RelationProposal, SemanticFit, SourceMode, TermChoice,
    TermSuggestion, PROPOSAL_SCHEMA_V2, PROPOSAL_SCHEMA_V3,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Number, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Clone, Debug)]
pub struct ProposalParseContext<'a> {
    pub passage_namespace: &'a str,
    pub issued_ranges: &'a [String],
    /// Only these host-issued document handles may appear in model output.
    pub document_handles: &'a [String],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalParseError {
    Limit(&'static str),
    Json(String),
    Envelope(&'static str),
    InvalidContext(&'static str),
}

impl fmt::Display for ProposalParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "invalid JSON: {error}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for ProposalParseError {}

type ShapeResult<T> = Result<T, ComponentErrorCode>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WireVersion {
    V2,
    V3,
}

/// Parses a proposal envelope according to its declared supported wire schema.
pub fn parse_proposals(
    text: &str,
    context: &ProposalParseContext<'_>,
    limits: &ProposalLimits,
) -> Result<ProposalEnvelopeV2, ProposalParseError> {
    let value = parse_strict_value(text, context, limits)?;
    let schema = value
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(Value::as_str)
        .ok_or(ProposalParseError::Envelope("schema"))?;
    match schema {
        PROPOSAL_SCHEMA_V2 => parse_proposals_value(value, context, limits, WireVersion::V2),
        PROPOSAL_SCHEMA_V3 => parse_proposals_value(value, context, limits, WireVersion::V3),
        _ => Err(ProposalParseError::Envelope("schema")),
    }
}

/// Parses exactly one historical closed v2 JSON envelope without renumbering
/// or otherwise repairing model-provided IDs.
pub fn parse_proposals_v2(
    text: &str,
    context: &ProposalParseContext<'_>,
    limits: &ProposalLimits,
) -> Result<ProposalEnvelopeV2, ProposalParseError> {
    let value = parse_strict_value(text, context, limits)?;
    parse_proposals_value(value, context, limits, WireVersion::V2)
}

/// Parses exactly one closed v3 envelope and assigns deterministic claim
/// component IDs from array positions. Entity IDs remain explicit model labels
/// because local references use them.
pub fn parse_proposals_v3(
    text: &str,
    context: &ProposalParseContext<'_>,
    limits: &ProposalLimits,
) -> Result<ProposalEnvelopeV2, ProposalParseError> {
    let value = parse_strict_value(text, context, limits)?;
    parse_proposals_value(value, context, limits, WireVersion::V3)
}

/// Parses an internally normalized v3 value. Wire adapters must enforce their
/// own raw-byte limit before using this helper.
pub(crate) fn parse_normalized_proposals_v3(
    value: Value,
    context: &ProposalParseContext<'_>,
    limits: &ProposalLimits,
) -> Result<ProposalEnvelopeV2, ProposalParseError> {
    validate_context(context, limits)?;
    parse_proposals_value(value, context, limits, WireVersion::V3)
}

fn parse_strict_value(
    text: &str,
    context: &ProposalParseContext<'_>,
    limits: &ProposalLimits,
) -> Result<Value, ProposalParseError> {
    if text.len() > limits.max_output_bytes {
        return Err(ProposalParseError::Limit("output_bytes"));
    }
    validate_context(context, limits)?;

    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| ProposalParseError::Json(error.to_string()))?
        .0;
    deserializer
        .end()
        .map_err(|error| ProposalParseError::Json(error.to_string()))?;
    Ok(value)
}

fn parse_proposals_value(
    value: Value,
    context: &ProposalParseContext<'_>,
    limits: &ProposalLimits,
    version: WireVersion,
) -> Result<ProposalEnvelopeV2, ProposalParseError> {
    let object = value
        .as_object()
        .ok_or(ProposalParseError::Envelope("object_required"))?;
    require_exact_fields(
        object,
        &["schema", "no_claims", "entities", "attributes", "relations"],
    )
    .map_err(envelope_shape)?;
    let expected_schema = match version {
        WireVersion::V2 => PROPOSAL_SCHEMA_V2,
        WireVersion::V3 => PROPOSAL_SCHEMA_V3,
    };
    if object.get("schema").and_then(Value::as_str) != Some(expected_schema) {
        return Err(ProposalParseError::Envelope("schema"));
    }
    let no_claims = object
        .get("no_claims")
        .and_then(Value::as_bool)
        .ok_or(ProposalParseError::Envelope("no_claims"))?;
    let entities_raw = required_array(object, "entities").map_err(envelope_shape)?;
    let attributes_raw = required_array(object, "attributes").map_err(envelope_shape)?;
    let relations_raw = required_array(object, "relations").map_err(envelope_shape)?;

    if entities_raw.len() > limits.max_entities {
        return Err(ProposalParseError::Limit("entities"));
    }
    if attributes_raw.len() > limits.max_attributes {
        return Err(ProposalParseError::Limit("attributes"));
    }
    if relations_raw.len() > limits.max_relations {
        return Err(ProposalParseError::Limit("relations"));
    }
    if no_claims
        != (entities_raw.is_empty() && attributes_raw.is_empty() && relations_raw.is_empty())
    {
        return Err(ProposalParseError::Envelope("no_claims_inconsistent"));
    }

    let mut raw_component_count = entities_raw.len() + attributes_raw.len() + relations_raw.len();
    for entity in entities_raw {
        if let Some(classes) = entity
            .as_object()
            .and_then(|object| object.get("classes"))
            .and_then(Value::as_array)
        {
            if classes.len() > limits.max_classes_per_entity {
                return Err(ProposalParseError::Limit("classes_per_entity"));
            }
            raw_component_count = raw_component_count.saturating_add(classes.len());
        }
    }
    if raw_component_count > limits.max_components {
        return Err(ProposalParseError::Limit("components"));
    }

    let allowed_ranges: BTreeSet<&str> = context.issued_ranges.iter().map(String::as_str).collect();
    let allowed_documents: BTreeSet<&str> = context
        .document_handles
        .iter()
        .map(String::as_str)
        .collect();

    let mut envelope = ProposalEnvelopeV2 {
        passage_namespace: context.passage_namespace.to_owned(),
        no_claims,
        entities: entities_raw
            .iter()
            .enumerate()
            .map(|(entity_index, value)| {
                component(
                    value,
                    parse_entity(value, entity_index, version, &allowed_ranges, limits),
                )
            })
            .collect(),
        attributes: attributes_raw
            .iter()
            .enumerate()
            .map(|(index, value)| {
                component(
                    value,
                    parse_attribute(
                        value,
                        index,
                        version,
                        context.passage_namespace,
                        &allowed_ranges,
                        &allowed_documents,
                        limits,
                    ),
                )
            })
            .collect(),
        relations: relations_raw
            .iter()
            .enumerate()
            .map(|(index, value)| {
                component(
                    value,
                    parse_relation(
                        value,
                        index,
                        version,
                        context.passage_namespace,
                        &allowed_ranges,
                        &allowed_documents,
                        limits,
                    ),
                )
            })
            .collect(),
    };

    match version {
        WireVersion::V2 => invalidate_duplicate_ids(&mut envelope),
        WireVersion::V3 => invalidate_v3_entity_ids(&mut envelope),
    }
    invalidate_unresolved_local_references(&mut envelope);
    Ok(envelope)
}

fn validate_context(
    context: &ProposalParseContext<'_>,
    limits: &ProposalLimits,
) -> Result<(), ProposalParseError> {
    if !valid_text(context.passage_namespace, limits.max_local_id_bytes, false) {
        return Err(ProposalParseError::InvalidContext("passage_namespace"));
    }
    let ranges: BTreeSet<&str> = context.issued_ranges.iter().map(String::as_str).collect();
    if ranges.len() != context.issued_ranges.len()
        || context
            .issued_ranges
            .iter()
            .any(|value| !valid_text(value, limits.max_label_bytes, false))
    {
        return Err(ProposalParseError::InvalidContext("issued_ranges"));
    }
    let documents: BTreeSet<&str> = context
        .document_handles
        .iter()
        .map(String::as_str)
        .collect();
    if documents.len() != context.document_handles.len()
        || context
            .document_handles
            .iter()
            .any(|value| !valid_text(value, limits.max_label_bytes, false))
    {
        return Err(ProposalParseError::InvalidContext("document_handles"));
    }
    Ok(())
}

fn component<T>(value: &Value, parsed: ShapeResult<T>) -> ProposalComponent<T> {
    ProposalComponent {
        original_json: serde_json::to_string(value)
            .expect("JSON value serialization is infallible"),
        original_text: None,
        value: parsed.map_err(ComponentError::new),
    }
}

fn parse_entity(
    value: &Value,
    entity_index: usize,
    version: WireVersion,
    ranges: &BTreeSet<&str>,
    limits: &ProposalLimits,
) -> ShapeResult<EntityProposal> {
    let object = closed_object(
        value,
        &[
            "id",
            "name",
            "aliases",
            "known_entity",
            "evidence",
            "classes",
        ],
    )?;
    let id = bounded_string(object, "id", limits.max_local_id_bytes, false)?;
    let name = bounded_string(object, "name", limits.max_label_bytes, false)?;
    let aliases = required_array(object, "aliases")?;
    if aliases.len() > limits.max_aliases {
        return Err(ComponentErrorCode::LimitExceeded);
    }
    let aliases = aliases
        .iter()
        .map(|value| component(value, parse_alias(value, ranges, limits)))
        .collect();
    let known_entity = nullable_bounded_string(object, "known_entity", limits.max_label_bytes)?;
    let evidence = parse_evidence_array(object, "evidence", ranges, limits)?;
    let classes = required_array(object, "classes")?;
    if classes.len() > limits.max_classes_per_entity {
        return Err(ComponentErrorCode::LimitExceeded);
    }
    let classes = classes
        .iter()
        .enumerate()
        .map(|(class_index, value)| {
            component(
                value,
                parse_classification(value, entity_index, class_index, version, ranges, limits),
            )
        })
        .collect();
    Ok(EntityProposal {
        id,
        name,
        aliases,
        known_entity,
        evidence,
        classes,
    })
}

fn parse_alias(
    value: &Value,
    ranges: &BTreeSet<&str>,
    limits: &ProposalLimits,
) -> ShapeResult<AliasProposal> {
    let object = closed_object(value, &["name", "evidence"])?;
    Ok(AliasProposal {
        name: bounded_string(object, "name", limits.max_label_bytes, false)?,
        evidence: parse_evidence(required(object, "evidence")?, ranges, limits)?,
    })
}

fn parse_classification(
    value: &Value,
    entity_index: usize,
    class_index: usize,
    version: WireVersion,
    ranges: &BTreeSet<&str>,
    limits: &ProposalLimits,
) -> ShapeResult<ClassificationProposal> {
    let fields = match version {
        WireVersion::V2 => &["id", "term", "evidence", "source_mode", "fit", "fit_note"][..],
        WireVersion::V3 => &["term", "evidence", "source_mode", "fit", "fit_note"][..],
    };
    let object = closed_object(value, fields)?;
    Ok(ClassificationProposal {
        id: match version {
            WireVersion::V2 => bounded_string(object, "id", limits.max_local_id_bytes, false)?,
            WireVersion::V3 => generated_class_id(entity_index, class_index),
        },
        term: parse_term_choice(required(object, "term")?, limits)?,
        evidence: parse_evidence_array(object, "evidence", ranges, limits)?,
        source_mode: parse_source_mode(required_string(object, "source_mode")?)?,
        fit: parse_fit(required_string(object, "fit")?)?,
        fit_note: bounded_string(object, "fit_note", limits.max_fit_note_bytes, true)?,
    })
}

fn parse_attribute(
    value: &Value,
    index: usize,
    version: WireVersion,
    namespace: &str,
    ranges: &BTreeSet<&str>,
    documents: &BTreeSet<&str>,
    limits: &ProposalLimits,
) -> ShapeResult<AttributeProposal> {
    let fields = match version {
        WireVersion::V2 => &[
            "id",
            "subject",
            "predicate",
            "value",
            "evidence",
            "source_mode",
            "qualifiers",
            "fit",
            "fit_note",
        ][..],
        WireVersion::V3 => &[
            "subject",
            "predicate",
            "value",
            "evidence",
            "source_mode",
            "qualifiers",
            "fit",
            "fit_note",
        ][..],
    };
    let object = closed_object(value, fields)?;
    let literal = closed_object(required(object, "value")?, &["lexical", "datatype"])?;
    Ok(AttributeProposal {
        id: match version {
            WireVersion::V2 => bounded_string(object, "id", limits.max_local_id_bytes, false)?,
            WireVersion::V3 => generated_attribute_id(index),
        },
        subject: parse_entity_ref(required(object, "subject")?, namespace, documents, limits)?,
        predicate: parse_term_choice(required(object, "predicate")?, limits)?,
        value: LiteralProposal {
            lexical: bounded_string(literal, "lexical", limits.max_literal_bytes, false)?,
            datatype: parse_term_choice(required(literal, "datatype")?, limits)?,
        },
        evidence: parse_evidence_array(object, "evidence", ranges, limits)?,
        source_mode: parse_source_mode(required_string(object, "source_mode")?)?,
        qualifiers: parse_qualifiers(object, limits)?,
        fit: parse_fit(required_string(object, "fit")?)?,
        fit_note: bounded_string(object, "fit_note", limits.max_fit_note_bytes, true)?,
    })
}

fn parse_relation(
    value: &Value,
    index: usize,
    version: WireVersion,
    namespace: &str,
    ranges: &BTreeSet<&str>,
    documents: &BTreeSet<&str>,
    limits: &ProposalLimits,
) -> ShapeResult<RelationProposal> {
    let fields = match version {
        WireVersion::V2 => &[
            "id",
            "subject",
            "predicate",
            "object",
            "evidence",
            "source_mode",
            "qualifiers",
            "fit",
            "fit_note",
        ][..],
        WireVersion::V3 => &[
            "subject",
            "predicate",
            "object",
            "evidence",
            "source_mode",
            "qualifiers",
            "fit",
            "fit_note",
        ][..],
    };
    let object = closed_object(value, fields)?;
    Ok(RelationProposal {
        id: match version {
            WireVersion::V2 => bounded_string(object, "id", limits.max_local_id_bytes, false)?,
            WireVersion::V3 => generated_relation_id(index),
        },
        subject: parse_entity_ref(required(object, "subject")?, namespace, documents, limits)?,
        predicate: parse_term_choice(required(object, "predicate")?, limits)?,
        object: parse_relation_object(required(object, "object")?, namespace, documents, limits)?,
        evidence: parse_evidence_array(object, "evidence", ranges, limits)?,
        source_mode: parse_source_mode(required_string(object, "source_mode")?)?,
        qualifiers: parse_qualifiers(object, limits)?,
        fit: parse_fit(required_string(object, "fit")?)?,
        fit_note: bounded_string(object, "fit_note", limits.max_fit_note_bytes, true)?,
    })
}

fn parse_term_choice(value: &Value, limits: &ProposalLimits) -> ShapeResult<TermChoice> {
    let object = closed_object(value, &["suggestions", "selected"])?;
    let raw = required_array(object, "suggestions")?;
    if raw.is_empty() || raw.len() > limits.max_suggestions {
        return Err(ComponentErrorCode::LimitExceeded);
    }
    let suggestions = raw
        .iter()
        .map(|value| {
            let item = closed_object(value, &["text", "note"])?;
            Ok(TermSuggestion {
                text: bounded_string(item, "text", limits.max_label_bytes, false)?,
                note: bounded_string(item, "note", limits.max_fit_note_bytes, true)?,
            })
        })
        .collect::<ShapeResult<Vec<_>>>()?;
    let selected = match required(object, "selected")? {
        Value::Null => None,
        Value::Number(number) => {
            let index = number.as_u64().ok_or(ComponentErrorCode::InvalidType)?;
            let index = usize::try_from(index).map_err(|_| ComponentErrorCode::InvalidValue)?;
            if index >= suggestions.len() {
                return Err(ComponentErrorCode::InvalidValue);
            }
            Some(index)
        }
        _ => return Err(ComponentErrorCode::InvalidType),
    };
    Ok(TermChoice {
        suggestions,
        selected,
    })
}

fn parse_evidence_array(
    object: &Map<String, Value>,
    field: &str,
    ranges: &BTreeSet<&str>,
    limits: &ProposalLimits,
) -> ShapeResult<Vec<Evidence>> {
    let raw = required_array(object, field)?;
    if raw.len() > limits.max_evidence {
        return Err(ComponentErrorCode::LimitExceeded);
    }
    raw.iter()
        .map(|value| parse_evidence(value, ranges, limits))
        .collect()
}

fn parse_evidence(
    value: &Value,
    ranges: &BTreeSet<&str>,
    limits: &ProposalLimits,
) -> ShapeResult<Evidence> {
    let object = closed_object(value, &["range", "quote", "occurrence"])?;
    let range = bounded_string(object, "range", limits.max_label_bytes, false)?;
    if !ranges.contains(range.as_str()) {
        return Err(ComponentErrorCode::UnresolvedReference);
    }
    let occurrence = required(object, "occurrence")?
        .as_u64()
        .ok_or(ComponentErrorCode::InvalidType)?;
    Ok(Evidence {
        range,
        quote: bounded_string(object, "quote", limits.max_excerpt_bytes, false)?,
        occurrence: usize::try_from(occurrence).map_err(|_| ComponentErrorCode::InvalidValue)?,
    })
}

fn parse_entity_ref(
    value: &Value,
    namespace: &str,
    documents: &BTreeSet<&str>,
    limits: &ProposalLimits,
) -> ShapeResult<EntityRef> {
    let object = value.as_object().ok_or(ComponentErrorCode::InvalidType)?;
    let kind = required_string(object, "kind")?;
    match kind {
        "local" => {
            require_exact_fields(object, &["kind", "id"])?;
            Ok(EntityRef::Local {
                passage_namespace: namespace.to_owned(),
                id: bounded_string(object, "id", limits.max_local_id_bytes, false)?,
            })
        }
        "document" => {
            require_exact_fields(object, &["kind", "handle"])?;
            let handle = bounded_string(object, "handle", limits.max_label_bytes, false)?;
            if !documents.contains(handle.as_str()) {
                return Err(ComponentErrorCode::UnresolvedReference);
            }
            Ok(EntityRef::Document { handle })
        }
        "known" => {
            require_exact_fields(object, &["kind", "iri"])?;
            Ok(EntityRef::Known {
                proposed_iri: bounded_string(object, "iri", limits.max_label_bytes, false)?,
            })
        }
        _ => Err(ComponentErrorCode::InvalidValue),
    }
}

fn parse_relation_object(
    value: &Value,
    namespace: &str,
    documents: &BTreeSet<&str>,
    limits: &ProposalLimits,
) -> ShapeResult<RelationObject> {
    if value
        .as_object()
        .and_then(|object| object.get("kind"))
        .and_then(Value::as_str)
        == Some("unresolved")
    {
        let object = closed_object(value, &["kind", "text"])?;
        return Ok(RelationObject::Unresolved {
            text: bounded_string(object, "text", limits.max_label_bytes, false)?,
        });
    }
    parse_entity_ref(value, namespace, documents, limits).map(RelationObject::Entity)
}

fn parse_qualifiers(
    object: &Map<String, Value>,
    limits: &ProposalLimits,
) -> ShapeResult<Vec<String>> {
    let values = required_array(object, "qualifiers")?;
    if values.len() > limits.max_qualifiers {
        return Err(ComponentErrorCode::LimitExceeded);
    }
    values
        .iter()
        .map(|value| {
            let value = value.as_str().ok_or(ComponentErrorCode::InvalidType)?;
            if !valid_text(value, limits.max_qualifier_bytes, false) {
                return Err(ComponentErrorCode::InvalidValue);
            }
            Ok(value.to_owned())
        })
        .collect()
}

fn parse_source_mode(value: &str) -> ShapeResult<SourceMode> {
    match value {
        "affirmative" => Ok(SourceMode::Affirmative),
        "negative" => Ok(SourceMode::Negative),
        "conditional" => Ok(SourceMode::Conditional),
        "attributed" => Ok(SourceMode::Attributed),
        "hypothetical" => Ok(SourceMode::Hypothetical),
        "unknown" => Ok(SourceMode::Unknown),
        _ => Err(ComponentErrorCode::InvalidValue),
    }
}

fn parse_fit(value: &str) -> ShapeResult<SemanticFit> {
    match value {
        "supported" => Ok(SemanticFit::Supported),
        "uncertain" => Ok(SemanticFit::Uncertain),
        "not_evaluated" => Ok(SemanticFit::NotEvaluated),
        _ => Err(ComponentErrorCode::InvalidValue),
    }
}

fn generated_class_id(entity_index: usize, class_index: usize) -> String {
    format!("host/classification/{entity_index}/{class_index}")
}

fn generated_attribute_id(index: usize) -> String {
    format!("host/attribute/{index}")
}

fn generated_relation_id(index: usize) -> String {
    format!("host/relation/{index}")
}

fn is_generated_component_id(id: &str) -> bool {
    id.strip_prefix("host/attribute/")
        .or_else(|| id.strip_prefix("host/relation/"))
        .is_some_and(|index| index.parse::<usize>().is_ok())
        || id
            .strip_prefix("host/classification/")
            .and_then(|indices| indices.split_once('/'))
            .is_some_and(|(entity, class)| {
                entity.parse::<usize>().is_ok() && class.parse::<usize>().is_ok()
            })
}

fn invalidate_v3_entity_ids(envelope: &mut ProposalEnvelopeV2) {
    let mut counts = BTreeMap::<String, usize>::new();
    for entity in &envelope.entities {
        if let Ok(entity) = &entity.value {
            *counts.entry(entity.id.clone()).or_default() += 1;
        }
    }
    let invalid: BTreeSet<String> = counts
        .into_iter()
        .filter_map(|(id, count)| (count > 1 || is_generated_component_id(&id)).then_some(id))
        .collect();
    for entity in &mut envelope.entities {
        if entity
            .value
            .as_ref()
            .is_ok_and(|entity| invalid.contains(&entity.id))
        {
            entity.value = Err(ComponentError::new(ComponentErrorCode::DuplicateId));
        }
    }
}

fn invalidate_duplicate_ids(envelope: &mut ProposalEnvelopeV2) {
    let mut counts = BTreeMap::<String, usize>::new();
    for entity in &envelope.entities {
        if let Ok(entity) = &entity.value {
            *counts.entry(entity.id.clone()).or_default() += 1;
            for class in &entity.classes {
                if let Ok(class) = &class.value {
                    *counts.entry(class.id.clone()).or_default() += 1;
                }
            }
        }
    }
    for attribute in &envelope.attributes {
        if let Ok(attribute) = &attribute.value {
            *counts.entry(attribute.id.clone()).or_default() += 1;
        }
    }
    for relation in &envelope.relations {
        if let Ok(relation) = &relation.value {
            *counts.entry(relation.id.clone()).or_default() += 1;
        }
    }
    let duplicates: BTreeSet<String> = counts
        .into_iter()
        .filter_map(|(id, count)| (count > 1).then_some(id))
        .collect();
    for entity in &mut envelope.entities {
        if entity
            .value
            .as_ref()
            .is_ok_and(|entity| duplicates.contains(&entity.id))
        {
            entity.value = Err(ComponentError::new(ComponentErrorCode::DuplicateId));
            continue;
        }
        if let Ok(entity) = &mut entity.value {
            for class in &mut entity.classes {
                if class
                    .value
                    .as_ref()
                    .is_ok_and(|class| duplicates.contains(&class.id))
                {
                    class.value = Err(ComponentError::new(ComponentErrorCode::DuplicateId));
                }
            }
        }
    }
    for attribute in &mut envelope.attributes {
        if attribute
            .value
            .as_ref()
            .is_ok_and(|attribute| duplicates.contains(&attribute.id))
        {
            attribute.value = Err(ComponentError::new(ComponentErrorCode::DuplicateId));
        }
    }
    for relation in &mut envelope.relations {
        if relation
            .value
            .as_ref()
            .is_ok_and(|relation| duplicates.contains(&relation.id))
        {
            relation.value = Err(ComponentError::new(ComponentErrorCode::DuplicateId));
        }
    }
}

fn invalidate_unresolved_local_references(envelope: &mut ProposalEnvelopeV2) {
    let valid_entities: BTreeSet<String> = envelope
        .entities
        .iter()
        .filter_map(|component| {
            component
                .value
                .as_ref()
                .ok()
                .map(|entity| entity.id.clone())
        })
        .collect();
    for attribute in &mut envelope.attributes {
        if attribute.value.as_ref().is_ok_and(|attribute| {
            local_id(&attribute.subject).is_some_and(|id| !valid_entities.contains(id))
        }) {
            attribute.value = Err(ComponentError::new(ComponentErrorCode::UnresolvedReference));
        }
    }
    for relation in &mut envelope.relations {
        if relation.value.as_ref().is_ok_and(|relation| {
            local_id(&relation.subject).is_some_and(|id| !valid_entities.contains(id))
                || match &relation.object {
                    RelationObject::Entity(reference) => {
                        local_id(reference).is_some_and(|id| !valid_entities.contains(id))
                    }
                    RelationObject::Unresolved { .. } => false,
                }
        }) {
            relation.value = Err(ComponentError::new(ComponentErrorCode::UnresolvedReference));
        }
    }
}

fn local_id(reference: &EntityRef) -> Option<&str> {
    match reference {
        EntityRef::Local { id, .. } => Some(id),
        EntityRef::Document { .. } | EntityRef::Known { .. } => None,
    }
}

fn closed_object<'a>(value: &'a Value, fields: &[&str]) -> ShapeResult<&'a Map<String, Value>> {
    let object = value.as_object().ok_or(ComponentErrorCode::InvalidType)?;
    require_exact_fields(object, fields)?;
    Ok(object)
}

fn require_exact_fields(object: &Map<String, Value>, fields: &[&str]) -> ShapeResult<()> {
    if fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(ComponentErrorCode::MissingField);
    }
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(ComponentErrorCode::UnknownField);
    }
    Ok(())
}

fn required<'a>(object: &'a Map<String, Value>, field: &str) -> ShapeResult<&'a Value> {
    object.get(field).ok_or(ComponentErrorCode::MissingField)
}

fn required_array<'a>(object: &'a Map<String, Value>, field: &str) -> ShapeResult<&'a Vec<Value>> {
    required(object, field)?
        .as_array()
        .ok_or(ComponentErrorCode::InvalidType)
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> ShapeResult<&'a str> {
    required(object, field)?
        .as_str()
        .ok_or(ComponentErrorCode::InvalidType)
}

fn bounded_string(
    object: &Map<String, Value>,
    field: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> ShapeResult<String> {
    let value = required_string(object, field)?;
    if !valid_text(value, max_bytes, allow_empty) {
        return Err(ComponentErrorCode::InvalidValue);
    }
    Ok(value.to_owned())
}

fn nullable_bounded_string(
    object: &Map<String, Value>,
    field: &str,
    max_bytes: usize,
) -> ShapeResult<Option<String>> {
    match required(object, field)? {
        Value::Null => Ok(None),
        Value::String(value) if valid_text(value, max_bytes, false) => Ok(Some(value.clone())),
        Value::String(_) => Err(ComponentErrorCode::InvalidValue),
        _ => Err(ComponentErrorCode::InvalidType),
    }
}

fn valid_text(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn envelope_shape(error: ComponentErrorCode) -> ProposalParseError {
    match error {
        ComponentErrorCode::MissingField => ProposalParseError::Envelope("missing_field"),
        ComponentErrorCode::UnknownField => ProposalParseError::Envelope("unknown_field"),
        _ => ProposalParseError::Envelope("invalid_field"),
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(|number| StrictValue(Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            let value = map.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}
