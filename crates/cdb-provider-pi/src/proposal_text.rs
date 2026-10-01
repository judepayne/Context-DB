//! Parser for the line-oriented `ctxql-extraction-text/v1` wire protocol.

use crate::proposal_protocol::{
    parse_normalized_proposals_v3, ProposalParseContext, ProposalParseError,
};
use cdb_acquisition::proposals::{
    ComponentError, ComponentErrorCode, ProposalComponent, ProposalEnvelopeV2, ProposalLimits,
    PROPOSAL_SCHEMA_V3,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const TEXT_PROPOSAL_PROTOCOL: &str = "ctxql-extraction-text/v1";
const MAX_PHYSICAL_RECORDS: usize = 768;

type ShapeResult<T> = Result<T, ComponentErrorCode>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextProposalEnvelope {
    pub envelope: ProposalEnvelopeV2,
    pub diagnostics: Vec<TextProposalDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextProposalDiagnostic {
    pub original_text: String,
    pub record_index: usize,
    pub code: ComponentErrorCode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordKind {
    Entity,
    Alias,
    Classification,
    Attribute,
    Relation,
}

#[derive(Debug)]
struct ParsedRecord {
    kind: RecordKind,
    raw: String,
    record_index: usize,
    value: Value,
    error: Option<ComponentErrorCode>,
    parent: Option<String>,
}

#[derive(Clone, Copy)]
struct Line<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

/// Parses one response bound by the host to `ctxql-extraction-text/v1`.
pub fn parse_proposals_text(
    text: &str,
    context: &ProposalParseContext<'_>,
    limits: &ProposalLimits,
) -> Result<TextProposalEnvelope, ProposalParseError> {
    if text.len() > limits.max_output_bytes {
        return Err(ProposalParseError::Limit("output_bytes"));
    }
    if text == "NO_CLAIMS" {
        let value = json!({
            "schema": PROPOSAL_SCHEMA_V3,
            "no_claims": true,
            "entities": [],
            "attributes": [],
            "relations": []
        });
        return Ok(TextProposalEnvelope {
            envelope: parse_normalized_proposals_v3(value, context, limits)?,
            diagnostics: Vec::new(),
        });
    }
    if text.is_empty() || text.trim() == "NO_CLAIMS" {
        return Err(ProposalParseError::Envelope("text_framing"));
    }

    let lines = split_lines(text)?;
    let blocks = frame_records(text, &lines)?;
    if blocks.len() > MAX_PHYSICAL_RECORDS {
        return Err(ProposalParseError::Limit("physical_records"));
    }

    let mut records = Vec::with_capacity(blocks.len());
    for (record_index, (raw, block_lines)) in blocks.into_iter().enumerate() {
        records.push(parse_record(raw, block_lines, record_index, limits)?);
    }

    // Count even rejected/unassignable records before parent resolution: orphan
    // diagnostics must not bypass the total component ceiling.
    if records
        .iter()
        .filter(|record| record.kind != RecordKind::Alias)
        .count()
        > limits.max_components
    {
        return Err(ProposalParseError::Limit("components"));
    }

    // A textual ID collision invalidates every matching entity, including an
    // otherwise malformed one, so dependants can never be reassigned.
    let mut id_counts = BTreeMap::<String, usize>::new();
    for record in &records {
        if record.kind == RecordKind::Entity {
            // Include misplaced/duplicate Id fields in malformed records too:
            // otherwise a surviving entity could silently capture their references.
            for id in record
                .raw
                .lines()
                .filter_map(|line| line.strip_prefix("Id: "))
            {
                *id_counts.entry(id.to_owned()).or_default() += 1;
            }
        }
    }
    for record in &mut records {
        if record.kind == RecordKind::Entity
            && record
                .parent
                .as_ref()
                .is_some_and(|id| id_counts.get(id).copied().unwrap_or(0) > 1)
        {
            record.error = Some(ComponentErrorCode::DuplicateId);
            record.value = json!({});
        }
    }

    let mut entity_records = Vec::new();
    let mut attributes = Vec::new();
    let mut relations = Vec::new();
    let mut dependants = Vec::new();
    for record in records {
        match record.kind {
            RecordKind::Entity => entity_records.push(record),
            RecordKind::Attribute => attributes.push(record),
            RecordKind::Relation => relations.push(record),
            RecordKind::Alias | RecordKind::Classification => dependants.push(record),
        }
    }

    let base_value = envelope_value(&entity_records, &attributes, &relations);
    let base = parse_normalized_proposals_v3(base_value, context, limits)?;
    let valid_parents: BTreeMap<String, usize> = base
        .entities
        .iter()
        .enumerate()
        .filter_map(|(index, component)| {
            component.parsed().map(|entity| (entity.id.clone(), index))
        })
        .collect();

    let mut diagnostics = Vec::new();
    let mut assigned: Vec<Vec<ParsedRecord>> =
        (0..entity_records.len()).map(|_| Vec::new()).collect();
    for dependant in dependants {
        let parent_index = dependant
            .parent
            .as_ref()
            .and_then(|parent| valid_parents.get(parent))
            .copied();
        if let Some(parent_index) = parent_index {
            assigned[parent_index].push(dependant);
        } else {
            diagnostics.push(TextProposalDiagnostic {
                original_text: dependant.raw,
                record_index: dependant.record_index,
                code: dependant
                    .error
                    .unwrap_or(ComponentErrorCode::UnresolvedReference),
            });
        }
    }

    let mut value = envelope_value(&entity_records, &attributes, &relations);
    for (entity_index, records) in assigned.iter().enumerate() {
        for record in records {
            let field = match record.kind {
                RecordKind::Alias => "aliases",
                RecordKind::Classification => "classes",
                _ => unreachable!("only dependant records are assigned"),
            };
            value["entities"][entity_index][field]
                .as_array_mut()
                .expect("normalized entity collections are arrays")
                .push(record.value.clone());
        }
    }

    let mut envelope = parse_normalized_proposals_v3(value, context, limits)?;
    // A response containing only orphaned dependant records is still a
    // non-sentinel response even though the normalized component arrays are empty.
    envelope.no_claims = false;
    restore_top_level(&mut envelope.entities, &entity_records);
    restore_top_level(&mut envelope.attributes, &attributes);
    restore_top_level(&mut envelope.relations, &relations);
    for (entity_index, records) in assigned.iter().enumerate() {
        let Some(entity) = envelope.entities[entity_index].value.as_mut().ok() else {
            continue;
        };
        let mut alias_index = 0;
        let mut class_index = 0;
        for record in records {
            match record.kind {
                RecordKind::Alias => {
                    restore_component(&mut entity.aliases[alias_index], record);
                    alias_index += 1;
                }
                RecordKind::Classification => {
                    restore_component(&mut entity.classes[class_index], record);
                    class_index += 1;
                }
                _ => unreachable!(),
            }
        }
    }

    diagnostics.sort_by_key(|diagnostic| diagnostic.record_index);
    Ok(TextProposalEnvelope {
        envelope,
        diagnostics,
    })
}

fn envelope_value(
    entities: &[ParsedRecord],
    attributes: &[ParsedRecord],
    relations: &[ParsedRecord],
) -> Value {
    let no_claims = entities.is_empty() && attributes.is_empty() && relations.is_empty();
    json!({
        "schema": PROPOSAL_SCHEMA_V3,
        "no_claims": no_claims,
        "entities": entities.iter().map(|record| record.value.clone()).collect::<Vec<_>>(),
        "attributes": attributes.iter().map(|record| record.value.clone()).collect::<Vec<_>>(),
        "relations": relations.iter().map(|record| record.value.clone()).collect::<Vec<_>>()
    })
}

fn restore_top_level<T>(components: &mut [ProposalComponent<T>], records: &[ParsedRecord]) {
    for (component, record) in components.iter_mut().zip(records) {
        restore_component(component, record);
    }
}

fn restore_component<T>(component: &mut ProposalComponent<T>, record: &ParsedRecord) {
    component.original_text = Some(record.raw.clone());
    if let Some(code) = record.error {
        component.value = Err(ComponentError::new(code));
    }
}

fn split_lines(text: &str) -> Result<Vec<Line<'_>>, ProposalParseError> {
    let separator = if text.contains("\r\n") {
        let bytes = text.as_bytes();
        for (index, byte) in bytes.iter().enumerate() {
            if (*byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r'))
                || (*byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'))
            {
                return Err(ProposalParseError::Envelope("mixed_line_endings"));
            }
        }
        "\r\n"
    } else {
        if text.contains('\r') {
            return Err(ProposalParseError::Envelope("mixed_line_endings"));
        }
        "\n"
    };

    let mut lines = Vec::new();
    let mut start = 0;
    while let Some(relative) = text[start..].find(separator) {
        let end = start + relative;
        lines.push(Line {
            text: &text[start..end],
            start,
            end,
        });
        start = end + separator.len();
    }
    if start < text.len() {
        lines.push(Line {
            text: &text[start..],
            start,
            end: text.len(),
        });
    }
    Ok(lines)
}

fn frame_records<'a>(
    text: &'a str,
    lines: &[Line<'a>],
) -> Result<Vec<(String, Vec<&'a str>)>, ProposalParseError> {
    let mut blocks = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if lines[index].text.is_empty() {
            return Err(ProposalParseError::Envelope("text_framing"));
        }
        if !matches!(lines[index].text, "ENTITY:" | "ALIAS:" | "CLAIM:") {
            return Err(ProposalParseError::Envelope("record_header"));
        }
        let start = lines[index].start;
        let mut block = Vec::new();
        loop {
            let line = lines
                .get(index)
                .ok_or(ProposalParseError::Envelope("unclosed_record"))?;
            if line.text.is_empty() {
                return Err(ProposalParseError::Envelope("text_framing"));
            }
            if !block.is_empty() && matches!(line.text, "ENTITY:" | "ALIAS:" | "CLAIM:") {
                return Err(ProposalParseError::Envelope("ambiguous_record_boundary"));
            }
            block.push(line.text);
            index += 1;
            if line.text == "---" {
                blocks.push((text[start..line.end].to_owned(), block));
                break;
            }
        }
        if index < lines.len() && lines[index].text.is_empty() {
            while index < lines.len() && lines[index].text.is_empty() {
                index += 1;
            }
            if index == lines.len() {
                return Err(ProposalParseError::Envelope("text_framing"));
            }
        }
    }
    Ok(blocks)
}

fn parse_record(
    raw: String,
    lines: Vec<&str>,
    record_index: usize,
    limits: &ProposalLimits,
) -> Result<ParsedRecord, ProposalParseError> {
    let header = lines[0];
    let body = &lines[1..lines.len() - 1];
    let (kind, parent, parsed) = match header {
        "ENTITY:" => {
            let parent = candidate_value(body.first().copied(), "Id");
            (RecordKind::Entity, parent, parse_entity(body, limits))
        }
        "ALIAS:" => {
            let parent = candidate_value(body.first().copied(), "Entity");
            (RecordKind::Alias, parent, parse_alias(body, limits))
        }
        "CLAIM:" => {
            let kind = body
                .first()
                .and_then(|line| line.strip_prefix("Kind: "))
                .ok_or(ProposalParseError::Envelope("claim_kind"))?;
            match kind {
                "classification" => {
                    let parent = body
                        .get(1)
                        .and_then(|line| candidate_value(Some(line), "Subject"))
                        .and_then(|value| value.strip_prefix("local ").map(str::to_owned));
                    (
                        RecordKind::Classification,
                        parent,
                        parse_classification(body, limits),
                    )
                }
                "attribute" => (RecordKind::Attribute, None, parse_attribute(body, limits)),
                "relation" => (RecordKind::Relation, None, parse_relation(body, limits)),
                _ => return Err(ProposalParseError::Envelope("claim_kind")),
            }
        }
        _ => unreachable!(),
    };
    let (value, error) = match parsed {
        Ok(value) => (value, None),
        Err(code) => (json!({}), Some(code)),
    };
    Ok(ParsedRecord {
        kind,
        raw,
        record_index,
        value,
        error,
        parent,
    })
}

fn candidate_value(line: Option<&str>, label: &str) -> Option<String> {
    line.and_then(|line| line.strip_prefix(&format!("{label}: ")))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

struct Cursor<'a> {
    lines: &'a [&'a str],
    index: usize,
}

impl<'a> Cursor<'a> {
    fn new(lines: &'a [&'a str]) -> Self {
        Self { lines, index: 0 }
    }

    fn peek(&self) -> Option<&'a str> {
        self.lines.get(self.index).copied()
    }

    fn literal(&mut self, expected: &str) -> ShapeResult<()> {
        match self.peek() {
            Some(line) if line == expected => {
                self.index += 1;
                Ok(())
            }
            None => Err(ComponentErrorCode::MissingField),
            Some(_) => Err(ComponentErrorCode::MissingField),
        }
    }

    fn value(&mut self, label: &str, max: usize, allow_empty: bool) -> ShapeResult<String> {
        let line = self.peek().ok_or(ComponentErrorCode::MissingField)?;
        let empty = format!("{label}:");
        let prefix = format!("{label}: ");
        let value = if line == empty {
            ""
        } else if let Some(value) = line.strip_prefix(&prefix) {
            value
        } else {
            return Err(if known_label(line) {
                ComponentErrorCode::MissingField
            } else {
                ComponentErrorCode::UnknownField
            });
        };
        if (!allow_empty && value.is_empty()) || value.len() > max || !valid_scalar(value) {
            return Err(ComponentErrorCode::InvalidValue);
        }
        self.index += 1;
        Ok(value.to_owned())
    }

    fn finish(&self) -> ShapeResult<()> {
        match self.peek() {
            None => Ok(()),
            Some(line) if known_label(line) => Err(ComponentErrorCode::InvalidValue),
            Some(_) => Err(ComponentErrorCode::UnknownField),
        }
    }
}

fn known_label(line: &str) -> bool {
    const LABELS: &[&str] = &[
        "Id",
        "Name",
        "Known entity",
        "Entity",
        "Kind",
        "Subject",
        "Term",
        "Term note",
        "Term selected",
        "Predicate",
        "Predicate note",
        "Predicate selected",
        "Value",
        "Datatype",
        "Datatype note",
        "Datatype selected",
        "Object",
        "CLAIM_METADATA",
        "Source mode",
        "Fit",
        "Fit note",
        "Qualifier",
        "EVIDENCE",
        "Range",
        "Occurrence",
        "Quote",
    ];
    LABELS
        .iter()
        .any(|label| line == format!("{label}:") || line.starts_with(&format!("{label}: ")))
}

fn valid_scalar(value: &str) -> bool {
    value.trim() == value && !value.chars().any(char::is_control)
}

fn parse_entity(lines: &[&str], limits: &ProposalLimits) -> ShapeResult<Value> {
    let mut cursor = Cursor::new(lines);
    let id = cursor.value("Id", limits.max_local_id_bytes, false)?;
    let name = cursor.value("Name", limits.max_label_bytes, false)?;
    let known = cursor.value("Known entity", limits.max_label_bytes + 4, false)?;
    let known = if known == "none" {
        Value::Null
    } else if let Some(iri) = known.strip_prefix("iri ") {
        if !bounded(iri, limits.max_label_bytes, false) {
            return Err(ComponentErrorCode::InvalidValue);
        }
        Value::String(iri.to_owned())
    } else {
        return Err(ComponentErrorCode::InvalidValue);
    };
    let evidence = parse_evidence_groups(&mut cursor, limits, None)?;
    cursor.finish()?;
    Ok(
        json!({"id":id,"name":name,"aliases":[],"known_entity":known,"evidence":evidence,"classes":[]}),
    )
}

fn parse_alias(lines: &[&str], limits: &ProposalLimits) -> ShapeResult<Value> {
    let mut cursor = Cursor::new(lines);
    cursor.value("Entity", limits.max_local_id_bytes, false)?;
    let name = cursor.value("Name", limits.max_label_bytes, false)?;
    let evidence = parse_evidence_groups(&mut cursor, limits, Some(1))?;
    cursor.finish()?;
    Ok(json!({"name":name,"evidence":evidence.into_iter().next().expect("one evidence group")}))
}

fn parse_classification(lines: &[&str], limits: &ProposalLimits) -> ShapeResult<Value> {
    let mut cursor = Cursor::new(lines);
    cursor.value("Kind", 32, false)?;
    let subject = cursor.value("Subject", limits.max_local_id_bytes + 6, false)?;
    let parent = subject
        .strip_prefix("local ")
        .filter(|value| bounded(value, limits.max_local_id_bytes, false))
        .ok_or(ComponentErrorCode::InvalidValue)?;
    let term = parse_choice(&mut cursor, "Term", limits)?;
    let (source_mode, fit, fit_note, qualifiers) = parse_metadata(&mut cursor, limits, false)?;
    debug_assert!(qualifiers.is_empty());
    let evidence = parse_evidence_groups(&mut cursor, limits, None)?;
    cursor.finish()?;
    let _ = parent;
    Ok(
        json!({"term":term,"evidence":evidence,"source_mode":source_mode,"fit":fit,"fit_note":fit_note}),
    )
}

fn parse_attribute(lines: &[&str], limits: &ProposalLimits) -> ShapeResult<Value> {
    let mut cursor = Cursor::new(lines);
    cursor.value("Kind", 32, false)?;
    let subject = parse_reference(
        &cursor.value("Subject", limits.max_label_bytes + 9, false)?,
        false,
        limits,
    )?;
    let predicate = parse_choice(&mut cursor, "Predicate", limits)?;
    let lexical = cursor.value("Value", limits.max_literal_bytes, false)?;
    let datatype = parse_choice(&mut cursor, "Datatype", limits)?;
    let (source_mode, fit, fit_note, qualifiers) = parse_metadata(&mut cursor, limits, true)?;
    let evidence = parse_evidence_groups(&mut cursor, limits, None)?;
    cursor.finish()?;
    Ok(
        json!({"subject":subject,"predicate":predicate,"value":{"lexical":lexical,"datatype":datatype},"evidence":evidence,"source_mode":source_mode,"qualifiers":qualifiers,"fit":fit,"fit_note":fit_note}),
    )
}

fn parse_relation(lines: &[&str], limits: &ProposalLimits) -> ShapeResult<Value> {
    let mut cursor = Cursor::new(lines);
    cursor.value("Kind", 32, false)?;
    let subject = parse_reference(
        &cursor.value("Subject", limits.max_label_bytes + 9, false)?,
        false,
        limits,
    )?;
    let predicate = parse_choice(&mut cursor, "Predicate", limits)?;
    let object = parse_reference(
        &cursor.value("Object", limits.max_label_bytes + 11, false)?,
        true,
        limits,
    )?;
    let (source_mode, fit, fit_note, qualifiers) = parse_metadata(&mut cursor, limits, true)?;
    let evidence = parse_evidence_groups(&mut cursor, limits, None)?;
    cursor.finish()?;
    Ok(
        json!({"subject":subject,"predicate":predicate,"object":object,"evidence":evidence,"source_mode":source_mode,"qualifiers":qualifiers,"fit":fit,"fit_note":fit_note}),
    )
}

fn parse_choice(
    cursor: &mut Cursor<'_>,
    label: &str,
    limits: &ProposalLimits,
) -> ShapeResult<Value> {
    let mut suggestions = Vec::new();
    let prefix = format!("{label}: ");
    while cursor.peek().is_some_and(|line| line.starts_with(&prefix)) {
        if suggestions.len() == limits.max_suggestions {
            return Err(ComponentErrorCode::LimitExceeded);
        }
        let text = cursor.value(label, limits.max_label_bytes, false)?;
        let note = cursor.value(&format!("{label} note"), limits.max_fit_note_bytes, true)?;
        suggestions.push(json!({"text":text,"note":note}));
    }
    if suggestions.is_empty() {
        return Err(match cursor.peek() {
            Some(line) if !known_label(line) => ComponentErrorCode::UnknownField,
            _ => ComponentErrorCode::MissingField,
        });
    }
    let selected = cursor.value(&format!("{label} selected"), 32, false)?;
    let selected = if selected == "none" {
        Value::Null
    } else {
        let index = parse_decimal(&selected)?;
        if index >= suggestions.len() {
            return Err(ComponentErrorCode::InvalidValue);
        }
        json!(index)
    };
    Ok(json!({"suggestions":suggestions,"selected":selected}))
}

fn parse_metadata(
    cursor: &mut Cursor<'_>,
    limits: &ProposalLimits,
    qualifiers_allowed: bool,
) -> ShapeResult<(String, String, String, Vec<String>)> {
    cursor.literal("CLAIM_METADATA:")?;
    let source_mode = cursor.value("Source mode", 32, false)?;
    if !matches!(
        source_mode.as_str(),
        "affirmative" | "negative" | "conditional" | "attributed" | "hypothetical" | "unknown"
    ) {
        return Err(ComponentErrorCode::InvalidValue);
    }
    let fit = cursor.value("Fit", 32, false)?;
    if !matches!(fit.as_str(), "supported" | "uncertain" | "not_evaluated") {
        return Err(ComponentErrorCode::InvalidValue);
    }
    let fit_note = cursor.value("Fit note", limits.max_fit_note_bytes, true)?;
    let mut qualifiers = Vec::new();
    while cursor
        .peek()
        .is_some_and(|line| line.starts_with("Qualifier:"))
    {
        if !qualifiers_allowed {
            return Err(ComponentErrorCode::InvalidValue);
        }
        if qualifiers.len() == limits.max_qualifiers {
            return Err(ComponentErrorCode::LimitExceeded);
        }
        qualifiers.push(cursor.value("Qualifier", limits.max_qualifier_bytes, false)?);
    }
    Ok((source_mode, fit, fit_note, qualifiers))
}

fn parse_evidence_groups(
    cursor: &mut Cursor<'_>,
    limits: &ProposalLimits,
    exact: Option<usize>,
) -> ShapeResult<Vec<Value>> {
    let mut evidence = Vec::new();
    while cursor.peek() == Some("EVIDENCE:") {
        if evidence.len() == limits.max_evidence {
            return Err(ComponentErrorCode::LimitExceeded);
        }
        cursor.literal("EVIDENCE:")?;
        let range = cursor.value("Range", limits.max_label_bytes, false)?;
        let occurrence = parse_decimal(&cursor.value("Occurrence", 32, false)?)?;
        let quote = cursor.value("Quote", limits.max_excerpt_bytes, false)?;
        evidence.push(json!({"range":range,"occurrence":occurrence,"quote":quote}));
    }
    if exact.is_some_and(|count| evidence.len() != count) {
        return Err(ComponentErrorCode::MissingField);
    }
    Ok(evidence)
}

fn parse_reference(
    value: &str,
    unresolved_allowed: bool,
    limits: &ProposalLimits,
) -> ShapeResult<Value> {
    for (tag, field) in [("local ", "id"), ("document ", "handle"), ("known ", "iri")] {
        if let Some(payload) = value.strip_prefix(tag) {
            let max = if tag == "local " {
                limits.max_local_id_bytes
            } else {
                limits.max_label_bytes
            };
            if !bounded(payload, max, false) {
                return Err(ComponentErrorCode::InvalidValue);
            }
            let kind = tag.trim();
            return Ok(match field {
                "id" => json!({"kind":kind,"id":payload}),
                "handle" => json!({"kind":kind,"handle":payload}),
                "iri" => json!({"kind":kind,"iri":payload}),
                _ => unreachable!(),
            });
        }
    }
    if unresolved_allowed {
        if let Some(payload) = value.strip_prefix("unresolved ") {
            if bounded(payload, limits.max_label_bytes, false) {
                return Ok(json!({"kind":"unresolved","text":payload}));
            }
        }
    }
    Err(ComponentErrorCode::InvalidValue)
}

fn parse_decimal(value: &str) -> ShapeResult<usize> {
    if value == "0"
        || (value
            .as_bytes()
            .first()
            .is_some_and(|byte| matches!(byte, b'1'..=b'9'))
            && value.as_bytes().iter().all(u8::is_ascii_digit))
    {
        value.parse().map_err(|_| ComponentErrorCode::InvalidValue)
    } else {
        Err(ComponentErrorCode::InvalidValue)
    }
}

fn bounded(value: &str, max: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty()) && value.len() <= max && valid_scalar(value)
}
