use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct ParseLimits {
    pub max_output_bytes: usize,
    pub max_blocks: usize,
    pub max_spans_per_claim: usize,
    pub max_string_bytes: usize,
    pub max_endpoint_refs: usize,
}
impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: 256 * 1024,
            max_blocks: 128,
            max_spans_per_claim: 16,
            max_string_bytes: 4096,
            max_endpoint_refs: 16,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedOutput {
    NoClaims { window_id: String },
    Claims(Vec<ClaimPair>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimPair {
    pub claim: Claim,
    pub metadata: ClaimMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub window_id: String,
    pub bundle_id: String,
    pub claim_id: String,
    pub subject: EntityRef,
    pub predicate_iri: String,
    pub object: ClaimObject,
    pub relation_type_iri: String,
    pub claim_type_iri: String,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub valid_time_start: Option<String>,
    #[serde(default)]
    pub valid_time_end: Option<String>,
    pub endpoint_type_claim_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EntityRef {
    pub entity_id: String,
    pub spelling: String,
    pub type_iri: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum ClaimObject {
    Entity(EntityRef),
    Literal(TypedLiteral),
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TypedLiteral {
    pub lexical: String,
    pub datatype_iri: String,
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimMetadata {
    pub window_id: String,
    pub bundle_id: String,
    pub claim_id: String,
    pub locator: String,
    pub text_version: String,
    pub coordinates: Vec<Coordinate>,
    #[serde(default)]
    pub temporal_qualifier_claim_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Coordinate {
    pub line_id: String,
    #[serde(default)]
    pub start: Option<usize>,
    #[serde(default)]
    pub end: Option<usize>,
    #[serde(default)]
    pub whole_line: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    Limit(&'static str),
    Grammar(&'static str),
    Json(String),
    UnknownWindow,
    DuplicateClaimId,
    DuplicateMetadata,
    DuplicateCoordinate,
    MissingMetadata,
    Mismatch,
    UnresolvedReference,
    CrossWindowAmbiguity,
    InvalidScalar(&'static str),
}
impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "invalid JSON object: {e}"),
            other => write!(f, "{other:?}"),
        }
    }
}
impl std::error::Error for ParseError {}

/// Parse the complete provider response. There is deliberately no repair path.
pub fn parse_output(
    text: &str,
    expected_window_ids: &[String],
    limits: &ParseLimits,
) -> Result<ParsedOutput, ParseError> {
    if text.len() > limits.max_output_bytes {
        return Err(ParseError::Limit("output_bytes"));
    }
    if expected_window_ids.is_empty() || expected_window_ids.len() > 2 {
        return Err(ParseError::Limit("batch_windows"));
    }
    if text.contains('\r') || text.contains("```") {
        return Err(ParseError::Grammar("fences_or_cr"));
    }
    if text == "NO_CLAIMS" {
        return if expected_window_ids.len() == 1 {
            Ok(ParsedOutput::NoClaims {
                window_id: expected_window_ids[0].clone(),
            })
        } else {
            Err(ParseError::CrossWindowAmbiguity)
        };
    }
    if text.trim() == "NO_CLAIMS" {
        return Err(ParseError::Grammar("sentinel_must_be_exact"));
    }
    for forbidden in [
        "MEMORY:",
        "EVIDENCE:",
        "WINDOW:",
        "FRAGMENT:",
        "CLAIM_JSON:",
        "CLAIM_METADATA_JSON:",
    ] {
        if text
            .lines()
            .any(|line| line.trim_start().starts_with(forbidden))
        {
            return Err(ParseError::Grammar("forbidden_section"));
        }
    }

    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return Err(ParseError::Grammar("empty"));
    }
    let mut i = 0usize;
    let mut pairs = Vec::new();
    while i < lines.len() {
        if pairs.len() >= limits.max_blocks {
            return Err(ParseError::Limit("blocks"));
        }
        if lines[i] != "CLAIM:" {
            return Err(ParseError::Grammar("expected_claim_header"));
        }
        i += 1;
        let claim_line = *lines.get(i).ok_or(ParseError::Grammar("truncated_claim"))?;
        if !looks_like_object(claim_line) {
            return Err(ParseError::Grammar("claim_must_be_one_json_object"));
        }
        let claim: Claim =
            serde_json::from_str(claim_line).map_err(|e| ParseError::Json(e.to_string()))?;
        i += 1;
        if lines.get(i) != Some(&"CLAIM_METADATA:") {
            return Err(ParseError::Grammar("expected_metadata_header"));
        }
        i += 1;
        let metadata_line = *lines
            .get(i)
            .ok_or(ParseError::Grammar("truncated_metadata"))?;
        if !looks_like_object(metadata_line) {
            return Err(ParseError::Grammar("metadata_must_be_one_json_object"));
        }
        let metadata: ClaimMetadata =
            serde_json::from_str(metadata_line).map_err(|e| ParseError::Json(e.to_string()))?;
        i += 1;
        if lines.get(i) != Some(&"---") {
            return Err(ParseError::Grammar("missing_terminator"));
        }
        i += 1;
        validate_pair(&claim, &metadata, expected_window_ids, limits)?;
        pairs.push(ClaimPair { claim, metadata });
    }
    if pairs.is_empty() {
        return Err(ParseError::Grammar("empty"));
    }
    validate_closure(&pairs)?;
    Ok(ParsedOutput::Claims(pairs))
}

fn looks_like_object(line: &str) -> bool {
    line.starts_with('{') && line.ends_with('}') && line.trim() == line
}

fn validate_pair(
    claim: &Claim,
    meta: &ClaimMetadata,
    windows: &[String],
    limits: &ParseLimits,
) -> Result<(), ParseError> {
    if !windows.iter().any(|w| w == &claim.window_id)
        || !windows.iter().any(|w| w == &meta.window_id)
    {
        return Err(ParseError::UnknownWindow);
    }
    if claim.window_id != meta.window_id
        || claim.bundle_id != meta.bundle_id
        || claim.claim_id != meta.claim_id
    {
        return Err(ParseError::Mismatch);
    }
    for id in [
        &claim.window_id,
        &claim.bundle_id,
        &claim.claim_id,
        &claim.subject.entity_id,
    ] {
        validate_id(id, limits)?;
    }
    validate_text(&claim.subject.spelling, limits)?;
    for iri in [
        &claim.subject.type_iri,
        &claim.predicate_iri,
        &claim.relation_type_iri,
        &claim.claim_type_iri,
    ] {
        validate_iri(iri, limits)?;
    }
    match &claim.object {
        ClaimObject::Entity(entity) => {
            validate_id(&entity.entity_id, limits)?;
            validate_text(&entity.spelling, limits)?;
            validate_iri(&entity.type_iri, limits)?;
        }
        ClaimObject::Literal(literal) => {
            validate_text(&literal.lexical, limits)?;
            validate_iri(&literal.datatype_iri, limits)?;
            if literal.language.is_some()
                && literal.datatype_iri != "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString"
            {
                return Err(ParseError::InvalidScalar("language_datatype"));
            }
            if let Some(language) = &literal.language {
                if language.is_empty()
                    || !language
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                {
                    return Err(ParseError::InvalidScalar("language"));
                }
            }
        }
    }
    if claim.endpoint_type_claim_ids.len() > limits.max_endpoint_refs {
        return Err(ParseError::Limit("endpoint_refs"));
    }
    for id in &claim.endpoint_type_claim_ids {
        validate_id(id, limits)?;
    }
    if let Some(c) = &claim.confidence {
        validate_decimal(c)?;
    }
    for time in [&claim.valid_time_start, &claim.valid_time_end]
        .into_iter()
        .flatten()
    {
        validate_rfc3339(time, limits)?;
    }
    validate_text(&meta.locator, limits)?;
    validate_text(&meta.text_version, limits)?;
    if meta.coordinates.is_empty() || meta.coordinates.len() > limits.max_spans_per_claim {
        return Err(ParseError::Limit("coordinates"));
    }
    let mut coords = BTreeSet::new();
    for coordinate in &meta.coordinates {
        validate_id(&coordinate.line_id, limits)?;
        let shape = match (coordinate.start, coordinate.end, coordinate.whole_line) {
            (Some(start), Some(end), None) if start < end => {
                (coordinate.line_id.as_str(), start, end, false)
            }
            (None, None, Some(true)) => (coordinate.line_id.as_str(), 0, 0, true),
            _ => return Err(ParseError::InvalidScalar("coordinate")),
        };
        if !coords.insert(shape) {
            return Err(ParseError::DuplicateCoordinate);
        }
    }
    if let Some(id) = &meta.temporal_qualifier_claim_id {
        validate_id(id, limits)?;
    }
    Ok(())
}

fn validate_closure(pairs: &[ClaimPair]) -> Result<(), ParseError> {
    let mut claims = BTreeMap::<&str, (&str, &str)>::new();
    let mut metadata = BTreeSet::new();
    let mut bundle_windows = BTreeMap::<&str, &str>::new();
    let mut entity_windows = BTreeMap::<&str, &str>::new();
    for pair in pairs {
        let c = &pair.claim;
        if claims
            .insert(&c.claim_id, (&c.window_id, &c.bundle_id))
            .is_some()
        {
            return Err(ParseError::DuplicateClaimId);
        }
        if !metadata.insert(&pair.metadata.claim_id) {
            return Err(ParseError::DuplicateMetadata);
        }
        if let Some(old) = bundle_windows.insert(&c.bundle_id, &c.window_id) {
            if old != c.window_id {
                return Err(ParseError::CrossWindowAmbiguity);
            }
        }
        for id in std::iter::once(&c.subject.entity_id).chain(match &c.object {
            ClaimObject::Entity(e) => Some(&e.entity_id),
            _ => None,
        }) {
            if let Some(old) = entity_windows.insert(id, &c.window_id) {
                if old != c.window_id {
                    return Err(ParseError::CrossWindowAmbiguity);
                }
            }
        }
    }
    for pair in pairs {
        let c = &pair.claim;
        for reference in c
            .endpoint_type_claim_ids
            .iter()
            .chain(pair.metadata.temporal_qualifier_claim_id.iter())
        {
            let Some((window, bundle)) = claims.get(reference.as_str()) else {
                return Err(ParseError::UnresolvedReference);
            };
            if *window != c.window_id || *bundle != c.bundle_id || reference == &c.claim_id {
                return Err(ParseError::UnresolvedReference);
            }
        }
    }
    if metadata.len() != claims.len() {
        return Err(ParseError::MissingMetadata);
    }
    Ok(())
}

fn validate_id(value: &str, limits: &ParseLimits) -> Result<(), ParseError> {
    if value.is_empty()
        || value.len() > limits.max_string_bytes
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
    {
        return Err(ParseError::InvalidScalar("id"));
    }
    Ok(())
}
fn validate_text(value: &str, limits: &ParseLimits) -> Result<(), ParseError> {
    if value.is_empty()
        || value.len() > limits.max_string_bytes
        || value.chars().any(char::is_control)
    {
        return Err(ParseError::InvalidScalar("text"));
    }
    Ok(())
}
fn validate_iri(value: &str, limits: &ParseLimits) -> Result<(), ParseError> {
    validate_text(value, limits)?;
    if !(value.starts_with("https://") || value.starts_with("http://") || value.starts_with("urn:"))
        || value.bytes().any(|b| b.is_ascii_whitespace())
    {
        return Err(ParseError::InvalidScalar("iri"));
    }
    Ok(())
}
fn validate_decimal(value: &str) -> Result<(), ParseError> {
    if value.is_empty() || value.starts_with('+') || value.contains(['e', 'E']) {
        return Err(ParseError::InvalidScalar("decimal"));
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap();
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.is_some_and(|v| v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(ParseError::InvalidScalar("decimal"));
    }
    if whole.len() > 1 && whole.starts_with('0') {
        return Err(ParseError::InvalidScalar("decimal"));
    }
    // Confidence is a canonical decimal in the closed [0,1] interval.
    if whole != "0" && whole != "1" {
        return Err(ParseError::InvalidScalar("decimal"));
    }
    if whole == "1" && fraction.is_some_and(|digits| digits.bytes().any(|b| b != b'0')) {
        return Err(ParseError::InvalidScalar("decimal"));
    }
    Ok(())
}
fn validate_rfc3339(value: &str, limits: &ParseLimits) -> Result<(), ParseError> {
    validate_text(value, limits)?;
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || !(value.ends_with('Z')
            || value
                .as_bytes()
                .get(value.len().saturating_sub(6))
                .is_some_and(|b| *b == b'+' || *b == b'-'))
    {
        return Err(ParseError::InvalidScalar("rfc3339"));
    }
    Ok(())
}
