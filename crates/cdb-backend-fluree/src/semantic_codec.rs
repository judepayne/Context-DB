//! Strict backend-side decoder for the `ctxql-semantic-rdf/v1` claim profile.
//! Fluree query/history code supplies exact RDF terms; this module owns no
//! source mutation capability and never invents claims from ordinary RDF.

use cdb_core::{
    admission::ExportRecord,
    claim::{
        AdmittedClaim, CandidateClaim, ClaimObject, Grounding, LifecycleAssertion, TypedLiteral,
    },
    CanonicalValue, Error, ExactNumber, Limits, Result, Timestamp,
};
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::collections::{BTreeMap, BTreeSet};

pub const PROFILE: &str = "ctxql-semantic-rdf/v1";
pub const NS: &str = "https://ctxql.example/semantic-rdf/v1/";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const ASSERTED_TYPE: &str = "https://ctxql.example/semantic-rdf/v1/assertedType";
const RDF_JSON: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON";
const RDF_LANG: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExactRdfTerm {
    Iri(String),
    Literal {
        lexical: String,
        datatype: String,
        language: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataFact {
    pub graph: String,
    pub predicate: String,
    pub object: ExactRdfTerm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RdfClaimDocument {
    pub graph: String,
    pub claim_iri: String,
    pub subject_iri: String,
    pub predicate_iri: String,
    pub object: ExactRdfTerm,
    pub metadata: Vec<MetadataFact>,
    pub attachment_transaction_time: Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticCodecLimits {
    pub max_metadata_facts: usize,
    pub max_metadata_bytes: usize,
    pub json: Limits,
}

/// Encode one already validated candidate as Fluree JSON-LD. The claim IRI is
/// the explicit edge-annotation identifier, so the persisted representation is
/// the exact inverse of [`decode_claim`] rather than an unrelated storage DTO.
pub fn encode_claim(
    claim: &CandidateClaim,
    graph: &str,
    limits: SemanticCodecLimits,
) -> Result<JsonValue> {
    validate_iri(graph, "claim graph")?;
    let logical_relation = lifecycle_predicate(claim.relation().as_str());
    validate_iri(logical_relation, "claim predicate")?;
    // Fluree requires JSON-LD `@type` for RDF type and cannot attach edge
    // annotations to that keyword. Persist a parallel typed edge for the exact
    // annotated claim while also asserting the native JSON-LD type.
    let relation = if logical_relation == RDF_TYPE {
        ASSERTED_TYPE
    } else {
        logical_relation
    };

    let mut annotation = JsonMap::new();
    annotation.insert("@id".into(), JsonValue::String(claim.id().as_str().into()));
    annotation.insert("@type".into(), JsonValue::String(format!("{NS}Claim")));
    for (name, iri) in [
        ("relationType", claim.relation_type().as_str()),
        ("subjectType", claim.subject_type().as_str()),
        ("objectType", claim.object_type().as_str()),
        ("claimType", claim.claim_type().as_str()),
    ] {
        annotation.insert(format!("{NS}{name}"), id_value(iri)?);
    }
    annotation.insert(
        format!("{NS}confidence"),
        typed_value(claim.confidence().number().token(), format!("{XSD}decimal")),
    );
    annotation.insert(
        format!("{NS}groundingLevel"),
        id_value(match claim.grounding() {
            Grounding::ClaimOnly => concat!("https://ctxql.example/semantic-rdf/v1/", "ClaimOnly"),
            Grounding::SourceLineageAvailable => concat!(
                "https://ctxql.example/semantic-rdf/v1/",
                "SourceLineageAvailable"
            ),
            Grounding::SourceSpansAvailable => concat!(
                "https://ctxql.example/semantic-rdf/v1/",
                "SourceSpansAvailable"
            ),
        })?,
    );
    annotation.insert(
        format!("{NS}lineage"),
        json_value(&claim.lineage().projection(), limits.json)?,
    );
    annotation.insert(
        format!("{NS}extensions"),
        json_value(claim.ext(), limits.json)?,
    );
    for (name, value) in [
        ("validTime", claim.valid_time()),
        ("sourceObservedAt", claim.source_observed_at()),
    ] {
        if let Some(value) = value {
            annotation.insert(
                format!("{NS}{name}"),
                typed_value(value.canonical(), format!("{XSD}dateTime")),
            );
        }
    }

    let mut edge = match encode_object(claim.object())? {
        JsonValue::Object(value) => value,
        _ => unreachable!(),
    };
    edge.insert("@annotation".into(), JsonValue::Object(annotation));
    let mut node = JsonMap::new();
    node.insert(
        "@id".into(),
        JsonValue::String(claim.subject().as_str().into()),
    );
    node.insert("@graph".into(), JsonValue::String(graph.into()));
    if logical_relation == RDF_TYPE {
        let ClaimObject::Entity(class) = claim.object() else {
            return Err(Error::invalid("RDF type claim object"));
        };
        node.insert("@type".into(), JsonValue::String(class.as_str().into()));
    }
    node.insert(relation.into(), JsonValue::Object(edge));
    Ok(JsonValue::Object(node))
}

pub fn encode_bundle(
    claims: &[CandidateClaim],
    graph: &str,
    limits: SemanticCodecLimits,
) -> Result<JsonValue> {
    if claims.is_empty() {
        return Err(Error::invalid("empty semantic bundle"));
    }
    if claims.len() > limits.max_metadata_facts.saturating_mul(1024) {
        return Err(Error::limit());
    }
    Ok(serde_json::json!({
        "@graph": claims
            .iter()
            .map(|claim| encode_claim(claim, graph, limits))
            .collect::<Result<Vec<_>>>()?
    }))
}

fn lifecycle_predicate(relation: &str) -> &str {
    match relation {
        "ctxql:superseded_by" => concat!("https://ctxql.example/semantic-rdf/v1/", "superseded_by"),
        "ctxql:contradicted_by" => {
            concat!("https://ctxql.example/semantic-rdf/v1/", "contradicted_by")
        }
        "ctxql:retracted_by" => concat!("https://ctxql.example/semantic-rdf/v1/", "retracted_by"),
        value => value,
    }
}

fn id_value(value: &str) -> Result<JsonValue> {
    validate_iri(value, "claim IRI value")?;
    Ok(serde_json::json!({ "@id": value }))
}

fn typed_value(value: impl Into<String>, datatype: impl Into<String>) -> JsonValue {
    serde_json::json!({ "@value": value.into(), "@type": datatype.into() })
}

fn json_value(value: &CanonicalValue, limits: Limits) -> Result<JsonValue> {
    let bytes = value.canonical_bytes(limits)?;
    let lexical = String::from_utf8(bytes).map_err(|_| Error::invalid("canonical JSON"))?;
    Ok(typed_value(lexical, RDF_JSON))
}

fn encode_object(object: &ClaimObject) -> Result<JsonValue> {
    match object {
        ClaimObject::Entity(value) => id_value(value.as_str()),
        ClaimObject::Literal(value) => encode_literal(value),
    }
}

fn encode_literal(value: &TypedLiteral) -> Result<JsonValue> {
    let lexical = match value.value() {
        CanonicalValue::String(value) => value.clone(),
        CanonicalValue::Bool(value) => value.to_string(),
        CanonicalValue::Number(value) => value.token(),
        _ => return Err(Error::invalid("unsupported semantic literal")),
    };
    let mut encoded = JsonMap::new();
    encoded.insert("@value".into(), JsonValue::String(lexical));
    encoded.insert(
        "@type".into(),
        JsonValue::String(value.datatype().as_str().into()),
    );
    if let Some(language) = value.language() {
        encoded.insert("@language".into(), JsonValue::String(language.into()));
    }
    Ok(JsonValue::Object(encoded))
}

impl Default for SemanticCodecLimits {
    fn default() -> Self {
        Self {
            max_metadata_facts: 32,
            max_metadata_bytes: 256 * 1024,
            json: Limits::default(),
        }
    }
}

pub fn decode_claim(
    document: &RdfClaimDocument,
    limits: SemanticCodecLimits,
) -> Result<ExportRecord> {
    validate_iri(&document.claim_iri, "claim IRI")?;
    validate_iri(&document.subject_iri, "claim subject")?;
    validate_iri(&document.predicate_iri, "claim predicate")?;
    if document.metadata.len() > limits.max_metadata_facts {
        return Err(Error::limit());
    }

    let mut bytes = document.graph.len()
        + document.claim_iri.len()
        + document.subject_iri.len()
        + document.predicate_iri.len();
    let mut values: BTreeMap<&str, Vec<&ExactRdfTerm>> = BTreeMap::new();
    let allowed: BTreeSet<&str> = [
        "relationType",
        "subjectType",
        "objectType",
        "claimType",
        "confidence",
        "groundingLevel",
        "lineage",
        "extensions",
        "validTime",
        "sourceObservedAt",
    ]
    .into_iter()
    .collect();
    let mut markers = 0usize;
    for fact in &document.metadata {
        if fact.graph != document.graph {
            return Err(Error::invalid("claim_profile_invalid"));
        }
        bytes = bytes
            .checked_add(fact.predicate.len() + term_bytes(&fact.object))
            .ok_or_else(Error::limit)?;
        if bytes > limits.max_metadata_bytes {
            return Err(Error::limit());
        }
        if fact.predicate == RDF_TYPE {
            if fact.object == ExactRdfTerm::Iri(format!("{NS}Claim")) {
                markers += 1;
            }
            continue;
        }
        if let Some(local) = fact.predicate.strip_prefix(NS) {
            if !allowed.contains(local) {
                return Err(Error::invalid("claim_profile_invalid"));
            }
            values.entry(local).or_default().push(&fact.object);
        }
    }
    if markers != 1 {
        return Err(Error::invalid("claim_profile_invalid"));
    }

    let relation = if document.predicate_iri == ASSERTED_TYPE {
        RDF_TYPE
    } else {
        lifecycle_relation(&document.predicate_iri).unwrap_or(document.predicate_iri.as_str())
    };
    let mut fields = vec![
        (
            "claim_id".into(),
            CanonicalValue::string(&document.claim_iri),
        ),
        (
            "subject_id".into(),
            CanonicalValue::string(&document.subject_iri),
        ),
        ("relation".into(), CanonicalValue::string(relation)),
        ("object_id".into(), endpoint(&document.object)?),
        (
            "relation_type".into(),
            CanonicalValue::string(required_iri(&values, "relationType")?),
        ),
        (
            "subject_type".into(),
            CanonicalValue::string(required_iri(&values, "subjectType")?),
        ),
        (
            "object_type".into(),
            CanonicalValue::string(required_iri(&values, "objectType")?),
        ),
        (
            "claim_type".into(),
            CanonicalValue::string(required_iri(&values, "claimType")?),
        ),
        (
            "confidence".into(),
            CanonicalValue::Number(required_decimal(&values, "confidence")?),
        ),
        (
            "grounding_level".into(),
            CanonicalValue::string(grounding(&values)?),
        ),
        (
            "lineage".into(),
            required_json(&values, "lineage", limits.json, false)?,
        ),
        (
            "ext".into(),
            required_json(&values, "extensions", limits.json, true)?,
        ),
    ];
    if let Some(value) = optional_datetime(&values, "validTime")? {
        fields.push((
            "valid_time".into(),
            CanonicalValue::string(value.canonical()),
        ));
    }
    if let Some(value) = optional_datetime(&values, "sourceObservedAt")? {
        fields.push((
            "source_observed_at".into(),
            CanonicalValue::string(value.canonical()),
        ));
    }
    let candidate = CandidateClaim::from_value(&CanonicalValue::object(fields)?)?;

    if candidate.is_lifecycle_assertion() {
        Ok(ExportRecord::Lifecycle {
            assertion: LifecycleAssertion::new(candidate)?,
            transaction_time: document.attachment_transaction_time,
        })
    } else {
        Ok(ExportRecord::Claim(Box::new(AdmittedClaim::assign(
            candidate,
            document.attachment_transaction_time,
        ))))
    }
}

fn validate_iri(value: &str, label: &str) -> Result<()> {
    if value.starts_with("_:") || !value.contains(':') {
        return Err(Error::invalid(label));
    }
    Ok(())
}

fn term_bytes(term: &ExactRdfTerm) -> usize {
    match term {
        ExactRdfTerm::Iri(v) => v.len(),
        ExactRdfTerm::Literal {
            lexical,
            datatype,
            language,
        } => lexical.len() + datatype.len() + language.as_deref().map_or(0, str::len),
    }
}

fn exactly_one<'a>(
    values: &'a BTreeMap<&str, Vec<&'a ExactRdfTerm>>,
    key: &str,
) -> Result<&'a ExactRdfTerm> {
    let members = values
        .get(key)
        .ok_or_else(|| Error::invalid("claim_profile_invalid"))?;
    if members.len() != 1 {
        return Err(Error::invalid("claim_profile_invalid"));
    }
    Ok(members[0])
}

fn required_iri<'a>(
    values: &'a BTreeMap<&str, Vec<&'a ExactRdfTerm>>,
    key: &str,
) -> Result<&'a str> {
    let ExactRdfTerm::Iri(value) = exactly_one(values, key)? else {
        return Err(Error::invalid("claim_profile_invalid"));
    };
    validate_iri(value, "claim metadata IRI")?;
    Ok(value)
}

fn required_decimal(values: &BTreeMap<&str, Vec<&ExactRdfTerm>>, key: &str) -> Result<ExactNumber> {
    let ExactRdfTerm::Literal {
        lexical,
        datatype,
        language: None,
    } = exactly_one(values, key)?
    else {
        return Err(Error::invalid("claim_profile_invalid"));
    };
    if datatype != &format!("{XSD}decimal")
        || lexical.contains(['e', 'E'])
        || !valid_decimal_lexical(lexical)
    {
        return Err(Error::invalid("claim_profile_invalid"));
    }
    ExactNumber::parse(lexical)
}

fn valid_decimal_lexical(value: &str) -> bool {
    let value = value.strip_prefix(['+', '-']).unwrap_or(value);
    let Some((whole, fractional)) = value.split_once('.') else {
        return !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
    };
    (!whole.is_empty() || !fractional.is_empty())
        && whole.bytes().all(|b| b.is_ascii_digit())
        && fractional.bytes().all(|b| b.is_ascii_digit())
}

fn grounding(values: &BTreeMap<&str, Vec<&ExactRdfTerm>>) -> Result<&'static str> {
    match required_iri(values, "groundingLevel")? {
        value if value == format!("{NS}ClaimOnly") => Ok("claim_only"),
        value if value == format!("{NS}SourceLineageAvailable") => Ok("source_lineage_available"),
        value if value == format!("{NS}SourceSpansAvailable") => Ok("source_spans_available"),
        _ => Err(Error::invalid("claim_profile_invalid")),
    }
}

fn required_json(
    values: &BTreeMap<&str, Vec<&ExactRdfTerm>>,
    key: &str,
    limits: Limits,
    require_object: bool,
) -> Result<CanonicalValue> {
    let ExactRdfTerm::Literal {
        lexical,
        datatype,
        language: None,
    } = exactly_one(values, key)?
    else {
        return Err(Error::invalid("claim_profile_invalid"));
    };
    if datatype != RDF_JSON {
        return Err(Error::invalid("claim_profile_invalid"));
    }
    let value = CanonicalValue::parse(lexical.as_bytes(), limits)?;
    let canonical = value.canonical_bytes(limits)?;
    if canonical != lexical.as_bytes() || (require_object && value.as_object().is_err()) {
        return Err(Error::invalid("claim_profile_invalid"));
    }
    Ok(value)
}

fn optional_datetime(
    values: &BTreeMap<&str, Vec<&ExactRdfTerm>>,
    key: &str,
) -> Result<Option<Timestamp>> {
    let Some(members) = values.get(key) else {
        return Ok(None);
    };
    if members.len() != 1 {
        return Err(Error::invalid("claim_profile_invalid"));
    }
    let ExactRdfTerm::Literal {
        lexical,
        datatype,
        language: None,
    } = members[0]
    else {
        return Err(Error::invalid("claim_profile_invalid"));
    };
    if datatype != &format!("{XSD}dateTime") {
        return Err(Error::invalid("claim_profile_invalid"));
    }
    Timestamp::parse(lexical).map(Some)
}

fn endpoint(term: &ExactRdfTerm) -> Result<CanonicalValue> {
    match term {
        ExactRdfTerm::Iri(value) => {
            validate_iri(value, "claim object IRI")?;
            Ok(CanonicalValue::string(value))
        }
        ExactRdfTerm::Literal {
            lexical,
            datatype,
            language,
        } => {
            let value = if datatype == &format!("{XSD}integer") {
                let unsigned = lexical
                    .strip_prefix('+')
                    .or_else(|| lexical.strip_prefix('-'))
                    .unwrap_or(lexical);
                if unsigned.is_empty() || !unsigned.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(Error::invalid("claim literal"));
                }
                CanonicalValue::Number(ExactNumber::parse(
                    lexical.strip_prefix('+').unwrap_or(lexical),
                )?)
            } else if datatype == &format!("{XSD}decimal") {
                if !valid_decimal_lexical(lexical) || lexical.contains(['e', 'E']) {
                    return Err(Error::invalid("claim literal"));
                }
                CanonicalValue::Number(ExactNumber::parse(lexical)?)
            } else if datatype == &format!("{XSD}boolean") {
                match lexical.as_str() {
                    "true" | "1" => CanonicalValue::Bool(true),
                    "false" | "0" => CanonicalValue::Bool(false),
                    _ => return Err(Error::invalid("claim literal")),
                }
            } else {
                CanonicalValue::string(lexical)
            };
            if language.is_some() && datatype != RDF_LANG {
                return Err(Error::invalid("claim literal language"));
            }
            CanonicalValue::object([
                ("kind".into(), CanonicalValue::string("literal")),
                ("datatype".into(), CanonicalValue::string(datatype)),
                ("value".into(), value),
                (
                    "language".into(),
                    language
                        .as_ref()
                        .map(CanonicalValue::string)
                        .unwrap_or(CanonicalValue::Null),
                ),
            ])
        }
    }
}

fn lifecycle_relation(predicate: &str) -> Option<&'static str> {
    match predicate.strip_prefix(NS) {
        Some("superseded_by") => Some("ctxql:superseded_by"),
        Some("contradicted_by") => Some("ctxql:contradicted_by"),
        Some("retracted_by") => Some("ctxql:retracted_by"),
        _ => None,
    }
}
