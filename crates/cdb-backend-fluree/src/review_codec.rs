//! RDF codec for durable acquisition-review records.
//!
//! Every RDF predicate emitted by this codec is host-defined. Model-suggested
//! predicates and types are encoded as `xsd:string` values, never as RDF
//! predicates and never as `rdf:type` objects.

use cdb_core::{
    review::{ReviewAssertionIntent, ReviewRecord, ReviewRecordId, VocabularyVerdict},
    Error, Result,
};
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::collections::{BTreeMap, BTreeSet};

pub const PROFILE: &str = "ctxql-acquisition-review-rdf/v1";
pub const NS: &str = "https://ctxql.example/acquisition-review/v1/";
pub const RECORD_MARKER: &str = "https://ctxql.example/acquisition-review/v1/Record";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExactReviewTerm {
    Iri(String),
    Literal {
        lexical: String,
        datatype: String,
        language: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewFact {
    pub graph: String,
    pub predicate: String,
    pub object: ExactReviewTerm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RdfReviewDocument {
    pub graph: String,
    pub review_iri: String,
    pub facts: Vec<ReviewFact>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewCodecLimits {
    pub max_facts: usize,
    pub max_bytes: usize,
}
impl Default for ReviewCodecLimits {
    fn default() -> Self {
        Self {
            max_facts: 160,
            max_bytes: 256 * 1024,
        }
    }
}

/// Encode a review record as one JSON-LD node in the dedicated review graph.
pub fn encode_review(
    record: &ReviewRecord,
    graph: &str,
    limits: ReviewCodecLimits,
) -> Result<JsonValue> {
    validate_iri(graph, "review graph")?;
    validate_iri(record.id().as_str(), "review record IRI")?;
    let fact_count = 6usize
        .saturating_add(record.reason_codes().len())
        .saturating_add(record.suggested_predicates().len())
        .saturating_add(record.suggested_types().len())
        .saturating_add(record.resolved_predicates().len())
        .saturating_add(record.resolved_types().len())
        .saturating_add(record.accepted_claim_ids().len());
    if fact_count > limits.max_facts {
        return Err(Error::limit());
    }

    let mut node = JsonMap::new();
    node.insert("@id".into(), JsonValue::String(record.id().as_str().into()));
    node.insert("@graph".into(), JsonValue::String(graph.into()));
    node.insert("@type".into(), JsonValue::String(RECORD_MARKER.into()));
    singleton_literal(&mut node, "componentRef", record.component_ref());
    singleton_literal(&mut node, "sourceRef", record.source_ref());
    singleton_literal(&mut node, "artifactRoot", record.artifact_root().as_str());
    singleton_literal(
        &mut node,
        "vocabularyVerdict",
        record.vocabulary_verdict().as_str(),
    );
    singleton_literal(
        &mut node,
        "assertionIntent",
        record.assertion_intent().as_str(),
    );
    literals(&mut node, "reasonCode", record.reason_codes());
    literals(
        &mut node,
        "proposedPredicate",
        record.suggested_predicates(),
    );
    literals(&mut node, "proposedType", record.suggested_types());
    iris(&mut node, "resolvedPredicate", record.resolved_predicates())?;
    iris(&mut node, "resolvedType", record.resolved_types())?;
    let accepted = record
        .accepted_claim_ids()
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect::<Vec<_>>();
    iris(&mut node, "acceptedClaim", &accepted)?;

    let encoded = JsonValue::Object(node);
    if serde_json::to_vec(&encoded)
        .map_err(|_| Error::invalid("review JSON-LD"))?
        .len()
        > limits.max_bytes
    {
        return Err(Error::limit());
    }
    Ok(encoded)
}

pub fn encode_review_bundle(
    records: &[ReviewRecord],
    graph: &str,
    limits: ReviewCodecLimits,
) -> Result<JsonValue> {
    if records.is_empty() {
        return Err(Error::invalid("empty review bundle"));
    }
    let graph = records
        .iter()
        .map(|record| encode_review(record, graph, limits))
        .collect::<Result<Vec<_>>>()?;
    let encoded = serde_json::json!({ "@graph": graph });
    if serde_json::to_vec(&encoded)
        .map_err(|_| Error::invalid("review JSON-LD"))?
        .len()
        > limits.max_bytes
    {
        return Err(Error::limit());
    }
    Ok(encoded)
}

/// Strictly decode exact RDF facts read from the review graph.
pub fn decode_review(
    document: &RdfReviewDocument,
    limits: ReviewCodecLimits,
) -> Result<ReviewRecord> {
    validate_iri(&document.review_iri, "review record IRI")?;
    if document.facts.len() > limits.max_facts {
        return Err(Error::limit());
    }
    let allowed = [
        "componentRef",
        "sourceRef",
        "artifactRoot",
        "vocabularyVerdict",
        "assertionIntent",
        "reasonCode",
        "proposedPredicate",
        "proposedType",
        "resolvedPredicate",
        "resolvedType",
        "acceptedClaim",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let mut fields: BTreeMap<&str, Vec<&ExactReviewTerm>> = BTreeMap::new();
    let mut markers = 0usize;
    let mut bytes = document.graph.len() + document.review_iri.len();
    for fact in &document.facts {
        if fact.graph != document.graph {
            return Err(Error::invalid("review_profile_invalid"));
        }
        bytes = bytes
            .checked_add(fact.predicate.len() + term_bytes(&fact.object))
            .ok_or_else(Error::limit)?;
        if bytes > limits.max_bytes {
            return Err(Error::limit());
        }
        if fact.predicate == RDF_TYPE {
            if fact.object == ExactReviewTerm::Iri(RECORD_MARKER.into()) {
                markers += 1;
            }
            continue;
        }
        let Some(local) = fact.predicate.strip_prefix(NS) else {
            return Err(Error::invalid("review_profile_invalid"));
        };
        if !allowed.contains(local) {
            return Err(Error::invalid("review_profile_invalid"));
        }
        fields.entry(local).or_default().push(&fact.object);
    }
    if markers != 1 {
        return Err(Error::invalid("review_profile_invalid"));
    }

    ReviewRecord::new(
        ReviewRecordId::new(&document.review_iri)?,
        required_literal(&fields, "componentRef")?,
        required_literal(&fields, "sourceRef")?,
        cdb_core::id::ContentHash::parse(required_literal(&fields, "artifactRoot")?)?,
        verdict(required_literal(&fields, "vocabularyVerdict")?)?,
        intent(required_literal(&fields, "assertionIntent")?)?,
        repeated_literals(&fields, "reasonCode")?,
        repeated_literals(&fields, "proposedPredicate")?,
        repeated_literals(&fields, "proposedType")?,
        repeated_iris(&fields, "resolvedPredicate")?,
        repeated_iris(&fields, "resolvedType")?,
        repeated_iris(&fields, "acceptedClaim")?
            .into_iter()
            .map(cdb_core::id::ClaimId::new)
            .collect::<Result<_>>()?,
    )
}

fn singleton_literal(node: &mut JsonMap<String, JsonValue>, local: &str, value: &str) {
    node.insert(format!("{NS}{local}"), literal(value));
}
fn literals(node: &mut JsonMap<String, JsonValue>, local: &str, values: &[String]) {
    if !values.is_empty() {
        node.insert(
            format!("{NS}{local}"),
            JsonValue::Array(values.iter().map(|value| literal(value)).collect()),
        );
    }
}
fn iris(node: &mut JsonMap<String, JsonValue>, local: &str, values: &[String]) -> Result<()> {
    if !values.is_empty() {
        let values = values
            .iter()
            .map(|value| {
                validate_iri(value, "review metadata IRI")?;
                Ok(serde_json::json!({"@id": value}))
            })
            .collect::<Result<Vec<_>>>()?;
        node.insert(format!("{NS}{local}"), JsonValue::Array(values));
    }
    Ok(())
}
fn literal(value: &str) -> JsonValue {
    serde_json::json!({"@value": value, "@type": XSD_STRING})
}
fn validate_iri(value: &str, label: &str) -> Result<()> {
    if value.starts_with("_:") || !value.contains(':') || value.chars().any(char::is_whitespace) {
        return Err(Error::invalid(label));
    }
    Ok(())
}
fn term_bytes(term: &ExactReviewTerm) -> usize {
    match term {
        ExactReviewTerm::Iri(value) => value.len(),
        ExactReviewTerm::Literal {
            lexical,
            datatype,
            language,
        } => lexical.len() + datatype.len() + language.as_deref().map_or(0, str::len),
    }
}
fn exactly_one<'a>(
    fields: &'a BTreeMap<&str, Vec<&'a ExactReviewTerm>>,
    key: &str,
) -> Result<&'a ExactReviewTerm> {
    let values = fields
        .get(key)
        .ok_or_else(|| Error::invalid("review_profile_invalid"))?;
    if values.len() != 1 {
        return Err(Error::invalid("review_profile_invalid"));
    }
    Ok(values[0])
}
fn required_literal<'a>(
    fields: &'a BTreeMap<&str, Vec<&'a ExactReviewTerm>>,
    key: &str,
) -> Result<&'a str> {
    let ExactReviewTerm::Literal {
        lexical,
        datatype,
        language: None,
    } = exactly_one(fields, key)?
    else {
        return Err(Error::invalid("review_profile_invalid"));
    };
    if datatype != XSD_STRING {
        return Err(Error::invalid("review_profile_invalid"));
    }
    Ok(lexical)
}
fn repeated_literals(
    fields: &BTreeMap<&str, Vec<&ExactReviewTerm>>,
    key: &str,
) -> Result<Vec<String>> {
    fields
        .get(key)
        .into_iter()
        .flatten()
        .map(|term| match term {
            ExactReviewTerm::Literal {
                lexical,
                datatype,
                language: None,
            } if datatype == XSD_STRING => Ok(lexical.clone()),
            _ => Err(Error::invalid("review_profile_invalid")),
        })
        .collect()
}
fn repeated_iris(fields: &BTreeMap<&str, Vec<&ExactReviewTerm>>, key: &str) -> Result<Vec<String>> {
    fields
        .get(key)
        .into_iter()
        .flatten()
        .map(|term| match term {
            ExactReviewTerm::Iri(value) => {
                validate_iri(value, "review metadata IRI")?;
                Ok(value.clone())
            }
            _ => Err(Error::invalid("review_profile_invalid")),
        })
        .collect()
}
fn verdict(value: &str) -> Result<VocabularyVerdict> {
    match value {
        "valid" => Ok(VocabularyVerdict::Valid),
        "repaired" => Ok(VocabularyVerdict::Repaired),
        "rejected" => Ok(VocabularyVerdict::Rejected),
        "not_checked" => Ok(VocabularyVerdict::NotChecked),
        _ => Err(Error::invalid("review_profile_invalid")),
    }
}
fn intent(value: &str) -> Result<ReviewAssertionIntent> {
    match value {
        "none" => Ok(ReviewAssertionIntent::None),
        "direct" => Ok(ReviewAssertionIntent::Direct),
        "provisional" => Ok(ReviewAssertionIntent::Provisional),
        _ => Err(Error::invalid("review_profile_invalid")),
    }
}
