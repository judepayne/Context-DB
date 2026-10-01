//! Host-side v2 grounding, literal validation, and stable document identity.
//!
//! Provider suggestions remain text here. This module performs only operations
//! whose authority belongs to the host and never treats a model term as an IRI.

use crate::coordinates::{CoordinateMap, ResolvedSpan};
use crate::proposals::Evidence;
use cdb_core::claim::TypedLiteral;
use cdb_core::id::{ContentHash, EntityId, Iri, SourceId};
use cdb_core::{CanonicalValue, Error, ExactNumber, Result};

const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroundingFailure {
    Empty,
    UnknownRange,
    QuoteMismatch,
    OccurrenceMissing,
    Limit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroundedEvidence {
    pub range: String,
    pub quote: String,
    pub occurrence: usize,
    pub resolved: ResolvedSpan,
}

/// Ground every evidence item independently and preserve source order.
pub fn ground_evidence(
    map: &CoordinateMap,
    document: &str,
    evidence: &[Evidence],
    max_spans: usize,
) -> std::result::Result<Vec<GroundedEvidence>, GroundingFailure> {
    if evidence.is_empty() {
        return Err(GroundingFailure::Empty);
    }
    if evidence.len() > max_spans {
        return Err(GroundingFailure::Limit);
    }
    evidence
        .iter()
        .map(|item| {
            let resolved = map
                .resolve_quote(document, &item.range, &item.quote, item.occurrence)
                .map_err(|error| classify_grounding_error(&error.to_string()))?;
            Ok(GroundedEvidence {
                range: item.range.clone(),
                quote: item.quote.clone(),
                occurrence: item.occurrence,
                resolved,
            })
        })
        .collect()
}

fn classify_grounding_error(message: &str) -> GroundingFailure {
    if message.contains("unknown range") {
        GroundingFailure::UnknownRange
    } else if message.contains("occurrence") {
        GroundingFailure::OccurrenceMissing
    } else if message.contains("limit") {
        GroundingFailure::Limit
    } else {
        GroundingFailure::QuoteMismatch
    }
}

/// Mint an identity from immutable document identity and the complete sorted
/// verified mention-anchor set. Labels, candidate order, ontology terms,
/// evaluation mode, and ledger heads intentionally do not participate.
pub fn document_entity_id(
    source: &SourceId,
    text_version: &ContentHash,
    grounded_mentions: &[GroundedEvidence],
) -> Result<EntityId> {
    if grounded_mentions.is_empty() {
        return Err(Error::invalid(
            "document entity requires a grounded mention",
        ));
    }
    let mut anchors = grounded_mentions
        .iter()
        .map(|item| {
            format!(
                "{}:{}:{}",
                item.resolved.span.start(),
                item.resolved.span.end(),
                item.resolved.selected_hash.as_str()
            )
        })
        .collect::<Vec<_>>();
    anchors.sort();
    anchors.dedup();
    let key = format!(
        "ctxql-document-entity/v2\0{}\0{}\0{}",
        source.as_str(),
        text_version.as_str(),
        anchors.join("\0")
    );
    let hash = ContentHash::of_bytes(key.as_bytes());
    EntityId::new(format!("urn:ctxql:entity:document:{}", &hash.as_str()[7..]))
}

/// Validate the intentionally small literal profile and preserve exact source
/// spelling separately from the canonical value carried by `TypedLiteral`.
pub fn typed_literal(datatype: &str, lexical: &str) -> Result<TypedLiteral> {
    let value = match datatype {
        value if value == format!("{XSD}string") => CanonicalValue::string(lexical),
        value if value == format!("{XSD}boolean") => match lexical {
            "true" | "1" => CanonicalValue::Bool(true),
            "false" | "0" => CanonicalValue::Bool(false),
            _ => return Err(Error::invalid("xsd:boolean lexical form")),
        },
        value if value == format!("{XSD}integer") => {
            CanonicalValue::Number(ExactNumber::parse(lexical)?)
        }
        value if value == format!("{XSD}decimal") => {
            let number = ExactNumber::parse(lexical)?;
            if lexical.contains(['e', 'E']) {
                return Err(Error::invalid("xsd:decimal exponent"));
            }
            CanonicalValue::Number(number)
        }
        value if value == format!("{XSD}date") || value == format!("{XSD}dateTime") => {
            CanonicalValue::string(lexical)
        }
        RDF_LANG_STRING => {
            return Err(Error::invalid(
                "rdf:langString requires an explicit language field",
            ))
        }
        _ => return Err(Error::invalid("unsupported acquisition datatype")),
    };
    TypedLiteral::new(Iri::new(datatype)?, value, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdb_core::evidence::Utf8Span;

    fn map(text: &str) -> CoordinateMap {
        CoordinateMap::issue(
            text,
            "attempt",
            "window",
            Iri::new("file:///loan.txt").unwrap(),
            ContentHash::of_bytes(b"text-version"),
            ContentHash::of_bytes(text.as_bytes()),
            Utf8Span::new(0, text.len()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn grounds_multiline_evidence_and_mints_order_independent_identity() {
        let text = "Dignity plc\nis the Borrower\n";
        let map = map(text);
        let evidence = Evidence {
            range: map.window_range_id(),
            quote: "Dignity plc\nis the Borrower".into(),
            occurrence: 0,
        };
        let grounded = ground_evidence(&map, text, &[evidence], 4).unwrap();
        let source = SourceId::new("urn:ctxql:source:test").unwrap();
        let one = document_entity_id(&source, map.text_version(), &grounded).unwrap();
        let mut reversed = grounded.clone();
        reversed.reverse();
        let two = document_entity_id(&source, map.text_version(), &reversed).unwrap();
        assert_eq!(one, two);
    }

    #[test]
    fn validates_dates_and_exact_decimal_without_binary_float() {
        assert!(typed_literal(&format!("{XSD}date"), "2024-02-29").is_ok());
        assert!(typed_literal(&format!("{XSD}date"), "2023-02-29").is_err());
        let decimal = typed_literal(&format!("{XSD}decimal"), "125000000.00").unwrap();
        assert_eq!(decimal.exact_numeric().unwrap().token(), "125000000");
        assert!(typed_literal(&format!("{XSD}decimal"), "1e3").is_err());
    }
}
