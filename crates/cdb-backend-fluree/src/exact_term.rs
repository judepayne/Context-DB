//! One exact conversion boundary for Fluree query bindings.
//!
//! Semantic claims and authority/configuration paths call the IRI-only helpers;
//! ontology extraction and disposable C0 readback may admit stable structural
//! blank nodes.

use crate::authorized_view::{ExactTerm, RdfNodeId};
use fluree_db_core::{DatatypeConstraint, FlakeMeta, FlakeValue, LedgerSnapshot, Sid};
use fluree_db_query::Binding;

const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
const STABLE_BLANK_PREFIX: &str = "_:fdb-";

pub(crate) fn decode_iri(
    snapshot: &LedgerSnapshot,
    binding: &Binding,
    failure: &str,
) -> Result<String, String> {
    let value = decode_reference(snapshot, binding, failure)?;
    if value.starts_with("_:") {
        return Err(failure.into());
    }
    Ok(value)
}

pub(crate) fn decode_node(
    snapshot: &LedgerSnapshot,
    binding: &Binding,
    failure: &str,
) -> Result<RdfNodeId, String> {
    let value = decode_reference(snapshot, binding, failure)?;
    if value.starts_with(STABLE_BLANK_PREFIX) {
        Ok(RdfNodeId::ScopedBlankNode(value))
    } else if value.starts_with("_:") {
        Err("unstable_structural_node_identity".into())
    } else {
        Ok(RdfNodeId::Iri(value))
    }
}

pub(crate) fn decode_term(
    snapshot: &LedgerSnapshot,
    binding: &Binding,
    structural_blank_nodes: bool,
    failure: &str,
) -> Result<ExactTerm, String> {
    if matches!(
        binding,
        Binding::Sid { .. } | Binding::Iri(_) | Binding::IriMatch { .. }
    ) {
        let value = decode_reference(snapshot, binding, failure)?;
        if value.starts_with(STABLE_BLANK_PREFIX) {
            return if structural_blank_nodes {
                Ok(ExactTerm::ScopedBlankNode(value))
            } else {
                Err(failure.into())
            };
        }
        if value.starts_with("_:") {
            return Err("unstable_structural_node_identity".into());
        }
        return Ok(ExactTerm::Iri(value));
    }

    let (value, datatype) = binding
        .as_lit()
        .ok_or_else(|| "unsupported_exact_literal".to_string())?;
    let lexical = literal_lexical(value)?;
    let (datatype, language) = match datatype {
        DatatypeConstraint::Explicit(datatype) => (
            snapshot
                .decode_sid(datatype)
                .ok_or_else(|| failure.to_string())?,
            None,
        ),
        DatatypeConstraint::LangTag(language) => {
            (RDF_LANG_STRING.to_string(), Some(language.to_string()))
        }
    };
    Ok(ExactTerm::Literal {
        lexical,
        datatype,
        language,
    })
}

pub(crate) fn decode_flake_object(
    snapshot: &LedgerSnapshot,
    value: &FlakeValue,
    datatype: &Sid,
    metadata: Option<&FlakeMeta>,
    structural_blank_nodes: bool,
    failure: &str,
) -> Result<ExactTerm, String> {
    if let FlakeValue::Ref(sid) = value {
        let decoded = snapshot
            .decode_sid(sid)
            .ok_or_else(|| failure.to_string())?;
        if decoded.starts_with(STABLE_BLANK_PREFIX) {
            return if structural_blank_nodes {
                Ok(ExactTerm::ScopedBlankNode(decoded))
            } else {
                Err(failure.into())
            };
        }
        if decoded.starts_with("_:") {
            return Err("unstable_structural_node_identity".into());
        }
        return Ok(ExactTerm::Iri(decoded));
    }
    let lexical = literal_lexical(value)?;
    let language = metadata.and_then(|meta| meta.lang.clone());
    let datatype = if language.is_some() {
        RDF_LANG_STRING.into()
    } else {
        snapshot
            .decode_sid(datatype)
            .ok_or_else(|| failure.to_string())?
    };
    Ok(ExactTerm::Literal {
        lexical,
        datatype,
        language,
    })
}

fn decode_reference(
    snapshot: &LedgerSnapshot,
    binding: &Binding,
    failure: &str,
) -> Result<String, String> {
    match binding {
        Binding::Sid { sid, .. } => snapshot.decode_sid(sid).ok_or_else(|| failure.to_string()),
        Binding::Iri(iri) | Binding::IriMatch { iri, .. } => Ok(iri.to_string()),
        _ => Err(failure.into()),
    }
}

fn literal_lexical(value: &FlakeValue) -> Result<String, String> {
    match value {
        FlakeValue::Boolean(value) => Ok(value.to_string()),
        FlakeValue::Long(value) => Ok(value.to_string()),
        FlakeValue::Double(value) => {
            if value.is_finite() {
                Ok(value.to_string())
            } else if value.is_nan() {
                Ok("NaN".into())
            } else if value.is_sign_positive() {
                Ok("INF".into())
            } else {
                Ok("-INF".into())
            }
        }
        FlakeValue::BigInt(value) => Ok(value.to_string()),
        FlakeValue::Decimal(value) => Ok(value.to_plain_string()),
        FlakeValue::DateTime(value) => Ok(value.to_string()),
        FlakeValue::Date(value) => Ok(value.to_string()),
        FlakeValue::Time(value) => Ok(value.to_string()),
        FlakeValue::GYear(value) => Ok(value.to_string()),
        FlakeValue::GYearMonth(value) => Ok(value.to_string()),
        FlakeValue::GMonth(value) => Ok(value.to_string()),
        FlakeValue::GDay(value) => Ok(value.to_string()),
        FlakeValue::GMonthDay(value) => Ok(value.to_string()),
        FlakeValue::YearMonthDuration(value) => Ok(value.to_string()),
        FlakeValue::DayTimeDuration(value) => Ok(value.to_string()),
        FlakeValue::Duration(value) => Ok(value.to_string()),
        FlakeValue::String(value) | FlakeValue::Json(value) => Ok(value.clone()),
        FlakeValue::Vector(values) => {
            let values = values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",");
            Ok(format!("[{values}]"))
        }
        FlakeValue::GeoPoint(value) => Ok(value.to_string()),
        FlakeValue::Ref(_) | FlakeValue::Null => Err("unsupported_exact_literal".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn literal_rendering_is_deterministic_and_not_debug_based() {
        assert_eq!(literal_lexical(&FlakeValue::Boolean(true)).unwrap(), "true");
        assert_eq!(literal_lexical(&FlakeValue::Long(-12)).unwrap(), "-12");
        assert_eq!(
            literal_lexical(&FlakeValue::Vector(Arc::from([1.0, 2.5]))).unwrap(),
            "[1,2.5]"
        );
        assert_eq!(
            literal_lexical(&FlakeValue::Double(f64::INFINITY)).unwrap(),
            "INF"
        );
        assert!(literal_lexical(&FlakeValue::Null).is_err());
    }
}
