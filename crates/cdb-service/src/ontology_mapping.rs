//! POC-only authority adapter for source-backed terms in a pinned raw FIBO load.
//!
//! This module is intentionally not part of the normal certified-catalog path.
//! Callers must opt in explicitly, and every raw term is re-described by the
//! pinned direct host before it can become extraction eligible.

use crate::ontology_direct::DirectFlureeOntologyToolHost;
use cdb_acquisition::validator::OntologyAuthority;
use cdb_backend_fluree::acquisition_catalog::CertifiedOntologyCatalog;
use cdb_core::id::Iri;
use cdb_core::ontology_catalog::{OntologyTerm, OntologyTermKind, VocabularyStatus};
use cdb_core::{Error, Result};
use cdb_provider_pi::ontology_bridge::OntologyToolHost;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const SEARCH_LIMIT: usize = 20;

/// An authority which retains the certified catalog and, only when explicitly
/// enabled, supplements it with exact terms from a pinned raw FIBO bootstrap.
pub(crate) struct RawMappingAuthority<'a> {
    certified: &'a CertifiedOntologyCatalog,
    direct: &'a DirectFlureeOntologyToolHost,
    pin: DirectPin,
}

impl<'a> RawMappingAuthority<'a> {
    /// Constructs the POC adapter. `poc_raw_fibo_opt_in` must be explicitly
    /// true; false does not silently produce a certified-only adapter.
    pub(crate) fn new(
        certified: &'a CertifiedOntologyCatalog,
        direct: &'a DirectFlureeOntologyToolHost,
        poc_raw_fibo_opt_in: bool,
    ) -> Result<Self> {
        if !poc_raw_fibo_opt_in {
            return Err(Error::invalid(
                "raw FIBO mapping requires explicit POC opt-in",
            ));
        }
        let provenance = direct
            .provenance()
            .map_err(|_| Error::invalid("raw FIBO host provenance unavailable"))?;
        provenance.closed(
            &[
                "mode",
                "capture",
                "inventory_root",
                "source_quad_root",
                "t",
                "cid",
            ],
            &[],
        )?;
        if provenance.field("mode")?.as_str()? != "fluree-direct/v1" {
            return Err(Error::invalid("unrecognized raw FIBO host mode"));
        }
        let t = provenance
            .field("t")?
            .as_str()?
            .parse::<i64>()
            .map_err(|_| Error::invalid("malformed raw FIBO host pin"))?;
        if t < 0 {
            return Err(Error::invalid("malformed raw FIBO host pin"));
        }
        let pin = DirectPin {
            capture: provenance.field("capture")?.as_str()?.to_owned(),
            catalog_root: provenance.field("inventory_root")?.as_str()?.to_owned(),
            t,
            cid: provenance.field("cid")?.as_str()?.to_owned(),
        };
        if pin.capture.is_empty() || pin.catalog_root.is_empty() || pin.cid.is_empty() {
            return Err(Error::invalid("malformed raw FIBO host pin"));
        }
        Ok(Self {
            certified,
            direct,
            pin,
        })
    }

    /// Resolves a model-suggested local name or label only when the direct
    /// search has one exact, source-backed match of the requested kind.
    /// No IRI is synthesized from `query`.
    pub(crate) fn resolve_unique(&self, query: &str, kind: OntologyTermKind) -> Result<Iri> {
        if query.is_empty()
            || query.len() > 512
            || query.chars().any(char::is_control)
            || !matches!(kind, OntologyTermKind::Class | OntologyTermKind::Property)
        {
            return Err(Error::invalid("invalid raw FIBO mapping suggestion"));
        }
        let response = self.lookup_kind("resolve_exact", query, SEARCH_LIMIT, Some(kind))?;
        if response
            .resolution
            .as_ref()
            .map(|value| value.status.as_str())
            != Some("unique")
        {
            return Err(Error::invalid(
                "raw ontology mapping suggestion is not unique",
            ));
        }
        let mut matches = response
            .terms
            .into_iter()
            .filter(|term| {
                term.kind.as_kind() == Some(kind)
                    && term.status == "loaded_uncertified"
                    && term.extraction_eligible
                    && term.approved_inventory_member
            })
            .map(|term| term.iri)
            .collect::<BTreeSet<_>>();
        if matches.len() != 1 {
            return Err(Error::invalid("raw FIBO mapping suggestion is not unique"));
        }
        let iri = Iri::new(matches.pop_first().expect("one match"))?;
        // Exact-name resolution is discovery only. Acceptance requires an exact
        // describe against the same pin.
        self.raw_term(&iri, Some(kind))?;
        Ok(iri)
    }

    fn raw_term(&self, iri: &Iri, expected: Option<OntologyTermKind>) -> Result<OntologyTerm> {
        let mut response = self.lookup("describe", iri.as_str(), 1)?;
        if response.terms.len() != 1 {
            return Err(Error::invalid("raw FIBO term was not described exactly"));
        }
        let term = response.terms.pop().expect("one term");
        if term.iri != iri.as_str()
            || term.status != "loaded_uncertified"
            || !term.extraction_eligible
            || !term.approved_inventory_member
        {
            return Err(Error::invalid(
                "raw ontology term is deprecated or malformed",
            ));
        }
        let kind = term
            .kind
            .as_kind()
            .filter(|kind| matches!(kind, OntologyTermKind::Class | OntologyTermKind::Property))
            .ok_or_else(|| Error::invalid("unrecognized raw FIBO term kind"))?;
        if expected.is_some_and(|expected| expected != kind) {
            return Err(Error::invalid("raw FIBO term kind differs"));
        }
        OntologyTerm::new(
            iri.clone(),
            kind,
            VocabularyStatus::PermittedExtension,
            true,
            iri_set(term.super_terms)?,
            constraint_iri_set(term.constraints.domains)?,
            constraint_iri_set(term.constraints.ranges)?,
        )
    }

    fn lookup(&self, operation: &str, query: &str, limit: usize) -> Result<DirectResponse> {
        self.lookup_kind(operation, query, limit, None)
    }

    fn lookup_kind(
        &self,
        operation: &str,
        query: &str,
        limit: usize,
        kind: Option<OntologyTermKind>,
    ) -> Result<DirectResponse> {
        let mut request = json!({
            "operation": operation,
            "query": query,
            "limit": limit,
        });
        if let Some(kind) = kind {
            request["kind"] = json!(match kind {
                OntologyTermKind::Class => "class",
                OntologyTermKind::Property => "property",
                _ => return Err(Error::invalid("unsupported extraction vocabulary kind")),
            });
        }
        let value = self
            .direct
            .lookup(&request)
            .map_err(|_| Error::invalid("raw FIBO direct lookup denied"))?;
        let response: DirectResponse = serde_json::from_value(value)
            .map_err(|_| Error::invalid("malformed raw FIBO direct response"))?;
        if response.schema != "ctxql-extraction-vocabulary-response/v2"
            || response.operation != operation
            || response.query != query
            || response.capture != self.pin.capture
            || response.inventory_root != self.pin.catalog_root
            || response.t != self.pin.t
            || response.cid != self.pin.cid
            || response.source_quad_root.is_empty()
            || response.normalized_query.is_empty()
            || response.page.limit != limit
            || response.page.cursor.is_some()
            || response.page.truncated
            || response.namespace_mappings.is_empty()
            || response.requested_kind.as_deref()
                != kind.map(|value| match value {
                    OntologyTermKind::Class => "class",
                    OntologyTermKind::Property => "property",
                    _ => "unsupported",
                })
        {
            return Err(Error::invalid("raw FIBO direct response pin mismatch"));
        }
        if operation != "resolve_exact" && response.terms.len() > limit {
            return Err(Error::invalid("raw FIBO direct response exceeds limit"));
        }
        let mut iris = BTreeSet::new();
        if let Some(resolution) = &response.resolution {
            if !matches!(
                resolution.status.as_str(),
                "unique" | "ambiguous" | "not_found"
            ) || resolution.candidates.len() > 32
                || resolution.rule.is_empty()
                || (resolution.status == "unique"
                    && (!resolution.complete
                        || resolution.candidates_truncated
                        || resolution.r#match.as_deref()
                            != resolution.candidates.first().map(String::as_str)))
            {
                return Err(Error::invalid("malformed raw ontology resolution"));
            }
        } else if operation == "resolve_exact" {
            return Err(Error::invalid("missing raw ontology resolution"));
        }
        for term in &response.terms {
            validate_direct_term(term)?;
            if !iris.insert(term.iri.as_str()) {
                return Err(Error::invalid("duplicate raw FIBO direct term"));
            }
        }
        Ok(response)
    }
}

impl OntologyAuthority for RawMappingAuthority<'_> {
    fn extraction_term(&self, iri: &Iri) -> Result<OntologyTerm> {
        match self.certified.extraction_term(iri) {
            Ok(term) => Ok(term),
            Err(_) => self.raw_term(iri, None),
        }
    }
}

#[derive(Clone)]
struct DirectPin {
    capture: String,
    catalog_root: String,
    t: i64,
    cid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectResponse {
    schema: String,
    capture: String,
    inventory_root: String,
    source_quad_root: String,
    t: i64,
    cid: String,
    operation: String,
    query: String,
    normalized_query: String,
    requested_kind: Option<String>,
    namespace_mappings: BTreeMap<String, String>,
    page: DirectPage,
    resolution: Option<DirectResolution>,
    terms: Vec<DirectTerm>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectPage {
    limit: usize,
    truncated: bool,
    cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectResolution {
    status: String,
    r#match: Option<String>,
    candidates: Vec<String>,
    candidates_truncated: bool,
    complete: bool,
    rule: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectTerm {
    iri: String,
    kind: DirectKind,
    declarations: Vec<String>,
    status: String,
    deprecated: bool,
    extraction_eligible: bool,
    approved_inventory_member: bool,
    imported: bool,
    inventory_members: Vec<String>,
    source_graphs: Vec<String>,
    super_terms: Vec<String>,
    labels: Vec<String>,
    definitions: Vec<String>,
    aliases: Vec<String>,
    constraints: DirectConstraints,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectConstraints {
    domains: Vec<NamedConstraint>,
    ranges: Vec<NamedConstraint>,
    anonymous_domain_present: bool,
    anonymous_range_present: bool,
    anonymous_super_present: bool,
    unsupported_expression_present: bool,
    complete: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedConstraint {
    iri: String,
    provenance: String,
    source_graphs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum DirectKind {
    Class,
    ObjectProperty,
    DatatypeProperty,
    AnnotationProperty,
    GenericProperty,
    ConflictingProperty,
    Datatype,
    Vocabulary,
    Individual,
}

impl DirectKind {
    fn as_kind(&self) -> Option<OntologyTermKind> {
        match self {
            Self::Class => Some(OntologyTermKind::Class),
            Self::ObjectProperty | Self::DatatypeProperty => Some(OntologyTermKind::Property),
            Self::AnnotationProperty
            | Self::GenericProperty
            | Self::ConflictingProperty
            | Self::Datatype
            | Self::Vocabulary
            | Self::Individual => None,
        }
    }
}

fn validate_direct_term(term: &DirectTerm) -> Result<()> {
    Iri::new(term.iri.as_str())?;
    if !matches!(term.status.as_str(), "loaded_uncertified" | "deprecated")
        || !term.extraction_eligible
    {
        return Err(Error::invalid("unrecognized raw FIBO term status"));
    }
    if term.deprecated
        || term.inventory_members.is_empty()
        || term.source_graphs.is_empty()
        || term.inventory_members.iter().any(String::is_empty)
        || term.source_graphs.iter().any(String::is_empty)
        || (term.imported
            && term.inventory_members.iter().all(|path| {
                !path.starts_with("commons/")
                    && !path.starts_with("lcc/")
                    && !path.starts_with("fibo/")
            }))
        || (term.constraints.complete
            && (term.constraints.anonymous_domain_present
                || term.constraints.anonymous_range_present
                || term.constraints.anonymous_super_present
                || term.constraints.unsupported_expression_present))
    {
        return Err(Error::invalid("raw ontology inventory membership"));
    }
    for values in [&term.declarations, &term.super_terms] {
        let mut unique = BTreeSet::new();
        for value in values {
            Iri::new(value.as_str())?;
            if !unique.insert(value) {
                return Err(Error::invalid("duplicate raw ontology relationship IRI"));
            }
        }
    }
    for constraints in [&term.constraints.domains, &term.constraints.ranges] {
        let mut unique = BTreeSet::new();
        for constraint in constraints {
            Iri::new(constraint.iri.as_str())?;
            if constraint.provenance != "direct"
                || constraint.source_graphs.is_empty()
                || !unique.insert(&constraint.iri)
            {
                return Err(Error::invalid("malformed named ontology constraint"));
            }
        }
    }
    for values in [&term.labels, &term.definitions, &term.aliases] {
        let mut unique = BTreeSet::new();
        for value in values {
            if value.len() > 8192 || value.chars().any(char::is_control) || !unique.insert(value) {
                return Err(Error::invalid("malformed raw FIBO discovery text"));
            }
        }
    }
    Ok(())
}

fn constraint_iri_set(values: Vec<NamedConstraint>) -> Result<BTreeSet<Iri>> {
    iri_set(values.into_iter().map(|value| value.iri).collect())
}

fn iri_set(values: Vec<String>) -> Result<BTreeSet<Iri>> {
    let expected = values.len();
    let values = values
        .into_iter()
        .map(Iri::new)
        .collect::<Result<BTreeSet<_>>>()?;
    if values.len() != expected {
        return Err(Error::invalid("duplicate raw FIBO relationship IRI"));
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_response_rejects_unknown_or_unrecognized_values() {
        let base = json!({
            "schema": "ctxql-extraction-vocabulary-response/v2",
            "capture": "sha256:capture",
            "inventory_root": "sha256:inventory",
            "source_quad_root": "sha256:quads",
            "t": 1,
            "cid": "cid",
            "operation": "describe",
            "query": "https://www.omg.org/spec/Commons/DatesAndTimes/Date",
            "normalized_query": "https://www.omg.org/spec/Commons/DatesAndTimes/Date",
            "requested_kind": null,
            "namespace_mappings": {"commons":"https://www.omg.org/spec/Commons/"},
            "page": {"limit":1,"truncated":false,"cursor":null},
            "resolution": null,
            "terms": [{
                "iri": "https://www.omg.org/spec/Commons/DatesAndTimes/Date",
                "kind": "class",
                "declarations": ["http://www.w3.org/2002/07/owl#Class"],
                "status": "loaded_uncertified",
                "deprecated": false,
                "extraction_eligible": true,
                "approved_inventory_member": true,
                "imported": true,
                "inventory_members": ["commons/DatesAndTimes.rdf"],
                "source_graphs": ["https://www.omg.org/spec/Commons/DatesAndTimes/"],
                "super_terms": [],
                "labels": ["Date"],
                "definitions": ["A calendar date."],
                "aliases": ["calendar date"],
                "constraints": {
                    "domains": [], "ranges": [],
                    "anonymous_domain_present": false,
                    "anonymous_range_present": false,
                    "anonymous_super_present": false,
                    "unsupported_expression_present": false,
                    "complete": true
                }
            }]
        });
        let parsed = serde_json::from_value::<DirectResponse>(base.clone()).unwrap();
        assert!(validate_direct_term(&parsed.terms[0]).is_ok());
        let mut unknown = base.clone();
        unknown["unexpected"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<DirectResponse>(unknown).is_err());
        let mut kind = base;
        kind["terms"][0]["kind"] = serde_json::Value::String("fuzzy_property".into());
        assert!(serde_json::from_value::<DirectResponse>(kind).is_err());
    }

    #[test]
    fn relationship_sets_reject_duplicates_and_bad_iris() {
        assert!(iri_set(vec!["https://example.test/A".into()]).is_ok());
        assert!(iri_set(vec![
            "https://example.test/A".into(),
            "https://example.test/A".into()
        ])
        .is_err());
        assert!(iri_set(vec!["not an iri".into()]).is_err());
    }
}
