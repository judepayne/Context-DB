//! Immutable extraction-vocabulary lookup over an authorized Semantic capture.
//!
//! The adapter copies the bounded schema image during construction. Lookups
//! therefore cannot observe a later ledger head and never reopen storage.

use cdb_backend_fluree::{
    authorized_view::{ExactTerm, SourceQuad},
    semantic_preparation::PreparedAuthorizedView,
};
use cdb_core::{id::ContentHash, CanonicalValue as V};
use cdb_provider_pi::ontology_bridge::{OntologyToolError, OntologyToolHost};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_PROPERTY: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#Property";
const RDFS_CLASS: &str = "http://www.w3.org/2000/01/rdf-schema#Class";
const RDFS_DATATYPE: &str = "http://www.w3.org/2000/01/rdf-schema#Datatype";
const RDFS_SUBCLASS: &str = "http://www.w3.org/2000/01/rdf-schema#subClassOf";
const RDFS_SUBPROPERTY: &str = "http://www.w3.org/2000/01/rdf-schema#subPropertyOf";
const RDFS_DOMAIN: &str = "http://www.w3.org/2000/01/rdf-schema#domain";
const RDFS_RANGE: &str = "http://www.w3.org/2000/01/rdf-schema#range";
const OWL_CLASS: &str = "http://www.w3.org/2002/07/owl#Class";
const OWL_OBJECT_PROPERTY: &str = "http://www.w3.org/2002/07/owl#ObjectProperty";
const OWL_DATATYPE_PROPERTY: &str = "http://www.w3.org/2002/07/owl#DatatypeProperty";
const OWL_ANNOTATION_PROPERTY: &str = "http://www.w3.org/2002/07/owl#AnnotationProperty";
const OWL_NAMED_INDIVIDUAL: &str = "http://www.w3.org/2002/07/owl#NamedIndividual";
const OWL_ONTOLOGY: &str = "http://www.w3.org/2002/07/owl#Ontology";
const OWL_DEPRECATED: &str = "http://www.w3.org/2002/07/owl#deprecated";
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
const MAX_SCHEMA_QUADS: usize = 100_000;
const MAX_TERMS: usize = 50_000;
const MAX_TEXT_BYTES: usize = 8192;
const MAX_AMBIGUITY_CANDIDATES: usize = 32;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

const STANDARD_DATATYPES: &[&str] = &[
    "http://www.w3.org/2001/XMLSchema#boolean",
    "http://www.w3.org/2001/XMLSchema#date",
    "http://www.w3.org/2001/XMLSchema#dateTime",
    "http://www.w3.org/2001/XMLSchema#decimal",
    "http://www.w3.org/2001/XMLSchema#integer",
    "http://www.w3.org/2001/XMLSchema#string",
    RDF_LANG_STRING,
];

#[derive(Clone, Debug, Default)]
struct CapturedTerm {
    declarations: BTreeSet<String>,
    super_terms: BTreeSet<String>,
    domains: BTreeMap<String, BTreeSet<String>>,
    ranges: BTreeMap<String, BTreeSet<String>>,
    labels: BTreeSet<String>,
    definitions: BTreeSet<String>,
    aliases: BTreeSet<String>,
    source_graphs: BTreeSet<String>,
    anonymous_super: bool,
    anonymous_domain: bool,
    anonymous_range: bool,
    unsupported_expression: bool,
    deprecated: bool,
}

/// Read-only Pi ontology host captured from one `PreparedAuthorizedView`.
#[derive(Clone, Debug)]
pub(crate) struct SemanticVocabularyToolHost {
    terms: BTreeMap<String, CapturedTerm>,
    capture: String,
    graph_set_root: String,
    schema_root: String,
    t: i64,
    cid: String,
}

impl SemanticVocabularyToolHost {
    /// Capture the exact policy-authorized schema image. No reference to the
    /// prepared view or underlying ledger is retained.
    pub(crate) fn from_prepared(prepared: &PreparedAuthorizedView) -> Result<Self, String> {
        if prepared.manifest.ontology_profile.identity
            != cdb_backend_fluree::ontology_profile_v2::ONTOLOGY_PROFILE_V2_ID
            || prepared.manifest.supported_subset.is_some()
        {
            return Err("semantic vocabulary requires the current raw ontology profile".into());
        }
        if prepared.manifest.schema_quads.len() > MAX_SCHEMA_QUADS {
            return Err("semantic vocabulary schema exceeds limit".into());
        }
        let capture = ContentHash::of_bytes(
            format!(
                "ctxql-semantic-vocabulary-capture/v1\0{}\0{}\0{}\0{}",
                prepared.manifest.capture.ledger,
                prepared.manifest.capture.t,
                prepared.manifest.capture.commit_cid,
                prepared.manifest.schema_root.as_str(),
            )
            .as_bytes(),
        )
        .as_str()
        .to_owned();
        let graphs = prepared
            .manifest
            .schema_quads
            .iter()
            .map(|quad| quad.graph.as_str())
            .collect::<BTreeSet<_>>();
        let graph_set_root = ContentHash::of_bytes(
            graphs
                .iter()
                .flat_map(|graph| [graph.as_bytes(), b"\0"])
                .flatten()
                .copied()
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .as_str()
        .to_owned();
        let terms = capture_terms(&prepared.manifest.schema_quads)?;
        Ok(Self {
            terms,
            capture,
            graph_set_root,
            schema_root: prepared.manifest.schema_root.as_str().to_owned(),
            t: prepared.manifest.capture.t,
            cid: prepared.manifest.capture.commit_cid.clone(),
        })
    }

    /// Capture provenance for durable request/evidence binding.
    pub(crate) fn provenance(&self) -> Result<V, String> {
        V::object([
            ("mode".into(), V::string("semantic-prepared/v1")),
            ("capture".into(), V::string(&self.capture)),
            ("inventory_root".into(), V::string(&self.graph_set_root)),
            ("source_quad_root".into(), V::string(&self.schema_root)),
            ("t".into(), V::string(self.t.to_string())),
            ("cid".into(), V::string(&self.cid)),
        ])
        .map_err(|_| "semantic vocabulary provenance invalid".into())
    }

    fn response(
        &self,
        operation: &str,
        query: &str,
        requested_kind: Option<&str>,
        limit: usize,
    ) -> Result<Value, String> {
        let normalized_query = if operation == "resolve_exact" {
            expand_compact_identifier(query).unwrap_or_else(|| query.to_owned())
        } else {
            query.to_owned()
        };
        let identifier_resolution = operation == "resolve_exact"
            && valid_iri(&normalized_query)
            && (normalized_query != query || query.contains(':'));
        let mut truncated = false;
        let mut resolution_truncated = false;
        let mut selected = if operation == "resolve_exact"
            && STANDARD_DATATYPES.contains(&normalized_query.as_str())
        {
            vec![normalized_query.clone()]
        } else if matches!(operation, "describe" | "hierarchy" | "vocabulary_status") {
            self.terms
                .contains_key(&normalized_query)
                .then_some(normalized_query.clone())
                .into_iter()
                .collect()
        } else {
            let needle = normalized_query.to_lowercase();
            let mut values = self
                .terms
                .iter()
                .filter(|(_, term)| kind_matches(term_kind(&term.declarations), requested_kind))
                .filter(|(iri, term)| {
                    if operation == "resolve_exact" {
                        identifier_resolution && iri.as_str() == normalized_query
                            || !identifier_resolution && exact_lexical_match(iri, term, &needle)
                    } else {
                        contains_lexical_match(iri, term, &needle)
                    }
                })
                .map(|(iri, _)| iri.clone())
                .collect::<Vec<_>>();
            if operation == "resolve_exact" {
                if values.len() > MAX_AMBIGUITY_CANDIDATES {
                    values.truncate(MAX_AMBIGUITY_CANDIDATES);
                    resolution_truncated = true;
                }
            } else if values.len() > limit {
                values.truncate(limit);
                truncated = true;
            }
            values
        };
        if operation == "search" && requested_kind.is_none_or(|kind| kind == "datatype") {
            let needle = query.to_lowercase();
            for datatype in STANDARD_DATATYPES {
                if local_name(datatype).is_some_and(|name| name.to_lowercase().contains(&needle))
                    && !selected.iter().any(|iri| iri == datatype)
                {
                    selected.push((*datatype).to_owned());
                }
            }
            selected.sort();
            if selected.len() > limit {
                selected.truncate(limit);
                truncated = true;
            }
        }
        selected.retain(|iri| {
            if STANDARD_DATATYPES.contains(&iri.as_str()) {
                requested_kind.is_none_or(|kind| kind == "datatype")
            } else {
                self.terms
                    .get(iri)
                    .is_some_and(|term| kind_matches(term_kind(&term.declarations), requested_kind))
            }
        });
        let terms = selected
            .iter()
            .map(|iri| {
                self.terms
                    .get(iri)
                    .map(|term| project_term(iri, term))
                    .unwrap_or_else(|| standard_datatype_term(iri))
            })
            .collect::<Vec<_>>();
        let resolution = (operation == "resolve_exact")
            .then(|| resolution_projection(&terms, identifier_resolution, resolution_truncated));
        let response = json!({
            "schema": "ctxql-extraction-vocabulary-response/v2",
            "capture": self.capture,
            "inventory_root": self.graph_set_root,
            "source_quad_root": self.schema_root,
            "t": self.t,
            "cid": self.cid,
            "operation": operation,
            "query": query,
            "normalized_query": normalized_query,
            "requested_kind": requested_kind,
            "namespace_mappings": namespace_mappings(),
            "page": { "limit": limit, "truncated": truncated, "cursor": Value::Null },
            "resolution": resolution,
            "terms": terms,
        });
        if serde_json::to_vec(&response)
            .map_err(|_| "semantic vocabulary response encoding failed")?
            .len()
            > MAX_RESPONSE_BYTES
        {
            return Err("semantic vocabulary response exceeds limit".into());
        }
        Ok(response)
    }
}

impl OntologyToolHost for SemanticVocabularyToolHost {
    fn lookup(&self, request: &Value) -> Result<Value, OntologyToolError> {
        let object = request.as_object().ok_or(OntologyToolError::Denied)?;
        if object.len() < 2
            || object.len() > 4
            || object
                .keys()
                .any(|key| !matches!(key.as_str(), "operation" | "query" | "limit" | "kind"))
        {
            return Err(OntologyToolError::Denied);
        }
        let operation = object
            .get("operation")
            .and_then(Value::as_str)
            .filter(|value| {
                matches!(
                    *value,
                    "search" | "resolve_exact" | "describe" | "hierarchy" | "vocabulary_status"
                )
            })
            .ok_or(OntologyToolError::Denied)?;
        let query = object
            .get("query")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(OntologyToolError::Denied)?;
        let limit = match object.get("limit") {
            Some(value) => value.as_u64().ok_or(OntologyToolError::Denied)?,
            None => 10,
        };
        let kind = match object.get("kind") {
            Some(value) => Some(
                value
                    .as_str()
                    .filter(|value| {
                        matches!(
                            *value,
                            "class"
                                | "property"
                                | "object_property"
                                | "datatype_property"
                                | "annotation_property"
                                | "generic_property"
                                | "conflicting_property"
                                | "datatype"
                        )
                    })
                    .ok_or(OntologyToolError::Denied)?,
            ),
            None => None,
        };
        if !(1..=20).contains(&limit)
            || (!matches!(operation, "search" | "resolve_exact") && !valid_iri(query))
        {
            return Err(OntologyToolError::Denied);
        }
        self.response(operation, query, kind, limit as usize)
            .map_err(|_| OntologyToolError::Denied)
    }
}

fn capture_terms(quads: &BTreeSet<SourceQuad>) -> Result<BTreeMap<String, CapturedTerm>, String> {
    let mut terms = BTreeMap::<String, CapturedTerm>::new();
    for quad in quads {
        let Some(subject) = quad.subject_iri() else {
            continue;
        };
        if !valid_iri(subject) || !valid_iri(&quad.graph) {
            return Err("semantic vocabulary contains invalid IRI".into());
        }
        let term = terms.entry(subject.to_owned()).or_default();
        term.source_graphs.insert(quad.graph.clone());
        match quad.predicate.as_str() {
            RDF_TYPE => match &quad.object {
                ExactTerm::Iri(iri) if valid_iri(iri) => {
                    term.declarations.insert(iri.clone());
                }
                ExactTerm::Iri(_) => {
                    return Err("semantic vocabulary declaration IRI invalid".into())
                }
                _ => term.unsupported_expression = true,
            },
            RDFS_SUBCLASS | RDFS_SUBPROPERTY => {
                insert_relation(
                    &quad.object,
                    &mut term.super_terms,
                    &mut term.anonymous_super,
                )?;
            }
            RDFS_DOMAIN => insert_constraint(
                &quad.object,
                &quad.graph,
                &mut term.domains,
                &mut term.anonymous_domain,
            )?,
            RDFS_RANGE => insert_constraint(
                &quad.object,
                &quad.graph,
                &mut term.ranges,
                &mut term.anonymous_range,
            )?,
            OWL_DEPRECATED => {
                if matches!(&quad.object, ExactTerm::Literal { lexical, .. } if lexical == "true" || lexical == "1")
                {
                    term.deprecated = true;
                }
            }
            "http://www.w3.org/2000/01/rdf-schema#label"
            | "http://www.w3.org/2004/02/skos/core#prefLabel" => {
                insert_text(&quad.object, &mut term.labels)?;
            }
            "http://www.w3.org/2000/01/rdf-schema#comment"
            | "http://www.w3.org/2004/02/skos/core#definition" => {
                insert_text(&quad.object, &mut term.definitions)?;
            }
            "http://www.w3.org/2004/02/skos/core#altLabel"
            | "http://www.w3.org/2004/02/skos/core#hiddenLabel" => {
                insert_text(&quad.object, &mut term.aliases)?;
            }
            _ => {}
        }
        if terms.len() > MAX_TERMS {
            return Err("semantic vocabulary term limit exceeded".into());
        }
    }
    terms.retain(|_, term| term_kind(&term.declarations).is_some());
    Ok(terms)
}

fn insert_relation(
    object: &ExactTerm,
    values: &mut BTreeSet<String>,
    anonymous: &mut bool,
) -> Result<(), String> {
    match object {
        ExactTerm::Iri(iri) if valid_iri(iri) => {
            values.insert(iri.clone());
        }
        ExactTerm::Iri(_) => return Err("semantic vocabulary relation IRI invalid".into()),
        ExactTerm::ScopedBlankNode(_) => *anonymous = true,
        ExactTerm::Literal { .. } => *anonymous = true,
    }
    Ok(())
}

fn insert_constraint(
    object: &ExactTerm,
    graph: &str,
    values: &mut BTreeMap<String, BTreeSet<String>>,
    anonymous: &mut bool,
) -> Result<(), String> {
    match object {
        ExactTerm::Iri(iri) if valid_iri(iri) => {
            values
                .entry(iri.clone())
                .or_default()
                .insert(graph.to_owned());
        }
        ExactTerm::Iri(_) => return Err("semantic vocabulary constraint IRI invalid".into()),
        ExactTerm::ScopedBlankNode(_) => *anonymous = true,
        ExactTerm::Literal { .. } => *anonymous = true,
    }
    Ok(())
}

fn insert_text(object: &ExactTerm, values: &mut BTreeSet<String>) -> Result<(), String> {
    if let ExactTerm::Literal { lexical, .. } = object {
        if lexical.len() > MAX_TEXT_BYTES {
            return Err("semantic vocabulary text exceeds limit".into());
        }
        if !lexical.is_empty() {
            values.insert(lexical.clone());
        }
    }
    Ok(())
}

fn project_term(iri: &str, term: &CapturedTerm) -> Value {
    let complete = !term.anonymous_domain
        && !term.anonymous_range
        && !term.anonymous_super
        && !term.unsupported_expression;
    json!({
        "iri": iri,
        "kind": term_kind(&term.declarations).expect("captured supported term"),
        "declarations": term.declarations,
        "status": if term.deprecated { "deprecated" } else { "loaded_uncertified" },
        "deprecated": term.deprecated,
        "extraction_eligible": !term.deprecated,
        "approved_inventory_member": true,
        "imported": false,
        "inventory_members": term.source_graphs,
        "source_graphs": term.source_graphs,
        "super_terms": term.super_terms,
        "labels": term.labels,
        "definitions": term.definitions,
        "aliases": term.aliases,
        "constraints": {
            "domains": named_constraints(&term.domains),
            "ranges": named_constraints(&term.ranges),
            "anonymous_domain_present": term.anonymous_domain,
            "anonymous_range_present": term.anonymous_range,
            "anonymous_super_present": term.anonymous_super,
            "unsupported_expression_present": term.unsupported_expression,
            "complete": complete,
        }
    })
}

fn named_constraints(values: &BTreeMap<String, BTreeSet<String>>) -> Vec<Value> {
    values
        .iter()
        .map(|(iri, graphs)| json!({"iri":iri,"provenance":"semantic_capture","source_graphs":graphs}))
        .collect()
}

fn term_kind(types: &BTreeSet<String>) -> Option<&'static str> {
    if types.contains(OWL_CLASS) || types.contains(RDFS_CLASS) {
        Some("class")
    } else if types.contains(RDFS_DATATYPE) {
        Some("datatype")
    } else {
        let object = types.contains(OWL_OBJECT_PROPERTY);
        let datatype = types.contains(OWL_DATATYPE_PROPERTY);
        let annotation = types.contains(OWL_ANNOTATION_PROPERTY);
        if usize::from(object) + usize::from(datatype) + usize::from(annotation) > 1 {
            Some("conflicting_property")
        } else if object {
            Some("object_property")
        } else if datatype {
            Some("datatype_property")
        } else if annotation {
            Some("annotation_property")
        } else if types.contains(RDF_PROPERTY) {
            Some("generic_property")
        } else if types.contains(OWL_ONTOLOGY) {
            Some("vocabulary")
        } else if types.contains(OWL_NAMED_INDIVIDUAL) {
            Some("individual")
        } else {
            None
        }
    }
}

fn kind_matches(actual: Option<&str>, requested: Option<&str>) -> bool {
    requested.is_none_or(|requested| {
        actual == Some(requested)
            || requested == "property"
                && matches!(
                    actual,
                    Some(
                        "object_property"
                            | "datatype_property"
                            | "annotation_property"
                            | "generic_property"
                            | "conflicting_property"
                    )
                )
    })
}

fn exact_lexical_match(iri: &str, term: &CapturedTerm, needle: &str) -> bool {
    local_name(iri).is_some_and(|name| name.to_lowercase() == needle)
        || term
            .labels
            .iter()
            .chain(&term.aliases)
            .any(|text| text.to_lowercase() == needle)
}

fn contains_lexical_match(iri: &str, term: &CapturedTerm, needle: &str) -> bool {
    iri.to_lowercase().contains(needle)
        || term
            .labels
            .iter()
            .chain(&term.aliases)
            .chain(&term.definitions)
            .any(|text| text.to_lowercase().contains(needle))
}

fn resolution_projection(terms: &[Value], identifier: bool, truncated: bool) -> Value {
    let status = if terms.is_empty() {
        "not_found"
    } else if terms.len() == 1 && !truncated {
        "unique"
    } else {
        "ambiguous"
    };
    let candidates = terms
        .iter()
        .filter_map(|term| term["iri"].as_str())
        .collect::<Vec<_>>();
    json!({
        "status": status,
        "match": if status == "unique" { candidates.first().copied() } else { None },
        "candidates": candidates,
        "candidates_truncated": truncated,
        "complete": !truncated,
        "rule": if identifier { "exact_identifier" } else { "unique_exact_lexical" },
    })
}

fn standard_datatype_term(iri: &str) -> Value {
    json!({
        "iri": iri, "kind":"datatype", "declarations":[RDFS_DATATYPE],
        "status":"standard", "deprecated":false, "extraction_eligible":true,
        "approved_inventory_member":false, "imported":false,
        "inventory_members":[], "source_graphs":[], "super_terms":[],
        "labels":[local_name(iri).unwrap_or(iri)], "definitions":[], "aliases":[],
        "constraints":{"domains":[],"ranges":[],"anonymous_domain_present":false,
            "anonymous_range_present":false,"anonymous_super_present":false,
            "unsupported_expression_present":false,"complete":true}
    })
}

fn namespace_mappings() -> Value {
    json!({
        "commons":"https://www.omg.org/spec/Commons/",
        "fibo":"https://spec.edmcouncil.org/fibo/ontology/",
        "lcc":"https://www.omg.org/spec/LCC/",
        "owl":"http://www.w3.org/2002/07/owl#",
        "rdf":"http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "rdfs":"http://www.w3.org/2000/01/rdf-schema#",
        "skos":"http://www.w3.org/2004/02/skos/core#",
        "xsd":XSD,
    })
}

fn expand_compact_identifier(value: &str) -> Option<String> {
    let (prefix, local) = value.split_once(':')?;
    if local.is_empty() || local.chars().any(char::is_control) {
        return None;
    }
    let namespace = match prefix {
        "commons" => "https://www.omg.org/spec/Commons/",
        "fibo" => "https://spec.edmcouncil.org/fibo/ontology/",
        "lcc" => "https://www.omg.org/spec/LCC/",
        "owl" => "http://www.w3.org/2002/07/owl#",
        "rdf" => "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "rdfs" => "http://www.w3.org/2000/01/rdf-schema#",
        "skos" => "http://www.w3.org/2004/02/skos/core#",
        "xsd" => XSD,
        _ => return None,
    };
    Some(format!("{namespace}{local}"))
}

fn local_name(iri: &str) -> Option<&str> {
    iri.rsplit(['#', '/', ':'])
        .next()
        .filter(|value| !value.is_empty())
}

fn valid_iri(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.contains(':')
        && !value
            .chars()
            .any(|character| character <= '\u{20}' || "<>\"{}|^`\\".contains(character))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdb_backend_fluree::authorized_view::RdfNodeId;

    fn quad(subject: &str, predicate: &str, object: ExactTerm) -> SourceQuad {
        SourceQuad {
            graph: "urn:test:schema".into(),
            subject: RdfNodeId::Iri(subject.into()),
            predicate: predicate.into(),
            object,
        }
    }

    fn test_host(quads: BTreeSet<SourceQuad>) -> SemanticVocabularyToolHost {
        SemanticVocabularyToolHost {
            terms: capture_terms(&quads).unwrap(),
            capture: "sha256:capture".into(),
            graph_set_root: "sha256:graphs".into(),
            schema_root: "sha256:schema".into(),
            t: 7,
            cid: "cid".into(),
        }
    }

    #[test]
    fn projection_preserves_property_kind_definitions_and_constraints() {
        let iri = "urn:test:executionDate";
        let quads = BTreeSet::from([
            quad(iri, RDF_TYPE, ExactTerm::Iri(OWL_DATATYPE_PROPERTY.into())),
            quad(
                iri,
                RDFS_DOMAIN,
                ExactTerm::Iri("urn:test:Agreement".into()),
            ),
            quad(iri, RDFS_RANGE, ExactTerm::Iri(format!("{XSD}date"))),
            quad(
                iri,
                "http://www.w3.org/2000/01/rdf-schema#comment",
                ExactTerm::Literal {
                    lexical: "The agreement execution date.".into(),
                    datatype: format!("{XSD}string"),
                    language: None,
                },
            ),
        ]);
        let response = test_host(quads)
            .lookup(&json!({"operation":"describe","query":iri,"limit":10}))
            .unwrap();
        assert_eq!(response["terms"][0]["kind"], "datatype_property");
        assert_eq!(
            response["terms"][0]["definitions"][0],
            "The agreement execution date."
        );
        assert_eq!(
            response["terms"][0]["constraints"]["ranges"][0]["iri"],
            format!("{XSD}date")
        );
    }

    #[test]
    fn exact_resolution_uses_urn_local_name() {
        let iri = "urn:ctxql:a2:hasBorrower";
        let host = test_host(BTreeSet::from([quad(
            iri,
            RDF_TYPE,
            ExactTerm::Iri(OWL_OBJECT_PROPERTY.into()),
        )]));

        let response = host
            .lookup(&json!({
                "operation":"resolve_exact",
                "query":"hasBorrower",
                "kind":"object_property"
            }))
            .unwrap();

        assert_eq!(response["resolution"]["status"], "unique");
        assert_eq!(response["resolution"]["match"], iri);
    }

    #[test]
    fn exact_resolution_never_selects_unknown_or_ambiguous_text() {
        let declaration = |iri: &str| quad(iri, RDF_TYPE, ExactTerm::Iri(OWL_CLASS.into()));
        let label = |iri: &str| {
            quad(
                iri,
                "http://www.w3.org/2000/01/rdf-schema#label",
                ExactTerm::Literal {
                    lexical: "Party".into(),
                    datatype: format!("{XSD}string"),
                    language: None,
                },
            )
        };
        let host = test_host(BTreeSet::from([
            declaration("urn:test:Borrower"),
            label("urn:test:Borrower"),
            declaration("urn:test:Lender"),
            label("urn:test:Lender"),
        ]));
        let ambiguous = host
            .lookup(&json!({"operation":"resolve_exact","query":"Party","kind":"class"}))
            .unwrap();
        assert_eq!(ambiguous["resolution"]["status"], "ambiguous");
        assert!(ambiguous["resolution"]["match"].is_null());
        let unknown = host
            .lookup(&json!({"operation":"resolve_exact","query":"Guarantor","kind":"class"}))
            .unwrap();
        assert_eq!(unknown["resolution"]["status"], "not_found");
        assert!(unknown["terms"].as_array().unwrap().is_empty());
    }
}
