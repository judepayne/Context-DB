//! Complete, source-aware ontology construct inventory.
//!
//! This module is deliberately separate from profile v2.  An audit is allowed
//! to report many semantic problems, but it is never allowed to return a
//! truncated inventory.  Resource exhaustion is therefore an error rather than
//! a partially successful result.

use crate::authorized_view::{framed_root, quad_root, ExactTerm, RdfNodeId, SourceQuad};
use crate::ontology_conversion::{
    ConversionResult, BLANK_NODE_ALGORITHM, PARSER_ID, PARSER_OPTIONS,
};
use crate::ontology_dependency_universe::{ConversionPin, OntologyDependencyUniverse};
use cdb_core::id::ContentHash;
use std::collections::{BTreeMap, BTreeSet};

pub const CONSTRUCT_AUDIT_ID: &str = "ctxql-ontology-construct-audit/v1";
pub const ONTOLOGY_CONSTRUCT_INVENTORY_INCOMPLETE: &str = "ontology_construct_inventory_incomplete";

const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const RDFS: &str = "http://www.w3.org/2000/01/rdf-schema#";
const OWL: &str = "http://www.w3.org/2002/07/owl#";
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
const F: &str = "https://ns.flur.ee/db#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_FIRST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
const RDF_REST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
const RDF_NIL: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";
const OWL_RESTRICTION: &str = "http://www.w3.org/2002/07/owl#Restriction";
const OWL_NAMED_INDIVIDUAL: &str = "http://www.w3.org/2002/07/owl#NamedIndividual";
const OWL_INVERSE: &str = "http://www.w3.org/2002/07/owl#inverseOf";
const OWL_CHAIN: &str = "http://www.w3.org/2002/07/owl#propertyChainAxiom";
const OWL_KEY: &str = "http://www.w3.org/2002/07/owl#hasKey";
const OWL_ON_PROPERTY: &str = "http://www.w3.org/2002/07/owl#onProperty";
const OWL_HAS_VALUE: &str = "http://www.w3.org/2002/07/owl#hasValue";
const OWL_SOME_VALUES: &str = "http://www.w3.org/2002/07/owl#someValuesFrom";
const OWL_ALL_VALUES: &str = "http://www.w3.org/2002/07/owl#allValuesFrom";
const OWL_MIN_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#minCardinality";
const OWL_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#cardinality";
const OWL_MAX_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#maxCardinality";
const OWL_MIN_QUALIFIED_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#minQualifiedCardinality";
const OWL_QUALIFIED_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#qualifiedCardinality";
const OWL_MAX_QUALIFIED_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#maxQualifiedCardinality";
const OWL_HAS_SELF: &str = "http://www.w3.org/2002/07/owl#hasSelf";
const OWL_ON_CLASS: &str = "http://www.w3.org/2002/07/owl#onClass";
const OWL_ON_DATA_RANGE: &str = "http://www.w3.org/2002/07/owl#onDataRange";
const OWL_ON_DATATYPE: &str = "http://www.w3.org/2002/07/owl#onDatatype";
const OWL_WITH_RESTRICTIONS: &str = "http://www.w3.org/2002/07/owl#withRestrictions";
const OWL_INTERSECTION: &str = "http://www.w3.org/2002/07/owl#intersectionOf";
const OWL_UNION: &str = "http://www.w3.org/2002/07/owl#unionOf";
const OWL_ONE_OF: &str = "http://www.w3.org/2002/07/owl#oneOf";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditedOntologyMember {
    pub source_release_id: String,
    pub source_file_id: String,
    pub ontology_iri: String,
    pub authoritative_hash: ContentHash,
    pub conversion_root: ContentHash,
    pub graph: String,
    pub graph_root: ContentHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologySourceOccurrence {
    pub source_release_id: String,
    pub source_file_id: String,
    pub ontology_iri: String,
    pub conversion_root: ContentHash,
    pub graph: String,
    pub subject: RdfNodeId,
    pub predicate: String,
    pub object: ExactTerm,
    pub occurrence_identity: ContentHash,
}

impl OntologySourceOccurrence {
    fn quad(&self) -> SourceQuad {
        SourceQuad {
            graph: self.graph.clone(),
            subject: self.subject.clone(),
            predicate: self.predicate.clone(),
            object: self.object.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditedOntologyClosure {
    pub members: Vec<AuditedOntologyMember>,
    pub bundle: BTreeSet<SourceQuad>,
    pub occurrences: Vec<OntologySourceOccurrence>,
    pub graph_map: BTreeMap<String, String>,
    pub dependency_root: ContentHash,
    pub source_quad_root: ContentHash,
    pub closure_root: ContentHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstructAuditLimits {
    pub max_bundle_quads: usize,
    pub max_source_occurrences: usize,
    pub max_list_length: usize,
    pub max_expression_depth: usize,
    pub max_structural_work: usize,
    pub max_issues: usize,
    pub max_serialized_output_bytes: usize,
    pub max_diagnostics: usize,
}

impl Default for ConstructAuditLimits {
    fn default() -> Self {
        Self {
            max_bundle_quads: 100_000,
            max_source_occurrences: 500_000,
            max_list_length: 10_000,
            max_expression_depth: 10,
            max_structural_work: 20_000_000,
            max_issues: 100_000,
            max_serialized_output_bytes: 128 * 1024 * 1024,
            max_diagnostics: 128,
        }
    }
}

impl ConstructAuditLimits {
    pub fn identity(&self) -> ContentHash {
        ContentHash::of_bytes(
            format!(
                "ctxql-construct-audit-limits/v1;bundle={};occurrences={};list={};depth={};work={};issues={};output={};diagnostics={}",
                self.max_bundle_quads,
                self.max_source_occurrences,
                self.max_list_length,
                self.max_expression_depth,
                self.max_structural_work,
                self.max_issues,
                self.max_serialized_output_bytes,
                self.max_diagnostics
            )
            .as_bytes(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConstructDisposition {
    ReasonedCandidate,
    DeclarationCandidate,
    RetainedAnnotationCandidate,
    Unsupported,
    Malformed,
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstructAuditEntry {
    pub quad: SourceQuad,
    pub disposition: ConstructDisposition,
    pub construct: String,
    pub occurrence_identities: Vec<ContentHash>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConstructAuditIssue {
    pub source_release_id: String,
    pub source_file_id: String,
    pub ontology_iri: String,
    pub graph: String,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub class: ConstructDisposition,
    pub reason: &'static str,
    pub stage: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstructAuditResult {
    pub complete: bool,
    pub accepted: bool,
    pub closure_root: ContentHash,
    pub source_quad_root: ContentHash,
    pub source_entry_root: ContentHash,
    pub bundle_classification_root: ContentHash,
    pub entries: Vec<ConstructAuditEntry>,
    pub category_sets: BTreeMap<ConstructDisposition, BTreeSet<SourceQuad>>,
    pub category_counts: BTreeMap<ConstructDisposition, usize>,
    pub category_roots: BTreeMap<ConstructDisposition, ContentHash>,
    pub issues: Vec<ConstructAuditIssue>,
    pub issue_root: ContentHash,
    pub diagnostics: Vec<ConstructAuditIssue>,
    pub limits_identity: ContentHash,
    pub construct_audit_root: ContentHash,
}

impl ConstructAuditResult {
    /// Recomputes all closure, occurrence, entry, classification and issue
    /// commitments. No caller-supplied occurrence identity is trusted.
    pub fn verify_integrity(&self, closure: &AuditedOntologyClosure) -> bool {
        if verify_closure_self_consistency(closure).is_err() {
            return false;
        }
        let occurrences = occurrence_index(&closure.occurrences);
        let issue_classes: BTreeMap<_, _> = self
            .issues
            .iter()
            .filter(|issue| !issue.predicate.is_empty())
            .map(|issue| {
                (
                    (
                        issue.graph.as_str(),
                        issue.subject.as_str(),
                        issue.predicate.as_str(),
                        issue.object.as_str(),
                    ),
                    issue.class,
                )
            })
            .collect();
        let expected_entries = closure
            .bundle
            .iter()
            .map(|quad| {
                let (mut disposition, _) = classify_member(quad);
                let subject = quad.subject.commitment();
                let object = quad.object.commitment();
                if let Some(class) = issue_classes.get(&(
                    quad.graph.as_str(),
                    subject.as_str(),
                    quad.predicate.as_str(),
                    object.as_str(),
                )) {
                    disposition = *class;
                }
                ConstructAuditEntry {
                    quad: quad.clone(),
                    disposition,
                    construct: construct_name(&quad.predicate).to_owned(),
                    occurrence_identities: occurrences
                        .get(quad)
                        .expect("closure consistency checked")
                        .iter()
                        .map(|occurrence| occurrence.occurrence_identity.clone())
                        .collect(),
                }
            })
            .collect::<Vec<_>>();
        let rebuilt_partition = expected_entries.iter().fold(
            BTreeMap::<ConstructDisposition, BTreeSet<SourceQuad>>::new(),
            |mut partition, entry| {
                partition
                    .entry(entry.disposition)
                    .or_default()
                    .insert(entry.quad.clone());
                partition
            },
        );
        let counts = self
            .category_sets
            .iter()
            .map(|(category, quads)| (*category, quads.len()))
            .collect::<BTreeMap<_, _>>();
        let roots = self
            .category_sets
            .iter()
            .map(|(category, quads)| (*category, quad_root(quads)))
            .collect::<BTreeMap<_, _>>();
        let entry_values = self
            .entries
            .iter()
            .map(entry_commitment)
            .collect::<Vec<_>>();
        let source_entry_root = framed_root(
            "ctxql-construct-audit-source-entries/v1",
            entry_values.iter().map(|value| ("entry", value.as_str())),
        );
        let issue_values = self.issues.iter().map(issue_commitment).collect::<Vec<_>>();
        let issue_root = framed_root(
            "ctxql-construct-audit-issues/v1",
            issue_values.iter().map(|value| ("issue", value.as_str())),
        );
        let count_value = self
            .category_counts
            .iter()
            .map(|(category, count)| format!("{category:?}:{count}"))
            .collect::<Vec<_>>()
            .join("\0");
        let audit_root = framed_root(
            "ctxql-ontology-construct-audit-result/v1",
            [
                ("identity", CONSTRUCT_AUDIT_ID),
                ("closure", self.closure_root.as_str()),
                ("source-quads", self.source_quad_root.as_str()),
                ("source-entries", self.source_entry_root.as_str()),
                ("classification", self.bundle_classification_root.as_str()),
                ("issues", self.issue_root.as_str()),
                ("counts", count_value.as_str()),
                ("limits", self.limits_identity.as_str()),
            ],
        );
        self.complete
            && self.closure_root == closure.closure_root
            && self.source_quad_root == closure.source_quad_root
            && self.entries == expected_entries
            && rebuilt_partition == self.category_sets
            && counts == self.category_counts
            && roots == self.category_roots
            && source_entry_root == self.source_entry_root
            && bundle_classification_root_for_partition(&self.category_sets)
                == self.bundle_classification_root
            && self.issues.windows(2).all(|pair| pair[0] <= pair[1])
            && issue_root == self.issue_root
            && self.diagnostics.len() <= self.issues.len()
            && self
                .diagnostics
                .iter()
                .zip(&self.issues)
                .all(|(left, right)| left == right)
            && self.accepted == self.issues.is_empty()
            && audit_root == self.construct_audit_root
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstructAuditError {
    pub public_code: &'static str,
    pub reason: &'static str,
}

impl std::fmt::Display for ConstructAuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.public_code)
    }
}
impl std::error::Error for ConstructAuditError {}

type Result<T> = std::result::Result<T, ConstructAuditError>;

fn incomplete(reason: &'static str) -> ConstructAuditError {
    ConstructAuditError {
        public_code: ONTOLOGY_CONSTRUCT_INVENTORY_INCOMPLETE,
        reason,
    }
}

/// Builds a source-aware closure from an already selected exact conversion set.
/// The caller supplies the ontology owner IRI for each conversion; executable
/// profile sealing separately proves that this set is the universe closure.
pub fn build_audited_closure_from_conversions(
    inputs: Vec<(String, ConversionPin, ConversionResult)>,
) -> Result<AuditedOntologyClosure> {
    if inputs.is_empty() {
        return Err(incomplete("conversion_set_empty"));
    }
    let owned_iris = inputs
        .iter()
        .map(|(ontology_iri, _, _)| ontology_iri.clone())
        .collect::<BTreeSet<_>>();
    if owned_iris.len() != inputs.len()
        || inputs.iter().any(|(ontology_iri, pin, _)| {
            pin.ontology_iris().len() != 1
                || pin.ontology_iris()[0] != *ontology_iri
                || pin.version_iris().len() != 1
                || pin
                    .imports()
                    .iter()
                    .any(|import| !owned_iris.contains(import))
        })
    {
        return Err(incomplete("dependency_ownership_map_invalid"));
    }
    let mut ownership_values = inputs
        .iter()
        .map(|(ontology_iri, pin, conversion)| {
            format!(
                "{}\0{}\0{}\0{}\0{}\0{}",
                ontology_iri,
                pin.version_iris()[0],
                pin.imports().join("\0"),
                conversion.source_release_id,
                conversion.source_file_id,
                pin.root().as_str(),
            )
        })
        .collect::<Vec<_>>();
    ownership_values.sort();
    let dependency_root = framed_root(
        "ctxql-audited-conversion-universe/v1",
        ownership_values
            .iter()
            .map(|value| ("owner", value.as_str())),
    );
    let mut members = Vec::new();
    let mut bundle = BTreeSet::new();
    let mut occurrences = Vec::new();
    let mut graph_map = BTreeMap::new();
    let mut sources = BTreeSet::new();
    for (ontology_iri, conversion_pin, conversion) in inputs {
        if ontology_iri.is_empty()
            || !conversion_pin.matches_result(&conversion)
            || conversion.parser_identity != PARSER_ID
            || conversion.parser_options != PARSER_OPTIONS
            || conversion.blank_node_algorithm != BLANK_NODE_ALGORITHM
            || conversion
                .quads
                .iter()
                .any(|quad| quad.graph != conversion.graph_iri)
            || !sources.insert((
                conversion.source_release_id.clone(),
                conversion.source_file_id.clone(),
            ))
            || graph_map
                .insert(ontology_iri.clone(), conversion.graph_iri.clone())
                .is_some()
        {
            return Err(incomplete("ownership_conversion_mismatch"));
        }
        members.push(AuditedOntologyMember {
            source_release_id: conversion.source_release_id.clone(),
            source_file_id: conversion.source_file_id.clone(),
            ontology_iri: ontology_iri.clone(),
            authoritative_hash: conversion.original_hash.clone(),
            conversion_root: conversion.conversion_root.clone(),
            graph: conversion.graph_iri.clone(),
            graph_root: conversion.graph_root.clone(),
        });
        for quad in &conversion.quads {
            bundle.insert(quad.clone());
            let occurrence_identity = occurrence_root(
                &conversion.source_release_id,
                &conversion.source_file_id,
                &ontology_iri,
                &conversion.conversion_root,
                quad,
            );
            occurrences.push(OntologySourceOccurrence {
                source_release_id: conversion.source_release_id.clone(),
                source_file_id: conversion.source_file_id.clone(),
                ontology_iri: ontology_iri.clone(),
                conversion_root: conversion.conversion_root.clone(),
                graph: quad.graph.clone(),
                subject: quad.subject.clone(),
                predicate: quad.predicate.clone(),
                object: quad.object.clone(),
                occurrence_identity,
            });
        }
    }
    members.sort_by(|a, b| member_key(a).cmp(&member_key(b)));
    occurrences.sort_by(|a, b| occurrence_key(a).cmp(&occurrence_key(b)));
    let source_quad_root = occurrence_set_root(&occurrences);
    let closure_root = compute_closure_root(&members, &dependency_root, &source_quad_root);
    Ok(AuditedOntologyClosure {
        members,
        bundle,
        occurrences,
        graph_map,
        dependency_root,
        source_quad_root,
        closure_root,
    })
}

/// Builds the source-aware closure from the universe's exact transitive closure.
/// Every selected owner must have exactly one matching conversion result.
pub fn build_audited_ontology_closure(
    universe: &OntologyDependencyUniverse,
    entries: &[String],
    conversions: &[ConversionResult],
) -> Result<AuditedOntologyClosure> {
    let selected = universe
        .transitive_closure(entries)
        .map_err(|_| incomplete("closure_resolution_failed"))?;
    let selected_set: BTreeSet<_> = selected.iter().cloned().collect();
    let mut by_source: BTreeMap<(&str, &str), &ConversionResult> = BTreeMap::new();
    for conversion in conversions {
        let key = (
            conversion.source_release_id.as_str(),
            conversion.source_file_id.as_str(),
        );
        if by_source.insert(key, conversion).is_some() {
            return Err(incomplete("duplicate_conversion_result"));
        }
    }
    if conversions.len() != selected.len() {
        return Err(incomplete("conversion_set_not_exact"));
    }

    let mut members = Vec::new();
    let mut bundle = BTreeSet::new();
    let mut occurrences = Vec::new();
    let mut graph_map = BTreeMap::new();
    for ontology_iri in selected {
        let owner = universe
            .owner(&ontology_iri)
            .ok_or_else(|| incomplete("selected_owner_missing"))?;
        let key = (owner.release_id().as_str(), owner.artifact().as_str());
        let conversion = by_source
            .remove(&key)
            .ok_or_else(|| incomplete("selected_conversion_missing"))?;
        if !selected_set.contains(owner.ontology_iri())
            || conversion.source_release_id != owner.release_id().as_str()
            || conversion.source_file_id != owner.artifact().as_str()
            || conversion.graph_iri != owner.graph_iri()
            || conversion.original_hash != *owner.authoritative_hash()
            || conversion.conversion_root != *owner.conversion().root()
            || conversion.graph_root != *owner.conversion().graph_root()
            || conversion.parser_identity != PARSER_ID
            || conversion.parser_options != PARSER_OPTIONS
            || conversion.blank_node_algorithm != BLANK_NODE_ALGORITHM
            || !owner.conversion().matches_result(conversion)
            || conversion.output_triple_count != conversion.quads.len()
            || quad_root(&conversion.quads) != conversion.graph_root
            || conversion
                .quads
                .iter()
                .any(|quad| quad.graph != conversion.graph_iri)
        {
            return Err(incomplete("ownership_conversion_mismatch"));
        }
        if graph_map
            .insert(ontology_iri.clone(), conversion.graph_iri.clone())
            .is_some()
        {
            return Err(incomplete("duplicate_graph_mapping"));
        }
        members.push(AuditedOntologyMember {
            source_release_id: conversion.source_release_id.clone(),
            source_file_id: conversion.source_file_id.clone(),
            ontology_iri: ontology_iri.clone(),
            authoritative_hash: conversion.original_hash.clone(),
            conversion_root: conversion.conversion_root.clone(),
            graph: conversion.graph_iri.clone(),
            graph_root: conversion.graph_root.clone(),
        });
        for quad in &conversion.quads {
            bundle.insert(quad.clone());
            let identity = occurrence_root(
                &conversion.source_release_id,
                &conversion.source_file_id,
                &ontology_iri,
                &conversion.conversion_root,
                quad,
            );
            occurrences.push(OntologySourceOccurrence {
                source_release_id: conversion.source_release_id.clone(),
                source_file_id: conversion.source_file_id.clone(),
                ontology_iri: ontology_iri.clone(),
                conversion_root: conversion.conversion_root.clone(),
                graph: quad.graph.clone(),
                subject: quad.subject.clone(),
                predicate: quad.predicate.clone(),
                object: quad.object.clone(),
                occurrence_identity: identity,
            });
        }
    }
    if !by_source.is_empty() {
        return Err(incomplete("conversion_set_not_exact"));
    }
    members.sort_by(|a, b| member_key(a).cmp(&member_key(b)));
    occurrences.sort_by(|a, b| occurrence_key(a).cmp(&occurrence_key(b)));
    let dependency_root = universe.root().clone();
    let source_quad_root = occurrence_set_root(&occurrences);
    let closure_root = compute_closure_root(&members, &dependency_root, &source_quad_root);
    Ok(AuditedOntologyClosure {
        members,
        bundle,
        occurrences,
        graph_map,
        dependency_root,
        source_quad_root,
        closure_root,
    })
}

/// Reconstructs a source-minimal audit projection from an exact historical
/// ledger bundle. Original source-occurrence commitments cannot be recreated
/// from the ledger and remain bound by the executable manifest; this projection
/// exists only to rerun the closed construct and component classifiers over the
/// captured RDF terms without cache, network, or ambient catalog access.
pub fn reconstruct_historical_audit_closure(
    bundle: &BTreeSet<SourceQuad>,
    dependency_root: ContentHash,
) -> Result<AuditedOntologyClosure> {
    if bundle.is_empty() {
        return Err(incomplete("historical_bundle_empty"));
    }
    let mut by_graph = BTreeMap::<String, BTreeSet<SourceQuad>>::new();
    for quad in bundle {
        if quad.graph.is_empty() {
            return Err(incomplete("historical_graph_missing"));
        }
        by_graph
            .entry(quad.graph.clone())
            .or_default()
            .insert(quad.clone());
    }

    let mut members = Vec::with_capacity(by_graph.len());
    let mut occurrences = Vec::with_capacity(bundle.len());
    let mut graph_map = BTreeMap::new();
    for (graph, graph_quads) in by_graph {
        let graph_root = quad_root(&graph_quads);
        let conversion_root = framed_root(
            "ctxql-historical-ledger-conversion-projection/v1",
            [("graph", graph.as_str()), ("quads", graph_root.as_str())],
        );
        let source_release_id = "ctxql-historical-ledger/v1".to_string();
        let source_file_id = graph.clone();
        if graph_map.insert(graph.clone(), graph.clone()).is_some() {
            return Err(incomplete("duplicate_graph_mapping"));
        }
        members.push(AuditedOntologyMember {
            source_release_id: source_release_id.clone(),
            source_file_id: source_file_id.clone(),
            ontology_iri: graph.clone(),
            authoritative_hash: graph_root.clone(),
            conversion_root: conversion_root.clone(),
            graph: graph.clone(),
            graph_root,
        });
        for quad in graph_quads {
            occurrences.push(OntologySourceOccurrence {
                occurrence_identity: occurrence_root(
                    &source_release_id,
                    &source_file_id,
                    &graph,
                    &conversion_root,
                    &quad,
                ),
                source_release_id: source_release_id.clone(),
                source_file_id: source_file_id.clone(),
                ontology_iri: graph.clone(),
                conversion_root: conversion_root.clone(),
                graph: quad.graph.clone(),
                subject: quad.subject.clone(),
                predicate: quad.predicate.clone(),
                object: quad.object.clone(),
            });
        }
    }
    members.sort_by(|left, right| member_key(left).cmp(&member_key(right)));
    occurrences.sort_by(|left, right| occurrence_key(left).cmp(&occurrence_key(right)));
    let source_quad_root = occurrence_set_root(&occurrences);
    let closure_root = compute_closure_root(&members, &dependency_root, &source_quad_root);
    Ok(AuditedOntologyClosure {
        members,
        bundle: bundle.clone(),
        occurrences,
        graph_map,
        dependency_root,
        source_quad_root,
        closure_root,
    })
}

/// Produces a complete collecting audit. `max_diagnostics` affects only the
/// display projection; all entries, issues, counts and roots remain complete.
pub fn audit_ontology_closure(
    closure: &AuditedOntologyClosure,
    limits: ConstructAuditLimits,
) -> Result<ConstructAuditResult> {
    if limits.max_bundle_quads == 0
        || limits.max_source_occurrences == 0
        || limits.max_list_length == 0
        || limits.max_expression_depth == 0
        || limits.max_structural_work == 0
        || limits.max_issues == 0
        || limits.max_serialized_output_bytes == 0
        || closure.bundle.len() > limits.max_bundle_quads
        || closure.occurrences.len() > limits.max_source_occurrences
    {
        return Err(incomplete("audit_limit_exceeded"));
    }
    verify_closure_self_consistency(closure)?;

    let occurrence_index = occurrence_index(&closure.occurrences);
    let mut issues = Vec::new();
    let mut entries = Vec::with_capacity(closure.bundle.len());
    let mut categories: BTreeMap<ConstructDisposition, BTreeSet<SourceQuad>> = BTreeMap::new();
    for quad in &closure.bundle {
        let (disposition, reason) = classify_member(quad);
        categories
            .entry(disposition)
            .or_default()
            .insert(quad.clone());
        let ids = occurrence_index
            .get(quad)
            .expect("closure consistency checked")
            .iter()
            .map(|occurrence| occurrence.occurrence_identity.clone())
            .collect();
        entries.push(ConstructAuditEntry {
            quad: quad.clone(),
            disposition,
            construct: construct_name(&quad.predicate).to_owned(),
            occurrence_identities: ids,
        });
        if let Some(reason) = reason {
            add_quad_issues(
                &mut issues,
                &occurrence_index,
                quad,
                disposition,
                reason,
                "classification",
            );
        }
    }

    let mut validator = Validator::new(closure, &occurrence_index, limits, issues);
    validator.validate()?;
    let mut issues = validator.issues;
    issues.sort();
    issues.dedup();
    if issues.len() > limits.max_issues {
        return Err(incomplete("issue_inventory_limit_exceeded"));
    }

    // A structural issue upgrades affected otherwise-successful members.  The
    // category partition remains total and disjoint.
    let issue_classes: BTreeMap<_, _> = issues
        .iter()
        .filter(|issue| !issue.predicate.is_empty())
        .map(|issue| {
            (
                (
                    issue.graph.as_str(),
                    issue.subject.as_str(),
                    issue.predicate.as_str(),
                    issue.object.as_str(),
                ),
                issue.class,
            )
        })
        .collect();
    categories.clear();
    for entry in &mut entries {
        let key = (
            entry.quad.graph.as_str(),
            entry.quad.subject.commitment(),
            entry.quad.predicate.as_str(),
            entry.quad.object.commitment(),
        );
        if let Some(class) = issue_classes.get(&(key.0, key.1.as_str(), key.2, key.3.as_str())) {
            entry.disposition = *class;
        }
        categories
            .entry(entry.disposition)
            .or_default()
            .insert(entry.quad.clone());
    }

    let category_counts = categories
        .iter()
        .map(|(category, quads)| (*category, quads.len()))
        .collect::<BTreeMap<_, _>>();
    let category_roots = categories
        .iter()
        .map(|(category, quads)| (*category, quad_root(quads)))
        .collect::<BTreeMap<_, _>>();
    let source_entry_values = entries.iter().map(entry_commitment).collect::<Vec<_>>();
    let source_entry_root = framed_root(
        "ctxql-construct-audit-source-entries/v1",
        source_entry_values
            .iter()
            .map(|value| ("entry", value.as_str())),
    );
    let bundle_classification_root = bundle_classification_root_for_partition(&categories);
    let issue_values = issues.iter().map(issue_commitment).collect::<Vec<_>>();
    let issue_root = framed_root(
        "ctxql-construct-audit-issues/v1",
        issue_values.iter().map(|value| ("issue", value.as_str())),
    );
    let output_size = source_entry_values
        .iter()
        .chain(issue_values.iter())
        .try_fold(0usize, |total, value| total.checked_add(value.len()))
        .ok_or_else(|| incomplete("serialized_output_limit_exceeded"))?;
    if output_size > limits.max_serialized_output_bytes {
        return Err(incomplete("serialized_output_limit_exceeded"));
    }
    let limits_identity = limits.identity();
    let count_value = category_counts
        .iter()
        .map(|(category, count)| format!("{category:?}:{count}"))
        .collect::<Vec<_>>()
        .join("\0");
    let construct_audit_root = framed_root(
        "ctxql-ontology-construct-audit-result/v1",
        [
            ("identity", CONSTRUCT_AUDIT_ID),
            ("closure", closure.closure_root.as_str()),
            ("source-quads", closure.source_quad_root.as_str()),
            ("source-entries", source_entry_root.as_str()),
            ("classification", bundle_classification_root.as_str()),
            ("issues", issue_root.as_str()),
            ("counts", count_value.as_str()),
            ("limits", limits_identity.as_str()),
        ],
    );
    let accepted = issues.is_empty();
    let diagnostics = issues
        .iter()
        .take(limits.max_diagnostics)
        .cloned()
        .collect();
    Ok(ConstructAuditResult {
        complete: true,
        accepted,
        closure_root: closure.closure_root.clone(),
        source_quad_root: closure.source_quad_root.clone(),
        source_entry_root,
        bundle_classification_root,
        entries,
        category_sets: categories,
        category_counts,
        category_roots,
        issues,
        issue_root,
        diagnostics,
        limits_identity,
        construct_audit_root,
    })
}

fn verify_closure_self_consistency(closure: &AuditedOntologyClosure) -> Result<()> {
    let rebuilt: BTreeSet<_> = closure
        .occurrences
        .iter()
        .map(OntologySourceOccurrence::quad)
        .collect();
    let mut sorted_members = closure.members.clone();
    sorted_members.sort_by(|a, b| member_key(a).cmp(&member_key(b)));
    let mut sorted_occurrences = closure.occurrences.clone();
    sorted_occurrences.sort_by(|a, b| occurrence_key(a).cmp(&occurrence_key(b)));
    let expected_graph_map: BTreeMap<_, _> = closure
        .members
        .iter()
        .map(|member| (member.ontology_iri.clone(), member.graph.clone()))
        .collect();
    let member_sources: BTreeSet<_> = closure
        .members
        .iter()
        .map(|member| {
            (
                member.source_release_id.as_str(),
                member.source_file_id.as_str(),
                member.ontology_iri.as_str(),
                member.conversion_root.as_str(),
                member.graph.as_str(),
            )
        })
        .collect();
    if rebuilt != closure.bundle
        || sorted_members != closure.members
        || sorted_occurrences != closure.occurrences
        || member_sources.len() != closure.members.len()
        || expected_graph_map.len() != closure.members.len()
        || expected_graph_map != closure.graph_map
        || occurrence_set_root(&closure.occurrences) != closure.source_quad_root
        || compute_closure_root(
            &closure.members,
            &closure.dependency_root,
            &closure.source_quad_root,
        ) != closure.closure_root
        || closure.occurrences.iter().any(|occurrence| {
            !member_sources.contains(&(
                occurrence.source_release_id.as_str(),
                occurrence.source_file_id.as_str(),
                occurrence.ontology_iri.as_str(),
                occurrence.conversion_root.as_str(),
                occurrence.graph.as_str(),
            )) || occurrence_root(
                &occurrence.source_release_id,
                &occurrence.source_file_id,
                &occurrence.ontology_iri,
                &occurrence.conversion_root,
                &occurrence.quad(),
            ) != occurrence.occurrence_identity
        })
    {
        return Err(incomplete("closure_integrity_mismatch"));
    }
    Ok(())
}

fn compute_closure_root(
    members: &[AuditedOntologyMember],
    dependency_root: &ContentHash,
    source_quad_root: &ContentHash,
) -> ContentHash {
    let member_values: Vec<_> = members
        .iter()
        .map(|member| {
            format!(
                "{}\0{}\0{}\0{}\0{}\0{}",
                member.source_release_id,
                member.source_file_id,
                member.ontology_iri,
                member.conversion_root.as_str(),
                member.graph,
                member.graph_root.as_str()
            )
        })
        .collect();
    let mut fields: Vec<(&str, &str)> = member_values
        .iter()
        .map(|value| ("member", value.as_str()))
        .collect();
    fields.push(("dependency-universe", dependency_root.as_str()));
    fields.push(("bundle", source_quad_root.as_str()));
    framed_root("ctxql-audited-ontology-closure/v1", fields)
}

fn member_key(member: &AuditedOntologyMember) -> (&str, &str, &str, &str) {
    (
        &member.source_release_id,
        &member.source_file_id,
        &member.ontology_iri,
        &member.graph,
    )
}
fn occurrence_key(occurrence: &OntologySourceOccurrence) -> (&str, &str, &str, &str, String) {
    (
        &occurrence.source_release_id,
        &occurrence.source_file_id,
        &occurrence.ontology_iri,
        &occurrence.graph,
        occurrence.quad().commitment(),
    )
}
fn occurrence_root(
    release: &str,
    file: &str,
    ontology: &str,
    conversion: &ContentHash,
    quad: &SourceQuad,
) -> ContentHash {
    let commitment = ContentHash::of_bytes(quad.commitment().as_bytes());
    framed_root(
        "ctxql-ontology-source-occurrence/v1",
        [
            ("release", release),
            ("file", file),
            ("ontology", ontology),
            ("conversion", conversion.as_str()),
            ("quad", commitment.as_str()),
        ],
    )
}
fn occurrence_set_root(occurrences: &[OntologySourceOccurrence]) -> ContentHash {
    let values = occurrences
        .iter()
        .map(|occurrence| occurrence.occurrence_identity.as_str().to_owned())
        .collect::<Vec<_>>();
    framed_root(
        "ctxql-ontology-source-occurrences/v1",
        values.iter().map(|value| ("occurrence", value.as_str())),
    )
}
fn occurrence_index(
    occurrences: &[OntologySourceOccurrence],
) -> BTreeMap<SourceQuad, Vec<&OntologySourceOccurrence>> {
    let mut index: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for occurrence in occurrences {
        index.entry(occurrence.quad()).or_default().push(occurrence);
    }
    index
}

fn classify_member(quad: &SourceQuad) -> (ConstructDisposition, Option<&'static str>) {
    if is_annotation(&quad.predicate) {
        return if annotation_shape_valid(quad) {
            (ConstructDisposition::RetainedAnnotationCandidate, None)
        } else {
            (
                ConstructDisposition::Unsupported,
                Some("ontology_metadata_shape_unsupported"),
            )
        };
    }
    if quad.predicate == RDF_TYPE {
        let Some(object) = quad.object.as_iri() else {
            return (
                ConstructDisposition::Malformed,
                Some("ontology_type_object_not_reference"),
            );
        };
        if object == OWL_NAMED_INDIVIDUAL && quad.subject.as_iri().is_some() {
            return (ConstructDisposition::DeclarationCandidate, None);
        }
        if object == OWL_NAMED_INDIVIDUAL {
            return (
                ConstructDisposition::Malformed,
                Some("ontology_named_individual_subject_not_iri"),
            );
        }
        if is_supported_type(object) || !is_reserved(object) {
            return (ConstructDisposition::ReasonedCandidate, None);
        }
        return (
            ConstructDisposition::Unsupported,
            Some("ontology_reserved_type_unsupported"),
        );
    }
    if is_reference_predicate(&quad.predicate) {
        return if matches!(
            quad.object,
            ExactTerm::Iri(_) | ExactTerm::ScopedBlankNode(_)
        ) {
            (ConstructDisposition::ReasonedCandidate, None)
        } else {
            (
                ConstructDisposition::Malformed,
                Some("ontology_reference_object_required"),
            )
        };
    }
    if matches!(quad.predicate.as_str(), RDF_FIRST | RDF_REST) {
        return if matches!(quad.subject, RdfNodeId::ScopedBlankNode(_))
            && matches!(
                quad.object,
                ExactTerm::Iri(_) | ExactTerm::ScopedBlankNode(_)
            ) {
            (ConstructDisposition::ReasonedCandidate, None)
        } else {
            (
                ConstructDisposition::Malformed,
                Some("ontology_list_member_invalid"),
            )
        };
    }
    if matches!(
        quad.predicate.as_str(),
        OWL_MAX_CARDINALITY | OWL_MAX_QUALIFIED_CARDINALITY
    ) {
        return if cardinality_one(&quad.object) {
            (ConstructDisposition::ReasonedCandidate, None)
        } else {
            (
                ConstructDisposition::Unsupported,
                Some("ontology_cardinality_unsupported"),
            )
        };
    }
    if explicitly_unsupported(&quad.predicate) || is_reserved(&quad.predicate) {
        return (
            ConstructDisposition::Unsupported,
            Some("ontology_reserved_semantic_unsupported"),
        );
    }
    if quad.subject.as_iri().is_none() {
        return (
            ConstructDisposition::Unsupported,
            Some("ontology_blank_application_statement"),
        );
    }
    if quad.subject.as_iri().is_some_and(is_reserved)
        || quad.object.as_iri().is_some_and(is_reserved)
    {
        return (
            ConstructDisposition::Unsupported,
            Some("ontology_reserved_term_unsupported"),
        );
    }
    (ConstructDisposition::ReasonedCandidate, None)
}

struct Validator<'a> {
    closure: &'a AuditedOntologyClosure,
    occurrences: &'a BTreeMap<SourceQuad, Vec<&'a OntologySourceOccurrence>>,
    by_subject: BTreeMap<(String, RdfNodeId), Vec<&'a SourceQuad>>,
    limits: ConstructAuditLimits,
    work: usize,
    issues: Vec<ConstructAuditIssue>,
}

impl<'a> Validator<'a> {
    fn new(
        closure: &'a AuditedOntologyClosure,
        occurrences: &'a BTreeMap<SourceQuad, Vec<&'a OntologySourceOccurrence>>,
        limits: ConstructAuditLimits,
        issues: Vec<ConstructAuditIssue>,
    ) -> Self {
        let mut by_subject: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for quad in &closure.bundle {
            by_subject
                .entry((quad.graph.clone(), quad.subject.clone()))
                .or_default()
                .push(quad);
        }
        Self {
            closure,
            occurrences,
            by_subject,
            limits,
            work: 0,
            issues,
        }
    }

    fn step(&mut self) -> Result<()> {
        self.work = self
            .work
            .checked_add(1)
            .ok_or_else(|| incomplete("structural_work_limit_exceeded"))?;
        if self.work > self.limits.max_structural_work {
            return Err(incomplete("structural_work_limit_exceeded"));
        }
        Ok(())
    }

    fn validate(&mut self) -> Result<()> {
        self.blank_scope()?;
        self.lists()?;
        self.restrictions()?;
        self.expressions()?;
        self.reachability()?;
        Ok(())
    }

    fn report(
        &mut self,
        quad: &SourceQuad,
        class: ConstructDisposition,
        reason: &'static str,
        stage: &'static str,
    ) {
        add_quad_issues(
            &mut self.issues,
            self.occurrences,
            quad,
            class,
            reason,
            stage,
        );
    }

    fn blank_scope(&mut self) -> Result<()> {
        let mut index: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for quad in &self.closure.bundle {
            self.step()?;
            if let RdfNodeId::ScopedBlankNode(label) = &quad.subject {
                index
                    .entry(label.clone())
                    .or_default()
                    .insert(quad.graph.clone());
            }
            if let ExactTerm::ScopedBlankNode(label) = &quad.object {
                index
                    .entry(label.clone())
                    .or_default()
                    .insert(quad.graph.clone());
            }
        }
        for (label, graphs) in index {
            if graphs.len() > 1 {
                for quad in self.closure.bundle.iter().filter(|quad| {
                    matches!(&quad.subject, RdfNodeId::ScopedBlankNode(v) if v == &label)
                        || matches!(&quad.object, ExactTerm::ScopedBlankNode(v) if v == &label)
                }) {
                    self.report(
                        quad,
                        ConstructDisposition::Malformed,
                        "ontology_structural_node_cross_graph",
                        "blank_graph_scope",
                    );
                }
            }
        }
        Ok(())
    }

    fn lists(&mut self) -> Result<()> {
        let heads: Vec<_> = self
            .closure
            .bundle
            .iter()
            .filter(|quad| is_list_head(&quad.predicate))
            .cloned()
            .collect();
        for head in heads {
            self.step()?;
            let ExactTerm::ScopedBlankNode(label) = &head.object else {
                self.report(
                    &head,
                    ConstructDisposition::Malformed,
                    "ontology_list_head_not_blank",
                    "list_shape",
                );
                continue;
            };
            if let Some(members) = self.walk_list(&head, label)? {
                let minimum = if head.predicate == OWL_CHAIN { 2 } else { 1 };
                if members.len() < minimum {
                    self.report(
                        &head,
                        ConstructDisposition::Malformed,
                        "ontology_list_too_short",
                        "list_shape",
                    );
                }
                if head.predicate == OWL_ONE_OF
                    && members
                        .iter()
                        .any(|member| !matches!(member, ExactTerm::Iri(_)))
                {
                    self.report(
                        &head,
                        ConstructDisposition::Unsupported,
                        "ontology_literal_or_anonymous_enumeration_unsupported",
                        "list_members",
                    );
                }
            }
        }
        Ok(())
    }

    fn walk_list(
        &mut self,
        owner: &SourceQuad,
        first_label: &str,
    ) -> Result<Option<Vec<ExactTerm>>> {
        let mut label = first_label.to_owned();
        let mut seen = BTreeSet::new();
        let mut members = Vec::new();
        loop {
            self.step()?;
            if members.len() >= self.limits.max_list_length {
                return Err(incomplete("list_length_limit_exceeded"));
            }
            if !seen.insert(label.clone()) {
                self.report(
                    owner,
                    ConstructDisposition::Malformed,
                    "ontology_list_cycle",
                    "list_shape",
                );
                return Ok(None);
            }
            let key = (
                owner.graph.clone(),
                RdfNodeId::ScopedBlankNode(label.clone()),
            );
            let Some(cell) = self.by_subject.get(&key).cloned() else {
                self.report(
                    owner,
                    ConstructDisposition::Incomplete,
                    "ontology_list_cell_missing",
                    "list_shape",
                );
                return Ok(None);
            };
            let first: Vec<_> = cell
                .iter()
                .filter(|quad| quad.predicate == RDF_FIRST)
                .copied()
                .collect();
            let rest: Vec<_> = cell
                .iter()
                .filter(|quad| quad.predicate == RDF_REST)
                .copied()
                .collect();
            if first.len() != 1 {
                self.report(
                    owner,
                    ConstructDisposition::Malformed,
                    "ontology_list_first_invalid",
                    "list_shape",
                );
                return Ok(None);
            }
            if rest.len() != 1 {
                self.report(
                    owner,
                    ConstructDisposition::Malformed,
                    "ontology_list_rest_invalid",
                    "list_shape",
                );
                return Ok(None);
            }
            if !matches!(
                first[0].object,
                ExactTerm::Iri(_) | ExactTerm::ScopedBlankNode(_)
            ) {
                self.report(
                    first[0],
                    ConstructDisposition::Unsupported,
                    "ontology_list_literal_member_unsupported",
                    "list_members",
                );
            }
            members.push(first[0].object.clone());
            match &rest[0].object {
                ExactTerm::Iri(value) if value == RDF_NIL => return Ok(Some(members)),
                ExactTerm::ScopedBlankNode(next) => label = next.clone(),
                _ => {
                    self.report(
                        rest[0],
                        ConstructDisposition::Malformed,
                        "ontology_list_rest_invalid",
                        "list_shape",
                    );
                    return Ok(None);
                }
            }
        }
    }

    fn restrictions(&mut self) -> Result<()> {
        let facets: Vec<_> = self
            .closure
            .bundle
            .iter()
            .filter(|quad| is_restriction_facet(&quad.predicate))
            .cloned()
            .collect();
        for facet in facets {
            self.step()?;
            let owner = self
                .by_subject
                .get(&(facet.graph.clone(), facet.subject.clone()))
                .cloned()
                .unwrap_or_default();
            let markers = owner
                .iter()
                .filter(|quad| {
                    quad.predicate == RDF_TYPE
                        && quad.object == ExactTerm::Iri(OWL_RESTRICTION.into())
                })
                .count();
            if markers != 1 {
                self.report(
                    &facet,
                    ConstructDisposition::Incomplete,
                    "ontology_restriction_marker_missing",
                    "restriction_ownership",
                );
            }
        }
        let markers: Vec<_> = self
            .closure
            .bundle
            .iter()
            .filter(|quad| {
                quad.predicate == RDF_TYPE && quad.object == ExactTerm::Iri(OWL_RESTRICTION.into())
            })
            .cloned()
            .collect();
        for marker in markers {
            self.step()?;
            let quads = self
                .by_subject
                .get(&(marker.graph.clone(), marker.subject.clone()))
                .cloned()
                .unwrap_or_default();
            let on_properties = quads
                .iter()
                .filter(|quad| quad.predicate == OWL_ON_PROPERTY)
                .copied()
                .collect::<Vec<_>>();
            if on_properties.len() != 1 {
                self.report(
                    &marker,
                    ConstructDisposition::Malformed,
                    "ontology_restriction_on_property_invalid",
                    "restriction_shape",
                );
            } else {
                self.validate_property_term(
                    &marker.graph,
                    &on_properties[0].object,
                    0,
                    on_properties[0],
                )?;
            }
            let kinds = quads
                .iter()
                .filter(|quad| {
                    matches!(
                        quad.predicate.as_str(),
                        OWL_HAS_VALUE
                            | OWL_SOME_VALUES
                            | OWL_ALL_VALUES
                            | OWL_MIN_CARDINALITY
                            | OWL_CARDINALITY
                            | OWL_MAX_CARDINALITY
                            | OWL_MIN_QUALIFIED_CARDINALITY
                            | OWL_QUALIFIED_CARDINALITY
                            | OWL_MAX_QUALIFIED_CARDINALITY
                            | OWL_HAS_SELF
                    )
                })
                .copied()
                .collect::<Vec<_>>();
            if kinds.len() != 1 {
                self.report(
                    &marker,
                    ConstructDisposition::Malformed,
                    "ontology_restriction_kind_ambiguous",
                    "restriction_shape",
                );
                continue;
            }
            match kinds[0].predicate.as_str() {
                OWL_HAS_VALUE => {
                    if !matches!(kinds[0].object, ExactTerm::Iri(_)) {
                        self.report(
                            kinds[0],
                            ConstructDisposition::Unsupported,
                            "ontology_literal_has_value_unsupported",
                            "restriction_shape",
                        );
                    }
                }
                OWL_SOME_VALUES | OWL_ALL_VALUES => {
                    self.validate_class_term(&marker.graph, &kinds[0].object, 0, kinds[0])?;
                }
                OWL_MIN_CARDINALITY | OWL_CARDINALITY | OWL_MAX_CARDINALITY => {
                    if quads.iter().any(|quad| {
                        matches!(quad.predicate.as_str(), OWL_ON_CLASS | OWL_ON_DATA_RANGE)
                    }) {
                        self.report(
                            &marker,
                            ConstructDisposition::Malformed,
                            "ontology_unqualified_cardinality_on_class",
                            "restriction_shape",
                        );
                    }
                }
                OWL_MIN_QUALIFIED_CARDINALITY
                | OWL_QUALIFIED_CARDINALITY
                | OWL_MAX_QUALIFIED_CARDINALITY => {
                    let qualifiers = quads
                        .iter()
                        .filter(|quad| {
                            matches!(quad.predicate.as_str(), OWL_ON_CLASS | OWL_ON_DATA_RANGE)
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    if qualifiers.len() != 1 {
                        self.report(
                            &marker,
                            ConstructDisposition::Malformed,
                            "ontology_qualified_cardinality_on_class_invalid",
                            "restriction_shape",
                        );
                    } else if !matches!(qualifiers[0].object, ExactTerm::Iri(_)) {
                        self.report(
                            qualifiers[0],
                            ConstructDisposition::Unsupported,
                            "ontology_qualified_cardinality_class_unsupported",
                            "restriction_shape",
                        );
                    }
                }
                OWL_HAS_SELF => {}
                _ => unreachable!(),
            }
        }
        Ok(())
    }

    fn expressions(&mut self) -> Result<()> {
        let expressions: Vec<_> = self
            .closure
            .bundle
            .iter()
            .filter(|quad| {
                matches!(
                    quad.predicate.as_str(),
                    OWL_INVERSE | OWL_CHAIN | OWL_INTERSECTION | OWL_UNION | OWL_ONE_OF
                )
            })
            .cloned()
            .collect();
        for expression in expressions {
            self.step()?;
            if expression.predicate == OWL_CHAIN {
                if expression.subject.as_iri().is_none()
                    && !self.closure.bundle.iter().any(|quad| {
                        quad.predicate == OWL_ON_PROPERTY
                            && quad.object
                                == ExactTerm::ScopedBlankNode(
                                    expression.subject.as_source_label().to_owned(),
                                )
                    })
                {
                    self.report(
                        &expression,
                        ConstructDisposition::Malformed,
                        "ontology_orphan_property_expression",
                        "expression_ownership",
                    );
                }
                let ExactTerm::ScopedBlankNode(head) = &expression.object else {
                    self.report(
                        &expression,
                        ConstructDisposition::Malformed,
                        "ontology_property_chain_list_invalid",
                        "expression_shape",
                    );
                    continue;
                };
                if let Some(members) = self.walk_list(&expression, head)? {
                    if members.len() < 2 {
                        self.report(
                            &expression,
                            ConstructDisposition::Malformed,
                            "ontology_property_chain_too_short",
                            "expression_shape",
                        );
                    }
                    for member in members {
                        self.validate_property_term(&expression.graph, &member, 0, &expression)?;
                    }
                }
            } else if matches!(
                expression.predicate.as_str(),
                OWL_INTERSECTION | OWL_UNION | OWL_ONE_OF
            ) {
                let ExactTerm::ScopedBlankNode(head) = &expression.object else {
                    self.report(
                        &expression,
                        ConstructDisposition::Malformed,
                        "ontology_class_expression_list_invalid",
                        "expression_shape",
                    );
                    continue;
                };
                if let Some(members) = self.walk_list(&expression, head)? {
                    for member in members {
                        if expression.predicate == OWL_ONE_OF {
                            if !matches!(member, ExactTerm::Iri(_)) {
                                self.report(
                                    &expression,
                                    ConstructDisposition::Unsupported,
                                    "ontology_literal_one_of_unsupported",
                                    "expression_shape",
                                );
                            }
                        } else {
                            self.validate_class_term(&expression.graph, &member, 0, &expression)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_property_term(
        &mut self,
        graph: &str,
        term: &ExactTerm,
        depth: usize,
        owner: &SourceQuad,
    ) -> Result<()> {
        self.step()?;
        if depth >= self.limits.max_expression_depth {
            return Err(incomplete("expression_depth_limit_exceeded"));
        }
        let ExactTerm::ScopedBlankNode(label) = term else {
            if !matches!(term, ExactTerm::Iri(_)) {
                self.report(
                    owner,
                    ConstructDisposition::Unsupported,
                    "ontology_property_expression_literal",
                    "expression_shape",
                );
            }
            return Ok(());
        };
        let Some(quads) = self
            .by_subject
            .get(&(graph.to_owned(), RdfNodeId::ScopedBlankNode(label.clone())))
            .cloned()
        else {
            self.report(
                owner,
                ConstructDisposition::Incomplete,
                "ontology_property_expression_missing",
                "expression_shape",
            );
            return Ok(());
        };
        let forms = quads
            .iter()
            .filter(|quad| matches!(quad.predicate.as_str(), OWL_INVERSE | OWL_CHAIN))
            .copied()
            .collect::<Vec<_>>();
        if forms.len() != 1 {
            self.report(
                owner,
                ConstructDisposition::Malformed,
                "ontology_property_expression_ambiguous",
                "expression_shape",
            );
            return Ok(());
        }
        if forms[0].predicate == OWL_INVERSE {
            self.validate_property_term(graph, &forms[0].object, depth + 1, owner)
        } else {
            let ExactTerm::ScopedBlankNode(head) = &forms[0].object else {
                self.report(
                    forms[0],
                    ConstructDisposition::Malformed,
                    "ontology_property_chain_list_invalid",
                    "expression_shape",
                );
                return Ok(());
            };
            if let Some(members) = self.walk_list(forms[0], head)? {
                if members.len() < 2 {
                    self.report(
                        forms[0],
                        ConstructDisposition::Malformed,
                        "ontology_property_chain_too_short",
                        "expression_shape",
                    );
                }
                for member in members {
                    self.validate_property_term(graph, &member, depth + 1, owner)?;
                }
            }
            Ok(())
        }
    }

    fn validate_class_term(
        &mut self,
        graph: &str,
        term: &ExactTerm,
        depth: usize,
        owner: &SourceQuad,
    ) -> Result<()> {
        self.step()?;
        if depth >= self.limits.max_expression_depth {
            return Err(incomplete("expression_depth_limit_exceeded"));
        }
        let ExactTerm::ScopedBlankNode(label) = term else {
            if !matches!(term, ExactTerm::Iri(_)) {
                self.report(
                    owner,
                    ConstructDisposition::Unsupported,
                    "ontology_class_expression_literal",
                    "expression_shape",
                );
            }
            return Ok(());
        };
        let Some(quads) = self
            .by_subject
            .get(&(graph.to_owned(), RdfNodeId::ScopedBlankNode(label.clone())))
            .cloned()
        else {
            self.report(
                owner,
                ConstructDisposition::Incomplete,
                "ontology_class_expression_missing",
                "expression_shape",
            );
            return Ok(());
        };
        let is_restriction = quads.iter().any(|quad| {
            quad.predicate == RDF_TYPE && quad.object == ExactTerm::Iri(OWL_RESTRICTION.into())
        });
        let forms = quads
            .iter()
            .filter(|quad| {
                matches!(
                    quad.predicate.as_str(),
                    OWL_INTERSECTION | OWL_UNION | OWL_ONE_OF
                )
            })
            .count();
        if usize::from(is_restriction) + forms != 1 {
            self.report(
                owner,
                ConstructDisposition::Malformed,
                "ontology_class_expression_ambiguous",
                "expression_shape",
            );
        }
        Ok(())
    }

    fn reachability(&mut self) -> Result<()> {
        let nodes: Vec<_> = self
            .by_subject
            .iter()
            .filter(|((_, node), _)| node.as_iri().is_none())
            .map(|(key, quads)| (key.clone(), quads.clone()))
            .collect();
        for ((graph, node), quads) in nodes {
            self.step()?;
            let allowed = quads.iter().all(|quad| {
                quad.predicate == RDF_FIRST
                    || quad.predicate == RDF_REST
                    || quad.predicate == RDF_TYPE
                    || is_structural(&quad.predicate)
            });
            let referenced = self.closure.bundle.iter().any(|quad| matches!((&node, &quad.object), (RdfNodeId::ScopedBlankNode(a), ExactTerm::ScopedBlankNode(b)) if a == b));
            if !allowed || !referenced {
                for quad in quads {
                    self.report(
                        quad,
                        ConstructDisposition::Malformed,
                        "ontology_orphan_or_invalid_structural_node",
                        "structural_reachability",
                    );
                }
            }
            let _ = graph;
        }
        Ok(())
    }
}

fn add_quad_issues(
    issues: &mut Vec<ConstructAuditIssue>,
    occurrences: &BTreeMap<SourceQuad, Vec<&OntologySourceOccurrence>>,
    quad: &SourceQuad,
    class: ConstructDisposition,
    reason: &'static str,
    stage: &'static str,
) {
    if let Some(sources) = occurrences.get(quad) {
        for source in sources {
            issues.push(ConstructAuditIssue {
                source_release_id: source.source_release_id.clone(),
                source_file_id: source.source_file_id.clone(),
                ontology_iri: source.ontology_iri.clone(),
                graph: quad.graph.clone(),
                subject: quad.subject.commitment(),
                predicate: quad.predicate.clone(),
                object: quad.object.commitment(),
                class,
                reason,
                stage,
            });
        }
    }
}

fn bundle_entry_commitment(entry: &ConstructAuditEntry) -> String {
    format!(
        "{:?}\0{}\0{}",
        entry.disposition,
        entry.construct,
        entry.quad.commitment()
    )
}

/// Computes the source-independent classification commitment used by profile v3
/// and by C0 when it reconstructs the exact bundle partition.
pub fn bundle_classification_root_for_partition(
    partition: &BTreeMap<ConstructDisposition, BTreeSet<SourceQuad>>,
) -> ContentHash {
    let mut entries = partition
        .iter()
        .flat_map(|(disposition, quads)| {
            quads.iter().map(move |quad| ConstructAuditEntry {
                quad: quad.clone(),
                disposition: *disposition,
                construct: construct_name(&quad.predicate).to_owned(),
                occurrence_identities: Vec::new(),
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.quad.cmp(&right.quad));
    let values = entries
        .iter()
        .map(bundle_entry_commitment)
        .collect::<Vec<_>>();
    framed_root(
        "ctxql-construct-bundle-classification/v1",
        values.iter().map(|value| ("entry", value.as_str())),
    )
}

fn entry_commitment(entry: &ConstructAuditEntry) -> String {
    let ids = entry
        .occurrence_identities
        .iter()
        .map(ContentHash::as_str)
        .collect::<Vec<_>>()
        .join("\0");
    format!("{}\0{}", bundle_entry_commitment(entry), ids)
}
fn issue_commitment(issue: &ConstructAuditIssue) -> String {
    format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{:?}\0{}\0{}",
        issue.source_release_id,
        issue.source_file_id,
        issue.ontology_iri,
        issue.graph,
        issue.subject,
        issue.predicate,
        issue.object,
        issue.class,
        issue.reason,
        issue.stage
    )
}
fn construct_name(predicate: &str) -> &str {
    predicate
        .rsplit_once(['#', '/'])
        .map_or(predicate, |(_, local)| local)
}
fn is_reserved(value: &str) -> bool {
    value.starts_with(RDF)
        || value.starts_with(RDFS)
        || value.starts_with(OWL)
        || value.starts_with(F)
        || value.starts_with(XSD)
}
fn is_supported_type(value: &str) -> bool {
    matches!(
        value,
        "http://www.w3.org/1999/02/22-rdf-syntax-ns#Property"
            | "http://www.w3.org/2000/01/rdf-schema#Class"
            | "http://www.w3.org/2002/07/owl#Class"
            | "http://www.w3.org/2002/07/owl#Ontology"
            | "http://www.w3.org/2002/07/owl#ObjectProperty"
            | "http://www.w3.org/2002/07/owl#DatatypeProperty"
            | "http://www.w3.org/2002/07/owl#AnnotationProperty"
            | "http://www.w3.org/2002/07/owl#SymmetricProperty"
            | "http://www.w3.org/2002/07/owl#TransitiveProperty"
            | "http://www.w3.org/2002/07/owl#FunctionalProperty"
            | "http://www.w3.org/2002/07/owl#InverseFunctionalProperty"
            | OWL_RESTRICTION
    )
}
fn is_reference_predicate(value: &str) -> bool {
    matches!(
        value,
        "http://www.w3.org/2000/01/rdf-schema#subClassOf"
            | "http://www.w3.org/2000/01/rdf-schema#subPropertyOf"
            | "http://www.w3.org/2000/01/rdf-schema#domain"
            | "http://www.w3.org/2000/01/rdf-schema#range"
            | "http://www.w3.org/2002/07/owl#equivalentClass"
            | "http://www.w3.org/2002/07/owl#sameAs"
            | "http://www.w3.org/2002/07/owl#imports"
            | OWL_INVERSE
            | OWL_CHAIN
            | OWL_KEY
            | OWL_ON_PROPERTY
            | OWL_HAS_VALUE
            | OWL_SOME_VALUES
            | OWL_ALL_VALUES
            | OWL_ON_CLASS
            | OWL_ON_DATA_RANGE
            | OWL_ON_DATATYPE
            | OWL_WITH_RESTRICTIONS
            | OWL_INTERSECTION
            | OWL_UNION
            | OWL_ONE_OF
    )
}
fn is_structural(value: &str) -> bool {
    value.starts_with(XSD)
        || matches!(
            value,
            OWL_INVERSE
                | OWL_CHAIN
                | OWL_KEY
                | OWL_ON_PROPERTY
                | OWL_HAS_VALUE
                | OWL_SOME_VALUES
                | OWL_ALL_VALUES
                | OWL_ON_CLASS
                | OWL_ON_DATA_RANGE
                | OWL_ON_DATATYPE
                | OWL_WITH_RESTRICTIONS
                | OWL_INTERSECTION
                | OWL_UNION
                | OWL_ONE_OF
                | OWL_MIN_CARDINALITY
                | OWL_CARDINALITY
                | OWL_MAX_CARDINALITY
                | OWL_MIN_QUALIFIED_CARDINALITY
                | OWL_QUALIFIED_CARDINALITY
                | OWL_MAX_QUALIFIED_CARDINALITY
                | OWL_HAS_SELF
        )
}
fn is_list_head(value: &str) -> bool {
    matches!(
        value,
        OWL_CHAIN | OWL_KEY | OWL_INTERSECTION | OWL_UNION | OWL_ONE_OF | OWL_WITH_RESTRICTIONS
    )
}
fn is_restriction_facet(value: &str) -> bool {
    matches!(
        value,
        OWL_ON_PROPERTY
            | OWL_HAS_VALUE
            | OWL_SOME_VALUES
            | OWL_ALL_VALUES
            | OWL_MIN_CARDINALITY
            | OWL_CARDINALITY
            | OWL_MAX_CARDINALITY
            | OWL_MIN_QUALIFIED_CARDINALITY
            | OWL_QUALIFIED_CARDINALITY
            | OWL_MAX_QUALIFIED_CARDINALITY
            | OWL_HAS_SELF
            | OWL_ON_CLASS
            | OWL_ON_DATA_RANGE
    )
}
fn explicitly_unsupported(value: &str) -> bool {
    matches!(
        value,
        "http://www.w3.org/2002/07/owl#equivalentProperty"
            | "http://www.w3.org/2002/07/owl#complementOf"
            | "http://www.w3.org/2002/07/owl#disjointWith"
            | "http://www.w3.org/2002/07/owl#differentFrom"
            | OWL_MIN_CARDINALITY
            | OWL_CARDINALITY
            | OWL_MIN_QUALIFIED_CARDINALITY
            | OWL_QUALIFIED_CARDINALITY
            | OWL_HAS_SELF
            | OWL_ON_DATA_RANGE
            | OWL_ON_DATATYPE
            | OWL_WITH_RESTRICTIONS
    )
}
fn is_annotation(value: &str) -> bool {
    matches!(
        value,
        "http://www.w3.org/2000/01/rdf-schema#label"
            | "http://www.w3.org/2000/01/rdf-schema#comment"
            | "http://www.w3.org/2000/01/rdf-schema#seeAlso"
            | "http://www.w3.org/2000/01/rdf-schema#isDefinedBy"
            | "http://www.w3.org/2002/07/owl#versionInfo"
            | "http://www.w3.org/2002/07/owl#versionIRI"
            | "http://www.w3.org/2002/07/owl#priorVersion"
            | "http://www.w3.org/2002/07/owl#backwardCompatibleWith"
            | "http://www.w3.org/2002/07/owl#incompatibleWith"
            | "http://www.w3.org/2002/07/owl#deprecated"
    )
}
fn annotation_shape_valid(quad: &SourceQuad) -> bool {
    match quad.predicate.as_str() {
        "http://www.w3.org/2000/01/rdf-schema#label"
        | "http://www.w3.org/2000/01/rdf-schema#comment" => {
            matches!(quad.object, ExactTerm::Literal { .. })
        }
        "http://www.w3.org/2000/01/rdf-schema#seeAlso"
        | "http://www.w3.org/2000/01/rdf-schema#isDefinedBy"
        | "http://www.w3.org/2002/07/owl#versionIRI"
        | "http://www.w3.org/2002/07/owl#priorVersion"
        | "http://www.w3.org/2002/07/owl#backwardCompatibleWith"
        | "http://www.w3.org/2002/07/owl#incompatibleWith" => {
            matches!(quad.object, ExactTerm::Iri(_))
        }
        "http://www.w3.org/2002/07/owl#versionInfo" => {
            matches!(quad.object, ExactTerm::Iri(_) | ExactTerm::Literal { .. })
        }
        "http://www.w3.org/2002/07/owl#deprecated" => {
            matches!(&quad.object, ExactTerm::Literal { lexical, datatype, language: None } if datatype == "http://www.w3.org/2001/XMLSchema#boolean" && matches!(lexical.as_str(), "true" | "false" | "1" | "0"))
        }
        _ => false,
    }
}
fn cardinality_one(term: &ExactTerm) -> bool {
    let ExactTerm::Literal {
        lexical,
        datatype,
        language: None,
    } = term
    else {
        return false;
    };
    lexical.parse::<i128>() == Ok(1)
        && matches!(
            datatype.as_str(),
            "http://www.w3.org/2001/XMLSchema#integer"
                | "http://www.w3.org/2001/XMLSchema#long"
                | "http://www.w3.org/2001/XMLSchema#int"
                | "http://www.w3.org/2001/XMLSchema#short"
                | "http://www.w3.org/2001/XMLSchema#byte"
                | "http://www.w3.org/2001/XMLSchema#unsignedLong"
                | "http://www.w3.org/2001/XMLSchema#unsignedInt"
                | "http://www.w3.org/2001/XMLSchema#unsignedShort"
                | "http://www.w3.org/2001/XMLSchema#unsignedByte"
                | "http://www.w3.org/2001/XMLSchema#nonNegativeInteger"
                | "http://www.w3.org/2001/XMLSchema#positiveInteger"
        )
}
