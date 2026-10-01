//! Complete, revision-bound structural profile for the pinned direct reasoner.
//!
//! Fluree's materializer deliberately tolerates malformed structures by
//! ignoring them. CTXQL validates the complete authorized bundle first so a
//! successful execution always means the whole executable ontology was used.

use crate::authorized_view::{framed_root, quad_root, ExactTerm, RdfNodeId, SourceQuad};
use cdb_core::id::ContentHash;
use std::collections::{BTreeMap, BTreeSet};

pub const ONTOLOGY_PROFILE_V2_ID: &str =
    "ctxql-ontology-profile/fluree-4.2-603974fad5c13efed9d147d214d613849fb43c73/v2";
pub const STRUCTURAL_MAPPING_ALGORITHM: &str = "ctxql-sandbox-structural-node/sha256-v1";

const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const RDFS: &str = "http://www.w3.org/2000/01/rdf-schema#";
const OWL: &str = "http://www.w3.org/2002/07/owl#";
const F: &str = "https://ns.flur.ee/db#";
const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_FIRST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
const RDF_REST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
const RDF_NIL: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";
const OWL_RESTRICTION: &str = "http://www.w3.org/2002/07/owl#Restriction";
const OWL_INVERSE: &str = "http://www.w3.org/2002/07/owl#inverseOf";
const OWL_CHAIN: &str = "http://www.w3.org/2002/07/owl#propertyChainAxiom";
const OWL_KEY: &str = "http://www.w3.org/2002/07/owl#hasKey";
const OWL_ON_PROPERTY: &str = "http://www.w3.org/2002/07/owl#onProperty";
const OWL_HAS_VALUE: &str = "http://www.w3.org/2002/07/owl#hasValue";
const OWL_SOME_VALUES: &str = "http://www.w3.org/2002/07/owl#someValuesFrom";
const OWL_ALL_VALUES: &str = "http://www.w3.org/2002/07/owl#allValuesFrom";
const OWL_MAX_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#maxCardinality";
const OWL_MAX_QUALIFIED_CARDINALITY: &str = "http://www.w3.org/2002/07/owl#maxQualifiedCardinality";
const OWL_ON_CLASS: &str = "http://www.w3.org/2002/07/owl#onClass";
const OWL_INTERSECTION: &str = "http://www.w3.org/2002/07/owl#intersectionOf";
const OWL_UNION: &str = "http://www.w3.org/2002/07/owl#unionOf";
const OWL_ONE_OF: &str = "http://www.w3.org/2002/07/owl#oneOf";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OntologyProfileLimits {
    pub max_bundle_quads: usize,
    pub max_list_length: usize,
    pub max_expression_depth: usize,
    pub max_diagnostics: usize,
}

impl Default for OntologyProfileLimits {
    fn default() -> Self {
        Self {
            max_bundle_quads: 100_000,
            max_list_length: 10_000,
            max_expression_depth: 10,
            max_diagnostics: 128,
        }
    }
}

impl OntologyProfileLimits {
    pub fn identity(&self) -> ContentHash {
        ContentHash::of_bytes(
            format!(
                "ctxql-ontology-profile-limits/v2;quads={};list={};depth={};diagnostics={}",
                self.max_bundle_quads,
                self.max_list_length,
                self.max_expression_depth,
                self.max_diagnostics
            )
            .as_bytes(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OntologyIssueClass {
    Unsupported,
    Malformed,
    Incomplete,
    Limit,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OntologyIssue {
    pub class: OntologyIssueClass,
    pub reason: &'static str,
    pub graph: Option<String>,
    pub predicate: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReasonerProjection {
    pub quads: BTreeSet<SourceQuad>,
    pub root: ContentHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologyProfileV2Result {
    pub identity: &'static str,
    pub full_bundle: BTreeSet<SourceQuad>,
    pub harmless: BTreeSet<SourceQuad>,
    pub construct_counts: BTreeMap<String, usize>,
    pub reasoner_projection: ReasonerProjection,
    pub full_bundle_root: ContentHash,
    pub result_root: ContentHash,
    pub limits_identity: ContentHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OntologyProfileFailure {
    pub public_code: &'static str,
    pub issues: Vec<OntologyIssue>,
}

impl std::fmt::Display for OntologyProfileFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.public_code)
    }
}

impl std::error::Error for OntologyProfileFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemberClass {
    Premise,
    Structural,
    Harmless,
}

type NodeKey = (String, RdfNodeId);

pub fn classify_ontology_bundle_v2(
    bundle: &BTreeSet<SourceQuad>,
    limits: OntologyProfileLimits,
) -> Result<OntologyProfileV2Result, String> {
    analyze_ontology_bundle_v2(bundle, limits).map_err(|failure| failure.public_code.into())
}

pub fn analyze_ontology_bundle_v2(
    bundle: &BTreeSet<SourceQuad>,
    limits: OntologyProfileLimits,
) -> Result<OntologyProfileV2Result, OntologyProfileFailure> {
    if bundle.len() > limits.max_bundle_quads {
        return Err(failure(
            OntologyIssueClass::Limit,
            "ontology_bundle_limit_exceeded",
            None,
        ));
    }

    let mut harmless = BTreeSet::new();
    let mut projection = BTreeSet::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for quad in bundle {
        let class = classify_member(quad)?;
        match class {
            MemberClass::Harmless => {
                harmless.insert(quad.clone());
            }
            MemberClass::Premise | MemberClass::Structural => {
                projection.insert(quad.clone());
                *counts
                    .entry(construct_name(&quad.predicate).into())
                    .or_insert(0) += 1;
            }
        }
    }

    let by_subject = subject_index(bundle);
    let blank_graphs = blank_graph_index(bundle);
    validate_blank_graph_scope(&blank_graphs)?;
    validate_lists(bundle, &by_subject, &limits)?;
    validate_restriction_ownership(bundle, &by_subject)?;
    validate_restrictions(bundle, &by_subject, &limits)?;
    validate_property_expressions(bundle, &by_subject, &limits)?;
    validate_class_expressions(bundle, &by_subject, &limits)?;
    validate_structural_reachability(bundle, &by_subject)?;

    let full_bundle_root = quad_root(bundle);
    let reasoner_root = quad_root(&projection);
    let harmless_root = quad_root(&harmless);
    let limits_identity = limits.identity();
    let count_commitment = counts
        .iter()
        .map(|(name, count)| format!("{}:{name}:{count}", name.len()))
        .collect::<Vec<_>>()
        .join("\0");
    let result_root = framed_root(
        "ctxql-ontology-profile-result/v2",
        [
            ("profile", ONTOLOGY_PROFILE_V2_ID),
            ("full-bundle", full_bundle_root.as_str()),
            ("reasoner-projection", reasoner_root.as_str()),
            ("harmless", harmless_root.as_str()),
            ("limits", limits_identity.as_str()),
            ("counts", count_commitment.as_str()),
        ],
    );
    Ok(OntologyProfileV2Result {
        identity: ONTOLOGY_PROFILE_V2_ID,
        full_bundle: bundle.clone(),
        harmless,
        construct_counts: counts,
        reasoner_projection: ReasonerProjection {
            quads: projection,
            root: reasoner_root,
        },
        full_bundle_root,
        result_root,
        limits_identity,
    })
}

fn classify_member(quad: &SourceQuad) -> Result<MemberClass, OntologyProfileFailure> {
    if is_harmless_predicate(&quad.predicate) {
        validate_harmless_shape(quad)?;
        return Ok(MemberClass::Harmless);
    }
    if quad.predicate == RDF_TYPE {
        let Some(object) = quad.object.as_iri() else {
            return Err(issue_for(
                OntologyIssueClass::Malformed,
                "ontology_type_object_not_reference",
                quad,
            ));
        };
        return if is_supported_type(object) || !is_reserved(object) {
            Ok(if is_declaration_type(object) {
                MemberClass::Structural
            } else {
                MemberClass::Premise
            })
        } else {
            Err(issue_for(
                OntologyIssueClass::Unsupported,
                "ontology_reserved_type_unsupported",
                quad,
            ))
        };
    }
    if is_supported_reference_predicate(&quad.predicate) {
        if !matches!(
            quad.object,
            ExactTerm::Iri(_) | ExactTerm::ScopedBlankNode(_)
        ) {
            return Err(issue_for(
                OntologyIssueClass::Malformed,
                "ontology_reference_object_required",
                quad,
            ));
        }
        return Ok(if is_structural_predicate(&quad.predicate) {
            MemberClass::Structural
        } else {
            MemberClass::Premise
        });
    }
    if matches!(quad.predicate.as_str(), RDF_FIRST | RDF_REST) {
        if !matches!(quad.subject, RdfNodeId::ScopedBlankNode(_))
            || !matches!(
                quad.object,
                ExactTerm::Iri(_) | ExactTerm::ScopedBlankNode(_)
            )
        {
            return Err(issue_for(
                OntologyIssueClass::Malformed,
                "ontology_list_member_invalid",
                quad,
            ));
        }
        return Ok(MemberClass::Structural);
    }
    if matches!(
        quad.predicate.as_str(),
        OWL_MAX_CARDINALITY | OWL_MAX_QUALIFIED_CARDINALITY
    ) {
        if !is_exact_cardinality_one(&quad.object) {
            return Err(issue_for(
                OntologyIssueClass::Unsupported,
                "ontology_cardinality_unsupported",
                quad,
            ));
        }
        return Ok(MemberClass::Structural);
    }
    if is_explicitly_unsupported(&quad.predicate) || is_reserved(&quad.predicate) {
        return Err(issue_for(
            OntologyIssueClass::Unsupported,
            "ontology_reserved_semantic_unsupported",
            quad,
        ));
    }
    if quad.subject.as_iri().is_none() {
        return Err(issue_for(
            OntologyIssueClass::Unsupported,
            "ontology_blank_application_statement",
            quad,
        ));
    }
    if quad.object.as_iri().is_some_and(is_reserved)
        || quad.subject.as_iri().is_some_and(is_reserved)
    {
        return Err(issue_for(
            OntologyIssueClass::Unsupported,
            "ontology_reserved_term_unsupported",
            quad,
        ));
    }
    Ok(MemberClass::Premise)
}

fn subject_index(bundle: &BTreeSet<SourceQuad>) -> BTreeMap<NodeKey, Vec<&SourceQuad>> {
    let mut index = BTreeMap::new();
    for quad in bundle {
        index
            .entry((quad.graph.clone(), quad.subject.clone()))
            .or_insert_with(Vec::new)
            .push(quad);
    }
    index
}

fn blank_graph_index(bundle: &BTreeSet<SourceQuad>) -> BTreeMap<String, BTreeSet<String>> {
    let mut graphs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for quad in bundle {
        if let RdfNodeId::ScopedBlankNode(label) = &quad.subject {
            graphs
                .entry(label.clone())
                .or_default()
                .insert(quad.graph.clone());
        }
        if let ExactTerm::ScopedBlankNode(label) = &quad.object {
            graphs
                .entry(label.clone())
                .or_default()
                .insert(quad.graph.clone());
        }
    }
    graphs
}

fn validate_blank_graph_scope(
    index: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), OntologyProfileFailure> {
    if index.values().any(|graphs| graphs.len() != 1) {
        return Err(failure(
            OntologyIssueClass::Malformed,
            "ontology_structural_node_cross_graph",
            None,
        ));
    }
    Ok(())
}

fn validate_lists(
    bundle: &BTreeSet<SourceQuad>,
    index: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
    limits: &OntologyProfileLimits,
) -> Result<(), OntologyProfileFailure> {
    for head in bundle
        .iter()
        .filter(|quad| is_list_head_predicate(&quad.predicate))
    {
        let ExactTerm::ScopedBlankNode(label) = &head.object else {
            return Err(issue_for(
                OntologyIssueClass::Malformed,
                "ontology_list_head_not_blank",
                head,
            ));
        };
        let members = traverse_list(&head.graph, label, index, limits)?;
        let minimum = if head.predicate == OWL_CHAIN { 2 } else { 1 };
        if members.len() < minimum {
            return Err(issue_for(
                OntologyIssueClass::Malformed,
                "ontology_list_too_short",
                head,
            ));
        }
        if head.predicate == OWL_ONE_OF
            && members
                .iter()
                .any(|member| !matches!(member, ExactTerm::Iri(_)))
        {
            return Err(issue_for(
                OntologyIssueClass::Unsupported,
                "ontology_literal_or_anonymous_enumeration_unsupported",
                head,
            ));
        }
    }
    Ok(())
}

fn traverse_list(
    graph: &str,
    head: &str,
    index: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
    limits: &OntologyProfileLimits,
) -> Result<Vec<ExactTerm>, OntologyProfileFailure> {
    let mut current = head.to_owned();
    let mut seen = BTreeSet::new();
    let mut members = Vec::new();
    loop {
        if members.len() >= limits.max_list_length {
            return Err(failure(
                OntologyIssueClass::Limit,
                "ontology_list_limit_exceeded",
                Some(graph),
            ));
        }
        if !seen.insert(current.clone()) {
            return Err(failure(
                OntologyIssueClass::Malformed,
                "ontology_list_cycle",
                Some(graph),
            ));
        }
        let node = RdfNodeId::ScopedBlankNode(current.clone());
        let quads = index.get(&(graph.to_owned(), node)).ok_or_else(|| {
            failure(
                OntologyIssueClass::Incomplete,
                "ontology_list_cell_missing",
                Some(graph),
            )
        })?;
        let first = exact_one(quads, RDF_FIRST, "ontology_list_first_invalid", graph)?;
        let rest = exact_one(quads, RDF_REST, "ontology_list_rest_invalid", graph)?;
        if !matches!(
            first.object,
            ExactTerm::Iri(_) | ExactTerm::ScopedBlankNode(_)
        ) {
            return Err(issue_for(
                OntologyIssueClass::Unsupported,
                "ontology_list_literal_member_unsupported",
                first,
            ));
        }
        members.push(first.object.clone());
        match &rest.object {
            ExactTerm::Iri(value) if value == RDF_NIL => break,
            ExactTerm::ScopedBlankNode(next) => current = next.clone(),
            _ => {
                return Err(issue_for(
                    OntologyIssueClass::Malformed,
                    "ontology_list_rest_invalid",
                    rest,
                ))
            }
        }
    }
    Ok(members)
}

fn validate_restriction_ownership(
    bundle: &BTreeSet<SourceQuad>,
    index: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
) -> Result<(), OntologyProfileFailure> {
    for facet in bundle.iter().filter(|quad| {
        matches!(
            quad.predicate.as_str(),
            OWL_ON_PROPERTY
                | OWL_HAS_VALUE
                | OWL_SOME_VALUES
                | OWL_ALL_VALUES
                | OWL_MAX_CARDINALITY
                | OWL_MAX_QUALIFIED_CARDINALITY
                | OWL_ON_CLASS
        )
    }) {
        let Some(quads) = index.get(&(facet.graph.clone(), facet.subject.clone())) else {
            return Err(issue_for(
                OntologyIssueClass::Incomplete,
                "ontology_restriction_owner_missing",
                facet,
            ));
        };
        let markers = quads
            .iter()
            .filter(|quad| {
                quad.predicate == RDF_TYPE && quad.object == ExactTerm::Iri(OWL_RESTRICTION.into())
            })
            .count();
        if markers != 1 {
            return Err(issue_for(
                OntologyIssueClass::Incomplete,
                "ontology_restriction_marker_missing",
                facet,
            ));
        }
    }
    Ok(())
}

fn validate_restrictions(
    bundle: &BTreeSet<SourceQuad>,
    index: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
    limits: &OntologyProfileLimits,
) -> Result<(), OntologyProfileFailure> {
    for marker in bundle.iter().filter(|quad| {
        quad.predicate == RDF_TYPE && quad.object == ExactTerm::Iri(OWL_RESTRICTION.into())
    }) {
        let quads = index
            .get(&(marker.graph.clone(), marker.subject.clone()))
            .expect("marker is indexed");
        let on_property = exact_one(
            quads,
            OWL_ON_PROPERTY,
            "ontology_restriction_on_property_invalid",
            &marker.graph,
        )?;
        let kinds = [
            OWL_HAS_VALUE,
            OWL_SOME_VALUES,
            OWL_ALL_VALUES,
            OWL_MAX_CARDINALITY,
            OWL_MAX_QUALIFIED_CARDINALITY,
        ];
        let present = quads
            .iter()
            .filter(|quad| kinds.contains(&quad.predicate.as_str()))
            .copied()
            .collect::<Vec<_>>();
        if present.len() != 1 {
            return Err(issue_for(
                OntologyIssueClass::Malformed,
                "ontology_restriction_kind_ambiguous",
                marker,
            ));
        }
        validate_property_term(&marker.graph, &on_property.object, index, limits, 0)?;
        match present[0].predicate.as_str() {
            OWL_HAS_VALUE => {
                if !matches!(present[0].object, ExactTerm::Iri(_)) {
                    return Err(issue_for(
                        OntologyIssueClass::Unsupported,
                        "ontology_literal_has_value_unsupported",
                        present[0],
                    ));
                }
            }
            OWL_SOME_VALUES | OWL_ALL_VALUES => {
                validate_class_term(&marker.graph, &present[0].object, index, limits, 0)?;
            }
            OWL_MAX_CARDINALITY => {
                if quads.iter().any(|quad| quad.predicate == OWL_ON_CLASS) {
                    return Err(issue_for(
                        OntologyIssueClass::Malformed,
                        "ontology_unqualified_cardinality_on_class",
                        marker,
                    ));
                }
            }
            OWL_MAX_QUALIFIED_CARDINALITY => {
                let on_class = exact_one(
                    quads,
                    OWL_ON_CLASS,
                    "ontology_qualified_cardinality_on_class_invalid",
                    &marker.graph,
                )?;
                if !matches!(on_class.object, ExactTerm::Iri(_)) {
                    return Err(issue_for(
                        OntologyIssueClass::Unsupported,
                        "ontology_qualified_cardinality_class_unsupported",
                        on_class,
                    ));
                }
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}

fn validate_property_expressions(
    bundle: &BTreeSet<SourceQuad>,
    index: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
    limits: &OntologyProfileLimits,
) -> Result<(), OntologyProfileFailure> {
    for quad in bundle.iter().filter(|quad| quad.predicate == OWL_CHAIN) {
        if quad.subject.as_iri().is_none()
            && !is_referenced_as_object(bundle, &quad.subject, OWL_ON_PROPERTY)
        {
            return Err(issue_for(
                OntologyIssueClass::Malformed,
                "ontology_orphan_property_expression",
                quad,
            ));
        }
        let ExactTerm::ScopedBlankNode(head) = &quad.object else {
            return Err(issue_for(
                OntologyIssueClass::Malformed,
                "ontology_property_chain_list_invalid",
                quad,
            ));
        };
        for member in traverse_list(&quad.graph, head, index, limits)? {
            validate_property_term(&quad.graph, &member, index, limits, 0)?;
        }
    }
    Ok(())
}

fn validate_class_expressions(
    bundle: &BTreeSet<SourceQuad>,
    index: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
    limits: &OntologyProfileLimits,
) -> Result<(), OntologyProfileFailure> {
    for quad in bundle.iter().filter(|quad| {
        matches!(
            quad.predicate.as_str(),
            OWL_INTERSECTION | OWL_UNION | OWL_ONE_OF
        )
    }) {
        let ExactTerm::ScopedBlankNode(head) = &quad.object else {
            return Err(issue_for(
                OntologyIssueClass::Malformed,
                "ontology_class_expression_list_invalid",
                quad,
            ));
        };
        let members = traverse_list(&quad.graph, head, index, limits)?;
        for member in members {
            if quad.predicate == OWL_ONE_OF {
                if !matches!(member, ExactTerm::Iri(_)) {
                    return Err(issue_for(
                        OntologyIssueClass::Unsupported,
                        "ontology_literal_one_of_unsupported",
                        quad,
                    ));
                }
            } else {
                validate_class_term(&quad.graph, &member, index, limits, 0)?;
            }
        }
    }
    Ok(())
}

fn validate_property_term(
    graph: &str,
    term: &ExactTerm,
    index: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
    limits: &OntologyProfileLimits,
    depth: usize,
) -> Result<(), OntologyProfileFailure> {
    if depth >= limits.max_expression_depth {
        return Err(failure(
            OntologyIssueClass::Limit,
            "ontology_expression_depth_exceeded",
            Some(graph),
        ));
    }
    let ExactTerm::ScopedBlankNode(label) = term else {
        return if matches!(term, ExactTerm::Iri(_)) {
            Ok(())
        } else {
            Err(failure(
                OntologyIssueClass::Unsupported,
                "ontology_property_expression_literal",
                Some(graph),
            ))
        };
    };
    let quads = index
        .get(&(graph.to_owned(), RdfNodeId::ScopedBlankNode(label.clone())))
        .ok_or_else(|| {
            failure(
                OntologyIssueClass::Incomplete,
                "ontology_property_expression_missing",
                Some(graph),
            )
        })?;
    let forms = quads
        .iter()
        .filter(|quad| matches!(quad.predicate.as_str(), OWL_INVERSE | OWL_CHAIN))
        .copied()
        .collect::<Vec<_>>();
    if forms.len() != 1 {
        return Err(failure(
            OntologyIssueClass::Malformed,
            "ontology_property_expression_ambiguous",
            Some(graph),
        ));
    }
    if forms[0].predicate == OWL_INVERSE {
        validate_property_term(graph, &forms[0].object, index, limits, depth + 1)
    } else {
        let ExactTerm::ScopedBlankNode(head) = &forms[0].object else {
            return Err(issue_for(
                OntologyIssueClass::Malformed,
                "ontology_property_chain_list_invalid",
                forms[0],
            ));
        };
        let members = traverse_list(graph, head, index, limits)?;
        if members.len() < 2 {
            return Err(issue_for(
                OntologyIssueClass::Malformed,
                "ontology_property_chain_too_short",
                forms[0],
            ));
        }
        for member in members {
            validate_property_term(graph, &member, index, limits, depth + 1)?;
        }
        Ok(())
    }
}

fn validate_class_term(
    graph: &str,
    term: &ExactTerm,
    index: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
    limits: &OntologyProfileLimits,
    depth: usize,
) -> Result<(), OntologyProfileFailure> {
    if depth >= limits.max_expression_depth {
        return Err(failure(
            OntologyIssueClass::Limit,
            "ontology_expression_depth_exceeded",
            Some(graph),
        ));
    }
    let ExactTerm::ScopedBlankNode(label) = term else {
        return if matches!(term, ExactTerm::Iri(_)) {
            Ok(())
        } else {
            Err(failure(
                OntologyIssueClass::Unsupported,
                "ontology_class_expression_literal",
                Some(graph),
            ))
        };
    };
    let quads = index
        .get(&(graph.to_owned(), RdfNodeId::ScopedBlankNode(label.clone())))
        .ok_or_else(|| {
            failure(
                OntologyIssueClass::Incomplete,
                "ontology_class_expression_missing",
                Some(graph),
            )
        })?;
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
        return Err(failure(
            OntologyIssueClass::Malformed,
            "ontology_class_expression_ambiguous",
            Some(graph),
        ));
    }
    Ok(())
}

fn validate_structural_reachability(
    bundle: &BTreeSet<SourceQuad>,
    index: &BTreeMap<NodeKey, Vec<&SourceQuad>>,
) -> Result<(), OntologyProfileFailure> {
    for ((graph, node), quads) in index {
        if node.as_iri().is_some() {
            continue;
        }
        let allowed = quads.iter().all(|quad| {
            quad.predicate == RDF_FIRST
                || quad.predicate == RDF_REST
                || quad.predicate == RDF_TYPE
                || is_structural_predicate(&quad.predicate)
        });
        if !allowed || !is_referenced_anywhere(bundle, node) {
            return Err(failure(
                OntologyIssueClass::Malformed,
                "ontology_orphan_or_invalid_structural_node",
                Some(graph),
            ));
        }
    }
    Ok(())
}

fn exact_one<'a>(
    quads: &'a [&SourceQuad],
    predicate: &str,
    reason: &'static str,
    graph: &str,
) -> Result<&'a SourceQuad, OntologyProfileFailure> {
    let matches = quads
        .iter()
        .filter(|quad| quad.predicate == predicate)
        .copied()
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err(failure(OntologyIssueClass::Malformed, reason, Some(graph)))
    }
}

fn is_referenced_anywhere(bundle: &BTreeSet<SourceQuad>, node: &RdfNodeId) -> bool {
    let RdfNodeId::ScopedBlankNode(label) = node else {
        return true;
    };
    bundle
        .iter()
        .any(|quad| matches!(&quad.object, ExactTerm::ScopedBlankNode(value) if value == label))
}

fn is_referenced_as_object(
    bundle: &BTreeSet<SourceQuad>,
    node: &RdfNodeId,
    predicate: &str,
) -> bool {
    let RdfNodeId::ScopedBlankNode(label) = node else {
        return false;
    };
    bundle.iter().any(|quad| {
        quad.predicate == predicate
            && matches!(&quad.object, ExactTerm::ScopedBlankNode(value) if value == label)
    })
}

fn is_exact_cardinality_one(term: &ExactTerm) -> bool {
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

fn is_supported_reference_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        "http://www.w3.org/2000/01/rdf-schema#subClassOf"
            | "http://www.w3.org/2000/01/rdf-schema#subPropertyOf"
            | "http://www.w3.org/2000/01/rdf-schema#domain"
            | "http://www.w3.org/2000/01/rdf-schema#range"
            | OWL_INVERSE
            | "http://www.w3.org/2002/07/owl#equivalentClass"
            | "http://www.w3.org/2002/07/owl#sameAs"
            | "http://www.w3.org/2002/07/owl#imports"
            | OWL_CHAIN
            | OWL_KEY
            | OWL_ON_PROPERTY
            | OWL_HAS_VALUE
            | OWL_SOME_VALUES
            | OWL_ALL_VALUES
            | OWL_ON_CLASS
            | OWL_INTERSECTION
            | OWL_UNION
            | OWL_ONE_OF
    )
}

fn is_structural_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        OWL_CHAIN
            | OWL_KEY
            | OWL_ON_PROPERTY
            | OWL_HAS_VALUE
            | OWL_SOME_VALUES
            | OWL_ALL_VALUES
            | OWL_ON_CLASS
            | OWL_INTERSECTION
            | OWL_UNION
            | OWL_ONE_OF
            | OWL_INVERSE
            | OWL_MAX_CARDINALITY
            | OWL_MAX_QUALIFIED_CARDINALITY
    )
}

fn is_list_head_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        OWL_CHAIN | OWL_KEY | OWL_INTERSECTION | OWL_UNION | OWL_ONE_OF
    )
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

fn is_declaration_type(value: &str) -> bool {
    matches!(
        value,
        "http://www.w3.org/1999/02/22-rdf-syntax-ns#Property"
            | "http://www.w3.org/2000/01/rdf-schema#Class"
            | "http://www.w3.org/2002/07/owl#Class"
            | "http://www.w3.org/2002/07/owl#Ontology"
            | "http://www.w3.org/2002/07/owl#ObjectProperty"
            | "http://www.w3.org/2002/07/owl#DatatypeProperty"
            | "http://www.w3.org/2002/07/owl#AnnotationProperty"
            | OWL_RESTRICTION
    )
}

fn validate_harmless_shape(quad: &SourceQuad) -> Result<(), OntologyProfileFailure> {
    let valid = match quad.predicate.as_str() {
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
        "http://www.w3.org/2002/07/owl#deprecated" => matches!(
            &quad.object,
            ExactTerm::Literal {
                lexical,
                datatype,
                language: None,
            } if datatype == "http://www.w3.org/2001/XMLSchema#boolean"
                && matches!(lexical.as_str(), "true" | "false" | "1" | "0")
        ),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(issue_for(
            OntologyIssueClass::Malformed,
            "ontology_metadata_object_invalid",
            quad,
        ))
    }
}

fn is_harmless_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
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

fn is_explicitly_unsupported(predicate: &str) -> bool {
    matches!(
        predicate,
        "http://www.w3.org/2002/07/owl#equivalentProperty"
            | "http://www.w3.org/2002/07/owl#complementOf"
            | "http://www.w3.org/2002/07/owl#disjointWith"
            | "http://www.w3.org/2002/07/owl#differentFrom"
            | "http://www.w3.org/2002/07/owl#minCardinality"
            | "http://www.w3.org/2002/07/owl#cardinality"
            | "http://www.w3.org/2002/07/owl#minQualifiedCardinality"
            | "http://www.w3.org/2002/07/owl#qualifiedCardinality"
    )
}

fn is_reserved(value: &str) -> bool {
    value.starts_with(RDF)
        || value.starts_with(RDFS)
        || value.starts_with(OWL)
        || value.starts_with(F)
        || value.starts_with(XSD)
}

fn construct_name(predicate: &str) -> &str {
    predicate
        .rsplit_once(['#', '/'])
        .map_or(predicate, |(_, local)| local)
}

fn issue_for(
    class: OntologyIssueClass,
    reason: &'static str,
    quad: &SourceQuad,
) -> OntologyProfileFailure {
    OntologyProfileFailure {
        public_code: public_code(class),
        issues: vec![OntologyIssue {
            class,
            reason,
            graph: Some(quad.graph.clone()),
            predicate: Some(quad.predicate.clone()),
        }],
    }
}

fn failure(
    class: OntologyIssueClass,
    reason: &'static str,
    graph: Option<&str>,
) -> OntologyProfileFailure {
    OntologyProfileFailure {
        public_code: public_code(class),
        issues: vec![OntologyIssue {
            class,
            reason,
            graph: graph.map(str::to_owned),
            predicate: None,
        }],
    }
}

fn public_code(class: OntologyIssueClass) -> &'static str {
    match class {
        OntologyIssueClass::Unsupported => "ontology_profile_unsupported",
        OntologyIssueClass::Malformed | OntologyIssueClass::Incomplete => {
            "ontology_configuration_invalid"
        }
        OntologyIssueClass::Limit => "ontology_profile_limit_exceeded",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iri(value: &str) -> RdfNodeId {
        RdfNodeId::Iri(value.into())
    }

    fn bnode(value: &str) -> RdfNodeId {
        RdfNodeId::ScopedBlankNode(value.into())
    }

    fn q(subject: RdfNodeId, predicate: &str, object: ExactTerm) -> SourceQuad {
        SourceQuad {
            graph: "urn:graph:schema".into(),
            subject,
            predicate: predicate.into(),
            object,
        }
    }

    #[test]
    fn accepts_a_complete_property_chain_and_rejects_a_cycle() {
        let mut bundle = BTreeSet::from([
            q(
                iri("urn:p:ancestor"),
                OWL_CHAIN,
                ExactTerm::ScopedBlankNode("_:fdb-list-1".into()),
            ),
            q(
                bnode("_:fdb-list-1"),
                RDF_FIRST,
                ExactTerm::Iri("urn:p:parent".into()),
            ),
            q(
                bnode("_:fdb-list-1"),
                RDF_REST,
                ExactTerm::ScopedBlankNode("_:fdb-list-2".into()),
            ),
            q(
                bnode("_:fdb-list-2"),
                RDF_FIRST,
                ExactTerm::Iri("urn:p:parent".into()),
            ),
            q(
                bnode("_:fdb-list-2"),
                RDF_REST,
                ExactTerm::Iri(RDF_NIL.into()),
            ),
        ]);
        assert!(analyze_ontology_bundle_v2(&bundle, OntologyProfileLimits::default()).is_ok());
        bundle.remove(&q(
            bnode("_:fdb-list-2"),
            RDF_REST,
            ExactTerm::Iri(RDF_NIL.into()),
        ));
        bundle.insert(q(
            bnode("_:fdb-list-2"),
            RDF_REST,
            ExactTerm::ScopedBlankNode("_:fdb-list-1".into()),
        ));
        let error = analyze_ontology_bundle_v2(&bundle, OntologyProfileLimits::default())
            .expect_err("cyclic list must fail");
        assert_eq!(error.public_code, "ontology_configuration_invalid");
        assert_eq!(error.issues[0].reason, "ontology_list_cycle");
    }

    #[test]
    fn harmless_metadata_changes_the_full_root_but_not_reasoner_projection() {
        let base = BTreeSet::from([q(
            iri("urn:C"),
            "http://www.w3.org/2000/01/rdf-schema#subClassOf",
            ExactTerm::Iri("urn:D".into()),
        )]);
        let mut annotated = base.clone();
        annotated.insert(q(
            iri("urn:C"),
            "http://www.w3.org/2000/01/rdf-schema#label",
            ExactTerm::Literal {
                lexical: "C".into(),
                datatype: format!("{XSD}string"),
                language: None,
            },
        ));
        let left = analyze_ontology_bundle_v2(&base, OntologyProfileLimits::default()).unwrap();
        let right =
            analyze_ontology_bundle_v2(&annotated, OntologyProfileLimits::default()).unwrap();
        assert_ne!(left.full_bundle_root, right.full_bundle_root);
        assert_eq!(
            left.reasoner_projection.root,
            right.reasoner_projection.root
        );
    }

    #[test]
    fn rejects_equivalent_property_and_non_one_cardinality() {
        let equivalent = BTreeSet::from([q(
            iri("urn:p"),
            "http://www.w3.org/2002/07/owl#equivalentProperty",
            ExactTerm::Iri("urn:q".into()),
        )]);
        assert_eq!(
            analyze_ontology_bundle_v2(&equivalent, OntologyProfileLimits::default())
                .unwrap_err()
                .public_code,
            "ontology_profile_unsupported"
        );

        let cardinality = BTreeSet::from([q(
            bnode("_:fdb-r"),
            OWL_MAX_CARDINALITY,
            ExactTerm::Literal {
                lexical: "2".into(),
                datatype: format!("{XSD}nonNegativeInteger"),
                language: None,
            },
        )]);
        assert_eq!(
            analyze_ontology_bundle_v2(&cardinality, OntologyProfileLimits::default())
                .unwrap_err()
                .public_code,
            "ontology_profile_unsupported"
        );
    }
}
