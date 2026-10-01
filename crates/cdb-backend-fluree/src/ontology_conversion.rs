//! Bounded, deterministic RDF/XML to Fluree-compatible N-Triples conversion.
//!
//! The converter is deliberately pure: it has no filesystem, cache, import,
//! repair, or network surface. `owl:imports` values are ordinary preserved
//! triples; resolving them belongs to the separately sealed dependency universe.

use crate::authorized_view::{framed_root, quad_root, ExactTerm, RdfNodeId, SourceQuad};
use cdb_core::id::ContentHash;
use oxrdf::{NamedOrBlankNode, Term};
use oxrdfxml::RdfXmlParser;
use quick_xml::{events::Event, Reader};
use std::collections::{BTreeMap, BTreeSet};

pub const CONVERTER_ID: &str = "ctxql-rdfxml-conversion/v1";
pub const PARSER_ID: &str = "oxrdfxml/0.2.4;oxrdf/0.3.4";
pub const PARSER_OPTIONS: &str =
    "rdf-1.1;strict;caller-base-iri;no-rdf-12;external-entities-forbidden;bounded-simple-internal-entities";
pub const BLANK_NODE_ALGORITHM: &str =
    "ctxql-graph-scoped-structural-refinement-bounded-tie-permutation/v2";

/// Canonical result used to compare source-derived ontology quads with native
/// ledger readback without depending on either parser or database blank labels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuralQuadCommitment {
    pub root: ContentHash,
    pub quad_count: usize,
    pub blank_node_count: usize,
    pub canonicalization_work: usize,
}

/// Canonicalize each named graph independently and commit the exact RDF terms.
/// Graph, datatype, language, lexical spelling, and unexpected quads all remain
/// part of the commitment. Exhausting either bound fails rather than truncates.
pub fn structural_quad_commitment(
    quads: &BTreeSet<SourceQuad>,
    max_blank_nodes: usize,
    max_work: usize,
) -> Result<StructuralQuadCommitment, ConversionError> {
    let mut by_graph = BTreeMap::<String, Vec<RawTriple>>::new();
    for quad in quads {
        let subject = match &quad.subject {
            RdfNodeId::Iri(value) => RawNode::Iri(value.clone()),
            RdfNodeId::ScopedBlankNode(value) => RawNode::Blank(value.clone()),
        };
        let object = match &quad.object {
            ExactTerm::Iri(value) => RawTerm::Iri(value.clone()),
            ExactTerm::ScopedBlankNode(value) => RawTerm::Blank(value.clone()),
            ExactTerm::Literal {
                lexical,
                datatype,
                language,
            } => RawTerm::Literal {
                lexical: lexical.clone(),
                datatype: datatype.clone(),
                language: language.clone(),
            },
        };
        by_graph
            .entry(quad.graph.clone())
            .or_default()
            .push(RawTriple {
                subject,
                predicate: quad.predicate.clone(),
                object,
            });
    }

    let mut canonical = BTreeSet::new();
    let mut blank_node_count = 0usize;
    let mut work = 0usize;
    for (graph, raw) in by_graph {
        let blanks = raw
            .iter()
            .flat_map(|triple| {
                let subject = match &triple.subject {
                    RawNode::Blank(value) => Some(value.clone()),
                    RawNode::Iri(_) => None,
                };
                let object = match &triple.object {
                    RawTerm::Blank(value) => Some(value.clone()),
                    RawTerm::Iri(_) | RawTerm::Literal { .. } => None,
                };
                subject.into_iter().chain(object)
            })
            .collect::<BTreeSet<_>>();
        blank_node_count = blank_node_count
            .checked_add(blanks.len())
            .ok_or_else(canonicalization_limit)?;
        if blank_node_count > max_blank_nodes {
            return Err(err(
                ConversionErrorKind::Limit,
                "rdfxml_blank_node_limit_exceeded",
            ));
        }
        let remaining = max_work
            .checked_sub(work)
            .ok_or_else(canonicalization_limit)?;
        let (mapping, graph_work) =
            canonical_mapping(&raw, &blanks.into_iter().collect::<Vec<_>>(), remaining)?;
        work = work
            .checked_add(graph_work)
            .ok_or_else(canonicalization_limit)?;
        let graph_hash = ContentHash::of_bytes(graph.as_bytes());
        let graph_scope = &graph_hash.as_str()[7..23];
        for triple in &raw {
            canonical.insert(to_quad(triple, &mapping, graph_scope, &graph));
        }
    }
    Ok(StructuralQuadCommitment {
        root: quad_root(&canonical),
        quad_count: canonical.len(),
        blank_node_count,
        canonicalization_work: work,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConversionLimits {
    pub max_input_bytes: usize,
    /// Counted from parser output, before duplicate normalization.
    pub max_input_triples: usize,
    pub max_output_bytes: usize,
    pub max_blank_nodes: usize,
    /// Number of triple renderings considered while finding the minimum
    /// blank-node labeling. Exhaustion is an error, never truncation.
    pub max_canonicalization_work: usize,
}

impl Default for ConversionLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_input_triples: 500_000,
            max_output_bytes: 128 * 1024 * 1024,
            max_blank_nodes: 100_000,
            max_canonicalization_work: 20_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ConversionRequest<'a> {
    pub authoritative_bytes: &'a [u8],
    /// Stable publisher/release identity, never a cache path.
    pub source_release_id: &'a str,
    /// Stable release-relative file identity, never a cache path.
    pub source_file_id: &'a str,
    pub base_iri: &'a str,
    pub graph_iri: &'a str,
    pub limits: ConversionLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionResult {
    pub source_release_id: String,
    pub source_file_id: String,
    pub base_iri: String,
    pub graph_iri: String,
    pub parser_identity: &'static str,
    pub parser_options: &'static str,
    pub blank_node_algorithm: &'static str,
    pub original_hash: ContentHash,
    pub derived_hash: ContentHash,
    pub graph_root: ContentHash,
    pub conversion_root: ContentHash,
    pub input_triple_count: usize,
    pub duplicate_input_triple_count: usize,
    pub output_triple_count: usize,
    pub canonicalization_work: usize,
    pub limits: ConversionLimits,
    pub quads: BTreeSet<SourceQuad>,
    pub turtle: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversionErrorKind {
    Invocation,
    Security,
    Malformed,
    Limit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionError {
    pub kind: ConversionErrorKind,
    pub public_code: &'static str,
}

impl std::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.public_code)
    }
}
impl std::error::Error for ConversionError {}

#[derive(Clone)]
struct RawTriple {
    subject: RawNode,
    predicate: String,
    object: RawTerm,
}
#[derive(Clone)]
enum RawNode {
    Iri(String),
    Blank(String),
}
#[derive(Clone)]
enum RawTerm {
    Iri(String),
    Blank(String),
    Literal {
        lexical: String,
        datatype: String,
        language: Option<String>,
    },
}

pub fn convert_rdfxml(request: ConversionRequest<'_>) -> Result<ConversionResult, ConversionError> {
    validate_request(&request)?;
    if request.authoritative_bytes.len() > request.limits.max_input_bytes {
        return Err(err(
            ConversionErrorKind::Limit,
            "rdfxml_input_byte_limit_exceeded",
        ));
    }
    validate_doctype_entities(request.authoritative_bytes, request.limits.max_output_bytes)?;
    let language_spellings = validate_xml(request.authoritative_bytes)?;

    let parser = RdfXmlParser::new()
        .with_base_iri(request.base_iri)
        .map_err(|_| err(ConversionErrorKind::Invocation, "rdfxml_base_iri_invalid"))?;
    // Validate graph IRI with the same exact IRI implementation used by terms.
    oxrdf::NamedNode::new(request.graph_iri)
        .map_err(|_| err(ConversionErrorKind::Invocation, "rdfxml_graph_iri_invalid"))?;

    let mut raw = Vec::new();
    let mut blanks = BTreeSet::new();
    for parsed in parser.for_reader(request.authoritative_bytes) {
        if raw.len() >= request.limits.max_input_triples {
            return Err(err(
                ConversionErrorKind::Limit,
                "rdfxml_triple_limit_exceeded",
            ));
        }
        let triple = parsed.map_err(|_| err(ConversionErrorKind::Malformed, "rdfxml_malformed"))?;
        let subject = match triple.subject {
            NamedOrBlankNode::NamedNode(node) => RawNode::Iri(node.into_string()),
            NamedOrBlankNode::BlankNode(node) => {
                let id = node.into_string();
                blanks.insert(id.clone());
                RawNode::Blank(id)
            }
        };
        let object = match triple.object {
            Term::NamedNode(node) => RawTerm::Iri(node.into_string()),
            Term::BlankNode(node) => {
                let id = node.into_string();
                blanks.insert(id.clone());
                RawTerm::Blank(id)
            }
            Term::Literal(literal) => RawTerm::Literal {
                lexical: literal.value().to_owned(),
                datatype: literal.datatype().as_str().to_owned(),
                language: literal.language().map(|language| {
                    language_spellings
                        .get(language)
                        .cloned()
                        .unwrap_or_else(|| language.to_owned())
                }),
            },
        };
        raw.push(RawTriple {
            subject,
            predicate: triple.predicate.into_string(),
            object,
        });
    }
    if blanks.len() > request.limits.max_blank_nodes {
        return Err(err(
            ConversionErrorKind::Limit,
            "rdfxml_blank_node_limit_exceeded",
        ));
    }

    let blank_ids: Vec<_> = blanks.into_iter().collect();
    let (mapping, required_work) =
        canonical_mapping(&raw, &blank_ids, request.limits.max_canonicalization_work)?;
    let scope_material = format!(
        "{}\0{}\0{}",
        request.source_release_id, request.source_file_id, request.graph_iri
    );
    let scope_hash = ContentHash::of_bytes(scope_material.as_bytes());
    let scope = &scope_hash.as_str()[7..23];

    let mut quads = BTreeSet::new();
    for triple in &raw {
        quads.insert(to_quad(triple, &mapping, scope, request.graph_iri));
    }
    let input_triple_count = raw.len();
    let output_triple_count = quads.len();
    let duplicate_input_triple_count = input_triple_count - output_triple_count;
    let turtle = serialize(&quads, request.limits.max_output_bytes)?;

    let original_hash = ContentHash::of_bytes(request.authoritative_bytes);
    let derived_hash = ContentHash::of_bytes(turtle.as_bytes());
    let graph_root = quad_root(&quads);
    let conversion_root = conversion_root(ConversionRootInput {
        source_release_id: request.source_release_id,
        source_file_id: request.source_file_id,
        base_iri: request.base_iri,
        graph_iri: request.graph_iri,
        original_hash: &original_hash,
        derived_hash: &derived_hash,
        graph_root: &graph_root,
        input_triple_count,
        duplicate_input_triple_count,
        output_triple_count,
        limits: request.limits,
    });

    Ok(ConversionResult {
        source_release_id: request.source_release_id.to_owned(),
        source_file_id: request.source_file_id.to_owned(),
        base_iri: request.base_iri.to_owned(),
        graph_iri: request.graph_iri.to_owned(),
        parser_identity: PARSER_ID,
        parser_options: PARSER_OPTIONS,
        blank_node_algorithm: BLANK_NODE_ALGORITHM,
        original_hash,
        derived_hash,
        graph_root,
        conversion_root,
        input_triple_count,
        duplicate_input_triple_count,
        output_triple_count,
        canonicalization_work: required_work,
        limits: request.limits,
        quads,
        turtle,
    })
}

struct ConversionRootInput<'a> {
    source_release_id: &'a str,
    source_file_id: &'a str,
    base_iri: &'a str,
    graph_iri: &'a str,
    original_hash: &'a ContentHash,
    derived_hash: &'a ContentHash,
    graph_root: &'a ContentHash,
    input_triple_count: usize,
    duplicate_input_triple_count: usize,
    output_triple_count: usize,
    limits: ConversionLimits,
}

fn conversion_root(input: ConversionRootInput<'_>) -> ContentHash {
    let counts = format!(
        "{}:{}:{}",
        input.input_triple_count, input.duplicate_input_triple_count, input.output_triple_count
    );
    let limits = format!(
        "{}:{}:{}:{}:{}",
        input.limits.max_input_bytes,
        input.limits.max_input_triples,
        input.limits.max_output_bytes,
        input.limits.max_blank_nodes,
        input.limits.max_canonicalization_work
    );
    framed_root(
        "ctxql-rdfxml-conversion-result/v1",
        [
            ("converter", CONVERTER_ID),
            ("parser", PARSER_ID),
            ("options", PARSER_OPTIONS),
            ("blank_nodes", BLANK_NODE_ALGORITHM),
            ("source_release", input.source_release_id),
            ("source_file", input.source_file_id),
            ("base_iri", input.base_iri),
            ("graph_iri", input.graph_iri),
            ("original_hash", input.original_hash.as_str()),
            ("derived_hash", input.derived_hash.as_str()),
            ("graph_root", input.graph_root.as_str()),
            ("counts", counts.as_str()),
            ("limits", limits.as_str()),
        ],
    )
}

impl ConversionResult {
    pub(crate) fn verify_integrity(&self) -> bool {
        if self.source_release_id.is_empty()
            || self.source_file_id.is_empty()
            || self.base_iri.is_empty()
            || self.parser_identity != PARSER_ID
            || self.parser_options != PARSER_OPTIONS
            || self.blank_node_algorithm != BLANK_NODE_ALGORITHM
            || self.output_triple_count != self.quads.len()
            || self.input_triple_count < self.output_triple_count
            || self.duplicate_input_triple_count
                != self.input_triple_count - self.output_triple_count
            || self.canonicalization_work > self.limits.max_canonicalization_work
            || ContentHash::of_bytes(self.turtle.as_bytes()) != self.derived_hash
            || quad_root(&self.quads) != self.graph_root
        {
            return false;
        }
        let Ok(serialized) = serialize(&self.quads, self.limits.max_output_bytes) else {
            return false;
        };
        if serialized != self.turtle {
            return false;
        }
        conversion_root(ConversionRootInput {
            source_release_id: &self.source_release_id,
            source_file_id: &self.source_file_id,
            base_iri: &self.base_iri,
            graph_iri: &self.graph_iri,
            original_hash: &self.original_hash,
            derived_hash: &self.derived_hash,
            graph_root: &self.graph_root,
            input_triple_count: self.input_triple_count,
            duplicate_input_triple_count: self.duplicate_input_triple_count,
            output_triple_count: self.output_triple_count,
            limits: self.limits,
        }) == self.conversion_root
    }
}

fn validate_request(request: &ConversionRequest<'_>) -> Result<(), ConversionError> {
    if request.source_release_id.is_empty() || request.source_file_id.is_empty() {
        return Err(err(
            ConversionErrorKind::Invocation,
            "rdfxml_source_identity_required",
        ));
    }
    if request.base_iri.is_empty() {
        return Err(err(
            ConversionErrorKind::Invocation,
            "rdfxml_base_iri_required",
        ));
    }
    if request.limits.max_input_bytes == 0
        || request.limits.max_input_triples == 0
        || request.limits.max_output_bytes == 0
        || request.limits.max_canonicalization_work == 0
    {
        return Err(err(
            ConversionErrorKind::Invocation,
            "rdfxml_limits_invalid",
        ));
    }
    Ok(())
}

fn validate_doctype_entities(
    bytes: &[u8],
    max_expanded_bytes: usize,
) -> Result<(), ConversionError> {
    const MAX_ENTITIES: usize = 256;
    const MAX_ENTITY_VALUE_BYTES: usize = 4096;
    const MAX_ENTITY_DECLARATION_BYTES: usize = 64 * 1024;

    let text = std::str::from_utf8(bytes)
        .map_err(|_| err(ConversionErrorKind::Malformed, "rdfxml_malformed"))?;
    let Some(start) = text.find("<!DOCTYPE") else {
        if text.contains("<!ENTITY") {
            return Err(unsafe_entity());
        }
        return Ok(());
    };
    if text[start + 1..].contains("<!DOCTYPE") {
        return Err(unsafe_entity());
    }
    let open = text[start..]
        .find('[')
        .map(|offset| start + offset)
        .ok_or_else(unsafe_entity)?;
    let close = text[open + 1..]
        .find("]>")
        .map(|offset| open + 1 + offset)
        .ok_or_else(unsafe_entity)?;
    let header = &text[start..open];
    if header.contains("SYSTEM") || header.contains("PUBLIC") || header.contains('%') {
        return Err(unsafe_entity());
    }
    let declarations = &text[open + 1..close];
    if declarations.len() > MAX_ENTITY_DECLARATION_BYTES
        || declarations.contains("SYSTEM")
        || declarations.contains("PUBLIC")
        || declarations.contains('%')
    {
        return Err(unsafe_entity());
    }

    let mut rest = declarations.trim();
    let mut entities = Vec::new();
    while !rest.is_empty() {
        let declaration = rest.strip_prefix("<!ENTITY").ok_or_else(unsafe_entity)?;
        let end = declaration.find('>').ok_or_else(unsafe_entity)?;
        let body = declaration[..end].trim();
        rest = declaration[end + 1..].trim();
        let split = body.find(char::is_whitespace).ok_or_else(unsafe_entity)?;
        let name = &body[..split];
        let quoted = body[split..].trim();
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
            || quoted.len() < 2
        {
            return Err(unsafe_entity());
        }
        let quote = quoted.as_bytes()[0];
        if !matches!(quote, b'\'' | b'"') || quoted.as_bytes().last().copied() != Some(quote) {
            return Err(unsafe_entity());
        }
        let value = &quoted[1..quoted.len() - 1];
        if value.is_empty()
            || value.len() > MAX_ENTITY_VALUE_BYTES
            || value.contains('&')
            || value.contains('<')
            || value.contains('>')
            || value.chars().any(char::is_control)
        {
            return Err(unsafe_entity());
        }
        entities.push((name, value));
        if entities.len() > MAX_ENTITIES {
            return Err(unsafe_entity());
        }
    }

    if text[close + 2..].contains("<!ENTITY") {
        return Err(unsafe_entity());
    }
    let document = &text[close + 2..];
    let expanded = entities
        .iter()
        .try_fold(bytes.len(), |total, (name, value)| {
            let reference = format!("&{name};");
            let occurrences = document.matches(&reference).count();
            total.checked_add(occurrences.checked_mul(value.len())?)
        });
    if expanded.is_none_or(|size| size > max_expanded_bytes) {
        return Err(err(
            ConversionErrorKind::Limit,
            "rdfxml_entity_expansion_limit_exceeded",
        ));
    }
    Ok(())
}

fn unsafe_entity() -> ConversionError {
    err(
        ConversionErrorKind::Security,
        "rdfxml_external_or_unsafe_entity_forbidden",
    )
}

fn validate_xml(bytes: &[u8]) -> Result<BTreeMap<String, String>, ConversionError> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().check_end_names = true;
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    let mut roots = 0usize;
    let mut languages = BTreeMap::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(start)) => {
                if depth == 0 {
                    roots += 1;
                }
                record_languages(&start, &mut languages)?;
                depth += 1;
            }
            Ok(Event::Empty(empty)) => {
                if depth == 0 {
                    roots += 1;
                }
                record_languages(&empty, &mut languages)?;
            }
            Ok(Event::End(_)) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| err(ConversionErrorKind::Malformed, "rdfxml_malformed"))?;
            }
            Ok(Event::DocType(_)) => {}
            Ok(Event::Text(text)) if depth == 0 && !xml_whitespace(text.as_ref()) => {
                return Err(err(ConversionErrorKind::Malformed, "rdfxml_malformed"));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(err(ConversionErrorKind::Malformed, "rdfxml_malformed")),
        }
        buffer.clear();
    }
    if depth != 0 || roots != 1 {
        return Err(err(ConversionErrorKind::Malformed, "rdfxml_malformed"));
    }
    Ok(languages)
}

fn record_languages(
    start: &quick_xml::events::BytesStart<'_>,
    languages: &mut BTreeMap<String, String>,
) -> Result<(), ConversionError> {
    for attribute in start.attributes() {
        let attribute =
            attribute.map_err(|_| err(ConversionErrorKind::Malformed, "rdfxml_malformed"))?;
        if attribute.key.as_ref() != b"xml:lang" {
            continue;
        }
        let spelling = std::str::from_utf8(attribute.value.as_ref())
            .map_err(|_| err(ConversionErrorKind::Malformed, "rdfxml_malformed"))?
            .to_owned();
        if spelling.is_empty() {
            continue;
        }
        let normalized = spelling.to_ascii_lowercase();
        if languages
            .insert(normalized, spelling.clone())
            .is_some_and(|existing| existing != spelling)
        {
            return Err(err(
                ConversionErrorKind::Malformed,
                "rdfxml_language_spelling_ambiguous",
            ));
        }
    }
    Ok(())
}

fn xml_whitespace(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_whitespace)
}

fn canonical_mapping(
    raw: &[RawTriple],
    blank_ids: &[String],
    work_limit: usize,
) -> Result<(BTreeMap<String, usize>, usize), ConversionError> {
    if blank_ids.is_empty() {
        return Ok((BTreeMap::new(), 0));
    }

    // Refine structural colors without using parser-generated labels. Most
    // ontology blank nodes become unique here, so canonicalization remains
    // practical for real release modules rather than factorial in all nodes.
    let mut work = 0usize;
    let mut colors = BTreeMap::new();
    for id in blank_ids {
        let signature = blank_signature(id, raw, &BTreeMap::new(), &mut work, work_limit)?;
        colors.insert(id.clone(), signature);
    }
    let mut ranks = assign_ranks(&colors);
    for _ in 0..=blank_ids.len().min(64) {
        let mut signatures = BTreeMap::new();
        for id in blank_ids {
            let signature = blank_signature(id, raw, &ranks, &mut work, work_limit)?;
            signatures.insert(id.clone(), signature);
        }
        let refined = assign_ranks(&signatures);
        colors = signatures;
        if refined == ranks {
            ranks = refined;
            break;
        }
        ranks = refined;
    }

    let mut groups: BTreeMap<(usize, String), Vec<String>> = BTreeMap::new();
    for id in blank_ids {
        groups
            .entry((ranks[id], colors[id].clone()))
            .or_default()
            .push(id.clone());
    }
    let groups: Vec<Vec<String>> = groups.into_values().collect();
    let mut mapping = BTreeMap::new();
    let mut next_label = 0usize;
    let mut ambiguous = Vec::new();
    for mut group in groups {
        group.sort();
        let start = next_label;
        next_label += group.len();
        if group.len() == 1 {
            mapping.insert(group.pop().expect("single member"), start);
        } else {
            ambiguous.push((group, start));
        }
    }
    if ambiguous.is_empty() {
        return Ok((mapping, work));
    }

    // Reject factorial tie classes before recursion. This protects the process
    // stack as well as the nominal work budget: a caller-controlled symmetric
    // graph must never descend once per configured blank-node allowance.
    let permutation_count = ambiguous.iter().try_fold(1usize, |count, (group, _)| {
        factorial_bounded(group.len(), work_limit)
            .and_then(|factorial| count.checked_mul(factorial))
            .filter(|value| *value <= work_limit)
    });
    let path_work = ambiguous
        .iter()
        .try_fold(raw.len().max(1), |count, (group, _)| {
            count.checked_add(group.len() + 1)
        });
    let required = permutation_count
        .zip(path_work)
        .and_then(|(count, per_path)| count.checked_mul(per_path))
        .and_then(|permutations| work.checked_add(permutations));
    if required.is_none_or(|required| required > work_limit) {
        return Err(canonicalization_limit());
    }

    let mut best: Option<(Vec<String>, BTreeMap<String, usize>)> = None;
    enumerate_ambiguous(
        0,
        &ambiguous,
        &mut mapping,
        raw,
        &mut work,
        work_limit,
        &mut best,
    )?;
    best.map(|(_, mapping)| (mapping, work)).ok_or_else(|| {
        err(
            ConversionErrorKind::Limit,
            "rdfxml_canonicalization_work_limit_exceeded",
        )
    })
}

fn factorial_bounded(n: usize, bound: usize) -> Option<usize> {
    (2..=n).try_fold(1usize, |value, factor| {
        value.checked_mul(factor).filter(|value| *value <= bound)
    })
}

fn assign_ranks(signatures: &BTreeMap<String, String>) -> BTreeMap<String, usize> {
    let ordered: BTreeSet<_> = signatures.values().cloned().collect();
    let ranks: BTreeMap<_, _> = ordered
        .into_iter()
        .enumerate()
        .map(|(rank, signature)| (signature, rank))
        .collect();
    signatures
        .iter()
        .map(|(id, signature)| (id.clone(), ranks[signature]))
        .collect()
}

fn blank_signature(
    id: &str,
    raw: &[RawTriple],
    ranks: &BTreeMap<String, usize>,
    work: &mut usize,
    work_limit: usize,
) -> Result<String, ConversionError> {
    let mut parts = Vec::new();
    for triple in raw {
        *work = work.checked_add(1).ok_or_else(canonicalization_limit)?;
        if *work > work_limit {
            return Err(canonicalization_limit());
        }
        if matches!(&triple.subject, RawNode::Blank(value) if value == id) {
            parts.push(format!(
                "S|{}|{}",
                triple.predicate,
                structural_term(&triple.object, id, ranks)
            ));
        }
        if matches!(&triple.object, RawTerm::Blank(value) if value == id) {
            parts.push(format!(
                "O|{}|{}",
                structural_node(&triple.subject, id, ranks),
                triple.predicate
            ));
        }
    }
    parts.sort();
    Ok(parts.join("\u{0}"))
}

fn structural_node(node: &RawNode, current: &str, ranks: &BTreeMap<String, usize>) -> String {
    match node {
        RawNode::Iri(iri) => format!("I{}:{iri}", iri.len()),
        RawNode::Blank(id) if id == current => "B:self".into(),
        RawNode::Blank(id) => ranks
            .get(id)
            .map_or_else(|| "B:any".into(), |rank| format!("B:{rank}")),
    }
}

fn structural_term(term: &RawTerm, current: &str, ranks: &BTreeMap<String, usize>) -> String {
    match term {
        RawTerm::Iri(iri) => format!("I{}:{iri}", iri.len()),
        RawTerm::Blank(id) if id == current => "B:self".into(),
        RawTerm::Blank(id) => ranks
            .get(id)
            .map_or_else(|| "B:any".into(), |rank| format!("B:{rank}")),
        RawTerm::Literal {
            lexical,
            datatype,
            language,
        } => format!(
            "L{}:{}:{}:{}:{}:{}",
            lexical.len(),
            lexical,
            datatype.len(),
            datatype,
            language.as_deref().map_or(0, str::len),
            language.as_deref().unwrap_or("")
        ),
    }
}

fn enumerate_ambiguous(
    group_index: usize,
    groups: &[(Vec<String>, usize)],
    mapping: &mut BTreeMap<String, usize>,
    raw: &[RawTriple],
    work: &mut usize,
    work_limit: usize,
    best: &mut Option<(Vec<String>, BTreeMap<String, usize>)>,
) -> Result<(), ConversionError> {
    if group_index == groups.len() {
        *work = work
            .checked_add(raw.len().max(1))
            .ok_or_else(canonicalization_limit)?;
        if *work > work_limit {
            return Err(canonicalization_limit());
        }
        let mut rendered: Vec<_> = raw
            .iter()
            .map(|triple| canonical_line(triple, mapping))
            .collect();
        rendered.sort();
        if best.as_ref().is_none_or(|(current, _)| rendered < *current) {
            *best = Some((rendered, mapping.clone()));
        }
        return Ok(());
    }

    let (ids, start) = &groups[group_index];
    let mut values = ids.clone();
    visit_group_permutations(
        0,
        &mut values,
        *start,
        group_index,
        groups,
        mapping,
        raw,
        work,
        work_limit,
        best,
    )
}

#[allow(clippy::too_many_arguments)]
fn visit_group_permutations(
    position: usize,
    values: &mut [String],
    start: usize,
    group_index: usize,
    groups: &[(Vec<String>, usize)],
    mapping: &mut BTreeMap<String, usize>,
    raw: &[RawTriple],
    work: &mut usize,
    work_limit: usize,
    best: &mut Option<(Vec<String>, BTreeMap<String, usize>)>,
) -> Result<(), ConversionError> {
    *work = work.checked_add(1).ok_or_else(canonicalization_limit)?;
    if *work > work_limit {
        return Err(canonicalization_limit());
    }
    if position == values.len() {
        for (offset, id) in values.iter().enumerate() {
            mapping.insert(id.clone(), start + offset);
        }
        return enumerate_ambiguous(
            group_index + 1,
            groups,
            mapping,
            raw,
            work,
            work_limit,
            best,
        );
    }
    for index in position..values.len() {
        values.swap(position, index);
        visit_group_permutations(
            position + 1,
            values,
            start,
            group_index,
            groups,
            mapping,
            raw,
            work,
            work_limit,
            best,
        )?;
        values.swap(position, index);
    }
    Ok(())
}

fn canonicalization_limit() -> ConversionError {
    err(
        ConversionErrorKind::Limit,
        "rdfxml_canonicalization_work_limit_exceeded",
    )
}

fn canonical_line(triple: &RawTriple, mapping: &BTreeMap<String, usize>) -> String {
    format!(
        "{} <{}> {} .",
        raw_node(&triple.subject, mapping, ""),
        escape_iri(&triple.predicate),
        raw_term(&triple.object, mapping, "")
    )
}

fn to_quad(
    triple: &RawTriple,
    mapping: &BTreeMap<String, usize>,
    scope: &str,
    graph: &str,
) -> SourceQuad {
    let blank = |id: &str| format!("_:c{scope}b{:08}", mapping[id]);
    let subject = match &triple.subject {
        RawNode::Iri(iri) => RdfNodeId::Iri(iri.clone()),
        RawNode::Blank(id) => RdfNodeId::ScopedBlankNode(blank(id)),
    };
    let object = match &triple.object {
        RawTerm::Iri(iri) => ExactTerm::Iri(iri.clone()),
        RawTerm::Blank(id) => ExactTerm::ScopedBlankNode(blank(id)),
        RawTerm::Literal {
            lexical,
            datatype,
            language,
        } => ExactTerm::Literal {
            lexical: lexical.clone(),
            datatype: datatype.clone(),
            language: language.clone(),
        },
    };
    SourceQuad {
        graph: graph.to_owned(),
        subject,
        predicate: triple.predicate.clone(),
        object,
    }
}

fn raw_node(node: &RawNode, mapping: &BTreeMap<String, usize>, scope: &str) -> String {
    match node {
        RawNode::Iri(iri) => format!("<{}>", escape_iri(iri)),
        RawNode::Blank(id) => format!("_:c{scope}b{:08}", mapping[id]),
    }
}
fn raw_term(term: &RawTerm, mapping: &BTreeMap<String, usize>, scope: &str) -> String {
    match term {
        RawTerm::Iri(iri) => format!("<{}>", escape_iri(iri)),
        RawTerm::Blank(id) => format!("_:c{scope}b{:08}", mapping[id]),
        RawTerm::Literal {
            lexical,
            datatype,
            language,
        } => literal(lexical, datatype, language.as_deref()),
    }
}

fn serialize(quads: &BTreeSet<SourceQuad>, max_bytes: usize) -> Result<String, ConversionError> {
    let mut output = String::new();
    for quad in quads {
        let subject = match &quad.subject {
            RdfNodeId::Iri(iri) => format!("<{}>", escape_iri(iri)),
            RdfNodeId::ScopedBlankNode(label) => label.clone(),
        };
        let object = match &quad.object {
            ExactTerm::Iri(iri) => format!("<{}>", escape_iri(iri)),
            ExactTerm::ScopedBlankNode(label) => label.clone(),
            ExactTerm::Literal {
                lexical,
                datatype,
                language,
            } => literal(lexical, datatype, language.as_deref()),
        };
        let line = format!("{subject} <{}> {object} .\n", escape_iri(&quad.predicate));
        if output
            .len()
            .checked_add(line.len())
            .is_none_or(|size| size > max_bytes)
        {
            return Err(err(
                ConversionErrorKind::Limit,
                "rdfxml_output_byte_limit_exceeded",
            ));
        }
        output.push_str(&line);
    }
    Ok(output)
}

fn literal(value: &str, datatype: &str, language: Option<&str>) -> String {
    let escaped = escape_literal(value);
    match language {
        Some(language) => format!("\"{escaped}\"@{language}"),
        None => format!("\"{escaped}\"^^<{}>", escape_iri(datatype)),
    }
}
fn escape_literal(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\\' => "\\\\".into(),
            '"' => "\\\"".into(),
            '\n' => "\\n".into(),
            '\r' => "\\r".into(),
            '\t' => "\\t".into(),
            ch if ch.is_control() => unicode_escape(ch),
            ch => ch.to_string(),
        })
        .collect()
}
fn escape_iri(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_control() || matches!(ch, '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`' | '\\')
            {
                unicode_escape(ch)
            } else {
                ch.to_string()
            }
        })
        .collect()
}
fn unicode_escape(ch: char) -> String {
    let value = ch as u32;
    if value <= 0xffff {
        format!("\\u{value:04X}")
    } else {
        format!("\\U{value:08X}")
    }
}
fn err(kind: ConversionErrorKind, public_code: &'static str) -> ConversionError {
    ConversionError { kind, public_code }
}
