//! Deterministic, bounded ontology briefing selection.
//!
//! This module only reads the caller-supplied pinned `OntologyToolHost`. The
//! caller remains responsible for binding the returned commitment into its
//! capture/request parent and for using the same host for later resolution.

use cdb_core::id::ContentHash;
use cdb_provider_pi::ontology_bridge::OntologyToolHost;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

pub const SELECTOR_VERSION: &str = "ctxql-ontology-briefing-selector/v1";
pub const RENDERER_VERSION: &str = "ctxql-ontology-briefing-renderer/v1";
const RESPONSE_SCHEMA: &str = "ctxql-extraction-vocabulary-response/v2";
const LOAN_SEED_MANIFEST: &[u8] =
    include_bytes!("../../../fixtures/conformance/p6/ontology-guided/loan-briefing-v1.json");

/// Load the checked-in topic-wide loan seed manifest. Synthetic vocabularies
/// should pass their own manifest to `build_ontology_briefing` instead.
pub fn loan_briefing_seed_manifest() -> Result<OntologyBriefingSeedManifest, OntologyBriefingError>
{
    OntologyBriefingSeedManifest::from_json(LOAN_SEED_MANIFEST)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OntologyBriefingSeedManifest {
    pub schema: String,
    pub topic: String,
    pub seeds: Vec<OntologyBriefingSeed>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OntologyBriefingSeed {
    pub iri: String,
    pub kind: String,
    pub priority: u32,
}

impl OntologyBriefingSeedManifest {
    pub fn from_json(bytes: &[u8]) -> Result<Self, OntologyBriefingError> {
        if bytes.len() > 64 * 1024 {
            return Err(OntologyBriefingError::new("seed_manifest_too_large"));
        }
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|_| OntologyBriefingError::new("seed_manifest_invalid"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub(crate) fn validate(&self) -> Result<(), OntologyBriefingError> {
        if self.schema != "ctxql-ontology-briefing-seeds/v1"
            || self.topic.is_empty()
            || self.topic.len() > 256
            || self.seeds.len() > 160
        {
            return Err(OntologyBriefingError::new("seed_manifest_invalid"));
        }
        let mut iris = BTreeSet::new();
        for seed in &self.seeds {
            if !valid_iri(&seed.iri)
                || !matches!(
                    seed.kind.as_str(),
                    "class"
                        | "property"
                        | "object_property"
                        | "datatype_property"
                        | "annotation_property"
                        | "generic_property"
                        | "conflicting_property"
                        | "datatype"
                )
                || !iris.insert(seed.iri.clone())
            {
                return Err(OntologyBriefingError::new("seed_manifest_invalid"));
            }
        }
        Ok(())
    }

    fn commitment(&self) -> Result<String, OntologyBriefingError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| OntologyBriefingError::new("seed_manifest_encoding_failed"))?;
        Ok(ContentHash::of_bytes(&bytes).as_str().to_owned())
    }
}

#[derive(Clone, Debug, Default)]
pub struct OntologyBriefingContext<'a> {
    pub passage: &'a str,
    pub title: Option<&'a str>,
    pub headings: &'a [&'a str],
    pub grounded_entity_names: &'a [&'a str],
}

#[derive(Clone, Debug)]
pub struct OntologyBriefingLimits {
    pub max_serialized_bytes: usize,
    pub max_terms: usize,
    pub max_lexical_candidates: usize,
    pub max_lexical_queries: usize,
    pub max_neighbor_terms: usize,
    pub neighbor_depth: usize,
    pub max_ancestor_terms: usize,
    pub ancestor_depth: usize,
}

impl Default for OntologyBriefingLimits {
    fn default() -> Self {
        Self {
            max_serialized_bytes: 64 * 1024,
            max_terms: 160,
            max_lexical_candidates: 512,
            // Each direct Fluree lexical query scans the approved 73-source
            // graph set. Sixteen ranked queries retain passage-wide discovery
            // without turning prompt construction into hundreds of scans.
            max_lexical_queries: 16,
            max_neighbor_terms: 256,
            neighbor_depth: 2,
            max_ancestor_terms: 256,
            ancestor_depth: 8,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CommittedOntologyBriefing {
    pub rendering: Value,
    pub rendered_bytes: Vec<u8>,
    pub commitment: String,
    pub provenance: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OntologyBriefingError {
    pub code: &'static str,
}

impl OntologyBriefingError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }
}

impl fmt::Display for OntologyBriefingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for OntologyBriefingError {}

#[derive(Clone, Debug)]
struct Candidate {
    term: Value,
    tier: Tier,
    score: LexicalScore,
    reasons: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    Seed,
    Lexical,
    Neighbor,
}

impl Tier {
    fn name(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Lexical => "lexical",
            Self::Neighbor => "neighbor",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LexicalScore {
    exact_phrase_tokens: usize,
    distinct_tokens: usize,
}

/// Build a deterministic briefing from a pinned vocabulary view.
///
/// No model is called and no certification state is consulted. The returned
/// `commitment` covers the exact `rendered_bytes`; the parent capture must bind
/// that commitment and the caller must retain the same pinned host.
pub fn build_ontology_briefing(
    host: &dyn OntologyToolHost,
    manifest: &OntologyBriefingSeedManifest,
    context: &OntologyBriefingContext<'_>,
    limits: &OntologyBriefingLimits,
) -> Result<CommittedOntologyBriefing, OntologyBriefingError> {
    manifest.validate()?;
    validate_limits(limits)?;
    if context.passage.len() > 256 * 1024
        || context.title.is_some_and(|value| value.len() > 16 * 1024)
        || context.headings.len() > 64
        || context.grounded_entity_names.len() > 64
    {
        return Err(OntologyBriefingError::new("briefing_context_limit"));
    }

    let manifest_commitment = manifest.commitment()?;
    let context_commitment = context_commitment(context)?;
    let mut candidates = BTreeMap::<String, Candidate>::new();
    let mut diagnostics = Vec::<Value>::new();
    let mut captures = BTreeSet::<String>::new();

    let mut seeds = manifest.seeds.iter().collect::<Vec<_>>();
    seeds.sort_by(|left, right| (left.priority, &left.iri).cmp(&(right.priority, &right.iri)));
    for seed in seeds {
        let response = lookup(
            host,
            json!({"operation":"describe","query":seed.iri,"kind":seed.kind,"limit":20}),
        );
        match response.and_then(|response| {
            capture_source(&response, &mut captures)?;
            single_exact_term(&response, &seed.iri)
        }) {
            Ok(term) if kind_compatible(term_kind(&term), &seed.kind) => {
                candidates.insert(
                    seed.iri.clone(),
                    Candidate {
                        term,
                        tier: Tier::Seed,
                        score: LexicalScore::default(),
                        reasons: BTreeSet::from([format!("seed_priority:{}", seed.priority)]),
                    },
                );
            }
            Ok(_) => diagnostics.push(json!({
                "code":"configured_seed_kind_mismatch", "iri":seed.iri,
                "expected_kind":seed.kind
            })),
            Err(code) => diagnostics.push(json!({
                "code":"configured_seed_missing", "iri":seed.iri,
                "expected_kind":seed.kind, "detail":code
            })),
        }
    }

    let context_tokens = normalized_context(context);
    let (queries, query_set_truncated) =
        lexical_queries(&context_tokens, limits.max_lexical_queries);
    let mut lexical_pool = BTreeMap::<String, Value>::new();
    let mut lexical_candidate_truncated = query_set_truncated;
    for query in queries {
        if lexical_pool.len() >= limits.max_lexical_candidates {
            lexical_candidate_truncated = true;
            break;
        }
        match lookup(host, json!({"operation":"search","query":query,"limit":20})) {
            Ok(response) => {
                if capture_source(&response, &mut captures).is_err() {
                    diagnostics.push(json!({"code":"lexical_response_invalid","query":query}));
                    continue;
                }
                if response.pointer("/page/truncated").and_then(Value::as_bool) == Some(true) {
                    lexical_candidate_truncated = true;
                }
                if let Some(terms) = response.get("terms").and_then(Value::as_array) {
                    for term in terms {
                        let Some(iri) = term.get("iri").and_then(Value::as_str) else {
                            continue;
                        };
                        if valid_iri(iri) && !lexical_pool.contains_key(iri) {
                            if lexical_pool.len() == limits.max_lexical_candidates {
                                lexical_candidate_truncated = true;
                                break;
                            }
                            lexical_pool.insert(iri.to_owned(), term.clone());
                        }
                    }
                }
            }
            Err(_) => diagnostics.push(json!({"code":"lexical_lookup_failed","query":query})),
        }
    }

    for (iri, term) in lexical_pool {
        let score = lexical_score(&term, &context_tokens);
        if score.distinct_tokens == 0 || candidates.contains_key(&iri) {
            continue;
        }
        candidates.insert(
            iri,
            Candidate {
                term,
                tier: Tier::Lexical,
                score,
                reasons: BTreeSet::from(["passage_context_lexical_match".to_owned()]),
            },
        );
    }

    expand_neighbors(
        host,
        &mut candidates,
        &mut captures,
        &mut diagnostics,
        limits,
    );

    let mut ordered = candidates.into_iter().collect::<Vec<_>>();
    ordered.sort_by(|(left_iri, left), (right_iri, right)| {
        left.tier
            .cmp(&right.tier)
            .then_with(|| {
                right
                    .score
                    .exact_phrase_tokens
                    .cmp(&left.score.exact_phrase_tokens)
            })
            .then_with(|| right.score.distinct_tokens.cmp(&left.score.distinct_tokens))
            .then_with(|| left_iri.cmp(right_iri))
    });

    let mut omitted = Vec::<Value>::new();
    if ordered.len() > limits.max_terms {
        for (iri, candidate) in ordered.drain(limits.max_terms..) {
            if candidate.tier == Tier::Seed {
                return Err(OntologyBriefingError::new("context_budget_insufficient"));
            }
            omitted.push(json!({"iri":iri,"reason":"term_budget"}));
        }
    }

    let mut groups = Vec::with_capacity(ordered.len());
    for (iri, candidate) in ordered {
        let inherited = inherited_metadata(host, &iri, &candidate.term, &mut captures, limits);
        groups.push(json!({
            "iri": iri,
            "tier": candidate.tier.name(),
            "lexical_score": {
                "exact_phrase_tokens": candidate.score.exact_phrase_tokens,
                "distinct_tokens": candidate.score.distinct_tokens
            },
            "selection_reasons": candidate.reasons,
            "term": candidate.term,
            "inherited_metadata": inherited
        }));
    }

    let base = |groups: &[Value], omitted: &[Value]| {
        json!({
            "schema":"ctxql-ontology-briefing/v3",
            "selector_version":SELECTOR_VERSION,
            "renderer_version":RENDERER_VERSION,
            "topic":manifest.topic,
            "seed_manifest_commitment":manifest_commitment,
            "context_commitment":context_commitment,
            "source_captures":captures,
            "limits":{
                "serialized_bytes":limits.max_serialized_bytes,
                "terms":limits.max_terms,
                "lexical_candidates":limits.max_lexical_candidates,
                "lexical_queries":limits.max_lexical_queries,
                "neighbor_depth":limits.neighbor_depth,
                "neighbor_terms":limits.max_neighbor_terms,
                "ancestor_depth":limits.ancestor_depth,
                "ancestor_terms_per_term":limits.max_ancestor_terms
            },
            "selection":{
                "groups":groups,
                "omitted":omitted,
                "lexical_candidates_truncated":lexical_candidate_truncated,
                "diagnostics":diagnostics
            }
        })
    };

    loop {
        let rendering = base(&groups, &omitted);
        let rendered_bytes = serde_json::to_vec(&rendering)
            .map_err(|_| OntologyBriefingError::new("briefing_encoding_failed"))?;
        if rendered_bytes.len() <= limits.max_serialized_bytes {
            let commitment = ContentHash::of_bytes(&rendered_bytes).as_str().to_owned();
            let provenance = json!({
                "schema":"ctxql-ontology-briefing-provenance/v1",
                "commitment":commitment,
                "rendered_bytes":rendered_bytes.len(),
                "term_count":groups.len(),
                "seed_manifest_commitment":manifest_commitment,
                "context_commitment":context_commitment,
                "selector_version":SELECTOR_VERSION,
                "renderer_version":RENDERER_VERSION,
                "source_captures":captures,
                "omitted_count":omitted.len()
            });
            return Ok(CommittedOntologyBriefing {
                rendering,
                rendered_bytes,
                commitment,
                provenance,
            });
        }
        let Some(index) = groups.iter().rposition(|group| group["tier"] != "seed") else {
            return Err(OntologyBriefingError::new("context_budget_insufficient"));
        };
        let removed = groups.remove(index);
        omitted.push(json!({"iri":removed["iri"],"reason":"serialized_byte_budget"}));
    }
}

fn validate_limits(limits: &OntologyBriefingLimits) -> Result<(), OntologyBriefingError> {
    if limits.max_serialized_bytes == 0
        || limits.max_serialized_bytes > 512 * 1024
        || limits.max_terms == 0
        || limits.max_terms > 160
        || limits.max_lexical_candidates == 0
        || limits.max_lexical_candidates > 512
        || limits.max_lexical_queries == 0
        || limits.max_lexical_queries > 128
        || limits.max_neighbor_terms == 0
        || limits.max_neighbor_terms > 256
        || limits.neighbor_depth > 2
        || limits.max_ancestor_terms == 0
        || limits.max_ancestor_terms > 256
        || limits.ancestor_depth > 8
    {
        return Err(OntologyBriefingError::new("briefing_limits_invalid"));
    }
    Ok(())
}

fn lookup(host: &dyn OntologyToolHost, request: Value) -> Result<Value, &'static str> {
    host.lookup(&request)
        .map_err(|_| "lookup_denied")
        .and_then(|response| {
            if response.get("schema").and_then(Value::as_str) != Some(RESPONSE_SCHEMA)
                || !response.get("terms").is_some_and(Value::is_array)
            {
                Err("response_shape_invalid")
            } else {
                Ok(response)
            }
        })
}

fn capture_source(response: &Value, captures: &mut BTreeSet<String>) -> Result<(), &'static str> {
    let capture = response
        .get("capture")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("capture_missing")?;
    captures.insert(capture.to_owned());
    Ok(())
}

fn single_exact_term(response: &Value, iri: &str) -> Result<Value, &'static str> {
    response
        .get("terms")
        .and_then(Value::as_array)
        .and_then(|terms| terms.iter().find(|term| term["iri"] == iri))
        .cloned()
        .ok_or("term_not_found")
}

fn expand_neighbors(
    host: &dyn OntologyToolHost,
    candidates: &mut BTreeMap<String, Candidate>,
    captures: &mut BTreeSet<String>,
    diagnostics: &mut Vec<Value>,
    limits: &OntologyBriefingLimits,
) {
    let selected_classes = candidates
        .iter()
        .filter(|(_, candidate)| term_kind(&candidate.term) == Some("class"))
        .map(|(iri, _)| iri.clone())
        .collect::<BTreeSet<_>>();
    let touching = candidates
        .iter()
        .filter(|(_, candidate)| is_property(term_kind(&candidate.term)))
        .filter(|(_, candidate)| {
            constraint_iris(&candidate.term)
                .iter()
                .any(|iri| selected_classes.contains(iri))
        })
        .map(|(iri, _)| iri.clone())
        .collect::<Vec<_>>();
    for iri in touching {
        if let Some(candidate) = candidates.get_mut(&iri) {
            candidate
                .reasons
                .insert("constraint_touches_selected_class".into());
        }
    }

    let mut queue = candidates
        .iter()
        .map(|(iri, candidate)| (iri.clone(), candidate.term.clone(), 0usize))
        .collect::<VecDeque<_>>();
    let mut visited = candidates.keys().cloned().collect::<BTreeSet<_>>();
    let mut limit_hit = false;
    while let Some((_iri, term, depth)) = queue.pop_front() {
        if depth >= limits.neighbor_depth {
            continue;
        }
        let mut neighbors = direct_neighbor_iris(&term);
        neighbors.sort();
        neighbors.dedup();
        for neighbor in neighbors {
            if !visited.insert(neighbor.clone()) {
                continue;
            }
            if visited.len() > limits.max_neighbor_terms {
                limit_hit = true;
                break;
            }
            match lookup(
                host,
                json!({"operation":"describe","query":neighbor,"limit":20}),
            )
            .and_then(|response| {
                capture_source(&response, captures)?;
                single_exact_term(&response, &neighbor)
            }) {
                Ok(neighbor_term) => {
                    candidates.entry(neighbor.clone()).or_insert(Candidate {
                        term: neighbor_term.clone(),
                        tier: Tier::Neighbor,
                        score: LexicalScore::default(),
                        reasons: BTreeSet::from([format!("neighbor_depth:{}", depth + 1)]),
                    });
                    queue.push_back((neighbor, neighbor_term, depth + 1));
                }
                Err(code) => diagnostics.push(json!({
                    "code":"neighbor_description_incomplete", "iri":neighbor, "detail":code
                })),
            }
        }
        if limit_hit {
            break;
        }
    }
    if limit_hit {
        diagnostics.push(json!({"code":"neighbor_traversal_limit","complete":false}));
    }
}

fn inherited_metadata(
    host: &dyn OntologyToolHost,
    described_iri: &str,
    direct: &Value,
    captures: &mut BTreeSet<String>,
    limits: &OntologyBriefingLimits,
) -> Value {
    let direct_constraints = projected_constraints(direct, "direct", &[described_iri.to_owned()]);
    let mut inherited = Vec::<Value>::new();
    let mut initial_supers = direct_super_iris(direct);
    initial_supers.sort();
    initial_supers.dedup();
    let mut queue = initial_supers
        .into_iter()
        .map(|iri| (iri.clone(), vec![described_iri.to_owned(), iri], 1usize))
        .collect::<VecDeque<_>>();
    let mut visited = BTreeSet::from([described_iri.to_owned()]);
    let mut complete = constraints_complete(direct);
    let mut limit_reason: Option<&str> = None;
    while let Some((iri, path, depth)) = queue.pop_front() {
        if !visited.insert(iri.clone()) {
            continue;
        }
        if visited.len() > limits.max_ancestor_terms {
            complete = false;
            limit_reason = Some("ancestor_term_limit");
            break;
        }
        if depth > limits.ancestor_depth {
            complete = false;
            limit_reason = Some("ancestor_depth_limit");
            continue;
        }
        match lookup(host, json!({"operation":"describe","query":iri,"limit":20})).and_then(
            |response| {
                capture_source(&response, captures)?;
                single_exact_term(&response, &iri)
            },
        ) {
            Ok(term) => {
                complete &= constraints_complete(&term);
                inherited.extend(projected_constraints(&term, "inherited", &path));
                let mut supers = direct_super_iris(&term);
                supers.sort();
                for parent in supers {
                    let mut parent_path = path.clone();
                    parent_path.push(parent.clone());
                    queue.push_back((parent, parent_path, depth + 1));
                }
            }
            Err(_) => {
                complete = false;
                limit_reason.get_or_insert("ancestor_description_unavailable");
            }
        }
    }
    inherited.sort_by(|left, right| {
        left["origin_path"]
            .to_string()
            .cmp(&right["origin_path"].to_string())
            .then_with(|| {
                left["constraint"]
                    .as_str()
                    .cmp(&right["constraint"].as_str())
            })
            .then_with(|| left["iri"].as_str().cmp(&right["iri"].as_str()))
    });
    json!({
        "direct_constraints":direct_constraints,
        "inherited_constraints":inherited,
        "complete":complete,
        "incomplete_reason":limit_reason,
        "visited_nodes":visited.len()
    })
}

fn projected_constraints(term: &Value, origin: &str, path: &[String]) -> Vec<Value> {
    let mut output = Vec::new();
    for kind in ["domains", "ranges"] {
        if let Some(values) = term
            .pointer(&format!("/constraints/{kind}"))
            .and_then(Value::as_array)
        {
            for value in values {
                if let Some(iri) = value.get("iri").and_then(Value::as_str) {
                    output.push(json!({
                        "constraint":kind,
                        "iri":iri,
                        "origin":origin,
                        "origin_path":path,
                        "source_graphs":value.get("source_graphs").cloned().unwrap_or_else(|| json!([]))
                    }));
                }
            }
        }
    }
    output.sort_by(|left, right| {
        left["constraint"]
            .as_str()
            .cmp(&right["constraint"].as_str())
            .then_with(|| left["iri"].as_str().cmp(&right["iri"].as_str()))
            .then_with(|| {
                left["source_graphs"]
                    .to_string()
                    .cmp(&right["source_graphs"].to_string())
            })
    });
    output
}

fn direct_neighbor_iris(term: &Value) -> Vec<String> {
    let mut output = direct_super_iris(term);
    output.extend(constraint_iris(term));
    if let Some(neighbors) = term.get("neighbors").and_then(Value::as_array) {
        output.extend(
            neighbors
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
    }
    output.retain(|iri| valid_iri(iri));
    output
}

fn direct_super_iris(term: &Value) -> Vec<String> {
    term.get("super_terms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|iri| valid_iri(iri))
        .map(str::to_owned)
        .collect()
}

fn constraint_iris(term: &Value) -> Vec<String> {
    ["domains", "ranges"]
        .into_iter()
        .flat_map(|kind| {
            term.pointer(&format!("/constraints/{kind}"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|value| value.get("iri").and_then(Value::as_str))
        .filter(|iri| valid_iri(iri))
        .map(str::to_owned)
        .collect()
}

fn constraints_complete(term: &Value) -> bool {
    term.pointer("/constraints/complete")
        .and_then(Value::as_bool)
        == Some(true)
}

fn term_kind(term: &Value) -> Option<&str> {
    term.get("kind").and_then(Value::as_str)
}

fn kind_compatible(actual: Option<&str>, expected: &str) -> bool {
    actual == Some(expected) || expected == "property" && is_property(actual)
}

fn is_property(kind: Option<&str>) -> bool {
    matches!(
        kind,
        Some(
            "object_property"
                | "datatype_property"
                | "annotation_property"
                | "generic_property"
                | "conflicting_property"
        )
    )
}

fn context_commitment(
    context: &OntologyBriefingContext<'_>,
) -> Result<String, OntologyBriefingError> {
    let bytes = serde_json::to_vec(&json!({
        "schema":"ctxql-ontology-briefing-context/v1",
        "passage":context.passage,
        "title":context.title,
        "headings":context.headings,
        "grounded_entity_names":context.grounded_entity_names
    }))
    .map_err(|_| OntologyBriefingError::new("briefing_context_encoding_failed"))?;
    Ok(ContentHash::of_bytes(&bytes).as_str().to_owned())
}

fn normalized_context(context: &OntologyBriefingContext<'_>) -> Vec<String> {
    let mut text = String::new();
    if let Some(title) = context.title {
        text.push_str(title);
        text.push(' ');
    }
    for heading in context.headings {
        text.push_str(heading);
        text.push(' ');
    }
    for name in context.grounded_entity_names {
        text.push_str(name);
        text.push(' ');
    }
    text.push_str(context.passage);
    normalize(&text)
}

fn lexical_queries(tokens: &[String], limit: usize) -> (Vec<String>, bool) {
    // A query is an ontology scan, not a cheap tokenizer operation. The old
    // selector issued up to 512 overlapping n-gram scans for one passage. Rank
    // a bounded set across the whole passage instead: frequent informative
    // tokens provide recall, while a smaller phrase allocation disambiguates
    // common labels. Selection is independent of hash-map iteration order.
    const STOP_WORDS: &[&str] = &[
        "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in", "is", "it", "of",
        "on", "or", "that", "the", "this", "to", "was", "were", "with",
    ];
    let mut token_counts = BTreeMap::<String, usize>::new();
    for token in tokens {
        if token.len() >= 3 && !STOP_WORDS.contains(&token.as_str()) {
            *token_counts.entry(token.clone()).or_default() += 1;
        }
    }
    let mut ranked_tokens = token_counts.into_iter().collect::<Vec<_>>();
    ranked_tokens.sort_by(|(left, left_count), (right, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| right.len().cmp(&left.len()))
            .then_with(|| left.cmp(right))
    });

    let mut phrase_counts = BTreeMap::<String, (usize, usize)>::new();
    for width in [3usize, 2] {
        for window in tokens.windows(width) {
            if window
                .iter()
                .all(|token| STOP_WORDS.contains(&token.as_str()))
            {
                continue;
            }
            let query = window.join(" ");
            let entry = phrase_counts.entry(query).or_insert((0, width));
            entry.0 += 1;
        }
    }
    let mut ranked_phrases = phrase_counts.into_iter().collect::<Vec<_>>();
    ranked_phrases.sort_by(
        |(left, (left_count, left_width)), (right, (right_count, right_width))| {
            right_count
                .cmp(left_count)
                .then_with(|| right_width.cmp(left_width))
                .then_with(|| left.cmp(right))
        },
    );

    let available = ranked_tokens.len() + ranked_phrases.len();
    let token_budget = limit.saturating_mul(3) / 4;
    let mut output = ranked_tokens
        .into_iter()
        .take(token_budget.max(1))
        .map(|(query, _)| query)
        .collect::<Vec<_>>();
    output.extend(
        ranked_phrases
            .into_iter()
            .take(limit.saturating_sub(output.len()))
            .map(|(query, _)| query),
    );
    output.truncate(limit);
    (output, available > limit)
}

fn lexical_score(term: &Value, context_tokens: &[String]) -> LexicalScore {
    let context_set = context_tokens.iter().collect::<BTreeSet<_>>();
    let mut best_phrase = 0;
    let mut matched = BTreeSet::<String>::new();
    for text in lexical_texts(term) {
        let tokens = normalize(text);
        for token in &tokens {
            if context_set.contains(token) {
                matched.insert(token.clone());
            }
        }
        if tokens.len() >= 2 && contains_sequence(context_tokens, &tokens) {
            best_phrase = best_phrase.max(tokens.len());
        }
    }
    LexicalScore {
        exact_phrase_tokens: best_phrase,
        distinct_tokens: matched.len(),
    }
}

fn lexical_texts(term: &Value) -> Vec<&str> {
    let mut output = Vec::new();
    if let Some(iri) = term.get("iri").and_then(Value::as_str) {
        if let Some(local) = iri.rsplit(['#', '/', ':']).next() {
            output.push(local);
        }
    }
    for field in ["labels", "aliases"] {
        output.extend(
            term.get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str),
        );
    }
    output
}

fn contains_sequence(haystack: &[String], needle: &[String]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn normalize(value: &str) -> Vec<String> {
    let mut segmented = String::with_capacity(value.len() + 8);
    let mut previous_lower_or_digit = false;
    for character in value.chars() {
        if character.is_uppercase() && previous_lower_or_digit {
            segmented.push(' ');
        }
        for lower in character.to_lowercase() {
            segmented.push(lower);
        }
        previous_lower_or_digit = character.is_lowercase() || character.is_numeric();
    }
    segmented
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
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

    #[test]
    fn lexical_lookup_count_is_bounded_and_uses_the_whole_context() {
        let tokens = normalize(
            "agreement borrower borrower maturity date the facility lender execution collateral",
        );
        let (queries, truncated) = lexical_queries(&tokens, 4);
        assert_eq!(queries.len(), 4);
        assert!(truncated);
        assert_eq!(queries[0], "borrower");
        assert!(queries.iter().any(|query| query == "agreement"));
    }

    #[test]
    fn lexical_query_limit_is_part_of_limit_validation() {
        let limits = OntologyBriefingLimits {
            max_lexical_queries: 129,
            ..OntologyBriefingLimits::default()
        };
        assert_eq!(
            validate_limits(&limits),
            Err(OntologyBriefingError::new("briefing_limits_invalid"))
        );
    }
}
