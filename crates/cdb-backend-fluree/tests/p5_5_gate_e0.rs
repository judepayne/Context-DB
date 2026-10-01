#[path = "p5_5_support/mod.rs"]
mod p5_5_support;

use cdb_core::id::ContentHash;
use fluree_db_api::{
    config_resolver, ontology_imports, policy_builder, Fluree, FlureeBuilder, GovernanceOptions,
    LedgerState, Novelty,
};
use fluree_db_core::{
    ledger_config::OverrideControl, DatatypeConstraint, FlakeValue, GraphDbRef, GraphId,
    LedgerSnapshot,
};
use fluree_db_query::{
    execute, execute_pattern, Binding, ContextConfig, ExecutableQuery, Pattern, Query, QueryOutput,
    QueryPolicyEnforcer, Ref, SortSpec, Term, TriplePattern, VarId, VarRegistry,
};
use p5_5_support::{
    framed_root, AuthorizedCounts, AuthorizedPremiseRoot, AuthorizedViewManifest,
    ExactTerm as ManifestTerm, ExecutionManifestRoot, OperationalScanStats, ReasoningDescriptor,
    SemanticCaptureDescriptor, SourceQuad,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

const EX: &str = "http://example.org/";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_JSON: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON";
const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
const CLAIM: &str = "https://ctxql.example/vocab#Claim";
const CTXQL: &str = "https://ctxql.example/vocab#";
const REQUIRED_CLAIM_PREDICATES: [&str; 9] = [
    RDF_TYPE,
    "https://ctxql.example/vocab#relationType",
    "https://ctxql.example/vocab#subjectType",
    "https://ctxql.example/vocab#objectType",
    "https://ctxql.example/vocab#claimType",
    "https://ctxql.example/vocab#confidence",
    "https://ctxql.example/vocab#groundingLevel",
    "https://ctxql.example/vocab#lineage",
    "https://ctxql.example/vocab#extensions",
];
const CLAIMS_GRAPH: &str = "http://example.org/graphs/claims";
const DATA_GRAPH: &str = "http://example.org/graphs/data";
const ONTOLOGY_GRAPH: &str = "http://example.org/graphs/ontology";
const IMPORTED_ONTOLOGY_GRAPH: &str = "http://example.org/graphs/imported-ontology";
const POLICY_GRAPH: &str = "http://example.org/graphs/policy";
const FLUREE_LEDGER_CONFIG: &str = "https://ns.flur.ee/db#LedgerConfig";
const FLUREE_ON_CLASS: &str = "https://ns.flur.ee/db#onClass";
const FLUREE_QUERY: &str = "https://ns.flur.ee/db#query";

fn genesis(ledger: &str) -> LedgerState {
    LedgerState::new(LedgerSnapshot::genesis(ledger), Novelty::new(0))
}

async fn apply_trig(fluree: &Fluree, ledger: LedgerState, trig: &str) -> LedgerState {
    fluree
        .stage_owned(ledger)
        .upsert_turtle(trig)
        .execute()
        .await
        .expect("TriG stage")
        .ledger
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RdfTerm {
    Iri(String),
    Literal {
        lexical: String,
        datatype: String,
        language: Option<String>,
    },
}

impl RdfTerm {
    fn commitment(&self) -> String {
        match self {
            Self::Iri(iri) => format!("I{}:{iri}", iri.len()),
            Self::Literal {
                lexical,
                datatype,
                language,
            } => format!(
                "L{}:{}:{}:{}:{}",
                lexical.len(),
                lexical,
                datatype.len(),
                datatype,
                language.as_deref().unwrap_or("")
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Quad {
    graph: String,
    subject: String,
    predicate: String,
    object: RdfTerm,
}

impl Quad {
    fn commitment(&self) -> String {
        format!(
            "G{}:{}S{}:{}P{}:{}O{}",
            self.graph.len(),
            self.graph,
            self.subject.len(),
            self.subject,
            self.predicate.len(),
            self.predicate,
            self.object.commitment()
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Proposition {
    graph: String,
    subject: String,
    predicate: String,
    object: RdfTerm,
}

impl Proposition {
    fn as_quad(&self) -> Quad {
        Quad {
            graph: self.graph.clone(),
            subject: self.subject.clone(),
            predicate: self.predicate.clone(),
            object: self.object.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct Attachment {
    claim: String,
    proposition: Proposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScanLimits {
    page_size: usize,
    max_pages: usize,
    max_rows: usize,
    max_bytes: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            page_size: 2,
            max_pages: 64,
            max_rows: 1024,
            max_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SemanticCapture {
    requested_as_of: String,
    ledger: String,
    t: i64,
    commit_cid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SemanticPolicyMode {
    Unrestricted,
    Configured,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SemanticPolicyBasis {
    mode: SemanticPolicyMode,
    dependency_root: ContentHash,
    principal: String,
    action: String,
    source_observation: String,
}

#[derive(Clone)]
struct CurrentSemanticAuthority {
    current: Arc<Mutex<LedgerState>>,
    ledger_id: String,
    principal: String,
    action: String,
}

#[derive(Clone)]
struct ResolvedSemanticAuthority {
    basis: SemanticPolicyBasis,
    enforcer: Option<Arc<QueryPolicyEnforcer>>,
}

#[derive(Clone)]
struct PolicyRefresh {
    resolved: ResolvedSemanticAuthority,
    authority: CurrentSemanticAuthority,
    checks: Arc<AtomicUsize>,
    change_at_check: Option<(usize, LedgerState)>,
    stats: Arc<Mutex<OperationalScanStats>>,
}

impl PolicyRefresh {
    fn stable(resolved: ResolvedSemanticAuthority, authority: CurrentSemanticAuthority) -> Self {
        Self {
            resolved,
            authority,
            checks: Arc::new(AtomicUsize::new(0)),
            change_at_check: None,
            stats: Arc::new(Mutex::new(OperationalScanStats::default())),
        }
    }

    fn changing(
        resolved: ResolvedSemanticAuthority,
        authority: CurrentSemanticAuthority,
        check: usize,
        replacement: LedgerState,
    ) -> Self {
        Self {
            resolved,
            authority,
            checks: Arc::new(AtomicUsize::new(0)),
            change_at_check: Some((check, replacement)),
            stats: Arc::new(Mutex::new(OperationalScanStats::default())),
        }
    }

    fn enforcer(&self) -> Option<Arc<QueryPolicyEnforcer>> {
        self.resolved.enforcer.clone()
    }

    async fn verify_current(&self) -> Result<(), String> {
        let check = self.checks.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some((change_at, replacement)) = &self.change_at_check {
            if check == *change_at {
                *self.authority.current.lock().expect("policy source lock") = replacement.clone();
            }
        }
        let current = resolve_current_semantic_authority(&self.authority).await?;
        if current.basis.dependency_root != self.resolved.basis.dependency_root {
            return Err("semantic_policy_changed".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GraphRoles {
    governed_data: BTreeSet<String>,
    claim_graphs: BTreeSet<String>,
    infrastructure: BTreeSet<String>,
}

struct QueryShape {
    vars: VarRegistry,
    patterns: Vec<Pattern>,
    output: Vec<VarId>,
    ordering: Vec<SortSpec>,
}

fn triple_shape() -> QueryShape {
    let mut vars = VarRegistry::new();
    let subject = vars.get_or_insert("?s");
    let predicate = vars.get_or_insert("?p");
    let object = vars.get_or_insert("?o");
    QueryShape {
        vars,
        patterns: vec![Pattern::Triple(TriplePattern::new(
            Ref::Var(subject),
            Ref::Var(predicate),
            Term::Var(object),
        ))],
        output: vec![subject, predicate, object],
        ordering: vec![
            SortSpec::asc(subject),
            SortSpec::asc(predicate),
            SortSpec::asc(object),
        ],
    }
}

fn iri_object_shape(predicate_iri: &str) -> QueryShape {
    let mut vars = VarRegistry::new();
    let subject = vars.get_or_insert("?s");
    let object = vars.get_or_insert("?o");
    QueryShape {
        vars,
        patterns: vec![Pattern::Triple(TriplePattern::new(
            Ref::Var(subject),
            Ref::Iri(Arc::from(predicate_iri)),
            Term::Var(object),
        ))],
        output: vec![subject, object],
        ordering: vec![SortSpec::asc(subject), SortSpec::asc(object)],
    }
}

fn attachment_shape() -> QueryShape {
    let mut vars = VarRegistry::new();
    let subject = vars.get_or_insert("?s");
    let predicate = vars.get_or_insert("?p");
    let object = vars.get_or_insert("?o");
    let annotation = vars.get_or_insert("?annotation");
    QueryShape {
        vars,
        patterns: vec![Pattern::EdgeAnnotation {
            edge: TriplePattern::new(Ref::Var(subject), Ref::Var(predicate), Term::Var(object)),
            annotation: Ref::Var(annotation),
            body: Vec::new(),
        }],
        output: vec![subject, predicate, object, annotation],
        ordering: vec![
            SortSpec::asc(subject),
            SortSpec::asc(predicate),
            SortSpec::asc(object),
            SortSpec::asc(annotation),
        ],
    }
}

fn decode_iri(snapshot: &LedgerSnapshot, binding: &Binding) -> Result<String, String> {
    match binding {
        Binding::Sid { sid, .. } => snapshot
            .decode_sid(sid)
            .ok_or_else(|| "undecodable SID".to_string()),
        Binding::Iri(iri) | Binding::IriMatch { iri, .. } => Ok(iri.to_string()),
        Binding::EncodedSid { .. } | Binding::EncodedPid { .. } => {
            Err("late materialization escaped eager extraction".into())
        }
        _ => Err("expected IRI binding".into()),
    }
}

fn decode_term(snapshot: &LedgerSnapshot, binding: &Binding) -> Result<RdfTerm, String> {
    match binding {
        Binding::Sid { .. } | Binding::Iri(_) | Binding::IriMatch { .. } => {
            decode_iri(snapshot, binding).map(RdfTerm::Iri)
        }
        Binding::Lit { val, dtc, .. } => {
            let lexical = match val {
                FlakeValue::String(value) | FlakeValue::Json(value) => value.clone(),
                FlakeValue::Decimal(value) => value.to_plain_string(),
                // Fluree exposes value semantics, not the authoritative source
                // lexical form, for these variants. The POC rejects them rather
                // than claiming an exact RDF round-trip it cannot prove.
                FlakeValue::DateTime(value) => value.to_string(),
                FlakeValue::Boolean(_)
                | FlakeValue::Long(_)
                | FlakeValue::Double(_)
                | FlakeValue::BigInt(_)
                | FlakeValue::Date(_)
                | FlakeValue::Time(_)
                | FlakeValue::GYear(_)
                | FlakeValue::GYearMonth(_)
                | FlakeValue::GMonth(_)
                | FlakeValue::GDay(_)
                | FlakeValue::GMonthDay(_)
                | FlakeValue::YearMonthDuration(_)
                | FlakeValue::DayTimeDuration(_)
                | FlakeValue::Duration(_)
                | FlakeValue::Vector(_)
                | FlakeValue::GeoPoint(_)
                | FlakeValue::Null
                | FlakeValue::Ref(_) => return Err("unsupported_exact_literal".into()),
            };
            let (datatype, language) = match dtc {
                DatatypeConstraint::Explicit(datatype) => (
                    snapshot
                        .decode_sid(datatype)
                        .ok_or_else(|| "undecodable datatype".to_string())?,
                    None,
                ),
                DatatypeConstraint::LangTag(language) => {
                    (RDF_LANG_STRING.to_string(), Some(language.to_string()))
                }
            };
            Ok(RdfTerm::Literal {
                lexical,
                datatype,
                language,
            })
        }
        Binding::EncodedLit { .. } => Err("late literal escaped eager extraction".into()),
        _ => Err("unsupported RDF result binding".into()),
    }
}

fn decode_policy_term(snapshot: &LedgerSnapshot, binding: &Binding) -> Result<RdfTerm, String> {
    if let Binding::Lit {
        val: FlakeValue::Boolean(value),
        dtc,
        ..
    } = binding
    {
        let DatatypeConstraint::Explicit(datatype) = dtc else {
            return Err("semantic_policy_unavailable".into());
        };
        return Ok(RdfTerm::Literal {
            lexical: value.to_string(),
            datatype: snapshot
                .decode_sid(datatype)
                .ok_or_else(|| "semantic_policy_unavailable".to_string())?,
            language: None,
        });
    }
    decode_term(snapshot, binding)
}

fn override_commitment(value: &OverrideControl) -> String {
    match value {
        OverrideControl::None => "none".into(),
        OverrideControl::AllowAll => "allow-all".into(),
        OverrideControl::IdentityRestricted { allowed_identities } => {
            let mut identities = allowed_identities
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            identities.sort();
            format!("identity-restricted:{}", identities.join(","))
        }
    }
}

async fn graph_dependency_members(
    ledger: &LedgerState,
    graph: GraphId,
    graph_iri: &str,
) -> Result<BTreeSet<Quad>, String> {
    let mut vars = VarRegistry::new();
    let subject = vars.get_or_insert("?s");
    let predicate = vars.get_or_insert("?p");
    let object = vars.get_or_insert("?o");
    let batches = execute_pattern(
        GraphDbRef::new(&ledger.snapshot, graph, ledger.novelty.as_ref(), ledger.t()).eager(),
        &vars,
        TriplePattern::new(Ref::Var(subject), Ref::Var(predicate), Term::Var(object)),
    )
    .await
    .map_err(|_| "semantic_policy_unavailable".to_string())?;
    let mut members = BTreeSet::new();
    for batch in batches {
        for row in 0..batch.len() {
            members.insert(Quad {
                graph: graph_iri.into(),
                subject: decode_iri(
                    &ledger.snapshot,
                    batch
                        .get(row, subject)
                        .ok_or_else(|| "semantic_policy_unavailable".to_string())?,
                )?,
                predicate: decode_iri(
                    &ledger.snapshot,
                    batch
                        .get(row, predicate)
                        .ok_or_else(|| "semantic_policy_unavailable".to_string())?,
                )?,
                object: decode_policy_term(
                    &ledger.snapshot,
                    batch
                        .get(row, object)
                        .ok_or_else(|| "semantic_policy_unavailable".to_string())?,
                )?,
            });
        }
    }
    if members.len() > 256 {
        return Err("semantic_policy_unavailable".into());
    }
    Ok(members)
}

async fn resolve_current_semantic_authority(
    authority: &CurrentSemanticAuthority,
) -> Result<ResolvedSemanticAuthority, String> {
    let ledger = authority
        .current
        .lock()
        .map_err(|_| "semantic_policy_unavailable".to_string())?
        .clone();
    if ledger.snapshot.ledger_id != authority.ledger_id {
        return Err("semantic_policy_unavailable".into());
    }
    let config_graph_iri = fluree_db_core::graph_registry::config_graph_iri(&authority.ledger_id);
    let config_graph = ledger
        .snapshot
        .graph_registry
        .graph_id_for_iri(&config_graph_iri)
        .ok_or_else(|| "semantic_policy_unavailable".to_string())?;
    let config_members = graph_dependency_members(&ledger, config_graph, &config_graph_iri).await?;
    let config_resources = config_members
        .iter()
        .filter(|quad| {
            quad.predicate == RDF_TYPE && quad.object == RdfTerm::Iri(FLUREE_LEDGER_CONFIG.into())
        })
        .count();
    if config_resources > 1 {
        return Err("semantic_policy_unavailable".into());
    }
    let source_observation = ledger
        .head_commit_id
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("t:{}", ledger.t()));
    let raw = config_resolver::resolve_ledger_config(
        &ledger.snapshot,
        ledger.novelty.as_ref(),
        ledger.t(),
    )
    .await
    .map_err(|_| "semantic_policy_unavailable".to_string())?;
    let Some(config) = raw else {
        let dependency_root = framed_root(
            "ctxql-semantic-policy-basis/v1",
            [
                ("ledger", authority.ledger_id.as_str()),
                ("principal", authority.principal.as_str()),
                ("action", authority.action.as_str()),
                ("mode", "unrestricted:no-configured-policy"),
            ],
        );
        return Ok(ResolvedSemanticAuthority {
            basis: SemanticPolicyBasis {
                mode: SemanticPolicyMode::Unrestricted,
                dependency_root,
                principal: authority.principal.clone(),
                action: authority.action.clone(),
                source_observation,
            },
            enforcer: None,
        });
    };
    let effective = config_resolver::resolve_effective_config(&config, None);
    let Some(policy) = effective.policy.as_ref() else {
        let dependency_root = framed_root(
            "ctxql-semantic-policy-basis/v1",
            [
                ("ledger", authority.ledger_id.as_str()),
                ("principal", authority.principal.as_str()),
                ("action", authority.action.as_str()),
                ("mode", "unrestricted:no-configured-policy"),
            ],
        );
        return Ok(ResolvedSemanticAuthority {
            basis: SemanticPolicyBasis {
                mode: SemanticPolicyMode::Unrestricted,
                dependency_root,
                principal: authority.principal.clone(),
                action: authority.action.clone(),
                source_observation,
            },
            enforcer: None,
        });
    };
    let source = policy
        .policy_source
        .as_ref()
        .ok_or_else(|| "semantic_policy_unavailable".to_string())?;
    let graph_iri = source
        .graph_selector
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "@default")
        .ok_or_else(|| "semantic_policy_unavailable".to_string())?;
    let policy_graphs = policy_builder::resolve_policy_source_g_ids(Some(source), &ledger.snapshot)
        .map_err(|_| "semantic_policy_unavailable".to_string())?;
    if policy_graphs.len() != 1 {
        return Err("semantic_policy_unavailable".into());
    }
    let effective_options =
        config_resolver::merge_policy_opts(&effective, &GovernanceOptions::default());
    if !effective_options.has_any_policy_inputs() {
        return Err("semantic_policy_unavailable".into());
    }
    let policy_members = graph_dependency_members(&ledger, policy_graphs[0], graph_iri).await?;
    if policy_members.is_empty()
        || policy_members
            .iter()
            .any(|quad| matches!(quad.predicate.as_str(), FLUREE_ON_CLASS | FLUREE_QUERY))
    {
        return Err("semantic_policy_unavailable".into());
    }
    let policy_commitments = policy_members
        .iter()
        .map(Quad::commitment)
        .collect::<Vec<_>>();
    let policy_graph_root = framed_root(
        "ctxql-policy-graph/v1",
        policy_commitments
            .iter()
            .map(|commitment| ("member", commitment.as_str())),
    );
    let mut classes = policy.policy_class.clone().unwrap_or_default();
    classes.sort();
    let classes = classes.join(",");
    let default_allow = policy
        .default_allow
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unset".into());
    let override_control = override_commitment(&policy.override_control);
    let dependency_root = framed_root(
        "ctxql-semantic-policy-basis/v1",
        [
            ("ledger", authority.ledger_id.as_str()),
            ("principal", authority.principal.as_str()),
            ("action", authority.action.as_str()),
            ("mode", "configured"),
            ("source", graph_iri),
            ("classes", classes.as_str()),
            ("default-allow", default_allow.as_str()),
            ("override", override_control.as_str()),
            ("policy-members", policy_graph_root.as_str()),
        ],
    );
    let policy_context = policy_builder::build_policy_context_from_opts(
        &ledger.snapshot,
        ledger.novelty.as_ref(),
        Some(ledger.novelty.as_ref()),
        ledger.t(),
        &effective_options,
        &policy_graphs,
    )
    .await
    .map_err(|_| "semantic_policy_unavailable".to_string())?;
    Ok(ResolvedSemanticAuthority {
        basis: SemanticPolicyBasis {
            mode: SemanticPolicyMode::Configured,
            dependency_root,
            principal: authority.principal.clone(),
            action: authority.action.clone(),
            source_observation,
        },
        enforcer: Some(Arc::new(QueryPolicyEnforcer::new(Arc::new(policy_context)))),
    })
}

async fn paged_rows(
    ledger: &LedgerState,
    graph: GraphId,
    enforcer: Option<Arc<QueryPolicyEnforcer>>,
    shape: &QueryShape,
    limits: ScanLimits,
    refresh: &PolicyRefresh,
) -> Result<Vec<Vec<Binding>>, String> {
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    let mut offset = 0usize;
    let mut bytes = 0usize;
    let mut pages = 0usize;
    loop {
        refresh.verify_current().await?;
        pages += 1;
        refresh.stats.lock().expect("extraction stats").pages += 1;
        if pages > limits.max_pages {
            return Err("authorized_view_incomplete: page limit".into());
        }
        let mut query = Query::new(Default::default());
        query.output = QueryOutput::select_all(shape.output.clone());
        query.patterns = shape.patterns.clone();
        query.ordering = shape.ordering.clone();
        query.limit = Some(limits.page_size);
        query.offset = Some(offset);
        assert!(
            !query.reasoning.modes.has_any_enabled(),
            "E0 extraction must never enable reasoning"
        );
        let executable = ExecutableQuery::simple(query);
        let config = ContextConfig {
            policy_enforcer: enforcer.clone(),
            ..ContextConfig::default()
        };
        let batches = tokio::time::timeout(
            Duration::from_secs(2),
            execute(
                GraphDbRef::new(&ledger.snapshot, graph, ledger.novelty.as_ref(), ledger.t())
                    .eager(),
                &shape.vars,
                &executable,
                config,
            ),
        )
        .await
        .map_err(|_| "authorized_view_incomplete: query timeout".to_string())?
        .map_err(|error| format!("authorized_view_incomplete: {error}"))?;
        refresh.verify_current().await?;
        let mut page = Vec::new();
        for batch in batches {
            for row in 0..batch.len() {
                let values = shape
                    .output
                    .iter()
                    .map(|var| {
                        batch
                            .get(row, *var)
                            .cloned()
                            .ok_or_else(|| "missing projected binding".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let key = format!("{values:?}");
                if !seen.insert(key.clone()) {
                    return Err("authorized_view_incomplete: duplicate/nonprogress row".into());
                }
                bytes = bytes
                    .checked_add(key.len())
                    .ok_or_else(|| "authorized_view_incomplete: byte overflow".to_string())?;
                if bytes > limits.max_bytes {
                    return Err("authorized_view_incomplete: byte limit".into());
                }
                {
                    let mut stats = refresh.stats.lock().expect("extraction stats");
                    stats.rows += 1;
                    stats.bytes += key.len();
                }
                page.push(values);
            }
        }
        if page.is_empty() {
            break;
        }
        offset = offset
            .checked_add(page.len())
            .ok_or_else(|| "authorized_view_incomplete: offset overflow".to_string())?;
        rows.extend(page);
        if rows.len() > limits.max_rows {
            return Err("authorized_view_incomplete: row limit".into());
        }
        // Continue even after a short page. Completion is proven only by an
        // explicit empty terminal page against the same immutable capture.
    }
    Ok(rows)
}

async fn scan_quads(
    ledger: &LedgerState,
    graph_iri: &str,
    enforcer: Option<Arc<QueryPolicyEnforcer>>,
    limits: ScanLimits,
    refresh: &PolicyRefresh,
) -> Result<BTreeSet<Quad>, String> {
    let graph = ledger
        .snapshot
        .graph_registry
        .graph_id_for_iri(graph_iri)
        .ok_or_else(|| format!("unknown graph {graph_iri}"))?;
    paged_rows(ledger, graph, enforcer, &triple_shape(), limits, refresh)
        .await?
        .into_iter()
        .map(|row| {
            Ok(Quad {
                graph: graph_iri.to_string(),
                subject: decode_iri(&ledger.snapshot, &row[0])?,
                predicate: decode_iri(&ledger.snapshot, &row[1])?,
                object: decode_term(&ledger.snapshot, &row[2])?,
            })
        })
        .collect()
}

async fn scan_infrastructure_quads(
    ledger: &LedgerState,
    graph_iri: &str,
    enforcer: Option<Arc<QueryPolicyEnforcer>>,
    limits: ScanLimits,
    refresh: &PolicyRefresh,
) -> Result<BTreeSet<Quad>, String> {
    let graph = ledger
        .snapshot
        .graph_registry
        .graph_id_for_iri(graph_iri)
        .ok_or_else(|| format!("unknown graph {graph_iri}"))?;
    paged_rows(ledger, graph, enforcer, &triple_shape(), limits, refresh)
        .await?
        .into_iter()
        .map(|row| {
            Ok(Quad {
                graph: graph_iri.to_string(),
                subject: decode_iri(&ledger.snapshot, &row[0])?,
                predicate: decode_iri(&ledger.snapshot, &row[1])?,
                object: decode_policy_term(&ledger.snapshot, &row[2])?,
            })
        })
        .collect()
}

async fn scan_attachments(
    ledger: &LedgerState,
    graph_iri: &str,
    enforcer: Option<Arc<QueryPolicyEnforcer>>,
    limits: ScanLimits,
    refresh: &PolicyRefresh,
) -> Result<Vec<Attachment>, String> {
    let graph = ledger
        .snapshot
        .graph_registry
        .graph_id_for_iri(graph_iri)
        .ok_or_else(|| format!("unknown graph {graph_iri}"))?;
    paged_rows(
        ledger,
        graph,
        enforcer,
        &attachment_shape(),
        limits,
        refresh,
    )
    .await?
    .into_iter()
    .map(|row| {
        Ok(Attachment {
            claim: decode_iri(&ledger.snapshot, &row[3])?,
            proposition: Proposition {
                graph: graph_iri.to_string(),
                subject: decode_iri(&ledger.snapshot, &row[0])?,
                predicate: decode_iri(&ledger.snapshot, &row[1])?,
                object: decode_term(&ledger.snapshot, &row[2])?,
            },
        })
    })
    .collect()
}

async fn config_iri_values(
    ledger: &LedgerState,
    predicate: &str,
    limits: ScanLimits,
    refresh: &PolicyRefresh,
) -> Result<BTreeSet<String>, String> {
    let config_graph = fluree_db_core::graph_registry::config_graph_iri(&ledger.snapshot.ledger_id);
    let graph = ledger
        .snapshot
        .graph_registry
        .graph_id_for_iri(&config_graph)
        .ok_or_else(|| "graph_role_map_invalid".to_string())?;
    paged_rows(
        ledger,
        graph,
        None,
        &iri_object_shape(predicate),
        limits,
        refresh,
    )
    .await?
    .into_iter()
    .map(|row| decode_iri(&ledger.snapshot, &row[1]))
    .collect()
}

async fn resolve_graph_roles(
    ledger: &LedgerState,
    limits: ScanLimits,
    refresh: &PolicyRefresh,
) -> Result<GraphRoles, String> {
    let roles = GraphRoles {
        governed_data: config_iri_values(
            ledger,
            &format!("{CTXQL}governedDataGraph"),
            limits,
            refresh,
        )
        .await?,
        claim_graphs: config_iri_values(ledger, &format!("{CTXQL}claimGraph"), limits, refresh)
            .await?,
        infrastructure: config_iri_values(
            ledger,
            &format!("{CTXQL}infrastructureGraph"),
            limits,
            refresh,
        )
        .await?,
    };
    if roles.governed_data.is_empty()
        || roles.claim_graphs.is_empty()
        || !roles.claim_graphs.is_subset(&roles.governed_data)
        || !roles.governed_data.is_disjoint(&roles.infrastructure)
    {
        return Err("graph_role_map_invalid".into());
    }
    Ok(roles)
}

fn is_profile_predicate(predicate: &str) -> bool {
    REQUIRED_CLAIM_PREDICATES.contains(&predicate)
        || predicate == format!("{CTXQL}validTime")
        || predicate == format!("{CTXQL}sourceObservedAt")
}

fn decimal_in_unit_interval(lexical: &str) -> bool {
    if lexical.is_empty() || lexical.contains(['e', 'E']) {
        return false;
    }
    let unsigned = lexical.strip_prefix('+').unwrap_or(lexical);
    let (negative, unsigned) = match unsigned.strip_prefix('-') {
        Some(value) => (true, value),
        None => (false, unsigned),
    };
    let mut parts = unsigned.split('.');
    let integer = parts.next().unwrap_or("");
    let fraction = parts.next();
    if parts.next().is_some()
        || (integer.is_empty() && fraction.is_none())
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || fraction
            .is_some_and(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    let integer = integer.trim_start_matches('0');
    let fraction_nonzero = fraction.is_some_and(|part| part.bytes().any(|byte| byte != b'0'));
    if negative {
        return integer.is_empty() && !fraction_nonzero;
    }
    integer.is_empty() || (integer == "1" && !fraction_nonzero)
}

fn parse_canonical_json(lexical: &str) -> Result<cdb_core::CanonicalValue, String> {
    let parsed = cdb_core::CanonicalValue::parse(lexical.as_bytes(), cdb_core::Limits::default())
        .map_err(|_| "claim_profile_invalid".to_string())?;
    let canonical = parsed
        .canonical_bytes(cdb_core::Limits::default())
        .map_err(|_| "claim_profile_invalid".to_string())?;
    if canonical != lexical.as_bytes() {
        return Err("claim_profile_invalid".into());
    }
    Ok(parsed)
}

fn validate_lineage(grounding: &str, lineage: &cdb_core::CanonicalValue) -> bool {
    let Ok(lineage) = cdb_core::evidence::Lineage::from_value(lineage) else {
        return false;
    };
    match grounding.strip_prefix(CTXQL) {
        Some("ClaimOnly") => lineage.sources().is_empty(),
        Some("SourceLineageAvailable") => !lineage.sources().is_empty(),
        Some("SourceSpansAvailable") => {
            !lineage.sources().is_empty()
                && lineage.sources().iter().all(|source| source.has_span())
        }
        _ => false,
    }
}

fn validate_claim_profile(
    marked: &BTreeSet<String>,
    facts: &BTreeMap<String, BTreeSet<Quad>>,
    attachments: &[Attachment],
) -> Result<BTreeMap<String, Proposition>, String> {
    let mut targets: BTreeMap<String, Vec<Proposition>> = BTreeMap::new();
    for attachment in attachments {
        if marked.contains(&attachment.claim) {
            targets
                .entry(attachment.claim.clone())
                .or_default()
                .push(attachment.proposition.clone());
        }
    }

    let mut complete = BTreeMap::new();
    for claim in marked {
        let metadata = facts
            .get(claim)
            .ok_or_else(|| "claim_profile_invalid".to_string())?;
        let claim_targets = targets
            .get(claim)
            .ok_or_else(|| "claim_profile_invalid".to_string())?;
        if claim_targets.len() != 1
            || metadata
                .iter()
                .filter(|quad| is_profile_predicate(&quad.predicate))
                .any(|quad| quad.graph != claim_targets[0].graph)
            || claim.starts_with("_:")
            || !claim.contains(':')
        {
            return Err("claim_profile_invalid".into());
        }
        for predicate in REQUIRED_CLAIM_PREDICATES {
            let count = if predicate == RDF_TYPE {
                metadata
                    .iter()
                    .filter(|quad| {
                        quad.predicate == RDF_TYPE && quad.object == RdfTerm::Iri(CLAIM.into())
                    })
                    .count()
            } else {
                metadata
                    .iter()
                    .filter(|quad| quad.predicate == predicate)
                    .count()
            };
            if count != 1 {
                return Err("claim_profile_invalid".into());
            }
        }
        for predicate in ["validTime", "sourceObservedAt"] {
            if metadata
                .iter()
                .filter(|quad| quad.predicate == format!("{CTXQL}{predicate}"))
                .count()
                > 1
            {
                return Err("claim_profile_invalid".into());
            }
        }
        if metadata
            .iter()
            .any(|quad| quad.predicate.starts_with(CTXQL) && !is_profile_predicate(&quad.predicate))
        {
            return Err("claim_profile_invalid".into());
        }
        let marker = metadata
            .iter()
            .find(|quad| quad.predicate == RDF_TYPE)
            .expect("cardinality checked");
        if marker.object != RdfTerm::Iri(CLAIM.into()) {
            return Err("claim_profile_invalid".into());
        }
        for predicate in [
            "relationType",
            "subjectType",
            "objectType",
            "claimType",
            "groundingLevel",
        ] {
            let object = &metadata
                .iter()
                .find(|quad| quad.predicate == format!("{CTXQL}{predicate}"))
                .expect("cardinality checked")
                .object;
            if !matches!(object, RdfTerm::Iri(_)) {
                return Err("claim_profile_invalid".into());
            }
        }
        let claim_type = &metadata
            .iter()
            .find(|quad| quad.predicate == format!("{CTXQL}claimType"))
            .expect("cardinality checked")
            .object;
        if claim_type == &RdfTerm::Iri(CLAIM.into()) {
            return Err("claim_profile_invalid".into());
        }
        let grounding = match &metadata
            .iter()
            .find(|quad| quad.predicate == format!("{CTXQL}groundingLevel"))
            .expect("cardinality checked")
            .object
        {
            RdfTerm::Iri(iri)
                if [
                    format!("{CTXQL}ClaimOnly"),
                    format!("{CTXQL}SourceLineageAvailable"),
                    format!("{CTXQL}SourceSpansAvailable"),
                ]
                .contains(iri) =>
            {
                iri.as_str()
            }
            _ => return Err("claim_profile_invalid".into()),
        };
        let confidence = &metadata
            .iter()
            .find(|quad| quad.predicate == format!("{CTXQL}confidence"))
            .expect("cardinality checked")
            .object;
        let RdfTerm::Literal {
            lexical,
            datatype,
            language: None,
        } = confidence
        else {
            return Err("claim_profile_invalid".into());
        };
        if datatype != "http://www.w3.org/2001/XMLSchema#decimal"
            || !decimal_in_unit_interval(lexical)
        {
            return Err("claim_profile_invalid".into());
        }
        for predicate in ["lineage", "extensions"] {
            let object = &metadata
                .iter()
                .find(|quad| quad.predicate == format!("{CTXQL}{predicate}"))
                .expect("cardinality checked")
                .object;
            let RdfTerm::Literal {
                lexical,
                datatype,
                language: None,
            } = object
            else {
                return Err("claim_profile_invalid".into());
            };
            let parsed = parse_canonical_json(lexical)?;
            if datatype != RDF_JSON
                || (predicate == "extensions"
                    && !matches!(parsed, cdb_core::CanonicalValue::Object(_)))
                || (predicate == "lineage" && !validate_lineage(grounding, &parsed))
            {
                return Err("claim_profile_invalid".into());
            }
        }
        for predicate in ["validTime", "sourceObservedAt"] {
            if let Some(timestamp) = metadata
                .iter()
                .find(|quad| quad.predicate == format!("{CTXQL}{predicate}"))
            {
                let RdfTerm::Literal {
                    lexical,
                    datatype,
                    language: None,
                } = &timestamp.object
                else {
                    return Err("claim_profile_invalid".into());
                };
                if datatype != "http://www.w3.org/2001/XMLSchema#dateTime"
                    || cdb_core::Timestamp::parse(lexical).is_err()
                {
                    return Err("claim_profile_invalid".into());
                }
            }
        }
        complete.insert(claim.clone(), claim_targets[0].clone());
    }
    if complete.len() != marked.len() {
        return Err("claim_profile_invalid".into());
    }
    Ok(complete)
}

#[derive(Debug, Eq, PartialEq)]
struct Extraction {
    semantic_capture: SemanticCapture,
    policy_basis: SemanticPolicyBasis,
    graph_roles: GraphRoles,
    extraction_version: &'static str,
    limits: ScanLimits,
    authorized_counts: AuthorizedCounts,
    data: BTreeSet<Quad>,
    schema: BTreeSet<Quad>,
    visible_supports: BTreeSet<String>,
    data_root: ContentHash,
    schema_root: ContentHash,
    historical_config_root: ContentHash,
    authorized_premise_root: AuthorizedPremiseRoot,
    execution_manifest_root: ExecutionManifestRoot,
    manifest: AuthorizedViewManifest,
}

fn root<'a>(members: impl IntoIterator<Item = &'a Quad>) -> ContentHash {
    let mut bytes = Vec::new();
    for member in members {
        let commitment = member.commitment();
        bytes.extend_from_slice(commitment.len().to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(commitment.as_bytes());
    }
    ContentHash::of_bytes(&bytes)
}

fn manifest_quad(quad: &Quad) -> SourceQuad {
    SourceQuad {
        graph: quad.graph.clone(),
        subject: quad.subject.clone().into(),
        predicate: quad.predicate.clone(),
        object: match &quad.object {
            RdfTerm::Iri(iri) => ManifestTerm::Iri(iri.clone()),
            RdfTerm::Literal {
                lexical,
                datatype,
                language,
            } => ManifestTerm::Literal {
                lexical: lexical.clone(),
                datatype: datatype.clone(),
                language: language.clone(),
            },
        },
    }
}

async fn extract(
    ledger: &LedgerState,
    limits: ScanLimits,
    refresh: &PolicyRefresh,
) -> Result<Extraction, String> {
    refresh.verify_current().await?;
    let enforcer = refresh.enforcer();
    let graph_roles = resolve_graph_roles(ledger, limits, refresh).await?;
    let mut unrestricted_claim_facts = BTreeSet::new();
    let mut visible_claim_facts = BTreeSet::new();
    let mut unrestricted_attachments = Vec::new();
    let mut visible_attachments = Vec::new();
    for graph in &graph_roles.claim_graphs {
        unrestricted_claim_facts.extend(scan_quads(ledger, graph, None, limits, refresh).await?);
        visible_claim_facts
            .extend(scan_quads(ledger, graph, enforcer.clone(), limits, refresh).await?);
        unrestricted_attachments
            .extend(scan_attachments(ledger, graph, None, limits, refresh).await?);
        visible_attachments
            .extend(scan_attachments(ledger, graph, enforcer.clone(), limits, refresh).await?);
    }

    let marked: BTreeSet<String> = unrestricted_claim_facts
        .iter()
        .filter(|quad| quad.predicate == RDF_TYPE && quad.object == RdfTerm::Iri(CLAIM.into()))
        .map(|quad| quad.subject.clone())
        .collect();
    let mut complete_metadata: BTreeMap<String, BTreeSet<Quad>> = BTreeMap::new();
    let mut visible_metadata: BTreeMap<String, BTreeSet<Quad>> = BTreeMap::new();
    for claim in &marked {
        complete_metadata.insert(
            claim.clone(),
            unrestricted_claim_facts
                .iter()
                .filter(|quad| {
                    &quad.subject == claim
                        && (is_profile_predicate(&quad.predicate)
                            || quad.predicate.starts_with(CTXQL))
                })
                .cloned()
                .collect(),
        );
        visible_metadata.insert(
            claim.clone(),
            visible_claim_facts
                .iter()
                .filter(|quad| {
                    &quad.subject == claim
                        && (is_profile_predicate(&quad.predicate)
                            || quad.predicate.starts_with(CTXQL))
                })
                .cloned()
                .collect(),
        );
    }

    let by_claim = validate_claim_profile(&marked, &complete_metadata, &unrestricted_attachments)?;
    let mut visible_targets: BTreeMap<&str, Vec<&Proposition>> = BTreeMap::new();
    for attachment in &visible_attachments {
        visible_targets
            .entry(&attachment.claim)
            .or_default()
            .push(&attachment.proposition);
    }
    let visible_supports: BTreeSet<String> = marked
        .iter()
        .filter(|claim| {
            visible_targets.get(claim.as_str()).is_some_and(|targets| {
                targets.len() == 1 && targets[0] == by_claim.get(*claim).expect("validated claim")
            }) && visible_metadata.get(*claim) == complete_metadata.get(*claim)
        })
        .cloned()
        .collect();

    let managed: BTreeSet<_> = by_claim.values().cloned().collect();
    let admitted: BTreeSet<_> = visible_supports
        .iter()
        .filter_map(|claim| by_claim.get(claim).cloned())
        .collect();
    let metadata_subjects = marked;
    let mut data: BTreeSet<Quad> = visible_claim_facts
        .into_iter()
        .filter(|quad| !metadata_subjects.contains(&quad.subject))
        .filter(|quad| {
            !managed.contains(&Proposition {
                graph: quad.graph.clone(),
                subject: quad.subject.clone(),
                predicate: quad.predicate.clone(),
                object: quad.object.clone(),
            })
        })
        .collect();
    data.extend(admitted.iter().map(Proposition::as_quad));
    for graph in graph_roles
        .governed_data
        .difference(&graph_roles.claim_graphs)
    {
        data.extend(scan_quads(ledger, graph, enforcer.clone(), limits, refresh).await?);
    }

    let config_graph = fluree_db_core::graph_registry::config_graph_iri(&ledger.snapshot.ledger_id);
    let complete_config =
        scan_infrastructure_quads(ledger, &config_graph, None, limits, refresh).await?;
    let visible_config =
        scan_infrastructure_quads(ledger, &config_graph, enforcer.clone(), limits, refresh).await?;
    if visible_config != complete_config {
        return Err("ontology_authorization_denied".into());
    }
    let historical_config_root = root(complete_config.iter());
    let config = config_resolver::resolve_ledger_config(
        &ledger.snapshot,
        ledger.novelty.as_ref(),
        ledger.t(),
    )
    .await
    .map_err(|_| "ontology_configuration_invalid".to_string())?
    .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let reasoning = config_resolver::resolve_effective_config(&config, None)
        .reasoning
        .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let bundle = ontology_imports::resolve_schema_bundle(
        &ledger.snapshot,
        ledger.novelty.as_ref(),
        ledger.t(),
        &reasoning,
    )
    .await
    .map_err(|_| "ontology_configuration_invalid".to_string())?
    .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let schema_source = reasoning
        .schema_source
        .as_ref()
        .and_then(|source| source.graph_selector.clone())
        .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
    let mut schema_graphs = BTreeSet::new();
    let mut complete_schema = BTreeSet::new();
    for graph_id in &bundle.sources {
        let graph = ledger
            .snapshot
            .graph_registry
            .iri_for_graph_id(*graph_id)
            .ok_or_else(|| "ontology_configuration_invalid".to_string())?;
        if !graph_roles.infrastructure.contains(graph) {
            return Err("graph_role_map_invalid".into());
        }
        schema_graphs.insert(graph.to_string());
        let unrestricted = scan_quads(ledger, graph, None, limits, refresh).await?;
        let visible = scan_quads(ledger, graph, enforcer.clone(), limits, refresh).await?;
        if visible != unrestricted {
            return Err("ontology_authorization_denied".into());
        }
        complete_schema.extend(unrestricted);
    }
    if bundle.sources.len() != graph_roles.infrastructure.len() {
        return Err("graph_role_map_invalid".into());
    }
    refresh.verify_current().await?;

    let semantic_capture = SemanticCapture {
        requested_as_of: format!("t:{}", ledger.t()),
        ledger: ledger.snapshot.ledger_id.clone(),
        t: ledger.t(),
        commit_cid: ledger
            .head_commit_id
            .as_ref()
            .ok_or_else(|| "semantic_capture_incomplete".to_string())?
            .to_string(),
    };
    let stats = refresh.stats.lock().expect("extraction stats").clone();
    let graph_role_commitment = [
        graph_roles
            .governed_data
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\u{0}"),
        graph_roles
            .claim_graphs
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\u{0}"),
        graph_roles
            .infrastructure
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\u{0}"),
    ]
    .join("\u{1}");
    let protected_evidence = format!(
        "extract=ctxql-authorized-extraction/v1;limits={}:{}:{}:{};scan={}:{}:{};roles={graph_role_commitment}",
        limits.page_size,
        limits.max_pages,
        limits.max_rows,
        limits.max_bytes,
        stats.pages,
        stats.rows,
        stats.bytes
    );
    let manifest = AuthorizedViewManifest::seal(
        SemanticCaptureDescriptor {
            ledger: semantic_capture.ledger.clone(),
            requested_as_of: semantic_capture.requested_as_of.clone(),
            t: semantic_capture.t,
            commit_cid: semantic_capture.commit_cid.clone(),
        },
        ReasoningDescriptor {
            schema_source,
            follow_owl_imports: reasoning.follow_owl_imports.unwrap_or(false),
            schema_graphs,
        },
        data.iter().map(manifest_quad).collect(),
        complete_schema.iter().map(manifest_quad).collect(),
        visible_supports.clone(),
        historical_config_root.clone(),
        refresh.resolved.basis.dependency_root.clone(),
        &protected_evidence,
    );
    let authorized_counts = manifest.authorized_counts.clone();
    let data_root = manifest.data_root.clone();
    let schema_root = manifest.schema_root.clone();
    let authorized_premise_root = manifest.authorized_premise_root.clone();
    let execution_manifest_root = manifest.execution_manifest_root.clone();
    Ok(Extraction {
        semantic_capture,
        policy_basis: refresh.resolved.basis.clone(),
        graph_roles,
        extraction_version: "ctxql-authorized-extraction/v1",
        limits,
        authorized_counts,
        data,
        schema: complete_schema,
        visible_supports,
        data_root,
        schema_root,
        historical_config_root,
        authorized_premise_root,
        execution_manifest_root,
        manifest,
    })
}

fn claim_annotation(id: &str) -> Value {
    json!({
        "@id": id,
        "@type": "ctxql:Claim",
        "ctxql:relationType": {"@id": "ex:SocialRelation"},
        "ctxql:subjectType": {"@id": "ex:Person"},
        "ctxql:objectType": {"@id": "ex:Person"},
        "ctxql:claimType": {"@id": "ex:Observed"},
        "ctxql:confidence": {"@value": "0.800", "@type": "xsd:decimal"},
        "ctxql:groundingLevel": {"@id": "ctxql:SourceLineageAvailable"},
        "ctxql:lineage": {"@value": "{\"schema\":\"ctxql.lineage.v1\",\"sources\":[{\"kind\":\"urn:ctxql:source-kind\",\"source_id\":\"source-1\"}]}", "@type": "rdf:JSON"},
        "ctxql:extensions": {"@value": "{}", "@type": "rdf:JSON"}
    })
}

fn valid_profile_facts(claim: &str) -> BTreeSet<Quad> {
    let iri = |predicate: &str, object: &str| Quad {
        graph: CLAIMS_GRAPH.into(),
        subject: claim.into(),
        predicate: predicate.into(),
        object: RdfTerm::Iri(object.into()),
    };
    BTreeSet::from([
        iri(RDF_TYPE, CLAIM),
        iri(
            &format!("{CTXQL}relationType"),
            &format!("{EX}SocialRelation"),
        ),
        iri(&format!("{CTXQL}subjectType"), &format!("{EX}Person")),
        iri(&format!("{CTXQL}objectType"), &format!("{EX}Person")),
        iri(&format!("{CTXQL}claimType"), &format!("{EX}Observed")),
        Quad {
            graph: CLAIMS_GRAPH.into(),
            subject: claim.into(),
            predicate: format!("{CTXQL}confidence"),
            object: RdfTerm::Literal {
                lexical: "0.800".into(),
                datatype: "http://www.w3.org/2001/XMLSchema#decimal".into(),
                language: None,
            },
        },
        iri(
            &format!("{CTXQL}groundingLevel"),
            &format!("{CTXQL}SourceLineageAvailable"),
        ),
        Quad {
            graph: CLAIMS_GRAPH.into(),
            subject: claim.into(),
            predicate: format!("{CTXQL}lineage"),
            object: RdfTerm::Literal {
                lexical: "{\"schema\":\"ctxql.lineage.v1\",\"sources\":[{\"kind\":\"urn:ctxql:source-kind\",\"source_id\":\"source-1\"}]}".into(),
                datatype: RDF_JSON.into(),
                language: None,
            },
        },
        Quad {
            graph: CLAIMS_GRAPH.into(),
            subject: claim.into(),
            predicate: format!("{CTXQL}extensions"),
            object: RdfTerm::Literal {
                lexical: "{}".into(),
                datatype: RDF_JSON.into(),
                language: None,
            },
        },
    ])
}

#[test]
fn malformed_marked_claims_fail_globally_before_visibility() {
    let claim = format!("{EX}claim/malformed");
    let marked = BTreeSet::from([claim.clone()]);
    let proposition = Proposition {
        graph: CLAIMS_GRAPH.into(),
        subject: format!("{EX}alice"),
        predicate: format!("{EX}knows"),
        object: RdfTerm::Iri(format!("{EX}bob")),
    };
    let attachment = Attachment {
        claim: claim.clone(),
        proposition: proposition.clone(),
    };

    let mut missing = valid_profile_facts(&claim);
    missing.retain(|quad| quad.predicate != format!("{CTXQL}confidence"));
    assert_eq!(
        validate_claim_profile(
            &marked,
            &BTreeMap::from([(claim.clone(), missing)]),
            std::slice::from_ref(&attachment),
        ),
        Err("claim_profile_invalid".into())
    );

    assert_eq!(
        validate_claim_profile(
            &marked,
            &BTreeMap::from([(
                claim.clone(),
                valid_profile_facts(&format!("{EX}claim/malformed")),
            )]),
            &[
                attachment.clone(),
                Attachment {
                    claim: attachment.claim.clone(),
                    proposition: Proposition {
                        object: RdfTerm::Iri(format!("{EX}carol")),
                        ..proposition
                    },
                },
            ],
        ),
        Err("claim_profile_invalid".into())
    );

    let invalid = |facts: BTreeSet<Quad>| {
        validate_claim_profile(
            &marked,
            &BTreeMap::from([(claim.clone(), facts)]),
            std::slice::from_ref(&attachment),
        )
    };
    let replace = |facts: &mut BTreeSet<Quad>, predicate: &str, replacement: Quad| {
        facts.retain(|quad| quad.predicate != predicate);
        facts.insert(replacement);
    };

    let mut duplicate = valid_profile_facts(&claim);
    duplicate.insert(Quad {
        graph: CLAIMS_GRAPH.into(),
        subject: claim.clone(),
        predicate: format!("{CTXQL}relationType"),
        object: RdfTerm::Iri(format!("{EX}OtherRelation")),
    });
    assert_eq!(invalid(duplicate), Err("claim_profile_invalid".into()));

    let mut cross_graph = valid_profile_facts(&claim);
    let mut moved = cross_graph
        .iter()
        .find(|quad| quad.predicate == format!("{CTXQL}relationType"))
        .expect("relation type")
        .clone();
    moved.graph = DATA_GRAPH.into();
    replace(&mut cross_graph, &format!("{CTXQL}relationType"), moved);
    assert_eq!(invalid(cross_graph), Err("claim_profile_invalid".into()));

    let mut wrong_type = valid_profile_facts(&claim);
    replace(
        &mut wrong_type,
        &format!("{CTXQL}relationType"),
        Quad {
            graph: CLAIMS_GRAPH.into(),
            subject: claim.clone(),
            predicate: format!("{CTXQL}relationType"),
            object: RdfTerm::Literal {
                lexical: "not-an-iri".into(),
                datatype: "http://www.w3.org/2001/XMLSchema#string".into(),
                language: None,
            },
        },
    );
    assert_eq!(invalid(wrong_type), Err("claim_profile_invalid".into()));

    let mut invalid_grounding = valid_profile_facts(&claim);
    replace(
        &mut invalid_grounding,
        &format!("{CTXQL}groundingLevel"),
        Quad {
            graph: CLAIMS_GRAPH.into(),
            subject: claim.clone(),
            predicate: format!("{CTXQL}groundingLevel"),
            object: RdfTerm::Iri(format!("{CTXQL}Unknown")),
        },
    );
    assert_eq!(
        invalid(invalid_grounding),
        Err("claim_profile_invalid".into())
    );

    for (predicate, lexical) in [
        ("extensions", "[]"),
        ("extensions", "{ }"),
        ("extensions", "{\"a\":1,\"a\":2}"),
    ] {
        let mut invalid_json = valid_profile_facts(&claim);
        replace(
            &mut invalid_json,
            &format!("{CTXQL}{predicate}"),
            Quad {
                graph: CLAIMS_GRAPH.into(),
                subject: claim.clone(),
                predicate: format!("{CTXQL}{predicate}"),
                object: RdfTerm::Literal {
                    lexical: lexical.into(),
                    datatype: RDF_JSON.into(),
                    language: None,
                },
            },
        );
        assert_eq!(invalid(invalid_json), Err("claim_profile_invalid".into()));
    }

    let mut invalid_decimal = valid_profile_facts(&claim);
    replace(
        &mut invalid_decimal,
        &format!("{CTXQL}confidence"),
        Quad {
            graph: CLAIMS_GRAPH.into(),
            subject: claim.clone(),
            predicate: format!("{CTXQL}confidence"),
            object: RdfTerm::Literal {
                lexical: "1.0001".into(),
                datatype: "http://www.w3.org/2001/XMLSchema#decimal".into(),
                language: None,
            },
        },
    );
    assert_eq!(
        invalid(invalid_decimal),
        Err("claim_profile_invalid".into())
    );
    assert!(decimal_in_unit_interval(
        "0.0000000000000000000000000000001"
    ));
    assert!(decimal_in_unit_interval("1.000"));
    assert!(!decimal_in_unit_interval(
        "1.0000000000000000000000000000001"
    ));

    let mut optional_timestamp = valid_profile_facts(&claim);
    optional_timestamp.insert(Quad {
        graph: CLAIMS_GRAPH.into(),
        subject: claim.clone(),
        predicate: format!("{CTXQL}validTime"),
        object: RdfTerm::Literal {
            lexical: "2026-09-16T12:00:00.123Z".into(),
            datatype: "http://www.w3.org/2001/XMLSchema#dateTime".into(),
            language: None,
        },
    });
    assert!(invalid(optional_timestamp).is_ok());

    let mut submillisecond_timestamp = valid_profile_facts(&claim);
    submillisecond_timestamp.insert(Quad {
        graph: CLAIMS_GRAPH.into(),
        subject: claim.clone(),
        predicate: format!("{CTXQL}sourceObservedAt"),
        object: RdfTerm::Literal {
            lexical: "2026-09-16T12:00:00.1234Z".into(),
            datatype: "http://www.w3.org/2001/XMLSchema#dateTime".into(),
            language: None,
        },
    });
    assert_eq!(
        invalid(submillisecond_timestamp),
        Err("claim_profile_invalid".into())
    );
}

#[tokio::test]
async fn unsupported_normalized_literal_fails_closed() {
    let fluree = FlureeBuilder::memory().build_memory();
    let ledger_id = "ctxql/p5-5-e0-unsupported:main";
    let graph = "http://example.org/graphs/unsupported";
    let ledger = apply_trig(
        &fluree,
        genesis(ledger_id),
        &format!(
            r#"@prefix ex: <{EX}> .
               @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
               GRAPH <{graph}> {{ ex:s ex:value "+001"^^xsd:integer . }}"#
        ),
    )
    .await;
    let authority = CurrentSemanticAuthority {
        current: Arc::new(Mutex::new(ledger.clone())),
        ledger_id: ledger_id.into(),
        principal: "did:example:test".into(),
        action: "ctxql:query".into(),
    };
    let resolved = resolve_current_semantic_authority(&authority)
        .await
        .expect("explicit no-policy authority");
    assert_eq!(resolved.basis.mode, SemanticPolicyMode::Unrestricted);
    let refresh = PolicyRefresh::stable(resolved, authority.clone());
    let error = scan_quads(&ledger, graph, None, ScanLimits::default(), &refresh)
        .await
        .expect_err("normalized integer lexical identity is unsupported");
    assert_eq!(error, "unsupported_exact_literal");

    let config_graph = fluree_db_core::graph_registry::config_graph_iri(ledger_id);
    let configured = apply_trig(
        &fluree,
        ledger,
        &format!(
            r#"@prefix ex: <{EX}> .
               @prefix f: <https://ns.flur.ee/db#> .
               @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
               GRAPH <{config_graph}> {{
                   <urn:ctxql:config> rdf:type f:LedgerConfig ; f:policyDefaults <urn:ctxql:policy> .
                   <urn:ctxql:policy> f:defaultAllow true ; f:policyClass ex:E0Policy ;
                       f:policySource <urn:ctxql:policy-ref> .
                   <urn:ctxql:policy-ref> rdf:type f:GraphRef ; f:graphSource <urn:ctxql:policy-source> .
                   <urn:ctxql:policy-source> f:graphSelector <{POLICY_GRAPH}> .
               }}
               GRAPH <{POLICY_GRAPH}> {{
                   <urn:ctxql:allow> rdf:type f:AccessPolicy, ex:E0Policy ;
                       f:action f:view ; f:allow true .
               }}"#
        ),
    )
    .await;
    *authority.current.lock().expect("semantic authority lock") = configured;
    assert_eq!(
        refresh
            .verify_current()
            .await
            .expect_err("adding policy invalidates unrestricted preparation"),
        "semantic_policy_changed"
    );
}

#[tokio::test]
async fn malformed_configured_policy_never_falls_back_to_unrestricted() {
    let fluree = FlureeBuilder::memory().build_memory();
    let ledger_id = "ctxql/p5-5-e0-malformed-policy:main";
    let config_graph = fluree_db_core::graph_registry::config_graph_iri(ledger_id);
    let ledger = apply_trig(
        &fluree,
        genesis(ledger_id),
        &format!(
            r#"@prefix ex: <{EX}> .
               @prefix f: <https://ns.flur.ee/db#> .
               @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
               GRAPH <{config_graph}> {{
                   <urn:ctxql:config> rdf:type f:LedgerConfig ; f:policyDefaults <urn:ctxql:policy> .
                   <urn:ctxql:policy> f:defaultAllow true ; f:policyClass ex:E0Policy ;
                       f:policySource <urn:ctxql:policy-ref> .
                   <urn:ctxql:policy-ref> rdf:type f:GraphRef ; f:graphSource <urn:ctxql:policy-source> .
               }}"#
        ),
    )
    .await;
    let authority = CurrentSemanticAuthority {
        current: Arc::new(Mutex::new(ledger)),
        ledger_id: ledger_id.into(),
        principal: "did:example:test".into(),
        action: "ctxql:query".into(),
    };
    let error = match resolve_current_semantic_authority(&authority).await {
        Ok(_) => panic!("missing explicit graph selector must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error, "semantic_policy_unavailable");
}

#[tokio::test]
async fn complete_policy_visible_extraction_precedes_reasoning() {
    Box::pin(async {
    let fluree = FlureeBuilder::memory().build_memory();
    let ledger_id = "ctxql/p5-5-e0:main";
    let config_graph = format!("urn:fluree:{ledger_id}#config");
    let seeded = apply_trig(
        &fluree,
        genesis(ledger_id),
        &format!(
            r#"
            @prefix ctxql: <https://ctxql.example/vocab#> .
            @prefix ex: <{EX}> .
            @prefix f: <https://ns.flur.ee/db#> .
            @prefix owl: <http://www.w3.org/2002/07/owl#> .
            @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
            @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
            @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

            GRAPH <{config_graph}> {{
                <urn:ctxql:config> rdf:type f:LedgerConfig ;
                    f:reasoningDefaults <urn:ctxql:reasoning> ;
                    f:policyDefaults <urn:ctxql:policy-defaults> ;
                    ctxql:governedDataGraph <{CLAIMS_GRAPH}>, <{DATA_GRAPH}> ;
                    ctxql:claimGraph <{CLAIMS_GRAPH}> ;
                    ctxql:infrastructureGraph <{ONTOLOGY_GRAPH}>, <{IMPORTED_ONTOLOGY_GRAPH}> .
                <urn:ctxql:reasoning> f:reasoningModes f:owl2rl ;
                    f:schemaSource <urn:ctxql:schema-ref> ;
                    f:followOwlImports true .
                <urn:ctxql:schema-ref> rdf:type f:GraphRef ;
                    f:graphSource <urn:ctxql:schema-source> .
                <urn:ctxql:schema-source> f:graphSelector <{ONTOLOGY_GRAPH}> .
                <urn:ctxql:policy-defaults> f:defaultAllow true ;
                    f:policyClass ex:E0Policy ;
                    f:policySource <urn:ctxql:policy-ref> .
                <urn:ctxql:policy-ref> rdf:type f:GraphRef ;
                    f:graphSource <urn:ctxql:policy-source> .
                <urn:ctxql:policy-source> f:graphSelector <{POLICY_GRAPH}> .
            }}
            GRAPH <{POLICY_GRAPH}> {{
                <urn:ctxql:deny-hidden> rdf:type f:AccessPolicy, ex:E0Policy ;
                    f:action f:view ;
                    f:onSubject <{EX}claim/hidden>, <{EX}claim/only-hidden>, <{EX}claim/hidden-extra>, ex:hiddenOrdinary ;
                    f:allow false .
            }}
            GRAPH <{ONTOLOGY_GRAPH}> {{
                <{ONTOLOGY_GRAPH}> rdf:type owl:Ontology ;
                    owl:imports <{IMPORTED_ONTOLOGY_GRAPH}> .
                ex:hasAncestor rdf:type owl:TransitiveProperty .
            }}
            GRAPH <{IMPORTED_ONTOLOGY_GRAPH}> {{
                <{IMPORTED_ONTOLOGY_GRAPH}> rdf:type owl:Ontology .
                ex:Manager rdfs:subClassOf ex:Person .
            }}
            GRAPH <{DATA_GRAPH}> {{
                ex:visible ex:decimal "0.800"^^xsd:decimal ;
                    ex:label "bonjour"@fr ;
                    ex:custom "001"^^ex:Code .
                ex:hiddenOrdinary ex:value "secret" .
            }}
            "#
        ),
    )
    .await;

    let context = json!({
        "ex": EX,
        "ctxql": "https://ctxql.example/vocab#",
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "xsd": "http://www.w3.org/2001/XMLSchema#"
    });
    let exact = fluree
        .insert(
            seeded,
            &json!({
                "@context": context,
                "@graph": [
                    {"@id": "ex:alice", "@graph": CLAIMS_GRAPH, "ex:knows": {
                        "@id": "ex:bob", "@annotation": claim_annotation("ex:claim/visible")
                    }},
                    {"@id": "ex:alice", "@graph": CLAIMS_GRAPH, "ex:knows": {
                        "@id": "ex:bob", "@annotation": claim_annotation("ex:claim/hidden")
                    }},
                    {"@id": "ex:alice", "@graph": CLAIMS_GRAPH, "ex:secretRelation": {
                        "@id": "ex:carol", "@annotation": claim_annotation("ex:claim/only-hidden")
                    }},
                    {"@id": "ex:ordinary", "@graph": CLAIMS_GRAPH, "ex:note": "coexists"}
                ]
            }),
        )
        .await
        .expect("claim fixture")
        .ledger;
    let hidden_sibling_capture = fluree
        .insert(
            exact.clone(),
            &json!({
                "@context": {
                    "ex": EX,
                    "ctxql": "https://ctxql.example/vocab#",
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "xsd": "http://www.w3.org/2001/XMLSchema#"
                },
                "@id": "ex:alice",
                "@graph": CLAIMS_GRAPH,
                "ex:knows": {
                    "@id": "ex:bob",
                    "@annotation": claim_annotation("ex:claim/hidden-extra")
                }
            }),
        )
        .await
        .expect("well-formed hidden sibling")
        .ledger;
    let current_semantic = fluree
        .insert(
            hidden_sibling_capture.clone(),
            &json!({"@context": {"ex": EX}, "@id": "ex:unrelated", "ex:value": "later"}),
        )
        .await
        .expect("unrelated semantic data commit")
        .ledger;
    assert!(current_semantic.t() > exact.t());

    let policy_authority = CurrentSemanticAuthority {
        current: Arc::new(Mutex::new(current_semantic.clone())),
        ledger_id: ledger_id.into(),
        principal: "did:example:alice".into(),
        action: "ctxql:query".into(),
    };
    let resolved_before = resolve_current_semantic_authority(&policy_authority)
        .await
        .expect("configured same-ledger policy");
    assert_eq!(resolved_before.basis.mode, SemanticPolicyMode::Configured);
    let dependency_root = resolved_before.basis.dependency_root.clone();
    let exact_authority = CurrentSemanticAuthority {
        current: Arc::new(Mutex::new(exact.clone())),
        ..policy_authority.clone()
    };
    assert_eq!(
        resolve_current_semantic_authority(&exact_authority)
            .await
            .expect("authority before unrelated head movement")
            .basis
            .dependency_root,
        dependency_root,
        "unrelated semantic head movement does not change the dependency root"
    );
    let changed_policy_state = apply_trig(
        &fluree,
        current_semantic.clone(),
        &format!(
            r#"@prefix ex: <{EX}> .
               @prefix f: <https://ns.flur.ee/db#> .
               @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
               GRAPH <{POLICY_GRAPH}> {{
                   <urn:ctxql:deny-new> rdf:type f:AccessPolicy, ex:E0Policy ;
                       f:action f:view ; f:onSubject ex:newlyDenied ; f:allow false .
               }}"#
        ),
    )
    .await;
    let changed_authority = CurrentSemanticAuthority {
        current: Arc::new(Mutex::new(changed_policy_state.clone())),
        ..policy_authority.clone()
    };
    assert_ne!(
        dependency_root,
        resolve_current_semantic_authority(&changed_authority)
            .await
            .expect("changed policy authority")
            .basis
            .dependency_root
    );
    let changed_config_state = apply_trig(
        &fluree,
        changed_policy_state.clone(),
        &format!(
            r#"@prefix ex: <{EX}> .
               @prefix f: <https://ns.flur.ee/db#> .
               GRAPH <{config_graph}> {{
                   <urn:ctxql:policy-defaults> f:policyClass ex:AdditionalPolicy .
               }}"#
        ),
    )
    .await;
    let changed_config_authority = CurrentSemanticAuthority {
        current: Arc::new(Mutex::new(changed_config_state)),
        ..policy_authority.clone()
    };
    assert_ne!(
        dependency_root,
        resolve_current_semantic_authority(&changed_config_authority)
            .await
            .expect("changed policy configuration")
            .basis
            .dependency_root,
        "relevant policy configuration changes freshness"
    );
    let basis_before = resolved_before.basis.clone();

    let first = extract(
        &exact,
        ScanLimits::default(),
        &PolicyRefresh::stable(resolved_before.clone(), policy_authority.clone()),
    )
    .await
    .expect("first complete extraction");
    let second = extract(
        &exact,
        ScanLimits::default(),
        &PolicyRefresh::stable(resolved_before.clone(), policy_authority.clone()),
    )
    .await
    .expect("second complete extraction");
    assert_eq!(first, second, "independent extractions are deterministic");

    let hidden_authority = CurrentSemanticAuthority {
        current: Arc::new(Mutex::new(hidden_sibling_capture.clone())),
        ..policy_authority.clone()
    };
    let hidden_resolved = resolve_current_semantic_authority(&hidden_authority)
        .await
        .expect("hidden-sibling current policy");
    assert_eq!(
        hidden_resolved.basis.dependency_root,
        basis_before.dependency_root,
        "governed-data-only advancement is irrelevant to policy freshness"
    );
    let with_hidden_sibling = extract(
        &hidden_sibling_capture,
        ScanLimits::default(),
        &PolicyRefresh::stable(hidden_resolved, hidden_authority),
    )
    .await
    .expect("hidden sibling extraction");
    assert_eq!(with_hidden_sibling.data, first.data);
    assert_eq!(with_hidden_sibling.schema, first.schema);
    assert_eq!(with_hidden_sibling.visible_supports, first.visible_supports);
    assert_eq!(with_hidden_sibling.authorized_counts, first.authorized_counts);
    assert_eq!(
        with_hidden_sibling.authorized_premise_root,
        first.authorized_premise_root,
        "hidden siblings cannot affect disclosure-safe commitments"
    );
    assert_ne!(
        with_hidden_sibling.execution_manifest_root,
        first.execution_manifest_root,
        "the protected execution root binds the different capture CID"
    );

    assert_eq!(
        first.visible_supports,
        BTreeSet::from([format!("{EX}claim/visible")]),
        "hidden sibling IDs and metadata do not enter the descriptor"
    );
    let shared = Quad {
        graph: CLAIMS_GRAPH.into(),
        subject: format!("{EX}alice"),
        predicate: format!("{EX}knows"),
        object: RdfTerm::Iri(format!("{EX}bob")),
    };
    let hidden_only = Quad {
        graph: CLAIMS_GRAPH.into(),
        subject: format!("{EX}alice"),
        predicate: format!("{EX}secretRelation"),
        object: RdfTerm::Iri(format!("{EX}carol")),
    };
    assert!(first.data.contains(&shared));
    assert!(
        !first.data.contains(&hidden_only),
        "visible bare edge cannot bypass hidden support"
    );
    assert!(first.data.iter().any(|quad| {
        quad.predicate == format!("{EX}decimal")
            && quad.object
                == RdfTerm::Literal {
                    lexical: "0.800".into(),
                    datatype: "http://www.w3.org/2001/XMLSchema#decimal".into(),
                    language: None,
                }
    }));
    assert!(first.data.iter().any(|quad| {
        quad.predicate == format!("{EX}label")
            && quad.object
                == RdfTerm::Literal {
                    lexical: "bonjour".into(),
                    datatype: RDF_LANG_STRING.into(),
                    language: Some("fr".into()),
                }
    }));
    assert!(first.data.iter().any(|quad| {
        quad.predicate == format!("{EX}custom")
            && quad.object
                == RdfTerm::Literal {
                    lexical: "001".into(),
                    datatype: format!("{EX}Code"),
                    language: None,
                }
    }));
    assert!(!first
        .data
        .iter()
        .any(|quad| quad.subject == format!("{EX}hiddenOrdinary")));
    assert_eq!(
        first.schema.len(),
        5,
        "whole imported ontology bundle admitted"
    );
    assert_eq!(first.policy_basis, basis_before);
    assert_eq!(first.semantic_capture.ledger, ledger_id);
    assert_eq!(first.semantic_capture.t, exact.t());
    assert_eq!(
        first.semantic_capture.requested_as_of,
        format!("t:{}", exact.t())
    );
    assert!(!first.semantic_capture.commit_cid.is_empty());
    assert_eq!(first.authorized_counts.data_quads, first.data.len());
    assert_eq!(first.authorized_counts.schema_quads, first.schema.len());
    assert_eq!(first.authorized_counts.visible_supports, 1);
    assert_eq!(
        first.graph_roles.infrastructure,
        BTreeSet::from([
            ONTOLOGY_GRAPH.to_string(),
            IMPORTED_ONTOLOGY_GRAPH.to_string(),
        ])
    );
    assert_ne!(first.data_root, first.schema_root);
    assert!(!first.authorized_premise_root.0.as_str().is_empty());
    assert!(!first.execution_manifest_root.0.as_str().is_empty());
    assert!(!first.historical_config_root.as_str().is_empty());

    assert_eq!(
        basis_before.dependency_root,
        resolve_current_semantic_authority(&policy_authority)
            .await
            .expect("current dependency root")
            .basis
            .dependency_root,
        "unrelated authority-head movement does not change the policy dependency root"
    );
    let changed_during_pagination = extract(
        &exact,
        ScanLimits::default(),
        &PolicyRefresh::changing(
            resolved_before.clone(),
            policy_authority.clone(),
            3,
            changed_policy_state,
        ),
    )
    .await
    .expect_err("policy dependency change during pagination must invalidate output");
    assert_eq!(changed_during_pagination, "semantic_policy_changed");

    *policy_authority
        .current
        .lock()
        .expect("policy authority lock") = current_semantic;
    let capped = extract(
        &exact,
        ScanLimits {
            max_pages: 1,
            ..ScanLimits::default()
        },
        &PolicyRefresh::stable(resolved_before, policy_authority),
    )
    .await
    .expect_err("page cap must fail closed");
    assert!(capped.contains("authorized_view_incomplete"));

    assert_eq!(RDF_JSON, "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON");
    })
    .await;
}
