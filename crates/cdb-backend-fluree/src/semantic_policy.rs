//! Current same-ledger semantic policy resolution.
//!
//! One resolution constructs both the native query enforcer and the canonical
//! dependency basis used for freshness. The moving head is audit evidence only.

use crate::{
    authorized_view::{framed_root, ExactTerm, SourceQuad},
    semantic::FlureeSemanticLedger,
};
use cdb_core::id::ContentHash;
use fluree_db_api::{config_resolver, policy_builder, GovernanceOptions, LedgerState};
use fluree_db_core::{ledger_config::OverrideControl, DatatypeConstraint, FlakeValue, GraphDbRef};
use fluree_db_query::{
    execute_pattern, Binding, QueryPolicyEnforcer, Ref, Term, TriplePattern, VarRegistry,
};
use std::{collections::BTreeSet, sync::Arc};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const FLUREE_LEDGER_CONFIG: &str = "https://ns.flur.ee/db#LedgerConfig";
const FLUREE_ON_CLASS: &str = "https://ns.flur.ee/db#onClass";
const FLUREE_QUERY: &str = "https://ns.flur.ee/db#query";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticPolicyMode {
    Unrestricted,
    Configured,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticPolicyBasis {
    pub mode: SemanticPolicyMode,
    pub dependency_root: ContentHash,
    pub principal: String,
    pub action: String,
    /// Audit evidence only; excluded from dependency-root equality.
    pub source_observation: String,
}

#[derive(Clone)]
pub struct ResolvedSemanticAuthority {
    pub basis: SemanticPolicyBasis,
    enforcer: Option<Arc<QueryPolicyEnforcer>>,
}

impl ResolvedSemanticAuthority {
    pub fn enforcer(&self) -> Option<Arc<QueryPolicyEnforcer>> {
        self.enforcer.clone()
    }
}

pub async fn resolve_current_semantic_authority(
    ledger: &FlureeSemanticLedger,
    principal: &str,
    action: &str,
) -> Result<ResolvedSemanticAuthority, String> {
    let record = ledger
        .current_authority_record()
        .await
        .map_err(|_| "semantic_policy_unavailable".to_string())?;
    if let Some(record) = &record {
        let cache = ledger.authority_cache.lock().await;
        if let Some((observed, authority)) = cache.as_ref() {
            if observed == record
                && authority.basis.principal == principal
                && authority.basis.action == action
            {
                return Ok(authority.clone());
            }
        }
    }
    let state = ledger
        .current_state()
        .await
        .map_err(|_| "semantic_policy_unavailable".to_string())?;
    let authority = resolve_state(&state, principal, action).await?;
    if let Some(record) = record {
        // Only cache a resolution proven to describe the exact currently
        // published state. Any commit (even unrelated data) invalidates reuse;
        // dependency-root comparison below still decides policy freshness.
        let after = ledger
            .current_authority_record()
            .await
            .map_err(|_| "semantic_policy_unavailable".to_string())?;
        if after.as_ref() != Some(&record)
            || state.t() != record.commit_t
            || state.head_commit_id != record.commit_head_id
        {
            return Err("semantic_policy_changed".into());
        }
        *ledger.authority_cache.lock().await = Some((record, authority.clone()));
    }
    Ok(authority)
}

pub async fn verify_semantic_authority_current(
    ledger: &FlureeSemanticLedger,
    expected: &SemanticPolicyBasis,
) -> Result<(), String> {
    let current =
        resolve_current_semantic_authority(ledger, &expected.principal, &expected.action).await?;
    if current.basis.dependency_root != expected.dependency_root {
        return Err("semantic_policy_changed".into());
    }
    Ok(())
}

async fn resolve_state(
    ledger: &LedgerState,
    principal: &str,
    action: &str,
) -> Result<ResolvedSemanticAuthority, String> {
    let ledger_id = ledger.snapshot.ledger_id.as_str();
    let config_graph_iri = fluree_db_core::graph_registry::config_graph_iri(ledger_id);
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
        return unrestricted(
            ledger_id,
            principal,
            action,
            source_observation,
            "no-config",
        );
    };
    let config_graph = ledger
        .snapshot
        .graph_registry
        .graph_id_for_iri(&config_graph_iri)
        .ok_or_else(|| "semantic_policy_unavailable".to_string())?;
    let config_members = graph_members(ledger, config_graph, &config_graph_iri).await?;
    let configs = config_members
        .iter()
        .filter(|quad| {
            quad.predicate == RDF_TYPE && quad.object == ExactTerm::Iri(FLUREE_LEDGER_CONFIG.into())
        })
        .count();
    if configs != 1 {
        return Err("semantic_policy_unavailable".into());
    }
    let effective = config_resolver::resolve_effective_config(&config, None);
    let Some(policy) = effective.policy.as_ref() else {
        return unrestricted(
            ledger_id,
            principal,
            action,
            source_observation,
            "no-configured-policy",
        );
    };
    let source = policy
        .policy_source
        .as_ref()
        .ok_or_else(|| "semantic_policy_unavailable".to_string())?;
    if source.ledger.is_some()
        || source.at_t.is_some()
        || source.trust_policy.is_some()
        || source.rollback_guard.is_some()
    {
        return Err("semantic_policy_unavailable".into());
    }
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
    // Merge the ledger's authoritative policy defaults first, then bind the
    // service-authenticated principal. Treating the principal as anonymous
    // would make identity-selected same-ledger policies principal-independent;
    // passing it as query input before the merge could incorrectly suppress the
    // configured policy class under Fluree's request-override rules.
    let mut options = config_resolver::merge_policy_opts(&effective, &GovernanceOptions::default());
    options.identity = Some(principal.to_owned());
    if !options.has_any_policy_inputs()
        || options.policy.is_some()
        || options.policy_values.is_some()
    {
        return Err("semantic_policy_unavailable".into());
    }
    let members = graph_members(ledger, policy_graphs[0], graph_iri).await?;
    if members.is_empty()
        || members
            .iter()
            .any(|quad| matches!(quad.predicate.as_str(), FLUREE_ON_CLASS | FLUREE_QUERY))
    {
        return Err("semantic_policy_profile_unsupported".into());
    }
    let member_strings: Vec<String> = members.iter().map(SourceQuad::commitment).collect();
    let member_root = framed_root(
        "ctxql-policy-graph/v1",
        member_strings
            .iter()
            .map(|member| ("member", member.as_str())),
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
            ("ledger", ledger_id),
            ("principal", principal),
            ("action", action),
            ("mode", "configured"),
            ("source", graph_iri),
            ("classes", classes.as_str()),
            ("default-allow", default_allow.as_str()),
            ("override", override_control.as_str()),
            ("policy-members", member_root.as_str()),
        ],
    );
    let context = policy_builder::build_policy_context_from_opts(
        &ledger.snapshot,
        ledger.novelty.as_ref(),
        Some(ledger.novelty.as_ref()),
        ledger.t(),
        &options,
        &policy_graphs,
    )
    .await
    .map_err(|_| "semantic_policy_unavailable".to_string())?;
    Ok(ResolvedSemanticAuthority {
        basis: SemanticPolicyBasis {
            mode: SemanticPolicyMode::Configured,
            dependency_root,
            principal: principal.into(),
            action: action.into(),
            source_observation,
        },
        enforcer: Some(Arc::new(QueryPolicyEnforcer::new(Arc::new(context)))),
    })
}

fn unrestricted(
    ledger: &str,
    principal: &str,
    action: &str,
    source_observation: String,
    reason: &str,
) -> Result<ResolvedSemanticAuthority, String> {
    Ok(ResolvedSemanticAuthority {
        basis: SemanticPolicyBasis {
            mode: SemanticPolicyMode::Unrestricted,
            dependency_root: framed_root(
                "ctxql-semantic-policy-basis/v1",
                [
                    ("ledger", ledger),
                    ("principal", principal),
                    ("action", action),
                    ("mode", "unrestricted"),
                    ("absence", reason),
                ],
            ),
            principal: principal.into(),
            action: action.into(),
            source_observation,
        },
        enforcer: None,
    })
}

async fn graph_members(
    ledger: &LedgerState,
    graph: u16,
    graph_iri: &str,
) -> Result<BTreeSet<SourceQuad>, String> {
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
            members.insert(SourceQuad {
                graph: graph_iri.into(),
                subject: decode_iri(&ledger.snapshot, batch.get(row, subject))?.into(),
                predicate: decode_iri(&ledger.snapshot, batch.get(row, predicate))?,
                object: decode_term(&ledger.snapshot, batch.get(row, object))?,
            });
            if members.len() > 256 {
                return Err("semantic_policy_unavailable".into());
            }
        }
    }
    Ok(members)
}

fn decode_iri(
    snapshot: &fluree_db_core::LedgerSnapshot,
    binding: Option<&Binding>,
) -> Result<String, String> {
    binding
        .and_then(Binding::as_sid)
        .and_then(|sid| snapshot.decode_sid(sid))
        .ok_or_else(|| "semantic_policy_unavailable".to_string())
}

fn decode_term(
    snapshot: &fluree_db_core::LedgerSnapshot,
    binding: Option<&Binding>,
) -> Result<ExactTerm, String> {
    let binding = binding.ok_or_else(|| "semantic_policy_unavailable".to_string())?;
    if binding.as_sid().is_some() {
        return decode_iri(snapshot, Some(binding)).map(ExactTerm::Iri);
    }
    let (value, datatype) = binding
        .as_lit()
        .ok_or_else(|| "semantic_policy_unavailable".to_string())?;
    let lexical = match value {
        FlakeValue::String(value) | FlakeValue::Json(value) => value.clone(),
        FlakeValue::Boolean(value) => value.to_string(),
        FlakeValue::Long(value) => value.to_string(),
        FlakeValue::Decimal(value) => value.to_plain_string(),
        _ => return Err("semantic_policy_profile_unsupported".into()),
    };
    let (datatype, language) = match datatype {
        DatatypeConstraint::Explicit(datatype) => (
            snapshot
                .decode_sid(datatype)
                .ok_or_else(|| "semantic_policy_unavailable".to_string())?,
            None,
        ),
        DatatypeConstraint::LangTag(language) => (
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString".into(),
            Some(language.to_string()),
        ),
    };
    Ok(ExactTerm::Literal {
        lexical,
        datatype,
        language,
    })
}

fn override_commitment(value: &OverrideControl) -> String {
    match value {
        OverrideControl::None => "none".into(),
        OverrideControl::AllowAll => "allow-all".into(),
        OverrideControl::IdentityRestricted { allowed_identities } => {
            let mut identities: Vec<String> =
                allowed_identities.iter().map(ToString::to_string).collect();
            identities.sort();
            format!("identity-restricted:{}", identities.join(","))
        }
    }
}
