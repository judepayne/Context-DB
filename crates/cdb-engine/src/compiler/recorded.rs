//! Typed restoration of normalized plan data; no artifact lookup, merge or defaults.
use super::*;
use cdb_core::{
    artifact::ArtifactRef,
    canonical::{CanonicalProjection, Domain},
    id::ContentHash,
    Limits,
};

/// Restore a supported plan from its canonical envelope and independently expected hash.
/// This validates data only: callers must authorize and verify the retained artifacts.
/// Notices are retained execution provenance (not part of the canonical plan); callers
/// must recover them from protected original inputs rather than today's profile.
pub fn load_recorded_plan(
    bytes: &[u8],
    expected_hash: &ContentHash,
    notices: Vec<CompileNotice>,
    limits: Limits,
) -> Result<ExecutablePlan> {
    load_recorded_plan_with_capabilities(
        bytes,
        expected_hash,
        notices,
        limits,
        CompilerCapabilities::default(),
    )
}

/// Reload with explicit compiler capabilities. This reconstructs only normalized
/// plan data and performs no merge, defaults, artifact lookup or native validation.
pub fn load_recorded_plan_with_capabilities(
    bytes: &[u8],
    expected_hash: &ContentHash,
    notices: Vec<CompileNotice>,
    limits: Limits,
    capabilities: CompilerCapabilities,
) -> Result<ExecutablePlan> {
    let canonical = CanonicalProjection::read(bytes, limits)?;
    if canonical.domain() != Domain::Plan || canonical.hash(limits)? != *expected_hash {
        return Err(Error::invalid("recorded plan identity"));
    }
    let payload = canonical.payload();
    let query = payload.field("query")?;
    // Normalized custom bindings are typed objects, unlike authored BIND strings.
    // The canonical core schema validates the enclosing normalized query below.
    cdb_core::projection::NormalizedQuery::from_value(query)?;
    let config_value = payload.field("config")?;
    let config = SemanticConfig::from_value(config_value)?;
    if !capabilities.external_functions
        && !config_value
            .field("external_functions")?
            .as_object()?
            .is_empty()
    {
        return Err(unsupported("recorded external functions"));
    }
    if !capabilities.prepared_interpretation
        && config_value
            .as_object()?
            .get("preparation")
            .is_some_and(|p| p.as_array().map_or(true, |a| !a.is_empty()))
    {
        return Err(unsupported("recorded prepared interpretation"));
    }
    let runtime = config_value.field("runtime")?;
    let predicate_numeric = runtime
        .as_object()?
        .get("predicate_numeric")
        .map(V::as_str)
        .transpose()?;
    if runtime.field("candidate_order")?
        != &array(&[
            "depth asc",
            "confidence desc",
            "transaction_time desc",
            "claim_id asc",
        ])
        || runtime.field("path_ranking")?
            != &array(&[
                "shorter_path",
                "higher_accumulated_confidence",
                "better_grounding",
                "newer_claims",
                "claim_id_tiebreak",
            ])
    {
        return Err(unsupported("recorded runtime ordering"));
    }
    if let Some(g) = config_value.as_object()?.get("grounding_registry") {
        if g != &array(&[
            "claim_only",
            "source_lineage_available",
            "source_spans_available",
        ]) {
            return Err(unsupported("recorded grounding registry"));
        }
    }
    let cycle = match runtime.field("cycle_policy")?.as_str()? {
        "no_repeated_claim" => CyclePolicy::NoRepeatedClaim,
        "allow_repeated_claim" => CyclePolicy::AllowRepeatedClaim,
        "no_repeated_node" => CyclePolicy::NoRepeatedNode,
        _ => return Err(unsupported("recorded cycle policy")),
    };
    let mut budget = cdb_core::limits::Budget::new(limits);
    charge_value(payload, &mut budget)?;
    let context = BTreeMap::new();
    validate_mappings(config_value.field("fields")?, &context, &mut budget)?;
    let bounds = query.field("bounds")?;
    let caps = Caps {
        max_depth: bounds.field("max_depth")?.u64()?,
        seed_limit: bounds.field("seed_limit")?.u64()?,
        fanout_limit: bounds.field("fanout_limit")?.u64()?,
        max_claims: bounds.field("max_claims")?.u64()?,
        path_limit: bounds.field("path_limit")?.u64()?,
    };
    let blocks = query
        .field("about")?
        .as_array()?
        .iter()
        .map(|b| {
            let match_mode = match b.field("match")?.as_str()? {
                "exact" => MatchMode::Exact,
                "approximate" if capabilities.approximate_landing => MatchMode::Approximate,
                "approximate" => return Err(unsupported("recorded approximate landing")),
                _ => return Err(Error::invalid("recorded match mode")),
            };
            let strings = |v: &V| {
                v.as_array()?
                    .iter()
                    .map(|s| Ok(s.as_str()?.to_owned()))
                    .collect::<Result<Vec<_>>>()
            };
            Ok(Block {
                from: strings(b.field("from")?)?,
                to: if *b.field("to")? == V::Null {
                    None
                } else {
                    Some(strings(b.field("to")?)?)
                },
                match_mode,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let direction = match query.field("walk")?.field("direction")?.as_str()? {
        "outgoing" => Direction::Outgoing,
        "incoming" => Direction::Incoming,
        "both" => Direction::Both,
        _ => return Err(Error::invalid("recorded direction")),
    };
    let mut phases = Vec::new();
    for (key, phase) in [("walk", Phase::Walk), ("filter", Phase::Filter)] {
        let mut compiled = Vec::new();
        for (index, original) in query
            .field(key)?
            .field("predicates")?
            .as_array()?
            .iter()
            .enumerate()
        {
            let mut value = original.clone();
            compiled.push(predicate(
                &mut value,
                phase,
                index,
                PredicateContext {
                    bounds: None,
                    context: &context,
                    mappings: config_value.field("fields")?,
                    capabilities,
                    predicate_numeric,
                },
                &mut budget,
            )?);
            if value != *original {
                return Err(Error::invalid("recorded operand not normalized"));
            }
        }
        phases.push(compiled);
    }
    let refs = payload.field("artifacts")?;
    let query_ref = ArtifactRef::from_value(refs.field("query")?)?;
    let profile_ref = if *refs.field("profile")? == V::Null {
        None
    } else {
        Some(ArtifactRef::from_value(refs.field("profile")?)?)
    };
    let as_of = Timestamp::parse(payload.field("as_of")?.as_str()?)?;
    let selection = ReturnSelection::from_value(query.field("return")?)?;
    let filter = phases.pop().expect("two phases");
    let walk = phases.pop().expect("two phases");
    let plan = ValidatedDraft {
        query: query.clone(),
        config,
        query_ref: Some(query_ref),
        profile_ref,
        config_ref: ArtifactRef::from_value(refs.field("config")?)?,
        requested: Some(as_of),
        semantics: ir::Semantics {
            blocks,
            caps,
            direction,
            cycle,
            walk,
            filter,
            selection,
        },
        notices,
        limits,
    }
    .finalize(as_of)?;
    if plan.hash() != expected_hash || plan.projection().canonical() != &canonical {
        return Err(Error::invalid("recorded plan reconstruction"));
    }
    Ok(plan)
}
