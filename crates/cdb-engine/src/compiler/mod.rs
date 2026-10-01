//! Structural parse → merge → typed validation → capture-finalized executable plan.
mod custom;
mod fields;
mod ir;
mod merge;
mod recorded;
use crate::{
    artifacts::ArtifactKind,
    diagnostics::{unsupported, CompileNotice},
    frontend::{self, SourceMap, SourceRole, SourceSpan},
    options::CompileOptions,
    values::{evaluate, Operator, Value},
};
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    id::Iri,
    projection::{ReturnSelection, SemanticConfig},
    CanonicalValue as V, Error, Result, Timestamp,
};
pub use custom::{CustomBinding, CustomProgram};
pub use fields::{FieldRef, FieldType};
pub use ir::*;
pub use recorded::{load_recorded_plan, load_recorded_plan_with_capabilities};
use std::collections::BTreeMap;

/// Bytes and optional exact published identity. Source bytes are never reserialized to verify identity.
#[derive(Clone, Copy)]
pub struct QuerySource<'a> {
    pub bytes: &'a [u8],
    pub published: Option<&'a PublishedArtifact>,
}
impl<'a> QuerySource<'a> {
    pub fn inline(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            published: None,
        }
    }
    pub fn published(artifact: &'a PublishedArtifact) -> Self {
        Self {
            bytes: artifact.content(),
            published: Some(artifact),
        }
    }
}
/// The catalog resolves the authored selector; the compiler checks this exact selected name/reference.
pub struct SelectedProfile<'a> {
    pub selector: &'a str,
    pub artifact: &'a PublishedArtifact,
}

#[derive(Clone, Debug)]
pub struct SourceOrigin {
    pub role: SourceRole,
    pub span: SourceSpan,
    pub line: usize,
    pub column: usize,
}

/// Non-canonical source metadata retained separately from executable identity.
#[derive(Clone, Debug)]
pub struct SourceOrigins {
    pub query: SourceMap,
    pub profile: Option<SourceMap>,
    pub config: SourceMap,
}
impl SourceOrigins {
    pub fn source(&self, role: SourceRole, path: &str) -> Option<SourceOrigin> {
        let map = match role {
            SourceRole::Query => &self.query,
            SourceRole::Profile => self.profile.as_ref()?,
            SourceRole::Config => &self.config,
        };
        let span = map.span(path)?;
        let (line, column) = map.location(span.start)?;
        Some(SourceOrigin {
            role,
            span,
            line,
            column,
        })
    }
    /// Resolve a merged query path by overlay precedence without affecting hashes.
    pub fn merged(&self, path: &str) -> Option<SourceOrigin> {
        for (role, map) in [
            (SourceRole::Query, Some(&self.query)),
            (SourceRole::Profile, self.profile.as_ref()),
        ] {
            if map.is_some_and(|m| m.exact_span(path).is_some()) {
                return self.source(role, path);
            }
        }
        let config_path = path
            .strip_prefix("/bounds")
            .map(|tail| format!("/defaults{tail}"));
        config_path
            .as_deref()
            .and_then(|p| self.config.exact_span(p).map(|_| p))
            .and_then(|p| self.source(SourceRole::Config, p))
    }
}
fn obj(fields: impl IntoIterator<Item = (&'static str, V)>) -> V {
    V::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
fn array(strings: &[&str]) -> V {
    V::Array(strings.iter().copied().map(V::string).collect())
}
fn set(v: &mut V, key: &str, value: V) -> Result<()> {
    let V::Object(o) = v else {
        return Err(Error::invalid("object"));
    };
    o.insert(key.to_owned(), value);
    Ok(())
}

/// Compile without reading a graph, clock, environment or file. Config is always retained published bytes.
/// Required configured mappings fail unless an explicit capability entry point is used.
pub fn compile(
    query: QuerySource<'_>,
    profile: Option<SelectedProfile<'_>>,
    config: &PublishedArtifact,
    options: CompileOptions,
) -> Result<ValidatedDraft> {
    compile_with_capabilities(
        query,
        profile,
        config,
        options,
        MappingCapabilities::default(),
    )
}

/// Capability selection is not authorization. Only deterministic stored-predicate fixture
/// mappings are implemented; runtime still requires an exact-snapshot trusted provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct MappingCapabilities {
    pub stored_predicate: bool,
    pub reasoned: bool,
    pub computed: bool,
    pub ontology: bool,
    pub lexical_landing: bool,
}

/// Explicit opt-in compiler features. Defaults retain P4's builtin-only behavior.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompilerCapabilities {
    pub mappings: MappingCapabilities,
    pub custom_predicates: bool,
    pub external_functions: bool,
    pub prepared_interpretation: bool,
    pub approximate_landing: bool,
}

pub fn compile_with_compiler_capabilities(
    query: QuerySource<'_>,
    profile: Option<SelectedProfile<'_>>,
    config: &PublishedArtifact,
    options: CompileOptions,
    capabilities: CompilerCapabilities,
) -> Result<ValidatedDraft> {
    compile_internal(query, profile, config, options, capabilities).map(|x| x.0)
}

pub fn compile_with_capabilities(
    query: QuerySource<'_>,
    profile: Option<SelectedProfile<'_>>,
    config: &PublishedArtifact,
    options: CompileOptions,
    capabilities: MappingCapabilities,
) -> Result<ValidatedDraft> {
    compile_internal(
        query,
        profile,
        config,
        options,
        CompilerCapabilities {
            mappings: capabilities,
            custom_predicates: false,
            external_functions: false,
            prepared_interpretation: false,
            approximate_landing: false,
        },
    )
    .map(|x| x.0)
}

/// Compile while retaining query/profile/config source locations as a sidecar.
/// Existing callers can continue to use `compile` unchanged.
pub fn compile_with_source_origins(
    query: QuerySource<'_>,
    profile: Option<SelectedProfile<'_>>,
    config: &PublishedArtifact,
    options: CompileOptions,
    capabilities: MappingCapabilities,
) -> Result<(ValidatedDraft, SourceOrigins)> {
    compile_internal(
        query,
        profile,
        config,
        options,
        CompilerCapabilities {
            mappings: capabilities,
            custom_predicates: false,
            external_functions: false,
            prepared_interpretation: false,
            approximate_landing: false,
        },
    )
}

fn compile_internal(
    query: QuerySource<'_>,
    profile: Option<SelectedProfile<'_>>,
    config: &PublishedArtifact,
    options: CompileOptions,
    capabilities: CompilerCapabilities,
) -> Result<(ValidatedDraft, SourceOrigins)> {
    if let Some(p) = query.published {
        if p.content() != query.bytes {
            return Err(Error::invalid("query published bytes mismatch"));
        }
    }
    let total_bytes = query
        .bytes
        .len()
        .checked_add(config.content().len())
        .and_then(|n| n.checked_add(profile.as_ref().map_or(0, |p| p.artifact.content().len())))
        .ok_or_else(Error::limit)?;
    if total_bytes > options.limits.input_bytes() {
        return Err(Error::limit());
    }
    let mut budget = cdb_core::limits::Budget::new(options.limits);
    budget.charge(0, total_bytes, total_bytes)?;
    let frontend::ParsedDocument {
        value: q,
        source_map: query_map,
        ..
    } = frontend::parse(ArtifactKind::Query, query.bytes, options.limits)?;
    charge_value(&q, &mut budget)?;
    merge::structural(&q, false)?;
    if let Some(c) = q.as_object()?.get("@context") {
        validate_context(c.as_object()?)?;
    }
    let frontend::ParsedDocument {
        value: mut config_value,
        source_map: config_map,
        ..
    } = frontend::parse(ArtifactKind::Config, config.content(), options.limits)?;
    charge_value(&config_value, &mut budget)?;
    let config = (
        SemanticConfig::from_value(&config_value)?,
        config.reference().clone(),
    );
    let mut notices = Vec::new();
    let selected = q.as_object()?.get("profile");
    let mut p = None;
    let mut profile_map = None;
    let mut profile_ref = None;
    match (selected, profile) {
        (None, None) => (),
        (Some(selector), Some(profile)) => {
            let name = selector.as_str()?;
            crate::artifacts::ArtifactName::new(name, options.limits.input_bytes())?;
            if name != profile.selector {
                return Err(Error::invalid("profile selector mismatch"));
            }
            let frontend::ParsedDocument {
                value: mut parsed,
                source_map,
                ..
            } = frontend::parse(
                ArtifactKind::Profile,
                profile.artifact.content(),
                options.limits,
            )?;
            profile_map = Some(source_map);
            charge_value(&parsed, &mut budget)?;
            merge::structural(&parsed, true)?;
            if let Some(c) = parsed.as_object()?.get("@context") {
                validate_context(c.as_object()?)?;
            }
            if parsed.as_object()?.contains_key("profile") {
                return Err(unsupported("profile chaining"));
            }
            if let V::Object(o) = &mut parsed {
                if o.remove("about").is_some() {
                    notices.push(CompileNotice::IgnoredProfileAbout);
                }
                o.remove("name");
            }
            p = Some(parsed);
            profile_ref = Some(profile.artifact.reference().clone());
        }
        _ => {
            return Err(Error::invalid(
                "selected profile required, no unsolicited profile",
            ))
        }
    }
    let mut bounds = obj([
        ("seed_limit", V::integer(2)),
        ("fanout_limit", V::integer(4)),
        ("max_claims", V::integer(16)),
        ("path_limit", V::integer(8)),
    ]);
    if let Some(d) = config_value.as_object()?.get("defaults") {
        merge::merge(&mut bounds, d);
    }
    let mut effective = obj([
        ("@context", obj([])),
        ("bounds", bounds),
        (
            "walk",
            obj([
                ("direction", V::string("outgoing")),
                ("predicates", V::Array(vec![])),
            ]),
        ),
        ("filter", obj([("predicates", V::Array(vec![]))])),
        ("return", ReturnSelection::default().projection()),
    ]);
    if let Some(p) = &p {
        merge::merge_source(&mut effective, p)?;
    }
    merge::merge_source(&mut effective, &q)?;
    let context = effective.field("@context")?.as_object()?.clone();
    validate_context(&context)?;
    let runtime = config_value.field("runtime")?;
    let predicate_numeric = runtime
        .as_object()?
        .get("predicate_numeric")
        .map(V::as_str)
        .transpose()?
        .map(str::to_owned);
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
        return Err(unsupported("runtime ordering strategy"));
    }
    let cycle = match runtime.field("cycle_policy")?.as_str()? {
        "no_repeated_claim" => CyclePolicy::NoRepeatedClaim,
        "allow_repeated_claim" => CyclePolicy::AllowRepeatedClaim,
        "no_repeated_node" => CyclePolicy::NoRepeatedNode,
        _ => return Err(unsupported("cycle policy")),
    };
    if let Some(g) = config_value.as_object()?.get("grounding_registry") {
        if g != &array(&[
            "claim_only",
            "source_lineage_available",
            "source_spans_available",
        ]) {
            return Err(unsupported("grounding registry"));
        }
    }
    validate_mappings(config_value.field("fields")?, &context, &mut budget)?;
    if let V::Object(config_object) = &mut config_value {
        if let Some(V::Object(fields)) = config_object.get_mut("fields") {
            for mapping in fields.values_mut() {
                if let V::Object(mapping) = mapping {
                    if let Some(iri) = mapping.get_mut("iri") {
                        *iri = V::string(expand(iri.as_str()?, &context, true, &mut budget)?);
                    }
                }
            }
        }
    }
    let bounds = effective.field("bounds")?.clone();
    let caps = Caps {
        max_depth: bounds.field("max_depth")?.u64()?,
        seed_limit: bounds.field("seed_limit")?.u64()?,
        fanout_limit: bounds.field("fanout_limit")?.u64()?,
        max_claims: bounds.field("max_claims")?.u64()?,
        path_limit: bounds.field("path_limit")?.u64()?,
    };
    let requested = bounds
        .as_object()?
        .get("as_of")
        .map(|v| Timestamp::parse(v.as_str()?))
        .transpose()?;
    if let Some(t) = requested {
        let mut b = bounds.clone();
        set(&mut b, "as_of", V::string(t.canonical()))?;
        set(&mut effective, "bounds", b)?;
    }
    let mut blocks = Vec::new();
    let mut normalized_blocks = Vec::new();
    for b in effective.field("about")?.as_array()? {
        b.closed(&["from"], &["to", "match"])?;
        let mode = b
            .as_object()?
            .get("match")
            .map(V::as_str)
            .transpose()?
            .unwrap_or("approximate");
        let match_mode = match mode {
            "exact" => MatchMode::Exact,
            "approximate" if capabilities.mappings.lexical_landing => {
                validate_lexical_landing(&config_value)?;
                MatchMode::Approximate
            }
            "approximate" => return Err(unsupported("approximate landing")),
            _ => return Err(Error::invalid("match mode")),
        };
        let from = anchors(b.field("from")?, &context, &mut budget)?;
        let to = b
            .as_object()?
            .get("to")
            .map(|v| anchors(v, &context, &mut budget))
            .transpose()?;
        normalized_blocks.push(obj([
            ("from", V::Array(from.iter().map(V::string).collect())),
            (
                "to",
                to.as_ref()
                    .map(|a| V::Array(a.iter().map(V::string).collect()))
                    .unwrap_or(V::Null),
            ),
            ("match", V::string(mode)),
        ]));
        blocks.push(Block {
            from,
            to,
            match_mode,
        });
    }
    if blocks.is_empty() {
        return Err(Error::invalid("about required"));
    }
    set(&mut effective, "about", V::Array(normalized_blocks))?;
    let direction = match effective.field("walk")?.field("direction")?.as_str()? {
        "outgoing" => Direction::Outgoing,
        "incoming" => Direction::Incoming,
        "both" => Direction::Both,
        _ => return Err(Error::invalid("direction")),
    };
    let mut compiled = Vec::new();
    for (key, phase) in [("walk", Phase::Walk), ("filter", Phase::Filter)] {
        let mut entries = effective
            .field(key)?
            .field("predicates")?
            .as_array()?
            .to_vec();
        let predicates = entries
            .iter_mut()
            .enumerate()
            .map(|(i, v)| {
                predicate(
                    v,
                    phase,
                    i,
                    PredicateContext {
                        bounds: Some(&bounds),
                        context: &context,
                        mappings: config_value.field("fields")?,
                        capabilities,
                        predicate_numeric: predicate_numeric.as_deref(),
                    },
                    &mut budget,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let mut section = effective.field(key)?.clone();
        set(&mut section, "predicates", V::Array(entries))?;
        set(&mut effective, key, section)?;
        compiled.push(predicates);
    }
    let selection = ReturnSelection::from_value(effective.field("return")?)?;
    if let V::Object(o) = &mut effective {
        o.remove("@context");
        o.remove("profile");
    }
    // Apply the same cumulative serializer budget to the expanded effective query.
    effective.canonical_bytes(options.limits)?;
    let filter = compiled.pop().expect("two phases");
    let walk = compiled.pop().expect("two phases");
    Ok((
        ValidatedDraft {
            query: effective,
            config: SemanticConfig::from_value(&config_value)?,
            query_ref: query.published.map(|a| a.reference().clone()),
            profile_ref,
            config_ref: config.1,
            requested,
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
            limits: options.limits,
        },
        SourceOrigins {
            query: query_map,
            profile: profile_map,
            config: config_map,
        },
    ))
}
fn charge_value(v: &V, budget: &mut cdb_core::limits::Budget) -> Result<()> {
    budget.charge(1, 1, 0)?;
    match v {
        V::String(s) => budget.charge(0, s.len(), 0)?,
        V::Number(n) => budget.charge(0, n.token().len(), 0)?,
        V::Array(a) => {
            for v in a {
                charge_value(v, budget)?;
            }
        }
        V::Object(o) => {
            for (k, v) in o {
                budget.charge(0, k.len(), 0)?;
                charge_value(v, budget)?;
            }
        }
        _ => (),
    }
    Ok(())
}
fn validate_context(context: &BTreeMap<String, V>) -> Result<()> {
    for (prefix, iri) in context {
        if prefix.is_empty()
            || !prefix
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            || matches!(prefix.as_str(), "meta" | "path" | "bound" | "ctxql" | "fn")
        {
            return Err(Error::invalid("reserved or malformed prefix"));
        }
        Iri::new(iri.as_str()?)?;
    }
    Ok(())
}
fn expand(
    s: &str,
    context: &BTreeMap<String, V>,
    required: bool,
    budget: &mut cdb_core::limits::Budget,
) -> Result<String> {
    budget.charge(0, s.len(), 0)?;
    if let Some((prefix, local)) = s.split_once(':') {
        if let Some(base) = context.get(prefix) {
            budget.charge(0, base.as_str()?.len(), 0)?;
            let expanded = format!("{}{local}", base.as_str()?);
            Iri::new(&expanded)?;
            return Ok(expanded);
        }
        if prefix == "ctxql"
            || local.starts_with("//")
            || matches!(
                prefix.to_ascii_lowercase().as_str(),
                "urn" | "mailto" | "tag" | "did"
            )
        {
            Iri::new(s)?;
            return Ok(s.into());
        }
        if required {
            return Err(Error::invalid("unknown identifier prefix"));
        }
    } else if required {
        return Err(Error::invalid("IRI or declared CURIE required"));
    }
    Ok(s.into())
}
fn anchors(
    v: &V,
    context: &BTreeMap<String, V>,
    budget: &mut cdb_core::limits::Budget,
) -> Result<Vec<String>> {
    let a = v.as_array()?;
    if a.is_empty() {
        return Err(Error::invalid("empty anchors"));
    }
    a.iter()
        .map(|v| {
            let s = v.as_str()?;
            cdb_core::id::ResourceId::new(s)?;
            expand(s, context, false, budget)
        })
        .collect()
}
fn validate_lexical_landing(config: &V) -> Result<()> {
    let landing = config
        .as_object()?
        .get("landing")
        .ok_or_else(|| unsupported("lexical landing configuration"))?;
    landing.closed(&["resolver", "unicode_version", "minimum_overlap"], &[])?;
    let unicode = landing.field("unicode_version")?.as_array()?;
    if unicode.len() != 3 {
        return Err(Error::invalid("Unicode version tuple"));
    }
    let tuple = (
        u8::try_from(unicode[0].u64()?).map_err(|_| Error::invalid("Unicode version"))?,
        u8::try_from(unicode[1].u64()?).map_err(|_| Error::invalid("Unicode version"))?,
        u8::try_from(unicode[2].u64()?).map_err(|_| Error::invalid("Unicode version"))?,
    );
    crate::lexical::Config::new(
        landing.field("resolver")?.as_str()?,
        tuple,
        landing.field("minimum_overlap")?.u64()?,
    )?;
    Ok(())
}

fn mapping_requires(mapping: &V) -> Result<Vec<String>> {
    mapping
        .as_object()?
        .get("requires")
        .map(|v| {
            v.as_array()?
                .iter()
                .map(|v| Ok(v.as_str()?.to_owned()))
                .collect()
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn compile_mapping(
    field: &FieldRef,
    mappings: &V,
    capabilities: MappingCapabilities,
) -> Result<Option<FieldMapping>> {
    let Some(mapping) = mappings.as_object()?.get(&field.mapping_key()) else {
        return Ok(None);
    };
    let field_name = field.mapping_key();
    let requires = mapping_requires(mapping)?;
    let source = mapping.field("source")?.as_str()?;
    let iri = || Iri::new(mapping.field("iri")?.as_str()?);
    Ok(Some(match source {
        "stored_predicate" if capabilities.stored_predicate => FieldMapping::StoredPredicate {
            field: field_name,
            iri: iri()?,
            requires,
        },
        "reasoned" if capabilities.reasoned => FieldMapping::Reasoned {
            field: field_name,
            iri: iri()?,
            requires,
        },
        "computed" if capabilities.computed => FieldMapping::Computed {
            field: field_name,
            iri: iri()?,
            resolver: ArtifactRef::from_value(mapping.field("resolver")?)?,
            requires,
        },
        _ => return Err(unsupported("configured field resolver required")),
    }))
}

fn validate_mappings(
    fields: &V,
    context: &BTreeMap<String, V>,
    budget: &mut cdb_core::limits::Budget,
) -> Result<()> {
    for (key, mapping) in fields.as_object()? {
        let field = FieldRef::parse(key)?;
        if field.is_path() || !field.metadata_key().starts_with("ext:") {
            return Err(Error::invalid("configured mapping must name ext field"));
        }
        mapping.closed(&["source"], &["iri", "resolver", "requires"])?;
        match mapping.field("source")?.as_str()? {
            "reasoned" | "stored_predicate" => {
                expand(mapping.field("iri")?.as_str()?, context, true, budget)?;
            }
            "computed" => {
                let resolver = mapping.field("resolver")?;
                if ArtifactRef::from_value(resolver).is_err() {
                    // Legacy untyped resolver names remain parseable but cannot be
                    // enabled as prepared native mappings.
                    resolver.as_str()?;
                }
                if let Some(iri) = mapping.as_object()?.get("iri") {
                    expand(iri.as_str()?, context, true, budget)?;
                }
            }
            _ => return Err(unsupported("field mapping source")),
        }
        if let Some(r) = mapping.as_object()?.get("requires") {
            for s in r.as_array()? {
                s.as_str()?;
            }
        }
    }
    Ok(())
}
fn resolve_operand(
    v: &V,
    bounds: &V,
    context: &BTreeMap<String, V>,
    identifier: bool,
    budget: &mut cdb_core::limits::Budget,
) -> Result<V> {
    fn substitute(v: &V, bounds: &V, budget: &mut cdb_core::limits::Budget) -> Result<V> {
        if let V::Array(a) = v {
            budget.charge(1, 1, 0)?;
            return Ok(V::Array(
                a.iter()
                    .map(|v| substitute(v, bounds, budget))
                    .collect::<Result<_>>()?,
            ));
        }
        let resolved = if let V::String(s) = v {
            if let Some(key) = s.strip_prefix("bound:") {
                bounds
                    .as_object()?
                    .get(key)
                    .ok_or_else(|| Error::invalid("missing bound"))?
            } else {
                v
            }
        } else {
            v
        };
        // A bound payload is data, not a recursively evaluated alias/program.
        charge_value(resolved, budget)?;
        Ok(resolved.clone())
    }
    let resolved = substitute(v, bounds, budget)?;
    if identifier {
        match resolved {
            V::String(s) => Ok(V::string(expand(&s, context, true, budget)?)),
            V::Array(a) => Ok(V::Array(
                a.iter()
                    .map(|v| match v {
                        V::Null => Ok(V::Null),
                        _ => Ok(V::string(expand(v.as_str()?, context, true, budget)?)),
                    })
                    .collect::<Result<_>>()?,
            )),
            V::Null => Ok(V::Null),
            _ => Err(Error::invalid("identifier operand")),
        }
    } else {
        Ok(resolved)
    }
}
pub(super) struct PredicateContext<'a> {
    pub bounds: Option<&'a V>,
    pub context: &'a BTreeMap<String, V>,
    pub mappings: &'a V,
    pub capabilities: CompilerCapabilities,
    pub predicate_numeric: Option<&'a str>,
}

fn predicate(
    v: &mut V,
    phase: Phase,
    index: usize,
    context: PredicateContext<'_>,
    budget: &mut cdb_core::limits::Budget,
) -> Result<CompiledPredicate> {
    let name = v
        .as_object()
        .ok()
        .and_then(|o| o.get("name"))
        .map(|v| v.as_str().map(str::to_owned))
        .transpose()?;
    let is_custom = matches!(v, V::Object(o) if !o.contains_key("where"));
    if is_custom {
        if !context.capabilities.custom_predicates {
            return Err(unsupported("custom Rhai predicate"));
        }
        if context.predicate_numeric != Some(crate::predicates::NUMERIC_ABI) {
            return Err(unsupported("custom predicate numeric ABI"));
        }
        let custom = custom::compile(
            v,
            context.bounds,
            context.mappings,
            context.capabilities.mappings,
            budget,
        )?;
        return Ok(CompiledPredicate {
            phase,
            index,
            name,
            body: PredicateBody::Custom(custom),
        });
    }
    let triple = match v {
        V::Array(a) => a,
        V::Object(o) => match o.get_mut("where") {
            Some(V::Array(a)) => a,
            _ => return Err(Error::invalid("predicate")),
        },
        _ => return Err(Error::invalid("predicate")),
    };
    if triple.len() != 3 {
        return Err(Error::invalid("predicate triple requires three elements"));
    }
    let field = FieldRef::parse(triple[0].as_str()?)?;
    let mapping = compile_mapping(&field, context.mappings, context.capabilities.mappings)?;
    let operator = Operator::parse(triple[1].as_str()?)?;
    if matches!(
        operator,
        Operator::Isa
            | Operator::NotIsa
            | Operator::SubpropertyOf
            | Operator::NotSubpropertyOf
            | Operator::ContainsIsa
            | Operator::ContainsSubpropertyOf
    ) && !context.capabilities.mappings.ontology
    {
        return Err(unsupported("ontology reasoning"));
    }
    let mut resolved = if let Some(bounds) = context.bounds {
        resolve_operand(
            &triple[2],
            bounds,
            context.context,
            (field.field_type() == FieldType::Identifier
                || matches!(
                    operator,
                    Operator::Isa
                        | Operator::NotIsa
                        | Operator::SubpropertyOf
                        | Operator::NotSubpropertyOf
                        | Operator::ContainsIsa
                        | Operator::ContainsSubpropertyOf
                ))
                && operator != Operator::Exists,
            budget,
        )?
    } else {
        // Persisted operands are already resolved data, never authored aliases.
        charge_value(&triple[2], budget)?;
        triple[2].clone()
    };
    if field.field_type() == FieldType::Timestamp && operator != Operator::Exists {
        fn normalize(v: &mut V) -> Result<()> {
            match v {
                V::Null | V::Object(_) => (),
                V::Array(a) => {
                    for v in a {
                        normalize(v)?;
                    }
                }
                _ => *v = V::string(Timestamp::parse(v.as_str()?)?.canonical()),
            }
            Ok(())
        }
        normalize(&mut resolved)?;
    }
    let operand = if operator == Operator::Exists {
        Value::Bool(resolved.as_bool()?)
    } else if matches!(
        operator,
        Operator::In | Operator::NotIn | Operator::ContainsAny
    ) {
        Value::List(
            resolved
                .as_array()?
                .iter()
                .map(|v| field.scalar_value(v))
                .collect::<Result<_>>()?,
        )
    } else {
        field.scalar_value(&resolved)?
    };
    // Static type checking using a representative declared field value. Dynamic ext values
    // are checked against their real value by evaluate; operand shape is still checked here.
    let scalar = match field.field_type() {
        FieldType::Number => Value::Number(cdb_core::ExactNumber::from_u64(0)),
        FieldType::Timestamp => Value::Timestamp(Timestamp::parse("2000-01-01T00:00:00Z")?),
        FieldType::Grounding => Value::Grounding(cdb_core::claim::Grounding::ClaimOnly),
        FieldType::String | FieldType::Identifier | FieldType::Lifecycle => {
            Value::String(String::new())
        }
        FieldType::Object => Value::Object(obj([])),
        FieldType::Dynamic => match &operand {
            Value::List(a) => a
                .iter()
                .find(|v| !matches!(v, Value::Null))
                .cloned()
                .unwrap_or(Value::Null),
            v => v.clone(),
        },
    };
    let sample = if field.is_path()
        || (field.field_type() == FieldType::Dynamic
            && matches!(operator, Operator::Contains | Operator::ContainsAny))
    {
        Value::List(vec![scalar])
    } else {
        scalar
    };
    if matches!(
        operator,
        Operator::Isa
            | Operator::NotIsa
            | Operator::SubpropertyOf
            | Operator::NotSubpropertyOf
            | Operator::ContainsIsa
            | Operator::ContainsSubpropertyOf
    ) {
        let Value::String(target) = &operand else {
            return Err(Error::invalid("ontology target IRI"));
        };
        Iri::new(target)?;
        let contains = matches!(
            operator,
            Operator::ContainsIsa | Operator::ContainsSubpropertyOf
        );
        if contains != field.is_path() {
            return Err(Error::invalid("ontology scalar/containment field shape"));
        }
        if !matches!(
            field.field_type(),
            FieldType::Identifier | FieldType::Dynamic
        ) {
            return Err(Error::invalid("ontology field type"));
        }
    } else {
        evaluate(operator, &sample, &operand)?;
    }
    triple[2] = resolved;
    Ok(CompiledPredicate {
        phase,
        index,
        name,
        body: PredicateBody::Builtin(BuiltinPredicate {
            mapping,
            field,
            operator,
            operand,
        }),
    })
}
