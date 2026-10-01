use crate::artifact::{ArtifactRef, FunctionManifest};
use crate::canonical::{CanonicalProjection, Domain};
use crate::claim::*;
use crate::id::*;
use crate::snapshot::GraphPin;
use crate::source::*;
use crate::value::obj;
use crate::{CanonicalValue as V, Error, Limits, Result, Timestamp};
use std::collections::BTreeSet;
fn ident(v: &V) -> Result<()> {
    ResourceId::new(v.as_str()?)?;
    Ok(())
}
fn iri(v: &V) -> Result<()> {
    Iri::new(v.as_str()?)?;
    Ok(())
}
fn hash(v: &V) -> Result<()> {
    ContentHash::parse(v.as_str()?)?;
    Ok(())
}
fn timestamp(v: &V) -> Result<()> {
    let s = v.as_str()?;
    if Timestamp::parse(s)?.canonical() != s {
        return Err(Error::invalid("projected timestamp must be normalized"));
    }
    Ok(())
}
fn nullable(v: &V, f: impl FnOnce(&V) -> Result<()>) -> Result<()> {
    if *v == V::Null {
        Ok(())
    } else {
        f(v)
    }
}
fn artifact(v: &V) -> Result<()> {
    ArtifactRef::from_value(v)?;
    Ok(())
}
fn sorted_strings(v: &V) -> Result<()> {
    let mut last = None;
    for x in v.as_array()? {
        let s = x.as_str()?;
        if last.is_some_and(|l| l >= s) {
            return Err(Error::invalid("sorted unique strings required"));
        }
        last = Some(s);
    }
    Ok(())
}
fn strings(v: &V) -> Result<()> {
    for s in v.as_array()? {
        ident(s)?;
    }
    Ok(())
}
pub(crate) fn validate(domain: Domain, v: &V) -> Result<()> {
    match domain {
        Domain::Plan => validate_plan(v),
        Domain::Response => validate_response(v),
        Domain::FunctionInput | Domain::FunctionOutput => {
            v.closed(
                &["name", "version", "manifest_hash", "call_index", "value"],
                &[],
            )?;
            function_identity(v)?;
            v.field("call_index")?.u64()?;
            Ok(())
        }
        Domain::FunctionInputRoot | Domain::FunctionOutputRoot => {
            v.closed(&["name", "version", "manifest_hash", "hashes"], &[])?;
            function_identity(v)?;
            for h in v.field("hashes")?.as_array()? {
                hash(h)?;
            }
            Ok(())
        }
        Domain::StructuredProduct | Domain::TextProduct => {
            validate_product(v, domain == Domain::TextProduct)
        }
        Domain::StructuredClaim => validate_structured_claim(v),
    }
}
fn function_identity(v: &V) -> Result<()> {
    ident(v.field("name")?)?;
    ident(v.field("version")?)?;
    hash(v.field("manifest_hash")?)
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionCallProjection(CanonicalProjection);
impl FunctionCallProjection {
    pub fn new(
        output: bool,
        manifest: &FunctionManifest,
        call_index: u64,
        value: V,
    ) -> Result<Self> {
        Ok(Self(CanonicalProjection::from_payload(
            if output {
                Domain::FunctionOutput
            } else {
                Domain::FunctionInput
            },
            obj([
                ("name", V::string(manifest.name().as_str())),
                ("version", V::string(manifest.version().as_str())),
                ("manifest_hash", V::string(manifest.hash().as_str())),
                ("call_index", V::integer(call_index)),
                ("value", value),
            ]),
        )?))
    }
    pub fn canonical(&self) -> &CanonicalProjection {
        &self.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionRootProjection(CanonicalProjection);
impl FunctionRootProjection {
    pub fn new(output: bool, manifest: &FunctionManifest, hashes: &[ContentHash]) -> Result<Self> {
        Ok(Self(CanonicalProjection::from_payload(
            if output {
                Domain::FunctionOutputRoot
            } else {
                Domain::FunctionInputRoot
            },
            obj([
                ("name", V::string(manifest.name().as_str())),
                ("version", V::string(manifest.version().as_str())),
                ("manifest_hash", V::string(manifest.hash().as_str())),
                (
                    "hashes",
                    V::Array(hashes.iter().map(|h| V::string(h.as_str())).collect()),
                ),
            ]),
        )?))
    }
    pub fn canonical(&self) -> &CanonicalProjection {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReturnSelection {
    pub claims: bool,
    pub paths: bool,
    pub evidence: bool,
    pub explain: bool,
}
impl Default for ReturnSelection {
    fn default() -> Self {
        Self {
            claims: true,
            paths: true,
            evidence: false,
            explain: false,
        }
    }
}
impl ReturnSelection {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(&["claims", "paths", "evidence", "explain"], &[])?;
        Ok(Self {
            claims: v.field("claims")?.as_bool()?,
            paths: v.field("paths")?.as_bool()?,
            evidence: v.field("evidence")?.as_bool()?,
            explain: v.field("explain")?.as_bool()?,
        })
    }
    pub fn projection(self) -> V {
        obj([
            ("claims", V::Bool(self.claims)),
            ("paths", V::Bool(self.paths)),
            ("evidence", V::Bool(self.evidence)),
            ("explain", V::Bool(self.explain)),
        ])
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticConfig(V);
impl SemanticConfig {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &["name", "version", "runtime", "fields", "external_functions"],
            &["preparation", "grounding_registry", "defaults", "landing"],
        )?;
        ident(v.field("name")?)?;
        ident(v.field("version")?)?;
        let r = v.field("runtime")?;
        r.closed(
            &["candidate_order", "path_ranking", "cycle_policy"],
            &["predicate_numeric"],
        )?;
        if let Some(numeric) = r.as_object()?.get("predicate_numeric") {
            if numeric.as_str()? != "ctxql-predicate-numeric/v2" {
                return Err(Error::invalid("predicate numeric ABI"));
            }
        }
        strings(r.field("candidate_order")?)?;
        strings(r.field("path_ranking")?)?;
        ident(r.field("cycle_policy")?)?;
        v.field("fields")?.as_object()?;
        for (name, f) in v.field("external_functions")?.as_object()? {
            crate::id::ResourceId::new(name)?;
            f.closed(
                &["version", "manifest_uri", "manifest_hash", "deterministic"],
                &[],
            )?;
            ident(f.field("version")?)?;
            iri(f.field("manifest_uri")?)?;
            hash(f.field("manifest_hash")?)?;
            f.field("deterministic")?.as_bool()?;
        }
        if let Some(p) = v.as_object()?.get("preparation") {
            let mut ids = BTreeSet::new();
            for s in p.as_array()? {
                SourceDeclaration::from_value(s)?;
                if !ids.insert(s.field("source_id")?.as_str()?) {
                    return Err(Error::invalid("duplicate configured source"));
                }
            }
        }
        if let Some(d) = v.as_object()?.get("defaults") {
            d.closed(
                &["seed_limit", "fanout_limit", "max_claims", "path_limit"],
                &[],
            )?;
            for n in d.as_object()?.values() {
                n.u64()?;
            }
        }
        if let Some(g) = v.as_object()?.get("grounding_registry") {
            strings(g)?;
        }
        if let Some(l) = v.as_object()?.get("landing") {
            l.closed(&["resolver", "unicode_version", "minimum_overlap"], &[])?;
            ident(l.field("resolver")?)?;
            let unicode = l.field("unicode_version")?.as_array()?;
            if unicode.len() != 3
                || unicode
                    .iter()
                    .any(|n| n.u64().map_or(true, |n| n > u8::MAX as u64))
            {
                return Err(Error::invalid("Unicode version tuple"));
            }
            if l.field("minimum_overlap")?.u64()? == 0 {
                return Err(Error::invalid("lexical minimum overlap"));
            }
        }
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedQuery(V);
impl NormalizedQuery {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(&["about", "bounds", "walk", "filter", "return"], &[])?;
        let a = v.field("about")?.as_array()?;
        if a.is_empty() {
            return Err(Error::invalid("about blocks required"));
        }
        for b in a {
            b.closed(&["from", "to", "match"], &[])?;
            if b.field("from")?.as_array()?.is_empty() {
                return Err(Error::invalid("from anchors"));
            }
            strings(b.field("from")?)?;
            if *b.field("to")? != V::Null {
                if b.field("to")?.as_array()?.is_empty() {
                    return Err(Error::invalid("empty to"));
                }
                strings(b.field("to")?)?;
            }
            if !matches!(b.field("match")?.as_str()?, "exact" | "approximate") {
                return Err(Error::invalid("match"));
            }
        }
        validate_bounds(v.field("bounds")?)?;
        for phase in ["walk", "filter"] {
            let p = v.field(phase)?;
            if phase == "walk" {
                p.closed(&["direction", "predicates"], &[])?;
                if !matches!(
                    p.field("direction")?.as_str()?,
                    "outgoing" | "incoming" | "both"
                ) {
                    return Err(Error::invalid("direction"));
                }
            } else {
                p.closed(&["predicates"], &[])?;
            }
            let mut names = BTreeSet::new();
            for predicate in p.field("predicates")?.as_array()? {
                if let V::Array(triple) = predicate {
                    if triple.len() != 3 {
                        return Err(Error::invalid("built-in predicate triple"));
                    }
                    triple[0].as_str()?;
                    triple[1].as_str()?;
                    continue;
                }
                predicate.as_object()?;
                if let Some(n) = predicate.as_object()?.get("name") {
                    ident(n)?;
                    if !names.insert(n.as_str()?) {
                        return Err(Error::invalid("duplicate predicate name"));
                    }
                } // P2 owns predicate language semantics; payloads remain open, lossless data.
            }
        }
        ReturnSelection::from_value(v.field("return")?)?;
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
}
pub fn validate_bounds(v: &V) -> Result<()> {
    // Bounds is explicitly open to query-bound values (design §3.3).
    // Required execution caps are validated below; custom values stay lossless.
    v.as_object()?;
    timestamp(v.field("as_of")?)?;
    for k in [
        "max_depth",
        "seed_limit",
        "fanout_limit",
        "max_claims",
        "path_limit",
    ] {
        v.field(k)?.u64()?;
    }
    Ok(())
}
fn validate_plan(v: &V) -> Result<()> {
    v.closed(&["query", "artifacts", "config", "as_of"], &[])?;
    NormalizedQuery::from_value(v.field("query")?)?;
    let a = v.field("artifacts")?;
    a.closed(&["query", "profile", "config"], &[])?;
    nullable(a.field("query")?, artifact)?;
    nullable(a.field("profile")?, artifact)?;
    artifact(a.field("config")?)?;
    SemanticConfig::from_value(v.field("config")?)?;
    timestamp(v.field("as_of")?)?;
    if v.field("query")?.field("bounds")?.field("as_of")? != v.field("as_of")? {
        return Err(Error::invalid("as_of mismatch"));
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanProjection(CanonicalProjection);
impl PlanProjection {
    pub fn new(
        query: NormalizedQuery,
        query_ref: Option<ArtifactRef>,
        profile: Option<ArtifactRef>,
        config_ref: ArtifactRef,
        config: SemanticConfig,
        as_of: Timestamp,
    ) -> Result<Self> {
        Ok(Self(CanonicalProjection::from_payload(
            Domain::Plan,
            obj([
                ("query", query.projection()),
                (
                    "artifacts",
                    obj([
                        (
                            "query",
                            query_ref.map(|r| r.projection()).unwrap_or(V::Null),
                        ),
                        (
                            "profile",
                            profile.map(|r| r.projection()).unwrap_or(V::Null),
                        ),
                        ("config", config_ref.projection()),
                    ]),
                ),
                ("config", config.projection()),
                ("as_of", V::string(as_of.canonical())),
            ]),
        )?))
    }
    pub fn canonical(&self) -> &CanonicalProjection {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphStatus {
    Ready,
    ReadyWithWarnings,
    Blocked,
    Error,
}
impl GraphStatus {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "ready" => Ok(Self::Ready),
            "ready_with_warnings" => Ok(Self::ReadyWithWarnings),
            "blocked" => Ok(Self::Blocked),
            "error" => Ok(Self::Error),
            _ => Err(Error::invalid("graph status")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::ReadyWithWarnings => "ready_with_warnings",
            Self::Blocked => "blocked",
            Self::Error => "error",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticNotice {
    code: ResourceId,
    details: V,
}
impl SemanticNotice {
    pub fn new(code: ResourceId, details: V) -> Self {
        Self { code, details }
    }
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(&["code", "details"], &[])?;
        Ok(Self::new(
            ResourceId::new(v.field("code")?.as_str()?)?,
            v.field("details")?.clone(),
        ))
    }
    pub fn projection(&self) -> V {
        obj([
            ("code", V::string(self.code.as_str())),
            ("details", self.details.clone()),
        ])
    }
}
fn validate_notices(v: &V, sorted: bool) -> Result<()> {
    let mut last = None;
    for n in v.as_array()? {
        SemanticNotice::from_value(n)?;
        let bytes = n.canonical_bytes(Limits::default())?;
        if sorted && last.as_ref().is_some_and(|l| l >= &bytes) {
            return Err(Error::invalid("notices canonical sorted unique"));
        }
        last = Some(bytes);
    }
    Ok(())
}
fn validate_response_claim(v: &V) -> Result<()> {
    v.closed(&["meta"], &[])?;
    let meta = v.field("meta")?;
    meta.closed(
        &[
            "claim_id",
            "subject_id",
            "relation",
            "object_id",
            "relation_type",
            "subject_type",
            "object_type",
            "claim_type",
            "confidence",
            "grounding_level",
            "lineage",
            "ext",
            "transaction_time",
            "lifecycle_state",
        ],
        &[],
    )?;
    timestamp(meta.field("transaction_time")?)?;
    LifecycleState::parse(meta.field("lifecycle_state")?.as_str()?)?;
    let mut candidate = meta.as_object()?.clone();
    candidate.remove("transaction_time");
    candidate.remove("lifecycle_state");
    if let Some(V::Object(ext)) = candidate.get_mut("ext") {
        if let Some(t) = ext.remove("ctxql.core.temporal/v1") {
            t.closed(&[], &["valid_time", "source_observed_at"])?;
            for (k, v) in t.as_object()? {
                timestamp(v)?;
                candidate.insert(k.clone(), v.clone());
            }
        }
    }
    CandidateClaim::from_value(&V::Object(candidate))?;
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseClaim {
    claim: AdmittedClaim,
    state: LifecycleState,
}
impl ResponseClaim {
    pub fn new(claim: AdmittedClaim, state: LifecycleState) -> Self {
        Self { claim, state }
    }
    pub fn projection(&self) -> V {
        self.claim.response(self.state)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathProjection(V);
impl PathProjection {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &[
                "seed_id",
                "node_ids",
                "endpoints",
                "claim_ids",
                "depth",
                "reached_target",
                "block_index",
                "scores",
            ],
            &[],
        )?;
        ident(v.field("seed_id")?)?;
        strings(v.field("node_ids")?)?;
        strings(v.field("claim_ids")?)?;
        let depth = v.field("depth")?.u64()?;
        if depth == 0
            || depth != v.field("claim_ids")?.as_array()?.len() as u64
            || depth.checked_add(1) != Some(v.field("endpoints")?.as_array()?.len() as u64)
        {
            return Err(Error::invalid("path depth/endpoint count"));
        }
        let endpoints = v
            .field("endpoints")?
            .as_array()?
            .iter()
            .map(ClaimObject::from_endpoint)
            .collect::<Result<Vec<_>>>()?;
        if !matches!(endpoints.first(), Some(ClaimObject::Entity(id)) if id.as_str() == v.field("seed_id")?.as_str()?)
            || endpoints[..endpoints.len() - 1]
                .iter()
                .any(|e| matches!(e, ClaimObject::Literal(_)))
        {
            return Err(Error::invalid("path seed or nonterminal literal"));
        }
        let entities: Vec<_> = endpoints
            .iter()
            .filter_map(|e| {
                if let ClaimObject::Entity(id) = e {
                    Some(V::string(id.as_str()))
                } else {
                    None
                }
            })
            .collect();
        if v.field("node_ids")?.as_array()? != entities
            || entities.first() != Some(v.field("seed_id")?)
        {
            return Err(Error::invalid("path entity trace"));
        }
        nullable(v.field("reached_target")?, ident)?;
        if *v.field("reached_target")? != V::Null
            && !matches!(endpoints.last(), Some(ClaimObject::Entity(id)) if id.as_str() == v.field("reached_target")?.as_str()?)
        {
            return Err(Error::invalid("target endpoint"));
        }
        v.field("block_index")?.u64()?;
        let s = v.field("scores")?;
        s.closed(&["accumulated_confidence", "grounding_level"], &[])?;
        Confidence::new(s.field("accumulated_confidence")?.as_number()?.clone())?;
        Grounding::parse(s.field("grounding_level")?.as_str()?)?;
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplainProjection(V);
impl ExplainProjection {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &[
                "evaluation_context",
                "seeds",
                "ontology_resolution",
                "traversal_stats",
                "lifecycle",
            ],
            &[],
        )?;
        let e = v.field("evaluation_context")?;
        e.closed(&["as_of", "db_time", "profile", "bounds"], &[])?;
        timestamp(e.field("as_of")?)?;
        GraphPin::from_value(e.field("db_time")?)?;
        nullable(e.field("profile")?, artifact)?;
        validate_bounds(e.field("bounds")?)?;
        if e.field("as_of")? != e.field("bounds")?.field("as_of")? {
            return Err(Error::invalid("explain cutoff"));
        }
        for s in v.field("seeds")?.as_array()? {
            validate_landing(s)?;
        }
        for o in v.field("ontology_resolution")?.as_array()? {
            o.closed(
                &[
                    "predicate_index",
                    "operator",
                    "requested",
                    "matched",
                    "rule",
                ],
                &[],
            )?;
            o.field("predicate_index")?.u64()?;
            ident(o.field("operator")?)?;
            iri(o.field("requested")?)?;
            for m in o.field("matched")?.as_array()? {
                iri(m)?;
            }
            ident(o.field("rule")?)?;
        }
        let t = v.field("traversal_stats")?;
        t.closed(
            &[
                "examined",
                "eligible",
                "traversed",
                "unique_traversed",
                "returned_paths",
            ],
            &[],
        )?;
        for n in t.as_object()?.values() {
            n.u64()?;
        }
        let mut last = None;
        for l in v.field("lifecycle")?.as_array()? {
            l.closed(&["claim_id", "rule", "state", "supporting_ids"], &[])?;
            let id = l.field("claim_id")?.as_str()?;
            ident(l.field("claim_id")?)?;
            if last.is_some_and(|s| s >= id) {
                return Err(Error::invalid("lifecycle sorted unique"));
            }
            last = Some(id);
            if l.field("rule")?.as_str()? != "ctxql-execution/v1:lifecycle" {
                return Err(Error::invalid("lifecycle rule identity"));
            }
            LifecycleState::parse(l.field("state")?.as_str()?)?;
            strings(l.field("supporting_ids")?)?;
        }
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
}
pub(crate) fn validate_landing(s: &V) -> Result<()> {
    s.closed(&["block_index", "role", "anchor", "id", "score"], &[])?;
    s.field("block_index")?.u64()?;
    if !matches!(s.field("role")?.as_str()?, "from" | "to") {
        return Err(Error::invalid("landing role"));
    }
    ident(s.field("anchor")?)?;
    ident(s.field("id")?)?;
    s.field("score")?.u64()?;
    Ok(())
}
fn validate_response(v: &V) -> Result<()> {
    v.closed(
        &[
            "selection",
            "graph_status",
            "semantic_flags",
            "notices",
            "claims",
            "paths",
            "explain",
        ],
        &[],
    )?;
    let s = ReturnSelection::from_value(v.field("selection")?)?;
    GraphStatus::parse(v.field("graph_status")?.as_str()?)?;
    sorted_strings(v.field("semantic_flags")?)?;
    validate_notices(v.field("notices")?, true)?;
    for (key, selected) in [
        ("claims", s.claims),
        ("paths", s.paths),
        ("explain", s.explain),
    ] {
        let section = v.field(key)?;
        if !selected {
            if *section != V::Null {
                return Err(Error::invalid("unselected section must be null"));
            }
            continue;
        }
        match key {
            "claims" => {
                let mut last = None;
                for c in section.as_array()? {
                    validate_response_claim(c)?;
                    let id = c.field("meta")?.field("claim_id")?.as_str()?;
                    if last.is_some_and(|l| l >= id) {
                        return Err(Error::invalid("claims sorted unique"));
                    }
                    last = Some(id);
                }
            }
            "paths" => {
                for p in section.as_array()? {
                    PathProjection::from_value(p)?;
                }
            }
            _ => {
                ExplainProjection::from_value(section)?;
            }
        }
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseProjection(CanonicalProjection);
impl ResponseProjection {
    pub fn new(
        selection: ReturnSelection,
        status: GraphStatus,
        flags: Vec<String>,
        notices: Vec<SemanticNotice>,
        claims: Vec<ResponseClaim>,
        paths: Vec<PathProjection>,
        explain: Option<ExplainProjection>,
    ) -> Result<Self> {
        let flags: BTreeSet<_> = flags.into_iter().collect();
        let mut notice_map = std::collections::BTreeMap::new();
        for n in notices {
            let v = n.projection();
            notice_map.insert(v.canonical_bytes(Limits::default())?, v);
        }
        let mut claims = claims
            .iter()
            .map(ResponseClaim::projection)
            .collect::<Vec<_>>();
        claims.sort_by(|a, b| {
            a.field("meta")
                .and_then(|v| v.field("claim_id"))
                .and_then(V::as_str)
                .ok()
                .cmp(
                    &b.field("meta")
                        .and_then(|v| v.field("claim_id"))
                        .and_then(V::as_str)
                        .ok(),
                )
        });
        let v = obj([
            ("selection", selection.projection()),
            ("graph_status", V::string(status.as_str())),
            (
                "semantic_flags",
                V::Array(flags.into_iter().map(V::string).collect()),
            ),
            ("notices", V::Array(notice_map.into_values().collect())),
            (
                "claims",
                if selection.claims {
                    V::Array(claims)
                } else {
                    V::Null
                },
            ),
            (
                "paths",
                if selection.paths {
                    V::Array(paths.iter().map(PathProjection::projection).collect())
                } else {
                    V::Null
                },
            ),
            (
                "explain",
                if selection.explain {
                    explain
                        .ok_or_else(|| Error::invalid("selected explain required"))?
                        .projection()
                } else {
                    V::Null
                },
            ),
        ]);
        Ok(Self(CanonicalProjection::from_payload(
            Domain::Response,
            v,
        )?))
    }
    pub fn canonical(&self) -> &CanonicalProjection {
        &self.0
    }
}
fn validate_structured_claim(v: &V) -> Result<()> {
    v.closed(
        &[
            "mode",
            "source_id",
            "snapshot",
            "row_key",
            "mapping_hash",
            "slot",
            "occurrence",
        ],
        &[],
    )?;
    let mode = PreparationMode::parse(v.field("mode")?.as_str()?)?;
    SourceId::new(v.field("source_id")?.as_str()?)?;
    let snapshot = ExternalSnapshot::from_value(v.field("snapshot")?)?;
    RowKey::from_value(v.field("row_key")?)?;
    hash(v.field("mapping_hash")?)?;
    if snapshot.mapping_hash()?.as_str() != v.field("mapping_hash")?.as_str()? {
        return Err(Error::invalid("snapshot mapping mismatch"));
    }
    AssertionSlot::from_value(v.field("slot")?)?;
    match mode {
        PreparationMode::Import => {
            IdempotencyKey::new(v.field("occurrence")?.as_str()?)?;
        }
        PreparationMode::Live => {
            if *v.field("occurrence")? != V::Null {
                return Err(Error::invalid("live occurrence must be null"));
            }
        }
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuredClaimProjection(CanonicalProjection);
impl StructuredClaimProjection {
    pub fn new(
        mode: PreparationMode,
        source: SourceId,
        snapshot: ExternalSnapshot,
        row_key: RowKey,
        mapping_hash: ContentHash,
        slot: AssertionSlot,
        occurrence: Option<IdempotencyKey>,
    ) -> Result<Self> {
        Ok(Self(CanonicalProjection::from_payload(
            Domain::StructuredClaim,
            obj([
                ("mode", V::string(mode.as_str())),
                ("source_id", V::string(source.as_str())),
                ("snapshot", snapshot.projection()),
                ("row_key", row_key.projection()),
                ("mapping_hash", V::string(mapping_hash.as_str())),
                ("slot", slot.projection()),
                (
                    "occurrence",
                    occurrence.map(|k| V::string(k.as_str())).unwrap_or(V::Null),
                ),
            ]),
        )?))
    }
    pub fn canonical(&self) -> &CanonicalProjection {
        &self.0
    }
}
fn validate_product(v: &V, text: bool) -> Result<()> {
    v.closed(
        &[
            "assembly",
            "product_type",
            "inputs",
            "sources",
            "notices",
            "citations",
            "content",
        ],
        &[],
    )?;
    validate_assembly(v.field("assembly")?)?;
    if v.field("product_type")?.as_str()? != if text { "text" } else { "structured" } {
        return Err(Error::invalid("product type/domain mismatch"));
    }
    let inputs = v.field("inputs")?.as_array()?;
    if inputs.is_empty() {
        return Err(Error::invalid("product inputs required"));
    }
    let mut names = std::collections::BTreeMap::new();
    for input in inputs {
        ProductInput::from_value(input)?;
        if names
            .insert(input.field("name")?.as_str()?, input)
            .is_some()
        {
            return Err(Error::invalid("duplicate product input name"));
        }
    }
    let sources = v.field("sources")?.as_array()?;
    let mut seen = BTreeSet::new();
    for s in sources {
        ProductSource::from_value(s)?;
        if !seen.insert(s.canonical_bytes(Limits::default())?) {
            return Err(Error::invalid("duplicate complete source reference"));
        }
    }
    for n in v.field("notices")?.as_array()? {
        n.closed(&["input_name", "code", "details"], &[])?;
        if *n.field("input_name")? != V::Null
            && !names.contains_key(n.field("input_name")?.as_str()?)
        {
            return Err(Error::invalid("notice input name"));
        }
        ident(n.field("code")?)?;
    }
    for c in v.field("citations")?.as_array()? {
        c.closed(&["input_name", "claim_id", "source_index"], &[])?;
        let input = names
            .get(c.field("input_name")?.as_str()?)
            .ok_or_else(|| Error::invalid("citation input"))?;
        if !input
            .field("claim_ids")?
            .as_array()?
            .contains(c.field("claim_id")?)
            || c.field("source_index")?.u64()? >= sources.len() as u64
        {
            return Err(Error::invalid("citation reference"));
        }
    }
    if text {
        let s = v.field("content")?.as_str()?;
        if normalize_product_text(s) != s {
            return Err(Error::invalid(
                "text projection must have LF and terminal LF",
            ));
        }
    }
    Ok(())
}
pub fn normalize_product_text(s: &str) -> String {
    let mut s = s.replace("\r\n", "\n").replace('\r', "\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}
pub(crate) fn validate_assembly(v: &V) -> Result<()> {
    v.closed(&["iri", "name", "version", "hash"], &[])?;
    iri(v.field("iri")?)?;
    ident(v.field("name")?)?;
    ident(v.field("version")?)?;
    hash(v.field("hash")?)
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductInput(V);
impl ProductInput {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &[
                "name",
                "query",
                "profile",
                "plan_hash",
                "run_id",
                "response_hash",
                "as_of",
                "db_time",
                "claim_ids",
                "availability",
            ],
            &[],
        )?;
        ident(v.field("name")?)?;
        sorted_strings(v.field("claim_ids")?)?;
        match v.field("availability")?.as_str()? {
            "absent" => {
                for k in [
                    "query",
                    "profile",
                    "plan_hash",
                    "run_id",
                    "response_hash",
                    "as_of",
                    "db_time",
                ] {
                    if *v.field(k)? != V::Null {
                        return Err(Error::invalid("absent input refs must be null"));
                    }
                }
                if !v.field("claim_ids")?.as_array()?.is_empty() {
                    return Err(Error::invalid("absent input claims"));
                }
            }
            "present" => {
                nullable(v.field("query")?, artifact)?;
                nullable(v.field("profile")?, artifact)?;
                hash(v.field("plan_hash")?)?;
                hash(v.field("response_hash")?)?;
                ident(v.field("run_id")?)?;
                timestamp(v.field("as_of")?)?;
                GraphPin::from_value(v.field("db_time")?)?;
            }
            _ => return Err(Error::invalid("input availability")),
        }
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductSource(V);
impl ProductSource {
    pub fn from_value(v: &V) -> Result<Self> {
        v.closed(
            &[
                "source_id",
                "version",
                "fragment_id",
                "selectors",
                "content_hash",
                "conversion",
            ],
            &[],
        )?;
        ident(v.field("source_id")?)?;
        nullable(v.field("version")?, hash)?;
        nullable(v.field("fragment_id")?, ident)?;
        crate::evidence::validate_selectors(v.field("selectors")?)?;
        nullable(v.field("content_hash")?, hash)?;
        if *v.field("conversion")? != V::Null {
            crate::evidence::ConversionProvenance::from_value(v.field("conversion")?)?;
        }
        Ok(Self(v.clone()))
    }
    pub fn projection(&self) -> V {
        self.0.clone()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductProjection(CanonicalProjection);
impl ProductProjection {
    /// Typed product components; invocation ID, timing, hydration and self hash are not parameters.
    pub fn new(
        text: bool,
        assembly: V,
        inputs: Vec<ProductInput>,
        sources: Vec<ProductSource>,
        notices: V,
        citations: V,
        content: V,
    ) -> Result<Self> {
        let content = if text {
            V::string(normalize_product_text(content.as_str()?))
        } else {
            content
        };
        Ok(Self(CanonicalProjection::from_payload(
            if text {
                Domain::TextProduct
            } else {
                Domain::StructuredProduct
            },
            obj([
                ("assembly", assembly),
                (
                    "product_type",
                    V::string(if text { "text" } else { "structured" }),
                ),
                (
                    "inputs",
                    V::Array(inputs.iter().map(ProductInput::projection).collect()),
                ),
                (
                    "sources",
                    V::Array(sources.iter().map(ProductSource::projection).collect()),
                ),
                ("notices", notices),
                ("citations", citations),
                ("content", content),
            ]),
        )?))
    }
    pub fn canonical(&self) -> &CanonicalProjection {
        &self.0
    }
}
