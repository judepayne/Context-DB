use super::{custom::CustomProgram, FieldRef};
use crate::{
    diagnostics::CompileNotice,
    values::{evaluate, Operator, Value},
};
use cdb_core::{
    artifact::ArtifactRef,
    id::ContentHash,
    projection::{NormalizedQuery, PlanProjection, ReturnSelection, SemanticConfig},
    CanonicalValue as V, Error, Limits, Result, Timestamp,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Walk,
    Filter,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Outgoing,
    Incoming,
    Both,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CyclePolicy {
    NoRepeatedClaim,
    AllowRepeatedClaim,
    NoRepeatedNode,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub(super) from: Vec<String>,
    pub(super) to: Option<Vec<String>>,
    pub(super) match_mode: MatchMode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchMode {
    Exact,
    Approximate,
}
impl Block {
    pub fn from(&self) -> &[String] {
        &self.from
    }
    pub fn to(&self) -> Option<&[String]> {
        self.to.as_deref()
    }
    pub fn match_mode(&self) -> MatchMode {
        self.match_mode
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Caps {
    pub max_depth: u64,
    pub seed_limit: u64,
    pub fanout_limit: u64,
    pub max_claims: u64,
    pub path_limit: u64,
}
/// Typed configured field mapping. Construction is compiler-only; runtime values
/// still require an exact-snapshot prepared provider and authorized dependencies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FieldMapping {
    StoredPredicate {
        field: String,
        iri: cdb_core::id::Iri,
        requires: Vec<String>,
    },
    Reasoned {
        field: String,
        iri: cdb_core::id::Iri,
        requires: Vec<String>,
    },
    Computed {
        field: String,
        iri: cdb_core::id::Iri,
        resolver: ArtifactRef,
        requires: Vec<String>,
    },
}
/// Compatibility name for the pre-P5 public seam; values are now typed variants.
pub type StoredPredicateMapping = FieldMapping;
impl FieldMapping {
    pub fn field(&self) -> &str {
        match self {
            Self::StoredPredicate { field, .. }
            | Self::Reasoned { field, .. }
            | Self::Computed { field, .. } => field,
        }
    }
    pub fn iri(&self) -> &cdb_core::id::Iri {
        match self {
            Self::StoredPredicate { iri, .. }
            | Self::Reasoned { iri, .. }
            | Self::Computed { iri, .. } => iri,
        }
    }
    pub fn requires(&self) -> &[String] {
        match self {
            Self::StoredPredicate { requires, .. }
            | Self::Reasoned { requires, .. }
            | Self::Computed { requires, .. } => requires,
        }
    }
    pub fn source(&self) -> &'static str {
        match self {
            Self::StoredPredicate { .. } => "stored_predicate",
            Self::Reasoned { .. } => "reasoned",
            Self::Computed { .. } => "computed",
        }
    }
    pub fn resolver(&self) -> Option<&ArtifactRef> {
        match self {
            Self::Computed { resolver, .. } => Some(resolver),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinPredicate {
    pub(super) mapping: Option<StoredPredicateMapping>,
    pub(super) field: FieldRef,
    pub(super) operator: Operator,
    pub(super) operand: Value,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PredicateBody {
    Builtin(BuiltinPredicate),
    Custom(CustomProgram),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPredicate {
    pub(super) phase: Phase,
    pub(super) index: usize,
    pub(super) name: Option<String>,
    pub(super) body: PredicateBody,
}
impl CompiledPredicate {
    pub fn body(&self) -> &PredicateBody {
        &self.body
    }
    pub fn builtin(&self) -> Option<&BuiltinPredicate> {
        match &self.body {
            PredicateBody::Builtin(value) => Some(value),
            PredicateBody::Custom(_) => None,
        }
    }
    pub fn custom(&self) -> Option<&CustomProgram> {
        match &self.body {
            PredicateBody::Custom(value) => Some(value),
            PredicateBody::Builtin(_) => None,
        }
    }
    pub fn mapping(&self) -> Option<&StoredPredicateMapping> {
        self.builtin().and_then(|value| value.mapping.as_ref())
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}
impl BuiltinPredicate {
    pub fn mapping(&self) -> Option<&StoredPredicateMapping> {
        self.mapping.as_ref()
    }
    pub fn field(&self) -> &FieldRef {
        &self.field
    }
    pub fn operator(&self) -> Operator {
        self.operator
    }
    pub fn operand(&self) -> &Value {
        &self.operand
    }
    pub fn evaluate(&self, looked_up: &Value) -> Result<bool> {
        evaluate(self.operator, looked_up, &self.operand)
    }
    /// Bare filter predicates are independently existential. Caller supplies claim-order values.
    /// Path predicates receive one ordered list, including internal Missing entries.
    pub fn evaluate_filter(&self, claim_values: &[Value], phase: Phase) -> Result<bool> {
        if phase != Phase::Filter {
            return Err(Error::invalid("filter phase required"));
        }
        if self.field.is_path() {
            return self.evaluate(&Value::List(claim_values.to_vec()));
        }
        let mut accepted = false;
        for v in claim_values {
            accepted |= self.evaluate(v)?;
        }
        Ok(accepted)
    }
}
#[derive(Clone, Debug)]
pub(super) struct Semantics {
    pub blocks: Vec<Block>,
    pub caps: Caps,
    pub direction: Direction,
    pub cycle: CyclePolicy,
    pub walk: Vec<CompiledPredicate>,
    pub filter: Vec<CompiledPredicate>,
    pub selection: ReturnSelection,
}
/// Validated pre-capture draft. Only the compiler can construct this value.
#[derive(Clone, Debug)]
pub struct ValidatedDraft {
    pub(super) query: V,
    pub(super) config: SemanticConfig,
    pub(super) query_ref: Option<ArtifactRef>,
    pub(super) profile_ref: Option<ArtifactRef>,
    pub(super) config_ref: ArtifactRef,
    pub(super) requested: Option<Timestamp>,
    pub(super) semantics: Semantics,
    pub(super) notices: Vec<CompileNotice>,
    pub(super) limits: Limits,
}
impl ValidatedDraft {
    pub fn walk_predicates(&self) -> &[CompiledPredicate] {
        &self.semantics.walk
    }
    pub fn filter_predicates(&self) -> &[CompiledPredicate] {
        &self.semantics.filter
    }
    pub fn semantic_config(&self) -> V {
        self.config.projection()
    }
    pub fn requested_as_of(&self) -> Option<Timestamp> {
        self.requested
    }
    pub fn has_custom_predicates(&self) -> bool {
        self.semantics
            .walk
            .iter()
            .chain(&self.semantics.filter)
            .any(|predicate| predicate.custom().is_some())
    }
    pub fn notices(&self) -> &[CompileNotice] {
        &self.notices
    }
    /// The coordinator supplies capture's cutoff; explicit requested cutoff must agree exactly.
    pub fn finalize(mut self, captured_as_of: Timestamp) -> Result<ExecutablePlan> {
        if self.requested.is_some_and(|t| t != captured_as_of) {
            return Err(Error::invalid("captured cutoff differs from request"));
        }
        if let V::Object(q) = &mut self.query {
            if let Some(V::Object(b)) = q.get_mut("bounds") {
                b.insert("as_of".into(), V::string(captured_as_of.canonical()));
            }
        }
        let projection = PlanProjection::new(
            NormalizedQuery::from_value(&self.query)?,
            self.query_ref,
            self.profile_ref,
            self.config_ref,
            self.config,
            captured_as_of,
        )?;
        let hash = projection.canonical().hash(self.limits)?;
        Ok(ExecutablePlan {
            projection,
            hash,
            as_of: captured_as_of,
            semantics: self.semantics,
            notices: self.notices,
        })
    }
}
/// An executable plan can only come from `ValidatedDraft::finalize`.
/// ```compile_fail
/// use cdb_engine::compiler::ExecutablePlan;
/// let plan = ExecutablePlan {};
/// ```
#[derive(Clone, Debug)]
pub struct ExecutablePlan {
    projection: PlanProjection,
    hash: ContentHash,
    as_of: Timestamp,
    semantics: Semantics,
    notices: Vec<CompileNotice>,
}
impl ExecutablePlan {
    pub fn projection(&self) -> &PlanProjection {
        &self.projection
    }
    pub fn hash(&self) -> &ContentHash {
        &self.hash
    }
    pub fn normalized_query(&self) -> &V {
        self.projection
            .canonical()
            .payload()
            .field("query")
            .expect("validated plan query")
    }
    pub fn semantic_config(&self) -> &V {
        self.projection
            .canonical()
            .payload()
            .field("config")
            .expect("validated plan config")
    }
    pub fn as_of(&self) -> Timestamp {
        self.as_of
    }
    pub fn blocks(&self) -> &[Block] {
        &self.semantics.blocks
    }
    pub fn caps(&self) -> Caps {
        self.semantics.caps
    }
    pub fn direction(&self) -> Direction {
        self.semantics.direction
    }
    pub fn cycle_policy(&self) -> CyclePolicy {
        self.semantics.cycle
    }
    pub fn walk_predicates(&self) -> &[CompiledPredicate] {
        &self.semantics.walk
    }
    pub fn filter_predicates(&self) -> &[CompiledPredicate] {
        &self.semantics.filter
    }
    pub fn selection(&self) -> ReturnSelection {
        self.semantics.selection
    }
    pub fn notices(&self) -> &[CompileNotice] {
        &self.notices
    }
    pub fn has_custom_predicates(&self) -> bool {
        self.semantics
            .walk
            .iter()
            .chain(&self.semantics.filter)
            .any(|predicate| predicate.custom().is_some())
    }
}
