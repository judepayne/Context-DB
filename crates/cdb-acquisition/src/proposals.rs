//! Versioned, advisory extraction proposals.
//!
//! These types deliberately retain model-supplied ontology identifiers as text.
//! Turning a suggestion into an authoritative IRI is a later host operation.

pub const PROPOSAL_SCHEMA_V2: &str = "ctxql-extraction-proposals/v2";
pub const PROPOSAL_SCHEMA_V3: &str = "ctxql-extraction-proposals/v3";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalLimits {
    pub max_output_bytes: usize,
    pub max_entities: usize,
    pub max_attributes: usize,
    pub max_relations: usize,
    pub max_classes_per_entity: usize,
    pub max_components: usize,
    pub max_suggestions: usize,
    pub max_aliases: usize,
    pub max_evidence: usize,
    pub max_qualifiers: usize,
    pub max_local_id_bytes: usize,
    pub max_label_bytes: usize,
    pub max_literal_bytes: usize,
    pub max_excerpt_bytes: usize,
    pub max_fit_note_bytes: usize,
    pub max_qualifier_bytes: usize,
}

impl Default for ProposalLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: 256 * 1024,
            max_entities: 64,
            max_attributes: 64,
            max_relations: 64,
            max_classes_per_entity: 8,
            max_components: 256,
            max_suggestions: 8,
            max_aliases: 8,
            max_evidence: 16,
            max_qualifiers: 8,
            max_local_id_bytes: 128,
            max_label_bytes: 1024,
            max_literal_bytes: 16 * 1024,
            max_excerpt_bytes: 16 * 1024,
            max_fit_note_bytes: 1024,
            max_qualifier_bytes: 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentErrorCode {
    MissingField,
    UnknownField,
    InvalidType,
    InvalidValue,
    LimitExceeded,
    DuplicateId,
    UnresolvedReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentError {
    pub code: ComponentErrorCode,
}

impl ComponentError {
    pub fn new(code: ComponentErrorCode) -> Self {
        Self { code }
    }
}

/// A component's compact normalized JSON is retained even when its shape is bad.
/// JSON wire parsers also retain those exact bytes; text wire parsers retain the
/// exact source block separately in `original_text`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalComponent<T> {
    pub original_json: String,
    pub original_text: Option<String>,
    pub value: Result<T, ComponentError>,
}

impl<T> ProposalComponent<T> {
    pub fn parsed(&self) -> Option<&T> {
        self.value.as_ref().ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TermSuggestion {
    pub text: String,
    pub note: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TermChoice {
    pub suggestions: Vec<TermSuggestion>,
    pub selected: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    pub range: String,
    pub quote: String,
    pub occurrence: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntityRef {
    Local {
        passage_namespace: String,
        id: String,
    },
    Document {
        handle: String,
    },
    Known {
        proposed_iri: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelationObject {
    Entity(EntityRef),
    Unresolved { text: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceMode {
    Affirmative,
    Negative,
    Conditional,
    Attributed,
    Hypothetical,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticFit {
    Supported,
    Uncertain,
    NotEvaluated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasProposal {
    pub name: String,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationProposal {
    pub id: String,
    pub term: TermChoice,
    pub evidence: Vec<Evidence>,
    pub source_mode: SourceMode,
    pub fit: SemanticFit,
    pub fit_note: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityProposal {
    pub id: String,
    pub name: String,
    pub aliases: Vec<ProposalComponent<AliasProposal>>,
    pub known_entity: Option<String>,
    pub evidence: Vec<Evidence>,
    pub classes: Vec<ProposalComponent<ClassificationProposal>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralProposal {
    pub lexical: String,
    pub datatype: TermChoice,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributeProposal {
    pub id: String,
    pub subject: EntityRef,
    pub predicate: TermChoice,
    pub value: LiteralProposal,
    pub evidence: Vec<Evidence>,
    pub source_mode: SourceMode,
    pub qualifiers: Vec<String>,
    pub fit: SemanticFit,
    pub fit_note: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationProposal {
    pub id: String,
    pub subject: EntityRef,
    pub predicate: TermChoice,
    pub object: RelationObject,
    pub evidence: Vec<Evidence>,
    pub source_mode: SourceMode,
    pub qualifiers: Vec<String>,
    pub fit: SemanticFit,
    pub fit_note: String,
}

/// Internal normalized proposal envelope used by both historical wire v2 and
/// host-ID wire v3. The v2 name is retained for existing service consumers;
/// it does not imply that parsed input used the v2 wire schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalEnvelopeV2 {
    pub passage_namespace: String,
    pub no_claims: bool,
    pub entities: Vec<ProposalComponent<EntityProposal>>,
    pub attributes: Vec<ProposalComponent<AttributeProposal>>,
    pub relations: Vec<ProposalComponent<RelationProposal>>,
}

impl ProposalEnvelopeV2 {
    pub fn component_count(&self) -> usize {
        self.entities.len()
            + self
                .entities
                .iter()
                .filter_map(ProposalComponent::parsed)
                .map(|entity| entity.classes.len())
                .sum::<usize>()
            + self.attributes.len()
            + self.relations.len()
    }
}
