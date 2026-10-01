use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) const SCHEMA: &str = "ctxql.graph-workspace/v1";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Handle(pub(crate) String);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TypedLiteral {
    pub(crate) lexical: String,
    pub(crate) datatype: String,
    pub(crate) language: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Endpoint {
    Record { handle: Handle },
    Literal { value: TypedLiteral },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssuedNode {
    pub(crate) key: String,
    pub(crate) canonical_iri: String,
    pub(crate) label: String,
    #[serde(default)]
    pub(crate) metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) dependencies: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum IssuedEndpoint {
    Node { key: String },
    Literal { value: TypedLiteral },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssuedClaim {
    pub(crate) claim_id: String,
    pub(crate) subject_key: String,
    pub(crate) predicate: String,
    pub(crate) object: IssuedEndpoint,
    #[serde(default)]
    pub(crate) metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) dependencies: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssuedGraph {
    pub(crate) schema: String,
    pub(crate) issuer: String,
    pub(crate) session_id: String,
    pub(crate) snapshot: String,
    pub(crate) nodes: Vec<IssuedNode>,
    pub(crate) claims: Vec<IssuedClaim>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DraftStatus {
    Active,
    Withdrawn,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReferenceStatus {
    Unresolved,
    Partial,
    Resolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HypothesisStatus {
    Candidate,
    Withdrawn,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RecordRef {
    Handle { handle: Handle },
    Temp { id: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum EndpointRef {
    Record { record: RecordRef },
    Literal { value: TypedLiteral },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Edit {
    AddNode {
        temp_id: String,
        local_id: String,
        label: String,
        evidence: Vec<String>,
    },
    AddClaim {
        temp_id: String,
        subject: RecordRef,
        predicate: String,
        object: EndpointRef,
        evidence: Vec<String>,
        fit_note: String,
    },
    AddReference {
        temp_id: String,
        label: String,
        scope: String,
        definition_evidence: Vec<String>,
        referent_shape: String,
        target_text: Option<String>,
        members: Vec<RecordRef>,
        membership_evidence: Vec<String>,
        status: ReferenceStatus,
    },
    AddHypothesis {
        temp_id: String,
        proposed: RecordRef,
        existing: RecordRef,
        comparison_evidence: Vec<String>,
        note: String,
    },
    AddQuestion {
        temp_id: String,
        code: String,
        message: String,
        relevant: Vec<RecordRef>,
    },
    Withdraw {
        handle: Handle,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplyRequest {
    pub(crate) schema: String,
    pub(crate) session_id: String,
    pub(crate) expected_revision: u64,
    pub(crate) idempotency_key: String,
    pub(crate) edits: Vec<Edit>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplyResult {
    pub(crate) schema: String,
    pub(crate) operation_id: String,
    pub(crate) revision: u64,
    pub(crate) idempotent_replay: bool,
    pub(crate) handles: BTreeMap<String, Handle>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ViewKind {
    Overview,
    Neighbourhood { centre: Handle },
    Changes,
    OpenQuestions,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ViewResponse {
    pub(crate) schema: String,
    pub(crate) revision: u64,
    pub(crate) kind: String,
    pub(crate) rendered: String,
    pub(crate) view_partial: bool,
    pub(crate) omitted_records: usize,
    pub(crate) included_handles: Vec<Handle>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckSeverity {
    Error,
    Warning,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckIssue {
    pub(crate) code: String,
    pub(crate) severity: CheckSeverity,
    pub(crate) handles: Vec<Handle>,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckResponse {
    pub(crate) schema: String,
    pub(crate) revision: u64,
    pub(crate) structurally_valid: bool,
    pub(crate) issues: Vec<CheckIssue>,
    pub(crate) check_partial: bool,
    pub(crate) omitted_issues: usize,
    pub(crate) note: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BudgetCounters {
    pub(crate) tool_calls: usize,
    pub(crate) graph_queries: usize,
    pub(crate) aggregate_request_bytes: usize,
    pub(crate) aggregate_response_bytes: usize,
    pub(crate) retained_state_bytes: usize,
    pub(crate) live_graphs: usize,
    pub(crate) imported_nodes: usize,
    pub(crate) imported_claims: usize,
    pub(crate) draft_nodes: usize,
    pub(crate) draft_edges: usize,
}
