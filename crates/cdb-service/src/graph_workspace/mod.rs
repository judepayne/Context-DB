mod contracts;
mod limits;
mod state;
mod views;

pub(crate) use contracts::*;
pub(crate) use limits::WorkspaceLimits;
pub(crate) use state::{DocumentContext, Workspace};

use std::fmt;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Cancelled,
    Conflict(&'static str),
    DependencyPinned(Vec<Handle>),
    ForeignEvidence,
    ForeignHandle,
    IdempotencyConflict,
    ImmutableImport,
    Invalid(&'static str),
    Limit(&'static str),
    RevisionConflict { expected: u64, actual: u64 },
    UnknownHandle,
    UnknownTemporary,
    WrongHandleType,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("workspace operation cancelled"),
            Self::Conflict(message) => write!(formatter, "workspace conflict: {message}"),
            Self::DependencyPinned(handles) => write!(
                formatter,
                "graph is pinned by {} active record(s)",
                handles.len()
            ),
            Self::ForeignEvidence => {
                formatter.write_str("evidence handle does not belong to this document")
            }
            Self::ForeignHandle => formatter.write_str("handle does not belong to this session"),
            Self::IdempotencyConflict => {
                formatter.write_str("idempotency key was reused with different input")
            }
            Self::ImmutableImport => formatter.write_str("imported records are immutable"),
            Self::Invalid(message) => write!(formatter, "invalid workspace input: {message}"),
            Self::Limit(limit) => write!(formatter, "workspace limit exceeded: {limit}"),
            Self::RevisionConflict { expected, actual } => write!(
                formatter,
                "workspace revision conflict: expected {expected}, actual {actual}"
            ),
            Self::UnknownHandle => formatter.write_str("unknown workspace handle"),
            Self::UnknownTemporary => {
                formatter.write_str("unknown request-local temporary reference")
            }
            Self::WrongHandleType => {
                formatter.write_str("workspace handle has the wrong record type")
            }
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        collections::{BTreeMap, BTreeSet},
    };

    struct Document {
        evidence: BTreeSet<String>,
        cancelled: Cell<bool>,
    }

    impl Document {
        fn new() -> Self {
            Self {
                evidence: ["e1", "e2", "e3"].into_iter().map(str::to_owned).collect(),
                cancelled: Cell::new(false),
            }
        }
    }

    impl DocumentContext for Document {
        fn owns_evidence(&self, handle: &str) -> bool {
            self.evidence.contains(handle)
        }
        fn is_cancelled(&self) -> bool {
            self.cancelled.get()
        }
    }

    fn workspace(limits: WorkspaceLimits) -> Workspace {
        Workspace::new("issuer-1", "session-a", limits).unwrap()
    }

    fn node(key: &str, label: &str) -> IssuedNode {
        IssuedNode {
            key: key.into(),
            canonical_iri: format!("urn:test:{key}"),
            label: label.into(),
            metadata: BTreeMap::new(),
            dependencies: vec![format!("dep:{key}")],
        }
    }

    fn graph(session: &str, nodes: usize, claims: usize) -> IssuedGraph {
        let nodes = (0..nodes)
            .map(|index| {
                node(
                    &format!("k{index}"),
                    if index < 2 { "Equal label" } else { "Node" },
                )
            })
            .collect::<Vec<_>>();
        let claims = (0..claims)
            .map(|index| IssuedClaim {
                claim_id: format!("urn:claim:{index}"),
                subject_key: "k0".into(),
                predicate: "urn:predicate:p".into(),
                object: IssuedEndpoint::Literal {
                    value: TypedLiteral {
                        lexical: "42".into(),
                        datatype: "http://www.w3.org/2001/XMLSchema#integer".into(),
                        language: None,
                    },
                },
                metadata: BTreeMap::new(),
                dependencies: vec!["dep:claim".into()],
            })
            .collect();
        IssuedGraph {
            schema: SCHEMA.into(),
            issuer: "issuer-1".into(),
            session_id: session.into(),
            snapshot: "snapshot-1".into(),
            nodes,
            claims,
        }
    }

    fn apply_request(revision: u64, key: &str, edits: Vec<Edit>) -> ApplyRequest {
        ApplyRequest {
            schema: SCHEMA.into(),
            session_id: "session-a".into(),
            expected_revision: revision,
            idempotency_key: key.into(),
            edits,
        }
    }

    #[test]
    fn playground_fields_do_not_extend_the_final_v2_envelope() {
        use cdb_acquisition::proposals::ProposalLimits;
        use cdb_provider_pi::proposal_protocol::{parse_proposals_v2, ProposalParseContext};

        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/conformance/graph-workspace/negative-final-output-cases.json"
        )))
        .unwrap();
        let ranges = Vec::new();
        let documents = Vec::new();
        let context = ProposalParseContext {
            passage_namespace: "passage:test",
            issued_ranges: &ranges,
            document_handles: &documents,
        };
        for case in fixture["cases"].as_array().unwrap() {
            let id = case["id"].as_str().unwrap();
            let text = serde_json::to_string(&case["value"]).unwrap();
            let parsed = parse_proposals_v2(&text, &context, &ProposalLimits::default());
            if id == "workspace-handle-component-field" {
                let envelope = parsed.unwrap();
                assert!(envelope.entities[0].value.is_err(), "{id}");
            } else {
                assert!(parsed.is_err(), "{id}");
            }
        }
    }

    #[test]
    fn graph_limits_are_inclusive_and_import_preserves_distinct_claims_and_equal_labels() {
        let mut ws = workspace(WorkspaceLimits::default());
        let handle = ws.register_graph(graph("session-a", 50, 100)).unwrap();
        ws.import_graph(&handle).unwrap();
        assert_eq!(ws.counters().imported_nodes, 50);
        assert_eq!(ws.counters().imported_claims, 100);
        assert_eq!(
            ws.records
                .values()
                .filter(|record| matches!(record, state::Record::ImportedClaim(_)))
                .count(),
            100
        );
        assert_eq!(ws.records.values().filter(|record| matches!(record, state::Record::ImportedNode(node) if node.label == "Equal label")).count(), 2);

        let mut over = workspace(WorkspaceLimits::default());
        assert_eq!(
            over.register_graph(graph("session-a", 51, 0)),
            Err(Error::Limit("nodes_per_graph"))
        );
        assert!(over.graphs.is_empty());
        assert_eq!(
            over.register_graph(graph("session-a", 1, 101)),
            Err(Error::Limit("claims_per_graph"))
        );
        assert!(over.graphs.is_empty());
    }

    #[test]
    fn documented_skill_draft_runs_apply_view_check_without_imports() {
        let skill = include_str!("../../../../assets/pi/skills/graph-workspace/SKILL.md");
        let example = skill
            .split("```text\n")
            .nth(1)
            .unwrap()
            .split("\n```")
            .next()
            .unwrap();
        let wire: serde_json::Value =
            serde_json::from_str(&example.replace("HOST_RANGE", "e1")).unwrap();
        let edits: Vec<Edit> = serde_json::from_value(wire["edits"].clone()).unwrap();
        let mut ws = workspace(WorkspaceLimits::default());
        let request = apply_request(0, wire["idempotency_key"].as_str().unwrap(), edits);
        let result = ws.apply(request, &Document::new()).unwrap();
        assert_eq!(result.revision, 1);
        assert_eq!(ws.records.len(), 3);
        ws.view(ViewKind::Changes, None).unwrap();
        ws.check().unwrap();
    }

    #[test]
    fn apply_is_atomic_revisioned_idempotent_and_validates_evidence() {
        let document = Document::new();
        let mut ws = workspace(WorkspaceLimits::default());
        let request = apply_request(
            0,
            "batch-1",
            vec![
                Edit::AddNode {
                    temp_id: "party".into(),
                    local_id: "party-1".into(),
                    label: "Société 🙂".into(),
                    evidence: vec!["e1".into()],
                },
                Edit::AddClaim {
                    temp_id: "name".into(),
                    subject: RecordRef::Temp { id: "party".into() },
                    predicate: "urn:p:name".into(),
                    object: EndpointRef::Literal {
                        value: TypedLiteral {
                            lexical: "Société 🙂".into(),
                            datatype: "http://www.w3.org/2001/XMLSchema#string".into(),
                            language: Some("fr".into()),
                        },
                    },
                    evidence: vec!["e1".into()],
                    fit_note: "candidate wording only".into(),
                },
            ],
        );
        let result = ws.apply(request.clone(), &document).unwrap();
        assert_eq!(result.revision, 1);
        assert_eq!(ws.apply(request, &document).unwrap(), result);
        assert_eq!(ws.revision(), 1);

        let before = ws.records.clone();
        let invalid = apply_request(
            1,
            "batch-2",
            vec![
                Edit::AddNode {
                    temp_id: "ok".into(),
                    local_id: "ok".into(),
                    label: "OK".into(),
                    evidence: vec!["e1".into()],
                },
                Edit::AddNode {
                    temp_id: "bad".into(),
                    local_id: "bad".into(),
                    label: "Bad".into(),
                    evidence: vec!["foreign".into()],
                },
            ],
        );
        assert_eq!(ws.apply(invalid, &document), Err(Error::ForeignEvidence));
        assert_eq!(ws.records, before);
        assert_eq!(ws.revision(), 1);

        let conflict = apply_request(
            1,
            "batch-1",
            vec![Edit::AddNode {
                temp_id: "x".into(),
                local_id: "x".into(),
                label: "X".into(),
                evidence: vec![],
            }],
        );
        assert_eq!(
            ws.apply(conflict, &document),
            Err(Error::IdempotencyConflict)
        );
    }

    #[test]
    fn oversized_literal_and_cancellation_roll_back_records() {
        let document = Document::new();
        let limits = WorkspaceLimits {
            max_literal_bytes: 4,
            ..WorkspaceLimits::default()
        };
        let mut ws = workspace(limits);
        let request = apply_request(
            0,
            "large",
            vec![
                Edit::AddNode {
                    temp_id: "n".into(),
                    local_id: "n".into(),
                    label: "Node".into(),
                    evidence: vec![],
                },
                Edit::AddClaim {
                    temp_id: "c".into(),
                    subject: RecordRef::Temp { id: "n".into() },
                    predicate: "urn:p".into(),
                    object: EndpointRef::Literal {
                        value: TypedLiteral {
                            lexical: "12345".into(),
                            datatype: "urn:type".into(),
                            language: None,
                        },
                    },
                    evidence: vec![],
                    fit_note: String::new(),
                },
            ],
        );
        assert_eq!(ws.apply(request, &document), Err(Error::Limit("literal")));
        assert!(ws.records.is_empty());
        document.cancelled.set(true);
        let cancelled = apply_request(
            0,
            "cancel",
            vec![Edit::AddNode {
                temp_id: "n".into(),
                local_id: "n".into(),
                label: "Node".into(),
                evidence: vec![],
            }],
        );
        assert_eq!(ws.apply(cancelled, &document), Err(Error::Cancelled));
        assert!(ws.records.is_empty());
    }

    #[test]
    fn handles_are_session_bound_and_imports_are_immutable() {
        let document = Document::new();
        let mut ws = workspace(WorkspaceLimits::default());
        let graph_handle = ws.register_graph(graph("session-a", 1, 0)).unwrap();
        let imported = ws.import_graph(&graph_handle).unwrap()["k0"].clone();
        let foreign = Handle(imported.0.replace("session-a", "session-b"));
        let request = apply_request(
            ws.revision(),
            "foreign",
            vec![Edit::AddClaim {
                temp_id: "c".into(),
                subject: RecordRef::Handle { handle: foreign },
                predicate: "urn:p".into(),
                object: EndpointRef::Literal {
                    value: TypedLiteral {
                        lexical: "x".into(),
                        datatype: "urn:t".into(),
                        language: None,
                    },
                },
                evidence: vec![],
                fit_note: String::new(),
            }],
        );
        assert_eq!(ws.apply(request, &document), Err(Error::ForeignHandle));
        let withdraw = apply_request(
            ws.revision(),
            "immutable",
            vec![Edit::Withdraw { handle: imported }],
        );
        assert_eq!(ws.apply(withdraw, &document), Err(Error::ImmutableImport));
    }

    #[test]
    fn release_requires_explicit_withdrawal_of_dependants() {
        let document = Document::new();
        let mut ws = workspace(WorkspaceLimits::default());
        let graph_handle = ws.register_graph(graph("session-a", 1, 0)).unwrap();
        let imported = ws.import_graph(&graph_handle).unwrap()["k0"].clone();
        let add = apply_request(
            ws.revision(),
            "pin",
            vec![
                Edit::AddNode {
                    temp_id: "d".into(),
                    local_id: "d".into(),
                    label: "Draft".into(),
                    evidence: vec!["e1".into()],
                },
                Edit::AddHypothesis {
                    temp_id: "h".into(),
                    proposed: RecordRef::Temp { id: "d".into() },
                    existing: RecordRef::Handle { handle: imported },
                    comparison_evidence: vec!["e2".into()],
                    note: "compare identifier".into(),
                },
            ],
        );
        let result = ws.apply(add, &document).unwrap();
        assert!(matches!(
            ws.release_graph(&graph_handle),
            Err(Error::DependencyPinned(_))
        ));
        let withdraw = apply_request(
            ws.revision(),
            "unpin",
            vec![Edit::Withdraw {
                handle: result.handles["h"].clone(),
            }],
        );
        ws.apply(withdraw, &document).unwrap();
        ws.release_graph(&graph_handle).unwrap();
        assert_eq!(ws.counters().live_graphs, 0);
        assert_eq!(ws.counters().imported_nodes, 0);
    }

    #[test]
    fn checks_reference_states_and_ambiguous_identity_without_parsing_fit_notes() {
        let document = Document::new();
        let mut ws = workspace(WorkspaceLimits::default());
        let handle = ws.register_graph(graph("session-a", 2, 0)).unwrap();
        let imported = ws.import_graph(&handle).unwrap();
        let request = apply_request(
            ws.revision(),
            "structured",
            vec![
                Edit::AddNode {
                    temp_id: "d".into(),
                    local_id: "d".into(),
                    label: "Draft".into(),
                    evidence: vec!["e1".into()],
                },
                Edit::AddReference {
                    temp_id: "r".into(),
                    label: "Original Borrowers".into(),
                    scope: "document".into(),
                    definition_evidence: vec!["e1".into()],
                    referent_shape: "set_of_parties".into(),
                    target_text: Some("Schedule 1".into()),
                    members: vec![],
                    membership_evidence: vec![],
                    status: ReferenceStatus::Resolved,
                },
                Edit::AddHypothesis {
                    temp_id: "h1".into(),
                    proposed: RecordRef::Temp { id: "d".into() },
                    existing: RecordRef::Handle {
                        handle: imported["k0"].clone(),
                    },
                    comparison_evidence: vec!["e2".into()],
                    note: "candidate one".into(),
                },
                Edit::AddHypothesis {
                    temp_id: "h2".into(),
                    proposed: RecordRef::Temp { id: "d".into() },
                    existing: RecordRef::Handle {
                        handle: imported["k1"].clone(),
                    },
                    comparison_evidence: vec!["e3".into()],
                    note: "candidate two".into(),
                },
            ],
        );
        ws.apply(request, &document).unwrap();
        let check = ws.check().unwrap();
        assert!(!check.structurally_valid);
        assert!(check
            .issues
            .iter()
            .any(|issue| issue.code == "resolved_reference_empty"));
        assert!(check
            .issues
            .iter()
            .any(|issue| issue.code == "ambiguous_identity_candidates"));
    }

    #[test]
    fn checks_are_deterministically_bounded() {
        let document = Document::new();
        let limits = WorkspaceLimits {
            max_response_bytes: 700,
            ..WorkspaceLimits::default()
        };
        let mut ws = workspace(limits);
        let edits = (0..20)
            .map(|index| Edit::AddNode {
                temp_id: format!("t{index}"),
                local_id: format!("local-{index}"),
                label: format!("Node {index}"),
                evidence: vec![],
            })
            .collect();
        ws.apply(apply_request(0, "bounded-check", edits), &document)
            .unwrap();
        let first = ws.check().unwrap();
        let second = ws.check().unwrap();
        assert_eq!(first, second);
        assert!(first.check_partial);
        assert!(first.omitted_issues > 0);
        assert!(serde_json::to_vec(&first).unwrap().len() <= 700);
    }

    #[test]
    fn deterministic_views_use_utf8_safe_omission_markers() {
        let document = Document::new();
        let mut ws = workspace(WorkspaceLimits::default());
        let edits = (0..10)
            .map(|index| Edit::AddNode {
                temp_id: format!("t{index}"),
                local_id: format!("local-{index}"),
                label: format!("借款人🙂-{index}"),
                evidence: vec!["e1".into()],
            })
            .collect();
        ws.apply(apply_request(0, "view", edits), &document)
            .unwrap();
        let first = ws.view(ViewKind::Overview, Some(256)).unwrap();
        let second = ws.view(ViewKind::Overview, Some(256)).unwrap();
        assert_eq!(first, second);
        assert!(first.view_partial);
        assert!(first.rendered.contains("VIEW PARTIAL"));
        assert!(std::str::from_utf8(first.rendered.as_bytes()).is_ok());
        assert!(serde_json::to_vec(&first).unwrap().len() <= 256);
    }

    #[test]
    fn external_call_accounting_enforces_query_call_and_context_limits() {
        let limits = WorkspaceLimits {
            max_graph_queries: 1,
            max_tool_calls: 2,
            max_state_bytes: 512,
            ..WorkspaceLimits::default()
        };
        let mut ws = workspace(limits);
        ws.begin_call(10, true).unwrap();
        ws.finish_call_bytes(10).unwrap();
        assert_eq!(ws.counters().tool_calls, 1);
        assert_eq!(ws.counters().graph_queries, 1);
        assert_eq!(ws.begin_call(1, true), Err(Error::Limit("graph_queries")));
        assert_eq!(ws.counters().tool_calls, 2);
        assert_eq!(ws.begin_call(1, false), Err(Error::Limit("tool_calls")));
        assert_eq!(
            ws.ensure_context_bytes(513),
            Err(Error::Limit("state_bytes"))
        );
    }
}
