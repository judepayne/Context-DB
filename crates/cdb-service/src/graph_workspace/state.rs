use super::{
    contracts::{
        ApplyRequest, ApplyResult, BudgetCounters, DraftStatus, Edit, Endpoint, EndpointRef,
        Handle, HypothesisStatus, IssuedEndpoint, IssuedGraph, RecordRef, ReferenceStatus, SCHEMA,
    },
    limits::WorkspaceLimits,
    Error, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) trait DocumentContext {
    fn owns_evidence(&self, handle: &str) -> bool;
    fn is_cancelled(&self) -> bool;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct ImportedNode {
    pub handle: Handle,
    pub graph: Handle,
    pub canonical_iri: String,
    pub label: String,
    pub metadata: BTreeMap<String, String>,
    pub dependencies: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct ImportedClaim {
    pub handle: Handle,
    pub graph: Handle,
    pub claim_id: String,
    pub subject: Handle,
    pub predicate: String,
    pub object: Endpoint,
    pub metadata: BTreeMap<String, String>,
    pub dependencies: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct DraftNode {
    pub handle: Handle,
    pub local_id: String,
    pub label: String,
    pub evidence: Vec<String>,
    pub status: DraftStatus,
    pub created_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct DraftClaim {
    pub handle: Handle,
    pub subject: Handle,
    pub predicate: String,
    pub object: Endpoint,
    pub evidence: Vec<String>,
    pub fit_note: String,
    pub status: DraftStatus,
    pub created_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct DocumentReference {
    pub handle: Handle,
    pub label: String,
    pub scope: String,
    pub definition_evidence: Vec<String>,
    pub referent_shape: String,
    pub target_text: Option<String>,
    pub members: Vec<Handle>,
    pub membership_evidence: Vec<String>,
    pub resolution: ReferenceStatus,
    pub status: DraftStatus,
    pub created_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct IdentityHypothesis {
    pub handle: Handle,
    pub proposed: Handle,
    pub existing: Handle,
    pub comparison_evidence: Vec<String>,
    pub note: String,
    pub status: HypothesisStatus,
    pub created_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct OpenQuestion {
    pub handle: Handle,
    pub code: String,
    pub message: String,
    pub relevant: Vec<Handle>,
    pub status: DraftStatus,
    pub created_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum Record {
    ImportedNode(ImportedNode),
    ImportedClaim(ImportedClaim),
    DraftNode(DraftNode),
    DraftClaim(DraftClaim),
    Reference(DocumentReference),
    Hypothesis(IdentityHypothesis),
    Question(OpenQuestion),
}

impl Record {
    pub(super) fn handle(&self) -> &Handle {
        match self {
            Self::ImportedNode(v) => &v.handle,
            Self::ImportedClaim(v) => &v.handle,
            Self::DraftNode(v) => &v.handle,
            Self::DraftClaim(v) => &v.handle,
            Self::Reference(v) => &v.handle,
            Self::Hypothesis(v) => &v.handle,
            Self::Question(v) => &v.handle,
        }
    }

    pub(super) fn active(&self) -> bool {
        match self {
            Self::ImportedNode(_) | Self::ImportedClaim(_) => true,
            Self::DraftNode(v) => v.status == DraftStatus::Active,
            Self::DraftClaim(v) => v.status == DraftStatus::Active,
            Self::Reference(v) => v.status == DraftStatus::Active,
            Self::Hypothesis(v) => v.status == HypothesisStatus::Candidate,
            Self::Question(v) => v.status == DraftStatus::Active,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum GraphStatus {
    Pending,
    Attached,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct GraphRecord {
    pub handle: Handle,
    pub snapshot: String,
    pub status: GraphStatus,
    pub issued: IssuedGraph,
    pub imported_handles: Vec<Handle>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct IdempotencyRecord {
    request: ApplyRequest,
    result: ApplyResult,
}

#[derive(Clone, Debug)]
pub(crate) struct Workspace {
    pub(super) issuer: String,
    pub(super) session_id: String,
    pub(super) revision: u64,
    pub(super) limits: WorkspaceLimits,
    pub(super) graphs: BTreeMap<Handle, GraphRecord>,
    pub(super) records: BTreeMap<Handle, Record>,
    idempotency: BTreeMap<String, IdempotencyRecord>,
    pub(super) counters: BudgetCounters,
    next_graph: u64,
    next_node: u64,
    next_claim: u64,
    next_reference: u64,
    next_hypothesis: u64,
    next_question: u64,
    next_operation: u64,
}

impl Workspace {
    pub(crate) fn new(
        issuer: impl Into<String>,
        session_id: impl Into<String>,
        limits: WorkspaceLimits,
    ) -> Result<Self> {
        let issuer = issuer.into();
        let session_id = session_id.into();
        limits.identifier("issuer", &issuer)?;
        limits.identifier("session_id", &session_id)?;
        if session_id.contains('~') {
            return Err(Error::Invalid("session_id contains reserved character"));
        }
        Ok(Self {
            issuer,
            session_id,
            revision: 0,
            limits,
            graphs: BTreeMap::new(),
            records: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            counters: BudgetCounters::default(),
            next_graph: 1,
            next_node: 1,
            next_claim: 1,
            next_reference: 1,
            next_hypothesis: 1,
            next_question: 1,
            next_operation: 1,
        })
    }

    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn counters(&self) -> &BudgetCounters {
        &self.counters
    }

    pub(crate) fn capture_projection(&self) -> cdb_core::Result<cdb_core::CanonicalValue> {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "ctxql-graph-workspace-state/v1",
            "issuer": self.issuer,
            "session_id": self.session_id,
            "revision": self.revision,
            "limits": self.limits,
            "graphs": self.graphs,
            "records": self.records,
            "idempotency": self.idempotency,
            "counters": self.counters,
            "next": {
                "graph": self.next_graph,
                "node": self.next_node,
                "claim": self.next_claim,
                "reference": self.next_reference,
                "hypothesis": self.next_hypothesis,
                "question": self.next_question,
                "operation": self.next_operation
            }
        }))
        .map_err(|_| cdb_core::Error::invalid("workspace capture encoding"))?;
        cdb_core::CanonicalValue::parse(&bytes, cdb_core::Limits::default())
    }

    pub(crate) fn begin_call(&mut self, request_bytes: usize, graph_query: bool) -> Result<()> {
        self.account_request(request_bytes)?;
        if graph_query {
            if self.counters.graph_queries >= self.limits.max_graph_queries {
                return Err(Error::Limit("graph_queries"));
            }
            self.counters.graph_queries += 1;
        }
        Ok(())
    }

    pub(crate) fn finish_call_bytes(&mut self, response_bytes: usize) -> Result<()> {
        self.account_response_bytes(response_bytes)
    }

    pub(crate) fn ensure_context_bytes(&self, context_bytes: usize) -> Result<()> {
        if self
            .counters
            .retained_state_bytes
            .checked_add(context_bytes)
            .is_none_or(|total| total > self.limits.max_state_bytes)
        {
            return Err(Error::Limit("state_bytes"));
        }
        Ok(())
    }

    pub(crate) fn issued_graph(&self, handle: &Handle) -> Option<&IssuedGraph> {
        self.graphs.get(handle).map(|record| &record.issued)
    }

    pub(crate) fn register_graph(&mut self, issued: IssuedGraph) -> Result<Handle> {
        if issued.schema != SCHEMA
            || issued.issuer != self.issuer
            || issued.session_id != self.session_id
        {
            return Err(Error::ForeignHandle);
        }
        if self.graphs.len() >= self.limits.max_live_graphs {
            return Err(Error::Limit("live_graphs"));
        }
        self.validate_graph(&issued)?;
        let mut staged = self.clone();
        let handle = staged.issue_graph();
        staged.graphs.insert(
            handle.clone(),
            GraphRecord {
                handle: handle.clone(),
                snapshot: issued.snapshot.clone(),
                status: GraphStatus::Pending,
                issued,
                imported_handles: Vec::new(),
            },
        );
        staged.refresh_counters()?;
        *self = staged;
        Ok(handle)
    }

    pub(crate) fn import_graph(&mut self, graph: &Handle) -> Result<BTreeMap<String, Handle>> {
        self.validate_owned_handle(graph)?;
        let graph_record = self.graphs.get(graph).ok_or(Error::UnknownHandle)?.clone();
        if graph_record.status == GraphStatus::Attached {
            return Err(Error::Conflict("graph already imported"));
        }
        let mut staged = self.clone();
        let mut keys = BTreeMap::new();
        let mut imported = Vec::new();
        for node in &graph_record.issued.nodes {
            let handle = staged.issue_node();
            keys.insert(node.key.clone(), handle.clone());
            imported.push(handle.clone());
            staged.records.insert(
                handle.clone(),
                Record::ImportedNode(ImportedNode {
                    handle,
                    graph: graph.clone(),
                    canonical_iri: node.canonical_iri.clone(),
                    label: node.label.clone(),
                    metadata: node.metadata.clone(),
                    dependencies: node.dependencies.clone(),
                }),
            );
        }
        for claim in &graph_record.issued.claims {
            let handle = staged.issue_claim();
            let subject = keys
                .get(&claim.subject_key)
                .ok_or(Error::Invalid("dangling graph subject"))?
                .clone();
            let object = match &claim.object {
                IssuedEndpoint::Node { key } => Endpoint::Record {
                    handle: keys
                        .get(key)
                        .ok_or(Error::Invalid("dangling graph object"))?
                        .clone(),
                },
                IssuedEndpoint::Literal { value } => Endpoint::Literal {
                    value: value.clone(),
                },
            };
            imported.push(handle.clone());
            staged.records.insert(
                handle.clone(),
                Record::ImportedClaim(ImportedClaim {
                    handle,
                    graph: graph.clone(),
                    claim_id: claim.claim_id.clone(),
                    subject,
                    predicate: claim.predicate.clone(),
                    object,
                    metadata: claim.metadata.clone(),
                    dependencies: claim.dependencies.clone(),
                }),
            );
        }
        let record = staged.graphs.get_mut(graph).expect("staged graph exists");
        record.status = GraphStatus::Attached;
        record.imported_handles = imported;
        staged.revision += 1;
        staged.refresh_counters()?;
        *self = staged;
        Ok(keys)
    }

    pub(crate) fn release_graph(&mut self, graph: &Handle) -> Result<()> {
        self.validate_owned_handle(graph)?;
        let record = self.graphs.get(graph).ok_or(Error::UnknownHandle)?;
        let imported: BTreeSet<_> = record.imported_handles.iter().cloned().collect();
        let blockers = self.active_dependencies(&imported);
        if !blockers.is_empty() {
            return Err(Error::DependencyPinned(blockers));
        }
        let mut staged = self.clone();
        if let Some(graph_record) = staged.graphs.remove(graph) {
            for handle in graph_record.imported_handles {
                staged.records.remove(&handle);
            }
        }
        staged.revision += 1;
        staged.refresh_counters()?;
        *self = staged;
        Ok(())
    }

    pub(crate) fn apply(
        &mut self,
        request: ApplyRequest,
        document: &dyn DocumentContext,
    ) -> Result<ApplyResult> {
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|_| Error::Invalid("request serialization"))?
            .len();
        self.begin_call(request_bytes, false)?;
        self.apply_preaccounted(request, document)
    }

    pub(crate) fn apply_preaccounted(
        &mut self,
        request: ApplyRequest,
        document: &dyn DocumentContext,
    ) -> Result<ApplyResult> {
        if document.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if request.schema != SCHEMA || request.session_id != self.session_id {
            return Err(Error::ForeignHandle);
        }
        if request.edits.is_empty() || request.edits.len() > self.limits.max_edits_per_batch {
            return Err(Error::Limit("edits_per_batch"));
        }
        self.limits
            .identifier("idempotency_key", &request.idempotency_key)?;
        if let Some(record) = self.idempotency.get(&request.idempotency_key) {
            if record.request != request {
                return Err(Error::IdempotencyConflict);
            }
            let result = record.result.clone();
            self.account_response(&result)?;
            return Ok(result);
        }
        if request.expected_revision != self.revision {
            return Err(Error::RevisionConflict {
                expected: request.expected_revision,
                actual: self.revision,
            });
        }
        if self.idempotency.len() >= self.limits.max_idempotency_records {
            return Err(Error::Limit("idempotency_records"));
        }

        let mut staged = self.clone();
        let commit_revision = staged.revision + 1;
        let mut temporary = BTreeMap::<String, Handle>::new();
        for edit in &request.edits {
            staged.apply_edit(edit, &mut temporary, document, commit_revision)?;
        }
        staged.validate_active_references()?;
        if document.is_cancelled() {
            return Err(Error::Cancelled);
        }
        staged.revision = commit_revision;
        let operation_id = format!("op{}~{}", staged.next_operation, staged.session_id);
        staged.next_operation += 1;
        let result = ApplyResult {
            schema: SCHEMA.to_owned(),
            operation_id,
            revision: commit_revision,
            idempotent_replay: false,
            handles: temporary,
        };
        staged.idempotency.insert(
            request.idempotency_key.clone(),
            IdempotencyRecord {
                request,
                result: result.clone(),
            },
        );
        staged.refresh_counters()?;
        staged.account_response(&result)?;
        *self = staged;
        Ok(result)
    }

    pub(super) fn record(&self, handle: &Handle) -> Result<&Record> {
        self.validate_owned_handle(handle)?;
        self.records.get(handle).ok_or(Error::UnknownHandle)
    }

    fn apply_edit(
        &mut self,
        edit: &Edit,
        temporary: &mut BTreeMap<String, Handle>,
        document: &dyn DocumentContext,
        revision: u64,
    ) -> Result<()> {
        match edit {
            Edit::AddNode {
                temp_id,
                local_id,
                label,
                evidence,
            } => {
                self.validate_temp(temp_id, temporary)?;
                self.limits.identifier("local_id", local_id)?;
                self.limits.label(label)?;
                self.validate_evidence(evidence, document)?;
                let handle = self.issue_node();
                temporary.insert(temp_id.clone(), handle.clone());
                self.records.insert(
                    handle.clone(),
                    Record::DraftNode(DraftNode {
                        handle,
                        local_id: local_id.clone(),
                        label: label.clone(),
                        evidence: evidence.clone(),
                        status: DraftStatus::Active,
                        created_revision: revision,
                    }),
                );
            }
            Edit::AddClaim {
                temp_id,
                subject,
                predicate,
                object,
                evidence,
                fit_note,
            } => {
                self.validate_temp(temp_id, temporary)?;
                self.limits.identifier("predicate", predicate)?;
                self.limits.note("fit_note", fit_note)?;
                self.validate_evidence(evidence, document)?;
                let subject = self.resolve_node(subject, temporary)?;
                let object = match object {
                    EndpointRef::Record { record } => Endpoint::Record {
                        handle: self.resolve_node(record, temporary)?,
                    },
                    EndpointRef::Literal { value } => {
                        self.limits.literal(value)?;
                        Endpoint::Literal {
                            value: value.clone(),
                        }
                    }
                };
                let handle = self.issue_claim();
                temporary.insert(temp_id.clone(), handle.clone());
                self.records.insert(
                    handle.clone(),
                    Record::DraftClaim(DraftClaim {
                        handle,
                        subject,
                        predicate: predicate.clone(),
                        object,
                        evidence: evidence.clone(),
                        fit_note: fit_note.clone(),
                        status: DraftStatus::Active,
                        created_revision: revision,
                    }),
                );
            }
            Edit::AddReference {
                temp_id,
                label,
                scope,
                definition_evidence,
                referent_shape,
                target_text,
                members,
                membership_evidence,
                status,
            } => {
                self.validate_temp(temp_id, temporary)?;
                self.limits.label(label)?;
                self.limits.identifier("reference_scope", scope)?;
                self.limits.identifier("referent_shape", referent_shape)?;
                if let Some(text) = target_text {
                    self.limits.note("target_text", text)?;
                }
                self.validate_evidence(definition_evidence, document)?;
                self.validate_evidence(membership_evidence, document)?;
                let members = members
                    .iter()
                    .map(|r| self.resolve_node(r, temporary))
                    .collect::<Result<Vec<_>>>()?;
                let handle = self.issue_reference();
                temporary.insert(temp_id.clone(), handle.clone());
                self.records.insert(
                    handle.clone(),
                    Record::Reference(DocumentReference {
                        handle,
                        label: label.clone(),
                        scope: scope.clone(),
                        definition_evidence: definition_evidence.clone(),
                        referent_shape: referent_shape.clone(),
                        target_text: target_text.clone(),
                        members,
                        membership_evidence: membership_evidence.clone(),
                        resolution: status.clone(),
                        status: DraftStatus::Active,
                        created_revision: revision,
                    }),
                );
            }
            Edit::AddHypothesis {
                temp_id,
                proposed,
                existing,
                comparison_evidence,
                note,
            } => {
                self.validate_temp(temp_id, temporary)?;
                self.limits.note("hypothesis_note", note)?;
                self.validate_evidence(comparison_evidence, document)?;
                let proposed = self.resolve_node(proposed, temporary)?;
                let existing = self.resolve_node(existing, temporary)?;
                if proposed == existing {
                    return Err(Error::Invalid("identity hypothesis endpoints must differ"));
                }
                let handle = self.issue_hypothesis();
                temporary.insert(temp_id.clone(), handle.clone());
                self.records.insert(
                    handle.clone(),
                    Record::Hypothesis(IdentityHypothesis {
                        handle,
                        proposed,
                        existing,
                        comparison_evidence: comparison_evidence.clone(),
                        note: note.clone(),
                        status: HypothesisStatus::Candidate,
                        created_revision: revision,
                    }),
                );
            }
            Edit::AddQuestion {
                temp_id,
                code,
                message,
                relevant,
            } => {
                self.validate_temp(temp_id, temporary)?;
                self.limits.identifier("question_code", code)?;
                self.limits.note("question_message", message)?;
                let relevant = relevant
                    .iter()
                    .map(|r| self.resolve_any(r, temporary))
                    .collect::<Result<Vec<_>>>()?;
                let handle = self.issue_question();
                temporary.insert(temp_id.clone(), handle.clone());
                self.records.insert(
                    handle.clone(),
                    Record::Question(OpenQuestion {
                        handle,
                        code: code.clone(),
                        message: message.clone(),
                        relevant,
                        status: DraftStatus::Active,
                        created_revision: revision,
                    }),
                );
            }
            Edit::Withdraw { handle } => {
                self.validate_owned_handle(handle)?;
                match self.records.get_mut(handle).ok_or(Error::UnknownHandle)? {
                    Record::ImportedNode(_) | Record::ImportedClaim(_) => {
                        return Err(Error::ImmutableImport)
                    }
                    Record::DraftNode(v) => v.status = DraftStatus::Withdrawn,
                    Record::DraftClaim(v) => v.status = DraftStatus::Withdrawn,
                    Record::Reference(v) => v.status = DraftStatus::Withdrawn,
                    Record::Hypothesis(v) => v.status = HypothesisStatus::Withdrawn,
                    Record::Question(v) => v.status = DraftStatus::Withdrawn,
                }
            }
        }
        Ok(())
    }

    fn validate_graph(&self, graph: &IssuedGraph) -> Result<()> {
        if graph.nodes.len() > self.limits.max_nodes_per_graph {
            return Err(Error::Limit("nodes_per_graph"));
        }
        if graph.claims.len() > self.limits.max_claims_per_graph {
            return Err(Error::Limit("claims_per_graph"));
        }
        self.limits.identifier("snapshot", &graph.snapshot)?;
        let mut keys = BTreeSet::new();
        for node in &graph.nodes {
            self.limits.identifier("node_key", &node.key)?;
            self.limits
                .identifier("canonical_iri", &node.canonical_iri)?;
            self.limits.label(&node.label)?;
            if node.metadata.len() > self.limits.max_metadata_entries
                || !keys.insert(node.key.as_str())
            {
                return Err(Error::Invalid("duplicate node key or excessive metadata"));
            }
            for (key, value) in &node.metadata {
                self.limits.identifier("metadata_key", key)?;
                self.limits.note("metadata_value", value)?;
            }
            for dep in &node.dependencies {
                self.limits.identifier("dependency", dep)?;
            }
        }
        let mut claim_ids = BTreeSet::new();
        for claim in &graph.claims {
            self.limits.identifier("claim_id", &claim.claim_id)?;
            self.limits.identifier("predicate", &claim.predicate)?;
            if !claim_ids.insert(claim.claim_id.as_str())
                || !keys.contains(claim.subject_key.as_str())
            {
                return Err(Error::Invalid(
                    "duplicate claim identity or dangling endpoint",
                ));
            }
            match &claim.object {
                IssuedEndpoint::Node { key } if !keys.contains(key.as_str()) => {
                    return Err(Error::Invalid("dangling endpoint"))
                }
                IssuedEndpoint::Literal { value } => self.limits.literal(value)?,
                IssuedEndpoint::Node { .. } => {}
            }
            if claim.metadata.len() > self.limits.max_metadata_entries {
                return Err(Error::Limit("metadata_entries"));
            }
            for dep in &claim.dependencies {
                self.limits.identifier("dependency", dep)?;
            }
        }
        Ok(())
    }

    fn validate_temp(&self, id: &str, temporary: &BTreeMap<String, Handle>) -> Result<()> {
        self.limits.identifier("temporary_id", id)?;
        if temporary.contains_key(id) {
            return Err(Error::Conflict("duplicate temporary id"));
        }
        Ok(())
    }

    fn validate_evidence(&self, evidence: &[String], document: &dyn DocumentContext) -> Result<()> {
        if evidence.len() > self.limits.max_evidence_per_record {
            return Err(Error::Limit("evidence_per_record"));
        }
        let mut unique = BTreeSet::new();
        for handle in evidence {
            self.limits.identifier("evidence_handle", handle)?;
            if !unique.insert(handle) {
                return Err(Error::Invalid("duplicate evidence handle"));
            }
            if !document.owns_evidence(handle) {
                return Err(Error::ForeignEvidence);
            }
        }
        Ok(())
    }

    fn resolve_any(
        &self,
        reference: &RecordRef,
        temporary: &BTreeMap<String, Handle>,
    ) -> Result<Handle> {
        let handle = match reference {
            RecordRef::Handle { handle } => handle.clone(),
            RecordRef::Temp { id } => temporary.get(id).ok_or(Error::UnknownTemporary)?.clone(),
        };
        self.validate_owned_handle(&handle)?;
        if !self.records.contains_key(&handle) {
            return Err(Error::UnknownHandle);
        }
        Ok(handle)
    }

    fn resolve_node(
        &self,
        reference: &RecordRef,
        temporary: &BTreeMap<String, Handle>,
    ) -> Result<Handle> {
        let handle = self.resolve_any(reference, temporary)?;
        match self.records.get(&handle) {
            Some(Record::ImportedNode(_)) | Some(Record::DraftNode(_)) => Ok(handle),
            _ => Err(Error::WrongHandleType),
        }
    }

    fn validate_active_references(&self) -> Result<()> {
        for record in self.records.values().filter(|record| record.active()) {
            let referenced = match record {
                Record::DraftClaim(v) => {
                    let mut refs = vec![&v.subject];
                    if let Endpoint::Record { handle } = &v.object {
                        refs.push(handle);
                    }
                    refs
                }
                Record::Reference(v) => v.members.iter().collect(),
                Record::Hypothesis(v) => vec![&v.proposed, &v.existing],
                Record::Question(v) => v.relevant.iter().collect(),
                _ => Vec::new(),
            };
            for handle in referenced {
                let target = self.records.get(handle).ok_or(Error::UnknownHandle)?;
                if !target.active() {
                    return Err(Error::Conflict("active record references withdrawn record"));
                }
            }
        }
        Ok(())
    }

    fn active_dependencies(&self, imported: &BTreeSet<Handle>) -> Vec<Handle> {
        self.records.values().filter(|record| record.active()).filter_map(|record| {
            let depends = match record {
                Record::DraftClaim(v) => imported.contains(&v.subject) || matches!(&v.object, Endpoint::Record { handle } if imported.contains(handle)),
                Record::Reference(v) => v.members.iter().any(|h| imported.contains(h)),
                Record::Hypothesis(v) => imported.contains(&v.proposed) || imported.contains(&v.existing),
                Record::Question(v) => v.relevant.iter().any(|h| imported.contains(h)),
                _ => false,
            };
            depends.then(|| record.handle().clone())
        }).collect()
    }

    fn validate_owned_handle(&self, handle: &Handle) -> Result<()> {
        let suffix = format!("~{}", self.session_id);
        if !handle.0.ends_with(&suffix) {
            return Err(Error::ForeignHandle);
        }
        Ok(())
    }

    fn account_request(&mut self, bytes: usize) -> Result<()> {
        if bytes > self.limits.max_request_bytes {
            return Err(Error::Limit("request_bytes"));
        }
        if self.counters.tool_calls >= self.limits.max_tool_calls {
            return Err(Error::Limit("tool_calls"));
        }
        let total = self
            .counters
            .aggregate_request_bytes
            .saturating_add(self.counters.aggregate_response_bytes)
            .saturating_add(bytes);
        if total > self.limits.max_aggregate_bytes {
            return Err(Error::Limit("aggregate_bytes"));
        }
        self.counters.tool_calls += 1;
        self.counters.aggregate_request_bytes += bytes;
        Ok(())
    }

    fn account_response<T: Serialize>(&mut self, response: &T) -> Result<()> {
        let bytes = serde_json::to_vec(response)
            .map_err(|_| Error::Invalid("response serialization"))?
            .len();
        self.account_response_bytes(bytes)
    }

    fn account_response_bytes(&mut self, bytes: usize) -> Result<()> {
        if bytes > self.limits.max_response_bytes {
            return Err(Error::Limit("response_bytes"));
        }
        let total = self
            .counters
            .aggregate_request_bytes
            .saturating_add(self.counters.aggregate_response_bytes)
            .saturating_add(bytes);
        if total > self.limits.max_aggregate_bytes {
            return Err(Error::Limit("aggregate_bytes"));
        }
        self.counters.aggregate_response_bytes += bytes;
        Ok(())
    }

    fn refresh_counters(&mut self) -> Result<()> {
        self.counters.live_graphs = self.graphs.len();
        self.counters.imported_nodes = self
            .records
            .values()
            .filter(|r| matches!(r, Record::ImportedNode(_)))
            .count();
        self.counters.imported_claims = self
            .records
            .values()
            .filter(|r| matches!(r, Record::ImportedClaim(_)))
            .count();
        self.counters.draft_nodes = self
            .records
            .values()
            .filter(|r| matches!(r, Record::DraftNode(_)))
            .count();
        self.counters.draft_edges = self
            .records
            .values()
            .filter(|r| matches!(r, Record::DraftClaim(_) | Record::Hypothesis(_)))
            .count()
            + self
                .records
                .values()
                .filter_map(|r| match r {
                    Record::Reference(v) => Some(v.members.len()),
                    _ => None,
                })
                .sum::<usize>();
        if self.counters.imported_nodes > self.limits.max_imported_nodes {
            return Err(Error::Limit("imported_nodes"));
        }
        if self.counters.imported_claims > self.limits.max_imported_claims {
            return Err(Error::Limit("imported_claims"));
        }
        if self.counters.draft_nodes > self.limits.max_draft_nodes {
            return Err(Error::Limit("draft_nodes"));
        }
        if self.counters.draft_edges > self.limits.max_draft_edges {
            return Err(Error::Limit("draft_edges"));
        }
        let serialized = serde_json::to_vec(&(
            &self.graphs,
            &self.records,
            &self.idempotency,
            self.revision,
        ))
        .map_err(|_| Error::Invalid("state serialization"))?
        .len();
        let allocation = serialized
            .saturating_mul(2)
            .saturating_add(self.records.len().saturating_mul(128));
        if serialized > self.limits.max_state_bytes || allocation > self.limits.max_state_bytes {
            return Err(Error::Limit("workspace_state"));
        }
        self.counters.retained_state_bytes = allocation;
        Ok(())
    }

    fn issue(&self, prefix: char, value: u64) -> Handle {
        Handle(format!("{prefix}{value}~{}", self.session_id))
    }
    fn issue_graph(&mut self) -> Handle {
        let h = self.issue('g', self.next_graph);
        self.next_graph += 1;
        h
    }
    fn issue_node(&mut self) -> Handle {
        let h = self.issue('n', self.next_node);
        self.next_node += 1;
        h
    }
    fn issue_claim(&mut self) -> Handle {
        let h = self.issue('c', self.next_claim);
        self.next_claim += 1;
        h
    }
    fn issue_reference(&mut self) -> Handle {
        let h = self.issue('r', self.next_reference);
        self.next_reference += 1;
        h
    }
    fn issue_hypothesis(&mut self) -> Handle {
        let h = self.issue('h', self.next_hypothesis);
        self.next_hypothesis += 1;
        h
    }
    fn issue_question(&mut self) -> Handle {
        let h = self.issue('q', self.next_question);
        self.next_question += 1;
        h
    }
}
