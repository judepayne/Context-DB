use super::{
    contracts::{
        CheckIssue, CheckResponse, CheckSeverity, DraftStatus, Endpoint, Handle, HypothesisStatus,
        ReferenceStatus, ViewKind, ViewResponse, SCHEMA,
    },
    state::{Record, Workspace},
    Error, Result,
};
use std::collections::BTreeMap;

impl Workspace {
    pub(crate) fn view(&self, kind: ViewKind, max_bytes: Option<usize>) -> Result<ViewResponse> {
        let ceiling = max_bytes
            .unwrap_or(self.limits.max_overview_bytes)
            .min(self.limits.max_response_bytes);
        if ceiling < 128 {
            return Err(Error::Limit("view_bytes"));
        }
        let (name, candidates) = match &kind {
            ViewKind::Overview => ("overview", self.overview_lines()),
            ViewKind::Neighbourhood { centre } => {
                self.record(centre)?;
                ("neighbourhood", self.neighbourhood_lines(centre))
            }
            ViewKind::Changes => ("changes", self.change_lines()),
            ViewKind::OpenQuestions => ("open_questions", self.question_lines()?),
        };
        self.render(name, candidates, ceiling)
    }

    pub(crate) fn check(&self) -> Result<CheckResponse> {
        let mut issues = Vec::new();
        let mut candidates = BTreeMap::<Handle, Vec<Handle>>::new();
        for record in self.records.values() {
            match record {
                Record::DraftNode(node)
                    if node.status == DraftStatus::Active && node.evidence.is_empty() =>
                {
                    issue(
                        &mut issues,
                        "missing_evidence",
                        CheckSeverity::Warning,
                        vec![node.handle.clone()],
                        "active draft node has no document evidence",
                    );
                }
                Record::DraftClaim(claim)
                    if claim.status == DraftStatus::Active && claim.evidence.is_empty() =>
                {
                    issue(
                        &mut issues,
                        "missing_evidence",
                        CheckSeverity::Warning,
                        vec![claim.handle.clone()],
                        "active draft claim has no document evidence",
                    );
                }
                Record::Reference(reference) if reference.status == DraftStatus::Active => {
                    if reference.definition_evidence.is_empty() {
                        issue(
                            &mut issues,
                            "reference_definition_evidence_missing",
                            CheckSeverity::Warning,
                            vec![reference.handle.clone()],
                            "document reference has no definition evidence",
                        );
                    }
                    match reference.resolution {
                        ReferenceStatus::Resolved if reference.members.is_empty() => issue(
                            &mut issues,
                            "resolved_reference_empty",
                            CheckSeverity::Error,
                            vec![reference.handle.clone()],
                            "resolved reference has no referents",
                        ),
                        ReferenceStatus::Resolved if reference.membership_evidence.is_empty() => {
                            issue(
                                &mut issues,
                                "resolved_reference_membership_evidence_missing",
                                CheckSeverity::Error,
                                vec![reference.handle.clone()],
                                "resolved reference has no membership evidence",
                            )
                        }
                        ReferenceStatus::Partial if reference.members.is_empty() => issue(
                            &mut issues,
                            "partial_reference_empty",
                            CheckSeverity::Warning,
                            vec![reference.handle.clone()],
                            "partial reference has no known referents",
                        ),
                        ReferenceStatus::Unresolved if !reference.members.is_empty() => issue(
                            &mut issues,
                            "unresolved_reference_has_members",
                            CheckSeverity::Error,
                            vec![reference.handle.clone()],
                            "unresolved reference contradicts represented members",
                        ),
                        ReferenceStatus::Unresolved => issue(
                            &mut issues,
                            "reference_unresolved",
                            CheckSeverity::Warning,
                            vec![reference.handle.clone()],
                            "document reference remains explicitly unresolved",
                        ),
                        _ => {}
                    }
                }
                Record::Hypothesis(hypothesis)
                    if hypothesis.status == HypothesisStatus::Candidate =>
                {
                    if hypothesis.comparison_evidence.is_empty() {
                        issue(
                            &mut issues,
                            "identity_comparison_evidence_missing",
                            CheckSeverity::Warning,
                            vec![hypothesis.handle.clone()],
                            "identity candidate has no comparison evidence",
                        );
                    }
                    candidates
                        .entry(hypothesis.proposed.clone())
                        .or_default()
                        .push(hypothesis.handle.clone());
                }
                _ => {}
            }
        }
        for handles in candidates.values().filter(|handles| handles.len() > 1) {
            issue(
                &mut issues,
                "ambiguous_identity_candidates",
                CheckSeverity::Warning,
                handles.clone(),
                "multiple active identity candidates remain; no identity was merged",
            );
        }
        issues.sort_by(|left, right| {
            left.code
                .cmp(&right.code)
                .then(left.handles.cmp(&right.handles))
        });
        let structurally_valid = !issues
            .iter()
            .any(|issue| issue.severity == CheckSeverity::Error);
        let total = issues.len();
        let mut response = CheckResponse {
            schema: SCHEMA.to_owned(),
            revision: self.revision,
            structurally_valid,
            issues,
            check_partial: false,
            omitted_issues: 0,
            note: "Structural checks do not certify semantic correctness, ontology fit, identity reuse, or admission.".to_owned(),
        };
        while serde_json::to_vec(&response)
            .map_err(|_| Error::Invalid("check serialization"))?
            .len()
            > self.limits.max_response_bytes
        {
            if response.issues.pop().is_none() {
                return Err(Error::Limit("response_bytes"));
            }
            response.check_partial = true;
            response.omitted_issues = total - response.issues.len();
        }
        Ok(response)
    }

    fn overview_lines(&self) -> Vec<(Option<Handle>, String)> {
        let mut lines = vec![(None, format!(
            "WORKSPACE {} / revision {} | graphs {} | imported nodes {} claims {} | draft nodes {} edges {}",
            clean(&self.session_id), self.revision, self.counters.live_graphs, self.counters.imported_nodes,
            self.counters.imported_claims, self.counters.draft_nodes, self.counters.draft_edges
        ))];
        for graph in self.graphs.values() {
            lines.push((
                Some(graph.handle.clone()),
                format!(
                    "GRAPH {} [{:?}] snapshot={}",
                    graph.handle.0,
                    graph.status,
                    clean(&graph.snapshot)
                ),
            ));
        }
        for record in self.records.values() {
            if let Some(line) = summary(record) {
                lines.push((Some(record.handle().clone()), line));
            }
        }
        lines
    }

    fn neighbourhood_lines(&self, centre: &Handle) -> Vec<(Option<Handle>, String)> {
        let mut lines = vec![(
            Some(centre.clone()),
            format!("NEIGHBOURHOOD {} / revision {}", centre.0, self.revision),
        )];
        if let Some(record) = self.records.get(centre).and_then(summary) {
            lines.push((Some(centre.clone()), record));
        }
        for record in self.records.values() {
            let connected = match record {
                Record::ImportedClaim(claim) => {
                    claim.subject == *centre
                        || matches!(&claim.object, Endpoint::Record { handle } if handle == centre)
                }
                Record::DraftClaim(claim) => {
                    claim.subject == *centre
                        || matches!(&claim.object, Endpoint::Record { handle } if handle == centre)
                }
                Record::Reference(reference) => reference.members.contains(centre),
                Record::Hypothesis(hypothesis) => {
                    hypothesis.proposed == *centre || hypothesis.existing == *centre
                }
                Record::Question(question) => question.relevant.contains(centre),
                _ => false,
            };
            if connected {
                if let Some(line) = summary(record) {
                    lines.push((Some(record.handle().clone()), line));
                }
            }
        }
        lines
    }

    fn change_lines(&self) -> Vec<(Option<Handle>, String)> {
        let mut lines = vec![(None, format!("CHANGES / revision {}", self.revision))];
        for record in self.records.values() {
            if !matches!(record, Record::ImportedNode(_) | Record::ImportedClaim(_)) {
                if let Some(line) = summary(record) {
                    lines.push((Some(record.handle().clone()), line));
                }
            }
        }
        lines
    }

    fn question_lines(&self) -> Result<Vec<(Option<Handle>, String)>> {
        let check = self.check()?;
        let mut lines = vec![(None, format!("OPEN QUESTIONS / revision {}", self.revision))];
        for record in self.records.values() {
            if let Record::Question(question) = record {
                if question.status == DraftStatus::Active {
                    lines.push((
                        Some(question.handle.clone()),
                        format!(
                            "QUESTION {} [{}] {}",
                            question.handle.0,
                            clean(&question.code),
                            clean(&question.message)
                        ),
                    ));
                }
            }
        }
        for issue in check.issues {
            lines.push((
                issue.handles.first().cloned(),
                format!(
                    "CHECK {} [{:?}] {}",
                    issue.code,
                    issue.severity,
                    clean(&issue.message)
                ),
            ));
        }
        Ok(lines)
    }

    fn render(
        &self,
        kind: &str,
        candidates: Vec<(Option<Handle>, String)>,
        max_bytes: usize,
    ) -> Result<ViewResponse> {
        let mut consumed = candidates.len();
        loop {
            let omitted = candidates.len().saturating_sub(consumed);
            let mut rendered = String::new();
            let mut included = Vec::new();
            for (handle, line) in candidates.iter().take(consumed) {
                rendered.push_str(line);
                rendered.push('\n');
                if let Some(handle) = handle {
                    included.push(handle.clone());
                }
            }
            if omitted > 0 {
                rendered.push_str(&format!("… VIEW PARTIAL: {omitted} record(s) omitted\n"));
            }
            let response = ViewResponse {
                schema: SCHEMA.to_owned(),
                revision: self.revision,
                kind: kind.to_owned(),
                rendered,
                view_partial: omitted > 0,
                omitted_records: omitted,
                included_handles: included,
            };
            let bytes = serde_json::to_vec(&response)
                .map_err(|_| Error::Invalid("view serialization"))?
                .len();
            if bytes <= max_bytes && bytes <= self.limits.max_response_bytes {
                return Ok(response);
            }
            if consumed == 0 {
                return Err(Error::Limit("view_bytes"));
            }
            consumed -= 1;
        }
    }
}

fn issue(
    issues: &mut Vec<CheckIssue>,
    code: &str,
    severity: CheckSeverity,
    handles: Vec<Handle>,
    message: &str,
) {
    issues.push(CheckIssue {
        code: code.to_owned(),
        severity,
        handles,
        message: message.to_owned(),
    });
}

fn summary(record: &Record) -> Option<String> {
    Some(match record {
        Record::ImportedNode(node) => format!(
            "EXISTING {}: {} [canonical={}]",
            node.handle.0,
            clean(&node.label),
            clean(&node.canonical_iri)
        ),
        Record::ImportedClaim(claim) => format!(
            "EXISTING {}: {} --{}--> {} [claim={}]",
            claim.handle.0,
            claim.subject.0,
            clean(&claim.predicate),
            endpoint(&claim.object),
            clean(&claim.claim_id)
        ),
        Record::DraftNode(node) => format!(
            "PROPOSED {} [{:?}]: {} [local={}]",
            node.handle.0,
            node.status,
            clean(&node.label),
            clean(&node.local_id)
        ),
        Record::DraftClaim(claim) => format!(
            "PROPOSED {} [{:?}]: {} --{}--> {} [evidence={}]",
            claim.handle.0,
            claim.status,
            claim.subject.0,
            clean(&claim.predicate),
            endpoint(&claim.object),
            claim
                .evidence
                .iter()
                .map(|v| clean(v))
                .collect::<Vec<_>>()
                .join(",")
        ),
        Record::Reference(reference) => format!(
            "WORKING {} [{:?}/{:?}]: reference “{}” scope={} members={{{}}}",
            reference.handle.0,
            reference.status,
            reference.resolution,
            clean(&reference.label),
            clean(&reference.scope),
            reference
                .members
                .iter()
                .map(|h| h.0.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
        Record::Hypothesis(hypothesis) => format!(
            "WORKING {} [{:?}]: {} may match {} ({})",
            hypothesis.handle.0,
            hypothesis.status,
            hypothesis.proposed.0,
            hypothesis.existing.0,
            clean(&hypothesis.note)
        ),
        Record::Question(question) => format!(
            "WORKING {} [{:?}]: question [{}] {}",
            question.handle.0,
            question.status,
            clean(&question.code),
            clean(&question.message)
        ),
    })
}

fn endpoint(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Record { handle } => handle.0.clone(),
        Endpoint::Literal { value } => format!(
            "\"{}\"^^{}{}",
            clean(&value.lexical),
            clean(&value.datatype),
            value
                .language
                .as_ref()
                .map(|v| format!("@{}", clean(v)))
                .unwrap_or_default()
        ),
    }
}

fn clean(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '�' } else { ch })
        .collect()
}
