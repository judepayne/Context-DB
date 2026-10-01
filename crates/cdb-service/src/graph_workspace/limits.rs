use super::{contracts::TypedLiteral, Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceLimits {
    pub(crate) max_nodes_per_graph: usize,
    pub(crate) max_claims_per_graph: usize,
    pub(crate) max_live_graphs: usize,
    pub(crate) max_imported_nodes: usize,
    pub(crate) max_imported_claims: usize,
    pub(crate) max_draft_nodes: usize,
    pub(crate) max_draft_edges: usize,
    pub(crate) max_edits_per_batch: usize,
    pub(crate) max_tool_calls: usize,
    pub(crate) max_graph_queries: usize,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_response_bytes: usize,
    pub(crate) max_overview_bytes: usize,
    pub(crate) max_aggregate_bytes: usize,
    pub(crate) max_state_bytes: usize,
    pub(crate) max_idempotency_records: usize,
    pub(crate) max_label_bytes: usize,
    pub(crate) max_identifier_bytes: usize,
    pub(crate) max_literal_bytes: usize,
    pub(crate) max_note_bytes: usize,
    pub(crate) max_evidence_per_record: usize,
    pub(crate) max_metadata_entries: usize,
}

impl Default for WorkspaceLimits {
    fn default() -> Self {
        Self {
            max_nodes_per_graph: 50,
            max_claims_per_graph: 100,
            max_live_graphs: 3,
            max_imported_nodes: 150,
            max_imported_claims: 300,
            max_draft_nodes: 100,
            max_draft_edges: 200,
            max_edits_per_batch: 20,
            max_tool_calls: 40,
            max_graph_queries: 12,
            max_request_bytes: 32 * 1024,
            max_response_bytes: 64 * 1024,
            max_overview_bytes: 8 * 1024,
            max_aggregate_bytes: 1024 * 1024,
            max_state_bytes: 2 * 1024 * 1024,
            max_idempotency_records: 64,
            max_label_bytes: 512,
            max_identifier_bytes: 2 * 1024,
            max_literal_bytes: 16 * 1024,
            max_note_bytes: 2 * 1024,
            max_evidence_per_record: 32,
            max_metadata_entries: 64,
        }
    }
}

impl WorkspaceLimits {
    pub(super) fn bounded_text(&self, field: &'static str, value: &str, max: usize) -> Result<()> {
        if value.is_empty() || value.len() > max {
            return Err(Error::Limit(field));
        }
        Ok(())
    }

    pub(super) fn identifier(&self, field: &'static str, value: &str) -> Result<()> {
        self.bounded_text(field, value, self.max_identifier_bytes)
    }

    pub(super) fn label(&self, value: &str) -> Result<()> {
        self.bounded_text("label", value, self.max_label_bytes)
    }

    pub(super) fn note(&self, field: &'static str, value: &str) -> Result<()> {
        if value.len() > self.max_note_bytes {
            return Err(Error::Limit(field));
        }
        Ok(())
    }

    pub(super) fn literal(&self, value: &TypedLiteral) -> Result<()> {
        if value.lexical.len() > self.max_literal_bytes {
            return Err(Error::Limit("literal"));
        }
        self.identifier("literal_datatype", &value.datatype)?;
        if let Some(language) = &value.language {
            self.identifier("literal_language", language)?;
            if language.is_empty() {
                return Err(Error::Invalid("empty literal language"));
            }
        }
        Ok(())
    }
}
