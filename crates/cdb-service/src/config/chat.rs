use super::{resolve_config_path, ArtifactReference, ConfigError, Result};
use cdb_core::id::ContentHash;
use serde::Deserialize;
use std::path::{Path, PathBuf};

// Operators may raise conversation retention above the conservative default.
const MAX_CHAT_CONTEXT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ChatOntologyConfig {
    pub bootstrap_path: PathBuf,
    pub receipt_hash: String,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct ChatLimits {
    pub max_input_bytes: usize,
    pub max_turns: usize,
    pub max_model_rounds: usize,
    pub turn_seconds: usize,
    pub shutdown_seconds: usize,
    pub max_answer_bytes: usize,
    pub max_rpc_record_bytes: usize,
    pub max_rpc_queue_bytes: usize,
    pub max_rpc_events_per_turn: usize,
    pub max_reported_tokens: usize,
    pub max_reported_cost_micro_usd: usize,
    pub host_call_seconds: usize,
    pub max_nodes: usize,
    pub max_claims: usize,
    pub max_live_graphs: usize,
    pub max_tool_calls_per_turn: usize,
    pub max_queries_per_turn: usize,
    pub max_tool_calls: usize,
    pub max_queries: usize,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_tool_response_bytes_per_turn: usize,
    pub max_state_bytes: usize,
    pub max_context_bytes: usize,
    pub max_source_span_bytes: usize,
    pub max_source_bytes_per_turn: usize,
    pub max_citations: usize,
    pub max_work: usize,
}

impl Default for ChatLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 8192,
            max_turns: 20,
            max_model_rounds: 100,
            turn_seconds: 300,
            shutdown_seconds: 2,
            max_answer_bytes: 65_536,
            max_rpc_record_bytes: 1_048_576,
            max_rpc_queue_bytes: 2_097_152,
            max_rpc_events_per_turn: 16_384,
            // Cumulative across requests, including repeatedly billed/read
            // cached context; this is not a model context-window size.
            max_reported_tokens: 1_000_000,
            max_reported_cost_micro_usd: 5_000_000,
            host_call_seconds: 10,
            max_nodes: 50,
            max_claims: 100,
            max_live_graphs: 3,
            max_tool_calls_per_turn: 40,
            max_queries_per_turn: 12,
            max_tool_calls: 200,
            max_queries: 60,
            max_request_bytes: 32 * 1024,
            max_response_bytes: 64 * 1024,
            max_tool_response_bytes_per_turn: 1024 * 1024,
            max_state_bytes: 2 * 1024 * 1024,
            max_context_bytes: 512 * 1024,
            max_source_span_bytes: 16 * 1024,
            max_source_bytes_per_turn: 64 * 1024,
            max_citations: 4096,
            max_work: 1_000_000,
        }
    }
}

impl ChatLimits {
    pub(crate) fn validate(&self, _service_deadline: usize, _service_work: usize) -> Result<()> {
        let d = Self::default();
        if self.max_input_bytes == 0
            || self.max_input_bytes > d.max_input_bytes
            || self.max_turns == 0
            || self.max_turns > d.max_turns
            || self.max_model_rounds == 0
            || self.max_model_rounds > d.max_model_rounds
            || self.turn_seconds == 0
            || self.turn_seconds > d.turn_seconds
            || self.shutdown_seconds == 0
            || self.shutdown_seconds > d.shutdown_seconds
            || self.max_answer_bytes == 0
            || self.max_answer_bytes > d.max_answer_bytes
            || self.max_rpc_record_bytes == 0
            || self.max_rpc_record_bytes > d.max_rpc_record_bytes
            || self.max_rpc_queue_bytes == 0
            || self.max_rpc_queue_bytes > d.max_rpc_queue_bytes
            || self.max_rpc_record_bytes > self.max_rpc_queue_bytes
            || self.max_rpc_events_per_turn == 0
            || self.max_rpc_events_per_turn > d.max_rpc_events_per_turn
            || self.max_reported_tokens == 0
            || self.max_reported_tokens > d.max_reported_tokens
            || self.max_reported_cost_micro_usd == 0
            || self.max_reported_cost_micro_usd > d.max_reported_cost_micro_usd
            || self.host_call_seconds == 0
            || self.host_call_seconds > d.host_call_seconds
            || self.host_call_seconds > self.turn_seconds
            || self.max_nodes == 0
            || self.max_nodes > d.max_nodes
            || self.max_claims == 0
            || self.max_claims > d.max_claims
            || self.max_live_graphs == 0
            || self.max_live_graphs > d.max_live_graphs
            || self.max_tool_calls_per_turn == 0
            || self.max_tool_calls_per_turn > d.max_tool_calls_per_turn
            || self.max_queries_per_turn == 0
            || self.max_queries_per_turn > d.max_queries_per_turn
            || self.max_queries_per_turn > self.max_tool_calls_per_turn
            || self.max_tool_calls == 0
            || self.max_tool_calls > d.max_tool_calls
            || self.max_queries == 0
            || self.max_queries > d.max_queries
            || self.max_queries > self.max_tool_calls
            || self.max_request_bytes == 0
            || self.max_request_bytes > d.max_request_bytes
            || self.max_response_bytes == 0
            || self.max_response_bytes > d.max_response_bytes
            || self.max_tool_response_bytes_per_turn == 0
            || self.max_tool_response_bytes_per_turn > d.max_tool_response_bytes_per_turn
            || self.max_state_bytes == 0
            || self.max_state_bytes > d.max_state_bytes
            || self.max_context_bytes == 0
            || self.max_context_bytes > MAX_CHAT_CONTEXT_BYTES
            || self.max_source_span_bytes == 0
            || self.max_source_span_bytes > d.max_source_span_bytes
            || self.max_source_bytes_per_turn == 0
            || self.max_source_bytes_per_turn > d.max_source_bytes_per_turn
            || self.max_source_span_bytes > self.max_source_bytes_per_turn
            || self.max_citations == 0
            || self.max_citations > d.max_citations
            || self.max_work == 0
            || self.max_work > d.max_work
        {
            return Err(ConfigError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ChatConfig {
    pub pi_command: PathBuf,
    pub pi_bundle: PathBuf,
    /// Explicit opt-in destination for sensitive native Pi sessions and
    /// content-free host diagnostics. Absent means no local session logging.
    #[serde(default)]
    pub pi_session_log_dir: Option<PathBuf>,
    #[serde(rename = "chat_model")]
    pub chat_model: String,
    pub thinking: String,
    pub query_config: ArtifactReference,
    #[serde(default)]
    pub unsafe_direct_projection: bool,
    #[serde(default)]
    pub profile_selector: Option<String>,
    #[serde(default)]
    pub profile: Option<ArtifactReference>,
    #[serde(default)]
    pub ontology: Option<ChatOntologyConfig>,
    #[serde(default)]
    pub limits: ChatLimits,
}

impl ChatConfig {
    pub(crate) fn validate_shape(
        &self,
        service_deadline: usize,
        service_work: usize,
    ) -> Result<()> {
        if self.pi_command.as_os_str().is_empty()
            || self.pi_bundle.as_os_str().is_empty()
            || self
                .pi_session_log_dir
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            || self.chat_model != cdb_provider_pi::MODEL
            || self.thinking != cdb_provider_pi::THINKING
            || self.profile_selector.is_some() != self.profile.is_some()
            || self
                .profile_selector
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 512)
        {
            return Err(ConfigError::Invalid);
        }
        self.query_config.artifact_ref()?;
        if let Some(profile) = &self.profile {
            profile.artifact_ref()?;
        }
        if let Some(ontology) = &self.ontology {
            if ontology.bootstrap_path.as_os_str().is_empty() {
                return Err(ConfigError::UnsafePath);
            }
            ContentHash::parse(&ontology.receipt_hash).map_err(|_| ConfigError::Invalid)?;
        }
        self.limits.validate(service_deadline, service_work)
    }

    pub(crate) fn resolve_and_validate(
        &mut self,
        base: &Path,
        service_deadline: usize,
        service_work: usize,
    ) -> Result<()> {
        self.validate_shape(service_deadline, service_work)?;
        self.pi_command = resolve_config_path(base, &self.pi_command)?;
        self.pi_bundle = resolve_config_path(base, &self.pi_bundle)?;
        if let Some(path) = &mut self.pi_session_log_dir {
            *path = resolve_config_path(base, path)?;
        }
        if let Some(ontology) = &mut self.ontology {
            ontology.bootstrap_path = resolve_config_path(base, &ontology.bootstrap_path)?;
        }
        Ok(())
    }
}
