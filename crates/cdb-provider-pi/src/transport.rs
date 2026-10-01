use crate::agent_bundle::AgentBundle;
use crate::cancel::CancellationToken;
use crate::ontology_bridge::{OntologyBridge, OntologyBridgeConfig};
use crate::session_logging::ProcessLog;
use crate::usage::{Usage, UsageAccumulator};
use crate::{SessionLogging, MODEL, RUNTIME_MODEL, THINKING};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct TransportLimits {
    pub timeout: Duration,
    pub max_request_bytes: usize,
    pub max_output_bytes: usize,
    pub max_event_bytes: usize,
    pub max_events: usize,
    pub max_tool_calls: usize,
    pub max_total_tokens: u64,
    pub max_cost_microusd: u64,
}
impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            max_request_bytes: 512 * 1024,
            max_output_bytes: 256 * 1024,
            max_event_bytes: 2 * 1024 * 1024,
            max_events: 2048,
            max_tool_calls: 32,
            max_total_tokens: 128_000,
            max_cost_microusd: 5_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtractionProtocol {
    LegacyV1,
    ProposalsV2,
}

#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub command: PathBuf,
    pub env: Vec<(String, String)>,
    pub system_prompt: String,
    pub protocol: ExtractionProtocol,
    pub bundle: AgentBundle,
    pub ontology_bridge: OntologyBridgeConfig,
    pub limits: TransportLimits,
    /// Explicit opt-in. Native Pi JSONL sessions may contain sensitive prompts,
    /// reasoning, tool arguments/results, and source text.
    pub session_logging: Option<SessionLogging>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportReply {
    pub request_id: String,
    pub text: String,
    pub usage: Usage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    Spawn,
    Io,
    Rpc,
    Timeout,
    Cancelled,
    Limit(&'static str),
    ModelMismatch,
    MissingModel,
    MissingOutput,
    MissingSkill,
    PromptMismatch,
}
impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TransportError {}

#[derive(Clone)]
pub struct PiTransport {
    config: Arc<TransportConfig>,
    session: Arc<Mutex<Option<Session>>>,
    usage: Arc<Mutex<UsageAccumulator>>,
    ontology_bridge: Arc<OntologyBridge>,
}

struct Session {
    child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<Result<Value, TransportError>>,
    process_log: Option<Arc<ProcessLog>>,
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

impl PiTransport {
    pub fn new(mut config: TransportConfig) -> Result<Self, TransportError> {
        if graph_workspace_enabled(&config) {
            config.limits.max_tool_calls = config.limits.max_tool_calls.min(40);
        }
        if config.bundle.manifest.model != MODEL || config.bundle.manifest.thinking != THINKING {
            return Err(TransportError::ModelMismatch);
        }
        if config
            .session_logging
            .as_ref()
            .is_some_and(|logging| !logging.root.is_absolute())
        {
            return Err(TransportError::Spawn);
        }
        let expected_prompt = match config.protocol {
            ExtractionProtocol::LegacyV1 => config.bundle.system_prompt(),
            ExtractionProtocol::ProposalsV2 => config.bundle.system_prompt_v2(),
        }
        .map_err(|_| TransportError::PromptMismatch)?;
        if expected_prompt != config.system_prompt {
            return Err(TransportError::PromptMismatch);
        }
        config.bundle = config
            .bundle
            .stage_verified()
            .map_err(|_| TransportError::PromptMismatch)?;
        if config.system_prompt.len() > config.limits.max_request_bytes {
            return Err(TransportError::Limit("system_prompt_bytes"));
        }
        let ontology_bridge = OntologyBridge::start(config.ontology_bridge.clone())
            .map_err(|_| TransportError::Spawn)?;
        Ok(Self {
            config: Arc::new(config),
            session: Arc::new(Mutex::new(None)),
            usage: Arc::new(Mutex::new(UsageAccumulator::default())),
            ontology_bridge,
        })
    }

    pub fn request(
        &self,
        prompt: &str,
        cancel: &CancellationToken,
    ) -> Result<TransportReply, TransportError> {
        if prompt.len() > self.config.limits.max_request_bytes {
            return Err(TransportError::Limit("request_bytes"));
        }
        if cancel.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        let request_id = format!("ctxql-{}", REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed));
        let mut guard = self.session.lock().map_err(|_| TransportError::Rpc)?;
        if guard.is_none() {
            *guard = Some(spawn_session(&self.config, &self.ontology_bridge)?);
        }
        let result = call_session(
            guard.as_mut().ok_or(TransportError::Rpc)?,
            &self.config,
            &request_id,
            prompt,
            cancel,
            &self.usage,
        );
        if let Some(log) = guard
            .as_ref()
            .and_then(|session| session.process_log.as_ref())
        {
            log.record(
                "extraction_request",
                result
                    .as_ref()
                    .map(|_| "ok")
                    .unwrap_or_else(|error| diagnostic_error(error)),
            );
        }
        if result.is_err() {
            *guard = None;
        }
        result
    }

    pub fn usage(&self) -> Usage {
        self.usage.lock().map(|u| u.snapshot()).unwrap_or_default()
    }
    pub fn teardown(&self) {
        if let Ok(mut session) = self.session.lock() {
            *session = None;
        }
    }
}

fn graph_workspace_enabled(config: &TransportConfig) -> bool {
    config.env.iter().any(|(key, value)| {
        key == "CTXQL_GRAPH_WORKSPACE_ENABLED" && matches!(value.as_str(), "1" | "true")
    })
}

fn required_skill_names(protocol: ExtractionProtocol, graph_workspace: bool) -> BTreeSet<String> {
    let mut required = BTreeSet::from([match protocol {
        ExtractionProtocol::LegacyV1 => "read-loan-agreement".to_owned(),
        ExtractionProtocol::ProposalsV2 => "read-loan-agreement-v2".to_owned(),
    }]);
    if protocol == ExtractionProtocol::ProposalsV2 && graph_workspace {
        required.extend([
            "ctxql-ontology".to_owned(),
            "ctxql-query".to_owned(),
            "graph-workspace".to_owned(),
        ]);
    }
    required
}

fn required_skills(config: &TransportConfig) -> BTreeSet<String> {
    required_skill_names(config.protocol, graph_workspace_enabled(config))
}

fn spawn_session(
    config: &TransportConfig,
    ontology_bridge: &OntologyBridge,
) -> Result<Session, TransportError> {
    let process_log = config
        .session_logging
        .as_ref()
        .map(|logging| ProcessLog::create(logging, "extraction"))
        .transpose()
        .map_err(|_| TransportError::Spawn)?
        .map(Arc::new);
    if let Some(log) = &process_log {
        log.record("provider_start", "attempt");
    }
    let extension = config.bundle.root.join("extensions/ctxql-ontology-tool.ts");
    let tools = if graph_workspace_enabled(config) {
        "ctxql_ontology,ctxql_entities,ctxql_skill,ctxql_graph_query,ctxql_graph_playground"
    } else {
        "ctxql_ontology,ctxql_entities,ctxql_skill"
    };
    let args = [
        "--mode",
        "rpc",
        "--no-context-files",
        "--no-skills",
        "--no-prompt-templates",
        "--no-extensions",
        "--no-builtin-tools",
        "--tools",
        tools,
        "--model",
        MODEL,
        "--thinking",
        THINKING,
        "--extension",
        extension.to_str().ok_or(TransportError::Spawn)?,
        "--system-prompt",
        &config.system_prompt,
    ];
    let mut command = Command::new(&config.command);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command.current_dir(&config.bundle.root);
    command.env_clear();
    for (key, value) in &config.env {
        command.env(key, value);
    }
    command.env("CTXQL_PI_BUNDLE_HASH", &config.bundle.hash);
    command.env("CTXQL_PI_PROFILE", "extraction");
    command.env("CTXQL_ONTOLOGY_SOCKET", ontology_bridge.socket());
    command.env("CTXQL_ONTOLOGY_TOKEN", ontology_bridge.token());
    if let Some(log) = &process_log {
        command.arg("--session-dir").arg(log.session_dir());
    } else {
        command.arg("--no-session");
    }
    let mut child = command.spawn().map_err(|_| TransportError::Spawn)?;
    if let Some(log) = &process_log {
        log.record("provider_start", "ok");
    }
    let stdin = child.stdin.take().ok_or(TransportError::Spawn)?;
    let stdout = child.stdout.take().ok_or(TransportError::Spawn)?;
    let (tx, rx) = mpsc::channel();
    let max = config.limits.max_event_bytes;
    let reader_log = process_log.clone();
    std::thread::spawn(move || read_events(stdout, max, tx, reader_log));
    Ok(Session {
        child,
        stdin,
        rx,
        process_log,
    })
}

fn call_session(
    session: &mut Session,
    config: &TransportConfig,
    request_id: &str,
    prompt: &str,
    cancel: &CancellationToken,
    usage: &Mutex<UsageAccumulator>,
) -> Result<TransportReply, TransportError> {
    let deadline = Instant::now() + config.limits.timeout;
    let new_id = format!("{request_id}-new");
    log_stage(session, "extraction_new_session", "attempt");
    send(session, &json!({"id":new_id,"type":"new_session"}))?;
    wait_response(session, &new_id, deadline, cancel, &config.limits)?;
    log_stage(session, "extraction_new_session", "ok");
    send(
        session,
        &json!({"id":request_id,"type":"prompt","message":prompt}),
    )?;
    log_stage(session, "extraction_prompt", "sent");
    let required_skills = required_skills(config);
    let AgentEnd {
        text,
        model,
        mut events,
        mut tools,
        loaded_skills,
    } = wait_agent_end(session, deadline, cancel, &config.limits, &required_skills)?;
    log_stage(session, "extraction_agent_end", "validated");
    if !matches!(model.as_deref(), Some(MODEL | RUNTIME_MODEL)) {
        return Err(if model.is_some() {
            TransportError::ModelMismatch
        } else {
            TransportError::MissingModel
        });
    }
    if text.len() > config.limits.max_output_bytes {
        return Err(TransportError::Limit("output_bytes"));
    }
    let requires_skill = match config.protocol {
        ExtractionProtocol::LegacyV1 => {
            text.starts_with("CLAIM:")
                || text.starts_with("FACT:")
                || text.starts_with("TYPED_FACT:")
        }
        ExtractionProtocol::ProposalsV2 => {
            serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|value| value.get("no_claims").and_then(Value::as_bool))
                != Some(true)
        }
    };
    if requires_skill && !required_skills.is_subset(&loaded_skills) {
        return Err(TransportError::MissingSkill);
    }
    let stats_id = format!("{request_id}-stats");
    log_stage(session, "extraction_usage", "attempt");
    send(session, &json!({"id":stats_id,"type":"get_session_stats"}))?;
    let stats = wait_response_counted(
        session,
        &stats_id,
        deadline,
        cancel,
        &config.limits,
        &mut events,
        &mut tools,
    )?;
    log_stage(session, "extraction_usage", "validated");
    let mut accumulator = usage.lock().map_err(|_| TransportError::Rpc)?;
    accumulator.add(request_id, &stats);
    let current = accumulator.snapshot();
    let request_usage = usage_from_stats(&stats);
    if request_usage
        .input_tokens
        .saturating_add(request_usage.output_tokens)
        > config.limits.max_total_tokens
    {
        return Err(TransportError::Limit("tokens"));
    }
    if request_usage.cost_microusd > config.limits.max_cost_microusd {
        return Err(TransportError::Limit("cost"));
    }
    Ok(TransportReply {
        request_id: request_id.to_owned(),
        text,
        usage: current,
    })
}

fn log_stage(session: &Session, event: &'static str, outcome: &'static str) {
    if let Some(log) = &session.process_log {
        log.record(event, outcome);
    }
}

fn diagnostic_error(error: &TransportError) -> &'static str {
    match error {
        TransportError::Spawn => "rejected_spawn",
        TransportError::Io => "rejected_io",
        TransportError::Rpc => "rejected_rpc",
        TransportError::Timeout => "rejected_timeout",
        TransportError::Cancelled => "rejected_cancelled",
        TransportError::Limit("request_bytes") => "rejected_limit_request_bytes",
        TransportError::Limit("system_prompt_bytes") => "rejected_limit_system_prompt_bytes",
        TransportError::Limit("output_bytes") => "rejected_limit_output_bytes",
        TransportError::Limit("event_bytes") => "rejected_limit_event_bytes",
        TransportError::Limit("events") => "rejected_limit_events",
        TransportError::Limit("tool_calls") => "rejected_limit_tool_calls",
        TransportError::Limit("tokens") => "rejected_limit_tokens",
        TransportError::Limit("cost") => "rejected_limit_cost",
        TransportError::Limit(_) => "rejected_limit_other",
        TransportError::ModelMismatch => "rejected_model_mismatch",
        TransportError::MissingModel => "rejected_missing_model",
        TransportError::MissingOutput => "rejected_missing_output",
        TransportError::MissingSkill => "rejected_missing_skill",
        TransportError::PromptMismatch => "rejected_prompt_mismatch",
    }
}

fn send(session: &mut Session, value: &Value) -> Result<(), TransportError> {
    serde_json::to_writer(&mut session.stdin, value).map_err(|_| TransportError::Io)?;
    session
        .stdin
        .write_all(b"\n")
        .map_err(|_| TransportError::Io)?;
    session.stdin.flush().map_err(|_| TransportError::Io)
}

fn wait_response(
    session: &mut Session,
    id: &str,
    deadline: Instant,
    cancel: &CancellationToken,
    limits: &TransportLimits,
) -> Result<Value, TransportError> {
    let mut events = 0;
    let mut tools = 0;
    wait_response_counted(
        session,
        id,
        deadline,
        cancel,
        limits,
        &mut events,
        &mut tools,
    )
}
fn wait_response_counted(
    session: &mut Session,
    id: &str,
    deadline: Instant,
    cancel: &CancellationToken,
    limits: &TransportLimits,
    events: &mut usize,
    tools: &mut usize,
) -> Result<Value, TransportError> {
    loop {
        let event = receive(session, deadline, cancel)?;
        count_event(&event, events, tools, limits)?;
        if event.get("type").and_then(Value::as_str) == Some("response")
            && event.get("id").and_then(Value::as_str) == Some(id)
        {
            if event.get("success").and_then(Value::as_bool) != Some(true) {
                return Err(TransportError::Rpc);
            }
            return Ok(event.get("data").cloned().unwrap_or(Value::Null));
        }
    }
}

struct AgentEnd {
    text: String,
    model: Option<String>,
    events: usize,
    tools: usize,
    loaded_skills: BTreeSet<String>,
}

fn wait_agent_end(
    session: &mut Session,
    deadline: Instant,
    cancel: &CancellationToken,
    limits: &TransportLimits,
    required_skills: &BTreeSet<String>,
) -> Result<AgentEnd, TransportError> {
    let mut events = 0;
    let mut tools = 0;
    let mut pending_skills = std::collections::BTreeMap::<String, String>::new();
    let mut loaded_skills = BTreeSet::new();
    loop {
        let event = receive(session, deadline, cancel)?;
        count_event(&event, &mut events, &mut tools, limits)?;
        let kind = event.get("type").and_then(Value::as_str);
        if kind == Some("tool_execution_start")
            && event.get("toolName").and_then(Value::as_str) == Some("ctxql_skill")
        {
            if let (Some(call_id), Some(name)) = (
                event.get("toolCallId").and_then(Value::as_str),
                event
                    .get("args")
                    .and_then(|args| args.get("name"))
                    .and_then(Value::as_str),
            ) {
                if required_skills.contains(name) {
                    pending_skills.insert(call_id.to_owned(), name.to_owned());
                }
            }
        } else if kind == Some("tool_execution_end") {
            if let Some(call_id) = event.get("toolCallId").and_then(Value::as_str) {
                if let Some(name) = pending_skills.remove(call_id) {
                    if event.get("isError").and_then(Value::as_bool) == Some(false) {
                        loaded_skills.insert(name);
                    }
                }
            }
        }
        if event.get("type").and_then(Value::as_str) == Some("response")
            && event.get("success").and_then(Value::as_bool) == Some(false)
        {
            return Err(TransportError::Rpc);
        }
        if event.get("type").and_then(Value::as_str) == Some("agent_end") {
            let text = assistant_text(&event).ok_or(TransportError::MissingOutput)?;
            let model = find_model(&event).map(str::to_owned);
            return Ok(AgentEnd {
                text,
                model,
                events,
                tools,
                loaded_skills,
            });
        }
    }
}

fn receive(
    session: &mut Session,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<Value, TransportError> {
    loop {
        if cancel.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(TransportError::Timeout)?;
        match session
            .rx
            .recv_timeout(remaining.min(Duration::from_millis(25)))
        {
            Ok(value) => return value,
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => continue,
            Err(mpsc::RecvTimeoutError::Timeout) => return Err(TransportError::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(TransportError::Rpc),
        }
    }
}
fn count_event(
    event: &Value,
    events: &mut usize,
    tools: &mut usize,
    limits: &TransportLimits,
) -> Result<(), TransportError> {
    *events += 1;
    if *events > limits.max_events {
        return Err(TransportError::Limit("events"));
    }
    let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
    // Pi emits start, update, and end events for one logical call. Count only
    // starts so the configured budget cannot vary with transport verbosity.
    if kind == "tool_execution_start" {
        *tools += 1;
        if *tools > limits.max_tool_calls {
            return Err(TransportError::Limit("tool_calls"));
        }
    }
    Ok(())
}

fn read_events(
    stdout: impl std::io::Read,
    max_event_bytes: usize,
    tx: mpsc::Sender<Result<Value, TransportError>>,
    process_log: Option<Arc<ProcessLog>>,
) {
    let mut reader = BufReader::new(stdout);
    loop {
        let mut bytes = Vec::new();
        match reader
            .by_ref()
            .take(max_event_bytes.saturating_add(1) as u64)
            .read_until(b'\n', &mut bytes)
        {
            Ok(0) => break,
            Ok(_) if bytes.len() > max_event_bytes => {
                if let Some(log) = &process_log {
                    log.record("extraction_rpc_framing", "record_too_large");
                }
                let _ = tx.send(Err(TransportError::Limit("event_bytes")));
                break;
            }
            Ok(_) => {
                while matches!(bytes.last(), Some(b'\n' | b'\r')) {
                    bytes.pop();
                }
                let parsed = serde_json::from_slice(&bytes).map_err(|_| {
                    if let Some(log) = &process_log {
                        log.record("extraction_rpc_framing", "invalid_json");
                    }
                    TransportError::Rpc
                });
                if tx.send(parsed).is_err() {
                    break;
                }
            }
            Err(_) => {
                if let Some(log) = &process_log {
                    log.record("extraction_rpc_framing", "read_io_error");
                }
                let _ = tx.send(Err(TransportError::Io));
                break;
            }
        }
    }
}

fn assistant_text(event: &Value) -> Option<String> {
    for message in event.get("messages")?.as_array()?.iter().rev() {
        if message.get("role").and_then(Value::as_str) != Some("assistant")
            && message.get("type").and_then(Value::as_str) != Some("assistant")
        {
            continue;
        }
        if let Some(text) = message.get("text").and_then(Value::as_str) {
            return Some(text.to_owned());
        }
        if let Some(text) = message.get("content").and_then(Value::as_str) {
            return Some(text.to_owned());
        }
        if let Some(blocks) = message.get("content").and_then(Value::as_array) {
            let joined: String = blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect();
            if !joined.is_empty() {
                return Some(joined);
            }
        }
    }
    None
}
fn find_model(value: &Value) -> Option<&str> {
    match value {
        Value::Object(map) => map
            .get("model")
            .and_then(Value::as_str)
            .or_else(|| map.values().find_map(find_model)),
        Value::Array(values) => values.iter().find_map(find_model),
        _ => None,
    }
}
fn usage_from_stats(stats: &Value) -> Usage {
    let mut a = UsageAccumulator::default();
    a.add("request", stats);
    a.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_errors_are_specific_content_free_categories() {
        assert_eq!(
            diagnostic_error(&TransportError::Timeout),
            "rejected_timeout"
        );
        assert_eq!(
            diagnostic_error(&TransportError::MissingSkill),
            "rejected_missing_skill"
        );
        assert_eq!(
            diagnostic_error(&TransportError::Limit("tokens")),
            "rejected_limit_tokens"
        );
        assert_eq!(
            diagnostic_error(&TransportError::Limit("unrecognized")),
            "rejected_limit_other"
        );
    }

    #[test]
    fn graph_enabled_v2_requires_both_correlated_skills() {
        assert_eq!(
            required_skill_names(ExtractionProtocol::LegacyV1, true),
            BTreeSet::from(["read-loan-agreement".to_owned()])
        );
        assert_eq!(
            required_skill_names(ExtractionProtocol::ProposalsV2, false),
            BTreeSet::from(["read-loan-agreement-v2".to_owned()])
        );
        assert_eq!(
            required_skill_names(ExtractionProtocol::ProposalsV2, true),
            BTreeSet::from([
                "ctxql-ontology".to_owned(),
                "ctxql-query".to_owned(),
                "graph-workspace".to_owned(),
                "read-loan-agreement-v2".to_owned(),
            ])
        );
    }
}
