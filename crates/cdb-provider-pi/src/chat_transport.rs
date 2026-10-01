//! Bounded, synchronous owner for one ephemeral Pi RPC chat process.
//!
//! The service should own this value on a dedicated OS worker. Calls are
//! intentionally small and blocking: [`ChatTransport::prompt`] only waits for
//! Pi to accept a prompt, while [`ChatTransport::poll_event`] streams typed
//! events until `Settled` or `Incomplete`. No arbitrary RPC or model-changing
//! operation is exposed.

use crate::agent_bundle::{AgentBundle, BundleProfile};
use crate::ontology_bridge::{OntologyBridge, OntologyBridgeConfig};
use crate::session_logging::ProcessLog;
use crate::usage::Usage;
use crate::{SessionLogging, MODEL, RUNTIME_MODEL, THINKING};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Finite process and per-turn bounds. Zero-valued fields are rejected.
#[derive(Clone, Debug)]
pub struct ChatTransportLimits {
    pub command_timeout: Duration,
    pub turn_timeout: Duration,
    pub shutdown_grace: Duration,
    pub max_prompt_bytes: usize,
    pub max_record_bytes: usize,
    pub max_queued_bytes: usize,
    pub max_events_per_turn: usize,
    pub max_answer_bytes_per_turn: usize,
    pub max_conversation_bytes: usize,
    pub max_tool_calls_per_turn: usize,
    pub max_tool_calls_per_process: usize,
    pub max_queries_per_turn: usize,
    pub max_queries_per_process: usize,
    pub max_user_turns_per_process: usize,
    pub max_model_rounds_per_process: usize,
    pub max_total_tokens: u64,
    pub max_cost_microusd: u64,
    pub max_stderr_bytes: usize,
}
impl Default for ChatTransportLimits {
    fn default() -> Self {
        Self {
            command_timeout: Duration::from_secs(10),
            turn_timeout: Duration::from_secs(120),
            shutdown_grace: Duration::from_secs(2),
            max_prompt_bytes: 8 * 1024,
            max_record_bytes: 1024 * 1024,
            max_queued_bytes: 2 * 1024 * 1024,
            max_events_per_turn: 16_384,
            max_answer_bytes_per_turn: 64 * 1024,
            max_conversation_bytes: 512 * 1024,
            max_tool_calls_per_turn: 40,
            max_tool_calls_per_process: 200,
            max_queries_per_turn: 12,
            max_queries_per_process: 60,
            max_user_turns_per_process: 20,
            max_model_rounds_per_process: 100,
            max_total_tokens: 128_000,
            max_cost_microusd: 5_000_000,
            max_stderr_bytes: 64 * 1024,
        }
    }
}

/// Inputs for a pinned chat process. `environment` is the complete explicit
/// provider environment; the parent's environment is never inherited.
#[derive(Clone, Debug)]
pub struct ChatTransportConfig {
    pub command: PathBuf,
    pub environment: Vec<(String, String)>,
    pub system_prompt: String,
    pub bundle: AgentBundle,
    pub ontology_bridge: OntologyBridgeConfig,
    pub limits: ChatTransportLimits,
    /// Explicit opt-in. Native Pi JSONL sessions may contain sensitive prompts,
    /// reasoning, tool arguments/results, and source text.
    pub session_logging: Option<SessionLogging>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssistantIdentity {
    /// Host-owned identity for the Pi message lifecycle. This is deliberately
    /// not an upstream provider response ID, which may be unavailable until
    /// after streaming has begun.
    pub message_id: String,
    pub provider: String,
    pub model: String,
}

/// Provider accounting is unknown until a complete assistant message supplies
/// its required final usage object. Unknown accounting is never represented by
/// an all-zero [`Usage`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsageStatus {
    Known(Usage),
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChatIncompleteReason {
    Cancelled,
    ProviderError,
    ContextLimit,
    Limit(&'static str),
    Protocol,
    Eof,
}

/// Display-safe stream events. Tool payloads, thinking, provider diagnostics,
/// and raw RPC records are deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChatEvent {
    TextDelta {
        identity: AssistantIdentity,
        content_index: usize,
        delta: String,
    },
    Progress {
        tool_name: String,
    },
    Usage {
        snapshot: Usage,
    },
    Settled {
        usage: Usage,
    },
    Incomplete {
        reason: ChatIncompleteReason,
        usage: UsageStatus,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChatTransportError {
    InvalidConfig,
    Spawn,
    Io,
    Protocol,
    Timeout,
    Busy,
    NotRunning,
    ModelMismatch,
    ResourceMismatch,
    Limit(&'static str),
}
impl std::fmt::Display for ChatTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ChatTransportError {}

struct RawQueue {
    records: VecDeque<(Value, usize)>,
    bytes: usize,
    closed: bool,
    error: Option<ChatTransportError>,
}
struct SharedQueue {
    state: Mutex<RawQueue>,
    ready: Condvar,
}

#[derive(Debug)]
struct StreamedTextBlock {
    text: String,
    finalized: bool,
}

#[derive(Debug)]
struct ActiveAssistant {
    identity: AssistantIdentity,
    upstream_response_id: Option<String>,
    text_blocks: BTreeMap<usize, StreamedTextBlock>,
}

struct PrivateRoot(PathBuf);
impl Drop for PrivateRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One persistent, in-memory Pi conversation.
pub struct ChatTransport {
    child: Child,
    writer: Option<mpsc::SyncSender<WriterRequest>>,
    queue: Arc<SharedQueue>,
    writer_worker: Option<JoinHandle<()>>,
    stdout_worker: Option<JoinHandle<()>>,
    stderr_worker: Option<JoinHandle<()>>,
    process_log: Option<Arc<ProcessLog>>,
    _private_root: PrivateRoot,
    _bridge: Arc<OntologyBridge>,
    limits: ChatTransportLimits,
    public_events: VecDeque<ChatEvent>,
    public_event_bytes: usize,
    next_id: u64,
    active: bool,
    cancelling: bool,
    turn_deadline: Option<Instant>,
    turn_events: usize,
    turn_answer_bytes: usize,
    epoch_prompt_bytes: usize,
    conversation_bytes: usize,
    turn_tools: usize,
    process_tools: usize,
    turn_queries: usize,
    process_queries: usize,
    process_turns: usize,
    process_rounds: usize,
    assistant_sequence: u64,
    assistant: Option<ActiveAssistant>,
    turn_completed_assistant: bool,
    terminal_failure: Option<ChatIncompleteReason>,
    usage: Usage,
    current_assistant_usage: Usage,
    turn_usage_pending: bool,
    usage_unknown: bool,
    closed: bool,
}

static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
/// Installed Pi protocol version verified for this transport implementation.
pub const SUPPORTED_PI_VERSION: &str = "0.87.1";

impl ChatTransport {
    /// Verify, stage, spawn, and perform the control-only RPC handshake.
    pub fn start(mut config: ChatTransportConfig) -> Result<Self, ChatTransportError> {
        validate_config(&config)?;
        verify_executable_version(
            &config.command,
            config.limits.command_timeout,
            config.limits.max_record_bytes,
        )?;
        config.bundle = config
            .bundle
            .stage_verified()
            .map_err(|_| ChatTransportError::ResourceMismatch)?;
        let expected_prompt = config
            .bundle
            .chat_system_prompt()
            .map_err(|_| ChatTransportError::ResourceMismatch)?;
        if expected_prompt != config.system_prompt {
            return Err(ChatTransportError::ResourceMismatch);
        }
        let bridge = OntologyBridge::start(config.ontology_bridge.clone())
            .map_err(|_| ChatTransportError::Spawn)?;
        let private_root = create_private_root()?;
        let process_log = config
            .session_logging
            .as_ref()
            .map(|logging| ProcessLog::create(logging, "chat"))
            .transpose()
            .map_err(|_| ChatTransportError::InvalidConfig)?
            .map(Arc::new);
        if let Some(log) = &process_log {
            log.record("provider_start", "attempt");
        }
        let extension = config.bundle.root.join("extensions/ctxql-ontology-tool.ts");
        let mut command = Command::new(&config.command);
        command
            .args([
                "--mode",
                "rpc",
                "--no-context-files",
                "--no-skills",
                "--no-prompt-templates",
                "--no-extensions",
                "--no-builtin-tools",
                "--no-approve",
                "--tools",
                "ctxql_capabilities,ctxql_ontology,ctxql_graph_query,ctxql_source",
                "--model",
                MODEL,
                "--thinking",
                THINKING,
                "--extension",
            ])
            .arg(&extension)
            .arg("--system-prompt")
            .arg(&config.system_prompt)
            .current_dir(&config.bundle.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        for (key, value) in &config.environment {
            command.env(key, value);
        }
        command
            .env("PATH", safe_execution_path(&config.command))
            .env("HOME", &private_root.0)
            .env("PI_CODING_AGENT_DIR", private_root.0.join("agent"))
            .env(
                "PI_CODING_AGENT_SESSION_DIR",
                private_root.0.join("sessions"),
            )
            .env("PI_SKIP_VERSION_CHECK", "1")
            .env("PI_TELEMETRY", "0")
            .env("CTXQL_PI_BUNDLE_HASH", &config.bundle.hash)
            .env("CTXQL_PI_PROFILE", "chat")
            .env("CTXQL_ONTOLOGY_SOCKET", bridge.socket())
            .env("CTXQL_ONTOLOGY_TOKEN", bridge.token());
        if let Some(log) = &process_log {
            command.arg("--session-dir").arg(log.session_dir());
        } else {
            command.arg("--no-session");
        }
        let mut child = command.spawn().map_err(|_| ChatTransportError::Spawn)?;
        if let Some(log) = &process_log {
            log.record("provider_start", "ok");
        }
        let stdin = child.stdin.take().ok_or(ChatTransportError::Spawn)?;
        let stdout = child.stdout.take().ok_or(ChatTransportError::Spawn)?;
        let stderr = child.stderr.take().ok_or(ChatTransportError::Spawn)?;
        let queue = Arc::new(SharedQueue {
            state: Mutex::new(RawQueue {
                records: VecDeque::new(),
                bytes: 0,
                closed: false,
                error: None,
            }),
            ready: Condvar::new(),
        });
        let (writer_tx, writer_rx) = mpsc::sync_channel(1);
        let writer_worker = Some(spawn_writer(stdin, writer_rx));
        let stdout_worker = Some(spawn_stdout_reader(
            stdout,
            queue.clone(),
            config.limits.max_record_bytes,
            config.limits.max_queued_bytes,
            config.limits.max_events_per_turn,
            process_log.clone(),
        ));
        let stderr_worker = Some(spawn_stderr_reader(
            stderr,
            config.limits.max_stderr_bytes,
            process_log.clone(),
        ));
        let epoch_prompt_bytes =
            retained_message_bytes("system", &Value::String(config.system_prompt.clone()))?;
        if epoch_prompt_bytes > config.limits.max_conversation_bytes {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ChatTransportError::Limit("conversation_bytes"));
        }
        let mut transport = Self {
            child,
            writer: Some(writer_tx),
            queue,
            writer_worker,
            stdout_worker,
            stderr_worker,
            process_log,
            _private_root: private_root,
            _bridge: bridge,
            limits: config.limits,
            public_events: VecDeque::new(),
            public_event_bytes: 0,
            next_id: 1,
            active: false,
            cancelling: false,
            turn_deadline: None,
            turn_events: 0,
            turn_answer_bytes: 0,
            epoch_prompt_bytes,
            conversation_bytes: epoch_prompt_bytes,
            turn_tools: 0,
            process_tools: 0,
            turn_queries: 0,
            process_queries: 0,
            process_turns: 0,
            process_rounds: 0,
            assistant_sequence: 0,
            assistant: None,
            turn_completed_assistant: false,
            terminal_failure: None,
            usage: Usage::default(),
            current_assistant_usage: Usage::default(),
            turn_usage_pending: false,
            usage_unknown: false,
            closed: false,
        };
        let state =
            transport.handshake_command("handshake_get_state", json!({"type":"get_state"}))?;
        if let Err(error) = transport.verify_state(&state) {
            transport.log("handshake_state_validation", diagnostic_error(&error));
            transport.close();
            return Err(error);
        }
        transport.log("handshake_state_validation", "ok");
        transport.handshake_command(
            "handshake_disable_compaction",
            json!({"type":"set_auto_compaction","enabled":false}),
        )?;
        transport.handshake_command(
            "handshake_disable_retry",
            json!({"type":"set_auto_retry","enabled":false}),
        )?;
        let commands = transport
            .handshake_command("handshake_get_commands", json!({"type":"get_commands"}))?;
        let Some(commands) = commands.get("commands").and_then(Value::as_array) else {
            transport.log("handshake_command_validation", "missing_commands");
            transport.close();
            return Err(ChatTransportError::ResourceMismatch);
        };
        // Pi 0.87.1 exposes one built-in inline llama.cpp management command
        // even with discovery disabled. It is not a skill/template or loaded
        // file resource, and user text cannot invoke it because prompts are
        // wrapped with a non-slash prefix. Reject every other discovery result.
        if !commands.iter().all(is_expected_inline_command) {
            transport.log("handshake_command_validation", "unexpected_command");
            transport.close();
            return Err(ChatTransportError::ResourceMismatch);
        }
        transport.log("handshake_command_validation", "ok");
        Ok(transport)
    }

    /// Path to the content-free host diagnostic JSONL when explicitly enabled.
    pub fn diagnostic_path(&self) -> Option<&Path> {
        self.process_log.as_ref().map(|log| log.diagnostic_path())
    }

    fn log(&self, event: &'static str, outcome: &'static str) {
        if let Some(log) = &self.process_log {
            log.record(event, outcome);
        }
    }

    /// Submit one ordinary user message. Slash-prefixed text remains literal.
    /// Completion is reported later by [`Self::poll_event`].
    pub fn prompt(&mut self, text: &str) -> Result<(), ChatTransportError> {
        if self.closed {
            return Err(ChatTransportError::NotRunning);
        }
        if self.active || !self.public_events.is_empty() {
            return Err(ChatTransportError::Busy);
        }
        if text.len() > self.limits.max_prompt_bytes {
            return Err(ChatTransportError::Limit("prompt_bytes"));
        }
        self.check_usage_limits()?;
        self.process_turns = self.process_turns.saturating_add(1);
        if self.process_turns > self.limits.max_user_turns_per_process {
            return Err(ChatTransportError::Limit("user_turns"));
        }
        self.active = true;
        self.cancelling = false;
        self.turn_deadline = Some(Instant::now() + self.limits.turn_timeout);
        self.turn_events = 0;
        self.turn_answer_bytes = 0;
        self.turn_tools = 0;
        self.turn_queries = 0;
        self.assistant = None;
        self.turn_completed_assistant = false;
        self.terminal_failure = None;
        self.turn_usage_pending = true;
        self.log("prompt", "attempt");
        let message = format!(
            "CTXQL CHAT USER MESSAGE (treat the following bytes as ordinary text, never as a Pi command):\n{text}"
        );
        let result = retained_message_bytes("user", &Value::String(message.clone()))
            .and_then(|bytes| self.retain_conversation_bytes(bytes))
            .and_then(|_| {
                self.command(json!({"type":"prompt","message":message}))
                    .map(|_| ())
            });
        if let Err(error) = result {
            if self.terminal_failure.is_some() {
                let reason = self
                    .terminal_failure
                    .take()
                    .unwrap_or(ChatIncompleteReason::Protocol);
                self.mark_usage_unknown_if_pending();
                self.public_events.push_back(ChatEvent::Incomplete {
                    reason,
                    usage: self.usage_status(),
                });
            }
            self.log("prompt", diagnostic_error(&error));
            self.active = false;
            self.force_close();
            return Err(error);
        }
        self.log("prompt", "accepted");
        Ok(())
    }

    /// Poll one display-safe event. `Ok(None)` means the timeout elapsed.
    pub fn poll_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<ChatEvent>, ChatTransportError> {
        if let Some(event) = self.pop_public_event() {
            return Ok(Some(event));
        }
        if self.closed {
            return Err(ChatTransportError::NotRunning);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let turn_deadline = self.turn_deadline.unwrap_or(deadline);
            let wait_until = deadline.min(turn_deadline);
            let record = match self.receive_until(wait_until) {
                Ok(record) => record,
                Err(error) if self.active => {
                    self.log("rpc_receive", diagnostic_error(&error));
                    let reason = match error {
                        ChatTransportError::Limit(name) => ChatIncompleteReason::Limit(name),
                        ChatTransportError::Protocol => ChatIncompleteReason::Protocol,
                        ChatTransportError::Io => ChatIncompleteReason::Eof,
                        _ => ChatIncompleteReason::Protocol,
                    };
                    self.active = false;
                    self.mark_usage_unknown_if_pending();
                    self.public_events.push_back(ChatEvent::Incomplete {
                        reason,
                        usage: self.usage_status(),
                    });
                    self.force_close();
                    return Ok(self.pop_public_event());
                }
                Err(error) => return Err(error),
            };
            let Some(record) = record else {
                if self.active && Instant::now() >= turn_deadline {
                    self.active = false;
                    self.mark_usage_unknown_if_pending();
                    self.public_events.push_back(ChatEvent::Incomplete {
                        reason: ChatIncompleteReason::Limit("turn_deadline"),
                        usage: self.usage_status(),
                    });
                    self.log("turn_deadline", "exceeded");
                    self.force_close();
                    return Ok(self.pop_public_event());
                }
                return Ok(None);
            };
            let kind = diagnostic_event_kind(&record);
            self.log(kind, "received");
            if let Err(error) = self.process_event(record) {
                self.log(kind, diagnostic_error(&error));
                if self.active {
                    let reason = self
                        .terminal_failure
                        .take()
                        .unwrap_or(ChatIncompleteReason::Protocol);
                    self.active = false;
                    self.mark_usage_unknown_if_pending();
                    self.public_events.push_back(ChatEvent::Incomplete {
                        reason,
                        usage: self.usage_status(),
                    });
                    self.force_close();
                } else {
                    return Err(error);
                }
            }
            if let Some(event) = self.pop_public_event() {
                return Ok(Some(event));
            }
        }
    }

    /// Start a fresh in-memory Pi context. Process-lifetime usage and budgets
    /// deliberately survive the clear.
    pub fn clear(&mut self) -> Result<(), ChatTransportError> {
        if self.active {
            return Err(ChatTransportError::Busy);
        }
        let data = self.command(json!({"type":"new_session"}))?;
        if data.get("cancelled").and_then(Value::as_bool) == Some(true) {
            return Err(ChatTransportError::Protocol);
        }
        let state = self.command(json!({"type":"get_state"}))?;
        self.verify_idle_state(&state)?;
        self.assistant = None;
        self.public_events.clear();
        self.public_event_bytes = 0;
        self.conversation_bytes = self.epoch_prompt_bytes;
        Ok(())
    }

    /// Cancel active work in the documented order: clear queue, then abort.
    pub fn cancel(&mut self) -> Result<(), ChatTransportError> {
        if !self.active {
            return Ok(());
        }
        self.cancelling = true;
        self.log("cancel", "attempt");
        let clear = self.command(json!({"type":"clear_queue"}));
        let abort = clear.and_then(|_| self.command(json!({"type":"abort"})).map(|_| ()));
        if abort.is_ok() {
            let state = self.command(json!({"type":"get_state"}))?;
            self.verify_idle_state(&state)?;
            self.active = false;
            self.turn_deadline = None;
            self.cancelling = false;
            self.public_events.retain(|event| {
                !matches!(
                    event,
                    ChatEvent::Settled { .. } | ChatEvent::Incomplete { .. }
                )
            });
            self.public_event_bytes = self.public_events.iter().map(event_size).sum();
            self.mark_usage_unknown_if_pending();
            self.public_events.push_back(ChatEvent::Incomplete {
                reason: ChatIncompleteReason::Cancelled,
                usage: self.usage_status(),
            });
            self.log("cancel", "confirmed_idle");
            Ok(())
        } else {
            self.log("cancel", "failed");
            self.fail_turn(ChatIncompleteReason::Cancelled);
            self.force_close();
            abort
        }
    }

    pub fn usage_snapshot(&self) -> UsageStatus {
        self.usage_status()
    }

    /// Close stdin for orderly shutdown, then kill and reap after the grace.
    pub fn close(&mut self) {
        self.log("provider_close", "attempt");
        if !self.closed {
            self.writer.take();
            let deadline = Instant::now() + self.limits.shutdown_grace;
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => break,
                    _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                    _ => {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        break;
                    }
                }
            }
        }
        if let Some(worker) = self.writer_worker.take() {
            let _ = worker.join();
        }
        if let Some(worker) = self.stdout_worker.take() {
            let _ = worker.join();
        }
        if let Some(worker) = self.stderr_worker.take() {
            let _ = worker.join();
        }
        self.closed = true;
        self.active = false;
    }

    fn handshake_command(
        &mut self,
        stage: &'static str,
        command: Value,
    ) -> Result<Value, ChatTransportError> {
        self.log(stage, "attempt");
        let result = self.command(command);
        self.log(
            stage,
            result
                .as_ref()
                .map(|_| "ok")
                .unwrap_or_else(|error| diagnostic_error(error)),
        );
        result
    }

    fn command(&mut self, mut command: Value) -> Result<Value, ChatTransportError> {
        let id = format!("ctxql-chat-{}", self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        command
            .as_object_mut()
            .ok_or(ChatTransportError::Protocol)?
            .insert("id".to_owned(), Value::String(id.clone()));
        self.write_record(&command)?;
        let deadline = Instant::now() + self.limits.command_timeout;
        loop {
            let record = self
                .receive_until(deadline)?
                .ok_or(ChatTransportError::Timeout)?;
            if record.get("type").and_then(Value::as_str) == Some("response") {
                if record.get("id").and_then(Value::as_str) != Some(&id) {
                    self.fail_turn(ChatIncompleteReason::Protocol);
                    return Err(ChatTransportError::Protocol);
                }
                if record.get("success").and_then(Value::as_bool) != Some(true) {
                    self.fail_turn(ChatIncompleteReason::ProviderError);
                    return Err(ChatTransportError::Protocol);
                }
                return Ok(record.get("data").cloned().unwrap_or(Value::Null));
            }
            self.process_event(record)?;
        }
    }

    fn write_record(&mut self, value: &Value) -> Result<(), ChatTransportError> {
        let mut bytes = serde_json::to_vec(value).map_err(|_| ChatTransportError::Protocol)?;
        if bytes.len() > self.limits.max_record_bytes {
            return Err(ChatTransportError::Limit("record_bytes"));
        }
        bytes.push(b'\n');
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        self.writer
            .as_ref()
            .ok_or(ChatTransportError::NotRunning)?
            .try_send(WriterRequest { bytes, ack: ack_tx })
            .map_err(|_| ChatTransportError::Io)?;
        ack_rx
            .recv_timeout(self.limits.command_timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => ChatTransportError::Timeout,
                mpsc::RecvTimeoutError::Disconnected => ChatTransportError::Io,
            })?
    }

    fn receive_until(&mut self, deadline: Instant) -> Result<Option<Value>, ChatTransportError> {
        let mut guard = self
            .queue
            .state
            .lock()
            .map_err(|_| ChatTransportError::Io)?;
        loop {
            if let Some(error) = guard.error.clone() {
                return Err(error);
            }
            if let Some((record, bytes)) = guard.records.pop_front() {
                guard.bytes = guard.bytes.saturating_sub(bytes);
                return Ok(Some(record));
            }
            if guard.closed {
                return if self.active {
                    Err(ChatTransportError::Protocol)
                } else {
                    Ok(None)
                };
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(None);
            };
            let (next, result) = self
                .queue
                .ready
                .wait_timeout(guard, remaining)
                .map_err(|_| ChatTransportError::Io)?;
            guard = next;
            if result.timed_out() {
                return Ok(None);
            }
        }
    }

    fn process_event(&mut self, record: Value) -> Result<(), ChatTransportError> {
        self.turn_events = self.turn_events.saturating_add(1);
        if self.active && self.turn_events > self.limits.max_events_per_turn {
            self.fail_turn(ChatIncompleteReason::Limit("events"));
            return Err(ChatTransportError::Limit("events"));
        }
        match record.get("type").and_then(Value::as_str).unwrap_or("") {
            "response" => return Err(ChatTransportError::Protocol),
            "turn_start" => {
                self.turn_usage_pending = true;
                self.process_rounds = self.process_rounds.saturating_add(1);
                if self.process_rounds > self.limits.max_model_rounds_per_process {
                    self.fail_turn(ChatIncompleteReason::Limit("model_rounds"));
                    return Err(ChatTransportError::Limit("model_rounds"));
                }
            }
            "message_start" | "message_end" => {
                let message = record.get("message").ok_or(ChatTransportError::Protocol)?;
                let ending = record.get("type").and_then(Value::as_str) == Some("message_end");
                self.inspect_assistant_message(message, ending)?;
                if ending && message.get("role").and_then(Value::as_str) != Some("user") {
                    self.retain_final_message(message)?;
                }
            }
            "message_update" => self.process_message_update(&record)?,
            "tool_execution_start" => self.process_tool_start(&record)?,
            "agent_settled" => {
                if self.active && !self.cancelling {
                    self.active = false;
                    self.turn_deadline = None;
                    let event = if let Some(reason) = self.terminal_failure.take() {
                        self.mark_usage_unknown_if_pending();
                        ChatEvent::Incomplete {
                            reason,
                            usage: self.usage_status(),
                        }
                    } else if self.turn_completed_assistant && !self.turn_usage_pending {
                        ChatEvent::Settled {
                            usage: self.usage_snapshot_with_current(),
                        }
                    } else {
                        self.log("agent_settled_validation", "missing_complete_usage");
                        self.mark_usage_unknown_if_pending();
                        ChatEvent::Incomplete {
                            reason: ChatIncompleteReason::Protocol,
                            usage: self.usage_status(),
                        }
                    };
                    self.queue_public_event(event)?;
                }
            }
            "compaction_start" | "auto_retry_start" | "summarization_retry_scheduled" => {
                self.fail_turn(ChatIncompleteReason::Protocol);
                return Err(ChatTransportError::Protocol);
            }
            _ => {}
        }
        Ok(())
    }

    fn inspect_assistant_message(
        &mut self,
        message: &Value,
        ending: bool,
    ) -> Result<(), ChatTransportError> {
        if message.get("role").and_then(Value::as_str) != Some("assistant") {
            return Ok(());
        }
        let provider = message.get("provider").and_then(Value::as_str);
        let model = message.get("model").and_then(Value::as_str);
        let response_model = message.get("responseModel").and_then(Value::as_str);
        let provider_thinking = message.get("providerThinkingLevel").and_then(Value::as_str);
        if provider != Some("openrouter")
            || !matches!(model, Some(MODEL | RUNTIME_MODEL))
            || response_model.is_some_and(|reported| reported != RUNTIME_MODEL)
            || provider_thinking.is_some_and(|reported| reported != THINKING)
        {
            self.fail_turn(ChatIncompleteReason::Protocol);
            return Err(ChatTransportError::ModelMismatch);
        }
        let upstream_response_id =
            optional_nonempty_string(message, "responseId").inspect_err(|_| {
                self.log("assistant_identity_validation", "invalid_response_id");
            })?;
        if !ending {
            if self.assistant.is_some() {
                self.log("assistant_sequence_validation", "duplicate_start");
                return Err(ChatTransportError::Protocol);
            }
            self.current_assistant_usage = Usage::default();
            self.assistant_sequence = self.assistant_sequence.saturating_add(1);
            self.assistant = Some(ActiveAssistant {
                identity: AssistantIdentity {
                    message_id: format!("ctxql-assistant-{}", self.assistant_sequence),
                    provider: provider.unwrap_or_default().to_owned(),
                    model: model.unwrap_or_default().to_owned(),
                },
                upstream_response_id,
                text_blocks: BTreeMap::new(),
            });
            if let Some(usage) = message.get("usage") {
                self.update_usage(usage)?;
            }
            return Ok(());
        }

        let Some(active) = self.assistant.as_ref() else {
            self.log("assistant_sequence_validation", "end_without_start");
            return Err(ChatTransportError::Protocol);
        };
        if let (Some(started), Some(ended)) = (
            active.upstream_response_id.as_deref(),
            upstream_response_id.as_deref(),
        ) {
            if started != ended {
                self.log("assistant_identity_validation", "response_id_mismatch");
                return Err(ChatTransportError::Protocol);
            }
        }
        if let Err(error) = validate_final_text(message, active) {
            self.log("assistant_final_text_validation", "stream_mismatch");
            return Err(error);
        }
        let Some(usage) = message.get("usage") else {
            self.log("assistant_usage_validation", "missing_final_usage");
            return Err(ChatTransportError::Protocol);
        };
        let final_usage = parse_final_usage(usage).inspect_err(|_| {
            self.log("assistant_usage_validation", "invalid_final_usage");
        })?;
        self.current_assistant_usage = final_usage;

        let Some(reason) = message.get("stopReason").and_then(Value::as_str) else {
            self.log("assistant_stop_validation", "missing_stop_reason");
            return Err(ChatTransportError::Protocol);
        };
        self.terminal_failure = match reason {
            "error" | "aborted" | "deferred" => Some(ChatIncompleteReason::ProviderError),
            "length" => Some(ChatIncompleteReason::ContextLimit),
            "stop" | "toolUse" => self.terminal_failure.take(),
            _ => {
                self.log("assistant_stop_validation", "unknown_stop_reason");
                return Err(ChatTransportError::Protocol);
            }
        };
        self.turn_completed_assistant = reason != "toolUse";
        add_usage(&mut self.usage, &self.current_assistant_usage);
        self.usage.requests = self.usage.requests.saturating_add(1);
        self.current_assistant_usage = Usage::default();
        self.turn_usage_pending = false;
        self.assistant = None;
        if let Err(ChatTransportError::Limit(name)) = self.check_usage_limits() {
            self.fail_turn(ChatIncompleteReason::Limit(name));
            return Err(ChatTransportError::Limit(name));
        }
        self.queue_public_event(ChatEvent::Usage {
            snapshot: self.usage_snapshot_with_current(),
        })?;
        Ok(())
    }

    fn retain_final_message(&mut self, message: &Value) -> Result<(), ChatTransportError> {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .ok_or(ChatTransportError::Protocol)?;
        let content = message.get("content").ok_or(ChatTransportError::Protocol)?;
        let bytes = retained_message_bytes(role, content)?;
        self.retain_conversation_bytes(bytes)
    }

    fn retain_conversation_bytes(&mut self, bytes: usize) -> Result<(), ChatTransportError> {
        self.conversation_bytes = self.conversation_bytes.saturating_add(bytes);
        if self.conversation_bytes > self.limits.max_conversation_bytes {
            self.fail_turn(ChatIncompleteReason::Limit("conversation_bytes"));
            return Err(ChatTransportError::Limit("conversation_bytes"));
        }
        Ok(())
    }

    fn process_message_update(&mut self, record: &Value) -> Result<(), ChatTransportError> {
        if self.assistant.is_none() {
            return Err(ChatTransportError::Protocol);
        }
        if let Some(usage) = record.get("usage") {
            self.update_usage(usage)?;
        }
        let update = record
            .get("assistantMessageEvent")
            .ok_or(ChatTransportError::Protocol)?;
        let update_type = update
            .get("type")
            .and_then(Value::as_str)
            .ok_or(ChatTransportError::Protocol)?;
        if !matches!(update_type, "text_start" | "text_delta" | "text_end") {
            return Ok(());
        }
        let content_index = update
            .get("contentIndex")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(ChatTransportError::Protocol)?;
        match update_type {
            "text_start" => {
                let active = self
                    .assistant
                    .as_mut()
                    .ok_or(ChatTransportError::Protocol)?;
                if active
                    .text_blocks
                    .insert(
                        content_index,
                        StreamedTextBlock {
                            text: String::new(),
                            finalized: false,
                        },
                    )
                    .is_some()
                {
                    return Err(ChatTransportError::Protocol);
                }
            }
            "text_delta" => {
                let delta = update
                    .get("delta")
                    .and_then(Value::as_str)
                    .ok_or(ChatTransportError::Protocol)?;
                self.turn_answer_bytes = self.turn_answer_bytes.saturating_add(delta.len());
                if self.turn_answer_bytes > self.limits.max_answer_bytes_per_turn {
                    self.fail_turn(ChatIncompleteReason::Limit("answer_bytes"));
                    return Err(ChatTransportError::Limit("answer_bytes"));
                }
                let active = self
                    .assistant
                    .as_mut()
                    .ok_or(ChatTransportError::Protocol)?;
                let block = active
                    .text_blocks
                    .get_mut(&content_index)
                    .ok_or(ChatTransportError::Protocol)?;
                if block.finalized {
                    return Err(ChatTransportError::Protocol);
                }
                block.text.push_str(delta);
                let identity = active.identity.clone();
                self.queue_public_event(ChatEvent::TextDelta {
                    identity,
                    content_index,
                    delta: delta.to_owned(),
                })?;
            }
            "text_end" => {
                let content = update
                    .get("content")
                    .and_then(Value::as_str)
                    .ok_or(ChatTransportError::Protocol)?;
                let active = self
                    .assistant
                    .as_mut()
                    .ok_or(ChatTransportError::Protocol)?;
                let block = active
                    .text_blocks
                    .get_mut(&content_index)
                    .ok_or(ChatTransportError::Protocol)?;
                if block.finalized || block.text != content {
                    return Err(ChatTransportError::Protocol);
                }
                block.finalized = true;
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn process_tool_start(&mut self, record: &Value) -> Result<(), ChatTransportError> {
        self.turn_tools = self.turn_tools.saturating_add(1);
        self.process_tools = self.process_tools.saturating_add(1);
        if self.turn_tools > self.limits.max_tool_calls_per_turn
            || self.process_tools > self.limits.max_tool_calls_per_process
        {
            self.fail_turn(ChatIncompleteReason::Limit("tool_calls"));
            return Err(ChatTransportError::Limit("tool_calls"));
        }
        let tool_name = record
            .get("toolName")
            .and_then(Value::as_str)
            .ok_or(ChatTransportError::Protocol)?;
        if tool_name == "ctxql_graph_query" {
            self.turn_queries = self.turn_queries.saturating_add(1);
            self.process_queries = self.process_queries.saturating_add(1);
            if self.turn_queries > self.limits.max_queries_per_turn
                || self.process_queries > self.limits.max_queries_per_process
            {
                self.fail_turn(ChatIncompleteReason::Limit("queries"));
                return Err(ChatTransportError::Limit("queries"));
            }
        }
        if !matches!(
            tool_name,
            "ctxql_capabilities" | "ctxql_ontology" | "ctxql_graph_query" | "ctxql_source"
        ) {
            self.fail_turn(ChatIncompleteReason::Protocol);
            return Err(ChatTransportError::ResourceMismatch);
        }
        self.queue_public_event(ChatEvent::Progress {
            tool_name: tool_name.to_owned(),
        })?;
        Ok(())
    }

    fn update_usage(&mut self, value: &Value) -> Result<(), ChatTransportError> {
        let partial = parse_partial_usage(value)?;
        // Provider streaming snapshots are cumulative for this response. A
        // partial update can omit fields; only present validated fields replace
        // earlier values. The authoritative final message replaces all of it.
        if let Some(value) = partial.input_tokens {
            self.current_assistant_usage.input_tokens = value;
        }
        if let Some(value) = partial.output_tokens {
            self.current_assistant_usage.output_tokens = value;
        }
        if let Some(value) = partial.cache_read_tokens {
            self.current_assistant_usage.cache_read_tokens = value;
        }
        if let Some(value) = partial.cache_write_tokens {
            self.current_assistant_usage.cache_write_tokens = value;
        }
        if let Some(value) = partial.cost_microusd {
            self.current_assistant_usage.cost_microusd = value;
        }
        if let Err(ChatTransportError::Limit(name)) = self.check_usage_limits() {
            self.fail_turn(ChatIncompleteReason::Limit(name));
            return Err(ChatTransportError::Limit(name));
        }
        // Intermediate provider usage is provisional and can be partial. It is
        // enforced internally but is not published as authoritative accounting.
        Ok(())
    }

    fn usage_status(&self) -> UsageStatus {
        if self.usage_unknown || self.turn_usage_pending {
            UsageStatus::Unknown
        } else {
            UsageStatus::Known(self.usage_snapshot_with_current())
        }
    }

    fn mark_usage_unknown_if_pending(&mut self) {
        if self.turn_usage_pending {
            self.usage_unknown = true;
        }
    }

    fn usage_snapshot_with_current(&self) -> Usage {
        Usage {
            input_tokens: self
                .usage
                .input_tokens
                .saturating_add(self.current_assistant_usage.input_tokens),
            output_tokens: self
                .usage
                .output_tokens
                .saturating_add(self.current_assistant_usage.output_tokens),
            cache_read_tokens: self
                .usage
                .cache_read_tokens
                .saturating_add(self.current_assistant_usage.cache_read_tokens),
            cache_write_tokens: self
                .usage
                .cache_write_tokens
                .saturating_add(self.current_assistant_usage.cache_write_tokens),
            cost_microusd: self
                .usage
                .cost_microusd
                .saturating_add(self.current_assistant_usage.cost_microusd),
            requests: self.usage.requests,
        }
    }

    fn check_usage_limits(&self) -> Result<(), ChatTransportError> {
        if self.usage_unknown {
            return Err(ChatTransportError::Limit("usage_unknown"));
        }
        let usage = self.usage_snapshot_with_current();
        if usage
            .input_tokens
            .saturating_add(usage.output_tokens)
            .saturating_add(usage.cache_read_tokens)
            .saturating_add(usage.cache_write_tokens)
            > self.limits.max_total_tokens
        {
            return Err(ChatTransportError::Limit("tokens"));
        }
        if usage.cost_microusd > self.limits.max_cost_microusd {
            return Err(ChatTransportError::Limit("cost"));
        }
        Ok(())
    }

    fn verify_state(&self, state: &Value) -> Result<(), ChatTransportError> {
        let model = state
            .get("model")
            .ok_or(ChatTransportError::ModelMismatch)?;
        if model.get("provider").and_then(Value::as_str) != Some("openrouter")
            || model.get("id").and_then(Value::as_str) != Some(RUNTIME_MODEL)
            || state.get("thinkingLevel").and_then(Value::as_str) != Some(THINKING)
        {
            return Err(ChatTransportError::ModelMismatch);
        }
        self.verify_idle_state(state)?;
        let session_file = state.get("sessionFile");
        if let Some(log) = &self.process_log {
            if let Some(value) = session_file.filter(|value| !value.is_null()) {
                let path = value
                    .as_str()
                    .map(Path::new)
                    .filter(|path| log.owns_session_file(path))
                    .ok_or(ChatTransportError::ResourceMismatch)?;
                debug_assert!(path.is_absolute());
            }
        } else if session_file.is_some_and(|value| !value.is_null()) {
            return Err(ChatTransportError::ResourceMismatch);
        }
        Ok(())
    }

    fn verify_idle_state(&self, state: &Value) -> Result<(), ChatTransportError> {
        if state.get("isStreaming").and_then(Value::as_bool) != Some(false)
            || state.get("pendingMessageCount").and_then(Value::as_u64) != Some(0)
        {
            return Err(ChatTransportError::Protocol);
        }
        Ok(())
    }

    fn queue_public_event(&mut self, event: ChatEvent) -> Result<(), ChatTransportError> {
        let bytes = event_size(&event);
        if self.public_events.len() >= self.limits.max_events_per_turn
            || self.public_event_bytes.saturating_add(bytes) > self.limits.max_queued_bytes
        {
            self.fail_turn(ChatIncompleteReason::Limit("event_queue"));
            return Err(ChatTransportError::Limit("event_queue"));
        }
        self.public_event_bytes += bytes;
        self.public_events.push_back(event);
        Ok(())
    }

    fn pop_public_event(&mut self) -> Option<ChatEvent> {
        let event = self.public_events.pop_front()?;
        self.public_event_bytes = self.public_event_bytes.saturating_sub(event_size(&event));
        Some(event)
    }

    fn fail_turn(&mut self, reason: ChatIncompleteReason) {
        if self.active {
            self.terminal_failure = Some(reason);
        }
    }

    fn force_close(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.closed = true;
        self.active = false;
        self.writer.take();
    }
}

struct WriterRequest {
    bytes: Vec<u8>,
    ack: mpsc::SyncSender<Result<(), ChatTransportError>>,
}

fn spawn_writer(
    mut stdin: impl Write + Send + 'static,
    requests: mpsc::Receiver<WriterRequest>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        while let Ok(request) = requests.recv() {
            let result = stdin
                .write_all(&request.bytes)
                .and_then(|_| stdin.flush())
                .map_err(|_| ChatTransportError::Io);
            let failed = result.is_err();
            let _ = request.ack.send(result);
            if failed {
                break;
            }
        }
    })
}

impl Drop for ChatTransport {
    fn drop(&mut self) {
        self.close();
    }
}

fn verify_executable_version(
    command: &Path,
    timeout: Duration,
    max_bytes: usize,
) -> Result<(), ChatTransportError> {
    let mut child = Command::new(command)
        .arg("--version")
        .env_clear()
        .env("PATH", safe_execution_path(command))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ChatTransportError::Spawn)?;
    let mut stdout = child.stdout.take().ok_or(ChatTransportError::Spawn)?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .by_ref()
            .take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(ChatTransportError::Timeout);
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| ChatTransportError::Io)?
        .map_err(|_| ChatTransportError::Io)?;
    if !status.success()
        || bytes.len() > max_bytes
        || std::str::from_utf8(&bytes).map(str::trim).ok() != Some(SUPPORTED_PI_VERSION)
    {
        return Err(ChatTransportError::ResourceMismatch);
    }
    Ok(())
}

fn is_expected_inline_command(command: &Value) -> bool {
    command.get("name").and_then(Value::as_str) == Some("llama")
        && command.get("source").and_then(Value::as_str) == Some("extension")
        && command
            .get("sourceInfo")
            .and_then(|info| info.get("path"))
            .and_then(Value::as_str)
            == Some("<inline:llama.cpp>")
        && command
            .get("sourceInfo")
            .and_then(|info| info.get("source"))
            .and_then(Value::as_str)
            == Some("inline")
}

fn safe_execution_path(command: &Path) -> std::ffi::OsString {
    let mut paths = command
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .into_iter()
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    paths.extend([PathBuf::from("/usr/bin"), PathBuf::from("/bin")]);
    std::env::join_paths(paths).unwrap_or_else(|_| std::ffi::OsString::from("/usr/bin:/bin"))
}

fn validate_config(config: &ChatTransportConfig) -> Result<(), ChatTransportError> {
    let limits = &config.limits;
    let valid = config.bundle.profile() == BundleProfile::Chat
        && config.bundle.manifest.model == MODEL
        && config.bundle.manifest.thinking == THINKING
        && !config.system_prompt.is_empty()
        && !limits.command_timeout.is_zero()
        && !limits.turn_timeout.is_zero()
        && !limits.shutdown_grace.is_zero()
        && limits.max_prompt_bytes > 0
        && limits.max_record_bytes > 0
        && limits.max_queued_bytes >= limits.max_record_bytes
        && limits.max_events_per_turn > 0
        && limits.max_answer_bytes_per_turn > 0
        && limits.max_conversation_bytes > 0
        && limits.max_tool_calls_per_turn > 0
        && limits.max_tool_calls_per_process >= limits.max_tool_calls_per_turn
        && limits.max_queries_per_turn > 0
        && limits.max_queries_per_process >= limits.max_queries_per_turn
        && limits.max_user_turns_per_process > 0
        && limits.max_model_rounds_per_process > 0
        && limits.max_total_tokens > 0
        && limits.max_cost_microusd > 0
        && limits.max_stderr_bytes > 0
        && config
            .session_logging
            .as_ref()
            .is_none_or(|logging| logging.root.is_absolute());
    if !valid {
        return Err(ChatTransportError::InvalidConfig);
    }
    for (key, _) in &config.environment {
        if key.is_empty()
            || matches!(
                key.as_str(),
                "HOME"
                    | "PI_CODING_AGENT_DIR"
                    | "PI_CODING_AGENT_SESSION_DIR"
                    | "CDB_CONFIG"
                    | "CDB_TOKEN_FILE"
                    | "CTXQL_ONTOLOGY_SOCKET"
                    | "CTXQL_ONTOLOGY_TOKEN"
                    | "CTXQL_PI_PROFILE"
                    | "CTXQL_PI_BUNDLE_HASH"
            )
        {
            return Err(ChatTransportError::InvalidConfig);
        }
    }
    Ok(())
}

fn create_private_root() -> Result<PrivateRoot, ChatTransportError> {
    let sequence = ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ChatTransportError::Io)?
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ctxql-pi-chat-{}-{sequence}-{now}",
        std::process::id()
    ));
    fs::create_dir(&root).map_err(|_| ChatTransportError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|_| ChatTransportError::Io)?;
    }
    fs::create_dir(root.join("agent")).map_err(|_| ChatTransportError::Io)?;
    fs::create_dir(root.join("sessions")).map_err(|_| ChatTransportError::Io)?;
    Ok(PrivateRoot(root))
}

fn spawn_stdout_reader(
    stdout: impl Read + Send + 'static,
    queue: Arc<SharedQueue>,
    max_record_bytes: usize,
    max_queued_bytes: usize,
    max_queued_records: usize,
    process_log: Option<Arc<ProcessLog>>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = stdout;
        let mut pending = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => {
                    let mut state = queue.state.lock().unwrap();
                    if !pending.is_empty() {
                        if let Some(log) = &process_log {
                            log.record("rpc_framing", "truncated_record");
                        }
                        state.error = Some(ChatTransportError::Protocol);
                    }
                    state.closed = true;
                    queue.ready.notify_all();
                    break;
                }
                Ok(count) => {
                    pending.extend_from_slice(&chunk[..count]);
                    loop {
                        let Some(index) = pending.iter().position(|byte| *byte == b'\n') else {
                            if pending.len() > max_record_bytes {
                                if let Some(log) = &process_log {
                                    log.record("rpc_framing", "record_too_large");
                                }
                                set_queue_error(&queue, ChatTransportError::Limit("record_bytes"));
                                return;
                            }
                            break;
                        };
                        let mut record: Vec<u8> = pending.drain(..=index).collect();
                        record.pop();
                        if record.last() == Some(&b'\r') {
                            record.pop();
                        }
                        if record.is_empty() || record.len() > max_record_bytes {
                            if let Some(log) = &process_log {
                                log.record("rpc_framing", "invalid_record_size");
                            }
                            set_queue_error(&queue, ChatTransportError::Protocol);
                            return;
                        }
                        if std::str::from_utf8(&record).is_err()
                            || cdb_core::CanonicalValue::parse(&record, cdb_core::Limits::default())
                                .is_err()
                        {
                            if let Some(log) = &process_log {
                                log.record("rpc_framing", "invalid_canonical_json");
                            }
                            set_queue_error(&queue, ChatTransportError::Protocol);
                            return;
                        }
                        let Ok(value) = serde_json::from_slice::<Value>(&record) else {
                            if let Some(log) = &process_log {
                                log.record("rpc_framing", "invalid_json");
                            }
                            set_queue_error(&queue, ChatTransportError::Protocol);
                            return;
                        };
                        if !value.is_object() {
                            if let Some(log) = &process_log {
                                log.record("rpc_framing", "non_object_record");
                            }
                            set_queue_error(&queue, ChatTransportError::Protocol);
                            return;
                        }
                        let bytes = record.len() + 1;
                        let mut state = queue.state.lock().unwrap();
                        if state.bytes.saturating_add(bytes) > max_queued_bytes
                            || state.records.len() >= max_queued_records
                        {
                            if let Some(log) = &process_log {
                                log.record("rpc_framing", "event_queue_limit");
                            }
                            state.error = Some(ChatTransportError::Limit("event_queue"));
                            state.closed = true;
                            queue.ready.notify_all();
                            return;
                        }
                        state.bytes += bytes;
                        state.records.push_back((value, bytes));
                        queue.ready.notify_all();
                    }
                }
                Err(_) => {
                    if let Some(log) = &process_log {
                        log.record("rpc_framing", "read_io_error");
                    }
                    set_queue_error(&queue, ChatTransportError::Io);
                    break;
                }
            }
        }
    })
}

fn set_queue_error(queue: &SharedQueue, error: ChatTransportError) {
    if let Ok(mut state) = queue.state.lock() {
        state.error = Some(error);
        state.closed = true;
        queue.ready.notify_all();
    }
}

fn spawn_stderr_reader(
    mut stderr: impl Read + Send + 'static,
    max: usize,
    process_log: Option<Arc<ProcessLog>>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut consumed = 0usize;
        let mut observed = false;
        let mut buffer = [0u8; 4096];
        loop {
            match stderr.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    if !observed {
                        if let Some(log) = &process_log {
                            log.record("provider_stderr", "observed");
                        }
                        observed = true;
                    }
                    consumed = consumed.saturating_add(count);
                    // Continue draining after the diagnostic retention ceiling. Raw
                    // stderr is intentionally neither retained nor exposed.
                    if consumed > max {
                        consumed = max;
                    }
                }
            }
        }
    })
}

fn diagnostic_event_kind(record: &Value) -> &'static str {
    match record.get("type").and_then(Value::as_str) {
        Some("response") => "rpc_response",
        Some("turn_start") => "turn_start",
        Some("message_start") => "message_start",
        Some("message_update") => "message_update",
        Some("message_end") => "message_end",
        Some("tool_execution_start") => "tool_execution_start",
        Some("tool_execution_end") => "tool_execution_end",
        Some("agent_start") => "agent_start",
        Some("agent_end") => "agent_end",
        Some("agent_settled") => "agent_settled",
        Some("auto_retry_start") => "auto_retry_start",
        Some("compaction_start") => "compaction_start",
        Some("summarization_retry_scheduled") => "summarization_retry_scheduled",
        _ => "unknown_rpc_record",
    }
}

fn diagnostic_error(error: &ChatTransportError) -> &'static str {
    match error {
        ChatTransportError::InvalidConfig => "rejected_invalid_config",
        ChatTransportError::Spawn => "rejected_spawn",
        ChatTransportError::Io => "rejected_io",
        ChatTransportError::Protocol => "rejected_protocol",
        ChatTransportError::Timeout => "rejected_timeout",
        ChatTransportError::Busy => "rejected_busy",
        ChatTransportError::NotRunning => "rejected_not_running",
        ChatTransportError::ModelMismatch => "rejected_model_mismatch",
        ChatTransportError::ResourceMismatch => "rejected_resource_mismatch",
        ChatTransportError::Limit(_) => "rejected_limit",
    }
}

fn event_size(event: &ChatEvent) -> usize {
    match event {
        ChatEvent::TextDelta {
            identity, delta, ..
        } => {
            identity.message_id.len()
                + identity.provider.len()
                + identity.model.len()
                + delta.len()
                + 64
        }
        ChatEvent::Progress { tool_name } => tool_name.len() + 32,
        ChatEvent::Usage { .. } | ChatEvent::Settled { .. } | ChatEvent::Incomplete { .. } => 96,
    }
}

#[derive(Default)]
struct PartialUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cache_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
    cost_microusd: Option<u64>,
}

fn optional_nonempty_string(
    value: &Value,
    key: &str,
) -> Result<Option<String>, ChatTransportError> {
    let Some(raw) = value.get(key) else {
        return Ok(None);
    };
    let text = raw.as_str().ok_or(ChatTransportError::Protocol)?;
    if text.is_empty() {
        return Err(ChatTransportError::Protocol);
    }
    Ok(Some(text.to_owned()))
}

fn parse_optional_u64(value: &Value, key: &str) -> Result<Option<u64>, ChatTransportError> {
    value
        .get(key)
        .map(|number| number.as_u64().ok_or(ChatTransportError::Protocol))
        .transpose()
}

fn parse_cost_microusd(value: &Value) -> Result<u64, ChatTransportError> {
    let dollars = value.as_f64().ok_or(ChatTransportError::Protocol)?;
    let microusd = dollars * 1_000_000.0;
    if !dollars.is_finite() || dollars < 0.0 || !microusd.is_finite() || microusd > u64::MAX as f64
    {
        return Err(ChatTransportError::Protocol);
    }
    Ok(microusd.round() as u64)
}

fn validate_cost_fields(cost: &Value, require_all: bool) -> Result<(), ChatTransportError> {
    let object = cost.as_object().ok_or(ChatTransportError::Protocol)?;
    for key in ["input", "output", "cacheRead", "cacheWrite", "total"] {
        match object.get(key) {
            Some(value) => {
                parse_cost_microusd(value)?;
            }
            None if require_all => return Err(ChatTransportError::Protocol),
            None => {}
        }
    }
    Ok(())
}

fn parse_partial_usage(value: &Value) -> Result<PartialUsage, ChatTransportError> {
    if !value.is_object() {
        return Err(ChatTransportError::Protocol);
    }
    for key in ["totalTokens", "reasoning", "cacheWrite1h"] {
        parse_optional_u64(value, key)?;
    }
    let cost_microusd = match value.get("cost") {
        Some(cost) => {
            validate_cost_fields(cost, false)?;
            cost.get("total").map(parse_cost_microusd).transpose()?
        }
        None => None,
    };
    Ok(PartialUsage {
        input_tokens: parse_optional_u64(value, "input")?,
        output_tokens: parse_optional_u64(value, "output")?,
        cache_read_tokens: parse_optional_u64(value, "cacheRead")?,
        cache_write_tokens: parse_optional_u64(value, "cacheWrite")?,
        cost_microusd,
    })
}

fn parse_final_usage(value: &Value) -> Result<Usage, ChatTransportError> {
    let partial = parse_partial_usage(value)?;
    parse_optional_u64(value, "totalTokens")?.ok_or(ChatTransportError::Protocol)?;
    let cost = value.get("cost").ok_or(ChatTransportError::Protocol)?;
    validate_cost_fields(cost, true)?;
    Ok(Usage {
        input_tokens: partial.input_tokens.ok_or(ChatTransportError::Protocol)?,
        output_tokens: partial.output_tokens.ok_or(ChatTransportError::Protocol)?,
        cache_read_tokens: partial
            .cache_read_tokens
            .ok_or(ChatTransportError::Protocol)?,
        cache_write_tokens: partial
            .cache_write_tokens
            .ok_or(ChatTransportError::Protocol)?,
        cost_microusd: partial.cost_microusd.ok_or(ChatTransportError::Protocol)?,
        requests: 0,
    })
}

fn add_usage(total: &mut Usage, response: &Usage) {
    total.input_tokens = total.input_tokens.saturating_add(response.input_tokens);
    total.output_tokens = total.output_tokens.saturating_add(response.output_tokens);
    total.cache_read_tokens = total
        .cache_read_tokens
        .saturating_add(response.cache_read_tokens);
    total.cache_write_tokens = total
        .cache_write_tokens
        .saturating_add(response.cache_write_tokens);
    total.cost_microusd = total.cost_microusd.saturating_add(response.cost_microusd);
}

fn validate_final_text(
    message: &Value,
    active: &ActiveAssistant,
) -> Result<(), ChatTransportError> {
    let content = message
        .get("content")
        .and_then(Value::as_array)
        .ok_or(ChatTransportError::Protocol)?;
    let mut final_text_blocks = 0usize;
    for (index, block) in content.iter().enumerate() {
        if block.get("type").and_then(Value::as_str) != Some("text") {
            continue;
        }
        final_text_blocks = final_text_blocks.saturating_add(1);
        let final_text = block
            .get("text")
            .and_then(Value::as_str)
            .ok_or(ChatTransportError::Protocol)?;
        let streamed = active
            .text_blocks
            .get(&index)
            .ok_or(ChatTransportError::Protocol)?;
        if !streamed.finalized || streamed.text != final_text {
            return Err(ChatTransportError::Protocol);
        }
    }
    if final_text_blocks != active.text_blocks.len() {
        return Err(ChatTransportError::Protocol);
    }
    Ok(())
}

fn retained_message_bytes(role: &str, content: &Value) -> Result<usize, ChatTransportError> {
    serde_json::to_vec(&json!({"role": role, "content": content}))
        .map(|bytes| bytes.len())
        .map_err(|_| ChatTransportError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_sensitive_environment_is_not_accepted_as_explicit_configuration() {
        let assets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/pi");
        let bundle =
            crate::agent_bundle::hash_agent_bundle_for_profile(assets, BundleProfile::Chat)
                .unwrap();
        struct Host;
        impl crate::ontology_bridge::OntologyToolHost for Host {
            fn lookup(
                &self,
                _: &Value,
            ) -> Result<Value, crate::ontology_bridge::OntologyToolError> {
                Err(crate::ontology_bridge::OntologyToolError::Denied)
            }
        }
        let config = ChatTransportConfig {
            command: PathBuf::from("pi"),
            environment: vec![("CDB_TOKEN_FILE".into(), "secret-path".into())],
            system_prompt: bundle.chat_system_prompt().unwrap(),
            bundle,
            ontology_bridge: OntologyBridgeConfig {
                host: Arc::new(Host),
                max_request_bytes: 32 * 1024,
                max_response_bytes: 64 * 1024,
            },
            limits: ChatTransportLimits::default(),
            session_logging: None,
        };
        assert_eq!(
            validate_config(&config),
            Err(ChatTransportError::InvalidConfig)
        );
    }
}
