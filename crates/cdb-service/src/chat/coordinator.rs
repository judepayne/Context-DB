use super::{bridge::ChatToolHost, terminal::*, ChatReadResources};
use crate::config::{ChatConfig, ChatLimits, InstanceConfig};
use cdb_core::{Error, ErrorKind, Result};
use cdb_provider_pi::{
    agent_bundle::{hash_agent_bundle_for_profile, BundleProfile},
    chat_transport::{
        ChatEvent, ChatIncompleteReason, ChatTransport, ChatTransportConfig, ChatTransportError,
        ChatTransportLimits, UsageStatus,
    },
    ontology_bridge::OntologyBridgeConfig,
};
use std::{
    collections::BTreeSet,
    io::{self, BufReader, IsTerminal, Write},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError},
        Arc,
    },
    time::Duration,
};

#[derive(Debug)]
enum TerminalEvent {
    Input(InputEvent),
    BusyQuestion,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PriorityControl {
    None = 0,
    Clear = 1,
    Interrupt = 2,
    Close = 3,
}

#[derive(Debug, Default)]
struct ControlState(AtomicU8);

impl ControlState {
    fn request(&self, requested: PriorityControl) {
        let requested = requested as u8;
        let mut current = self.0.load(Ordering::Acquire);
        while current < requested {
            match self.0.compare_exchange_weak(
                current,
                requested,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    fn take(&self) -> PriorityControl {
        match self.0.swap(PriorityControl::None as u8, Ordering::AcqRel) {
            1 => PriorityControl::Clear,
            2 => PriorityControl::Interrupt,
            3 => PriorityControl::Close,
            _ => PriorityControl::None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionState {
    Starting,
    Idle,
    Running,
    Cancelling,
    Closing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunningAction {
    Continue,
    Cancel,
    Clear,
    Close,
}

/// Run one ephemeral terminal chat. Protected read resources are authenticated
/// and prepared before Pi is started; the blocking transport never occupies a
/// Tokio executor worker.
pub async fn run_chat(config: InstanceConfig, token: String) -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(Error::invalid(
            "chat requires interactive terminal stdin and stdout",
        ));
    }
    let chat = config
        .chat
        .clone()
        .ok_or_else(|| Error::invalid("chat configuration required"))?;
    let reads = ChatReadResources::open(config, token).await?;
    let runtime = tokio::runtime::Handle::current();
    let (tx, rx) = mpsc::sync_channel(16);
    let busy = Arc::new(AtomicBool::new(false));
    let control = Arc::new(ControlState::default());
    spawn_input(
        tx,
        busy.clone(),
        control.clone(),
        chat.limits.max_input_bytes,
    );

    let worker_control = control.clone();
    let worker = tokio::task::spawn_blocking(move || {
        run_blocking(chat, reads, runtime, rx, busy, worker_control)
    });
    tokio::pin!(worker);
    loop {
        tokio::select! {
            result = &mut worker => {
                return result.map_err(|_| Error::new(ErrorKind::Backend, "chat worker failed"))?;
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_err() {
                    return Err(Error::new(ErrorKind::Backend, "terminal signal unavailable"));
                }
                control.request(PriorityControl::Interrupt);
            }
        }
    }
}

fn spawn_input(
    tx: SyncSender<TerminalEvent>,
    busy: Arc<AtomicBool>,
    control: Arc<ControlState>,
    limit: usize,
) {
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        loop {
            let event = match read_line(&mut reader, limit) {
                Ok(event) => event,
                Err(_) => InputEvent::End,
            };
            match &event {
                InputEvent::End => {
                    control.request(PriorityControl::Close);
                    break;
                }
                InputEvent::Line(line) if line.trim().eq_ignore_ascii_case("quit") => {
                    control.request(PriorityControl::Close);
                    break;
                }
                InputEvent::Line(line)
                    if busy.load(Ordering::Acquire)
                        && line.trim().eq_ignore_ascii_case("/clear") =>
                {
                    control.request(PriorityControl::Clear);
                    continue;
                }
                _ => {}
            }
            let classified = match &event {
                InputEvent::Line(line)
                    if busy.load(Ordering::Acquire)
                        && !line.trim().is_empty()
                        && !is_busy_local(line) =>
                {
                    TerminalEvent::BusyQuestion
                }
                _ => TerminalEvent::Input(event),
            };
            match tx.try_send(classified) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => break,
            }
        }
    });
}

fn run_blocking(
    chat: ChatConfig,
    reads: Arc<ChatReadResources>,
    runtime: tokio::runtime::Handle,
    input: Receiver<TerminalEvent>,
    busy: Arc<AtomicBool>,
    control: Arc<ControlState>,
) -> Result<()> {
    let mut state = SessionState::Starting;
    let bundle = hash_agent_bundle_for_profile(&chat.pi_bundle, BundleProfile::Chat)
        .map_err(|_| Error::invalid("verified chat bundle unavailable"))?;
    let prompt = bundle
        .chat_system_prompt()
        .map_err(|_| Error::invalid("verified chat prompt unavailable"))?;
    let host = Arc::new(ChatToolHost::new(
        reads.clone(),
        runtime,
        chat.limits.max_tool_calls,
    ));
    let limits = transport_limits(&chat.limits)?;
    let environment = ["PATH", "OPENROUTER_API_KEY"]
        .into_iter()
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| (name.to_owned(), value))
        })
        .collect();
    let mut transport = ChatTransport::start(ChatTransportConfig {
        command: chat.pi_command.clone(),
        environment,
        system_prompt: prompt,
        bundle,
        ontology_bridge: OntologyBridgeConfig {
            host: host.clone(),
            max_request_bytes: chat.limits.max_request_bytes,
            max_response_bytes: chat.limits.max_response_bytes,
        },
        limits,
        session_logging: chat
            .pi_session_log_dir
            .clone()
            .map(|root| cdb_provider_pi::SessionLogging { root }),
    })
    .map_err(|_| Error::new(ErrorKind::Backend, "chat provider unavailable"))?;

    let ontology = if chat.ontology.is_some() {
        "verified public ontology"
    } else {
        "ontology unavailable (untyped queries supported)"
    };
    if chat.unsafe_direct_projection {
        output("\nWARNING: UNSAFE DIRECT PROJECTION MODE ENABLED\nGraph-data permissions are bypassed. Queries read the latest completed redb projection, which may lag Fluree; source reads remain protected.\n\n")?;
    }
    if let Some(path) = transport.diagnostic_path() {
        output(&format!(
            "WARNING: Pi session logging enabled. Logs may contain prompts, reasoning, tool data, and source text.\nHost diagnostics: {}\n\n",
            path.display()
        ))?;
    }
    let session_status = if transport.diagnostic_path().is_some() {
        "native Pi session logging enabled"
    } else {
        "session not saved"
    };
    output(&format!(
        "Context DB chat — read-only; {session_status}. Type quit to exit.\nModel: {}; thinking: {}; {}. Results are bounded.\n",
        chat.chat_model, chat.thinking, ontology
    ))?;
    debug_assert_eq!(state, SessionState::Starting);
    state = SessionState::Idle;
    let mut accepted_turns = 0usize;
    let mut answer = String::new();
    let mut sanitizer = Sanitizer::default();
    output(&session_cost_line(&transport.usage_snapshot()))?;
    show_prompt()?;

    loop {
        match state {
            SessionState::Idle => {
                match control.take() {
                    PriorityControl::Close | PriorityControl::Interrupt => {
                        state = SessionState::Closing;
                        continue;
                    }
                    PriorityControl::Clear => {
                        clear_context(&mut transport, &reads)?;
                        show_prompt()?;
                        continue;
                    }
                    PriorityControl::None => {}
                }
                match input.recv_timeout(Duration::from_millis(25)) {
                    Ok(event) => handle_idle(
                        event,
                        &mut transport,
                        &host,
                        &reads,
                        &chat.limits,
                        &mut state,
                        &mut accepted_turns,
                        &mut answer,
                        &busy,
                    )?,
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => state = SessionState::Closing,
                }
            }
            SessionState::Running => {
                let mut action = match control.take() {
                    PriorityControl::None => RunningAction::Continue,
                    PriorityControl::Clear => RunningAction::Clear,
                    PriorityControl::Interrupt => RunningAction::Cancel,
                    PriorityControl::Close => RunningAction::Close,
                };
                while action == RunningAction::Continue {
                    match input.try_recv() {
                        Ok(event) => action = handle_running_input(event, &reads)?,
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            action = RunningAction::Close;
                            break;
                        }
                    }
                }
                if action != RunningAction::Continue {
                    state = SessionState::Cancelling;
                    debug_assert_eq!(state, SessionState::Cancelling);
                    host.cancel_all();
                    let cancellation = transport.cancel();
                    finish_answer(&answer, &reads, true)?;
                    answer.clear();
                    sanitizer = Sanitizer::default();
                    if cancellation.is_err()
                        || discard_cancel_completion(
                            &mut transport,
                            chat.limits.max_rpc_events_per_turn,
                        )
                        .is_err()
                    {
                        output(&session_cost_line(&transport.usage_snapshot()))?;
                        transport.close();
                        busy.store(false, Ordering::Release);
                        return Err(Error::new(
                            ErrorKind::Backend,
                            "chat cancellation could not confirm provider idle",
                        ));
                    }
                    match action {
                        RunningAction::Cancel => {
                            output(&session_cost_line(&transport.usage_snapshot()))?;
                            state = SessionState::Idle;
                            busy.store(false, Ordering::Release);
                            show_prompt()?;
                        }
                        RunningAction::Clear => {
                            clear_context(&mut transport, &reads)?;
                            state = SessionState::Idle;
                            busy.store(false, Ordering::Release);
                            show_prompt()?;
                        }
                        RunningAction::Close => {
                            output(&session_cost_line(&transport.usage_snapshot()))?;
                            busy.store(false, Ordering::Release);
                            state = SessionState::Closing;
                        }
                        RunningAction::Continue => unreachable!(),
                    }
                    continue;
                }

                match transport.poll_event(Duration::from_millis(25)) {
                    Ok(Some(ChatEvent::TextDelta { delta, .. })) => {
                        answer.push_str(&delta);
                        let safe = sanitizer.push(&delta);
                        if !safe.is_empty() {
                            output(&safe)?;
                        }
                    }
                    // Consume progress for transport accounting, without printing
                    // repetitive tool notices or extra assistant prompt markers.
                    Ok(Some(ChatEvent::Progress { .. } | ChatEvent::Usage { .. })) | Ok(None) => {}
                    Ok(Some(ChatEvent::Settled { usage })) => {
                        host.end_turn();
                        finish_answer(&answer, &reads, false)?;
                        output(&session_cost_line(&UsageStatus::Known(usage)))?;
                        answer.clear();
                        sanitizer = Sanitizer::default();
                        state = SessionState::Idle;
                        busy.store(false, Ordering::Release);
                        show_prompt()?;
                    }
                    Ok(Some(ChatEvent::Incomplete { reason, usage })) => {
                        host.cancel_all();
                        finish_answer(&answer, &reads, true)?;
                        output(&incomplete_reason_line(&reason, &chat.limits))?;
                        output(&session_cost_line(&usage))?;
                        answer.clear();
                        sanitizer = Sanitizer::default();
                        busy.store(false, Ordering::Release);
                        if matches!(reason, ChatIncompleteReason::ContextLimit) {
                            state = SessionState::Idle;
                            show_prompt()?;
                        } else {
                            transport.close();
                            return Err(Error::new(
                                ErrorKind::Backend,
                                "chat provider turn failed; context was not recovered",
                            ));
                        }
                    }
                    Err(error) => {
                        host.cancel_all();
                        finish_answer(&answer, &reads, true)?;
                        output(&transport_failure_line(&error, &chat.limits))?;
                        output(&session_cost_line(&transport.usage_snapshot()))?;
                        transport.close();
                        busy.store(false, Ordering::Release);
                        return Err(Error::new(ErrorKind::Backend, "chat provider failed"));
                    }
                }
            }
            SessionState::Cancelling => unreachable!("cancellation is handled synchronously"),
            SessionState::Closing => {
                host.cancel_all();
                transport.close();
                busy.store(false, Ordering::Release);
                output("\n")?;
                return Ok(());
            }
            SessionState::Starting => unreachable!("provider startup completed"),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_idle(
    event: TerminalEvent,
    transport: &mut ChatTransport,
    host: &ChatToolHost,
    reads: &ChatReadResources,
    limits: &ChatLimits,
    state: &mut SessionState,
    accepted_turns: &mut usize,
    answer: &mut String,
    busy: &AtomicBool,
) -> Result<()> {
    match event {
        TerminalEvent::BusyQuestion => {}
        TerminalEvent::Input(InputEvent::End) => *state = SessionState::Closing,
        TerminalEvent::Input(InputEvent::Oversized) => {
            output(&format!(
                "Input exceeds the configured {}-byte ceiling.\n",
                limits.max_input_bytes
            ))?;
            show_prompt()?;
        }
        TerminalEvent::Input(InputEvent::InvalidEncoding) => {
            output("Input must be valid UTF-8.\n")?;
            show_prompt()?;
        }
        TerminalEvent::Input(InputEvent::Line(line)) => {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                show_prompt()?;
            } else if trimmed.eq_ignore_ascii_case("quit") {
                *state = SessionState::Closing;
            } else if trimmed.eq_ignore_ascii_case("/help") {
                output("/help  show local commands\n/clear clear conversation context and references\n/queries show last-turn executed queries\n/evidence C1 or S1  inspect retained citation metadata (no new read)\nquit   exit\n")?;
                show_prompt()?;
            } else if trimmed.eq_ignore_ascii_case("/queries") {
                show_queries(reads)?;
                show_prompt()?;
            } else if let Some(argument) = evidence_argument(trimmed) {
                show_evidence(reads, argument)?;
                show_prompt()?;
            } else if trimmed.eq_ignore_ascii_case("/clear") {
                clear_context(transport, reads)?;
                show_prompt()?;
            } else if *accepted_turns >= limits.max_turns {
                output("Process turn ceiling reached; exit and start a new chat.\n")?;
                show_prompt()?;
            } else {
                reads.begin_turn();
                host.begin_turn();
                answer.clear();
                busy.store(true, Ordering::Release);
                if let Err(error) = transport.prompt(trimmed) {
                    host.cancel_all();
                    busy.store(false, Ordering::Release);
                    finish_answer(answer, reads, true)?;
                    output(&transport_failure_line(&error, limits))?;
                    transport.close();
                    return Err(transport_error(error));
                }
                *accepted_turns += 1;
                *state = SessionState::Running;
                output("cdb> ")?;
            }
        }
    }
    Ok(())
}

fn handle_running_input(event: TerminalEvent, reads: &ChatReadResources) -> Result<RunningAction> {
    match event {
        TerminalEvent::BusyQuestion => {
            output("\nA question is already running; input was not queued.\n")?;
            Ok(RunningAction::Continue)
        }
        TerminalEvent::Input(InputEvent::End) => Ok(RunningAction::Close),
        TerminalEvent::Input(InputEvent::Line(line))
            if line.trim().eq_ignore_ascii_case("quit") =>
        {
            Ok(RunningAction::Close)
        }
        TerminalEvent::Input(InputEvent::Line(line))
            if line.trim().eq_ignore_ascii_case("/clear") =>
        {
            Ok(RunningAction::Clear)
        }
        TerminalEvent::Input(InputEvent::Line(line))
            if line.trim().eq_ignore_ascii_case("/help") =>
        {
            output(
                "\n/help /clear /queries /evidence C1 or S1 / quit (ordinary questions are not queued while busy)\n",
            )?;
            Ok(RunningAction::Continue)
        }
        TerminalEvent::Input(InputEvent::Line(line))
            if line.trim().eq_ignore_ascii_case("/queries") =>
        {
            output("\n")?;
            show_queries(reads)?;
            Ok(RunningAction::Continue)
        }
        TerminalEvent::Input(InputEvent::Line(line)) if evidence_argument(&line).is_some() => {
            output("\n")?;
            show_evidence(reads, evidence_argument(&line).unwrap())?;
            Ok(RunningAction::Continue)
        }
        TerminalEvent::Input(InputEvent::Line(line)) if line.trim().is_empty() => {
            Ok(RunningAction::Continue)
        }
        TerminalEvent::Input(InputEvent::Line(_))
        | TerminalEvent::Input(InputEvent::Oversized)
        | TerminalEvent::Input(InputEvent::InvalidEncoding) => {
            output("\nA question is already running; input was not queued.\n")?;
            Ok(RunningAction::Continue)
        }
    }
}

fn discard_cancel_completion(transport: &mut ChatTransport, max_events: usize) -> Result<()> {
    for _ in 0..=max_events {
        match transport.poll_event(Duration::ZERO) {
            Ok(Some(ChatEvent::Incomplete { .. })) => return Ok(()),
            Ok(Some(_)) => continue,
            Ok(None) => {
                return Err(Error::new(
                    ErrorKind::Backend,
                    "provider cancellation completion missing",
                ))
            }
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::Backend,
                    "provider cancellation completion invalid",
                ))
            }
        }
    }
    Err(Error::new(
        ErrorKind::Backend,
        "provider cancellation completion overflow",
    ))
}

fn clear_context(transport: &mut ChatTransport, reads: &ChatReadResources) -> Result<()> {
    transport
        .clear()
        .map_err(|_| Error::new(ErrorKind::Backend, "chat context clear failed"))?;
    reads.clear_epoch();
    output("Conversation context cleared; process usage ceilings remain.\n")?;
    output(&session_cost_line(&transport.usage_snapshot()))
}

fn show_queries(reads: &ChatReadResources) -> Result<()> {
    let queries = reads.last_queries();
    if queries.is_empty() {
        return output("No queries recorded for the last turn.\n");
    }
    for (index, (query, outcome)) in queries.iter().enumerate() {
        let mut sanitizer = Sanitizer::default();
        let query = sanitizer.push(query);
        let mut sanitizer = Sanitizer::default();
        let outcome = sanitizer.push(outcome);
        output(&format!("{}. {}\n   {}\n", index + 1, query, outcome))?;
    }
    Ok(())
}

fn finish_answer(answer: &str, reads: &ChatReadResources, incomplete: bool) -> Result<()> {
    if !answer.ends_with('\n') {
        output("\n")?;
    }
    let mut citations = BTreeSet::new();
    for token in citation_tokens(answer) {
        citations.insert(token);
    }
    for token in citations {
        if reads.citation_details(&token).is_none() {
            output(&format!("Warning: unresolved citation {token}.\n"))?;
        }
    }
    if incomplete {
        output("[answer incomplete]\n")?;
    }
    Ok(())
}

fn evidence_argument(line: &str) -> Option<&str> {
    let line = line.trim();
    let (command, argument) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    command
        .eq_ignore_ascii_case("/evidence")
        .then_some(argument.trim())
}

fn evidence_token(argument: &str) -> Option<String> {
    let token = if argument.starts_with('[') {
        argument.to_owned()
    } else {
        format!("[{argument}]")
    };
    (citation_tokens(&token) == [token.clone()]).then_some(token)
}

fn show_evidence(reads: &ChatReadResources, argument: &str) -> Result<()> {
    let Some(token) = evidence_token(argument) else {
        return output("Usage: /evidence C1 or /evidence S1 (brackets are optional).\n");
    };
    match reads.citation_details(&token) {
        Some(detail) => {
            output("Retained citation metadata (not a fresh source read):\n")?;
            output(&citation_line(&token, &detail))
        }
        None => output(&format!(
            "No retained citation {token} in this conversation.\n"
        )),
    }
}

fn citation_line(token: &str, detail: &serde_json::Value) -> String {
    Sanitizer::default().push(&format!("{token}: {detail:#}\n"))
}

fn citation_tokens(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if bytes[index] == b'[' && matches!(bytes[index + 1], b'C' | b'S') {
            let mut end = index + 2;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > index + 2 && bytes.get(end) == Some(&b']') {
                found.push(text[index..=end].to_owned());
                index = end + 1;
                continue;
            }
        }
        index += 1;
    }
    found
}

fn is_busy_local(line: &str) -> bool {
    let line = line.trim();
    line.eq_ignore_ascii_case("/help")
        || line.eq_ignore_ascii_case("/clear")
        || line.eq_ignore_ascii_case("/queries")
        || evidence_argument(line).is_some()
}

fn transport_limits(limits: &ChatLimits) -> Result<ChatTransportLimits> {
    Ok(ChatTransportLimits {
        command_timeout: Duration::from_secs(limits.host_call_seconds as u64),
        turn_timeout: Duration::from_secs(limits.turn_seconds as u64),
        shutdown_grace: Duration::from_secs(limits.shutdown_seconds as u64),
        max_prompt_bytes: limits.max_input_bytes,
        max_record_bytes: limits.max_rpc_record_bytes,
        max_queued_bytes: limits.max_rpc_queue_bytes,
        max_events_per_turn: limits.max_rpc_events_per_turn,
        max_answer_bytes_per_turn: limits.max_answer_bytes,
        max_conversation_bytes: limits.max_context_bytes,
        max_tool_calls_per_turn: limits.max_tool_calls_per_turn.min(limits.max_tool_calls),
        max_tool_calls_per_process: limits.max_tool_calls,
        max_queries_per_turn: limits.max_queries_per_turn.min(limits.max_queries),
        max_queries_per_process: limits.max_queries,
        max_user_turns_per_process: limits.max_turns,
        max_model_rounds_per_process: limits.max_model_rounds,
        max_total_tokens: u64::try_from(limits.max_reported_tokens).map_err(|_| Error::limit())?,
        max_cost_microusd: u64::try_from(limits.max_reported_cost_micro_usd)
            .map_err(|_| Error::limit())?,
        max_stderr_bytes: 64 * 1024,
    })
}

/// Closed, display-safe reasons only: never print provider messages, stderr,
/// RPC payloads or even an unrecognized internal limit string.
fn incomplete_reason_line(reason: &ChatIncompleteReason, limits: &ChatLimits) -> String {
    let reason = match reason {
        ChatIncompleteReason::Limit("turn_deadline") => format!(
            "whole-turn deadline reached ({} seconds, including model and tool time)", limits.turn_seconds),
        ChatIncompleteReason::Limit("tokens") => format!(
            "cumulative session token limit reached ({} tokens, including repeated cached context); restart chat for a new budget", limits.max_reported_tokens),
        ChatIncompleteReason::Limit("cost") => "reported session cost threshold reached; no automatic retry".into(),
        ChatIncompleteReason::Limit("usage_unknown") => "provider usage accounting is unavailable; cannot safely continue".into(),
        ChatIncompleteReason::Limit("conversation_bytes") => "conversation byte limit reached; restart with a smaller scope".into(),
        ChatIncompleteReason::Limit("tool_calls") => "read-tool call limit reached".into(),
        ChatIncompleteReason::Limit("queries") => "graph-query call limit reached".into(),
        ChatIncompleteReason::Limit("model_rounds") => "session model-round limit reached".into(),
        ChatIncompleteReason::Limit("user_turns") => "session user-turn limit reached".into(),
        ChatIncompleteReason::Limit("answer_bytes") => "answer byte limit reached".into(),
        ChatIncompleteReason::Limit("prompt_bytes") => "prompt byte limit reached".into(),
        ChatIncompleteReason::Limit("events" | "event_queue" | "record_bytes") => "provider stream capacity limit reached".into(),
        ChatIncompleteReason::Limit(_) => "provider safety limit reached".into(),
        ChatIncompleteReason::ProviderError => "provider reported a failed or aborted response".into(),
        ChatIncompleteReason::Cancelled => "turn cancelled".into(),
        ChatIncompleteReason::ContextLimit => "provider context/output limit reached; use /clear or quit".into(),
        ChatIncompleteReason::Protocol => "provider stream failed protocol validation".into(),
        ChatIncompleteReason::Eof => "provider stream ended before the turn completed".into(),
    };
    format!("[chat stopped: {reason}]\n")
}

fn transport_failure_line(error: &ChatTransportError, limits: &ChatLimits) -> String {
    match error {
        ChatTransportError::Limit(name) => {
            incomplete_reason_line(&ChatIncompleteReason::Limit(name), limits)
        }
        ChatTransportError::Protocol => {
            incomplete_reason_line(&ChatIncompleteReason::Protocol, limits)
        }
        ChatTransportError::Io | ChatTransportError::NotRunning => {
            incomplete_reason_line(&ChatIncompleteReason::Eof, limits)
        }
        ChatTransportError::Timeout => {
            "[chat stopped: provider control command timed out]\n".into()
        }
        _ => "[chat stopped: provider transport could not accept the operation]\n".into(),
    }
}

fn transport_error(error: ChatTransportError) -> Error {
    match error {
        ChatTransportError::Limit(_) => Error::limit(),
        _ => Error::new(ErrorKind::Backend, "chat provider rejected the turn"),
    }
}

/// Transport snapshots already accumulate across turns and /clear; never sum
/// them again. Only settled, provider-reported accounting is displayed.
fn session_cost_line(usage: &UsageStatus) -> String {
    let UsageStatus::Known(usage) = usage else {
        return "[session cost: unavailable]\n".into();
    };
    let micros = usage.cost_microusd;
    if micros > 0 && micros < 10_000 {
        return "[session cost: <$0.01]\n".into();
    }
    // Integer rounding avoids float precision loss and overflow at u64::MAX.
    let cents = micros / 10_000 + u64::from(micros % 10_000 >= 5_000);
    format!("[session cost: ${}.{:02}]\n", cents / 100, cents % 100)
}

fn show_prompt() -> Result<()> {
    output("You> ")
}

fn output(text: &str) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .and_then(|_| stdout.flush())
        .map_err(|_| Error::new(ErrorKind::Backend, "terminal output unavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_reasons_are_specific_but_never_echo_unknown_details() {
        let limits = ChatLimits::default();
        assert_eq!(limits.turn_seconds, 300);
        assert_eq!(limits.max_reported_tokens, 1_000_000);
        assert_eq!(limits.max_reported_cost_micro_usd, 5_000_000);
        assert_eq!(limits.host_call_seconds, 10);
        for (reason, expected) in [
            (ChatIncompleteReason::Limit("tokens"), "1000000 tokens"),
            (ChatIncompleteReason::Limit("turn_deadline"), "300 seconds"),
            (
                ChatIncompleteReason::Limit("queries"),
                "graph-query call limit",
            ),
            (ChatIncompleteReason::ProviderError, "provider reported"),
            (ChatIncompleteReason::Cancelled, "turn cancelled"),
            (ChatIncompleteReason::Protocol, "protocol validation"),
            (ChatIncompleteReason::Eof, "ended before"),
            (ChatIncompleteReason::ContextLimit, "context/output limit"),
        ] {
            assert!(incomplete_reason_line(&reason, &limits).contains(expected));
        }
        assert_eq!(
            incomplete_reason_line(
                &ChatIncompleteReason::Limit("secret/path\\u{1b}[31m"),
                &limits
            ),
            "[chat stopped: provider safety limit reached]\n"
        );
        assert!(
            transport_failure_line(&ChatTransportError::Limit("tokens"), &limits)
                .contains("1000000 tokens")
        );
        assert!(
            transport_failure_line(&ChatTransportError::Timeout, &limits).contains("timed out")
        );
        let lowered = ChatLimits {
            turn_seconds: 17,
            max_reported_tokens: 200,
            ..limits
        };
        assert!(
            incomplete_reason_line(&ChatIncompleteReason::Limit("tokens"), &lowered)
                .contains("200 tokens")
        );
        assert!(
            incomplete_reason_line(&ChatIncompleteReason::Limit("turn_deadline"), &lowered)
                .contains("17 seconds")
        );
    }

    #[test]
    fn session_cost_formats_reported_totals_without_inventing_unknown_usage() {
        use cdb_provider_pi::usage::Usage;
        for (micros, expected) in [
            (0, "$0.00"),
            (1, "<$0.01"),
            (9_999, "<$0.01"),
            (10_000, "$0.01"),
            (30_000, "$0.03"),
            (35_000, "$0.04"),
            (999_999, "$1.00"),
            (u64::MAX, "$18446744073709.55"),
        ] {
            let usage = UsageStatus::Known(Usage {
                cost_microusd: micros,
                ..Default::default()
            });
            assert_eq!(
                session_cost_line(&usage),
                format!("[session cost: {expected}]\n")
            );
        }
        assert_eq!(
            session_cost_line(&UsageStatus::Unknown),
            "[session cost: unavailable]\n"
        );
    }

    #[test]
    fn process_ceilings_clamp_effective_per_turn_budgets() {
        for (tools, queries) in [(200, 1), (5, 3)] {
            let limits = ChatLimits {
                max_tool_calls: tools,
                max_queries: queries,
                ..ChatLimits::default()
            };
            limits.validate(10, 1_000_000).unwrap();
            let effective = transport_limits(&limits).unwrap();
            assert_eq!(effective.max_tool_calls_per_turn, 40.min(tools));
            assert_eq!(effective.max_queries_per_turn, queries);
            assert_eq!(effective.max_tool_calls_per_process, tools);
            assert_eq!(effective.max_queries_per_process, queries);
        }
    }

    #[test]
    fn citations_are_exact_and_only_known_commands_are_local() {
        let metadata = serde_json::json!({"label": "\u{009b}31mred\u{009b}0m"});
        assert_eq!(
            citation_line("[C1]", &metadata),
            "[C1]: {\n  \"label\": \"red\"\n}\n"
        );
        assert_eq!(
            citation_tokens("x [C1], [S22], [C] [S2oops] [X1]"),
            vec!["[C1]", "[S22]"]
        );
        assert!(is_busy_local("/queries"));
        assert!(is_busy_local("/evidence C1"));
        assert!(is_busy_local("/EVIDENCE [S1]"));
        assert_eq!(evidence_argument(" /evidence  C1 "), Some("C1"));
        assert_eq!(evidence_argument("/evidence"), Some(""));
        assert_eq!(evidence_argument("/evidence-extra C1"), None);
        assert_eq!(evidence_token("C1").as_deref(), Some("[C1]"));
        assert_eq!(evidence_token("[S22]").as_deref(), Some("[S22]"));
        for invalid in [
            "",
            "C",
            "X1",
            "C1 extra",
            "[C1][S1]",
            "[C1]extra",
            "C1\u{001b}",
        ] {
            assert!(evidence_token(invalid).is_none(), "{invalid:?}");
        }
        assert!(!is_busy_local("please quit now"));
        assert!(!is_busy_local("/bash"));
    }

    #[test]
    fn priority_control_cannot_be_downgraded_or_lost_to_queue_pressure() {
        let control = ControlState::default();
        control.request(PriorityControl::Interrupt);
        control.request(PriorityControl::Clear);
        control.request(PriorityControl::Close);
        control.request(PriorityControl::Interrupt);
        assert_eq!(control.take(), PriorityControl::Close);
        assert_eq!(control.take(), PriorityControl::None);
    }

    #[test]
    fn unknown_slash_text_is_not_a_local_command() {
        for text in ["/bash", "/skill:anything", "/unknown", "!command", "@file"] {
            assert!(!is_busy_local(text));
        }
    }
}
