#![cfg(unix)]

use cdb_provider_pi::agent_bundle::{hash_agent_bundle_for_profile, BundleProfile};
use cdb_provider_pi::chat_transport::{
    ChatEvent, ChatIncompleteReason, ChatTransport, ChatTransportConfig, ChatTransportError,
    ChatTransportLimits, UsageStatus,
};
use cdb_provider_pi::ontology_bridge::{OntologyBridgeConfig, OntologyToolError, OntologyToolHost};
use cdb_provider_pi::{SessionLogging, RUNTIME_MODEL};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Deny;
impl OntologyToolHost for Deny {
    fn lookup(&self, _: &Value) -> Result<Value, OntologyToolError> {
        Err(OntologyToolError::Denied)
    }
}

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn fixture(mode: &str) -> (ChatTransportConfig, PathBuf) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .saturating_add(SEQUENCE.fetch_add(1, Ordering::Relaxed) as u128);
    let root =
        std::env::temp_dir().join(format!("ctxql-chat-fake-{}-{unique}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let script = root.join("fake-pi");
    fs::write(
        &script,
        r##"#!/bin/sh
if [ "$1" = "--version" ]; then printf '0.87.1\n'; exit 0; fi
session_json=null
previous=
for argument in "$@"; do
  if [ "$previous" = "--session-dir" ]; then
    mkdir -p "$argument"
    session_file="$argument/fake-session.jsonl"
    printf '{"type":"session","version":3,"id":"fake","cwd":"fake"}\n' > "$session_file"
    session_json="\"$session_file\""
  fi
  previous="$argument"
done
printf '%s|%s' "${CDB_CONFIG-}" "${CDB_TOKEN_FILE-}" > "${CDB_FAKE_EXIT_FILE}.env"
turn=0
while IFS= read -r line; do
  id=${line#*\"id\":\"}; id=${id%%\"*}
  case "$line" in
    *\"type\":\"get_state\"*)
      if [ "$CDB_FAKE_MODE" = "handshake-invalid-json" ]; then
        printf '{invalid-json}\n'
        exit 0
      fi
      model="deepseek/deepseek-v4.1-flash"
      [ "$CDB_FAKE_MODE" = "model-mismatch" ] && model="other/model"
      printf '{"type":"response","id":"%s","command":"get_state","success":true,"data":{"model":{"provider":"openrouter","id":"%s"},"thinkingLevel":"high","isStreaming":false,"pendingMessageCount":0,"sessionFile":%s,"ambientConfig":"%s","ambientToken":"%s"}}\n' "$id" "$model" "$session_json" "${CDB_CONFIG-}" "${CDB_TOKEN_FILE-}"
      ;;
    *\"type\":\"set_auto_compaction\"*|*\"type\":\"set_auto_retry\"*)
      printf '{"type":"response","id":"%s","success":true}\n' "$id"
      ;;
    *\"type\":\"get_commands\"*)
      printf '{"type":"response","id":"%s","success":true,"data":{"commands":[]}}\n' "$id"
      [ "$CDB_FAKE_MODE" = "blocked-stdin" ] && while :; do :; done
      ;;
    *\"type\":\"new_session\"*)
      turn=0
      printf '{"type":"response","id":"%s","success":true,"data":{"cancelled":false}}\n' "$id"
      ;;
    *\"type\":\"clear_queue\"*)
      printf '{"type":"response","id":"%s","success":true,"data":{"steering":[],"followUp":[]}}\n' "$id"
      ;;
    *\"type\":\"abort\"*)
      printf '{"type":"agent_settled"}\n'
      printf '{"type":"response","id":"%s","success":true}\n' "$id"
      ;;
    *\"type\":\"prompt\"*)
      turn=$((turn + 1))
      printf '%s\n' "$line" >> "${CDB_FAKE_EXIT_FILE}.prompts"
      if [ "$CDB_FAKE_MODE" = "crash" ]; then exit 17; fi
      if [ "$CDB_FAKE_MODE" = "invalid-utf8" ]; then
        printf '\377\n'
        exit 0
      fi
      if [ "$CDB_FAKE_MODE" = "oversized-record" ]; then
        printf '%02000d' 0
        while :; do :; done
      fi
      if [ "$CDB_FAKE_MODE" = "queue-overflow" ]; then
        printf '{"type":"agent_start"}\n'
        printf '{"type":"turn_start"}\n'
        printf '{"type":"message_start","message":{"role":"assistant","provider":"openrouter","model":"deepseek/deepseek-v4.1-flash","content":[],"stopReason":"pending","usage":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"totalTokens":0,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":0}}}}\n'
        printf '{"type":"message_update","assistantMessageEvent":{"type":"text_start","contentIndex":0}}\n'
        index=0
        while [ "$index" -lt 100 ]; do
          printf '{"type":"message_update","assistantMessageEvent":{"type":"text_delta","contentIndex":0,"delta":"%0100d"}}\n' "$index"
          index=$((index + 1))
        done
        continue
      fi
      if [ "$CDB_FAKE_MODE" = "fragmented-framing" ]; then
        printf '%s' '{"type":"agent_start"}'
        printf '\r\n'
        printf '%s' '{"type":"turn_start"}'
        printf '\n'
        printf '%s' '{"type":"message_start","message":{"role":"assistant","provider":"openrouter","model":"deepseek/deepseek-v4.1-flash","responseId":"fragmented","content":[],"stopReason":"pending","usage":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"totalTokens":0,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":0}}}}'
        printf '\r\n'
        printf '%s' '{"type":"message_update","assistantMessageEvent":{"type":"text_start","contentIndex":0}}'
        printf '\n'
        printf '%s' '{"type":"message_update","assistantMessageEvent":{"type":"text_delta","contentIndex":0,"delta":"λ\u2028\u2029"}}'
        printf '\r\n'
        printf '%s' '{"type":"message_update","assistantMessageEvent":{"type":"text_end","contentIndex":0,"content":"λ\u2028\u2029"}}'
        printf '\n'
        printf '{"type":"response","id":"%s","command":"prompt","success":true}\r\n' "$id"
        printf '%s' '{"type":"message_end","message":{"role":"assistant","provider":"openrouter","model":"deepseek/deepseek-v4.1-flash","responseId":"fragmented","content":[{"type":"text","text":"λ\u2028\u2029"}],"stopReason":"stop","usage":{"input":1,"output":1,"cacheRead":0,"cacheWrite":0,"totalTokens":2,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":0}}}}'
        printf '\n'
        printf '%s' '{"type":"agent_end","messages":[],"willRetry":false}'
        printf '\r\n'
        printf '%s' '{"type":"agent_settled"}'
        printf '\n'
        continue
      fi
      if [ "$CDB_FAKE_MODE" = "duplicate-json" ]; then
        printf '{"type":"agent_start","type":"agent_end"}\n'
        continue
      fi
      if [ "$CDB_FAKE_MODE" = "unterminated" ]; then
        printf '{"type":"agent_start"}'
        exit 0
      fi
      printf '{"type":"agent_start"}\n'
      printf '{"type":"turn_start"}\n'
      [ "$CDB_FAKE_MODE" = "multiple-model-rounds" ] && printf '{"type":"turn_start"}\n'
      start_response_id=',"responseId":"response-'$turn'"'
      [ "$CDB_FAKE_MODE" = "missing-start-id" ] || [ "$CDB_FAKE_MODE" = "missing-both-ids" ] && start_response_id=''
      [ "$CDB_FAKE_MODE" = "malformed-start-id" ] && start_response_id=',"responseId":7'
      printf '{"type":"message_start","message":{"role":"assistant","provider":"openrouter","model":"deepseek/deepseek-v4.1-flash"%s,"content":[],"stopReason":"pending","usage":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"totalTokens":0,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":0}}}}\n' "$start_response_id"
      printf '{"type":"message_update","usage":{"input":10},"assistantMessageEvent":{"type":"text_start","contentIndex":0}}\n'
      printf '{"type":"message_update","usage":{"output":1,"cost":{"total":0.000001}},"assistantMessageEvent":{"type":"text_delta","contentIndex":0,"delta":"turn-%s λ"}}\n' "$turn"
      [ "$CDB_FAKE_MODE" = "missing-text-end" ] || printf '{"type":"message_update","usage":{"cacheRead":0,"cacheWrite":0},"assistantMessageEvent":{"type":"text_end","contentIndex":0,"content":"turn-%s λ"}}\n' "$turn"
      response_id="$id"
      [ "$CDB_FAKE_MODE" = "wrong-id" ] && response_id="wrong"
      printf '{"type":"response","id":"%s","command":"prompt","success":true}\n' "$response_id"
      [ "$CDB_FAKE_MODE" = "duplicate-response" ] && printf '{"type":"response","id":"%s","command":"prompt","success":true}\n' "$id"
      if [ "$CDB_FAKE_MODE" = "capability-tool" ]; then
        printf '{"type":"tool_execution_start","toolCallId":"cap-%s","toolName":"ctxql_capabilities","args":{}}\n' "$turn"
      fi
      if [ "$CDB_FAKE_MODE" = "query-budget" ]; then
        printf '{"type":"tool_execution_start","toolCallId":"query-1","toolName":"ctxql_graph_query","args":{"query":"{}"}}\n'
        printf '{"type":"tool_execution_start","toolCallId":"query-2","toolName":"ctxql_graph_query","args":{"query":"{}"}}\n'
      fi
      if [ "$CDB_FAKE_MODE" = "hang" ]; then continue; fi
      if [ "$CDB_FAKE_MODE" = "hidden-overflow" ]; then
        hidden=$(printf '%04096d' 0)
        printf '{"type":"message_end","message":{"role":"assistant","provider":"openrouter","model":"deepseek/deepseek-v4.1-flash","responseId":"response-%s","content":[{"type":"text","text":"turn-%s λ"},{"type":"thinking","thinking":"%s"}],"stopReason":"stop","usage":{"input":10,"output":2,"cacheRead":0,"cacheWrite":0,"totalTokens":12,"cost":{"input":0,"output":0.000002,"cacheRead":0,"cacheWrite":0,"total":0.000002}}}}\n' "$turn" "$turn" "$hidden"
        printf '{"type":"agent_end","messages":[],"willRetry":false}\n'
        printf '{"type":"agent_settled"}\n'
        continue
      fi
      if [ "$CDB_FAKE_MODE" = "tool-overflow" ]; then
        args=$(printf '%0600d' 0)
        result=$(printf '%03000d' 0)
        printf '{"type":"message_end","message":{"role":"assistant","provider":"openrouter","model":"deepseek/deepseek-v4.1-flash","responseId":"response-%s","content":[{"type":"text","text":"turn-%s λ"},{"type":"toolCall","id":"call-1","name":"ctxql_capabilities","arguments":{"payload":"%s"}}],"stopReason":"toolUse","usage":{"input":10,"output":2,"cacheRead":0,"cacheWrite":0,"totalTokens":12,"cost":{"input":0,"output":0.000002,"cacheRead":0,"cacheWrite":0,"total":0.000002}}}}\n' "$turn" "$turn" "$args"
        printf '{"type":"tool_execution_start","toolCallId":"call-1","toolName":"ctxql_capabilities","args":{}}\n'
        printf '{"type":"tool_execution_end","toolCallId":"call-1","toolName":"ctxql_capabilities","result":{"content":[{"type":"text","text":"%s"}],"details":{}},"isError":false}\n' "$result"
        printf '{"type":"message_end","message":{"role":"toolResult","toolCallId":"call-1","toolName":"ctxql_capabilities","content":[{"type":"text","text":"%s"}],"isError":false,"timestamp":1}}\n' "$result"
        continue
      fi
      stop_reason="stop"
      [ "$CDB_FAKE_MODE" = "provider-error" ] && stop_reason="error"
      end_response_id=',"responseId":"response-'$turn'"'
      [ "$CDB_FAKE_MODE" = "missing-both-ids" ] && end_response_id=''
      [ "$CDB_FAKE_MODE" = "mismatched-message-id" ] && end_response_id=',"responseId":"different"'
      [ "$CDB_FAKE_MODE" = "malformed-end-id" ] && end_response_id=',"responseId":null'
      final_text="turn-$turn λ"
      [ "$CDB_FAKE_MODE" = "final-text-mismatch" ] && final_text="different"
      usage='{"input":10,"output":2,"cacheRead":0,"cacheWrite":0,"totalTokens":12,"cost":{"input":0,"output":0.000002,"cacheRead":0,"cacheWrite":0,"total":0.000002}}'
      [ "$CDB_FAKE_MODE" = "usage-absent" ] && usage=''
      [ "$CDB_FAKE_MODE" = "usage-partial" ] && usage='{"input":10}'
      [ "$CDB_FAKE_MODE" = "usage-negative" ] && usage='{"input":-1,"output":2,"cacheRead":0,"cacheWrite":0,"totalTokens":12,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":0}}'
      [ "$CDB_FAKE_MODE" = "usage-string" ] && usage='{"input":"10","output":2,"cacheRead":0,"cacheWrite":0,"totalTokens":12,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":0}}'
      [ "$CDB_FAKE_MODE" = "cost-string" ] && usage='{"input":10,"output":2,"cacheRead":0,"cacheWrite":0,"totalTokens":12,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":"free"}}'
      [ "$CDB_FAKE_MODE" = "cost-nonfinite" ] && usage='{"input":10,"output":2,"cacheRead":0,"cacheWrite":0,"totalTokens":12,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"total":1e999}}'
      if [ -n "$usage" ]; then usage_field=',"usage":'$usage; else usage_field=''; fi
      printf '{"type":"message_end","message":{"role":"assistant","provider":"openrouter","model":"deepseek/deepseek-v4.1-flash"%s,"content":[{"type":"text","text":"%s"}],"stopReason":"%s"%s}}\n' "$end_response_id" "$final_text" "$stop_reason" "$usage_field"
      [ "$CDB_FAKE_MODE" = "late-update" ] && printf '{"type":"message_update","usage":{"output":3},"assistantMessageEvent":{"type":"text_delta","contentIndex":0,"delta":"late"}}\n'
      printf '{"type":"agent_end","messages":[],"willRetry":false}\n'
      printf '{"type":"agent_settled"}\n'
      ;;
  esac
done
printf closed > "$CDB_FAKE_EXIT_FILE"
"##,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).unwrap();

    let assets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/pi");
    let bundle = hash_agent_bundle_for_profile(assets, BundleProfile::Chat).unwrap();
    let exit_file = root.join("closed");
    let config = ChatTransportConfig {
        command: script,
        environment: vec![
            ("CDB_FAKE_MODE".into(), mode.into()),
            (
                "CDB_FAKE_EXIT_FILE".into(),
                exit_file.to_string_lossy().into_owned(),
            ),
        ],
        system_prompt: bundle.chat_system_prompt().unwrap(),
        bundle,
        ontology_bridge: OntologyBridgeConfig {
            host: Arc::new(Deny),
            max_request_bytes: 32 * 1024,
            max_response_bytes: 64 * 1024,
        },
        limits: ChatTransportLimits {
            command_timeout: Duration::from_secs(2),
            turn_timeout: Duration::from_secs(2),
            shutdown_grace: Duration::from_secs(1),
            ..ChatTransportLimits::default()
        },
        session_logging: None,
    };
    (config, root)
}

fn complete_turn(transport: &mut ChatTransport) -> Vec<ChatEvent> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut events = Vec::new();
    while Instant::now() < deadline {
        if let Some(event) = transport.poll_event(Duration::from_millis(100)).unwrap() {
            let done = matches!(
                event,
                ChatEvent::Settled { .. } | ChatEvent::Incomplete { .. }
            );
            events.push(event);
            if done {
                return events;
            }
        }
    }
    panic!("turn did not settle")
}

#[test]
fn persistent_process_streams_identity_before_settled_across_turns_and_clear() {
    let (config, root) = fixture("normal");
    let mut transport = ChatTransport::start(config).unwrap();
    for expected in [1, 2] {
        transport
            .prompt(if expected == 1 { "/bash" } else { "follow up" })
            .unwrap();
        let events = complete_turn(&mut transport);
        let delta_index = events
            .iter()
            .position(|event| matches!(event, ChatEvent::TextDelta { .. }))
            .unwrap();
        let settled_index = events
            .iter()
            .position(|event| matches!(event, ChatEvent::Settled { .. }))
            .unwrap();
        assert!(delta_index < settled_index);
        match &events[delta_index] {
            ChatEvent::TextDelta {
                identity,
                delta,
                content_index,
            } => {
                assert_eq!(identity.message_id, format!("ctxql-assistant-{expected}"));
                assert_eq!(identity.provider, "openrouter");
                assert_eq!(identity.model, RUNTIME_MODEL);
                assert_eq!(*content_index, 0);
                assert_eq!(delta, &format!("turn-{expected} λ"));
            }
            _ => unreachable!(),
        }
    }
    assert!(matches!(
        transport.usage_snapshot(),
        UsageStatus::Known(ref usage) if usage.output_tokens == 4 && usage.requests == 2
    ));
    transport.clear().unwrap();
    transport.prompt("after clear").unwrap();
    assert!(complete_turn(&mut transport)
        .iter()
        .any(|event| matches!(event, ChatEvent::Settled { .. })));
    transport.close();
    assert!(
        root.join("closed").exists(),
        "stdin EOF must permit orderly reap"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn explicit_session_logging_retains_native_session_and_content_free_diagnostics() {
    let (mut config, root) = fixture("normal");
    let log_root = root.join("logs");
    config.session_logging = Some(SessionLogging {
        root: log_root.clone(),
    });
    let mut transport = ChatTransport::start(config).unwrap();
    let diagnostic = transport.diagnostic_path().unwrap().to_path_buf();
    transport
        .prompt("sensitive question must not enter host log")
        .unwrap();
    assert!(matches!(
        complete_turn(&mut transport).last(),
        Some(ChatEvent::Settled { .. })
    ));
    transport.close();

    let diagnostic_text = fs::read_to_string(&diagnostic).unwrap();
    assert!(diagnostic_text.contains("agent_settled"));
    assert!(!diagnostic_text.contains("sensitive question"));
    let native_sessions = fs::read_dir(&log_root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .flat_map(|entry| fs::read_dir(entry.path()).unwrap().filter_map(Result::ok))
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("jsonl"))
        .count();
    assert_eq!(native_sessions, 1);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn session_diagnostics_distinguish_handshake_framing_failure() {
    let (mut config, root) = fixture("handshake-invalid-json");
    let logs = root.join("logs");
    config.session_logging = Some(SessionLogging { root: logs.clone() });
    assert!(matches!(
        ChatTransport::start(config),
        Err(ChatTransportError::Protocol)
    ));
    let diagnostic = fs::read_dir(logs)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("host-chat-")
        })
        .map(|entry| fs::read_to_string(entry.path()).unwrap())
        .unwrap();
    assert!(diagnostic.contains("\"event\":\"rpc_framing\""));
    assert!(diagnostic.contains("\"outcome\":\"invalid_canonical_json\""));
    assert!(diagnostic.contains("\"event\":\"handshake_get_state\""));
    assert!(diagnostic.contains("\"outcome\":\"rejected_protocol\""));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn session_diagnostics_retain_protocol_failure_and_confirmed_cancellation() {
    let (mut failed_config, failed_root) = fixture("final-text-mismatch");
    let failed_logs = failed_root.join("logs");
    failed_config.session_logging = Some(SessionLogging { root: failed_logs });
    let mut failed = ChatTransport::start(failed_config).unwrap();
    let failed_diagnostic = failed.diagnostic_path().unwrap().to_path_buf();
    failed.prompt("failure probe").unwrap();
    assert!(matches!(
        complete_turn(&mut failed).last(),
        Some(ChatEvent::Incomplete {
            reason: ChatIncompleteReason::Protocol,
            ..
        })
    ));
    failed.close();
    let failed_diagnostic = fs::read_to_string(failed_diagnostic).unwrap();
    assert!(failed_diagnostic.contains("rejected_protocol"));
    assert!(failed_diagnostic.contains("assistant_final_text_validation"));
    assert!(failed_diagnostic.contains("stream_mismatch"));
    let _ = fs::remove_dir_all(failed_root);

    let (mut cancel_config, cancel_root) = fixture("hang");
    cancel_config.session_logging = Some(SessionLogging {
        root: cancel_root.join("logs"),
    });
    let mut cancelled = ChatTransport::start(cancel_config).unwrap();
    let cancel_diagnostic = cancelled.diagnostic_path().unwrap().to_path_buf();
    cancelled.prompt("cancel probe").unwrap();
    cancelled.cancel().unwrap();
    cancelled.close();
    assert!(fs::read_to_string(cancel_diagnostic)
        .unwrap()
        .contains("confirmed_idle"));
    let _ = fs::remove_dir_all(cancel_root);
}

#[test]
fn model_round_limit_counts_each_turn_start_within_one_agent_run() {
    let (mut config, root) = fixture("multiple-model-rounds");
    config.limits.max_model_rounds_per_process = 1;
    let mut transport = ChatTransport::start(config).unwrap();

    assert_eq!(
        transport.prompt("one"),
        Err(ChatTransportError::Limit("model_rounds"))
    );
    assert!(matches!(
        transport.poll_event(Duration::from_secs(1)),
        Ok(Some(ChatEvent::Incomplete {
            reason: ChatIncompleteReason::Limit("model_rounds"),
            ..
        }))
    ));

    transport.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn clear_does_not_reset_process_model_round_count() {
    let (mut config, root) = fixture("normal");
    config.limits.max_model_rounds_per_process = 1;
    let mut transport = ChatTransport::start(config).unwrap();

    transport.prompt("before clear").unwrap();
    assert!(complete_turn(&mut transport)
        .iter()
        .any(|event| matches!(event, ChatEvent::Settled { .. })));
    transport.clear().unwrap();
    assert_eq!(
        transport.prompt("after clear"),
        Err(ChatTransportError::Limit("model_rounds"))
    );
    assert!(matches!(
        transport.poll_event(Duration::from_secs(1)),
        Ok(Some(ChatEvent::Incomplete {
            reason: ChatIncompleteReason::Limit("model_rounds"),
            ..
        }))
    ));

    transport.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn provider_error_after_streaming_is_incomplete() {
    let (config, root) = fixture("provider-error");
    let mut transport = ChatTransport::start(config).unwrap();
    transport.prompt("one").unwrap();
    let events = complete_turn(&mut transport);
    assert!(events
        .iter()
        .any(|event| matches!(event, ChatEvent::TextDelta { .. })));
    assert!(events.iter().any(|event| matches!(
        event,
        ChatEvent::Incomplete {
            reason: ChatIncompleteReason::ProviderError,
            ..
        }
    )));
    transport.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn provider_ids_are_optional_but_malformed_mismatched_and_late_lifecycles_fail() {
    for mode in ["missing-start-id", "missing-both-ids"] {
        let (config, root) = fixture(mode);
        let mut transport = ChatTransport::start(config).unwrap();
        transport.prompt("one").unwrap();
        let events = complete_turn(&mut transport);
        assert!(matches!(events.last(), Some(ChatEvent::Settled { .. })));
        let identity = events.iter().find_map(|event| match event {
            ChatEvent::TextDelta { identity, .. } => Some(identity),
            _ => None,
        });
        assert_eq!(identity.unwrap().message_id, "ctxql-assistant-1");
        transport.close();
        let _ = fs::remove_dir_all(root);
    }

    for mode in [
        "malformed-start-id",
        "malformed-end-id",
        "mismatched-message-id",
        "late-update",
    ] {
        let (config, root) = fixture(mode);
        let mut transport = ChatTransport::start(config).unwrap();
        let result = transport.prompt("one");
        if result.is_ok() {
            let events = complete_turn(&mut transport);
            assert!(
                events.iter().any(|event| matches!(
                    event,
                    ChatEvent::Incomplete {
                        reason: ChatIncompleteReason::Protocol,
                        ..
                    }
                )),
                "mode {mode}"
            );
        } else {
            assert_eq!(result, Err(ChatTransportError::Protocol), "mode {mode}");
        }
        transport.close();
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn streamed_blocks_must_finalize_and_match_authoritative_message_text() {
    for mode in ["missing-text-end", "final-text-mismatch"] {
        let (config, root) = fixture(mode);
        let mut transport = ChatTransport::start(config).unwrap();
        transport.prompt("one").unwrap();
        let events = complete_turn(&mut transport);
        assert!(
            events.iter().any(|event| matches!(
                event,
                ChatEvent::Incomplete {
                    reason: ChatIncompleteReason::Protocol,
                    ..
                }
            )),
            "mode {mode}"
        );
        transport.close();
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn required_final_usage_rejects_missing_partial_and_malformed_values_as_unknown() {
    for mode in [
        "usage-absent",
        "usage-partial",
        "usage-negative",
        "usage-string",
        "cost-string",
        "cost-nonfinite",
    ] {
        let (config, root) = fixture(mode);
        let mut transport = ChatTransport::start(config).unwrap();
        transport.prompt("one").unwrap();
        let events = complete_turn(&mut transport);
        assert!(
            events.iter().any(|event| matches!(
                event,
                ChatEvent::Incomplete {
                    reason: ChatIncompleteReason::Protocol,
                    usage: UsageStatus::Unknown,
                }
            )),
            "mode {mode}: {events:?}"
        );
        assert_eq!(transport.usage_snapshot(), UsageStatus::Unknown);
        assert_eq!(
            transport.prompt("again"),
            Err(ChatTransportError::NotRunning)
        );
        transport.close();
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn model_mismatch_fails_during_control_only_startup() {
    let (config, root) = fixture("model-mismatch");
    assert!(matches!(
        ChatTransport::start(config),
        Err(ChatTransportError::ModelMismatch)
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn duplicate_keys_and_unterminated_eof_are_protocol_failures() {
    for mode in ["duplicate-json", "unterminated"] {
        let (config, root) = fixture(mode);
        let mut transport = ChatTransport::start(config).unwrap();
        assert!(matches!(
            transport.prompt("one"),
            Err(ChatTransportError::Protocol)
        ));
        transport.close();
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn fragmented_lf_crlf_unicode_separators_are_one_strict_utf8_stream() {
    let (config, root) = fixture("fragmented-framing");
    let mut transport = ChatTransport::start(config).unwrap();
    transport.prompt("one").unwrap();
    let events = complete_turn(&mut transport);
    assert!(events.iter().any(|event| matches!(
        event,
        ChatEvent::TextDelta { delta, .. } if delta == "λ\u{2028}\u{2029}"
    )));
    assert!(matches!(events.last(), Some(ChatEvent::Settled { .. })));
    transport.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn invalid_utf8_oversized_records_and_queued_output_fail_closed() {
    for (mode, expected) in [
        ("invalid-utf8", "protocol"),
        ("oversized-record", "record_bytes"),
        ("queue-overflow", "event_queue"),
    ] {
        let (mut config, root) = fixture(mode);
        config.limits.max_record_bytes = 1024;
        config.limits.max_queued_bytes = 1024;
        let mut transport = ChatTransport::start(config).unwrap();
        let observed = match transport.prompt("one") {
            Err(ChatTransportError::Protocol) => "protocol",
            Err(ChatTransportError::Limit(name)) => name,
            Err(error) => panic!("mode {mode}: unexpected {error:?}"),
            Ok(()) => complete_turn(&mut transport)
                .into_iter()
                .find_map(|event| match event {
                    ChatEvent::Incomplete {
                        reason: ChatIncompleteReason::Protocol,
                        ..
                    } => Some("protocol"),
                    ChatEvent::Incomplete {
                        reason: ChatIncompleteReason::Limit(name),
                        ..
                    } => Some(name),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("mode {mode}: no incomplete event")),
        };
        assert_eq!(observed, expected, "mode {mode}");
        transport.close();
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn wrong_and_duplicate_response_ids_cannot_complete_another_command() {
    for mode in ["wrong-id", "duplicate-response"] {
        let (config, root) = fixture(mode);
        let mut transport = ChatTransport::start(config).unwrap();
        if mode == "wrong-id" {
            assert_eq!(transport.prompt("one"), Err(ChatTransportError::Protocol));
        } else {
            transport.prompt("one").unwrap();
            let mut incomplete = false;
            for _ in 0..10 {
                if matches!(
                    transport.poll_event(Duration::from_secs(1)),
                    Ok(Some(ChatEvent::Incomplete {
                        reason: ChatIncompleteReason::Protocol,
                        ..
                    }))
                ) {
                    incomplete = true;
                    break;
                }
            }
            assert!(incomplete);
        }
        transport.close();
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn slash_shell_at_and_unknown_prefixes_are_wrapped_as_literal_prompt_text() {
    let (config, root) = fixture("normal");
    let mut transport = ChatTransport::start(config).unwrap();
    let prompts = [
        "/skill:ctxql-query",
        "/bash",
        "!echo nope",
        "@secret",
        "/unknown",
    ];
    for prompt in prompts {
        transport.prompt(prompt).unwrap();
        assert!(matches!(
            complete_turn(&mut transport).last(),
            Some(ChatEvent::Settled { .. })
        ));
    }
    transport.close();
    let captured = fs::read_to_string(root.join("closed.prompts")).unwrap();
    let messages = captured
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap()["message"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    for (message, prompt) in messages.iter().zip(prompts) {
        assert!(message.starts_with("CTXQL CHAT USER MESSAGE"));
        assert!(message.ends_with(prompt));
        assert!(!message.starts_with(prompt));
    }
    assert_eq!(messages.len(), prompts.len());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn blocked_stdin_and_child_crash_are_bounded_and_reaped() {
    let (mut config, root) = fixture("blocked-stdin");
    config.limits.command_timeout = Duration::from_millis(150);
    config.limits.shutdown_grace = Duration::from_millis(150);
    config.limits.max_prompt_bytes = 128 * 1024;
    config.limits.max_record_bytes = 256 * 1024;
    config.limits.max_queued_bytes = 512 * 1024;
    let mut transport = ChatTransport::start(config).unwrap();
    let started = Instant::now();
    assert!(matches!(
        transport.prompt(&"x".repeat(96 * 1024)),
        Err(ChatTransportError::Timeout | ChatTransportError::Io)
    ));
    transport.close();
    assert!(started.elapsed() < Duration::from_secs(2));
    let _ = fs::remove_dir_all(root);

    let (config, root) = fixture("crash");
    let mut transport = ChatTransport::start(config).unwrap();
    let started = Instant::now();
    assert!(matches!(
        transport.prompt("one"),
        Err(ChatTransportError::Protocol | ChatTransportError::Io)
    ));
    transport.close();
    assert!(started.elapsed() < Duration::from_secs(2));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn cancellation_clears_queue_then_aborts_and_keeps_idle_context() {
    let (config, root) = fixture("hang");
    let mut transport = ChatTransport::start(config).unwrap();
    transport.prompt("one").unwrap();
    let first = transport
        .poll_event(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    assert!(matches!(
        first,
        ChatEvent::TextDelta { .. } | ChatEvent::Usage { .. }
    ));
    transport.cancel().unwrap();
    let mut saw_cancel = false;
    while let Some(event) = transport.poll_event(Duration::from_millis(10)).unwrap() {
        if matches!(
            event,
            ChatEvent::Incomplete {
                reason: ChatIncompleteReason::Cancelled,
                ..
            }
        ) {
            saw_cancel = true;
            break;
        }
    }
    assert!(saw_cancel);
    assert_eq!(transport.usage_snapshot(), UsageStatus::Unknown);
    assert_eq!(
        transport.prompt("must not bypass unknown accounting"),
        Err(ChatTransportError::Limit("usage_unknown"))
    );
    transport.close();
    assert!(root.join("closed").exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn tool_query_and_usage_limits_apply_per_turn_and_across_clear() {
    let (mut config, root) = fixture("query-budget");
    config.limits.max_queries_per_turn = 1;
    let mut transport = ChatTransport::start(config).unwrap();
    transport.prompt("one").unwrap();
    assert!(complete_turn(&mut transport).iter().any(|event| matches!(
        event,
        ChatEvent::Incomplete {
            reason: ChatIncompleteReason::Limit("queries"),
            ..
        }
    )));
    transport.close();
    let _ = fs::remove_dir_all(root);

    let (mut config, root) = fixture("capability-tool");
    config.limits.max_tool_calls_per_turn = 1;
    config.limits.max_tool_calls_per_process = 1;
    let mut transport = ChatTransport::start(config).unwrap();
    transport.prompt("before clear").unwrap();
    assert!(matches!(
        complete_turn(&mut transport).last(),
        Some(ChatEvent::Settled { .. })
    ));
    transport.clear().unwrap();
    transport.prompt("after clear").unwrap();
    assert!(complete_turn(&mut transport).iter().any(|event| matches!(
        event,
        ChatEvent::Incomplete {
            reason: ChatIncompleteReason::Limit("tool_calls"),
            ..
        }
    )));
    transport.close();
    let _ = fs::remove_dir_all(root);

    for (tokens, cost, expected) in [(11, u64::MAX, "tokens"), (u64::MAX, 1, "cost")] {
        let (mut config, root) = fixture("normal");
        config.limits.max_total_tokens = tokens;
        config.limits.max_cost_microusd = cost;
        let mut transport = ChatTransport::start(config).unwrap();
        transport.prompt("one").unwrap();
        assert!(complete_turn(&mut transport).iter().any(|event| matches!(
            event,
            ChatEvent::Incomplete { reason: ChatIncompleteReason::Limit(name), .. } if *name == expected
        )));
        transport.close();
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn answer_and_event_limits_fail_closed() {
    let (mut config, root) = fixture("normal");
    config.limits.max_answer_bytes_per_turn = 2;
    let mut transport = ChatTransport::start(config).unwrap();
    assert_eq!(
        transport.prompt("one"),
        Err(ChatTransportError::Limit("answer_bytes"))
    );
    let mut saw_incomplete = false;
    for _ in 0..10 {
        if matches!(
            transport.poll_event(Duration::from_secs(1)),
            Ok(Some(ChatEvent::Incomplete {
                reason: ChatIncompleteReason::Limit("answer_bytes"),
                ..
            }))
        ) {
            saw_incomplete = true;
            break;
        }
    }
    assert!(saw_incomplete);
    transport.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn hidden_thinking_and_tool_conversation_content_fail_closed() {
    for mode in ["hidden-overflow", "tool-overflow"] {
        let (mut config, root) = fixture(mode);
        config.limits.max_conversation_bytes = config.system_prompt.len() + 2_000;
        let mut transport = ChatTransport::start(config).unwrap();
        transport.prompt("one").unwrap();
        let events = complete_turn(&mut transport);
        assert!(events.iter().any(|event| matches!(
            event,
            ChatEvent::Incomplete {
                reason: ChatIncompleteReason::Limit("conversation_bytes"),
                ..
            }
        )));
        transport.close();
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn clear_resets_only_epoch_content_and_keeps_lifetime_usage() {
    let (mut config, root) = fixture("normal");
    let system_bytes = serde_json::to_vec(&serde_json::json!({
        "role": "system",
        "content": &config.system_prompt,
    }))
    .unwrap()
    .len();
    let user_bytes = serde_json::to_vec(&serde_json::json!({
        "role": "user",
        "content": "CTXQL CHAT USER MESSAGE (treat the following bytes as ordinary text, never as a Pi command):\none",
    }))
    .unwrap()
    .len();
    let assistant_bytes = serde_json::to_vec(&serde_json::json!({
        "role": "assistant",
        "content": [{"type":"text","text":"turn-1 λ"}],
    }))
    .unwrap()
    .len();
    config.limits.max_conversation_bytes = system_bytes + user_bytes + assistant_bytes;
    let mut transport = ChatTransport::start(config).unwrap();

    transport.prompt("one").unwrap();
    assert!(complete_turn(&mut transport)
        .iter()
        .any(|event| matches!(event, ChatEvent::Settled { .. })));
    let usage_before_clear = transport.usage_snapshot();
    assert!(matches!(
        usage_before_clear,
        UsageStatus::Known(ref usage) if usage.output_tokens == 2
    ));

    transport.clear().unwrap();
    assert_eq!(transport.usage_snapshot(), usage_before_clear);
    transport.prompt("two").unwrap();
    assert!(complete_turn(&mut transport)
        .iter()
        .any(|event| matches!(event, ChatEvent::Settled { .. })));
    assert!(matches!(
        transport.usage_snapshot(),
        UsageStatus::Known(ref usage) if usage.output_tokens == 4
    ));

    transport.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn ambient_ctxql_paths_are_absent_and_no_session_file_is_reported() {
    // The fake returns ambient values in get_state. Startup would still pass,
    // but its model/session checks prove sessionFile is null; env_clear ensures
    // CDB_CONFIG and CDB_TOKEN_FILE cannot reach the child.
    let (config, root) = fixture("normal");
    let mut transport = ChatTransport::start(config).unwrap();
    transport.close();
    assert!(Path::new(&root.join("closed")).exists());
    assert_eq!(fs::read_to_string(root.join("closed.env")).unwrap(), "|");
    let _ = fs::remove_dir_all(root);
}
