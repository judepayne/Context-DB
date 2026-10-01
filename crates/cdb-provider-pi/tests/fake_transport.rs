#![cfg(unix)]

use cdb_provider_pi::agent_bundle::hash_agent_bundle;
use cdb_provider_pi::cancel::CancellationToken;
use cdb_provider_pi::ontology_bridge::{OntologyBridgeConfig, OntologyToolError, OntologyToolHost};
use cdb_provider_pi::parser::{ParseLimits, ParsedOutput};
use cdb_provider_pi::provider::PiProvider;
use cdb_provider_pi::transport::{
    ExtractionProtocol, PiTransport, TransportConfig, TransportError, TransportLimits,
};
use cdb_provider_pi::{SessionLogging, MODEL};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

struct NoLookup;
impl OntologyToolHost for NoLookup {
    fn lookup(&self, _: &serde_json::Value) -> Result<serde_json::Value, OntologyToolError> {
        Err(OntologyToolError::Denied)
    }
}

fn fake(model: &str, hang: bool, tool_events: usize, claim: bool) -> (PiTransport, PathBuf) {
    fake_with_skill(model, hang, tool_events, claim, "none")
}

fn fake_with_skill(
    model: &str,
    hang: bool,
    tool_events: usize,
    claim: bool,
    skill: &str,
) -> (PiTransport, PathBuf) {
    fake_config(
        model,
        hang,
        tool_events,
        claim,
        skill,
        ExtractionProtocol::LegacyV1,
        false,
    )
}

fn fake_graph(skill: &str, tool_events: usize) -> (PiTransport, PathBuf) {
    fake_config(
        MODEL,
        false,
        tool_events,
        false,
        skill,
        ExtractionProtocol::ProposalsV2,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn fake_config(
    model: &str,
    hang: bool,
    tool_events: usize,
    claim: bool,
    skill: &str,
    protocol: ExtractionProtocol,
    graph_workspace: bool,
) -> (PiTransport, PathBuf) {
    let dir =
        std::env::temp_dir().join(format!("ctxql-fake-pi-{}-{}", std::process::id(), unique()));
    fs::create_dir_all(&dir).unwrap();
    let script = dir.join("fake-pi");
    fs::write(&script, r#"#!/bin/sh
previous=
for argument in "$@"; do
  if [ "$previous" = "--session-dir" ]; then
    mkdir -p "$argument"
    printf '{"type":"session","version":3,"id":"fake","cwd":"fake"}\n' > "$argument/fake-session.jsonl"
  fi
  previous="$argument"
done
while IFS= read -r line; do
  id=${line#*\"id\":\"}; id=${id%%\"*}
  case "$line" in
    *new_session*) printf '{"type":"response","id":"%s","success":true,"data":{}}\n' "$id" ;;
    *get_session_stats*) printf '{"type":"response","id":"%s","success":true,"data":{"input_tokens":10,"output_tokens":2,"cost_microusd":3}}\n' "$id" ;;
    *prompt*)
      if [ "$CDB_FAKE_HANG" = "1" ]; then while :; do IFS= read -r ignored || :; done; fi
      if [ "$CDB_FAKE_SKILL" = "logging_invalid_rpc" ]; then
        printf '{invalid-json}\n'
        exit 0
      fi
      case "$CDB_FAKE_SKILL" in
        success|fact_success|logging)
          printf '{"type":"tool_execution_start","toolCallId":"skill-1","toolName":"ctxql_skill","args":{"name":"read-loan-agreement"}}\n'
          printf '{"type":"tool_execution_end","toolCallId":"skill-1","toolName":"ctxql_skill","isError":false}\n'
          ;;
        error)
          printf '{"type":"tool_execution_start","toolCallId":"skill-1","toolName":"ctxql_skill","args":{"name":"read-loan-agreement"}}\n'
          printf '{"type":"tool_execution_end","toolCallId":"skill-1","toolName":"ctxql_skill","isError":true}\n'
          ;;
        unmatched)
          printf '{"type":"tool_execution_start","toolCallId":"skill-1","toolName":"ctxql_skill","args":{"name":"read-loan-agreement"}}\n'
          printf '{"type":"tool_execution_end","toolCallId":"other-1","toolName":"ctxql_skill","isError":false}\n'
          ;;
        graph_success|graph_missing|graph_error|graph_unmatched|graph_ctxql-ontology_missing|graph_ctxql-query_missing)
          printf '{"type":"tool_execution_start","toolCallId":"loan-v2","toolName":"ctxql_skill","args":{"name":"read-loan-agreement-v2"}}\n'
          printf '{"type":"tool_execution_end","toolCallId":"loan-v2","toolName":"ctxql_skill","isError":false}\n'
          if [ "$CDB_FAKE_SKILL" != "graph_missing" ]; then
            for shared in ctxql-ontology ctxql-query; do
              if [ "$CDB_FAKE_SKILL" = "graph_${shared}_missing" ]; then continue; fi
              printf '{"type":"tool_execution_start","toolCallId":"%s-v2","toolName":"ctxql_skill","args":{"name":"%s"}}\n' "$shared" "$shared"
              printf '{"type":"tool_execution_end","toolCallId":"%s-v2","toolName":"ctxql_skill","isError":false}\n' "$shared"
            done
            printf '{"type":"tool_execution_start","toolCallId":"graph-v2","toolName":"ctxql_skill","args":{"name":"graph-workspace"}}\n'
            if [ "$CDB_FAKE_SKILL" = "graph_error" ]; then
              printf '{"type":"tool_execution_end","toolCallId":"graph-v2","toolName":"ctxql_skill","isError":true}\n'
            elif [ "$CDB_FAKE_SKILL" = "graph_unmatched" ]; then
              printf '{"type":"tool_execution_end","toolCallId":"other-v2","toolName":"ctxql_skill","isError":false}\n'
            else
              printf '{"type":"tool_execution_end","toolCallId":"graph-v2","toolName":"ctxql_skill","isError":false}\n'
            fi
          fi
          ;;
      esac
      n=0
      while [ "$n" -lt "$CDB_FAKE_TOOLS" ]; do
        printf '{"type":"tool_execution_start","toolCallId":"bounded-%s","toolName":"ctxql_ontology","args":{}}\n' "$n"
        printf '{"type":"tool_execution_end","toolCallId":"bounded-%s","toolName":"ctxql_ontology","isError":false}\n' "$n"
        n=$((n + 1))
      done
      printf '{"type":"response","id":"%s","success":true,"data":{}}\n' "$id"
      if [ "$CDB_FAKE_V2" = "1" ]; then
        printf '{"type":"agent_end","model":"%s","messages":[{"role":"assistant","text":"{\\"schema\\":\\"ctxql-extraction-proposals/v2\\",\\"no_claims\\":false,\\"entities\\":[],\\"attributes\\":[],\\"relations\\":[]}"}]}\n' "$CDB_FAKE_MODEL"
      elif [ "$CDB_FAKE_SKILL" = "fact" ] || [ "$CDB_FAKE_SKILL" = "fact_success" ]; then
        printf '{"type":"agent_end","model":"%s","messages":[{"role":"assistant","text":"FACT:"}]}\n' "$CDB_FAKE_MODEL"
      elif [ "$CDB_FAKE_CLAIM" = "1" ]; then
        printf '{"type":"agent_end","model":"%s","messages":[{"role":"assistant","text":"CLAIM:"}]}\n' "$CDB_FAKE_MODEL"
      else
        printf '{"type":"agent_end","model":"%s","messages":[{"role":"assistant","text":"NO_CLAIMS"}]}\n' "$CDB_FAKE_MODEL"
      fi
      ;;
  esac
done
"#).unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&script, perms).unwrap();
    let assets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/pi");
    let bundle = hash_agent_bundle(assets).unwrap();
    let system_prompt = match protocol {
        ExtractionProtocol::LegacyV1 => bundle.system_prompt().unwrap(),
        ExtractionProtocol::ProposalsV2 => bundle.system_prompt_v2().unwrap(),
    };
    let config = TransportConfig {
        command: script,
        env: vec![
            ("CDB_FAKE_MODEL".into(), model.into()),
            ("CDB_FAKE_HANG".into(), if hang { "1" } else { "0" }.into()),
            ("CDB_FAKE_TOOLS".into(), tool_events.to_string()),
            (
                "CDB_FAKE_CLAIM".into(),
                if claim { "1" } else { "0" }.into(),
            ),
            ("CDB_FAKE_SKILL".into(), skill.into()),
            (
                "CDB_FAKE_V2".into(),
                if protocol == ExtractionProtocol::ProposalsV2 {
                    "1"
                } else {
                    "0"
                }
                .into(),
            ),
            (
                "CTXQL_GRAPH_WORKSPACE_ENABLED".into(),
                if graph_workspace { "1" } else { "0" }.into(),
            ),
        ],
        system_prompt,
        protocol,
        bundle,
        ontology_bridge: OntologyBridgeConfig {
            host: Arc::new(NoLookup),
            max_request_bytes: 4096,
            max_response_bytes: 4096,
        },
        limits: TransportLimits {
            timeout: if hang {
                Duration::from_millis(300)
            } else {
                Duration::from_secs(2)
            },
            max_tool_calls: if graph_workspace {
                128
            } else if tool_events == 0 {
                32
            } else {
                1
            },
            ..TransportLimits::default()
        },
        session_logging: skill.starts_with("logging").then(|| SessionLogging {
            root: dir.join("logs"),
        }),
    };
    (PiTransport::new(config).unwrap(), dir)
}
static UNIQUE: AtomicU64 = AtomicU64::new(1);
fn unique() -> u128 {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    time.saturating_add(UNIQUE.fetch_add(1, Ordering::Relaxed) as u128)
}

#[test]
fn warm_process_uses_fresh_sessions_and_deduplicated_content_free_usage() {
    let (transport, dir) = fake(MODEL, false, 0, false);
    let cancel = CancellationToken::default();
    assert_eq!(transport.request("one", &cancel).unwrap().text, "NO_CLAIMS");
    assert_eq!(transport.request("two", &cancel).unwrap().text, "NO_CLAIMS");
    let usage = transport.usage();
    assert_eq!(
        (
            usage.requests,
            usage.input_tokens,
            usage.output_tokens,
            usage.cost_microusd
        ),
        (2, 20, 4, 6)
    );
    transport.teardown();
    let _ = fs::remove_dir_all(dir);
}

fn host_diagnostic(dir: &std::path::Path) -> String {
    let host = fs::read_dir(dir.join("logs"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("host-extraction-")
        })
        .unwrap();
    fs::read_to_string(host.path()).unwrap()
}

#[test]
fn extraction_failure_diagnostics_distinguish_timeout_and_missing_skill() {
    let (timeout, timeout_dir) = fake_config(
        MODEL,
        true,
        0,
        false,
        "logging_timeout",
        ExtractionProtocol::LegacyV1,
        false,
    );
    assert_eq!(
        timeout
            .request("timeout probe", &CancellationToken::default())
            .unwrap_err(),
        TransportError::Timeout
    );
    assert!(host_diagnostic(&timeout_dir).contains("\"outcome\":\"rejected_timeout\""));
    timeout.teardown();
    let _ = fs::remove_dir_all(timeout_dir);

    let (missing, missing_dir) = fake_config(
        MODEL,
        false,
        0,
        true,
        "logging_missing_skill",
        ExtractionProtocol::LegacyV1,
        false,
    );
    assert_eq!(
        missing
            .request("skill probe", &CancellationToken::default())
            .unwrap_err(),
        TransportError::MissingSkill
    );
    let diagnostic = host_diagnostic(&missing_dir);
    assert!(diagnostic.contains("\"event\":\"extraction_agent_end\""));
    assert!(diagnostic.contains("\"outcome\":\"rejected_missing_skill\""));
    missing.teardown();
    let _ = fs::remove_dir_all(missing_dir);

    let (invalid, invalid_dir) = fake_config(
        MODEL,
        false,
        0,
        false,
        "logging_invalid_rpc",
        ExtractionProtocol::LegacyV1,
        false,
    );
    assert_eq!(
        invalid
            .request("invalid RPC probe", &CancellationToken::default())
            .unwrap_err(),
        TransportError::Rpc
    );
    let diagnostic = host_diagnostic(&invalid_dir);
    assert!(diagnostic.contains("\"event\":\"extraction_rpc_framing\""));
    assert!(diagnostic.contains("\"outcome\":\"invalid_json\""));
    assert!(diagnostic.contains("\"outcome\":\"rejected_rpc\""));
    invalid.teardown();
    let _ = fs::remove_dir_all(invalid_dir);
}

#[test]
fn extraction_session_logging_retains_native_session_and_host_outcome() {
    let (transport, dir) = fake_with_skill(MODEL, false, 0, false, "logging");
    let reply = transport
        .request("sensitive extraction prompt", &CancellationToken::default())
        .unwrap();
    assert_eq!(reply.text, "NO_CLAIMS");
    transport.teardown();

    let logs = dir.join("logs");
    let entries = fs::read_dir(&logs)
        .unwrap()
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    assert!(entries
        .iter()
        .any(|entry| entry.file_type().unwrap().is_dir()));
    let host = entries
        .iter()
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("host-extraction-")
        })
        .unwrap();
    let diagnostics = fs::read_to_string(host.path()).unwrap();
    assert!(diagnostics.contains("extraction_request"));
    assert!(diagnostics.contains("\"outcome\":\"ok\""));
    assert!(!diagnostics.contains("sensitive extraction prompt"));
    let native = entries
        .iter()
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .flat_map(|entry| fs::read_dir(entry.path()).unwrap().filter_map(Result::ok))
        .any(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("jsonl"));
    assert!(native);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn single_window_no_claims_does_not_make_a_fallback_request() {
    let (transport, dir) = fake(MODEL, false, 0, false);
    let provider = PiProvider::new(transport, ParseLimits::default());
    let requests = vec![("w1".to_owned(), "one".to_owned())];
    let outcomes =
        provider.extract_batch_with_fallback("one", &requests, &CancellationToken::default());
    assert!(matches!(
        outcomes[0].output,
        Ok(ParsedOutput::NoClaims { .. })
    ));
    assert_eq!(provider.usage().requests, 1);
    provider.teardown();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn batch_failure_falls_back_to_each_window_once() {
    let (transport, dir) = fake(MODEL, false, 0, false);
    let provider = PiProvider::new(transport, ParseLimits::default());
    let requests = vec![
        ("w1".to_owned(), "one".to_owned()),
        ("w2".to_owned(), "two".to_owned()),
    ];
    let (outcomes, captured) = provider.extract_batch_with_fallback_captured(
        "batch",
        &requests,
        &CancellationToken::default(),
    );
    assert_eq!(outcomes.len(), 2);
    assert_eq!(captured.len(), 3);
    assert_eq!(captured[0].phase, "batch");
    assert_eq!(captured[0].text.as_deref(), Some("NO_CLAIMS"));
    assert!(captured[0].parse_error.is_some());
    assert!(captured[0].transport_error.is_none());
    assert!(captured[1..].iter().all(|response| {
        response.phase == "individual"
            && response.text.as_deref() == Some("NO_CLAIMS")
            && response.transport_error.is_none()
    }));
    assert!(outcomes
        .iter()
        .all(|outcome| matches!(outcome.output, Ok(ParsedOutput::NoClaims { .. }))));
    assert_eq!(provider.usage().requests, 3);
    provider.teardown();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn captured_fallback_retains_content_free_transport_failures() {
    let (transport, dir) = fake("other/model", false, 0, false);
    let provider = PiProvider::new(transport, ParseLimits::default());
    let requests = vec![
        ("w1".to_owned(), "one".to_owned()),
        ("w2".to_owned(), "two".to_owned()),
    ];
    let (outcomes, captured) = provider.extract_batch_with_fallback_captured(
        "batch",
        &requests,
        &CancellationToken::default(),
    );
    assert_eq!(captured.len(), 3);
    assert_eq!(captured[0].phase, "batch");
    assert_eq!(captured[0].window_ids, vec!["w1", "w2"]);
    assert!(captured.iter().all(|response| {
        response.text.is_none()
            && response.parse_error.is_none()
            && response.transport_error == Some(TransportError::ModelMismatch)
    }));
    assert!(outcomes.iter().all(|outcome| matches!(
        outcome.output,
        Err(cdb_provider_pi::provider::ProviderError::Transport(
            TransportError::ModelMismatch
        ))
    )));
    provider.teardown();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn model_substitution_fails_closed() {
    let (transport, dir) = fake("other/model", false, 0, false);
    assert_eq!(
        transport
            .request("one", &CancellationToken::default())
            .unwrap_err(),
        TransportError::ModelMismatch
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn cancellation_tears_down_the_blocked_child() {
    let (transport, dir) = fake(MODEL, true, 0, false);
    let token = CancellationToken::default();
    let trigger = token.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(40));
        trigger.cancel();
    });
    assert_eq!(
        transport.request("one", &token).unwrap_err(),
        TransportError::Cancelled
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn timeout_tears_down_the_blocked_child() {
    let (transport, dir) = fake(MODEL, true, 0, false);
    assert_eq!(
        transport
            .request("one", &CancellationToken::default())
            .unwrap_err(),
        TransportError::Timeout
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn fact_output_requires_a_correlated_successful_skill_call() {
    let (transport, dir) = fake_with_skill(MODEL, false, 0, false, "fact");
    assert_eq!(
        transport
            .request("one", &CancellationToken::default())
            .unwrap_err(),
        TransportError::MissingSkill
    );
    transport.teardown();
    let _ = fs::remove_dir_all(dir);

    let (transport, dir) = fake_with_skill(MODEL, false, 0, false, "fact_success");
    assert_eq!(
        transport
            .request("one", &CancellationToken::default())
            .unwrap()
            .text,
        "FACT:"
    );
    transport.teardown();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn claim_output_without_the_required_skill_call_fails_closed() {
    let (transport, dir) = fake(MODEL, false, 0, true);
    assert_eq!(
        transport
            .request("one", &CancellationToken::default())
            .unwrap_err(),
        TransportError::MissingSkill
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn claim_output_requires_a_successful_matching_skill_end_event() {
    let (transport, dir) = fake_with_skill(MODEL, false, 0, true, "success");
    assert_eq!(
        transport
            .request("one", &CancellationToken::default())
            .unwrap()
            .text,
        "CLAIM:"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn failed_skill_end_event_does_not_authorize_claim_output() {
    let (transport, dir) = fake_with_skill(MODEL, false, 0, true, "error");
    assert_eq!(
        transport
            .request("one", &CancellationToken::default())
            .unwrap_err(),
        TransportError::MissingSkill
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unmatched_skill_end_event_does_not_authorize_claim_output() {
    let (transport, dir) = fake_with_skill(MODEL, false, 0, true, "unmatched");
    assert_eq!(
        transport
            .request("one", &CancellationToken::default())
            .unwrap_err(),
        TransportError::MissingSkill
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn tool_call_bound_fails_closed_and_tears_down() {
    let (transport, dir) = fake(MODEL, false, 2, false);
    assert_eq!(
        transport
            .request("one", &CancellationToken::default())
            .unwrap_err(),
        TransportError::Limit("tool_calls")
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn graph_enabled_v2_requires_both_correlated_skills() {
    let (transport, dir) = fake_graph("graph_success", 0);
    let reply = transport
        .request("one", &CancellationToken::default())
        .unwrap();
    assert!(reply.text.contains("ctxql-extraction-proposals/v2"));
    transport.teardown();
    let _ = fs::remove_dir_all(dir);

    for mode in [
        "graph_missing",
        "graph_error",
        "graph_unmatched",
        "graph_ctxql-ontology_missing",
        "graph_ctxql-query_missing",
    ] {
        let (transport, dir) = fake_graph(mode, 0);
        assert_eq!(
            transport
                .request("one", &CancellationToken::default())
                .unwrap_err(),
            TransportError::MissingSkill,
            "{mode}"
        );
        let _ = fs::remove_dir_all(dir);
    }
}

#[test]
fn graph_enabled_transport_caps_all_tool_calls_at_forty() {
    // Four required skill calls plus 36 host calls consume the full budget.
    let (transport, dir) = fake_graph("graph_success", 36);
    transport
        .request("one", &CancellationToken::default())
        .unwrap();
    transport.teardown();
    let _ = fs::remove_dir_all(dir);

    let (transport, dir) = fake_graph("graph_success", 37);
    assert_eq!(
        transport
            .request("one", &CancellationToken::default())
            .unwrap_err(),
        TransportError::Limit("tool_calls")
    );
    let _ = fs::remove_dir_all(dir);
}
