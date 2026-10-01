use super::*;
use crate::{
    acquisition_v2_fixture::AcquisitionV2Fixture,
    chat::bridge::ChatToolHost,
    config::{ArtifactReference, ChatConfig, ChatLimits},
    Service,
};
use cdb_core::{
    artifact::{ArtifactRef, PublishedArtifact},
    contracts::{GraphBackend, SemanticProjectionSource},
    id::{ContentHash, Iri, VersionId},
    Limits,
};
use cdb_provider_pi::{
    agent_bundle::{hash_agent_bundle_for_profile, BundleProfile},
    chat_transport::{
        ChatEvent, ChatTransport, ChatTransportConfig, ChatTransportLimits, UsageStatus,
    },
    ontology_bridge::{OntologyBridgeConfig, OntologyToolError, OntologyToolHost, ToolCapability},
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const OPT_IN: &str = "CDB_RUN_PAID_CHAT_QUALITY";
const OUTPUT_ENV: &str = "CDB_PAID_CHAT_OUTPUT";
const PI_COMMAND_ENV: &str = "CDB_PAID_CHAT_PI_COMMAND";
const FIXTURE_ENV: &str = "CDB_PAID_CHAT_FIXTURES";
const PREFLIGHT_ONLY_ENV: &str = "CDB_PAID_CHAT_PREFLIGHT_ONLY";
const MAX_COST_MICRO_USD: u64 = 500_000;
// Four high-thinking questions count repeated prompt/cache tokens too. Keep a
// finite ceiling below the production default alongside the $0.50 cost stop.
const MAX_REPORTED_TOKENS: u64 = 65_536;

#[derive(Clone, Debug)]
struct ToolRecord {
    turn: usize,
    tool: String,
    request: Value,
    result: Option<Value>,
    error: Option<String>,
}

struct RecordingHost {
    inner: Arc<ChatToolHost>,
    turn: Mutex<usize>,
    records: Mutex<Vec<ToolRecord>>,
}

impl RecordingHost {
    fn new(inner: Arc<ChatToolHost>) -> Self {
        Self {
            inner,
            turn: Mutex::new(0),
            records: Mutex::new(Vec::new()),
        }
    }

    fn begin_turn(&self, turn: usize) {
        *self.turn.lock().unwrap_or_else(|error| error.into_inner()) = turn;
        self.inner.begin_turn();
    }

    fn end_turn(&self) {
        self.inner.end_turn();
    }

    fn records(&self) -> Vec<ToolRecord> {
        self.records
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn record(
        &self,
        tool: &str,
        request: &Value,
        result: &std::result::Result<Value, OntologyToolError>,
    ) {
        let turn = *self.turn.lock().unwrap_or_else(|error| error.into_inner());
        self.records
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(ToolRecord {
                turn,
                tool: tool.to_owned(),
                request: request.clone(),
                result: result.as_ref().ok().cloned(),
                error: result.as_ref().err().map(|error| format!("{error:?}")),
            });
    }
}

impl OntologyToolHost for RecordingHost {
    fn lookup(&self, request: &Value) -> std::result::Result<Value, OntologyToolError> {
        let result = self.inner.lookup(request);
        self.record("ctxql_ontology", request, &result);
        result
    }

    fn invoke(
        &self,
        capability: ToolCapability,
        call_id: &str,
        request: &Value,
    ) -> std::result::Result<Value, OntologyToolError> {
        let tool = match capability {
            ToolCapability::Capabilities => "ctxql_capabilities",
            ToolCapability::Ontology => "ctxql_ontology",
            ToolCapability::GraphQuery => "ctxql_graph_query",
            ToolCapability::Source => "ctxql_source",
            ToolCapability::Entities => "ctxql_entities",
            ToolCapability::GraphPlayground => "ctxql_graph_playground",
        };
        let result = self.inner.invoke(capability, call_id, request);
        self.record(tool, request, &result);
        result
    }

    fn cancel(&self, call_id: &str) -> std::result::Result<(), OntologyToolError> {
        self.inner.cancel(call_id)
    }
}

#[derive(Debug)]
struct TurnCapture {
    question: String,
    answer: String,
    events: Vec<Value>,
    terminal: Value,
    queries: Vec<(String, String)>,
}

#[derive(Debug)]
struct LiveCapture {
    turns: Vec<TurnCapture>,
    tools: Vec<ToolRecord>,
    usage: UsageStatus,
    failure: Option<String>,
}

async fn publish_artifact(
    service: &Arc<Service>,
    token: &str,
    iri: &str,
    content: &[u8],
) -> ArtifactRef {
    let reference = ArtifactRef::new(
        Iri::new(iri).unwrap(),
        VersionId::new("1").unwrap(),
        ContentHash::of_bytes(content),
    );
    let published =
        PublishedArtifact::new(reference.clone(), content.to_vec(), Limits::default()).unwrap();
    let artifact: Value = serde_json::from_slice(
        &published
            .reference()
            .projection()
            .canonical_bytes(Limits::default())
            .unwrap(),
    )
    .unwrap();
    service
        .dispatch(
            token,
            &serde_json::to_vec(&json!({
                "schema":"ctxql-service/v1",
                "op":"publish",
                "artifact":artifact,
                "content":String::from_utf8(published.content().to_vec()).unwrap()
            }))
            .unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap();
    reference
}

fn chat_config(fixture: &AcquisitionV2Fixture, query_config: &ArtifactRef) -> InstanceConfig {
    let mut config = fixture.config().unwrap();
    let acquisition = config.acquisition.take().unwrap();
    config.schema = "ctxql-instance/v3".into();
    let reference = ArtifactReference {
        iri: query_config.iri().as_str().into(),
        version: query_config.version().as_str().into(),
        hash: query_config.hash().as_str().into(),
    };
    let limits = ChatLimits {
        max_turns: 4,
        max_model_rounds: 16,
        turn_seconds: 90,
        max_reported_tokens: MAX_REPORTED_TOKENS as usize,
        max_reported_cost_micro_usd: MAX_COST_MICRO_USD as usize,
        max_tool_calls_per_turn: 16,
        max_queries_per_turn: 6,
        max_tool_calls: 32,
        max_queries: 12,
        ..ChatLimits::default()
    };
    let pi_command =
        PathBuf::from(std::env::var_os(PI_COMMAND_ENV).expect("paid Pi command path missing"));
    assert!(pi_command.is_absolute());
    assert!(pi_command.is_file());
    config.chat = Some(ChatConfig {
        unsafe_direct_projection: false,
        // Fixture extraction uses a fake executable; the explicitly opted-in
        // paid chat must name the installed Pi, never that fixture double.
        pi_command,
        pi_bundle: acquisition.pi_bundle,
        pi_session_log_dir: None,
        chat_model: cdb_provider_pi::MODEL.into(),
        thinking: cdb_provider_pi::THINKING.into(),
        query_config: reference,
        profile_selector: None,
        profile: None,
        ontology: None,
        limits,
    });
    config.validate_runtime().unwrap();
    config
}

fn inventory(root: &Path) -> BTreeMap<String, Value> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<String, Value>) {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if path.is_dir() {
                visit(root, &path, out);
            } else {
                let bytes = fs::read(&path).unwrap();
                out.insert(
                    relative,
                    json!({"bytes":bytes.len(),"sha256":ContentHash::of_bytes(&bytes).as_str()}),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir(target).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if source_path.is_dir() {
            copy_tree(&source_path, &target_path);
        } else {
            fs::copy(source_path, target_path).unwrap();
        }
    }
}

fn usage_json(status: &UsageStatus) -> Value {
    match status {
        UsageStatus::Known(usage) => json!({
            "status":"known",
            "input_tokens":usage.input_tokens,
            "output_tokens":usage.output_tokens,
            "cache_read_tokens":usage.cache_read_tokens,
            "cache_write_tokens":usage.cache_write_tokens,
            "reported_tokens":usage.input_tokens.saturating_add(usage.output_tokens).saturating_add(usage.cache_read_tokens).saturating_add(usage.cache_write_tokens),
            "cost_micro_usd":usage.cost_microusd,
            "cost_usd":usage.cost_microusd as f64 / 1_000_000.0,
            "requests":usage.requests,
        }),
        UsageStatus::Unknown => json!({"status":"unknown"}),
    }
}

fn event_json(event: &ChatEvent) -> Value {
    match event {
        ChatEvent::TextDelta {
            identity,
            content_index,
            delta,
        } => {
            json!({"type":"text_delta","identity":{"message_id":identity.message_id,"provider":identity.provider,"model":identity.model},"content_index":content_index,"delta":delta})
        }
        ChatEvent::Progress { tool_name } => json!({"type":"progress","tool_name":tool_name}),
        ChatEvent::Usage { snapshot } => {
            json!({"type":"usage","snapshot":usage_json(&UsageStatus::Known(snapshot.clone()))})
        }
        ChatEvent::Settled { usage } => {
            json!({"type":"settled","usage":usage_json(&UsageStatus::Known(usage.clone()))})
        }
        ChatEvent::Incomplete { reason, usage } => {
            json!({"type":"incomplete","reason":format!("{reason:?}"),"usage":usage_json(usage)})
        }
    }
}

fn run_live(
    chat: ChatConfig,
    reads: Arc<ChatReadResources>,
    runtime: tokio::runtime::Handle,
    questions: Vec<String>,
) -> LiveCapture {
    let bundle = match hash_agent_bundle_for_profile(&chat.pi_bundle, BundleProfile::Chat) {
        Ok(bundle) => bundle,
        Err(error) => {
            return LiveCapture {
                turns: Vec::new(),
                tools: Vec::new(),
                usage: UsageStatus::Unknown,
                failure: Some(format!("verified bundle unavailable: {error:?}")),
            }
        }
    };
    let system_prompt = match bundle.chat_system_prompt() {
        Ok(prompt) => prompt,
        Err(error) => {
            return LiveCapture {
                turns: Vec::new(),
                tools: Vec::new(),
                usage: UsageStatus::Unknown,
                failure: Some(format!("verified prompt unavailable: {error:?}")),
            }
        }
    };
    let inner = Arc::new(ChatToolHost::new(reads.clone(), runtime, 32));
    let host = Arc::new(RecordingHost::new(inner));
    let key = match std::env::var("OPENROUTER_API_KEY") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            return LiveCapture {
                turns: Vec::new(),
                tools: Vec::new(),
                usage: UsageStatus::Unknown,
                failure: Some("OPENROUTER_API_KEY unavailable".into()),
            }
        }
    };
    let limits = ChatTransportLimits {
        command_timeout: Duration::from_secs(10),
        turn_timeout: Duration::from_secs(90),
        shutdown_grace: Duration::from_secs(2),
        max_user_turns_per_process: 4,
        max_model_rounds_per_process: 16,
        max_tool_calls_per_turn: 16,
        max_tool_calls_per_process: 32,
        max_queries_per_turn: 6,
        max_queries_per_process: 12,
        max_total_tokens: MAX_REPORTED_TOKENS,
        max_cost_microusd: MAX_COST_MICRO_USD,
        ..ChatTransportLimits::default()
    };
    let mut transport = match ChatTransport::start(ChatTransportConfig {
        command: chat.pi_command,
        environment: vec![("OPENROUTER_API_KEY".into(), key)],
        system_prompt,
        bundle,
        ontology_bridge: OntologyBridgeConfig {
            host: host.clone(),
            max_request_bytes: chat.limits.max_request_bytes,
            max_response_bytes: chat.limits.max_response_bytes,
        },
        limits,
        session_logging: chat
            .pi_session_log_dir
            .map(|root| cdb_provider_pi::SessionLogging { root }),
    }) {
        Ok(transport) => transport,
        Err(error) => {
            return LiveCapture {
                turns: Vec::new(),
                tools: host.records(),
                usage: UsageStatus::Unknown,
                failure: Some(format!("provider startup failed: {error:?}")),
            }
        }
    };
    let mut turns = Vec::new();
    let mut failure = None;
    for (index, question) in questions.into_iter().enumerate() {
        reads.begin_turn();
        host.begin_turn(index + 1);
        if let Err(error) = transport.prompt(&question) {
            host.end_turn();
            failure = Some(format!("turn {} prompt failed: {error:?}", index + 1));
            break;
        }
        let deadline = Instant::now() + Duration::from_secs(95);
        let mut answer = String::new();
        let mut events = Vec::new();
        let terminal = loop {
            if Instant::now() >= deadline {
                failure = Some(format!("turn {} outer deadline", index + 1));
                let _ = transport.cancel();
                break json!({"type":"outer_deadline"});
            }
            match transport.poll_event(Duration::from_millis(200)) {
                Ok(Some(event)) => {
                    if let ChatEvent::TextDelta { delta, .. } = &event {
                        answer.push_str(delta);
                    }
                    let encoded = event_json(&event);
                    let done = matches!(
                        event,
                        ChatEvent::Settled { .. } | ChatEvent::Incomplete { .. }
                    );
                    let failed = match &event {
                        ChatEvent::Incomplete { reason, usage } => Some(format!(
                            "turn {} incomplete: {reason:?}; usage={usage:?}",
                            index + 1
                        )),
                        _ => None,
                    };
                    events.push(encoded.clone());
                    if done {
                        if let Some(observed) = failed {
                            failure = Some(observed);
                        }
                        break encoded;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    failure = Some(format!("turn {} transport failed: {error:?}", index + 1));
                    break json!({"type":"transport_error","error":format!("{error:?}")});
                }
            }
        };
        host.end_turn();
        turns.push(TurnCapture {
            question,
            answer,
            events,
            terminal,
            queries: reads.last_queries(),
        });
        if failure.is_some() || matches!(transport.usage_snapshot(), UsageStatus::Unknown) {
            if failure.is_none() {
                failure = Some(format!("turn {} ended with unknown usage", index + 1));
            }
            break;
        }
    }
    let usage = transport.usage_snapshot();
    transport.close();
    LiveCapture {
        turns,
        tools: host.records(),
        usage,
        failure,
    }
}

fn find_citations(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut found = BTreeSet::new();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if bytes[index] == b'[' && matches!(bytes[index + 1], b'C' | b'S') {
            let mut end = index + 2;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > index + 2 && bytes.get(end) == Some(&b']') {
                found.insert(text[index..=end].to_owned());
                index = end + 1;
                continue;
            }
        }
        index += 1;
    }
    found
}

fn tool_records_json(records: &[ToolRecord]) -> Vec<Value> {
    records
        .iter()
        .map(|record| {
            json!({
                "turn":record.turn,
                "tool":record.tool,
                "request":record.request,
                "result":record.result,
                "error":record.error,
            })
        })
        .collect()
}

fn transcript_contains(records: &[ToolRecord], turn: usize, needle: &str) -> bool {
    records
        .iter()
        .filter(|record| record.turn == turn)
        .any(|record| {
            record
                .result
                .as_ref()
                .is_some_and(|value| value.to_string().contains(needle))
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit paid opt-in only: one bounded OpenRouter DeepSeek chat experiment"]
async fn paid_deepseek_chat_quality_once() {
    let preflight_only = std::env::var(PREFLIGHT_ONLY_ENV).as_deref() == Ok("1");
    if !preflight_only {
        assert_eq!(
            std::env::var(OPT_IN).as_deref(),
            Ok("AUTHORIZED_PAID_ONE_RUN"),
            "explicit one-run paid opt-in missing"
        );
        assert!(
            std::env::var_os("OPENROUTER_API_KEY").is_some(),
            "provider key missing"
        );
    }
    let output_parent =
        PathBuf::from(std::env::var_os(OUTPUT_ENV).expect("paid output path missing"));
    assert!(output_parent.is_absolute());
    fs::create_dir_all(&output_parent).unwrap();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let run_dir = output_parent.join(format!(
        "deepseek-v4.1-flash-{unique}-{}",
        std::process::id()
    ));
    fs::create_dir(&run_dir).unwrap();

    // Preparation is entirely hermetic and fake-provider-backed. No paid call is
    // possible before ChatTransport::start below.
    let fixture_files = PathBuf::from(
        std::env::var_os(FIXTURE_ENV).expect("paid checked-fixture directory missing"),
    );
    assert!(fixture_files.is_absolute());
    // The checked fixture path remains an explicit operator binding, but all
    // graph/source provisioning is shared with the native preflight and makes no model call.
    assert!(fixture_files.join("quality-scenarios-v1.json").is_file());
    let setup = crate::chat::quality_fixture::setup_quality_fixture().await;
    let fixture = &setup.fixture;
    let scenario = &setup.scenario;
    let provision_subject = setup.provision_subject.clone();
    let provision_report = setup.provision_ingest_report.clone();

    let token = fs::read_to_string(fixture.root().join("owner.secret")).unwrap();
    let service = Service::open(fixture.config().unwrap()).await.unwrap();
    let query_config = publish_artifact(
        &service,
        &token,
        "https://ctxql.example/test/chat-paid-quality-config",
        include_bytes!("../../../../fixtures/conformance/graph-workspace/config.json"),
    )
    .await;
    service.shutdown().await.unwrap();
    drop(service);

    let config = chat_config(fixture, &query_config);
    assert!(config.acquisition.is_none());
    let source_root = config.source_root.clone();
    let chat = config.chat.clone().unwrap();
    // This is the live read composition; Semantic claim denials were committed
    // at fresh-store bootstrap before it opens.
    let source_before = inventory(&source_root);
    let reads = ChatReadResources::open(config, token).await.unwrap();
    let semantic_before = SemanticProjectionSource::head(reads.semantic.as_ref())
        .await
        .unwrap();
    let control_before = GraphBackend::head(reads.control.as_ref().unwrap().as_ref())
        .await
        .unwrap();
    let preflight = crate::chat::quality_fixture::verify_quality_preflight(&reads, &setup).await;
    assert_eq!(preflight["status"], "passed_before_transport_start");
    assert_eq!(
        SemanticProjectionSource::head(reads.semantic.as_ref())
            .await
            .unwrap(),
        semantic_before
    );
    assert_eq!(
        GraphBackend::head(reads.control.as_ref().unwrap().as_ref())
            .await
            .unwrap(),
        control_before
    );
    assert_eq!(inventory(&source_root), source_before);
    if preflight_only {
        fs::write(
            run_dir.join("preflight.json"),
            serde_json::to_vec_pretty(&json!({
                "schema":"ctxql.chat-paid-quality-preflight/v1",
                "model_calls":0,
                "preflight":preflight,
                "semantic_head":snapshot_binding(&semantic_before),
                "control_head":snapshot_binding(&control_before),
                "source_inventory":source_before,
            }))
            .unwrap(),
        )
        .unwrap();
        eprintln!("paid chat preflight evidence: {}", run_dir.display());
        return;
    }

    let lender = scenario["entities"]["lender"].as_str().unwrap();
    let questions = vec![
        format!("Which agreements involve the exact entity {lender} as lender rather than arranger? Report the role evidence and any conflicting status claims you encounter."),
        format!("For the exact agreement entity {provision_subject}, does it permit further drawings? Quote the exact source evidence and preserve its condition."),
        scenario["scenarios"].as_array().unwrap().iter().find(|item| item["id"] == "ambiguous-name").unwrap()["question"].as_str().unwrap().to_owned(),
        scenario["scenarios"].as_array().unwrap().iter().find(|item| item["id"] == "global-unsupported").unwrap()["question"].as_str().unwrap().to_owned(),
    ];
    let bundle = hash_agent_bundle_for_profile(&chat.pi_bundle, BundleProfile::Chat).unwrap();
    let system_prompt = bundle.chat_system_prompt().unwrap();
    let bundle_hash = bundle.hash.clone();
    let runtime = tokio::runtime::Handle::current();
    let live_reads = reads.clone();
    let live = tokio::task::spawn_blocking(move || run_live(chat, live_reads, runtime, questions))
        .await
        .unwrap();

    let semantic_after = SemanticProjectionSource::head(reads.semantic.as_ref())
        .await
        .unwrap();
    let control_after = GraphBackend::head(reads.control.as_ref().unwrap().as_ref())
        .await
        .unwrap();
    let source_after = inventory(&source_root);
    let citations = live
        .turns
        .iter()
        .flat_map(|turn| find_citations(&turn.answer))
        .map(|token| {
            let detail = reads.citation_details(&token);
            (token, detail)
        })
        .collect::<BTreeMap<_, _>>();

    let hidden = scenario["entities"]["inaccessible_agreement"]
        .as_str()
        .unwrap();
    let agreement = scenario["entities"]["agreement"].as_str().unwrap();
    let ambiguous = scenario["entities"]["ambiguous_agreement"]
        .as_str()
        .unwrap();
    let quote = "permits further drawings while no Event of Default is continuing";
    let expected_checks = json!({
        "role_host_outcome": {
            "expected_visible_agreement":agreement,
            "expected_predicate":scenario["predicates"]["lender"],
            "hidden_subject_must_not_contribute":hidden,
            "observed_visible_agreement":transcript_contains(&live.tools, 1, agreement),
            "observed_lender_predicate":transcript_contains(&live.tools, 1, scenario["predicates"]["lender"].as_str().unwrap()),
            "observed_hidden_subject":transcript_contains(&live.tools, 1, hidden),
            "observed_both_conflicting_status_values":transcript_contains(&live.tools, 1, "active") && transcript_contains(&live.tools, 1, "suspended"),
        },
        "source_host_outcome": {
            "exact_subject":provision_subject,
            "expected_predicate":"urn:ctxql:chat-quality:permitsFurtherDrawings",
            "expected_exact_quote":quote,
            "observed_predicate":transcript_contains(&live.tools, 2, "urn:ctxql:chat-quality:permitsFurtherDrawings"),
            "observed_exact_source_result":transcript_contains(&live.tools, 2, quote),
        },
        "ambiguity_host_outcome": {
            "expected_visible_ids":[agreement,ambiguous],
            "observed_first":transcript_contains(&live.tools, 3, agreement),
            "observed_second":transcript_contains(&live.tools, 3, ambiguous),
            "assistant_requested_clarification":live.turns.get(2).is_some_and(|turn| turn.answer.to_ascii_lowercase().contains("clarif") || turn.answer.contains(agreement) || turn.answer.contains(ambiguous)),
        },
        "unsupported_global_outcome": {
            "operation_supported":false,
            "assistant_disclosed_scope_limit":live.turns.get(3).is_some_and(|turn| {
                let answer = turn.answer.to_ascii_lowercase();
                answer.contains("cannot") || answer.contains("unsupported") || answer.contains("bounded") || answer.contains("world")
            }),
            "note":"Prose indicators are advisory; parent performs final semantic assessment against the retained answer and host transcript."
        }
    });

    let turns_json = live
        .turns
        .iter()
        .enumerate()
        .map(|(index, turn)| json!({
            "turn":index + 1,
            "question":turn.question,
            "streamed_text":turn.answer,
            "events":turn.events,
            "terminal":turn.terminal,
            "host_queries":turn.queries.iter().map(|(query,outcome)| json!({"query":query,"outcome":outcome})).collect::<Vec<_>>(),
        }))
        .collect::<Vec<_>>();
    let usage = usage_json(&live.usage);
    let final_status = if live.failure.is_none() && live.turns.len() == 4 {
        "completed"
    } else {
        "failed_stop_no_retry"
    };
    let report = json!({
        "schema":"ctxql.chat-paid-quality-evidence/v1",
        "synthetic_data_only":true,
        "authorization_scope":"AUTHORIZED_PAID scoped only to this one experiment",
        "billing_control_note":"The $0.50 ceiling is enforced against provider-reported cumulative usage after streamed accounting arrives; it is not a provider-side hard billing cap and an individual in-flight response could report over the target before the host can stop.",
        "no_automatic_retries":true,
        "no_fallback_models":true,
        "final_status":final_status,
        "failure":live.failure,
        "provider":"openrouter",
        "configured_model":cdb_provider_pi::MODEL,
        "runtime_model":cdb_provider_pi::RUNTIME_MODEL,
        "thinking":cdb_provider_pi::THINKING,
        "verified_bundle_hash":bundle_hash,
        "system_prompt":system_prompt,
        "limits":{
            "target_cost_usd":0.50,
            "max_reported_cost_micro_usd":MAX_COST_MICRO_USD,
            "max_user_turns":4,
            "max_model_rounds":16,
            "max_tool_calls":32,
            "max_queries":12,
            "max_reported_tokens":MAX_REPORTED_TOKENS,
            "turn_seconds":90,
        },
        "fixture":{
            "quality_scenario_schema":scenario["schema"],
            "source_provision_subject":provision_subject,
            "provision_ingest_report":provision_report,
            "semantic_denied_claim_ids":setup.denied_claim_ids,
            "offline_preflight":preflight,
            "retained_store":"fixture-store",
        },
        "prior_heads":{
            "semantic":snapshot_binding(&semantic_before),
            "control":snapshot_binding(&control_before),
        },
        "after_heads":{
            "semantic":snapshot_binding(&semantic_after),
            "control":snapshot_binding(&control_after),
        },
        "durable_source_objects_before":source_before,
        "durable_source_objects_after":source_after,
        "source_objects_unchanged_during_chat":source_before == source_after,
        "semantic_unchanged_during_chat":semantic_before == semantic_after,
        "control_unchanged_during_chat":control_before == control_after,
        "turns":turns_json,
        "tool_transcript":tool_records_json(&live.tools),
        "citation_metadata":citations,
        "usage":usage,
        "host_expected_outcomes":expected_checks,
        "semantic_judgment":"Host outcomes are checked structurally above; answer quality remains a human semantic judgment and is not represented as a string-only pass/fail grade."
    });
    fs::write(
        run_dir.join("evidence.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    drop(reads);
    copy_tree(fixture.root(), &run_dir.join("fixture-store"));
    fs::write(
        run_dir.join("fixture-store-inventory.json"),
        serde_json::to_vec_pretty(&inventory(&run_dir.join("fixture-store"))).unwrap(),
    )
    .unwrap();

    assert_eq!(
        semantic_before, semantic_after,
        "paid chat changed Semantic"
    );
    assert_eq!(control_before, control_after, "paid chat changed Control");
    assert_eq!(
        source_before, source_after,
        "paid chat changed source objects"
    );
    assert!(
        live.failure.is_none(),
        "paid experiment stopped without retry; evidence retained at {}: {:?}",
        run_dir.display(),
        live.failure
    );
    assert_eq!(live.turns.len(), 4);
    match live.usage {
        UsageStatus::Known(usage) => {
            assert!(usage.cost_microusd <= MAX_COST_MICRO_USD);
            assert!(
                usage
                    .input_tokens
                    .saturating_add(usage.output_tokens)
                    .saturating_add(usage.cache_read_tokens)
                    .saturating_add(usage.cache_write_tokens)
                    <= MAX_REPORTED_TOKENS
            );
        }
        UsageStatus::Unknown => panic!(
            "unknown final usage; evidence retained at {}",
            run_dir.display()
        ),
    }
    eprintln!("paid chat evidence: {}", run_dir.display());
}
