#![cfg(unix)]

use cdb_provider_pi::agent_bundle::{hash_agent_bundle_for_profile, BundleProfile};
use cdb_provider_pi::chat_transport::{
    ChatEvent, ChatTransport, ChatTransportConfig, ChatTransportLimits, UsageStatus,
};
use cdb_provider_pi::ontology_bridge::{
    OntologyBridgeConfig, OntologyToolError, OntologyToolHost, ToolCapability,
};
use cdb_provider_pi::SessionLogging;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn installed_pi_command() -> PathBuf {
    PathBuf::from(
        env::var_os("CDB_CHAT_PI_TEST_COMMAND")
            .expect("CDB_CHAT_PI_TEST_COMMAND must name the installed Pi executable"),
    )
}

struct Deny;
impl OntologyToolHost for Deny {
    fn lookup(&self, _: &Value) -> Result<Value, OntologyToolError> {
        Err(OntologyToolError::Denied)
    }
}

/// Control-only installed-Pi smoke: version/state/settings/resources/new-session
/// and EOF shutdown. It sends no prompt and performs no provider call.
#[test]
#[ignore = "run explicitly when the pinned installed Pi executable is available"]
fn installed_pi_control_only_no_remote_call() {
    let command = installed_pi_command();
    assert!(command.is_file(), "installed Pi executable unavailable");
    let assets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/pi");
    let bundle = hash_agent_bundle_for_profile(assets, BundleProfile::Chat).unwrap();
    let mut transport = ChatTransport::start(ChatTransportConfig {
        command,
        environment: Vec::new(),
        system_prompt: bundle.chat_system_prompt().unwrap(),
        bundle,
        ontology_bridge: OntologyBridgeConfig {
            host: Arc::new(Deny),
            max_request_bytes: 32 * 1024,
            max_response_bytes: 64 * 1024,
        },
        limits: ChatTransportLimits {
            command_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(2),
            ..ChatTransportLimits::default()
        },
        session_logging: None,
    })
    .unwrap();
    transport.clear().unwrap();
    transport.close();
}

#[test]
#[ignore = "run explicitly when the pinned installed Pi executable is available"]
fn installed_pi_control_only_accepts_opt_in_session_logging_without_provider_call() {
    let command = installed_pi_command();
    assert!(command.is_file(), "installed Pi executable unavailable");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ctxql-installed-pi-session-log-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let log_root = root.join("logs");
    let assets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/pi");
    let bundle = hash_agent_bundle_for_profile(assets, BundleProfile::Chat).unwrap();
    let mut transport = ChatTransport::start(ChatTransportConfig {
        command,
        environment: Vec::new(),
        system_prompt: bundle.chat_system_prompt().unwrap(),
        bundle,
        ontology_bridge: OntologyBridgeConfig {
            host: Arc::new(Deny),
            max_request_bytes: 32 * 1024,
            max_response_bytes: 64 * 1024,
        },
        limits: ChatTransportLimits {
            command_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(2),
            ..ChatTransportLimits::default()
        },
        session_logging: Some(SessionLogging {
            root: log_root.clone(),
        }),
    })
    .unwrap();
    let diagnostic = transport.diagnostic_path().unwrap().to_path_buf();
    transport.clear().unwrap();
    transport.close();
    assert!(diagnostic.is_file());
    assert!(log_root.is_dir());
    fs::remove_dir_all(root).unwrap();
}

struct Capabilities {
    calls: Arc<AtomicUsize>,
}
impl OntologyToolHost for Capabilities {
    fn lookup(&self, _: &Value) -> Result<Value, OntologyToolError> {
        Err(OntologyToolError::Denied)
    }

    fn invoke(
        &self,
        capability: ToolCapability,
        _: &str,
        request: &Value,
    ) -> Result<Value, OntologyToolError> {
        assert_eq!(capability, ToolCapability::Capabilities);
        assert_eq!(request, &json!({}));
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"kind":"capabilities","mock":true}))
    }
}

struct MockServer {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    worker: Option<JoinHandle<()>>,
}

impl MockServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            for response_index in 0..3 {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            break stream;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "mock provider request timed out");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("mock provider accept failed: {error}"),
                    }
                };
                let body = read_http_body(&mut stream);
                captured.lock().unwrap().push(body);
                let events = if response_index == 0 {
                    vec![
                        json!({"id":"mock-1","object":"chat.completion.chunk","created":1,"model":"deepseek/deepseek-v4.1-flash","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call-1","type":"function","function":{"name":"ctxql_capabilities","arguments":"{}"}}]},"finish_reason":null}]}),
                        json!({"id":"mock-1","object":"chat.completion.chunk","created":1,"model":"deepseek/deepseek-v4.1-flash","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}),
                    ]
                } else {
                    let text = if response_index == 1 {
                        "first answer"
                    } else {
                        "second answer"
                    };
                    vec![
                        json!({"id":format!("mock-{}", response_index + 1),"object":"chat.completion.chunk","created":1,"model":"deepseek/deepseek-v4.1-flash","choices":[{"index":0,"delta":{"role":"assistant","content":text},"finish_reason":null}]}),
                        json!({"id":format!("mock-{}", response_index + 1),"object":"chat.completion.chunk","created":1,"model":"deepseek/deepseek-v4.1-flash","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
                    ]
                };
                write_sse_response(&mut stream, &events);
            }
        });
        Self {
            base_url,
            requests,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> Vec<String> {
        self.worker.take().unwrap().join().unwrap();
        Arc::try_unwrap(self.requests)
            .unwrap()
            .into_inner()
            .unwrap()
    }
}

fn read_http_body(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut chunk).unwrap();
        assert!(count > 0, "provider closed before request headers");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    while bytes.len() - header_end < content_length {
        let count = stream.read(&mut chunk).unwrap();
        assert!(count > 0, "provider closed before request body");
        bytes.extend_from_slice(&chunk[..count]);
    }
    String::from_utf8(bytes[header_end..header_end + content_length].to_vec()).unwrap()
}

fn write_sse_response(stream: &mut TcpStream, events: &[Value]) {
    let mut body = String::new();
    for event in events {
        body.push_str("data: ");
        body.push_str(&serde_json::to_string(event).unwrap());
        body.push_str("\n\n");
    }
    body.push_str("data: [DONE]\n\n");
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .unwrap();
    stream.flush().unwrap();
}

fn installed_pi_wrapper(root: &Path, real_pi: &Path) -> PathBuf {
    let wrapper = root.join("pi-local-mock");
    let script = r##"#!/bin/sh
set -eu
REAL_PI=__CDB_TEST_REAL_PI__
PATH=/opt/homebrew/bin:/usr/bin:/bin
export PATH
if [ "${1-}" = "--version" ]; then exec "$REAL_PI" --version; fi
: "${CDB_TEST_MODEL_BASE_URL:?missing local mock URL}"
mkdir -p "$PI_CODING_AGENT_DIR"
cat > "$PI_CODING_AGENT_DIR/models.json" <<EOF
{"providers":{"openrouter":{"baseUrl":"$CDB_TEST_MODEL_BASE_URL","api":"openai-completions","apiKey":"test-only-not-a-credential","models":[{"id":"deepseek/deepseek-v4.1-flash","name":"CTXQL local mock","reasoning":true,"input":["text"],"contextWindow":131072,"maxTokens":4096,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0}}]}}}
EOF
exec "$REAL_PI" "$@" 2>"$CDB_TEST_PI_STDERR"
"##
    .replace("__CDB_TEST_REAL_PI__", &real_pi.to_string_lossy());
    fs::write(&wrapper, script).unwrap();
    let mut permissions = fs::metadata(&wrapper).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&wrapper, permissions).unwrap();
    wrapper
}

fn collect_turn(transport: &mut ChatTransport) -> Vec<ChatEvent> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut events = Vec::new();
    while Instant::now() < deadline {
        if let Some(event) = transport.poll_event(Duration::from_millis(200)).unwrap() {
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
    panic!("installed Pi mock turn did not settle")
}

/// Actual installed Pi 0.87.1 with a private test wrapper and models.json
/// pointing the production-pinned OpenRouter model identity at loopback.
/// This never uses ambient or real provider credentials.
#[test]
#[ignore = "run explicitly with CDB_CHAT_PI_TEST_COMMAND naming installed Pi 0.87.1"]
fn installed_pi_loopback_provider_executes_tool_streams_and_keeps_context() {
    let installed_pi = installed_pi_command();
    assert!(installed_pi.is_file());
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ctxql-installed-pi-mock-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let server = MockServer::start();
    let wrapper = installed_pi_wrapper(&root, &installed_pi);
    let pi_stderr = root.join("pi.stderr");
    let log_root = root.join("logs");
    let calls = Arc::new(AtomicUsize::new(0));
    let assets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/pi");
    let bundle = hash_agent_bundle_for_profile(assets, BundleProfile::Chat).unwrap();
    let mut transport = ChatTransport::start(ChatTransportConfig {
        command: wrapper,
        environment: vec![
            ("CDB_TEST_MODEL_BASE_URL".into(), server.base_url.clone()),
            (
                "CDB_TEST_PI_STDERR".into(),
                pi_stderr.to_string_lossy().into_owned(),
            ),
            ("PI_OFFLINE".into(), "1".into()),
        ],
        system_prompt: bundle.chat_system_prompt().unwrap(),
        bundle,
        ontology_bridge: OntologyBridgeConfig {
            host: Arc::new(Capabilities {
                calls: calls.clone(),
            }),
            max_request_bytes: 32 * 1024,
            max_response_bytes: 64 * 1024,
        },
        limits: ChatTransportLimits {
            command_timeout: Duration::from_secs(15),
            turn_timeout: Duration::from_secs(15),
            shutdown_grace: Duration::from_secs(2),
            ..ChatTransportLimits::default()
        },
        session_logging: Some(SessionLogging {
            root: log_root.clone(),
        }),
    })
    .unwrap_or_else(|error| {
        panic!(
            "installed Pi startup failed: {error:?}\nstderr: {}",
            fs::read_to_string(&pi_stderr).unwrap_or_default()
        )
    });

    transport.prompt("use capabilities once").unwrap();
    let first = collect_turn(&mut transport);
    assert!(first.iter().any(|event| matches!(
        event,
        ChatEvent::Progress { tool_name } if tool_name == "ctxql_capabilities"
    )));
    assert!(first.iter().any(|event| matches!(
        event,
        ChatEvent::TextDelta { identity, delta, .. }
            if identity.message_id == "ctxql-assistant-2" && delta == "first answer"
    )));
    assert!(matches!(
        first.last(),
        Some(ChatEvent::Settled { usage }) if usage.requests == 2
    ));

    transport.prompt("follow up").unwrap();
    let second = collect_turn(&mut transport);
    assert!(second.iter().any(|event| matches!(
        event,
        ChatEvent::TextDelta { identity, delta, .. }
            if identity.message_id == "ctxql-assistant-3" && delta == "second answer"
    )));
    assert!(matches!(
        second.last(),
        Some(ChatEvent::Settled { usage }) if usage.requests == 3
    ));
    assert!(matches!(transport.usage_snapshot(), UsageStatus::Known(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    transport.close();
    let native_sessions = fs::read_dir(&log_root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .flat_map(|entry| fs::read_dir(entry.path()).unwrap().filter_map(Result::ok))
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("jsonl"))
        .count();
    assert!(
        native_sessions >= 1,
        "Pi did not retain a native session file"
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].contains("CTXQL CHAT USER MESSAGE"));
    assert!(requests[0].contains("ctxql_capabilities"));
    assert!(requests[1].contains("mock"));
    assert!(requests[2].contains("first answer"));
    assert!(requests[2].contains("follow up"));
    let _ = fs::remove_dir_all(root);
}
