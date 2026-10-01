//! Private authenticated Unix-socket bridge for CTXQL Pi tools.
//!
//! The bridge owns framing, capability denial and byte limits. Domain semantics
//! remain in the host. Graph capabilities are denied by the default host method
//! and are therefore unavailable until an explicitly graph-aware service host is
//! installed and the transport allowlist enables their tool names.

use cdb_core::id::ContentHash;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const GRAPH_REQUEST_BYTES: usize = 32 * 1024;
const GRAPH_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OntologyToolError {
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolCapability {
    Capabilities,
    Ontology,
    Entities,
    GraphQuery,
    GraphPlayground,
    Source,
}
impl ToolCapability {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "capabilities" => Some(Self::Capabilities),
            "ontology" => Some(Self::Ontology),
            "entities" => Some(Self::Entities),
            "graph_query" => Some(Self::GraphQuery),
            "graph_playground" => Some(Self::GraphPlayground),
            "source" => Some(Self::Source),
            _ => None,
        }
    }
    fn is_graph(self) -> bool {
        matches!(
            self,
            Self::GraphQuery | Self::GraphPlayground | Self::Source
        )
    }
}

pub trait OntologyToolHost: Send + Sync {
    fn lookup(&self, request: &Value) -> Result<Value, OntologyToolError>;

    /// Explicit capability dispatch. Existing ontology hosts remain feature-off:
    /// graph calls are denied unless a service host deliberately overrides this.
    fn invoke(
        &self,
        capability: ToolCapability,
        _call_id: &str,
        request: &Value,
    ) -> Result<Value, OntologyToolError> {
        match capability {
            ToolCapability::Ontology => self.lookup(request),
            ToolCapability::Entities => self.lookup(&json!({
                "capability": "entities",
                "request": request,
            })),
            ToolCapability::Capabilities
            | ToolCapability::GraphQuery
            | ToolCapability::GraphPlayground
            | ToolCapability::Source => Err(OntologyToolError::Denied),
        }
    }

    /// Cancellation is keyed by the untrusted-call-independent host call ID.
    /// Feature-off hosts have no asynchronous work and may ignore it.
    fn cancel(&self, _call_id: &str) -> Result<(), OntologyToolError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct OntologyBridgeConfig {
    pub host: Arc<dyn OntologyToolHost>,
    /// Legacy ontology/entity request limit. Graph calls retain their separate
    /// fixed 32 KiB ceiling and do not broaden this value.
    pub max_request_bytes: usize,
    /// Legacy ontology/entity response limit. Graph calls are capped at 64 KiB.
    pub max_response_bytes: usize,
}

impl std::fmt::Debug for OntologyBridgeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OntologyBridgeConfig")
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

pub(crate) struct OntologyBridge {
    directory: PathBuf,
    socket: PathBuf,
    token: String,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

static BRIDGE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

impl OntologyBridge {
    #[cfg(unix)]
    pub(crate) fn start(config: OntologyBridgeConfig) -> Result<Arc<Self>, ()> {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        if config.max_request_bytes == 0 || config.max_response_bytes == 0 {
            return Err(());
        }
        let sequence = BRIDGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ctxql-ontology-bridge-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).map_err(|_| ())?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| ())?;
        let socket = directory.join("bridge.sock");
        let listener = UnixListener::bind(&socket).map_err(|_| ())?;
        listener.set_nonblocking(true).map_err(|_| ())?;
        let token = ContentHash::of_bytes(
            format!(
                "ctxql-ontology-bridge/v2\0{}\0{sequence}\0{now}",
                std::process::id()
            )
            .as_bytes(),
        )
        .as_str()
        .to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let call_ids = Arc::new(Mutex::new(BTreeSet::<String>::new()));
        let worker_stop = stop.clone();
        let worker_token = token.clone();
        let worker = std::thread::spawn(move || {
            let mut calls = Vec::<JoinHandle<()>>::new();
            while !worker_stop.load(Ordering::Acquire) {
                calls.retain(|call| !call.is_finished());
                match listener.accept() {
                    Ok((stream, _)) => {
                        if active.load(Ordering::Acquire) >= MAX_CONNECTIONS {
                            let mut stream = stream;
                            let _ = write_response(
                                &mut stream,
                                &json!({"ok":false,"error":"bridge_busy"}),
                                config.max_response_bytes,
                            );
                            continue;
                        }
                        active.fetch_add(1, Ordering::AcqRel);
                        let call_active = active.clone();
                        let call_config = config.clone();
                        let call_token = worker_token.clone();
                        let call_ids = call_ids.clone();
                        let call_stop = worker_stop.clone();
                        calls.push(std::thread::spawn(move || {
                            handle_stream(stream, &call_token, &call_config, &call_ids, &call_stop);
                            call_active.fetch_sub(1, Ordering::AcqRel);
                        }));
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            for call in calls {
                let _ = call.join();
            }
        });
        Ok(Arc::new(Self {
            directory,
            socket,
            token,
            stop,
            worker: Mutex::new(Some(worker)),
        }))
    }

    #[cfg(not(unix))]
    pub(crate) fn start(_: OntologyBridgeConfig) -> Result<Arc<Self>, ()> {
        Err(())
    }

    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }
    pub(crate) fn token(&self) -> &str {
        &self.token
    }
}

#[cfg(unix)]
fn handle_stream(
    mut stream: std::os::unix::net::UnixStream,
    token: &str,
    config: &OntologyBridgeConfig,
    call_ids: &Mutex<BTreeSet<String>>,
    stop: &AtomicBool,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let framing_limit = GRAPH_REQUEST_BYTES
        .max(config.max_request_bytes)
        .saturating_add(1024);
    let mut bytes = Vec::new();
    let result = BufReader::new(&mut stream)
        .take(framing_limit as u64 + 1)
        .read_until(b'\n', &mut bytes);
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    let (response, response_limit) = if result.is_err() || bytes.len() > framing_limit {
        (
            json!({"ok":false,"error":"request_limit"}),
            config.max_response_bytes,
        )
    } else {
        handle(&bytes, token, config, call_ids, &stream, stop)
    };
    let _ = write_response(&mut stream, &response, response_limit);
}

fn write_response(stream: &mut impl Write, response: &Value, max: usize) -> std::io::Result<()> {
    let encoded = serde_json::to_vec(response).map_err(std::io::Error::other)?;
    if encoded.len() > max {
        let fallback = serde_json::to_vec(&json!({"ok":false,"error":"response_limit"}))
            .map_err(std::io::Error::other)?;
        stream.write_all(&fallback)?;
    } else {
        stream.write_all(&encoded)?;
    }
    stream.flush()
}

#[cfg(unix)]
fn handle(
    bytes: &[u8],
    token: &str,
    config: &OntologyBridgeConfig,
    call_ids: &Mutex<BTreeSet<String>>,
    stream: &std::os::unix::net::UnixStream,
    stop: &AtomicBool,
) -> (Value, usize) {
    // Reject duplicate decoded keys at every depth before Value would silently
    // normalize them. The captured canonical request must have one meaning.
    if cdb_core::CanonicalValue::parse(bytes, cdb_core::Limits::default()).is_err() {
        return (
            json!({"ok":false,"error":"invalid_request"}),
            config.max_response_bytes,
        );
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return (
            json!({"ok":false,"error":"invalid_request"}),
            config.max_response_bytes,
        );
    };
    let Some(object) = value.as_object() else {
        return (
            json!({"ok":false,"error":"invalid_request"}),
            config.max_response_bytes,
        );
    };
    if object.get("token").and_then(Value::as_str) != Some(token) {
        return (
            json!({"ok":false,"error":"unauthorized"}),
            config.max_response_bytes,
        );
    }
    if object.get("kind").and_then(Value::as_str) == Some("cancel") {
        if object.len() != 3 {
            return (
                json!({"ok":false,"error":"invalid_request"}),
                config.max_response_bytes,
            );
        }
        let Some(call_id) = object.get("call_id").and_then(Value::as_str) else {
            return (
                json!({"ok":false,"error":"invalid_request"}),
                config.max_response_bytes,
            );
        };
        let known = call_ids
            .lock()
            .map(|ids| ids.contains(call_id))
            .unwrap_or(false);
        let response = if !known {
            json!({"ok":false,"error":"cancel_denied"})
        } else {
            match config.host.cancel(call_id) {
                Ok(()) => json!({"ok":true,"response":{"cancelled":true}}),
                Err(OntologyToolError::Denied) => json!({"ok":false,"error":"cancel_denied"}),
            }
        };
        return (response, config.max_response_bytes);
    }
    if object.len() != 5 || object.get("kind").and_then(Value::as_str) != Some("call") {
        return (
            json!({"ok":false,"error":"invalid_request"}),
            config.max_response_bytes,
        );
    }
    let Some(call_id) = object.get("call_id").and_then(Value::as_str) else {
        return (
            json!({"ok":false,"error":"invalid_request"}),
            config.max_response_bytes,
        );
    };
    if call_id.is_empty() || call_id.len() > 256 {
        return (
            json!({"ok":false,"error":"invalid_request"}),
            config.max_response_bytes,
        );
    }
    let Some(capability_name) = object.get("capability").and_then(Value::as_str) else {
        return (
            json!({"ok":false,"error":"invalid_request"}),
            config.max_response_bytes,
        );
    };
    let Some(capability) = ToolCapability::parse(capability_name) else {
        return (
            json!({"ok":false,"error":"capability_denied"}),
            config.max_response_bytes,
        );
    };
    let Some(request) = object.get("request") else {
        return (
            json!({"ok":false,"error":"invalid_request"}),
            config.max_response_bytes,
        );
    };
    let request_limit = if capability.is_graph() {
        GRAPH_REQUEST_BYTES
    } else {
        config.max_request_bytes
    };
    if serde_json::to_vec(request).map_or(true, |encoded| encoded.len() > request_limit) {
        return (
            json!({"ok":false,"error":"request_limit"}),
            config.max_response_bytes,
        );
    }
    let response_limit = if capability.is_graph() {
        GRAPH_RESPONSE_BYTES.min(config.max_response_bytes)
    } else {
        config.max_response_bytes
    };
    let inserted = call_ids
        .lock()
        .map(|mut ids| ids.insert(call_id.to_owned()))
        .unwrap_or(false);
    if !inserted {
        return (json!({"ok":false,"error":"call_id_denied"}), response_limit);
    }
    // Watch the authenticated call while the dedicated worker waits in native
    // execution. A disconnected Pi or bridge shutdown must cancel that work,
    // not merely discard a result after its deadline.
    let result = stream.try_clone().and_then(|mut watcher| {
        watcher.set_read_timeout(Some(Duration::from_millis(25)))?;
        let finished = AtomicBool::new(false);
        let abandoned = AtomicBool::new(false);
        Ok(std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut byte = [0u8; 1];
                while !finished.load(Ordering::Acquire) {
                    if !stop.load(Ordering::Acquire) {
                        match watcher.read(&mut byte) {
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::WouldBlock
                                        | std::io::ErrorKind::TimedOut
                                        | std::io::ErrorKind::Interrupted
                                ) =>
                            {
                                continue
                            }
                            _ => {}
                        }
                    }
                    abandoned.store(true, Ordering::Release);
                    let _ = config.host.cancel(call_id);
                    break;
                }
            });
            let result = config.host.invoke(capability, call_id, request);
            finished.store(true, Ordering::Release);
            result
        })
        .and_then(|response| {
            if abandoned.load(Ordering::Acquire) {
                Err(OntologyToolError::Denied)
            } else {
                Ok(response)
            }
        }))
    });
    let response = match result {
        Ok(Ok(response)) => json!({"ok":true,"response":response}),
        _ => json!({"ok":false,"error":"lookup_denied"}),
    };
    if let Ok(mut ids) = call_ids.lock() {
        ids.remove(call_id);
    }
    (response, response_limit)
}

impl Drop for OntologyBridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        #[cfg(unix)]
        {
            let _ = std::os::unix::net::UnixStream::connect(&self.socket);
        }
        if let Ok(mut worker) = self.worker.lock() {
            if let Some(worker) = worker.take() {
                let _ = worker.join();
            }
        }
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Host {
        cancelled: AtomicBool,
    }
    impl OntologyToolHost for Host {
        fn lookup(&self, request: &Value) -> Result<Value, OntologyToolError> {
            Ok(json!({"request":request}))
        }
        fn invoke(
            &self,
            capability: ToolCapability,
            _call_id: &str,
            request: &Value,
        ) -> Result<Value, OntologyToolError> {
            match capability {
                ToolCapability::Capabilities => Ok(json!({"profile":"chat"})),
                ToolCapability::GraphQuery => {
                    if request.get("query").and_then(Value::as_str) == Some("block") {
                        self.cancelled.store(false, Ordering::Release);
                        let deadline = std::time::Instant::now() + Duration::from_secs(2);
                        while !self.cancelled.load(Ordering::Acquire)
                            && std::time::Instant::now() < deadline
                        {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        return Err(OntologyToolError::Denied);
                    }
                    Ok(json!({"graph":request}))
                }
                ToolCapability::Source => Ok(json!({"source":request})),
                _ => OntologyToolHost::lookup(self, request),
            }
        }
        fn cancel(&self, _: &str) -> Result<(), OntologyToolError> {
            self.cancelled.store(true, Ordering::Release);
            Ok(())
        }
    }

    #[cfg(unix)]
    #[test]
    fn bridge_closes_capabilities_tokens_and_limits() {
        use std::os::unix::net::UnixStream;
        let bridge = OntologyBridge::start(OntologyBridgeConfig {
            host: Arc::new(Host::default()),
            max_request_bytes: 1024,
            max_response_bytes: 4096,
        })
        .unwrap();
        let call = |value: Value| {
            let mut stream = UnixStream::connect(bridge.socket()).unwrap();
            let mut request = serde_json::to_vec(&value).unwrap();
            request.push(b'\n');
            stream.write_all(&request).unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        };
        let envelope = |token: &str, capability: &str, request: Value| json!({"token":token,"kind":"call","call_id":"call-1","capability":capability,"request":request});
        assert_eq!(
            call(envelope("foreign", "ontology", json!({})))["error"],
            "unauthorized"
        );
        assert_eq!(
            call(envelope(bridge.token(), "unknown", json!({})))["error"],
            "capability_denied"
        );
        assert_eq!(
            call(envelope(bridge.token(), "ontology", json!({"query":"x"})))["ok"],
            true
        );
        assert_eq!(
            call(envelope(
                bridge.token(),
                "graph_query",
                json!({"query":"{}"})
            ))["ok"],
            true
        );
        let unknown_cancel =
            call(json!({"token":bridge.token(),"kind":"cancel","call_id":"call-1"}));
        assert_eq!(unknown_cancel["ok"], false);
        assert_eq!(unknown_cancel["error"], "cancel_denied");
        let mut stream = UnixStream::connect(bridge.socket()).unwrap();
        writeln!(stream, "{{\"token\":\"{}\",\"kind\":\"call\",\"call_id\":\"duplicate\",\"capability\":\"ontology\",\"request\":{{\"query\":\"first\",\"query\":\"second\"}}}}", bridge.token()).unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["error"],
            "invalid_request"
        );
    }

    #[cfg(unix)]
    #[test]
    fn disconnect_and_shutdown_cancel_blocked_authenticated_calls() {
        struct BlockingHost {
            entered: AtomicBool,
            cancelled: AtomicBool,
        }
        impl OntologyToolHost for BlockingHost {
            fn lookup(&self, _: &Value) -> Result<Value, OntologyToolError> {
                self.entered.store(true, Ordering::Release);
                let deadline = std::time::Instant::now() + Duration::from_secs(3);
                while !self.cancelled.load(Ordering::Acquire)
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(OntologyToolError::Denied)
            }
            fn cancel(&self, _: &str) -> Result<(), OntologyToolError> {
                self.cancelled.store(true, Ordering::Release);
                Ok(())
            }
        }
        for disconnect in [true, false] {
            let host = Arc::new(BlockingHost {
                entered: AtomicBool::new(false),
                cancelled: AtomicBool::new(false),
            });
            let bridge = OntologyBridge::start(OntologyBridgeConfig {
                host: host.clone(),
                max_request_bytes: 1024,
                max_response_bytes: 4096,
            })
            .unwrap();
            let socket = bridge.socket().to_owned();
            let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
            writeln!(stream, "{}", json!({"token":bridge.token(),"kind":"call","call_id":"blocked","capability":"ontology","request":{}})).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !host.entered.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(host.entered.load(Ordering::Acquire));
            if disconnect {
                stream.shutdown(std::net::Shutdown::Both).unwrap();
                let deadline = std::time::Instant::now() + Duration::from_secs(1);
                while !host.cancelled.load(Ordering::Acquire)
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert!(
                    host.cancelled.load(Ordering::Acquire),
                    "disconnect must cancel before shutdown"
                );
            }
            let start = std::time::Instant::now();
            drop(bridge);
            assert!(host.cancelled.load(Ordering::Acquire));
            assert!(start.elapsed() < Duration::from_secs(1));
            assert!(!socket.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn actual_typescript_extension_registers_and_calls_live_bridge() {
        let source = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/pi");
        let bundle = crate::agent_bundle::hash_agent_bundle(&source)
            .unwrap()
            .stage_verified()
            .unwrap();
        let bridge = OntologyBridge::start(OntologyBridgeConfig {
            host: Arc::new(Host::default()),
            max_request_bytes: 4096,
            max_response_bytes: 64 * 1024,
        })
        .unwrap();
        let script = bundle.root.join("extension-smoke.mjs");
        let extension = bundle.root.join("extensions/ctxql-ontology-tool.ts");
        std::fs::write(
            &script,
            r#"const { default: extension } = await import(process.env.CDB_EXTENSION);
const tools = new Map();
const handlers = new Map();
extension({
  registerTool(tool) { tools.set(tool.name, tool); },
  on(event, handler) { handlers.set(event, handler); return () => handlers.delete(event); },
});
const profile = process.env.CTXQL_PI_PROFILE;
const expected = profile === "chat"
  ? ["ctxql_capabilities","ctxql_ontology","ctxql_graph_query","ctxql_source"]
  : ["ctxql_ontology","ctxql_entities","ctxql_graph_query","ctxql_graph_playground","ctxql_skill"];
for (const name of expected) if (!tools.has(name)) throw new Error(`missing ${name}`);
for (const name of tools.keys()) if (!expected.includes(name)) throw new Error(`unexpected ${name}`);
if (tools.get("ctxql_ontology").executionMode !== "sequential") throw new Error("ontology not sequential");
if (tools.get("ctxql_graph_query").executionMode !== "sequential") throw new Error("query not sequential");
if (profile !== "chat" && tools.get("ctxql_graph_playground").executionMode !== "sequential") throw new Error("playground not sequential");
const ontology = await tools.get("ctxql_ontology").execute("call-o", {operation:"describe",query:"urn:x"});
if (!ontology.content[0].text.includes("urn:x")) throw new Error("ontology response");
const graph = await tools.get("ctxql_graph_query").execute("call-g", {query:"{}"});
if (!graph.content[0].text.includes("graph")) throw new Error("graph response");
if (profile === "chat") {
  const warming = handlers.get("cache_warming_decision");
  if (!warming || (await warming({type:"cache_warming_decision"}, {}))?.action !== "stop") throw new Error("cache warming not stopped");
  const capabilities = await tools.get("ctxql_capabilities").execute("call-c", {});
  if (!capabilities.content[0].text.includes("chat")) throw new Error("capabilities dispatch");
  const source = await tools.get("ctxql_source").execute("call-src", {reference:"S1"});
  if (!source.content[0].text.includes("S1")) throw new Error("source dispatch");
} else {
  const playground = await tools.get("ctxql_graph_playground").execute("call-p", {operation:"check"});
  if (!playground.content[0].text.includes("check")) throw new Error("playground dispatch");
}
async function mustReject(operation, expected) {
  try { await operation(); } catch (error) {
    if (!String(error).includes(expected)) throw error;
    return;
  }
  throw new Error(`expected rejection: ${expected}`);
}
await mustReject(() => tools.get("ctxql_graph_query").execute("oversize", {query:"é".repeat(20000)}), "request limit");
const abort = new AbortController(); abort.abort();
await mustReject(() => tools.get("ctxql_graph_query").execute("aborted", {query:"{}"}, abort.signal), "aborted");
const liveAbort = new AbortController();
const pending = tools.get("ctxql_graph_query").execute("cancel-live", {query:"block"}, liveAbort.signal);
setTimeout(() => liveAbort.abort(), 25);
await mustReject(() => pending, "aborted");
const originalToken = process.env.CTXQL_ONTOLOGY_TOKEN;
process.env.CTXQL_ONTOLOGY_TOKEN = "foreign";
await mustReject(() => tools.get("ctxql_graph_query").execute("foreign", {query:"{}"}), "unauthorized");
process.env.CTXQL_ONTOLOGY_TOKEN = originalToken;
if (profile !== "chat") {
  const skill = await tools.get("ctxql_skill").execute("call-s", {name:"ctxql-query"});
  if (!skill.content[0].text.includes("Query CTXQL")) throw new Error("skill response");
  await mustReject(() => tools.get("ctxql_skill").execute("chat-skill", {name:"ctxql-answer"}), "denied");
}
"#,
        )
        .unwrap();
        let output = std::process::Command::new("node")
            .arg("--experimental-strip-types")
            .arg(&script)
            .current_dir(&bundle.root)
            .env("CDB_EXTENSION", extension)
            .env("CTXQL_PI_PROFILE", "extraction")
            .env("CTXQL_ONTOLOGY_SOCKET", bridge.socket())
            .env("CTXQL_ONTOLOGY_TOKEN", bridge.token())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        for profile in [None, Some("unknown")] {
            let mut command = std::process::Command::new("node");
            command
                .arg("--experimental-strip-types")
                .arg(&script)
                .current_dir(&bundle.root)
                .env(
                    "CDB_EXTENSION",
                    bundle.root.join("extensions/ctxql-ontology-tool.ts"),
                )
                .env_remove("CTXQL_PI_PROFILE");
            if let Some(profile) = profile {
                command.env("CTXQL_PI_PROFILE", profile);
            }
            let output = command.output().unwrap();
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("unknown CTXQL Pi profile"));
        }

        let chat = crate::agent_bundle::hash_agent_bundle_for_profile(
            &source,
            crate::agent_bundle::BundleProfile::Chat,
        )
        .unwrap()
        .stage_verified()
        .unwrap();
        let chat_script = chat.root.join("extension-smoke.mjs");
        std::fs::copy(&script, &chat_script).unwrap();
        let output = std::process::Command::new("node")
            .arg("--experimental-strip-types")
            .arg(&chat_script)
            .current_dir(&chat.root)
            .env(
                "CDB_EXTENSION",
                chat.root.join("extensions/ctxql-ontology-tool.ts"),
            )
            .env("CTXQL_PI_PROFILE", "chat")
            .env("CTXQL_ONTOLOGY_SOCKET", bridge.socket())
            .env("CTXQL_ONTOLOGY_TOKEN", bridge.token())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
