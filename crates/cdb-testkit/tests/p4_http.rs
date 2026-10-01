//! Real loopback HTTP acceptance; no client crate and no alternate policy authority.
use cdb_backend_fluree::FlureeBackend;
use cdb_core::id::{ContentHash, IdempotencyKey, PrincipalId};
use cdb_service::{
    config::{CredentialTable, InstanceConfig},
    Service,
};
use serde_json::{json, Value};
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

const CONFIG: &str = include_str!("../../../fixtures/conformance/p2/config.json");
const QUERY: &str = r#"{"about":[{"from":["missing"],"match":"exact"}],"bounds":{"max_depth":1}}"#;
fn config(root: &Path) -> InstanceConfig {
    InstanceConfig::parse(
        &format!(
            r#"schema="ctxql-instance/v1"
projection="projection"
credential-file="credentials.json"
source-root="sources"
[authority]
path="authority"
ledger="p4-http:main"
backend="p4-http"
authority="p4-http-authority"
graph="p4-http-graph"
[default-config]
iri="https://test/config"
version="1"
hash="{}"
[limits]
max_body_bytes=8192
concurrency=1
connections=16
deadline_seconds=3
"#,
            ContentHash::of_bytes(CONFIG.as_bytes()).as_str()
        ),
        &root.join("cdb.toml"),
    )
    .unwrap()
}
fn reference(iri: &str, content: &str) -> Value {
    json!({"iri":iri,"version":"1","hash":ContentHash::of_bytes(content.as_bytes()).as_str()})
}
fn op(name: &str) -> Value {
    json!({"schema":"ctxql-service/v1","op":name})
}
fn query(id: &str) -> Value {
    json!({"schema":"ctxql-service/v1","op":"query","run_id":id,"query":reference("https://test/query", QUERY)})
}
struct Server {
    service: Arc<Service>,
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<cdb_core::Result<()>>,
}
impl Server {
    async fn start(service: Arc<Service>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(cdb_service::http::serve(service.clone(), listener, rx));
        Self {
            service,
            addr,
            stop,
            task,
        }
    }
    async fn stop(self) {
        self.stop.send(true).unwrap();
        self.task.await.unwrap().unwrap();
        self.service.shutdown().await.unwrap();
        drop(self.service);
    }
}
struct Reply {
    status: u16,
    body: String,
    wire: String,
}
async fn raw(addr: SocketAddr, wire: &str) -> Reply {
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(wire.as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        let (head, body) = wire.split_once("\r\n\r\n").expect("HTTP response");
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        Reply {
            status,
            body: body.to_owned(),
            wire,
        }
    })
    .await
    .expect("bounded wire request")
}
fn request(token: Option<&str>, body: &str) -> String {
    let auth = token
        .map(|s| format!("Authorization: Bearer {s}\r\n"))
        .unwrap_or_default();
    format!("POST /v1/operation HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}
async fn call(s: &Server, token: &str, v: Value) -> Reply {
    raw(s.addr, &request(Some(token), &v.to_string())).await
}
fn denied(r: &Reply, status: u16, secrets: &[String]) {
    assert_eq!(r.status, status, "{}", r.wire);
    for secret in secrets {
        assert!(!r.wire.contains(secret), "credential leaked");
    }
    for protected in [
        "http-owner-run",
        "https://test/query",
        "recording_snapshot",
        "operation_hash",
        "resolved_plan",
    ] {
        assert!(
            !r.wire.contains(protected),
            "protected metadata leaked: {}",
            r.wire
        );
    }
}
async fn publish(s: &Server, token: &str, iri: &str, content: &str) -> Reply {
    call(s, token, json!({"schema":"ctxql-service/v1","op":"publish","artifact":reference(iri,content),"content":content})).await
}

#[tokio::test]
async fn real_http_auth_record_restart_and_limits() {
    Box::pin(async {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        Box::pin(Service::initialize(config(&root), PrincipalId::new("owner").unwrap(), root.join("owner.secret"))).await.unwrap();
        for (name, admin) in [("reader",false),("other",false),("expired",false),("revoked",false),("disabled",false),("blind",false)] {
            Box::pin(Service::provision(config(&root), PrincipalId::new(name).unwrap(), root.join(format!("{name}.secret")), admin)).await.unwrap();
        }
        let names = ["owner","reader","other","expired","revoked","disabled","blind"];
        let mut secrets: Vec<String> = names.iter().map(|n| std::fs::read_to_string(root.join(format!("{n}.secret"))).unwrap()).collect();
        secrets.push("bad-opaque-secret".into());
        let token = &secrets[0];
        let path = root.join("credentials.json");
        let mut table = CredentialTable::load(&path).unwrap();
        table.entries.iter_mut().find(|e| e.principal == "expired").unwrap().expires_at = Some("2000-01-01T00:00:00Z".into());
        table.entries.iter_mut().find(|e| e.principal == "revoked").unwrap().enabled = false;
        // Preserve the initialized private file's mode; restart-required credentials.
        std::fs::write(&path, serde_json::to_vec(&table).unwrap()).unwrap();
        {
            let backend = Box::pin(FlureeBackend::open(config(&root).authority_options().unwrap())).await.unwrap();
            let mut state = backend.policy_state().await.unwrap();
            state.principals.get_mut(&PrincipalId::new("disabled").unwrap()).unwrap().0 = false;
            state.principals.get_mut(&PrincipalId::new("blind").unwrap()).unwrap().1.remove(&cdb_core::id::Iri::new("https://ctxql.org/roles/serviceReader").unwrap());
            Box::pin(backend.set_policy_state(&IdempotencyKey::new("http-disable").unwrap(), &state)).await.unwrap();
        }
        let s = Server::start(Box::pin(Service::open(config(&root))).await.unwrap()).await;
        denied(&raw(s.addr, &request(None, &op("status").to_string())).await,401,&secrets);
        for i in [3,4,5,7] { denied(&call(&s,&secrets[i],op("status")).await,403,&secrets); }
        println!("P4_CASE {{\"id\":\"P4-H001\",\"outcome\":\"passed\"}}");
        assert_eq!(call(&s,token,op("status")).await.status,200);
        for field in ["principal","admin","trace","unknown"] {
            let mut v = op("status"); v[field] = json!("owner");
            denied(&call(&s,token,v).await,400,&secrets);
        }
        denied(&call(&s,token,json!({"schema":"unknown","op":"status"})).await,400,&secrets);
        denied(&raw(s.addr,&request(Some(token),"{broken")).await,400,&secrets);
        println!("P4_CASE {{\"id\":\"P4-H002\",\"outcome\":\"passed\"}}");
        denied(&publish(&s,&secrets[1],"https://test/query",QUERY).await,403,&secrets);
        denied(&call(&s,&secrets[1],op("admin")).await,400,&secrets);
        assert_eq!(publish(&s,token,"https://test/config",CONFIG).await.status,200);
        assert_eq!(publish(&s,token,"https://test/query",QUERY).await.status,200);
        assert_eq!(call(&s,&secrets[6],op("status")).await.status,200);
        denied(&call(&s,&secrets[6],query("blind-run")).await,403,&secrets);
        println!("P4_CASE {{\"id\":\"P4-H007\",\"outcome\":\"passed\"}}");
        let other = call(&s,&secrets[2],query("other-owner-run")).await;
        assert_eq!(other.status,200,"{}",other.wire);
        let first = call(&s,token,query("http-owner-run")).await;
        assert_eq!(first.status,200,"{}",first.wire);
        let first: Value = serde_json::from_str(&first.body).unwrap();
        assert_eq!(first["run_id"],"http-owner-run");
        for action in ["run","replay"] {
            let v = json!({"schema":"ctxql-service/v1","op":action,"run_id":"http-owner-run"});
            assert_eq!(call(&s,token,v.clone()).await.status,200);
            for i in [1,2] { denied(&call(&s,&secrets[i],v.clone()).await,403,&secrets); }
        }
        denied(&call(&s,&secrets[2],query("http-owner-run")).await,403,&secrets);
        println!("P4_CASE {{\"id\":\"P4-H003\",\"outcome\":\"passed\"}}");
        let base = request(Some(token),&op("status").to_string());
        for wire in [base.replacen("POST ","GET ",1),base.replacen("/v1/operation","/raw",1),base.replacen("/v1/operation","/v1/operation?principal=owner",1)] {
            denied(&raw(s.addr,&wire).await,400,&secrets);
        }
        denied(&raw(s.addr,&base.replacen("Host: localhost\r\n",&format!("Host: localhost\r\nAuthorization: Bearer {}\r\n",secrets[2]),1)).await,401,&secrets);
        denied(&raw(s.addr,&format!("POST /v1/operation HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: 8193\r\n\r\n")).await,400,&secrets);
        let chunk = "x".repeat(8193);
        denied(&raw(s.addr,&format!("POST /v1/operation HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nTransfer-Encoding: chunked\r\n\r\n2001\r\n{chunk}\r\n0\r\n\r\n")).await,400,&secrets);
        println!("P4_CASE {{\"id\":\"P4-H004\",\"outcome\":\"passed\"}}");
        // Expect: 100-continue is a wire barrier proving body collection owns the sole permit.
        let mut stalled = TcpStream::connect(s.addr).await.unwrap();
        stalled.write_all(format!("POST /v1/operation HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n").as_bytes()).await.unwrap();
        let mut interim = [0;25];
        tokio::time::timeout(Duration::from_secs(2),stalled.read_exact(&mut interim)).await.unwrap().unwrap();
        assert_eq!(&interim,b"HTTP/1.1 100 Continue\r\n\r\n");
        denied(&call(&s,token,op("status")).await,503,&secrets);
        drop(stalled);
        let mut recovered = false;
        for _ in 0..100 {
            let r = call(&s,token,op("status")).await;
            if r.status == 200 { recovered=true; break; }
            denied(&r,503,&secrets);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(recovered,"disconnect must release HTTP permit");
        println!("P4_CASE {{\"id\":\"P4-H005\",\"outcome\":\"passed\"}}");
        s.stop().await;
        {
            let check = Box::pin(FlureeBackend::open(config(&root).authority_options().unwrap())).await;
            assert!(check.is_ok(), "reopen diagnostic: {:?}", check.err());
        }
        let s = Server::start(Box::pin(Service::open(config(&root))).await.unwrap()).await;
        let replay = call(&s,token,json!({"schema":"ctxql-service/v1","op":"replay","run_id":"http-owner-run"})).await;
        assert_eq!(replay.status,200,"{}",replay.wire);
        let replay: Value = serde_json::from_str(&replay.body).unwrap();
        assert_eq!(replay["response"]["graph"],"reproduced");
        let retry = call(&s,token,query("http-owner-run")).await;
        assert_eq!(retry.status,200);
        let retry: Value = serde_json::from_str(&retry.body).unwrap();
        assert_eq!(retry["response"],first["response"]);
        println!("P4_CASE {{\"id\":\"P4-H006\",\"outcome\":\"passed\"}}");
        s.stop().await;
    }).await;
}
