use super::dispatch::{
    Adapter, Attempt, AttemptFailure, Cancellation, ExecutionClass, FailureClass, PhysicalRequest,
};
use cdb_core::{
    function_manifest::{Batching, ExternalFunctionManifest},
    id::ContentHash,
    CanonicalValue as V, Error, Limits, Result,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    redirect::Policy,
    Url,
};
use std::{collections::BTreeMap, sync::Mutex};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::sleep_until,
};

pub struct SecretString(String);
impl SecretString {
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty() || value.contains(['\r', '\n']) {
            return Err(Error::invalid("invalid provider credential"));
        }
        Ok(Self(value))
    }
}
struct Work {
    request: PhysicalRequest,
    completion: oneshot::Sender<super::dispatch::AttemptOutcome>,
}

/// Pinned HTTP JSON adapter. URL and credentials exist only in startup state. The
/// request sends the registered manifest identity and output-affecting parameters;
/// the response must echo that identity. Neither side replaces the exact published
/// manifest bytes, which remain the local authority and hash source.
pub struct HttpJsonAdapter {
    build: String,
    implementation: String,
    implementation_version: String,
    implementation_build: ContentHash,
    sender: mpsc::Sender<Work>,
    stopping: Cancellation,
    drained: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}
impl HttpJsonAdapter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: &str,
        allow_loopback_plaintext: bool,
        credential: Option<SecretString>,
        queue: usize,
        implementation: String,
        implementation_version: String,
        implementation_build: ContentHash,
    ) -> Result<Self> {
        if queue == 0 {
            return Err(Error::limit());
        }
        let url = Url::parse(endpoint).map_err(|_| Error::invalid("invalid provider endpoint"))?;
        if url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::invalid(
                "provider endpoint contains forbidden components",
            ));
        }
        match url.scheme() {
            "https" => {}
            "http" if allow_loopback_plaintext && is_loopback(&url) => {}
            _ => {
                return Err(Error::invalid(
                    "verified HTTPS required; plaintext is loopback-only",
                ));
            }
        }
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(secret) = credential {
            let mut value = HeaderValue::from_str(&format!("Bearer {}", secret.0))
                .map_err(|_| Error::invalid("invalid provider credential"))?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .default_headers(headers)
            .build()
            .map_err(|_| Error::invalid("HTTP adapter initialization failed"))?;
        let (sender, mut receiver) = mpsc::channel::<Work>(queue);
        let stopping = Cancellation::new();
        let worker_stopping = stopping.clone();
        let (drained_tx, drained_rx) = std::sync::mpsc::channel();
        let target = url.clone();
        tokio::spawn(async move {
            let mut active = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = worker_stopping.cancelled() => {
                        receiver.close();
                        while let Some(work) = receiver.recv().await {
                            let _ = work.completion.send(Err(AttemptFailure {
                                class: FailureClass::Unavailable,
                                retryable: false,
                            }));
                        }
                        break;
                    }
                    work = receiver.recv(), if active.len() < queue => match work {
                        Some(work) => {
                            let client = client.clone();
                            let target = target.clone();
                            let shutdown = worker_stopping.clone();
                            active.spawn(async move {
                                let outcome = execute(&client, &target, work.request, &shutdown).await;
                                let _ = work.completion.send(outcome);
                            });
                        }
                        None => break,
                    },
                    Some(_) = active.join_next(), if !active.is_empty() => {}
                }
            }
            while active.join_next().await.is_some() {}
            let _ = drained_tx.send(());
        });
        Ok(Self {
            build: "ctxql-http-json/v1+reqwest-0.12.28".into(),
            implementation,
            implementation_version,
            implementation_build,
            sender,
            stopping,
            drained: Mutex::new(Some(drained_rx)),
        })
    }
}
fn is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}
impl Adapter for HttpJsonAdapter {
    fn class(&self) -> ExecutionClass {
        ExecutionClass::HttpService
    }
    fn build_identity(&self) -> &str {
        &self.build
    }
    fn supports(&self, m: &ExternalFunctionManifest) -> bool {
        let i = m.implementation();
        i.implementation.as_str() == self.implementation
            && i.version.as_str() == self.implementation_version
            && i.build == self.implementation_build
            && m.batching() == Batching::None
    }
    fn enqueue(&self, request: PhysicalRequest) -> Result<Attempt> {
        if self.stopping.is_cancelled() {
            return Err(Error::invalid("HTTP adapter stopped"));
        }
        let (tx, rx) = oneshot::channel();
        self.sender
            .try_send(Work {
                request,
                completion: tx,
            })
            .map_err(|_| Error::limit())?;
        Ok(Attempt(Box::pin(async move {
            rx.await.unwrap_or(Err(AttemptFailure {
                class: FailureClass::Transport,
                retryable: true,
            }))
        })))
    }
    fn shutdown(&self) -> Result<()> {
        self.stopping.cancel();
        if let Some(drained) = self
            .drained
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            drained
                .recv()
                .map_err(|_| Error::invalid("HTTP adapter worker failed"))?;
        }
        Ok(())
    }
}
impl Drop for HttpJsonAdapter {
    fn drop(&mut self) {
        self.stopping.cancel();
    }
}

async fn execute(
    client: &reqwest::Client,
    url: &Url,
    request: PhysicalRequest,
    shutdown: &Cancellation,
) -> super::dispatch::AttemptOutcome {
    let deadline = request.deadline;
    let cancellation = request.cancellation.clone();
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(deadline_failure()),
        _ = shutdown.cancelled() => Err(AttemptFailure {
            class: FailureClass::Unavailable,
            retryable: false,
        }),
        _ = sleep_until(deadline) => Err(deadline_failure()),
        outcome = execute_inner(client, url, request) => outcome,
    }
}
fn deadline_failure() -> AttemptFailure {
    AttemptFailure {
        class: FailureClass::Deadline,
        retryable: true,
    }
}
async fn execute_inner(
    client: &reqwest::Client,
    url: &Url,
    request: PhysicalRequest,
) -> super::dispatch::AttemptOutcome {
    let expected_binding = request.manifest_binding.clone();
    let mut call = BTreeMap::new();
    call.insert(
        "attempt".into(),
        V::Number(cdb_core::ExactNumber::from_u64(u64::from(request.attempt))),
    );
    call.insert("logical_id".into(), V::String(request.logical_id));
    let mut root = BTreeMap::new();
    root.insert("call".into(), V::Object(call));
    root.insert("input".into(), request.input);
    root.insert("manifest".into(), request.manifest_binding);
    root.insert("schema".into(), V::String("ctxql-function-http/v1".into()));
    let bytes = V::Object(root)
        .canonical_bytes(Limits::default())
        .map_err(|_| AttemptFailure {
            class: FailureClass::Malformed,
            retryable: false,
        })?;
    let mut response = client
        .post(url.clone())
        .body(bytes)
        .send()
        .await
        .map_err(|e| AttemptFailure {
            class: if e.is_timeout() {
                FailureClass::Deadline
            } else {
                FailureClass::Transport
            },
            retryable: e.is_timeout() || e.is_connect(),
        })?;
    if !response.status().is_success() {
        let retryable = matches!(response.status().as_u16(), 429 | 502 | 503 | 504);
        return Err(AttemptFailure {
            class: FailureClass::Status,
            retryable,
        });
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body
                    .len()
                    .checked_add(chunk.len())
                    .is_none_or(|n| n > request.max_result_bytes)
                {
                    return Err(AttemptFailure {
                        class: FailureClass::Oversize,
                        retryable: false,
                    });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => {
                return Err(AttemptFailure {
                    class: FailureClass::Transport,
                    retryable: true,
                });
            }
        }
    }
    let value = V::parse(&body, Limits::default()).map_err(|_| AttemptFailure {
        class: FailureClass::Malformed,
        retryable: false,
    })?;
    value
        .closed(&["schema", "manifest", "output"], &["usage"])
        .map_err(|_| AttemptFailure {
            class: FailureClass::Malformed,
            retryable: false,
        })?;
    if value.field("schema").and_then(V::as_str).ok() != Some("ctxql-function-http/v1")
        || value.field("manifest").ok() != Some(&expected_binding)
    {
        return Err(AttemptFailure {
            class: FailureClass::Malformed,
            retryable: false,
        });
    }
    Ok(value
        .field("output")
        .map_err(|_| AttemptFailure {
            class: FailureClass::Malformed,
            retryable: false,
        })?
        .clone())
}
