use cdb_core::{id::ContentHash, CanonicalValue as V};
use cdb_service::broker::{
    dispatch::{Adapter, Cancellation, FailureClass, PhysicalRequest},
    http::{HttpJsonAdapter, SecretString},
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::{sleep, timeout, Instant},
};

const BUILD: &str = "sha256:274b81f561128c138f601d2fb5ac4288c4a4a6841199ca915be55d3b903b7f7f";

fn binding() -> V {
    let mut value = BTreeMap::new();
    value.insert("artifact_hash".into(), V::String(BUILD.into()));
    value.insert("semantic_parameters".into(), V::Object(BTreeMap::new()));
    V::Object(value)
}
fn request(
    max_result_bytes: usize,
    deadline: Instant,
    cancellation: Cancellation,
) -> PhysicalRequest {
    PhysicalRequest {
        logical_id: "logical-transport-test".into(),
        attempt: 1,
        input: V::String("input-cannot-be-an-endpoint".into()),
        max_result_bytes,
        deadline,
        cancellation,
        manifest_binding: binding(),
    }
}
fn adapter(endpoint: &str, credential: Option<SecretString>) -> Arc<HttpJsonAdapter> {
    Arc::new(
        HttpJsonAdapter::new(
            endpoint,
            true,
            credential,
            4,
            "urn:test:http".into(),
            "1".into(),
            ContentHash::parse(BUILD).unwrap(),
        )
        .unwrap(),
    )
}
async fn server(
    status: u16,
    body: Option<Vec<u8>>,
    pause: bool,
) -> (
    String,
    oneshot::Receiver<Vec<u8>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/fixed", listener.local_addr().unwrap());
    let (wire_tx, wire_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut wire = Vec::new();
        let header_end = loop {
            let mut chunk = [0; 1024];
            let n = timeout(Duration::from_secs(2), stream.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            if n == 0 {
                return;
            }
            wire.extend_from_slice(&chunk[..n]);
            if let Some(p) = wire.windows(4).position(|v| v == b"\r\n\r\n") {
                break p + 4;
            }
        };
        let headers = String::from_utf8_lossy(&wire[..header_end]);
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        while wire.len() - header_end < length {
            let mut chunk = [0; 1024];
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            wire.extend_from_slice(&chunk[..n]);
        }
        let _ = wire_tx.send(wire.clone());
        if pause {
            sleep(Duration::from_secs(5)).await;
            return;
        }
        let body = body.unwrap_or_else(|| {
            let request = V::parse(
                &wire[header_end..header_end + length],
                cdb_core::Limits::default(),
            )
            .unwrap();
            let mut response = BTreeMap::new();
            response.insert(
                "manifest".into(),
                request.field("manifest").unwrap().clone(),
            );
            response.insert("output".into(), V::Null);
            response.insert("schema".into(), V::String("ctxql-function-http/v1".into()));
            V::Object(response)
                .canonical_bytes(cdb_core::Limits::default())
                .unwrap()
        });
        let response = format!("HTTP/1.1 {status} X\r\nLocation: http://127.0.0.1:1/stolen\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
    });
    (endpoint, wire_rx, task)
}

#[tokio::test]
async fn transport_rejects_status_malformed_oversize_and_identity_mismatch() {
    for (status, body, limit, expected) in [
        (302, Some(Vec::new()), 1024, FailureClass::Status),
        (
            200,
            Some(b"not-json".to_vec()),
            1024,
            FailureClass::Malformed,
        ),
        (200, Some(vec![b'x'; 128]), 16, FailureClass::Oversize),
        (
            200,
            Some(br#"{"manifest":{},"output":null,"schema":"ctxql-function-http/v1"}"#.to_vec()),
            1024,
            FailureClass::Malformed,
        ),
    ] {
        let (endpoint, wire, task) = server(status, body, false).await;
        let adapter = adapter(&endpoint, None);
        let result = timeout(
            Duration::from_secs(2),
            adapter
                .enqueue(request(
                    limit,
                    Instant::now() + Duration::from_secs(1),
                    Cancellation::new(),
                ))
                .unwrap()
                .finish(),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(result.class, expected);
        let _ = wire.await;
        task.await.unwrap();
        tokio::task::spawn_blocking(move || adapter.shutdown())
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn request_has_fixed_path_headers_input_and_manifest_identity() {
    let (endpoint, wire, task) = server(200, None, false).await;
    let adapter = adapter(
        &endpoint,
        Some(SecretString::new("test-secret".into()).unwrap()),
    );
    let outcome = adapter
        .enqueue(request(
            1024,
            Instant::now() + Duration::from_secs(1),
            Cancellation::new(),
        ))
        .unwrap()
        .finish()
        .await;
    assert!(outcome.is_ok());
    let wire = wire.await.unwrap();
    let header_end = wire.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
    let headers = String::from_utf8_lossy(&wire[..header_end]).to_ascii_lowercase();
    assert!(headers.starts_with("post /fixed http/1.1\r\n"));
    assert!(headers.contains("content-type: application/json"));
    assert!(headers.contains("authorization: bearer test-secret"));
    let body = V::parse(&wire[header_end..], cdb_core::Limits::default()).unwrap();
    assert_eq!(body.field("manifest").unwrap(), &binding());
    assert_eq!(
        body.field("input").unwrap().as_str().unwrap(),
        "input-cannot-be-an-endpoint"
    );
    task.await.unwrap();
    tokio::task::spawn_blocking(move || adapter.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn timeout_cancellation_and_shutdown_cooperatively_drain_http() {
    for mode in 0..3 {
        let (endpoint, wire, task) = server(200, None, true).await;
        let adapter = adapter(&endpoint, None);
        let cancellation = Cancellation::new();
        let attempt = adapter
            .enqueue(request(
                1024,
                Instant::now()
                    + if mode == 0 {
                        Duration::from_millis(30)
                    } else {
                        Duration::from_secs(2)
                    },
                cancellation.clone(),
            ))
            .unwrap();
        let _ = timeout(Duration::from_secs(1), wire).await.unwrap();
        if mode == 1 {
            cancellation.cancel();
        }
        if mode == 2 {
            let closing = adapter.clone();
            tokio::task::spawn_blocking(move || closing.shutdown())
                .await
                .unwrap()
                .unwrap();
        }
        let failure = timeout(Duration::from_secs(1), attempt.finish())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(
            failure.class,
            if mode == 2 {
                FailureClass::Unavailable
            } else {
                FailureClass::Deadline
            }
        );
        if mode != 2 {
            tokio::task::spawn_blocking({
                let adapter = adapter.clone();
                move || adapter.shutdown()
            })
            .await
            .unwrap()
            .unwrap();
        }
        task.abort();
    }
}

#[test]
fn plaintext_loopback_and_endpoint_components_are_closed() {
    assert!(HttpJsonAdapter::new(
        "http://example.com/x",
        true,
        None,
        1,
        "i".into(),
        "1".into(),
        ContentHash::parse(BUILD).unwrap()
    )
    .is_err());
    assert!(HttpJsonAdapter::new(
        "http://127.0.0.1/x?model=other",
        true,
        None,
        1,
        "i".into(),
        "1".into(),
        ContentHash::parse(BUILD).unwrap()
    )
    .is_err());
    assert!(HttpJsonAdapter::new(
        "http://user@127.0.0.1/x",
        true,
        None,
        1,
        "i".into(),
        "1".into(),
        ContentHash::parse(BUILD).unwrap()
    )
    .is_err());
}
