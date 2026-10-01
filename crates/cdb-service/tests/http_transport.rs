//! Actual Hyper parser/body-limit tests, not business-authorization integration tests.
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn exchange(raw: &[u8]) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = http1::Builder::new()
            .keep_alive(false)
            .max_headers(4)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|request: Request<Incoming>| async move {
                    let status = if Limited::new(request.into_body(), 8).collect().await.is_ok() {
                        StatusCode::OK
                    } else {
                        StatusCode::PAYLOAD_TOO_LARGE
                    };
                    let mut response = Response::new(Full::new(Bytes::new()));
                    *response.status_mut() = status;
                    Ok::<_, Infallible>(response)
                }),
            )
            .await;
    });
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(raw).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    server.await.unwrap();
    response
}
#[tokio::test]
async fn hyper_rejects_malformed_headers_and_ambiguous_lengths() {
    for request in [
        &b"POST / HTTP/1.1\r\nHost: local\r\nBad Header: x\r\nContent-Length: 0\r\n\r\n"[..],
        &b"POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx"[..],
    ] {
        let response = exchange(request).await;
        assert!(response.starts_with(b"HTTP/1.1 400"));
    }
}
#[tokio::test]
async fn hyper_limits_chunked_body_before_json_parse() {
    let response = exchange(b"POST / HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n123456789\r\n0\r\n\r\n").await;
    assert!(response.starts_with(b"HTTP/1.1 413"));
}
#[tokio::test]
async fn hyper_rejects_malformed_chunked_body() {
    let response = exchange(b"POST / HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\ninvalid\r\n0\r\n\r\n").await;
    // The parser reports an error through Incoming; this harness maps it to 413.
    assert!(response.starts_with(b"HTTP/1.1 413"));
}
#[tokio::test]
async fn hyper_rejects_excess_header_count() {
    let response = exchange(b"POST / HTTP/1.1\r\nHost: local\r\nA: a\r\nB: b\r\nC: c\r\nD: d\r\nContent-Length: 0\r\n\r\n").await;
    assert!(response.starts_with(b"HTTP/1.1 431"));
}
