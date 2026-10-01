//! Bounded loopback-only HTTP/1 adapter. All data operations use Service::dispatch.
use crate::Service;
use cdb_core::{Error, ErrorKind, Result};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    header,
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{
    net::TcpListener,
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};

const MAX_HEADERS: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_URI_BYTES: usize = 256;

struct CancelGuard(Arc<AtomicBool>);
impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
struct ReplyBody {
    bytes: Full<Bytes>,
    _cancel: Option<CancelGuard>,
    _permit: Option<OwnedSemaphorePermit>,
}
impl Body for ReplyBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Infallible>>> {
        Pin::new(&mut self.bytes).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.bytes.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.bytes.size_hint()
    }
}
fn reply(
    status: StatusCode,
    bytes: Vec<u8>,
    cancel: Option<CancelGuard>,
    permit: Option<OwnedSemaphorePermit>,
) -> Response<ReplyBody> {
    let mut response = Response::new(ReplyBody {
        bytes: Full::new(Bytes::from(bytes)),
        _cancel: cancel,
        _permit: permit,
    });
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    response
}
fn failure(status: StatusCode, error: Error) -> Response<ReplyBody> {
    reply(status, error.public_json().into_bytes(), None, None)
}
fn validate_head<B>(request: &Request<B>, max_body: usize) -> Result<String> {
    if request.method() != Method::POST
        || request.uri().path() != "/v1/operation"
        || request.uri().query().is_some()
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().to_string().len() > MAX_URI_BYTES
        || request.headers().len() > MAX_HEADERS
    {
        return Err(Error::invalid("unsupported HTTP request"));
    }
    let mut authorization = request.headers().get_all(header::AUTHORIZATION).iter();
    let value = authorization
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Denied, "credential required"))?;
    if authorization.next().is_some() {
        return Err(Error::new(ErrorKind::Denied, "ambiguous credential"));
    }
    let token = value
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_graphic()) && !v.contains(','))
        .ok_or_else(|| Error::new(ErrorKind::Denied, "invalid credential"))?;
    if let Some(length) = request.headers().get(header::CONTENT_LENGTH) {
        let length = length
            .to_str()
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| Error::invalid("invalid length"))?;
        if length > max_body as u64 {
            return Err(Error::limit());
        }
    }
    Ok(token.to_owned())
}
async fn operation(
    service: Arc<Service>,
    permits: Arc<Semaphore>,
    request: Request<Incoming>,
) -> std::result::Result<Response<ReplyBody>, Infallible> {
    let limits = &service.config().limits;
    let token = match validate_head(&request, limits.max_body_bytes) {
        Ok(token) => token,
        Err(error) => {
            return Ok(failure(
                if error.kind == ErrorKind::Denied {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::BAD_REQUEST
                },
                error,
            ))
        }
    };
    let permit = match permits.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Ok(failure(StatusCode::SERVICE_UNAVAILABLE, Error::limit())),
    };
    let flag = Arc::new(AtomicBool::new(false));
    let guard = CancelGuard(flag.clone());
    let work = async {
        let body = Limited::new(request.into_body(), limits.max_body_bytes)
            .collect()
            .await
            .map_err(|_| Error::limit())?
            .to_bytes();
        service.dispatch(&token, &body, flag).await
    };
    let result = timeout(limits.deadline(), work).await;
    Ok(match result {
        Ok(Ok(bytes)) if bytes.len() <= limits.run_bytes => {
            reply(StatusCode::OK, bytes, Some(guard), Some(permit))
        }
        Ok(Ok(_)) => failure(StatusCode::INTERNAL_SERVER_ERROR, Error::limit()),
        Ok(Err(error)) => failure(
            if error.kind == ErrorKind::Denied {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::BAD_REQUEST
            },
            error,
        ),
        Err(_) => failure(
            StatusCode::REQUEST_TIMEOUT,
            Error::new(ErrorKind::Deadline, "request deadline"),
        ),
    })
}

/// The caller must subsequently shut down the service. No network exposure beyond loopback.
pub async fn serve(
    service: Arc<Service>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if !listener
        .local_addr()
        .map_err(|_| Error::invalid("listener address"))?
        .ip()
        .is_loopback()
    {
        return Err(Error::invalid("loopback listener required"));
    }
    let limits = &service.config().limits;
    let deadline = limits.deadline();
    let connections = Arc::new(Semaphore::new(limits.connections));
    let inflight = Arc::new(Semaphore::new(limits.concurrency));
    let (stop, _) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let result = loop {
        if *shutdown.borrow() {
            break Ok(());
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break Ok(()); }
            },
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, peer) = match accepted { Ok(pair) => pair, Err(_) => break Err(Error::new(ErrorKind::Backend, "accept failed")) };
                if !peer.ip().is_loopback() { continue; }
                let permit = match connections.clone().try_acquire_owned() { Ok(p) => p, Err(_) => continue };
                let service = service.clone();
                let inflight = inflight.clone();
                let mut stopping = stop.subscribe();
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut builder = http1::Builder::new();
                    builder.keep_alive(false).max_headers(MAX_HEADERS).max_buf_size(MAX_HEADER_BYTES)
                        .timer(TokioTimer::new()).header_read_timeout(deadline);
                    let connection = builder.serve_connection(TokioIo::new(stream), service_fn(move |request| operation(service.clone(), inflight.clone(), request)));
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = stopping.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = timeout(deadline, &mut connection).await;
                        },
                        _ = tokio::time::sleep(deadline) => {},
                    }
                });
            }
        }
    };
    drop(listener);
    let _ = stop.send(true);
    if timeout(deadline, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unauthenticated_ambiguous_and_unbounded_heads() {
        let request = Request::post("/v1/operation").body(()).unwrap();
        assert_eq!(
            validate_head(&request, 32).unwrap_err().kind,
            ErrorKind::Denied
        );
        let mut request = Request::post("/v1/operation")
            .header("authorization", "Bearer secret")
            .body(())
            .unwrap();
        assert!(validate_head(&request, 32).is_ok());
        request.headers_mut().append(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer other"),
        );
        assert!(validate_head(&request, 32).is_err());
        for uri in ["/v1/operation?x=1", "/raw", "http://localhost/v1/operation"] {
            assert!(validate_head(
                &Request::post(uri)
                    .header("authorization", "Bearer secret")
                    .body(())
                    .unwrap(),
                32
            )
            .is_err());
        }
        assert!(validate_head(
            &Request::post("/v1/operation")
                .header("authorization", "Bearer secret")
                .header("content-length", "33")
                .body(())
                .unwrap(),
            32
        )
        .is_err());
    }
}
