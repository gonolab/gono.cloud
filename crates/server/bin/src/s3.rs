//! The S3 API's listener (`s3.bind`), next to the HTTP server.
//!
//! The API itself is [`gono_server_s3`]; this adapts its service to axum, so that it is served
//! with the same accept loop (`TCP_NODELAY`) and graceful shutdown as the main listener.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse as _, Response},
};
use gono_server_s3::S3State;
use ipnet::IpNet;

use crate::{client_ip::client_ip, request_log::redact};

/// The router of the S3 listener: every request goes to the S3 API, and one log line per
/// request records it (presigned URLs lose their signatures there, like every query value).
pub fn router(state: S3State, trusted_proxies: Arc<Vec<IpNet>>) -> Router {
    let service = gono_server_s3::service(state);
    let handler = move |request: Request<Body>| {
        let mut service = service.clone();
        async move {
            match tower_service::Service::call(&mut service, request).await {
                Ok(response) => response.map(Body::new),
                // s3s answers protocol errors itself; what reaches here failed below it.
                Err(err) => {
                    tracing::error!(error = ?err, "S3 request failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
    };
    Router::new()
        .fallback(handler)
        .layer(middleware::from_fn_with_state(
            trusted_proxies,
            log_requests,
        ))
}

/// Logs method, redacted target, status, duration and client address of an S3 request.
async fn log_requests(
    State(trusted_proxies): State<Arc<Vec<IpNet>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let started = Instant::now();
    let method = request.method().clone();
    let target = redact(request.uri());
    let client = client_ip(peer.ip(), request.headers(), &trusted_proxies);
    let response = next.run(request).await;
    tracing::info!(
        %method,
        %target,
        status = response.status().as_u16(),
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        %client,
        "s3 request"
    );
    response
}
