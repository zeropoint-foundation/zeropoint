//! Canonical loopback gRPC serve helper for tonic.
//!
//! See module docs in `lib.rs` for the rationale.

use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::server::Router;

use crate::bind::{bind_loopback, bind_network};

/// Handles for a dual-stack gRPC serve. Each task runs until the
/// shutdown token fires (or until tonic surfaces a serve error).
pub struct GrpcServeHandles {
    pub v4: tokio::task::JoinHandle<()>,
    pub v6: Option<tokio::task::JoinHandle<()>>,
    pub bound_stacks: Vec<&'static str>,
}

/// Bind both IPv4 and IPv6 loopback for a tonic Router, spawn one
/// serve task per stack, return handles plus the `bound_stacks`
/// summary.
///
/// `router_factory` is called once per stack to construct the
/// per-task router. tonic's `Router` is not `Clone`, so the caller
/// returns a fresh `Server::builder().add_service(...)...` from the
/// closure. The factory is called once per stack; ensure handler
/// construction is cheap or memoize state externally.
///
/// The `shutdown` token gates graceful drain — when it fires, each
/// `tonic::transport::Server::serve_with_incoming_shutdown` task
/// finishes its in-flight RPCs and exits.
pub async fn serve_loopback_grpc_with_shutdown<F>(
    router_factory: F,
    port: u16,
    shutdown: CancellationToken,
) -> anyhow::Result<GrpcServeHandles>
where
    F: Fn() -> Router + Send + 'static,
{
    let listener = bind_loopback(port).await?;
    let bound_stacks = listener.bound_stacks();

    let v4_stream = TcpListenerStream::new(listener.v4);
    let v4_router = router_factory();
    let v4_shutdown = shutdown.clone();
    let v4 = tokio::spawn(async move {
        if let Err(e) = v4_router
            .serve_with_incoming_shutdown(v4_stream, v4_shutdown.cancelled_owned())
            .await
        {
            tracing::error!("gRPC v4 server error: {}", e);
        }
    });

    let v6 = listener.v6.map(|v6_listener| {
        let v6_stream = TcpListenerStream::new(v6_listener);
        let v6_router = router_factory();
        let v6_shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = v6_router
                .serve_with_incoming_shutdown(v6_stream, v6_shutdown.cancelled_owned())
                .await
            {
                tracing::error!("gRPC v6 server error: {}", e);
            }
        })
    });

    Ok(GrpcServeHandles {
        v4,
        v6,
        bound_stacks,
    })
}

/// Bind a single-stack network-facing gRPC listener, spawn the serve
/// task, return a handle plus the (single-stack) `bound_stacks`
/// summary. Use this for non-loopback deployments (`0.0.0.0`,
/// explicit public IP).
///
/// `router_factory` matches `serve_loopback_grpc_with_shutdown`'s
/// shape so the call site doesn't fork on bind mode — it always
/// passes a factory closure.
pub async fn serve_network_grpc_with_shutdown<F>(
    router_factory: F,
    addr: &str,
    port: u16,
    shutdown: CancellationToken,
) -> anyhow::Result<GrpcServeHandles>
where
    F: Fn() -> Router + Send + 'static,
{
    let listener = bind_network(addr, port).await?;
    let stream = TcpListenerStream::new(listener);
    let router = router_factory();
    let task_shutdown = shutdown.clone();
    let v4 = tokio::spawn(async move {
        if let Err(e) = router
            .serve_with_incoming_shutdown(stream, task_shutdown.cancelled_owned())
            .await
        {
            tracing::error!("gRPC server error: {}", e);
        }
    });

    Ok(GrpcServeHandles {
        v4,
        v6: None,
        bound_stacks: vec!["ipv4"],
    })
}
