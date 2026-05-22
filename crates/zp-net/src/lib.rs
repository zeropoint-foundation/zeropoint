//! Canonical loopback networking primitives for the ZeroPoint substrate.
//!
//! # Why this crate exists
//!
//! On 2026-05-21 IronClaw's `chain_render` tool failed for days with
//! "ZP gate unreachable" even though `zp serve` was listening on port
//! 17010 and answering `curl` correctly. Root cause: ZP bound IPv4
//! only (`127.0.0.1:17010`), macOS's resolver returns `::1` first for
//! `localhost`, IronClaw's HTTP client doesn't do RFC 6555 happy-
//! eyeballs fallback. It tried `::1`, got connection-refused, and
//! surfaced the failure without trying `127.0.0.1`.
//!
//! The two-site patch (HTTP + gRPC dual-stack) unblocked the
//! immediate symptom. This crate is the structural follow-up: one
//! canonical bind path, one canonical client URL builder, one
//! canonical shutdown coordinator. Discipline pins in `zp-discipline`
//! enforce that no other crate in the workspace calls
//! `TcpListener::bind` directly for loopback servers, nor uses
//! `tonic::transport::Server::builder().serve(...)` for loopback
//! gRPC, nor formats raw `http://localhost:<port>` / `http://127.0.0.1:<port>`
//! strings for substrate-internal peer URLs.
//!
//! See `docs/handoffs/singular-loopback-binding-design-2026-05.md`.

pub mod bind;
pub mod grpc;

pub use bind::{bind_loopback, bind_network, DualStackListener};
pub use grpc::{
    serve_loopback_grpc_with_shutdown, serve_network_grpc_with_shutdown, GrpcServeHandles,
};

// Re-export CancellationToken so callers don't need a direct
// dependency on tokio-util just to wire shutdown.
pub use tokio_util::sync::CancellationToken;
