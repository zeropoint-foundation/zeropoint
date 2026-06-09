//! The HostContext trait — the typed contract for all governed side effects.
//!
//! ## Design rationale
//!
//! The WASM trust boundary (Architecture §Commitment A) makes gate coverage a
//! *structural* invariant rather than a convention.  The mechanism: every
//! side effect with world-external impact (process spawn, file write, network
//! call) is reachable only through a method on this trait.  The production
//! implementation (`SystemHostContext`) always calls the governance gate and
//! always emits an audit receipt — callers have no way to bypass either,
//! because the API does not expose raw `Command::new` or `std::fs::write`.
//!
//! ## Extension
//!
//! Add new host functions here as new privileged actions are ported.  Each
//! new method should follow the same pattern as `spawn_process`:
//!   1. Gate evaluation with an appropriate `ActionType`
//!   2. Gate decision appended to the audit chain
//!   3. Side effect executed only if the gate allows
//!   4. Outcome appended to the audit chain
//!
//! ## WASM note
//!
//! When a WASM module is the caller, the host bindings will delegate to the
//! same trait methods.  The trait is the contract; the WASM ABI is an
//! implementation of it.

use async_trait::async_trait;

use crate::{HostError, HttpRequest, HttpResult, SpawnRequest, SpawnResult, WriteRequest, WriteResult};

/// The interface through which all governed side effects must pass.
///
/// Implementations must satisfy the following invariants for every method:
///
/// - **Gate-first**: the governance gate is consulted before any side effect.
/// - **Receipt-always**: the gate decision is appended to the audit chain
///   regardless of whether the action is allowed or denied.
/// - **No ambient authority**: the implementation must not provide any path
///   to execute a side effect that skips the gate.
#[async_trait]
pub trait HostContext: Send + Sync {
    /// Check the governance gate, spawn a process if allowed, and return the
    /// child handle.
    ///
    /// # Contract
    ///
    /// 1. Evaluates `gate.evaluate(PolicyContext { action: Execute, .. }, actor)`.
    /// 2. Appends the gate decision's `UnsealedEntry` to the audit chain.
    /// 3. If the gate blocks: returns `Err(HostError::GateDenied)`.
    ///    The denial is on-chain before the error propagates.
    /// 4. If the gate allows: spawns `program args` in `cwd` with stdout/stderr
    ///    piped and stdin closed.
    /// 5. Returns `Ok(SpawnResult { child, gate_receipt_hash })`.
    ///
    /// The caller is responsible for:
    /// - Consuming `child.stdout` / `child.stderr`
    /// - Calling `child.wait()` to reap the process
    /// - Emitting an exec-completion receipt (exit code + output hash) once
    ///   streaming is done
    async fn spawn_process(&self, req: SpawnRequest) -> Result<SpawnResult, HostError>;

    /// Check the governance gate, write (or append) a file if allowed, and
    /// return the byte count.
    ///
    /// # Contract
    ///
    /// 1. Evaluates `gate.evaluate(PolicyContext { action: FileOp::Write, .. }, actor)`.
    /// 2. Appends the gate decision's `UnsealedEntry` to the audit chain.
    /// 3. If the gate blocks: returns `Err(HostError::GateDenied)`.
    /// 4. If the gate allows: writes `req.content` to `req.path` using `req.mode`.
    ///    Parent directories are created if absent (best-effort).
    /// 5. Returns `Ok(WriteResult { gate_receipt_hash, bytes_written })`.
    async fn write_file(&self, req: WriteRequest) -> Result<WriteResult, HostError>;

    /// Check the governance gate, make an outbound HTTP call if allowed, and
    /// return the buffered response.
    ///
    /// # Contract
    ///
    /// 1. Evaluates `gate.evaluate(PolicyContext { action: ApiCall { endpoint }, .. }, actor)`.
    /// 2. Appends the gate decision's `UnsealedEntry` to the audit chain.
    /// 3. If the gate blocks: returns `Err(HostError::GateDenied)`.
    /// 4. If the gate allows: sends the HTTP request and buffers the response body.
    /// 5. Returns `Ok(HttpResult { status, body, gate_receipt_hash })`.
    ///
    /// Note: the response body is fully buffered.  Use `http_request_streaming`
    /// for SSE or any response that must be consumed incrementally.
    async fn http_request(&self, req: HttpRequest) -> Result<HttpResult, HostError>;

    /// Like `http_request` but returns the raw `reqwest::Response` for streaming.
    ///
    /// Gate evaluation and receipt emission are identical to `http_request`.
    /// The difference is in stage 4: the response is not buffered — the caller
    /// receives the live `Response` and can stream it (e.g. via `bytes_stream()`).
    ///
    /// Use this for SSE connections and long-lived tool-proxy streams.
    async fn http_request_streaming(
        &self,
        req: HttpRequest,
    ) -> Result<reqwest::Response, HostError>;
}
