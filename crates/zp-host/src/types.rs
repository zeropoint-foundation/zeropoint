//! Request/result types for host-function calls.
//!
//! These are intentionally minimal — they carry only what the host boundary
//! needs to enforce policy and emit receipts.  Caller-level context (WebSocket
//! sinks, streaming adapters) stays in the surface layer (exec_ws.rs, etc.).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A request to spawn a process through the governed host boundary.
///
/// Callers are responsible for input validation (allowlist checking, metachar
/// rejection, path canonicalization) BEFORE constructing a `SpawnRequest`.
/// The host boundary enforces policy (gate evaluation + receipt); it does not
/// re-validate the command string.
///
/// Use `SpawnRequest::from_validated` (or construct directly) once you hold a
/// `ValidatedCommand`-equivalent (program + args already checked).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnRequest {
    /// The program to execute (must be an absolute path or a name on PATH).
    /// No shell interpretation — passed directly as argv[0].
    pub program: String,

    /// Arguments to the program (argv[1..]).
    pub args: Vec<String>,

    /// Working directory for the spawned process.  Must be canonicalized and
    /// within the substrate's home directory before construction.
    pub cwd: String,

    /// Human-readable actor label (e.g. "exec_ws", "agent:ironclaw").
    /// Used as the `ActorId` in gate evaluation and in audit receipts.
    pub actor_label: String,

    /// Tool name reported to the gate context (`tool_names` field).
    /// Convention: `"exec/<program_name>"`.
    pub tool_name: String,

    /// Environment variables for the spawned process.
    ///
    /// - `None` (default): inherit the current process environment.
    /// - `Some(vars)`: clear the environment completely, then set only these
    ///   variables.  Used by execution-engine to enforce sandbox isolation
    ///   (`env_clear()` + minimal PATH/HOME/TMPDIR/LANG).
    pub env_vars: Option<Vec<(String, String)>>,
}

impl SpawnRequest {
    /// Convenience constructor for exec_ws-style callers that already have a
    /// parsed, validated program + args.  Environment is inherited (None).
    pub fn new(
        program: impl Into<String>,
        args: Vec<String>,
        cwd: impl Into<String>,
        actor_label: impl Into<String>,
        tool_name: impl Into<String>,
    ) -> Self {
        Self {
            program: program.into(),
            args,
            cwd: cwd.into(),
            actor_label: actor_label.into(),
            tool_name: tool_name.into(),
            env_vars: None,
        }
    }

    /// Set an explicit, isolated environment (env_clear + these vars only).
    /// Used by execution-engine to enforce sandbox isolation.
    pub fn with_env_vars(mut self, vars: Vec<(String, String)>) -> Self {
        self.env_vars = Some(vars);
        self
    }
}

/// The result of a successful `HostContext::spawn_process` call.
///
/// The gate has already been consulted and its decision recorded on-chain.
/// The child process has been spawned with stdout/stderr piped.
pub struct SpawnResult {
    /// The spawned child process.  Stdout and stderr are piped; stdin is
    /// closed.  The caller is responsible for consuming output and calling
    /// `child.wait()` to reap the process.
    pub child: tokio::process::Child,

    /// The audit chain entry_hash of the gate decision receipt.
    ///
    /// `None` only if the audit store couldn't be locked (transient mutex
    /// failure) — the gate still allowed the spawn, but the receipt didn't
    /// land.  Callers should log a warning in this case.
    pub gate_receipt_hash: Option<String>,
}

// ── File write types ──────────────────────────────────────────────────────────

/// Whether to truncate-and-create or append to an existing file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WriteMode {
    /// Create the file (or truncate if it exists) and write content.
    Create,
    /// Create the file if it doesn't exist; append content if it does.
    Append,
}

/// A request to write or append to a file through the governed host boundary.
///
/// The caller is responsible for path canonicalization before construction.
/// The host boundary enforces policy (gate evaluation + receipt) but does not
/// re-validate the path.
#[derive(Debug, Clone)]
pub struct WriteRequest {
    /// Destination path.  Must be canonicalized and within the substrate's
    /// home directory before construction.
    pub path: PathBuf,

    /// Content to write (Create) or append (Append).
    pub content: Vec<u8>,

    /// Write mode — create/truncate or append.
    pub mode: WriteMode,

    /// Human-readable actor label (e.g. "write_env_zp", "agent:ironclaw").
    /// Used as the `ActorId` in gate evaluation and in audit receipts.
    pub actor_label: String,

    /// Short human-readable description for the audit receipt
    /// (e.g. "tool env config", "session token").
    pub description: String,
}

impl WriteRequest {
    pub fn new(
        path: impl Into<PathBuf>,
        content: impl Into<Vec<u8>>,
        mode: WriteMode,
        actor_label: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            content: content.into(),
            mode,
            actor_label: actor_label.into(),
            description: description.into(),
        }
    }
}

/// Result of a successful `HostContext::write_file` call.
pub struct WriteResult {
    /// Audit chain entry_hash of the gate decision receipt.  `None` if the
    /// audit store was unreachable (transient mutex failure).
    pub gate_receipt_hash: Option<String>,
    /// Number of bytes written.
    pub bytes_written: usize,
}

// ── HTTP request types ────────────────────────────────────────────────────────

/// HTTP method for an outbound request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
        };
        write!(f, "{}", s)
    }
}

/// A request to make an outbound HTTP call through the governed host boundary.
///
/// Use `HttpRequest::new` for standard (buffered) calls or
/// `HttpRequest::for_streaming` for SSE / long-lived connections.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Full target URL (scheme + host + path + query).
    pub url: String,

    /// HTTP method.
    pub method: HttpMethod,

    /// Request headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,

    /// Request body (may be empty).
    pub body: Vec<u8>,

    /// Human-readable actor label used in gate evaluation and audit receipts.
    pub actor_label: String,

    /// Short description for audit receipts (e.g. "anthropic/messages proxy").
    pub description: String,

    /// Request timeout in milliseconds.
    /// - `Some(ms)`: applies a timeout to the outbound request.
    /// - `None`: no timeout (use for SSE / streaming responses).
    pub timeout_ms: Option<u64>,

    /// When true, disables system proxy settings.
    /// Use for requests to loopback / LAN tool processes.
    pub no_proxy: bool,
}

impl HttpRequest {
    /// Standard buffered request — 30 s timeout, system proxy enabled.
    pub fn new(
        url: impl Into<String>,
        method: HttpMethod,
        headers: Vec<(String, String)>,
        body: impl Into<Vec<u8>>,
        actor_label: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            url: url.into(),
            method,
            headers,
            body: body.into(),
            actor_label: actor_label.into(),
            description: description.into(),
            timeout_ms: Some(30_000),
            no_proxy: false,
        }
    }

    /// Streaming request — no timeout, proxy disabled.
    /// Use for SSE and long-lived connections to local tool processes.
    pub fn for_streaming(
        url: impl Into<String>,
        method: HttpMethod,
        headers: Vec<(String, String)>,
        body: impl Into<Vec<u8>>,
        actor_label: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            url: url.into(),
            method,
            headers,
            body: body.into(),
            actor_label: actor_label.into(),
            description: description.into(),
            timeout_ms: None,
            no_proxy: true,
        }
    }
}

/// Result of a successful `HostContext::http_request` call.
pub struct HttpResult {
    /// HTTP status code.
    pub status: u16,

    /// Response body (fully buffered).
    pub body: Vec<u8>,

    /// Audit chain entry_hash of the gate decision receipt.
    pub gate_receipt_hash: Option<String>,
}
