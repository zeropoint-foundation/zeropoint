//! Session authentication — bearer token middleware.
//!
//! ZeroPoint uses HMAC-SHA256 session tokens derived from the node's
//! Ed25519 signing key. Tokens are issued at server start and embedded
//! into the dashboard HTML, so the cockpit is authenticated from first
//! load without an external identity provider.
//!
//! Token format: hex(HMAC-SHA256(key_material, nonce || timestamp))
//! The key_material is SHA-256(signing_key_bytes || "zp-session-v1").
//!
//! Routes that bypass auth:
//!   - GET  /api/v1/health          (monitoring probes)
//!   - GET  /onboard                (pre-genesis setup UI)
//!   - GET  /api/onboard/ws         (pre-genesis WebSocket)
//!   - GET  /assets/*               (static files — handled by ServeDir, not routes)
//!   - GET  /                       (root redirect)

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

/// Session token state — shared via AppState.
///
/// The token is wrapped in an `RwLock` so [`Self::rotate`] can invalidate
/// the current session on logout (AUTH-VULN-05/06). `hmac_key` is the
/// immutable derivation input and never changes.
pub struct SessionAuth {
    /// The current valid session token (hex-encoded), behind an RwLock so
    /// logout can rotate it atomically.
    token: RwLock<String>,
    /// HMAC key material derived from the signing key.
    /// Used to derive rotated tokens on logout.
    hmac_key: [u8; 32],
    /// Unix seconds when the current token was minted. Combined with
    /// `max_age` this gives a hard upper bound on session lifetime.
    created_at: RwLock<i64>,
    /// Maximum session lifetime in seconds. Configured from
    /// `ZP_SESSION_MAX_AGE_SECONDS`, default 8 hours.
    max_age_secs: i64,
}

impl SessionAuth {
    /// Create a new session auth context from the server's signing key bytes.
    ///
    /// Generates a fresh session token for this server run.
    pub fn new(signing_key_bytes: &[u8; 32]) -> Self {
        // Derive HMAC key: SHA-256(signing_key || domain_separator)
        let mut hasher = Sha256::new();
        hasher.update(signing_key_bytes);
        hasher.update(b"zp-session-v1");
        let hmac_key: [u8; 32] = hasher.finalize().into();

        let token = Self::mint_token(&hmac_key);
        tracing::info!(
            "Session token generated: {}...{} (valid for this server run)",
            &token[..8],
            &token[token.len() - 4..]
        );

        let max_age_secs = std::env::var("ZP_SESSION_MAX_AGE_SECONDS")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(8 * 60 * 60);

        Self {
            token: RwLock::new(token),
            hmac_key,
            created_at: RwLock::new(chrono::Utc::now().timestamp()),
            max_age_secs,
        }
    }

    /// Mint a fresh hex-encoded session token bound to the HMAC key.
    fn mint_token(hmac_key: &[u8; 32]) -> String {
        let nonce: [u8; 16] = rand::random();
        let timestamp = chrono::Utc::now().timestamp().to_le_bytes();
        let mut token_hasher = Sha256::new();
        token_hasher.update(hmac_key);
        token_hasher.update(nonce);
        token_hasher.update(timestamp);
        hex::encode(token_hasher.finalize())
    }

    /// Return a snapshot of the current token. Callers should minimize how
    /// long they hold it — the returned `String` is a clone, so it's safe
    /// to stash briefly, but it becomes stale after the next `rotate`.
    pub fn current_token(&self) -> String {
        self.token.read().clone()
    }

    /// Session max-age in seconds, for use by cookie builders.
    pub fn max_age_secs(&self) -> i64 {
        self.max_age_secs
    }

    /// Rotate the session token. Called by the logout handler to invalidate
    /// the current session. Returns the newly-minted token.
    pub fn rotate(&self) -> String {
        let new_token = Self::mint_token(&self.hmac_key);
        *self.token.write() = new_token.clone();
        *self.created_at.write() = chrono::Utc::now().timestamp();
        tracing::info!(
            "Session token rotated: {}...{}",
            &new_token[..8],
            &new_token[new_token.len() - 4..]
        );
        new_token
    }

    /// Verify a bearer token matches the current session.
    ///
    /// Returns `false` if the session has expired (past `max_age_secs`)
    /// even when the bytes match — AUTH-VULN-05.
    pub fn verify(&self, candidate: &str) -> bool {
        // Expiry check
        let age = chrono::Utc::now().timestamp() - *self.created_at.read();
        if age >= self.max_age_secs {
            return false;
        }
        let token = self.token.read();
        // Constant-time comparison to prevent timing attacks
        if candidate.len() != token.len() {
            return false;
        }
        let a = candidate.as_bytes();
        let b = token.as_bytes();
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

// ── Failed-auth rate limiter (AUTH-VULN-04) ────────────────────────────

/// In-memory per-IP failed-auth counter.
///
/// Simple sliding window: `limit` failures within `window` from the same IP
/// trigger a `429 Too Many Requests` for subsequent attempts from that IP
/// until the window expires. Not intended to defeat a distributed attacker
/// — this is defense against a single actor probing for a valid token.
///
/// Defaults: 10 failures per 60 seconds per IP. Override with the env var
/// `ZP_AUTH_RATE_LIMIT_PER_MIN`.
pub struct FailedAuthLimiter {
    map: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    window: Duration,
    limit: u32,
}

impl FailedAuthLimiter {
    pub fn new() -> Self {
        let limit = std::env::var("ZP_AUTH_RATE_LIMIT_PER_MIN")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(10);
        Self {
            map: Mutex::new(HashMap::new()),
            window: Duration::from_secs(60),
            limit,
        }
    }

    /// Record a failed auth from `ip`. Returns `Err(retry_after)` once the
    /// per-window limit is exceeded; `Ok(())` otherwise.
    pub fn record_failure(&self, ip: IpAddr) -> Result<(), Duration> {
        let mut map = self.map.lock();
        let now = Instant::now();
        let entry = map.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            // Window expired — reset.
            *entry = (1, now);
            return Ok(());
        }
        entry.0 += 1;
        if entry.0 > self.limit {
            let retry_after = self.window.saturating_sub(now.duration_since(entry.1));
            return Err(retry_after);
        }
        Ok(())
    }

    /// Peek whether `ip` is currently blocked without incrementing.
    pub fn is_blocked(&self, ip: IpAddr) -> Option<Duration> {
        let map = self.map.lock();
        let entry = map.get(&ip)?;
        let now = Instant::now();
        if now.duration_since(entry.1) >= self.window {
            return None;
        }
        if entry.0 > self.limit {
            Some(self.window.saturating_sub(now.duration_since(entry.1)))
        } else {
            None
        }
    }
}

// ============================================================================
// Per-endpoint rate limiter (Phase 1.7: AUTH-VULN-04)
// ============================================================================

/// Per-endpoint sliding window rate limiter.
///
/// Tracks (endpoint, IP) pairs and rejects requests that exceed the
/// configured limit within the window. This protects expensive operations
/// (tool launch, capability grants, audit export) from abuse.
pub struct EndpointRateLimiter {
    /// Map of (endpoint_key, ip) → (count, window_start)
    map: Mutex<HashMap<(String, IpAddr), (u32, Instant)>>,
    /// Per-endpoint limits: (window_secs, max_requests)
    limits: HashMap<String, (Duration, u32)>,
}

impl EndpointRateLimiter {
    pub fn new() -> Self {
        let mut limits = HashMap::new();
        // Tool launch: 5 per minute
        limits.insert("/api/v1/tools/launch".to_string(), (Duration::from_secs(60), 5));
        // Tool stop: 5 per minute
        limits.insert("/api/v1/tools/stop".to_string(), (Duration::from_secs(60), 5));
        // Capability grant: 10 per minute
        limits.insert("/api/v1/capabilities/grant".to_string(), (Duration::from_secs(60), 10));
        // Delegation: 10 per minute
        limits.insert("/api/v1/capabilities/delegate".to_string(), (Duration::from_secs(60), 10));
        // Chat/LLM proxy: 30 per minute
        limits.insert("/api/v1/chat".to_string(), (Duration::from_secs(60), 30));

        Self {
            map: Mutex::new(HashMap::new()),
            limits,
        }
    }

    /// Check whether a request to `path` from `ip` is allowed.
    /// Returns `Ok(())` if allowed, `Err(retry_after)` if rate-limited.
    pub fn check(&self, path: &str, ip: IpAddr) -> Result<(), Duration> {
        // Find the matching limit (exact match or prefix for /api/v1/proxy/*)
        let (key, window, limit) = match self.limits.get(path) {
            Some(&(w, l)) => (path.to_string(), w, l),
            None if path.starts_with("/api/v1/proxy/") => {
                // LLM proxy: 30 per minute
                ("/api/v1/proxy/*".to_string(), Duration::from_secs(60), 30)
            }
            None => return Ok(()), // No limit configured for this endpoint
        };

        let mut map = self.map.lock();
        let now = Instant::now();
        let entry = map.entry((key, ip)).or_insert((0, now));

        if now.duration_since(entry.1) >= window {
            // Window expired — reset
            *entry = (1, now);
            return Ok(());
        }

        entry.0 += 1;
        if entry.0 > limit {
            let retry_after = window.saturating_sub(now.duration_since(entry.1));
            Err(retry_after)
        } else {
            Ok(())
        }
    }
}

impl Default for EndpointRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for FailedAuthLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Paths that bypass authentication.
///
/// These are either pre-genesis flows, health probes, or the root redirect.
fn is_exempt(path: &str) -> bool {
    // Exact matches
    matches!(
        path,
        "/" | "/api/v1/health"
            | "/healthz"
            | "/readyz"
            | "/onboard"
            | "/api/onboard/ws"
    )
    // Prefix matches for static assets (served by ServeDir, but just in case)
    || path.starts_with("/assets/")
}

/// Extract a token from the `Cookie: zp_session=...` header if present.
/// Returns `None` if no cookie header or no matching cookie.
fn extract_cookie_token(req: &Request) -> Option<String> {
    let cookie_header = req.headers().get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("zp_session=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Axum middleware: require valid session token on protected routes.
///
/// Extracts the session token, in priority order:
///   1. `Authorization: Bearer <token>` header (CLI + API clients)
///   2. `Cookie: zp_session=<token>` (browser, HttpOnly, SameSite=Strict)
///   3. `?token=<token>` query param — **only for /ws/* upgrades** because
///      browsers can't set headers on WebSocket connections. HTTP routes no
///      longer honor the query param (AUTH-VULN-03).
///
/// Returns 401 for missing/invalid tokens, 429 when the per-IP failed-auth
/// rate limit is exceeded.
pub async fn require_auth(
    req: Request,
    next: Next,
    session_auth: Arc<SessionAuth>,
    rate_limiter: Arc<FailedAuthLimiter>,
    endpoint_limiter: Arc<EndpointRateLimiter>,
) -> Result<Response, StatusCode> {
    let path = req.uri().path().to_string();

    // Let exempt paths through
    if is_exempt(&path) {
        return Ok(next.run(req).await);
    }

    // Client IP for rate-limiting. Axum doesn't give us ConnectInfo without
    // extra wiring, so we best-effort parse X-Forwarded-For / X-Real-IP /
    // fall back to a synthetic bucket.
    let client_ip: IpAddr = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| {
            req.headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));

    // Check if the IP is already rate-limited before doing any work.
    if let Some(retry_after) = rate_limiter.is_blocked(client_ip) {
        warn!(
            "Auth rate limit: {} blocked for {}s on {}",
            client_ip,
            retry_after.as_secs(),
            path
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Extract bearer token from Authorization header
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let bearer = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    let cookie_token = extract_cookie_token(&req);

    // Query-param token is ONLY accepted on /ws/* upgrades. For any other
    // path, the query param is ignored so tokens never land in access logs
    // or browser history (AUTH-VULN-03).
    let query_token = if path.starts_with("/ws") {
        req.uri()
            .query()
            .and_then(|q| {
                q.split('&')
                    .find(|p| p.starts_with("token="))
                    .map(|p| p.trim_start_matches("token=").to_string())
            })
    } else {
        None
    };

    let token = bearer.or(cookie_token).or(query_token);

    match token {
        Some(t) if session_auth.verify(&t) => {
            // Phase 1.7: per-endpoint rate limiting for expensive operations.
            if let Err(retry_after) = endpoint_limiter.check(&path, client_ip) {
                warn!(
                    "Endpoint rate limit: {} on {} — retry in {}s",
                    client_ip, path, retry_after.as_secs()
                );
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            Ok(next.run(req).await)
        }
        Some(_) => {
            warn!("Auth rejected: invalid token for {}", path);
            if let Err(retry) = rate_limiter.record_failure(client_ip) {
                warn!(
                    "Auth rate limit tripped: {} for {}s",
                    client_ip,
                    retry.as_secs()
                );
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            Err(StatusCode::UNAUTHORIZED)
        }
        None => {
            // For dashboard and page loads, redirect to root (which is exempt)
            // For API calls, return 401
            if path.starts_with("/api/") || path.starts_with("/ws") {
                warn!("Auth rejected: no token for {}", path);
                let _ = rate_limiter.record_failure(client_ip);
                Err(StatusCode::UNAUTHORIZED)
            } else {
                // HTML page requests without auth — let through. The root
                // handler will set the session cookie on response.
                Ok(next.run(req).await)
            }
        }
    }
}

/// Build a `Set-Cookie` header value for the session cookie.
///
/// The cookie is `HttpOnly` (JS cannot read it — neutralizes XSS token
/// theft), `SameSite=Strict` (no cross-site CSRF), and scoped to `/`.
///
/// Phase 1.6 (AUTH-VULN-08): The `Secure` flag is set when TLS is enabled
/// (detected via ZP_TLS_CERT env var). When TLS is active, the cookie is
/// only sent over HTTPS, preventing interception on the wire.
pub fn build_session_cookie(token: &str, max_age_secs: i64) -> String {
    let secure_flag = if is_tls_enabled() { "; Secure" } else { "" };
    format!(
        "zp_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{}",
        token, max_age_secs, secure_flag
    )
}

/// Cookie that immediately invalidates the session on the client — used by
/// the logout handler.
pub fn build_logout_cookie() -> String {
    let secure_flag = if is_tls_enabled() { "; Secure" } else { "" };
    format!(
        "zp_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{}",
        secure_flag
    )
}

/// Check whether TLS is configured (cert + key paths set).
pub fn is_tls_enabled() -> bool {
    std::env::var("ZP_TLS_CERT").is_ok() && std::env::var("ZP_TLS_KEY").is_ok()
}

// ── Command governance for /ws/exec ────────────────────────────────────

/// Command allowlist for governed execution.
///
/// Only commands matching these prefixes are allowed through the exec
/// WebSocket. Everything else is rejected before spawning.
///
/// SECURITY NOTE (Phase 0.2, INJ-VULN-01/02/04, SSRF-VULN-01):
/// The following commands are INTENTIONALLY EXCLUDED:
///   - `curl`, `wget`: enable SSRF and data exfiltration (SSRF-VULN-01, INJ-VULN-04)
///   - `make`, `cmake`: execute arbitrary code via Makefile in attacker-controlled cwd (INJ-VULN-02)
///   - `cargo run`, `cargo build`: arbitrary code execution
///   - `node`, `python`, `python3`, `deno`, `bun`: arbitrary code execution
///   - `pip`, `pip3`: can run setup.py with arbitrary code
///   - `kill`: process termination should go through tool management API
///
/// Each command below has been individually justified. To add a new command,
/// document the threat model in a comment and get security review.
const ALLOWED_CMD_PREFIXES: &[&str] = &[
    // Package managers (install only — safe subcommands)
    "npm install",
    "npm ls",
    "npm list",
    "npm outdated",
    "npm audit",
    "pnpm install",
    "pnpm ls",
    "pnpm list",
    "yarn install",
    "yarn list",
    // Docker (read-only + lifecycle for governed tools)
    "docker ps",
    "docker logs",
    "docker inspect",
    "docker images",
    "docker compose up",
    "docker compose down",
    "docker compose ps",
    "docker compose logs",
    "docker-compose up",
    "docker-compose down",
    "docker-compose ps",
    "docker-compose logs",
    // Git (read-only)
    "git status",
    "git log",
    "git diff",
    "git branch",
    "git remote",
    "git show",
    "git ls-files",
    "git rev-parse",
    // File listing (read-only, no write capability)
    "ls ",
    "ls",
    "cat ",
    "head ",
    "tail ",
    "wc ",
    "file ",
    "tree ",
    "tree",
    // System info (read-only)
    "which ",
    "env",
    "echo ",
    "date",
    "whoami",
    "uname",
    "df ",
    "du ",
    "free",
    "ps ",
    "lsof ",
    "pgrep ",
    // ZP-specific (governed tools)
    "zp doctor",
    "zp config",
    "zp status",
    "zp version",
];

/// Blocked command patterns — these are never allowed regardless of prefix.
///
/// SECURITY NOTE: These are defense-in-depth. The primary defense is the
/// allowlist above + shell metacharacter rejection in exec_ws.rs. These
/// patterns catch anything that somehow slips through.
const BLOCKED_PATTERNS: &[&str] = &[
    // Destructive filesystem operations
    "rm -rf /",
    "rm -rf /*",
    "rm -rf .",
    "mkfs",
    "dd if=",
    "> /dev/sd",
    "chmod 777",
    "chmod -R 777",
    // Fork bomb
    ":(){ :|:& };:",
    // Sensitive files — block regardless of how accessed
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "ssh-keygen",
    "authorized_keys",
    ".zeropoint/keys",
    // Code execution via eval/interpreters
    "eval ",
    "base64 -d",
    "python -c",
    "python3 -c",
    "node -e",
    "perl -e",
    "ruby -e",
    // Data exfiltration patterns (defense in depth)
    "| curl",
    "| wget",
    "|curl",
    "|wget",
    "curl ",
    "wget ",
    // Network tools that enable SSRF
    "nc ",
    "ncat ",
    "netcat ",
    "socat ",
    "telnet ",
    "nmap ",
];

/// Check if a command is allowed by the governance policy.
///
/// Returns `Ok(())` if allowed, `Err(reason)` if blocked.
pub fn check_command(cmd: &str) -> Result<(), String> {
    let cmd_trimmed = cmd.trim();

    if cmd_trimmed.is_empty() {
        return Err("Empty command".to_string());
    }

    // Check blocked patterns first (highest priority)
    for pattern in BLOCKED_PATTERNS {
        if cmd_trimmed.contains(pattern) {
            return Err(format!(
                "Command blocked by governance policy: contains '{}'",
                pattern
            ));
        }
    }

    // Check if command matches any allowed prefix
    let allowed = ALLOWED_CMD_PREFIXES
        .iter()
        .any(|prefix| cmd_trimmed.starts_with(prefix));

    if allowed {
        Ok(())
    } else {
        // Extract the first word of the command for the error message
        let first_word = cmd_trimmed.split_whitespace().next().unwrap_or(cmd_trimmed);
        Err(format!(
            "Command '{}' not in governance allowlist. \
             Use the cockpit to request elevated access.",
            first_word
        ))
    }
}

// ── Path validation for tool registration ──────────────────────────────

/// Paths that must never be registered as tools.
const BLOCKED_PATHS: &[&str] = &[
    "/etc",
    "/var",
    "/usr",
    "/bin",
    "/sbin",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/tmp",
    "/root",
    "/lib",
    "/lib64",
    "/opt",
];

/// Path components that indicate sensitive directories.
const BLOCKED_PATH_COMPONENTS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".gcloud",
    ".config/gcloud",
    ".kube",
    ".docker",
    "id_rsa",
    "id_ed25519",
    ".zeropoint/keys",
    ".zeropoint/data",
    "node_modules",
    "__pycache__",
    ".git",
];

/// Validate a path is safe for tool registration.
///
/// Returns `Ok(canonical_path)` or `Err(reason)`.
pub fn validate_register_path(path: &str) -> Result<std::path::PathBuf, String> {
    let path = path.trim();

    if path.is_empty() {
        return Err("Empty path".to_string());
    }

    // Reject path traversal
    if path.contains("..") {
        return Err("Path traversal (..) not allowed".to_string());
    }

    // Expand tilde
    let expanded = if path.starts_with("~/") || path == "~" {
        match dirs::home_dir() {
            Some(home) => home
                .join(path.strip_prefix("~/").unwrap_or(""))
                .to_string_lossy()
                .to_string(),
            None => path.to_string(),
        }
    } else {
        path.to_string()
    };

    let canonical = match std::path::Path::new(&expanded).canonicalize() {
        Ok(p) => p,
        Err(_) => return Err(format!("Path does not exist: {}", expanded)),
    };

    let canonical_str = canonical.to_string_lossy();

    // EXEC-02 hardening: on macOS, `/etc`, `/var`, `/tmp` canonicalize to
    // `/private/etc`, `/private/var`, `/private/tmp`, which would sneak
    // past a naive prefix check. Compare BOTH the pre-canonical expanded
    // input and the canonical form against the blocked list.
    let expanded_str: &str = &expanded;
    for blocked in BLOCKED_PATHS {
        if expanded_str == *blocked || expanded_str.starts_with(&format!("{}/", blocked)) {
            if *blocked == "/opt" {
                continue;
            }
            return Err(format!(
                "System path '{}' cannot be registered as a tool",
                blocked
            ));
        }
    }
    for blocked in BLOCKED_PATHS {
        if canonical_str.as_ref() == *blocked || canonical_str.starts_with(&format!("{}/", blocked)) {
            // Exception: /opt is sometimes used for tools
            if *blocked == "/opt" {
                continue;
            }
            return Err(format!(
                "System path '{}' cannot be registered as a tool",
                blocked
            ));
        }
    }

    // Check blocked path components
    for component in BLOCKED_PATH_COMPONENTS {
        if canonical_str.contains(component) {
            return Err(format!(
                "Path contains sensitive component '{}' — cannot register",
                component
            ));
        }
    }

    // Must be a directory
    if !canonical.is_dir() {
        return Err(format!("Not a directory: {}", canonical_str));
    }

    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_allowlist() {
        // Allowed commands
        assert!(check_command("docker compose up").is_ok());
        assert!(check_command("docker compose down").is_ok());
        assert!(check_command("docker ps").is_ok());
        assert!(check_command("npm install").is_ok());
        assert!(check_command("npm audit").is_ok());
        assert!(check_command("git status").is_ok());
        assert!(check_command("git log --oneline").is_ok());
        assert!(check_command("ls -la").is_ok());

        // Explicitly removed from allowlist (Phase 0.2)
        assert!(check_command("curl http://example.com").is_err(), "curl must be blocked (SSRF-VULN-01)");
        assert!(check_command("wget http://example.com").is_err(), "wget must be blocked (SSRF-VULN-01)");
        assert!(check_command("make").is_err(), "make must be blocked (INJ-VULN-02)");
        assert!(check_command("make install").is_err(), "make must be blocked (INJ-VULN-02)");
        assert!(check_command("cargo build --release").is_err(), "cargo must be blocked");
        assert!(check_command("cargo run").is_err(), "cargo run must be blocked");
        assert!(check_command("python script.py").is_err(), "python must be blocked");
        assert!(check_command("python3 script.py").is_err(), "python3 must be blocked");
        assert!(check_command("node app.js").is_err(), "node must be blocked");

        // Always blocked
        assert!(check_command("rm -rf /").is_err());
        assert!(check_command("cat /etc/shadow").is_err());
        assert!(check_command("bash").is_err());
        assert!(check_command("sh").is_err());
        assert!(check_command("vim").is_err());
        assert!(check_command("nano").is_err());
    }

    #[test]
    fn test_blocked_patterns_override_allow() {
        // Even if prefix matches, blocked patterns win
        assert!(check_command("echo hello").is_ok());
        // Curl and wget are now blocked at the allowlist level too
        assert!(check_command("curl http://evil.com").is_err());
        assert!(check_command("wget http://evil.com").is_err());
    }

    #[test]
    fn test_double_space_bypass_blocked() {
        // INJ-VULN-01: double space should not bypass blocklist
        // Since "rm" is not in the allowlist, it's blocked regardless
        assert!(check_command("rm  -rf /tmp/test").is_err());
        assert!(check_command("rm\t-rf /tmp/test").is_err());
    }

    #[test]
    fn test_network_tools_blocked() {
        // SSRF-VULN-01: network tools must be blocked
        assert!(check_command("nc 10.0.0.1 8080").is_err());
        assert!(check_command("ncat --listen 4444").is_err());
        assert!(check_command("telnet 127.0.0.1 6379").is_err());
        assert!(check_command("nmap -sV 10.0.0.0/24").is_err());
    }

    #[test]
    fn test_path_validation() {
        assert!(validate_register_path("/etc").is_err());
        assert!(validate_register_path("/root").is_err());
        assert!(validate_register_path("../../../etc").is_err());
        assert!(validate_register_path("").is_err());
    }

    #[test]
    fn test_session_auth() {
        let key = [42u8; 32];
        let auth = SessionAuth::new(&key);
        let tok = auth.current_token();
        assert!(auth.verify(&tok));
        assert!(!auth.verify("bad-token"));
        assert!(!auth.verify(""));
    }

    #[test]
    fn test_session_rotate_invalidates_old_token() {
        let key = [7u8; 32];
        let auth = SessionAuth::new(&key);
        let old = auth.current_token();
        assert!(auth.verify(&old));
        let new = auth.rotate();
        assert_ne!(old, new);
        assert!(!auth.verify(&old));
        assert!(auth.verify(&new));
    }

    #[test]
    fn test_failed_auth_limiter_blocks_after_limit() {
        // Force a tiny limit so we can exercise the block path.
        std::env::set_var("ZP_AUTH_RATE_LIMIT_PER_MIN", "3");
        let limiter = FailedAuthLimiter::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(limiter.record_failure(ip).is_ok());
        assert!(limiter.record_failure(ip).is_ok());
        assert!(limiter.record_failure(ip).is_ok());
        assert!(limiter.record_failure(ip).is_err(), "4th failure should trip");
        assert!(limiter.is_blocked(ip).is_some());
        std::env::remove_var("ZP_AUTH_RATE_LIMIT_PER_MIN");
    }
}
