//! Tool Reverse Proxy — subdomain-based routing for governed tools.
//!
//! ZeroPoint acts as the single entry point for all governed tools.
//! Each tool is accessed via `{name}.localhost:17770`, and ZP proxies
//! to the tool's ZP-assigned port on loopback.
//!
//! **Why subdomains?**  Modern frameworks (Next.js, Vite, Django, etc.)
//! assume they own `/`.  Path-prefix proxying (`/tools/{name}/...`)
//! requires invasive HTML/JS rewriting that breaks with every framework
//! update.  Subdomain routing gives each tool a clean `/` root — zero
//! rewriting needed.
//!
//! **Governance sensor**: The proxy emits health receipts onto the audit
//! chain based on observed traffic.  A successful 2xx response produces
//! `tool:health:up:{name}`.  A connection failure produces
//! `tool:health:down:{name}`.  A 5xx produces `tool:health:degraded:{name}`.
//!
//! Health receipts are **sampled** — not every request emits one.
//! The sampling window prevents flooding the chain while still giving
//! the state engine enough signal to derive tool liveness.

use axum::{
    body::Body,
    extract::{Host, Request, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;
use tracing::{debug, warn};

use crate::tool_chain;
use crate::tool_state::events;
use crate::AppState;

// ── Health receipt sampling ─────────────────────────────────────────────

/// Minimum interval between health receipts for the same tool (seconds).
/// Prevents flooding the chain on high-traffic tools.
const HEALTH_SAMPLE_INTERVAL_SECS: u64 = 30;

/// Tracks the last time we emitted a health receipt for each tool.
/// This is process-local (not persisted) — if ZP restarts, it emits
/// fresh health receipts on the first requests.
struct HealthSampler {
    last_emitted: Mutex<HashMap<String, (Instant, HealthKind)>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthKind {
    Up,
    Down,
    Degraded,
}

impl HealthSampler {
    fn new() -> Self {
        Self {
            last_emitted: Mutex::new(HashMap::new()),
        }
    }

    /// Should we emit a health receipt for this tool?
    /// Returns true if:
    ///   - We've never emitted one, OR
    ///   - The health status changed (up→down, down→up, etc.), OR
    ///   - Enough time has passed since the last emission
    fn should_emit(&self, tool: &str, kind: HealthKind) -> bool {
        let mut map = self.last_emitted.lock().unwrap();
        let now = Instant::now();

        if let Some((last_time, last_kind)) = map.get(tool) {
            // State changed — always emit
            if *last_kind != kind {
                map.insert(tool.to_string(), (now, kind));
                return true;
            }
            // Same state — throttle
            if now.duration_since(*last_time).as_secs() < HEALTH_SAMPLE_INTERVAL_SECS {
                return false;
            }
        }

        map.insert(tool.to_string(), (now, kind));
        true
    }
}

/// Global sampler — lives for the lifetime of the ZP process.
fn sampler() -> &'static HealthSampler {
    static SAMPLER: std::sync::OnceLock<HealthSampler> = std::sync::OnceLock::new();
    SAMPLER.get_or_init(HealthSampler::new)
}

// ── Subdomain extraction ────────────────────────────────────────────────

/// Extract the tool name from a `Host` header.
///
/// Valid patterns:
///   - `ember.localhost`         → Some("ember")
///   - `ember.localhost:17770`    → Some("ember")
///   - `my-tool.localhost:17770`  → Some("my-tool")
///   - `localhost:17770`          → None (bare host, not a tool)
///   - `127.0.0.1:17770`        → None
///
/// Only the first subdomain label is used.  `a.b.localhost` → "a".
pub fn extract_subdomain(host: &str) -> Option<String> {
    // Strip port if present
    let hostname = host.split(':').next().unwrap_or(host);

    // Must end with "localhost" and have a subdomain prefix
    if !hostname.ends_with("localhost") {
        return None;
    }

    // "localhost" alone — no subdomain
    if hostname == "localhost" {
        return None;
    }

    // "ember.localhost" → strip ".localhost"
    let prefix = hostname.strip_suffix(".localhost")?;

    // Take only the first label (e.g. "a.b" → "a")
    let name = prefix.split('.').next().unwrap_or(prefix);

    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

// ── Proxy handler ───────────────────────────────────────────────────────

/// Subdomain proxy — the main handler for `{tool}.localhost:17770/*`.
///
/// Extracts the tool name from the Host header, looks up its port,
/// and forwards the entire request unchanged.  No path rewriting,
/// no HTML surgery, no monkey-patches.  The tool sees itself at `/`.
pub async fn subdomain_proxy(
    state: State<AppState>,
    Host(host): Host,
    req: Request,
) -> Result<Response, StatusCode> {
    let tool_name = extract_subdomain(&host).ok_or_else(|| {
        // Not a tool subdomain — this handler shouldn't have been called.
        // The main router handles bare localhost requests.
        debug!("Subdomain proxy: no tool in host '{}'", host);
        StatusCode::NOT_FOUND
    })?;

    let path = req.uri().path().trim_start_matches('/').to_string();
    proxy_inner(&state, &tool_name, &path, req).await
}

// ── Core proxy logic ────────────────────────────────────────────────────

pub(crate) async fn proxy_inner(
    state: &AppState,
    tool_name: &str,
    path: &str,
    req: Request,
) -> Result<Response, StatusCode> {
    // Look up the assigned port
    let assignment = state
        .0
        .port_registry
        .get_assigned(tool_name)
        .ok_or_else(|| {
            warn!("Proxy: no port assignment for tool '{}'", tool_name);
            StatusCode::NOT_FOUND
        })?;

    // Build target URL, preserving query string.
    // The tool sees the original path — no prefix stripping needed.
    // Use proxy_target() which prefers the discovered web-UI port
    // over the statically-assigned primary port.
    let target_port = assignment.proxy_target();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let target_url = zp_net::peer_url_with_path(
        "127.0.0.1",
        target_port,
        &format!("/{}{}", path, query),
    );

    debug!("Proxy: {} → {}", tool_name, target_url);

    // Detect if this looks like an SSE request (Accept: text/event-stream)
    let accepts_sse = req
        .headers()
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/event-stream"))
        .unwrap_or(false);

    // ── Port through governed host boundary ─────────────────────────
    // Build headers, convert method, read body — then dispatch through
    // state.0.host.http_request_streaming() which enforces gate evaluation
    // and receipt emission before any network call leaves the process.
    let method = req.method().clone();
    let mut fwd_headers: Vec<(String, String)> = vec![];
    for (key, value) in req.headers() {
        let k = key.as_str().to_lowercase();
        if k == "host" || k == "connection" || k == "transfer-encoding" || k == "accept-encoding" {
            continue;
        }
        if let Ok(v) = value.to_str() {
            fwd_headers.push((key.as_str().to_string(), v.to_string()));
        }
    }
    fwd_headers.push(("X-ZeroPoint-Governed".to_string(), "true".to_string()));
    fwd_headers.push(("X-ZeroPoint-Tool".to_string(), tool_name.to_string()));
    fwd_headers.push(("Authorization".to_string(), format!("Bearer {}", assignment.auth_token)));

    let body_bytes = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let http_method = match &method {
        m if m == axum::http::Method::GET     => zp_host::HttpMethod::Get,
        m if m == axum::http::Method::POST    => zp_host::HttpMethod::Post,
        m if m == axum::http::Method::PUT     => zp_host::HttpMethod::Put,
        m if m == axum::http::Method::DELETE  => zp_host::HttpMethod::Delete,
        m if m == axum::http::Method::PATCH   => zp_host::HttpMethod::Patch,
        m if m == axum::http::Method::HEAD    => zp_host::HttpMethod::Head,
        m if m == axum::http::Method::OPTIONS => zp_host::HttpMethod::Options,
        _ => zp_host::HttpMethod::Post,
    };

    let http_req = if accepts_sse {
        zp_host::HttpRequest::for_streaming(
            &target_url, http_method, fwd_headers, body_bytes.to_vec(),
            "tool_proxy", format!("{}/{}", tool_name, path),
        )
    } else {
        zp_host::HttpRequest::new(
            &target_url, http_method, fwd_headers, body_bytes.to_vec(),
            "tool_proxy", format!("{}/{}", tool_name, path),
        )
    };

    // ── Send to tool via governed host boundary ──────────────────────
    let resp = match state.0.host.http_request_streaming(http_req).await {
        Ok(r) => r,
        Err(zp_host::HostError::GateDenied { reason }) => {
            return Ok((StatusCode::TOO_MANY_REQUESTS, format!("gate denied: {}", reason))
                .into_response());
        }
        Err(e) => {
            warn!("Proxy: failed to reach {} at {}: {}", tool_name, target_url, e);
            if sampler().should_emit(tool_name, HealthKind::Down) {
                let event = events::for_tool(events::HEALTH_DOWN, tool_name);
                let detail = format!("error={} target={}", e, target_url);
                tool_chain::emit_tool_receipt(&state.0.audit_store, &event, Some(&detail));
            }
            return Err(StatusCode::BAD_GATEWAY);
        }
    };
    let resp_status = resp.status().as_u16();

    // ── Emit health receipt based on response ────────────────────────
    let health_kind = if (200..400).contains(&resp_status) {
        HealthKind::Up
    } else if resp_status >= 500 {
        HealthKind::Degraded
    } else {
        HealthKind::Up // 4xx is still "tool is responding"
    };

    if sampler().should_emit(tool_name, health_kind) {
        let event = match health_kind {
            HealthKind::Up => events::for_tool(events::HEALTH_UP, tool_name),
            HealthKind::Degraded => events::for_tool(events::HEALTH_DEGRADED, tool_name),
            HealthKind::Down => events::for_tool(events::HEALTH_DOWN, tool_name),
        };
        let detail = format!("status={} method={} path=/{}", resp_status, method, path);
        let audit_store = state.0.audit_store.lock().ok();
        drop(audit_store);
        tool_chain::emit_tool_receipt(&state.0.audit_store, &event, Some(&detail));
    }

    emit_traffic_receipt(state, tool_name, resp_status);

    // ── Build the axum response ──────────────────────────────────────
    let status =
        StatusCode::from_u16(resp_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    // ── SSE streaming fast-path ──────────────────────────────────────
    let is_sse = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/event-stream"))
        .unwrap_or(false);

    if is_sse {
        let mut response = Response::builder().status(status);
        for (key, value) in resp.headers() {
            let k = key.as_str().to_lowercase();
            if k == "transfer-encoding" || k == "connection" || k == "content-length" {
                continue;
            }
            if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
                response = response.header(key.as_str(), v);
            }
        }
        let byte_stream = resp.bytes_stream();
        let body = Body::from_stream(byte_stream);
        return response
            .body(body)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── Standard response — pass through unchanged ───────────────────
    let mut response = Response::builder().status(status);

    let is_html = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(false);

    for (key, value) in resp.headers() {
        let k = key.as_str().to_lowercase();
        if k == "transfer-encoding" || k == "connection" || k == "content-length" {
            continue;
        }
        // Strip encoding headers — we asked upstream not to compress
        if k == "content-encoding" {
            continue;
        }
        if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
            response = response.header(key.as_str(), v);
        }
    }

    let resp_bytes = resp.bytes().await.map_err(|e| {
        warn!(
            "Proxy: failed to read response body from {}: {}",
            tool_name, e
        );
        StatusCode::BAD_GATEWAY
    })?;

    // For HTML responses: inject a minimal governance script.
    // No path rewriting — just auth token auto-inject so the tool
    // recognizes the user without a login screen.
    let final_body = if is_html {
        let html = String::from_utf8_lossy(&resp_bytes);
        let injected = inject_governance_script(&html, &assignment.auth_token);
        response = response
            .header("Content-Encoding", "identity")
            .header("Cache-Control", "no-store");
        Body::from(injected)
    } else {
        Body::from(resp_bytes)
    };

    response
        .body(final_body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

// ── Governance script injection ─────────────────────────────────────────

/// Inject a minimal governance script into HTML responses.
///
/// Unlike the old path-prefix proxy, this does NOT rewrite any paths.
/// The only injection is the auth token auto-inject so tools that read
/// `?token=...` from the URL can authenticate automatically.
fn inject_governance_script(html: &str, auth_token: &str) -> String {
    let script = format!(
        r#"<script data-zp-governance="true">
(function(){{
  if(!new URLSearchParams(window.location.search).has('token')){{
    var u=new URL(window.location);
    u.searchParams.set('token','{auth_token}');
    window.history.replaceState({{}},'',u.pathname+u.search);
  }}
}})();
</script>"#,
        auth_token = auth_token,
    );

    // Inject right after <head>
    let lower = html.to_lowercase();
    if let Some(start) = lower.find("<head") {
        if let Some(offset) = lower[start..].find('>') {
            let insert_pos = start + offset + 1;
            let mut result = String::with_capacity(html.len() + script.len());
            result.push_str(&html[..insert_pos]);
            result.push_str(&script);
            result.push_str(&html[insert_pos..]);
            return result;
        }
    }

    // Fallback: prepend if no <head> found
    format!("{}{}", script, html)
}

// ── Traffic receipts (heavily sampled) ──────────────────────────────────

const TRAFFIC_SAMPLE_INTERVAL_SECS: u64 = 60;

fn emit_traffic_receipt(state: &AppState, tool_name: &str, status: u16) {
    static TRAFFIC_SAMPLER: std::sync::OnceLock<Mutex<HashMap<String, Instant>>> =
        std::sync::OnceLock::new();
    let sampler = TRAFFIC_SAMPLER.get_or_init(|| Mutex::new(HashMap::new()));

    let now = Instant::now();
    let mut map = sampler.lock().unwrap();

    if let Some(last) = map.get(tool_name) {
        if now.duration_since(*last).as_secs() < TRAFFIC_SAMPLE_INTERVAL_SECS {
            return;
        }
    }

    map.insert(tool_name.to_string(), now);
    drop(map);

    let event = if status >= 500 {
        events::for_tool(events::TRAFFIC_ERROR, tool_name)
    } else {
        events::for_tool(events::TRAFFIC_REQUEST, tool_name)
    };

    tool_chain::emit_tool_receipt(&state.0.audit_store, &event, None);
}

// ── Port assignments API ────────────────────────────────────────────────

/// API endpoint to list current port assignments (for dashboard / debugging).
pub async fn port_assignments_handler(State(state): State<AppState>) -> impl IntoResponse {
    let port = state.0.config_port;
    let assignments = state.0.port_registry.list_map();
    let entries: Vec<serde_json::Value> = assignments
        .iter()
        .map(|(name, a)| {
            serde_json::json!({
                "name": name,
                "port": a.port,
                "port_var": a.port_var,
                "proxy_url": format!("http://{}.localhost:{}/", name, port),
            })
        })
        .collect();
    axum::Json(serde_json::json!({ "assignments": entries }))
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_subdomain() {
        assert_eq!(
            extract_subdomain("ember.localhost:17770"),
            Some("ember".into())
        );
        assert_eq!(extract_subdomain("ember.localhost"), Some("ember".into()));
        assert_eq!(
            extract_subdomain("my-tool.localhost:17770"),
            Some("my-tool".into())
        );
        assert_eq!(
            extract_subdomain("EMBER.localhost:17770"),
            Some("EMBER".into())
        );
        assert_eq!(extract_subdomain("localhost:17770"), None);
        assert_eq!(extract_subdomain("localhost"), None);
        assert_eq!(extract_subdomain("127.0.0.1:17770"), None);
        assert_eq!(extract_subdomain("a.b.localhost:17770"), Some("a".into()));
        assert_eq!(extract_subdomain(".localhost"), None);
    }
}
