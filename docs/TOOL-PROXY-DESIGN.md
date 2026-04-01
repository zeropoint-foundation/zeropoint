# Tool Proxy & Port Management Design

**Status**: Draft / Architecture Sketch
**Author**: Ken + Claude
**Date**: 2026-03-26

## Problem

Every AI tool defaults to the same ports (3000, 8080). When the cockpit
manages multiple tools, port collisions are inevitable. The current
approach—scanning `.env` for a port and hoping it's unique—doesn't scale.

## Solution: ZP as Reverse Proxy

ZeroPoint already governs tool lifecycle. Extend that to own the network
layer: ZP assigns each tool a port from a reserved range, rewrites the
tool's `.env` before launch, and proxies all traffic through itself.

```
Browser ──► localhost:3000/tools/ironclaw/...
                │
                ▼
            ZP Router
                │
                ├── /tools/ironclaw/*  ──► localhost:9101
                ├── /tools/pentagi/*   ──► localhost:9102
                └── /tools/agent-zero/*──► localhost:9103
```

Users never see backend ports. The cockpit tile opens a ZP path, not a
random port. ZP can log, meter, and policy-gate the traffic.

## Port Allocation

Reserved range: **9100–9199** (100 tool slots, expandable).

```rust
// crates/zp-server/src/tool_ports.rs

use std::collections::HashMap;
use std::sync::Mutex;

/// Manages port assignments for governed tools.
///
/// Ports are allocated from a reserved range and persisted in
/// `{data_dir}/tool-ports.json` so they survive restarts.
pub struct PortAllocator {
    range_start: u16,
    range_end: u16,
    /// tool_name → assigned port
    assignments: Mutex<HashMap<String, u16>>,
    persist_path: std::path::PathBuf,
}

impl PortAllocator {
    pub fn new(data_dir: &std::path::Path) -> Self {
        let persist_path = data_dir.join("tool-ports.json");
        let assignments = if persist_path.exists() {
            let data = std::fs::read_to_string(&persist_path).unwrap_or_default();
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        };

        Self {
            range_start: 9100,
            range_end: 9199,
            assignments: Mutex::new(assignments),
            persist_path,
        }
    }

    /// Get or assign a port for a tool. Stable across restarts.
    pub fn get_or_assign(&self, tool_name: &str) -> Result<u16, PortError> {
        let mut map = self.assignments.lock().unwrap();

        // Already assigned?
        if let Some(&port) = map.get(tool_name) {
            return Ok(port);
        }

        // Find next free port in range
        let used: std::collections::HashSet<u16> = map.values().copied().collect();
        for port in self.range_start..=self.range_end {
            if !used.contains(&port) {
                map.insert(tool_name.to_string(), port);
                drop(map);
                self.persist();
                return Ok(port);
            }
        }

        Err(PortError::RangeExhausted)
    }

    /// Release a port (tool unregistered).
    pub fn release(&self, tool_name: &str) {
        let mut map = self.assignments.lock().unwrap();
        map.remove(tool_name);
        drop(map);
        self.persist();
    }

    /// All current assignments (for dashboard display).
    pub fn list(&self) -> HashMap<String, u16> {
        self.assignments.lock().unwrap().clone()
    }

    fn persist(&self) {
        let map = self.assignments.lock().unwrap();
        if let Ok(json) = serde_json::to_string_pretty(&*map) {
            let _ = std::fs::write(&self.persist_path, json);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PortError {
    #[error("All ports in range {0}–{1} are assigned")]
    RangeExhausted,
}
```

## .env Rewriting at Launch

Before spawning a tool, ZP patches the `.env` with the assigned port.
This is surgical—only the port variable changes, everything else stays.

```rust
// In the launch handler, before spawning:

/// Rewrite port variables in a tool's .env to the ZP-assigned port.
fn rewrite_env_port(tool_path: &Path, port: u16) -> std::io::Result<()> {
    let env_path = tool_path.join(".env");
    if !env_path.exists() {
        return Ok(()); // No .env to rewrite
    }

    let contents = std::fs::read_to_string(&env_path)?;
    let mut lines: Vec<String> = Vec::new();
    let mut found_any = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.contains('=') {
            lines.push(line.to_string());
            continue;
        }

        if let Some((key, _val)) = trimmed.split_once('=') {
            let key = key.trim();
            if PORT_VAR_NAMES.iter().any(|&p| p == key) {
                // Rewrite this port variable, preserve the key name
                lines.push(format!("{}={}", key, port));
                found_any = true;
                continue;
            }
        }
        lines.push(line.to_string());
    }

    // If no port var existed, inject one
    if !found_any {
        lines.push(format!("PORT={}", port));
    }

    std::fs::write(&env_path, lines.join("\n") + "\n")
}
```

## Reverse Proxy Layer

An axum handler that forwards requests from `/tools/{name}/*` to the
tool's assigned port. This is the HTTP equivalent of what `proxy.rs`
already does for LLM providers.

```rust
// crates/zp-server/src/tool_proxy.rs

use axum::{
    extract::{Path, State},
    http::{Request, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use hyper::body::Body;

/// Proxy handler: /tools/{tool_name}/{rest}
///
/// Forwards the request to localhost:{assigned_port}/{rest},
/// preserving method, headers, and body.
pub async fn proxy_tool_request(
    State(state): State<AppState>,
    Path((tool_name, rest)): Path<(String, String)>,
    req: Request<Body>,
) -> Result<Response, StatusCode> {
    // Look up assigned port
    let port = state.port_allocator
        .get_assigned(&tool_name)
        .ok_or(StatusCode::NOT_FOUND)?;

    // Build target URL
    let target = format!("http://127.0.0.1:{}/{}", port, rest);
    let target_uri: Uri = target.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    // --- Governance check (optional per-request policy) ---
    // This is where ZP can enforce per-tool access policies,
    // rate limiting, or audit logging on every proxied request.
    //
    // let gate_result = state.gate.check_tool_access(&tool_name).await;
    // if !gate_result.allowed { return Err(StatusCode::FORBIDDEN); }

    // Forward the request
    let client = hyper::Client::new();
    let (mut parts, body) = req.into_parts();
    parts.uri = target_uri;

    // Inject ZP governance headers so tools know they're governed
    parts.headers.insert(
        "X-ZeroPoint-Governed",
        "true".parse().unwrap(),
    );
    parts.headers.insert(
        "X-ZeroPoint-Tool",
        tool_name.parse().unwrap(),
    );

    let proxied_req = Request::from_parts(parts, body);

    match client.request(proxied_req).await {
        Ok(resp) => Ok(resp.into_response()),
        Err(_) => Err(StatusCode::BAD_GATEWAY),
    }
}
```

## Router Integration

```rust
// In build_router():

let app = Router::new()
    // ... existing routes ...
    .route("/api/v1/tools/launch", post(launch_tool))
    .route("/api/v1/tools/list",   get(list_tools))
    // Tool proxy — catch-all for /tools/{name}/*
    .route("/tools/:tool_name/*rest", axum::routing::any(proxy_tool_request))
    .with_state(state);
```

## AppState Extension

```rust
pub struct AppStateInner {
    pub gate: GovernanceGate,
    pub audit_store: std::sync::Mutex<AuditStore>,
    pub identity: ServerIdentity,
    pub pipeline: Option<Pipeline>,
    pub grants: std::sync::Mutex<Vec<CapabilityGrant>>,
    pub data_dir: String,
    pub vault_key: Option<zp_keys::ResolvedVaultKey>,
    pub port_allocator: PortAllocator,  // <-- NEW
}
```

## Launch Flow (Updated)

```
1. User clicks cockpit tile for "ironclaw"
2. Dashboard JS → POST /api/v1/tools/launch { name: "ironclaw" }
3. ZP launch handler:
   a. port_allocator.get_or_assign("ironclaw") → 9101
   b. rewrite_env_port(tool_path, 9101)         # GATEWAY_PORT=9101
   c. spawn: docker compose up -d && cargo run --release
   d. respond: { url: "/tools/ironclaw/", port: 9101, kind: "native" }
4. Dashboard JS → waitForPort("/tools/ironclaw/", ...)
5. Port ready → window.open("/tools/ironclaw/")
6. Browser hits ZP at /tools/ironclaw/
7. ZP proxies to 127.0.0.1:9101, injects governance headers
8. IronClaw responds through ZP
```

## Dashboard Changes

Cockpit tiles open ZP paths instead of raw ports:

```javascript
// Before:
window.open(targetUrl, '_blank');  // http://localhost:9101

// After:
window.open(`/tools/${tool.name}/`, '_blank');  // /tools/ironclaw/
```

The diagnostic panel still shows the real port for debugging.

## What This Gets Us

| Benefit | Details |
|---------|---------|
| **No port collisions** | ZP owns the range, assigns deterministically |
| **Single entry point** | Everything through localhost:3000 |
| **Governance on the wire** | ZP sees every request to every tool |
| **Audit trail** | Can log proxied requests alongside LLM proxy receipts |
| **CORS solved** | Same origin, no cross-port issues |
| **Stable URLs** | `/tools/ironclaw/` works forever, port can change |
| **Future: remote tools** | Proxy target could be a remote host, not just localhost |

## WebSocket Consideration

Some tools (including IronClaw) use WebSockets. The proxy needs to
handle WS upgrade requests:

```rust
// In proxy_tool_request, detect upgrade header:
if req.headers().get("upgrade")
    .map_or(false, |v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
{
    return proxy_websocket(tool_name, port, rest, req).await;
}
```

axum + hyper can handle this, but it needs explicit WS forwarding logic.
Tower's `tower-http` doesn't do WS proxying out of the box. Options:

- `hyper` raw connection upgrade (manual but full control)
- `tokio-tungstenite` bridge (proven, battle-tested)
- `pingora` (Cloudflare's proxy lib — might be overkill)

## .env.zp Sidecar (Alternative to .env Rewriting)

Rewriting `.env` directly is invasive — if the user has custom values,
ZP is stepping on their file. A cleaner variant:

1. ZP writes `tool_path/.env.zp` with just the port override
2. The launch command prepends: `source .env.zp &&` before the tool's
   start command
3. Environment variables from `.env.zp` override `.env` values
4. The user's `.env` stays untouched
5. `.env.zp` gets `.gitignored`

```rust
fn write_env_zp(tool_path: &Path, port: u16) -> std::io::Result<()> {
    let zp_env = tool_path.join(".env.zp");
    let content = format!(
        "# Auto-generated by ZeroPoint — do not edit\n\
         # Overrides port to avoid collisions with other governed tools\n\
         GATEWAY_PORT={port}\n\
         PORT={port}\n"
    );
    std::fs::write(&zp_env, content)
}
```

Launch command becomes:
```bash
cd '/path/to/tool' && set -a && source .env.zp && set +a && cargo run --release
```

This is the recommended approach. Cleaner, non-destructive, easy to debug.

## Implementation Order

1. `PortAllocator` struct + persistence → `tool_ports.rs`
2. Wire into `AppState`
3. `.env.zp` sidecar write in launch handler
4. `tool_proxy.rs` — HTTP forwarding
5. WebSocket forwarding
6. Dashboard: tiles open `/tools/{name}/` paths
7. Governance hooks in proxy (audit log, rate limit)

Steps 1–3 are a day of work. Step 4 is another day. Steps 5–7 are
iterative improvements that can land separately.
