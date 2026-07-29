> **Promoted from `docs/handoffs/` on 2026-07-29.** This document is the cited
> rationale for 3 shipped discipline pins — `no_raw_peer_url_outside_zp_net`, `no_raw_tcp_bind_outside_zp_net`, `no_raw_tonic_serve_outside_zp_net` — which fail the
> build when violated. `docs/handoffs/` is excluded by `.gitignore`, and the corpus
> convention adopted 2026-07-27 classifies handoffs as local notes rather than corpus,
> so until this promotion the rule travelled with the repo and the reason for it did
> not. Content is unchanged from the handoff original, which remains in place locally
> as the working copy. References below to companion *investigation* documents still
> point into `docs/handoffs/` and are still local-only: those are working notes, and
> deliberately not promoted.

# Design — Singular loopback binding (structural sweep)

*2026-05-21. Companion to
`docs/handoffs/singular-loopback-binding-investigation-2026-05.md`.
Phases 1–4. Phase 5 (IronClaw side) is separate scope, separate repo,
separate brief.*

*Phase 0 already landed in working tree at
`crates/zp-server/src/lib.rs:1423` (HTTP dual-stack) and `:1517` /
`:1543` (gRPC dual-stack). This design preserves those patches'
behavior while moving them behind a single canonical helper.*

---

## Surface findings (confirmed against tree at `e3ef121`)

### TcpListener::bind sites — 7 occurrences

| # | Location | Kind | Role under new design |
|---|----------|------|---|
| 1 | `crates/zp-server/src/lib.rs:1423` | tokio | HTTP IPv4 (Phase 0). **Migrates to `bind_loopback`.** |
| 2 | `crates/zp-server/src/lib.rs:1437` | tokio | HTTP IPv6 (Phase 0). **Absorbed into `bind_loopback`.** |
| 3 | `crates/zp-preflight/src/checks.rs:240` | std::net | Port-availability probe (not a server). **Stays — pin allowlist.** |
| 4 | `crates/zp-cli/src/main.rs:3367` | std::net | Port-availability probe (not a server). **Stays — pin allowlist.** |
| 5 | `crates/zp-hardening-tests/src/harness.rs:209` | tokio | Test harness, port-0 random bind. **Stays — pin allowlist for `tests/`.** |
| 6 | `crates/zp-mesh/src/tcp.rs:300` | tokio | Mesh `TcpServerInterface::bind`. **Stays — non-loopback transport, distinct concern; pin allowlist.** |
| 7 | `crates/trust-triangle/src/bin/main.rs:87, 111` | tokio | Demo binaries (clinic, pharmacy). **Migrates to `bind_loopback`** — they bind 127.0.0.1 and would trip the same trap. |

Plus tonic Server::builder + `.serve(...)` sites:

| # | Location | Role under new design |
|---|----------|---|
| 1 | `crates/zp-server/src/lib.rs:1517` | gRPC IPv4 (Phase 0). **Migrates to `serve_loopback_grpc`.** |
| 2 | `crates/zp-server/src/lib.rs:1543` | gRPC IPv6 (Phase 0). **Absorbed into `serve_loopback_grpc`.** |

The investigation's "two ZP bind sites" was the HTTP + gRPC pair the
Phase 0 patch addressed. The surface is broader (4 server-bind sites
+ 3 non-server uses); the pin must distinguish *loopback servers*
(must route through helper) from *probes / mesh transport / tests*
(allowlisted, will not migrate).

### PortRegistry receipt schema — confirmed

- `ReceiptType::PortAllocated` and `ReceiptType::PortReleased` declared
  in `crates/zp-receipt/src/types.rs:576` (variant), `:608`
  (id_prefix → `"port"`), `:728` (Display impl).
- Emitted by `crates/zp-server/src/tool_ports.rs:579`
  (`emit_allocate_receipt`) and `:608` (`emit_release_receipt`).
- Receipt payload is the `zp.port.lifecycle` extension, currently:
  ```json
  { "tool": "...", "port": 17010, "port_var": "PORT",
    "pid": 12345, "extra_ports": {...},
    "preference_source": "Default" }
  ```
- Receipt extension namespace is `zp.port.lifecycle` — **not**
  `"port:allocated"` as the brief sketched. The brief's `port:allocated`
  string is the `event` field on the `SystemEvent`
  (`port:lifecycle:port` per the `append_to_chain` formatter). Schema
  extension lands inside `zp.port.lifecycle` regardless.

**Important scoping clarification.** PortRegistry allocates ports for
*tool processes* launched via `tool_proxy` / `launch_inference`. The
substrate's own HTTP (17010) and gRPC (17011) listeners do **not** go
through PortRegistry today. The investigation brief's framing —
"chain is canonical answer to what's listening where" — implies a
choice:

- **(a) Minimal:** `bound_stacks` is added to tool-port receipts.
  Substrate's own listeners remain off-chain. Phase 4 only touches
  `tool_ports.rs`. Future-compatible — substrate listeners can be
  added later.
- **(b) Full:** Substrate's own HTTP and gRPC listeners also emit
  `PortAllocated` receipts at startup. The chain becomes the literal
  answer to "what is the substrate listening on right now." More
  scope; closer to the lsof-test endgame.

**Recommendation: (a) now, (b) as a follow-up.** Option (a) is one
field-add to one struct + one validator update. Option (b) requires
deciding the actor identity for substrate-own allocations
(`ActorId::System("zp_server_listener")`?), where the receipt is
emitted (early in `start()`, before `axum::serve` ever returns), and
how PID is recorded (the substrate's own PID, not a tool's). All
tractable but separable. Land (a) as Phase 4; surface (b) as a task
in the same change.

### tokio-util — already transitively in tree

Cargo.lock shows `tokio-util` pulled by `axum`, `h2`, `hyper-util`,
`tonic`, `tower-http`, etc. (six call sites in the workspace lock).
We can depend on it directly in `zp-net` without a new third-party
crate cost. `CancellationToken` lives in `tokio_util::sync`.

---

## Phase 1 — `zp-net::bind_loopback` (canonical bind path)

### Crate placement

**New crate: `crates/zp-net/`.** Justification:

- Phase 1 callers: `zp-server`, `crates/trust-triangle` (demo binaries).
- Phase 2 callers: `zp-server`, `zp-cli`, `zp-configure`, `zp-server`'s
  `tool_proxy.rs` / `launch_inference.rs`, `zp-server`'s
  `onboard/detect.rs` and `onboard/verify.rs`.
- Both phases have callers in multiple crates. Putting the helpers in
  `zp-server` forces dependency inversion (zp-cli would need to depend
  on zp-server for a URL builder). Putting them in `zp-config` is
  defensible but hides networking inside a config crate.
- A dedicated `zp-net` makes the surface discoverable from the crate
  name and matches the Singular Sovereign Root shape: one named
  module for one canonical concern. The pin's `restrict_paths` /
  `allow_path` rules are also easier to write when the canonical
  module has its own path prefix.

Crate layout:

```
crates/zp-net/
├── Cargo.toml
└── src/
    ├── lib.rs           // re-exports
    ├── bind.rs          // Phase 1: bind_loopback, bind_network, DualStackListener
    ├── grpc.rs          // Phase 1: serve_loopback_grpc helper
    ├── peer.rs          // Phase 2: peer_url, peer_grpc_uri
    └── shutdown.rs      // Phase 3: ShutdownCoordinator (optional re-export)
```

Dependencies: `tokio`, `tokio-util` (for CancellationToken in
shutdown.rs), `tonic`, `tracing`, `http`, `anyhow`. No ZP-crate
dependencies — `zp-net` sits at the bottom of the graph.

### Public API — bind side

```rust
// crates/zp-net/src/bind.rs

use tokio::net::TcpListener;

/// Result of a dual-stack loopback bind.
///
/// `v4` is the required listener — IPv4 loopback is the substrate's
/// minimum guarantee. `v6` is best-effort: a successful IPv6 bind
/// closes the resolver-order trap (clients that resolve `localhost`
/// to `::1` first); a failed IPv6 bind is logged and the dual-stack
/// flag becomes `["ipv4"]` for the receipt layer.
pub struct DualStackListener {
    pub v4: TcpListener,
    pub v6: Option<TcpListener>,
}

impl DualStackListener {
    /// Stacks actually bound, in canonical form for the receipt's
    /// `bound_stacks` field. Always contains "ipv4"; contains "ipv6"
    /// iff `v6` is Some.
    pub fn bound_stacks(&self) -> Vec<&'static str> { ... }
}

/// Bind both IPv4 and IPv6 loopback at the given port.
///
/// Returns Ok with v4 always present; v6 present when [::1]:port
/// could be bound (logged-and-continue on failure).
/// Returns Err only when IPv4 bind itself fails — IPv4 is required.
pub async fn bind_loopback(port: u16) -> anyhow::Result<DualStackListener>;

/// Bind a non-loopback (network-facing) listener at the explicit
/// address. Single listener — no dual-stack semantics. Emits the
/// existing network-facing warning at WARN level.
pub async fn bind_network(addr: &str, port: u16)
    -> anyhow::Result<TcpListener>;
```

`bind_loopback` body mirrors today's Phase 0 sequence: bind
`127.0.0.1:port`, then attempt `[::1]:port`, log-and-continue on the
IPv6 failure, never fail when v6 fails. The Phase 0 INFO/WARN log
strings move into the helper verbatim so log output is unchanged
across the migration.

### Public API — gRPC side

tonic's `Server::builder().serve(addr)` binds internally and doesn't
take a pre-bound listener cleanly. tonic *does* expose
`.serve_with_incoming(stream)` which accepts a
`Stream<Item = Result<TcpStream, _>>` — wrapping our `TcpListener` in
`tokio_stream::wrappers::TcpListenerStream` works, but adds a
dependency and a non-obvious incantation at each call site.

Choice: provide a tonic-specific helper that accepts a `Server` (the
already-configured builder, including `.add_service` calls) plus a
port, and internally:

1. Calls `bind_loopback(port)` (no, see below — gRPC uses `port + 1`
   by convention, so caller passes the actual gRPC port).
2. Wraps each listener in `TcpListenerStream`.
3. Spawns each `serve_with_incoming` as a task.
4. Returns a `GrpcServeHandles` carrying the v4 and v6 join handles
   plus the `bound_stacks` summary.

```rust
// crates/zp-net/src/grpc.rs

use tonic::transport::server::Router; // the type returned by `.add_service(...)`

/// Bind both IPv4 and IPv6 loopback for a tonic Router; spawn one
/// serve task per listener; return handles + bound_stacks summary.
///
/// `router` is the result of `Server::builder().add_service(...)...`
/// The caller has already configured the service registrations; this
/// helper owns only the bind + spawn step.
///
/// Shutdown: each task takes a CancellationToken (Phase 3) — see
/// `serve_loopback_grpc_with_shutdown` for the wired variant.
pub async fn serve_loopback_grpc(
    router: Router,
    port: u16,
) -> anyhow::Result<GrpcServeHandles>;

pub async fn serve_loopback_grpc_with_shutdown(
    router_factory: impl Fn() -> Router + Send + 'static,
    port: u16,
    shutdown: tokio_util::sync::CancellationToken,
) -> anyhow::Result<GrpcServeHandles>;

pub struct GrpcServeHandles {
    pub v4: tokio::task::JoinHandle<()>,
    pub v6: Option<tokio::task::JoinHandle<()>>,
    pub bound_stacks: Vec<&'static str>,
}
```

`router_factory` exists because the `Router` is not `Clone` — when
binding two listeners we need to construct one router per task. The
factory closure constructs the per-task router from the caller's
service set. The two zp-server call sites already construct a fresh
`NodeStatusHandler` per server task, so the factory shape is a
natural fit.

### Migration plan — Phase 1

`crates/zp-server/src/lib.rs:1423..1582` collapses to:

```rust
let listener = zp_net::bind_loopback(config.port).await?;
let bound_stacks = listener.bound_stacks();

// ... shutdown wiring (Phase 3) ...

let _grpc = zp_net::serve_loopback_grpc_with_shutdown(
    move || {
        let handler = grpc::NodeStatusHandler::new(state.clone());
        tonic::transport::Server::builder()
            .add_service(NodeStatusServer::new(handler))
    },
    config.port + 1,
    shutdown.clone(),
).await?;

// Serve HTTP on both stacks with one shutdown token (Phase 3).
zp_net::serve_dual_http_with_shutdown(listener, app, shutdown).await?;
```

`trust-triangle/src/bin/main.rs:87` and `:111` migrate identically —
they currently bind `127.0.0.1:port` only and would trip the same
trap if anyone ran the demo through `localhost:...`.

`zp-preflight/src/checks.rs:240`, `zp-cli/src/main.rs:3367`, and
`zp-hardening-tests/src/harness.rs:209` do **not** migrate — they
are port-availability probes (bind-and-drop) or random-port test
harnesses, not loopback servers. The discipline pin allowlists these
paths.

`zp-mesh/src/tcp.rs:300` does **not** migrate — it is the mesh
transport's network-facing TCP server interface, a distinct concern.
The discipline pin allowlists `crates/zp-mesh/`.

### Discipline pin — Phase 1

The investigation brief said "pre-commit hook." This repo's
canonical mechanism is **discipline-pin tests** under
`crates/zp-discipline/tests/` (see `no_sh_c_in_tool_launch.rs`,
`no_raw_home_lookup.rs`, etc.) — they run under
`cargo test -p zp-discipline` and panic on violation. We follow that
pattern. The pre-push hook (`.githooks/pre-push`) runs
`cargo check --workspace` and does not currently run tests; we
extend it to also run `cargo test -p zp-discipline --quiet` so pins
fire on push without slowing down `cargo check`.

File: `crates/zp-discipline/tests/no_raw_tcp_bind_outside_zp_net.rs`

```rust
use zp_discipline::Discipline;

#[test]
fn loopback_servers_must_route_through_zp_net() {
    Discipline::new("no_raw_tcp_bind_outside_zp_net")
        .cite_invariant("Principle 8 (one canonical path) — \
                         singular loopback binding")
        .rationale(
            "Direct TcpListener::bind calls (tokio or std::net) for \
             loopback servers re-introduce the IPv4-only trap that \
             surfaced on 2026-05-21 (IronClaw chain_render unreachable \
             via ::1-first resolver). All loopback server binds must \
             route through zp_net::bind_loopback so the IPv4 + IPv6 \
             pair are bound atomically and the bound_stacks fact is \
             carried into the chain.",
        )
        .forbid_pattern(r"tokio::net::TcpListener::bind\(")
        .forbid_pattern(r"std::net::TcpListener::bind\(")
        // Bare `TcpListener::bind(` catches `use tokio::net::TcpListener;`
        // followed by `TcpListener::bind(...)` at the call site.
        .forbid_pattern(r"\bTcpListener::bind\(")
        // Allowlists — paths that may legitimately call bind directly.
        // zp-net itself is the canonical implementation site.
        .allow_path("crates/zp-net/src/")
        // Port-availability probes (bind-then-drop). Not server starts.
        .allow_path("crates/zp-preflight/src/checks.rs")
        .allow_path("crates/zp-cli/src/main.rs")
        // Mesh transport — distinct concern (non-loopback transport).
        .allow_path("crates/zp-mesh/src/")
        // Test harnesses bind port-0 for random ephemeral servers.
        .allow_path("crates/zp-hardening-tests/")
        // Skip comment lines and pin-declaration lines.
        .skip_lines_containing("//")
        .skip_lines_containing("forbid_pattern")
        .assert();
}
```

File: `crates/zp-discipline/tests/no_raw_tonic_serve_outside_zp_net.rs`

```rust
use zp_discipline::Discipline;

#[test]
fn loopback_grpc_must_route_through_zp_net() {
    Discipline::new("no_raw_tonic_serve_outside_zp_net")
        .cite_invariant("Principle 8 — singular loopback binding")
        .rationale(
            "tonic Server::builder().serve(addr) binds IPv4 only and \
             repeats the resolver-order trap for gRPC clients. All \
             gRPC loopback serves must route through \
             zp_net::serve_loopback_grpc which binds both stacks.",
        )
        // The two-line tonic pattern; either half is a violation on its own.
        .forbid_pattern(r"tonic::transport::Server::builder\(\)")
        .forbid_pattern(r"Server::builder\(\)\s*\.")
        .allow_path("crates/zp-net/src/")
        .skip_lines_containing("//")
        .skip_lines_containing("forbid_pattern")
        .assert();
}
```

The pin uses the existing `Discipline` builder; no framework changes.

### Pre-push hook extension

`.githooks/pre-push` currently runs `cargo check --workspace` in a
temp worktree. Append a second step that runs
`cargo test -p zp-discipline --quiet` in the same worktree.
Discipline tests are pure-Rust regex scans — ~1–2 seconds — so the
hook stays inside the 5–30 s budget the hook's docstring promises.

```sh
# After the cargo check block:
echo "pre-push: cargo test -p zp-discipline against HEAD..."
if ! ( cd "$WORKTREE" && cargo test -p zp-discipline --quiet ); then
    echo ""
    echo "pre-push: A discipline pin is failing. Push aborted."
    echo ""
    echo "Run locally for the full violation list:"
    echo "  cargo test -p zp-discipline -- --nocapture"
    exit 1
fi
```

### Phase 1 deliverable — one commit

1. New crate `crates/zp-net/` with `bind.rs` + `grpc.rs` (`peer.rs`
   and `shutdown.rs` land in later phases — files exist as empty
   modules from the start for graph stability).
2. `crates/zp-server/src/lib.rs:1423..1582` migrated to
   `bind_loopback` + `serve_loopback_grpc_with_shutdown` (Phase 3's
   shutdown wiring lands in the same commit as Phase 1 to keep the
   migration coherent — see Phase 3 below).
3. `crates/trust-triangle/src/bin/main.rs:87, :111` migrated to
   `bind_loopback`.
4. Two new discipline pins under `crates/zp-discipline/tests/`.
5. `.githooks/pre-push` extended to run `cargo test -p zp-discipline`.

Workspace `Cargo.toml` gains `zp-net` under `members`. `zp-server`
and `trust-triangle` Cargo.tomls add `zp-net = { path = "../zp-net" }`.

---

## Phase 2 — `zp-net::peer_url` (canonical client path)

### What "peer" means

A "peer service" is a substrate-owned service the caller wants to
reach on the same host via loopback. Three categories appear in the
surface scan:

- **Substrate-internal peer** — code in one crate calling the
  substrate's own HTTP/gRPC endpoints (e.g. tool_proxy forwarding
  to `127.0.0.1:tool_port`, security policy version probe in
  `zp-cli/src/main.rs:3830`).
- **Substrate-launched tool peer** — code addressing a port the
  substrate allocated for a launched tool (`tool_ports.rs:957`,
  `proxy.rs:10` docstring, etc.).
- **External-service peer** — code addressing a tool that ZP did
  *not* launch (Ollama at `localhost:11434`, voice-tuner at
  `localhost:8473`, the chain-renderer proxy at `localhost:17770`).

Phase 2 covers the first two: services where the substrate has
control of (or knowledge of) the server side and where we therefore
benefit from canonicalizing the client URL. The third category —
external services — must remain addressable by URL string because
the substrate doesn't control their stack choice. The pin's
allowlist accounts for this distinction.

### Public API

```rust
// crates/zp-net/src/peer.rs

/// Build an HTTP URL for a substrate peer service on loopback.
///
/// Always returns the IPv4 explicit form: `http://127.0.0.1:<port><path>`.
/// Servers are guaranteed dual-stack via Phase 1, so the IPv4 path
/// is always reachable and the URL is resolver-order-immune.
///
/// `path` may be empty, "/", or start with "/" — the builder
/// normalizes so callers don't have to.
pub fn peer_url(port: u16, path: &str) -> String;

/// Same shape for gRPC clients. Returns http://127.0.0.1:<port>/
/// as an http::Uri — the form tonic Channels accept.
pub fn peer_grpc_uri(port: u16) -> http::Uri;

/// Build a peer URL when only a port is in hand (no path). Equivalent
/// to `peer_url(port, "")` and exists so call sites that previously
/// wrote `format!("http://127.0.0.1:{}", port)` get a 1:1 replacement.
pub fn peer_origin(port: u16) -> String;
```

The choice of IPv4 explicit (not `localhost`, not `[::1]`) is
deliberate: it's the substrate's canonical loopback stack for
client→peer-service calls, the cheapest stack to bind (no v6 module
required on the host), and guaranteed reachable since
`bind_loopback` always succeeds for v4 or fails the bind altogether.

### Migration plan — Phase 2

Targeted call sites (server-side substrate-internal + tool-peer):

| Path | Current pattern | Replacement |
|------|-----------------|-------------|
| `crates/zp-server/src/tool_proxy.rs:186` | `format!("http://127.0.0.1:{}/{}{}", target_port, path, query)` | `peer_url(target_port, &format!("/{}{}", path, query))` |
| `crates/zp-server/src/tool_ports.rs:957` | `format!("http://127.0.0.1:{}/", port)` | `peer_origin(port)` |
| `crates/zp-server/src/onboard/verify.rs:59` | `format!("http://127.0.0.1:{}", tool_port)` | `peer_origin(tool_port)` |
| `crates/zp-cli/src/main.rs:2840` | `format!("http://127.0.0.1:{}", port)` | `peer_origin(port)` |
| `crates/zp-cli/src/main.rs:3830` | `format!("http://127.0.0.1:{}/api/v1/security/policy-version", port)` | `peer_url(port, "/api/v1/security/policy-version")` |
| `crates/zp-server/src/lib.rs:1018-1019, 1226-1227` | CORS origin comparison strings — `format!("http://localhost:{}", port)` and `127.0.0.1` variant | Keep as **server-side comparison** (NOT a client URL); allowlist via comment marker. |
| `crates/zp-server/src/lib.rs:1380, 1383, 1387` | Dashboard launch URLs (`http://localhost:{dashboard_port}/...`) | `peer_url(dashboard_port, "/onboard?token=...")` — but `localhost` is intentional for the browser-facing URL the operator copies; surface as design Q below |
| `crates/zp-server/src/lib.rs:2874, 2918, 2992` | Tool-process `url` field stamped onto `RunningTool` | `peer_origin(p)` |
| `crates/zp-configure/src/lib.rs:308` | `format!("http://localhost:{}/api/v1/proxy/{}{}", ...)` | `peer_url(port, &format!("/api/v1/proxy/{}{}", ...))` — `localhost` → `127.0.0.1` rewrite is a behavior change; see "Compatibility note" below |

**Non-targets (allowlist required):**

- `crates/zp-llm/src/providers/ollama.rs:48` — Ollama is an external
  service. Stays as-is.
- `crates/zp-server/src/onboard/detect.rs:190, 216, 244` — probing
  external providers (Ollama, OpenAI-compatible base URLs). Stays.
- `crates/zp-server/src/lease_heartbeat.rs:344` — config example
  string in docstring/test; stays.
- `crates/zp-server/src/lib.rs:955` — CSP header literal; stays.
- `crates/zp-server/assets/*.js` — frontend code, not Rust scope.
- `crates/zp-cli/src/secure.rs:1122, 1268, 1274` — `eprintln!` prose
  + `open` browser argument. `eprintln!` line is operator-facing
  copy ("Dashboard: http://localhost:17770") — must remain
  `localhost` because that's what operators type. `open` arg is
  passed to the OS browser launcher, same constraint. Stays.

### Compatibility note — `localhost` vs `127.0.0.1` in operator copy

Operator-facing copy ("Dashboard: ...") and browser-launch URLs use
`localhost` deliberately — it's what operators read, type, and
bookmark. Phase 2's substitution targets **machine-to-machine** peer
URLs where the substrate is both the producer and consumer. Operator
copy is preserved through path-based allowlisting (mostly via
`secure.rs` and the dashboard-launch lines in `lib.rs`).

A second compatibility concern: `zp-configure/src/lib.rs:308`
generates the proxy URL injected into tool environments
(`OPENAI_BASE_URL=...`). Tools resolve this URL themselves; flipping
from `localhost` to `127.0.0.1` changes the resolution path tools
take. **Behavior impact:** tools that hardcode TLS SNI based on the
literal hostname would behave differently — but loopback HTTP isn't
TLS, so this is not an actual breakage. The flip is a strict
improvement: it eliminates the same IPv6-first resolver trap on the
tool side that bit IronClaw. Land the flip; surface in the commit
body for explicit acknowledgment.

### Discipline pin — Phase 2

File: `crates/zp-discipline/tests/no_raw_peer_url_outside_zp_net.rs`

```rust
use zp_discipline::Discipline;

#[test]
fn peer_urls_must_route_through_zp_net() {
    Discipline::new("no_raw_peer_url_outside_zp_net")
        .cite_invariant("Principle 8 — singular loopback binding (client side)")
        .rationale(
            "Hardcoded http://localhost:<port> and \
             http://127.0.0.1:<port> URL strings risk the IPv6-first \
             resolver trap (localhost form) or scatter the substrate's \
             loopback policy across N call sites (both forms). All \
             substrate-internal peer URLs must route through \
             zp_net::peer_url / peer_origin / peer_grpc_uri so the \
             canonical stack choice is enforced structurally.",
        )
        // The literal string forms callers tend to format!() into URLs.
        // Loose enough to catch concatenation and format! variants;
        // the path allowlist excludes legitimate non-peer-URL uses.
        .forbid_pattern(r#""http://localhost:"#)
        .forbid_pattern(r#""http://127\.0\.0\.1:"#)
        .forbid_pattern(r#""http://localhost:\{"#)
        .forbid_pattern(r#""http://127\.0\.0\.1:\{"#)

        // Canonical implementation site.
        .allow_path("crates/zp-net/src/")

        // Operator-facing copy + browser-launch URLs (must stay `localhost`).
        .allow_path("crates/zp-cli/src/secure.rs")
        // CSP header literal + CORS comparison + dashboard browser-launch URLs.
        // Narrower-than-file allowlist would be better; for now allow the
        // file and rely on review to keep new peer URLs out of it.
        .allow_path("crates/zp-server/src/lib.rs")
        // External-provider probing — Ollama / OpenAI base URL detection.
        .allow_path("crates/zp-server/src/onboard/detect.rs")
        // External provider client (Ollama).
        .allow_path("crates/zp-llm/src/")
        // Configuration example strings + test fixtures.
        .allow_path("crates/zp-server/src/lease_heartbeat.rs")
        // Discovery-allowlist test fixture.
        .allow_path("crates/zp-engine/src/discovery.rs")
        // Frontend assets — JavaScript scope, not Rust.
        .allow_path("crates/zp-server/assets/")

        .skip_lines_containing("//")
        .skip_lines_containing("forbid_pattern")
        // Cargo and config docstrings sometimes mention these URLs in prose.
        .skip_lines_containing("e.g.")
        .skip_lines_containing("example")
        .assert();
}
```

The `zp-server/src/lib.rs` whole-file allowlist is broader than ideal
(CSP, CORS, dashboard-launch URLs all live there alongside lines that
*should* migrate). After Phase 2's migration lands, follow up with a
tightening pass: move the legitimate uses out of `lib.rs` into smaller
modules (`csp.rs`, `cors.rs`, `dashboard_launch.rs`) and narrow the
allowlist to those files. That follow-up is out of scope for the
Phase 2 commit but tracked in the commit body.

### Phase 2 deliverable — one commit

1. `crates/zp-net/src/peer.rs` populated with `peer_url`,
   `peer_origin`, `peer_grpc_uri`.
2. Migration of the call sites in the table above.
3. One new discipline pin.
4. Commit body documents the `localhost`→`127.0.0.1` flip at
   `zp-configure/src/lib.rs:308` and the `lib.rs` whole-file
   allowlist as a tracked follow-up.

---

## Phase 3 — Cross-listener graceful shutdown

### Current state

`crates/zp-server/src/lib.rs:1457..1478` constructs a single
`shutdown` async block bound to ctrl_c + tool PID cleanup. The block
is consumed once by
`axum::serve(listener, app).with_graceful_shutdown(shutdown)` at
`:1579`. The IPv6 HTTP listener (`:1571`) and both gRPC tasks
(`:1522, :1548`) have no shutdown hook — they die abruptly with the
process when axum's serve future returns.

### Target state

Replace the single-shot `shutdown` async block with a
`CancellationToken`. Spawn one watcher task that calls
`token.cancel()` after `ctrl_c().await + tool PID cleanup`. Each
listener task takes a `.child_token()` (or `.cancelled_owned()`)
and drains gracefully when the token fires.

```rust
use tokio_util::sync::CancellationToken;

let shutdown = CancellationToken::new();

// Signal watcher — owns the existing PID-cleanup logic.
{
    let token = shutdown.clone();
    let pid_dir = pid_dir();
    let server_pid_path = server_pid_path.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutdown signal received — stopping launched tools...");
        if let Ok(entries) = std::fs::read_dir(pid_dir) { /* ... */ }
        std::fs::remove_file(&server_pid_path).ok();
        info!("All tools stopped. Goodbye.");
        token.cancel();
    });
}

// HTTP IPv4 (the main task — `.await`ed, not spawned).
let http_v4_shutdown = shutdown.clone();
let http_v4 = axum::serve(listener.v4, app.clone())
    .with_graceful_shutdown(http_v4_shutdown.cancelled_owned());

// HTTP IPv6 — spawn under the same token.
if let Some(v6) = listener.v6 {
    let app_v6 = app.clone();
    let token = shutdown.clone();
    tokio::spawn(async move {
        if let Err(e) = axum::serve(v6, app_v6)
            .with_graceful_shutdown(token.cancelled_owned())
            .await
        {
            tracing::error!("IPv6 loopback serve error: {}", e);
        }
    });
}

// gRPC v4 + v6 — handled by `serve_loopback_grpc_with_shutdown`
// (Phase 1), which wires the token into both tasks internally.

http_v4.await?;
```

### Why this lands in the Phase 1 commit

Phase 1's migration to `bind_loopback` + `serve_loopback_grpc` rewrites
the same code region. Doing Phase 3's shutdown wiring in a separate
later commit forces an intermediate state where the IPv4 HTTP listener
has a different shutdown story than the IPv6 HTTP listener and the
two gRPC listeners — the half-state shape the
"two-reasonable-models-conflict" heuristic warns against. Bundling
Phase 3 into Phase 1 keeps the migration coherent and avoids the
intermediate.

The investigation brief's phase numbering is preserved for
documentation purposes; the implementation commits are:

- **Commit 1 (Phases 1 + 3 bundled):** introduce `zp-net`,
  migrate the four bind/serve sites, wire CancellationToken through
  all four, add the two discipline pins, extend pre-push hook.
- **Commit 2 (Phase 2):** introduce `peer.rs`, migrate the peer-URL
  call sites, add the third discipline pin.
- **Commit 3 (Phase 4):** extend PortRegistry receipt schema.

### Phase 3 — no separate discipline pin

CancellationToken is a tokio-util type, not a forbidden pattern. The
structural property "all listeners watch the same token" isn't
greppable — it would require AST analysis. Enforcement is by
convention here + integration test (see Acceptance).

---

## Phase 4 — PortRegistry stack-awareness

### Schema change

`crates/zp-server/src/tool_ports.rs` — `ToolBinding` gains:

```rust
/// Stacks the tool intends to bind. Initially set at allocation
/// time from the operator/launcher's intent. Validated post-launch
/// by the binding-reconciler (future): if the tool's actual bind
/// doesn't match the declared stacks, emit a divergence receipt.
///
/// Canonical values: ["ipv4"] (default, single-stack), or
/// ["ipv4", "ipv6"] (dual-stack via zp_net::bind_loopback).
/// Serialized as JSON array in receipt extension.
#[serde(default = "default_bound_stacks")]
pub bound_stacks: Vec<String>,
```

`default_bound_stacks()` returns `vec!["ipv4".to_string()]` so old
JSON files migrate forward without manual intervention. The on-disk
`tool-ports.json` persistence layer round-trips the new field.

### Receipt emission

`emit_allocate_receipt` gains a `bound_stacks: &[&str]` parameter and
includes the field in the `zp.port.lifecycle` extension:

```rust
.extension(
    "zp.port.lifecycle",
    serde_json::json!({
        "tool": tool,
        "port": port,
        "port_var": port_var,
        "pid": pid,
        "extra_ports": extra_ports,
        "preference_source": preference_source,
        "bound_stacks": bound_stacks,  // NEW
    }),
)
```

`allocate_or_existing` accepts the new parameter via a new wrapper
method or via an optional argument — depending on how many call sites
need updating. For Phase 4's minimal landing, default to `["ipv4"]`
inside `emit_allocate_receipt` and add a separate setter
`PortRegistry::record_bound_stacks(&self, tool: &str, stacks: &[&str])`
that the launcher calls *after* it knows whether the tool used
`bind_loopback` (and so bound v4+v6) or its own single-stack bind.
That setter persists into the binding and emits a follow-up
`PortAllocated` receipt amendment — or, simpler: the launcher is
already the caller of `allocate_or_existing`, so the launcher passes
the stacks at allocation time.

Cleanest shape: extend `allocate_or_existing` (and the
backward-compat wrappers) with a `bound_stacks: &[&str]` parameter,
defaulted to `&["ipv4"]` in the backward-compat wrappers and set
explicitly by the new-style call sites that go through
`bind_loopback`.

### What's NOT in Phase 4

- The substrate's own HTTP/gRPC listeners do not yet emit
  `PortAllocated` receipts (see "Important scoping clarification"
  above). Adding them is the natural follow-up to close the chain-
  is-canonical-truth gap. Tracked as a separate task.
- The post-launch binding-reconciler that verifies the actual bind
  matches the receipt's declared `bound_stacks` is also a follow-up.
  Phase 4 introduces the field; future work adds the validator.

### Migration of existing receipts

No backfill required. Old `PortAllocated` receipts on the chain
continue to validate — they lack the field, which deserializes to
the default (`["ipv4"]`) on read. New receipts carry the field
explicitly. The receipt validator in
`crates/zp-receipt/src/validation.rs:238` already treats
PortAllocated/PortReleased as flexible-schema (`TypeRules` permissive
mode for these types); no validator change needed.

### Discipline pin — Phase 4

None at the pin layer. The structural property is "every
`PortAllocated` receipt carries `bound_stacks`," but that's a runtime
invariant of the single emitter (`emit_allocate_receipt`), enforced
by the function signature once the field is required. A pin would be
redundant with the compiler.

### Phase 4 deliverable — one commit

1. `ToolBinding.bound_stacks` field added with default-derivable
   deserialization.
2. `emit_allocate_receipt` signature + body updated to thread the
   field into the receipt extension.
3. `allocate_or_existing` signature updated; backward-compat wrappers
   default to `["ipv4"]`; new call sites pass the value from
   `DualStackListener::bound_stacks()`.
4. Unit test in `tool_ports.rs` confirming a round-trip:
   allocate → receipt contains `bound_stacks` → deserialize binding
   → field round-trips.
5. Commit body notes the follow-up task: substrate-own listeners
   register in PortRegistry.

---

## Acceptance criteria (mapped to investigation brief)

1. **Zero direct `TcpListener::bind` calls outside `zp-net` for
   loopback servers.** Enforced by
   `no_raw_tcp_bind_outside_zp_net.rs`. Mesh / probe / test exceptions
   are explicitly allowlisted and named.
2. **Zero direct tonic `Server::builder().serve(addr)` calls outside
   `zp-net` for loopback gRPC.** Enforced by
   `no_raw_tonic_serve_outside_zp_net.rs`.
3. **Zero hardcoded `http://localhost:` / `http://127.0.0.1:` strings
   in substrate client code outside `zp-net`.** Enforced by
   `no_raw_peer_url_outside_zp_net.rs`. Operator-facing copy,
   external-provider probing, CSP/CORS, and assets are allowlisted.
4. **All four listeners (HTTP v4/v6, gRPC v4/v6) drain on SIGINT.**
   Verified by integration test in `zp-hardening-tests` — spawn the
   server, send SIGINT, observe each listener emit its
   `serve_with_graceful_shutdown` completion message, then process
   exit code 0. Captured in same commit as Phase 1+3.
5. **PortRegistry receipts include `bound_stacks`.** Verified by the
   `tool_ports.rs` unit test added in Phase 4 + visible in the chain
   via `zp chain show port:allocated`.
6. **IronClaw `chain_render` works on first attempt** — Phase 0
   already satisfies this; Phases 1+ make it impossible to regress.
7. **Pre-push hook runs discipline pins.** Verified by tampering with
   a guarded file in a scratch commit and observing the hook fail.

---

## Risk + rollout sequence

**Sequencing:** Commit 1 (Phases 1+3) → Commit 2 (Phase 2) →
Commit 3 (Phase 4). Each commit is independently revertable; each
passes `cargo check --workspace`, `cargo test --workspace`, and the
pre-push hook.

**Highest-risk change:** Commit 1's shutdown rewrite. The existing
shutdown closure performs tool PID cleanup at SIGINT; refactoring it
into a watcher task that owns the cleanup is small in code but
load-bearing for clean process exit. Mitigation:

- Keep the cleanup body byte-identical; only the *scheduling* moves
  from "argument to `with_graceful_shutdown`" to "task body before
  `token.cancel()`."
- Integration test in `zp-hardening-tests` exercises the SIGINT path
  end-to-end (spawn → SIGINT → observe PID cleanup → observe exit).

**Second-highest-risk change:** Commit 2's
`zp-configure/src/lib.rs:308` `localhost`→`127.0.0.1` flip. Tools
launched through ZP receive the new URL in their environment;
behavior change is invisible on modern hosts but could theoretically
affect a tool that does literal-hostname URL matching. Mitigation: a
single environment-variable rewrite, easy to revert; surface the
change explicitly in the commit body.

**Lowest-risk change:** Commit 3's PortRegistry schema extension —
default-derivable field with no validator change. Old receipts read
identically; new receipts carry one extra key.

---

## Out of scope

- **Phase 5 (IronClaw side):** separate repo, separate CLIC, separate
  brief. The Phase 1 dual-stack guarantee unblocks IronClaw's
  IPv4-explicit-via-builder path; the decision between
  happy-eyeballs and builder is captured in the investigation brief.
- **Substrate-own listeners in PortRegistry:** the (b) option above.
  Adds the substrate's HTTP/gRPC ports to the chain alongside tool
  ports. One follow-up task after Phase 4.
- **Tightening the `zp-server/src/lib.rs` whole-file allowlist** in
  Phase 2's pin: separate file structural pass after Phase 2 lands.
- **Post-bind reconciliation** (validator that confirms a tool's
  actual bind matches the receipt's declared `bound_stacks`): future
  work, mentioned by the brief but explicitly out of scope here.
- **happy-eyeballs RFC 6555 client wrapper** for substrate-internal
  HTTP clients: a substrate-wide upgrade independent of this sweep,
  tractable later as Phase 2's IPv4-explicit form already eliminates
  the trap structurally.

---

## Open questions to confirm before Commit 1

1. **`zp-net` as new crate vs. module in `zp-server`?** Design picks
   new crate; confirm.
2. **Bundle Phase 3 into Phase 1's commit?** Design says yes;
   confirm (single coherent migration vs. two-step landing).
3. **Substrate-own listeners → PortRegistry (option b)?** Design says
   defer to follow-up task; confirm.
4. **`zp-configure/src/lib.rs:308` `localhost`→`127.0.0.1` flip on
   tool-injected URL?** Design says yes (strict improvement);
   confirm.
5. **Pre-push hook extension to run `cargo test -p zp-discipline`?**
   Design says yes; confirm budget (~1–2s) is acceptable.

---

## Composition with existing principles

Identical to the investigation brief's mapping — Principle 8,
Singular Sovereign Root, Principle 4, the lsof test,
operator-surface hygiene, friction-is-the-finding. The design's
specific contribution: collapsing what the brief described as "the
helper layer" into a named, addressable, dependency-bottom crate
(`zp-net`) and routing enforcement through the existing
`zp-discipline` framework rather than a new pre-commit-hook
mechanism. The substrate already has a structural-rule enforcement
pattern; using it preserves convention→invariant coherence with the
rest of the codebase.

---

## Refs

- `docs/handoffs/singular-loopback-binding-investigation-2026-05.md`
  — the brief this design realizes.
- `crates/zp-server/src/lib.rs:1423..1582` — Phase 0 patch sites and
  migration target.
- `crates/zp-server/src/tool_ports.rs:579, 608` — receipt emission
  sites updated in Phase 4.
- `crates/zp-receipt/src/types.rs:576, 608, 728` — `PortAllocated`
  receipt type definition.
- `crates/zp-discipline/` — pin framework + existing pin examples
  (`no_sh_c_in_tool_launch.rs`, `no_raw_home_lookup.rs`).
- `.githooks/pre-push` — hook extended in Commit 1.
- `docs/ARCHITECTURE-2026-04.md` Principle 8 — one canonical path
  per substrate concern.
- `~/projects/zeropoint/CLAUDE.md` — Singular Sovereign Root
  heuristic, two-reasonable-models-conflict heuristic, lsof test.
