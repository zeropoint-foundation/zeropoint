//! Discipline: loopback servers MUST NOT call `TcpListener::bind`
//! directly. All loopback server binds must route through
//! `zp_net::bind_loopback` (or `zp_net::bind_network` for explicit
//! network-facing deployments).
//!
//! # Why (singular loopback binding, 2026-05-21)
//!
//! On 2026-05-21 IronClaw's `chain_render` tool failed for days
//! because `zp serve` bound IPv4 only (`127.0.0.1`), macOS's resolver
//! returns `::1` first for `localhost`, and IronClaw's HTTP client
//! doesn't do RFC 6555 happy-eyeballs fallback. The two-site patch
//! (HTTP + gRPC dual-stack) at `crates/zp-server/src/lib.rs:1423,
//! :1517` unblocked the symptom; the structural fix moves all bind
//! logic into `zp_net::bind_loopback` so the next bind site cannot
//! repeat the trap.
//!
//! See
//! `docs/design/SINGULAR-LOOPBACK-BINDING-2026-05.md`.
//!
//! # Allowlist
//!
//! - `crates/zp-net/src/` — the canonical implementation site.
//! - `crates/zp-preflight/src/checks.rs`,
//!   `crates/zp-cli/src/main.rs` — port-availability probes
//!   (bind-and-drop). Not server starts; the trap doesn't apply.
//! - `crates/zp-mesh/src/` — mesh transport's network-facing TCP
//!   server interface, a distinct concern from loopback substrate
//!   listeners.
//! - `crates/zp-hardening-tests/` — test harnesses bind port-0 for
//!   random ephemeral servers.
//! - `crates/trust-triangle/` — standalone reference demo excluded
//!   from the workspace; migration deferred.

use zp_discipline::Discipline;

#[test]
fn loopback_servers_must_route_through_zp_net() {
    Discipline::new("no_raw_tcp_bind_outside_zp_net")
        .cite_invariant("Principle 8 (one canonical path) — singular loopback binding")
        .rationale(
            "Direct TcpListener::bind calls for loopback servers \
             re-introduce the IPv4-only resolver-order trap that \
             surfaced on 2026-05-21 (ExampleTool chain_render unreachable \
             via ::1-first resolution). All loopback server binds must \
             route through zp_net::bind_loopback so the IPv4 + IPv6 \
             pair are bound atomically and the bound_stacks fact can \
             be carried into the chain.",
        )
        // The tokio form (substrate's standard for async servers).
        .forbid_pattern(r"tokio::net::TcpListener::bind\(")
        // The std form (used in port-availability probes — allowlisted
        // below — and as a backstop for any future blocking bind).
        .forbid_pattern(r"std::net::TcpListener::bind\(")
        // The bare form: `use tokio::net::TcpListener;` followed by
        // `TcpListener::bind(...)` at the call site. Catches both
        // async and blocking variants under a bare import.
        .forbid_pattern(r"\bTcpListener::bind\(")
        // Canonical implementation site.
        .allow_path("crates/zp-net/src/")
        // Port-availability probes (bind-then-drop). Not server starts.
        .allow_path("crates/zp-preflight/src/checks.rs")
        .allow_path("crates/zp-cli/src/main.rs")
        // Mesh transport — distinct concern (non-loopback transport).
        .allow_path("crates/zp-mesh/src/")
        // Test harnesses bind port-0 for random ephemeral servers.
        .allow_path("crates/zp-hardening-tests/")
        // Standalone demo, excluded from workspace; migration deferred.
        .allow_path("crates/trust-triangle/")
        // Skip comment lines (module docs mention the forbidden form).
        .skip_lines_containing("//")
        // Skip pin-declaration lines in this file itself.
        .skip_lines_containing("forbid_pattern")
        .assert();
}
