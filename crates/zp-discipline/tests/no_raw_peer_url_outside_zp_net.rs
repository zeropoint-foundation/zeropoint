//! Discipline: substrate-internal peer URLs MUST NOT be assembled by
//! raw `format!()` / string concatenation of `http://localhost:<port>`
//! or `http://127.0.0.1:<port>` (or the bracketed IPv6 form). All
//! substrate-internal peer URLs route through
//! `zp_net::peer_url` / `peer_url_with_path` / `peer_origin` /
//! `peer_grpc_uri`, which loopback-normalize the host segment to the
//! IPv4 literal so the dual-stack listener's IPv4 path is exercised
//! and the resolver-order trap (Phase 0 root cause) cannot regress
//! from the client side.
//!
//! # Why (singular loopback binding — client side)
//!
//! Phase 1 closed the server side: every loopback server binds both
//! IPv4 and IPv6. This pin closes the symmetric gap on the client
//! side: anywhere substrate code constructs a URL pointing at a
//! loopback peer, the host is canonicalized to `127.0.0.1` so the
//! choice is structural rather than scattered across N call sites.
//! See `docs/handoffs/singular-loopback-binding-design-2026-05.md`.
//!
//! # Allowlist
//!
//! - `crates/zp-net/src/` — the canonical implementation site.
//! - `crates/zp-cli/src/secure.rs` — operator-facing copy and
//!   `open <browser-url>` argument. Operators read and type
//!   `localhost`; this is a human-display surface, not a peer URL.
//! - `crates/zp-cli/src/onboard.rs` — operator-facing copy
//!   ("API calls will route through http://localhost:.../proxy/").
//! - `crates/zp-server/src/lib.rs` — CSP / CORS comparison strings
//!   (browser-side Origin header values) plus dashboard-launch URLs
//!   handed to the OS browser. Whole-file allowlist; the substantive
//!   peer-URL sites in this file migrated to `zp_net::peer_origin`.
//!   (Tightening this file's allowlist by splitting CSP/CORS/launch
//!   into smaller modules is tracked as a follow-up.)
//! - `crates/zp-server/src/onboard/detect.rs` — probing external
//!   providers (Ollama at :11434, OpenAI-compatible base URLs).
//! - `crates/zp-server/src/lease_heartbeat.rs` — config-example
//!   prose + unreachable-URL test fixtures.
//! - `crates/zp-engine/src/discovery.rs` — `looks_like_internal_url`
//!   test fixtures.
//! - `crates/zp-llm/` — external-provider clients (Ollama).
//! - `crates/zp-regent/src/{routing,inference,config}.rs`,
//!   `crates/zp-server/src/regent.rs`, `crates/zp-config/src/schema.rs`
//!   — Ollama endpoint defaults, the inference fallback endpoint, and
//!   the `ensure_ollama_running` health probes. Ollama is an external
//!   provider that happens to listen on loopback; it is not a
//!   substrate peer, so `zp_net::peer_url*` is the wrong carrier
//!   (`zp-regent` and `zp-config` do not depend on `zp-net`, and
//!   adding the dependency to normalize a third-party provider URL
//!   would invert the layering).
//!
//!   The resolver-order concern is real for these sites even though
//!   the pin does not reach them: all five were normalized to the
//!   IPv4 literal on 2026-07-26 after `routing.rs` and `inference.rs`
//!   were found using the `localhost` form while the configured
//!   defaults used `127.0.0.1`. Keep new Ollama URLs on the IPv4
//!   literal.
//! - `crates/zp-configure/` — operator-facing display copy + test
//!   fixtures (`.env.example` prose, OLLAMA_SERVER_URL templates).
//!   The substantive proxy-URL site migrated to
//!   `zp_net::peer_url_with_path`; the file's remaining matches are
//!   display strings or test fixtures.
//! - `crates/zp-server/assets/` — frontend JavaScript scope, not Rust.
//! - `crates/zp-hardening-tests/` — hardening-test fixtures and the
//!   singular-loopback shutdown integration test.
//! - `crates/trust-triangle/` — standalone reference demo, excluded
//!   from the workspace; migration deferred.
//!
//! # Why `skip_lines_containing` uses `///` and `//!`
//!
//! Earlier pins used the broader substrings `"e.g."` and `"example"`
//! to skip prose mentions of the forbidden form. That filter is too
//! coarse — a substantive code line that happens to contain the
//! word "example" would be silently exempted. This pin uses the
//! Rust documentation comment prefixes `///` (item docs) and `//!`
//! (module / crate docs). Lines that begin (after leading
//! whitespace) with a doc-comment marker are unconditionally
//! skipped; substantive code lines are checked.

use zp_discipline::Discipline;

#[test]
fn peer_urls_must_route_through_zp_net() {
    Discipline::new("no_raw_peer_url_outside_zp_net")
        .cite_invariant(
            "Principle 8 (one canonical path) — singular loopback binding (client side)",
        )
        .rationale(
            "Hardcoded http://localhost:<port> and http://127.0.0.1:<port> \
             URL strings risk the IPv6-first resolver trap (localhost \
             form) or scatter the substrate's loopback policy across N \
             call sites (both forms). All substrate-internal peer URLs \
             must route through zp_net::peer_url / peer_url_with_path / \
             peer_origin / peer_grpc_uri so the canonical stack choice \
             is enforced structurally and cannot regress from the \
             client side the way Phase 0 regressed from the server side.",
        )
        // The literal string forms callers tend to format!() into URLs.
        // The path allowlist excludes legitimate non-peer-URL uses
        // (operator-facing copy, CORS comparison, external providers).
        .forbid_pattern(r#""http://localhost:"#)
        .forbid_pattern(r#""http://127\.0\.0\.1:"#)
        .forbid_pattern(r#""http://\[::1\]:"#)
        // Canonical implementation site.
        .allow_path("crates/zp-net/src/")
        // Operator-facing copy (CLI eprintln! / println!) + browser
        // launch arg ("open <url>") — `localhost` is what the operator
        // reads and types; not a substrate peer URL.
        .allow_path("crates/zp-cli/src/secure.rs")
        .allow_path("crates/zp-cli/src/onboard.rs")
        // CSP / CORS / dashboard-launch URLs (whole-file allowlist;
        // tightening is tracked as follow-up).
        .allow_path("crates/zp-server/src/lib.rs")
        // External-provider probing — Ollama, OpenAI-compatible base
        // URLs. Not substrate peer URLs.
        .allow_path("crates/zp-server/src/onboard/detect.rs")
        // External provider client (Ollama).
        .allow_path("crates/zp-llm/src/")
        // Ollama endpoint defaults and health probes. Same class as
        // zp-llm and onboard/detect.rs above: Ollama is an external
        // provider reached over loopback, not a substrate peer, so
        // zp_net's peer builders are the wrong carrier. Host form is
        // pinned to the IPv4 literal at every site by convention
        // rather than by this pin — see the module note below.
        .allow_path("crates/zp-regent/src/routing.rs")
        .allow_path("crates/zp-regent/src/inference.rs")
        .allow_path("crates/zp-regent/src/config.rs")
        .allow_path("crates/zp-server/src/regent.rs")
        .allow_path("crates/zp-config/src/schema.rs")
        // Config-example prose + unreachable-URL test fixtures.
        .allow_path("crates/zp-server/src/lease_heartbeat.rs")
        // Discovery test fixture (`looks_like_internal_url`).
        .allow_path("crates/zp-engine/src/discovery.rs")
        // Operator-facing display copy + .env.example test fixtures.
        // The substantive proxy-URL builder migrated; the remaining
        // matches in this file are display strings or fixtures.
        .allow_path("crates/zp-configure/src/")
        // Frontend JavaScript scope, not Rust (the framework also
        // filters by extension, but the path allowlist makes intent
        // explicit if assets ever picks up .rs files).
        .allow_path("crates/zp-server/assets/")
        // Hardening tests and the singular-loopback shutdown
        // integration test. Test-harness code, not substrate code.
        .allow_path("crates/zp-hardening-tests/")
        // Standalone demo binaries, excluded from the workspace.
        .allow_path("crates/trust-triangle/")
        // Skip doc-comment lines (item docs `///` and module docs
        // `//!`). Substantive code lines are still checked. Per Ken's
        // Commit 2 note: do NOT skip on the broader words "e.g." or
        // "example" — they are too coarse and silently exempt code.
        .skip_lines_containing("///")
        .skip_lines_containing("//!")
        // Skip pin-declaration lines in this file itself (the
        // `forbid_pattern(...)` calls contain the forbidden literal).
        .skip_lines_containing("forbid_pattern")
        .assert();
}
