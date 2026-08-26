//! Discipline: substrate code MUST NOT post directly to cloud provider
//! API endpoints. All inference must route through the ZP proxy
//! (`crates/zp-server/src/proxy.rs`), which adds receipt signing,
//! cost tracking, and policy gating on every call.
//!
//! # Why (singular canonical inference surface, 2026-05-25)
//!
//! Three parallel inference paths existed: the proxy (cost-tracked,
//! receipt-signed), AnthropicProvider in zp-llm (direct HTTP, no receipts),
//! and the provider catalog (metadata only). The proxy is the structurally
//! correct path. The singular-inference-surface consolidation designates it
//! as the sole point where substrate code reaches cloud providers.
//!
//! Direct HTTP to cloud provider endpoints produces inaccurate cost receipts
//! (at best) or no receipts at all, breaking the chain's authority over
//! "what ran and what it cost."
//!
//! See `docs/design/INFERENCE-ARCHITECTURE-CONSOLIDATION-2026-05.md`.
//!
//! # Allowlist
//!
//! - `crates/zp-server/src/proxy.rs` — the canonical implementation; the
//!   only place permitted to hold cloud provider base URLs.
//! - `crates/zp-llm/src/providers/anthropic.rs` — migration bridge; direct
//!   HTTP retained until AnthropicProvider is deleted after the pin ships.
//!   Remove this entry when the deletion commit lands.
//! - `crates/zp-llm/src/providers/ollama.rs` — local runtime, not a cloud
//!   provider; loopback HTTP to localhost is a distinct concern.
//! - Test files — string fixtures for unit tests may contain provider URLs
//!   as data; not call sites.

use zp_discipline::Discipline;

#[test]
fn no_raw_provider_http_outside_canonical_layer() {
    Discipline::new("no_raw_provider_http_outside_canonical_layer")
        .cite_invariant(
            "Singular canonical inference surface — every inference call emits a signed receipt",
        )
        .rationale(
            "Direct HTTP to cloud provider endpoints bypasses the ZP proxy's \
             cost extraction, policy gating, and receipt signing. \
             AnthropicProvider (crates/zp-llm/src/providers/anthropic.rs:181) \
             was the primary bypass path at the time this pin was introduced.",
        )
        // Cloud provider base URLs — all providers wired in proxy.rs
        .forbid_pattern(r#""https://api.anthropic.com"#)
        .forbid_pattern(r#""https://api.openai.com"#)
        .forbid_pattern(r#""https://api.together.xyz"#)
        .forbid_pattern(r#""https://api.fireworks.ai"#)
        .forbid_pattern(r#""https://api.groq.com"#)
        .forbid_pattern(r#""https://api.deepinfra.com"#)
        .forbid_pattern(r#""https://openrouter.ai"#)
        .forbid_pattern(r#""https://routellm.abacus.ai"#)
        // Canonical implementation — the only place permitted to hold these URLs
        .allow_path("crates/zp-server/src/proxy.rs")
        // Migration bridge — AnthropicProvider pending deletion
        .allow_path("crates/zp-llm/src/providers/anthropic.rs")
        // Ollama — local runtime; localhost HTTP is not a cloud provider bypass
        .allow_path("crates/zp-llm/src/providers/ollama.rs")
        // Skip comment lines (docs may reference the forbidden forms)
        .skip_lines_containing("//")
        // Skip this pin's own forbid_pattern declarations
        .skip_lines_containing("forbid_pattern")
        .assert();
}

// ── W5 step 4: loopback extension ───────────────────────────────────────
//
// The check above pins cloud provider bypasses. It does not (and by design
// does not -- see its own "Ollama" allowlist entry) cover loopback provider
// ports: 127.0.0.1:11434, localhost:11434, etc. Direct HTTP to a loopback
// provider port is the same class of bypass as direct HTTP to a cloud
// endpoint -- no receipt, no cost tracking, no policy gate -- just reached
// over loopback instead of the internet. W5 3c retired the last governed-
// path use of a raw Ollama endpoint (InferenceBackend::chat, chat_local,
// chat_via_proxy, health_check, model_available now all route through the
// proxy); this pin exists to keep that retired class of bypass retired.
//
// # Canonical set (loopback)
//
// - crates/zp-server/src/proxy.rs -- same canonical file as the cloud
//   check; the proxy is the one place permitted to hold a raw provider
//   base URL, loopback or not.
// - crates/zp-server/src/onboard/detect.rs -- pre-Genesis onboarding probe
//   (handle_detect_local_inference). Read-only discovery (GET /api/tags,
//   GET /api/version, and an OpenAI-compatible GET /v1/models sweep over
//   LM Studio/llama.cpp/Jan/vLLM's ports) run once during setup to
//   populate the onboarding UI with what's installed locally -- not a
//   chat/inference call, and it runs before the proxy's governance layer
//   is necessarily even configured. Same class of exception as a
//   tool_ports-style discovery probe.
// - crates/zp-configure/src/lib.rs -- holds localhost:11434 /
//   host.docker.internal:11434 only as default *values* for other tools'
//   env vars (a Docker container reaching the host) and as test-fixture
//   data for its env-scanner tests. This crate constructs no reqwest
//   client anywhere (verified) -- it generates config, it does not make
//   HTTP calls.
//
// # Explicit opt-ins (line-level)
//
// Two files hold governed-inference code *and* legitimate raw-loopback
// code side by side, so they can't be allowlisted by path without also
// blinding the pin to the governed functions living in the same file.
// Each legitimate line instead carries an explicit, greppable marker:
//
// - RAW_OLLAMA_BASE_URL -- the zp-regent constant itself, and every call
//   site that references it by name (unload_all, preload,
//   evaluation::discover_local_models, awareness::query_loaded_models) --
//   none of which contain a raw loopback *literal* of their own; they all
//   go through the named constant, which is the actual opt-in.
// - zpd:raw-loopback-opt-in -- the handful of sites that construct the
//   same literal independently of the constant: ensure_ollama_running's
//   own liveness probe (kept as a separate literal -- see the constant's
//   own doc comment in inference.rs), three #[cfg(test)] fixtures in
//   inference.rs::detect_tests that assert ProviderProfile::detect and
//   request_path correctly recognize a raw-Ollama-shaped URL as *not* the
//   proxy, and one dead field in zp-regent::routing::Router::route (a
//   RouteDecision.endpoint value that is never read by the actual
//   dispatch path -- Regent::infer matches on `tier`, not `endpoint` --
//   kept as display/rationale metadata only).
//
// Deliberately NOT reused: the base check's blanket
// skip_lines_containing("//") convention. Reusing it here would let
// anyone dodge this pin by appending any trailing comment to a violating
// line -- a real loophole for a check whose entire job is to catch a
// reintroduced bypass. The two markers above are exact-string opt-ins
// instead, each naming why the line is safe.
//
// # What this pin does NOT catch (disclosed, not silently missed)
//
// This is a literal-string scan, like the check above it. It matches a
// quoted "http://<loopback-host>:11434 prefix. It does NOT catch:
//
// - A loopback URL built with a *templated* port -- a format! call
//   shaped like http://<loopback-host>:<port-var> -- because that shape
//   is used constantly and legitimately throughout this codebase for the
//   substrate's *own* internal addressing (CORS origin checks and the
//   dashboard URL in zp-server::lib, the Regent's own proxy_base in
//   run_server, ProxyLlmProvider's own proxy URL, loopback-shutdown test
//   harnesses). A regex cannot tell "reaches a provider" from "reaches
//   the substrate's own service" when both are spelled the same way with
//   a variable port -- that distinction needs the port's origin, not its
//   text. Confirmed empirically while designing this pin: broadening the
//   pattern to match any format!("http://<loopback>:{}" produced false
//   positives against zp-server/src/lib.rs's own CORS checks and its
//   proxy_base construction on the first pass.
// - Any URL built via a helper (e.g. zp_net::peer_url(host, port)) rather
//   than a string literal.
// - Any port other than 11434. 11434 is the only provider port that
//   appears anywhere in this codebase as a compile-time literal; the
//   other four local runtimes the onboarding probe checks for (LM Studio
//   1234, llama.cpp/LocalAI 8080, Jan 1337, vLLM 8000) are only ever
//   reached via a format! call shaped like
//   http://localhost:<port>/v1/models with a runtime-supplied port, which
//   the point above already covers.
//
// These gaps are left to code review, not pretended away.

#[test]
fn no_raw_provider_http_outside_canonical_layer_loopback() {
    Discipline::new("no_raw_provider_http_outside_canonical_layer_loopback")
        .cite_invariant(
            "Singular canonical inference surface — every inference call emits a signed receipt",
        )
        .rationale(
            "W5 step 4: extends the cloud-provider check to loopback provider \
             ports. Direct HTTP to 127.0.0.1:11434 (or an equivalent loopback \
             form) is the same bypass as direct HTTP to a cloud endpoint — no \
             receipt, no cost tracking, no policy gate — just reached over \
             loopback instead of the internet.",
        )
        .forbid_pattern(r#""http://127.0.0.1:11434"#)
        .forbid_pattern(r#""http://localhost:11434"#)
        .forbid_pattern(r#""http://\[::1\]:11434"#)
        .forbid_pattern(r#""http://0.0.0.0:11434"#)
        // Canonical implementation — same file as the cloud check above
        .allow_path("crates/zp-server/src/proxy.rs")
        // Pre-Genesis onboarding discovery probe — read-only, not inference
        .allow_path("crates/zp-server/src/onboard/detect.rs")
        // Config-value defaults / test fixtures only — no HTTP client in this crate
        .allow_path("crates/zp-configure/src/lib.rs")
        // Explicit opt-in: the named constant and every call site using it
        .skip_lines_containing("RAW_OLLAMA_BASE_URL")
        // Explicit opt-in: sites that can't reference the constant by name —
        // see the doc comment above for what each one is and why.
        .skip_lines_containing("zpd:raw-loopback-opt-in")
        // Skip this pin's own forbid_pattern declarations
        .skip_lines_containing("forbid_pattern")
        .assert();
}
