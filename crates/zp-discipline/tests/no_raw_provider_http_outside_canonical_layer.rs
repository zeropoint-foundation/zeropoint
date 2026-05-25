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
//! See `docs/handoffs/inference-architecture-consolidation-design-2026-05.md`.
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
