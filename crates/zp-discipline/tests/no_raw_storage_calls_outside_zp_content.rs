//! Discipline: raw filesystem writes for content purposes, and direct R2/D1/KV
//! calls, must not appear outside `crates/zp-content/`.
//!
//! # Why (storage abstraction, 2026-05-25)
//!
//! The storage abstraction design (`docs/handoffs/storage-abstraction-design-2026-05.md`)
//! establishes `ContentStore` in `zp-content` as the singular substrate primitive
//! for signed, content-addressed artifact storage — the same singular-X pattern
//! applied previously to networking (`zp-net`) and inference (proxy).
//!
//! Without this pin, the same "two reasonable models competing for the same
//! surface" failure mode can reappear at the storage layer: code written against
//! R2 directly in `zp-server`, code written against `std::fs` in a consumer
//! crate, and `zp-content` backends all serve the same need with no structural
//! enforcement that they stay separate.
//!
//! # What is forbidden
//!
//! - `worker::kv::` — Cloudflare KV direct access
//! - `worker::Bucket` / `R2Bucket` — Cloudflare R2 direct access outside the
//!   adapter crate
//!
//! `std::fs` writes are NOT forbidden globally — they are legitimate for config
//! files, vault files, genesis/session state, and audit chain. The discipline
//! can't mechanically distinguish "content-for-the-store" `std::fs::write` from
//! "config file" `std::fs::write`, so this pin focuses on the cloud-storage
//! primitives that have no legitimate use outside their adapter crate.
//!
//! # Allowlist
//!
//! - `crates/zp-content/` — the canonical implementation site for the trait and
//!   local backends.
//! - `crates/zp-cloudflare/` — the legitimate home for R2 and D1 backend
//!   implementations of `ContentStore`. This is NOT a bypass: `zp-cloudflare`
//!   implements the trait; it is not an alternative data path that skips it.
//!
//! See `docs/handoffs/storage-abstraction-design-2026-05.md` and the analogous
//! `no_raw_tcp_bind_outside_zp_net` pin for the structural pattern.

use zp_discipline::Discipline;

#[test]
fn no_raw_storage_calls_outside_zp_content() {
    Discipline::new("no_raw_storage_calls_outside_zp_content")
        .cite_invariant(
            "Principle 8 (one canonical path) — singular content-addressed storage",
        )
        .rationale(
            "Direct Cloudflare KV and R2 calls outside the adapter crate \
             bypass the ContentStore abstraction and create parallel data paths \
             for signed artifact storage. All content storage must route through \
             the ContentStore trait defined in zp-content. Cloud backend \
             implementations live in zp-cloudflare (a legitimate implementor, \
             not a bypass). No other crate may call Cloudflare storage primitives \
             directly.",
        )
        // Cloudflare KV direct access
        .forbid_pattern(r"\bworker::kv\b")
        .forbid_pattern(r"\buse\s+worker::kv")
        // Cloudflare R2 / Bucket direct access
        .forbid_pattern(r"\bR2Bucket\b")
        .forbid_pattern(r"\bworker::Bucket\b")
        // Canonical implementation site — the trait and local backends.
        .allow_path("crates/zp-content/")
        // Legitimate cloud adapter — implements ContentStore for R2/D1.
        .allow_path("crates/zp-cloudflare/")
        // Skip comment and doc lines (rationale strings mention forbidden forms).
        .skip_lines_containing("//")
        // Skip pin-declaration lines in this file itself.
        .skip_lines_containing("forbid_pattern")
        .assert();
}
