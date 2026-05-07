//! Wire types for the ZP↔Cloudflare boundary.
//!
//! These are pure-Rust types (no Cloudflare deps) that travel across
//! the adapter boundary. They are defined here rather than in the
//! `zp-*` ports because they are *adapter-shared* — used by both the
//! port (for the trait method signatures) and the adapter (for the
//! Cloudflare-side translation).
//!
//! Where each wire type lives — port crate vs adapter wire module —
//! is a per-port decision. The current convention:
//!
//! - **Pure ZP semantics** (e.g. `SignedMessage<T>`, `AuditEntry`):
//!   live in the port crate (`zp-mesh`, `zp-audit`). The adapter
//!   imports them.
//! - **Boundary-shaped types** (e.g. retry hints, adapter-specific
//!   error variants, request batching shapes): live in this module.
//!
//! Status: Phase 1.0 — empty. Each adapter phase adds its wire
//! sub-module here.
