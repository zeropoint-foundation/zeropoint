//! Adapter implementations of ZeroPoint port traits.
//!
//! Each adapter wraps a Cloudflare binding (`env.AI`, `env.DB`,
//! `env.AI_INDEX`, `env.QUEUE`, etc.) and implements the
//! corresponding ZP port trait. Adapters are constructed by Worker
//! entry points in the foundation workspace
//! (`zeropointfoundation.org/src/`); the `zp-*` crates upstream
//! receive opaque trait objects.
//!
//! # Adapter checklist
//!
//! When adding a new adapter, every adapter MUST:
//!
//! 1. Implement the corresponding ZP port trait verbatim — no
//!    extension methods, no shape changes.
//! 2. Emit an audit-chain receipt at every boundary crossing. Use
//!    the receipt-emitting helper (TBD; will land alongside the
//!    first real adapter — Phase 1.2 Workers AI).
//! 3. Translate Cloudflare-side errors into the port's error type.
//!    Never let a `worker::Error` (or equivalent) escape upstream.
//! 4. Have a documented fallback adapter — even if the fallback
//!    is unimplemented, the port shape must support it. See the
//!    "Fallback adapter (documented)" notes in
//!    `docs/STACK-CLOUDFLARE-2026-05.md`.
//!
//! Status: Phase 1.0 — empty. Each adapter phase adds a sub-module
//! here.
