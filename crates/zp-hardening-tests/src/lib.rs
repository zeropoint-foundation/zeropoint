//! ZeroPoint Hardening — Regression Replay Test Harness
//!
//! This crate provides a test harness that boots `zp-server` in-process
//! (using `build_app()` directly) and fires Shannon pentest payloads as
//! HTTP/WebSocket requests. Each test maps to a VULN-TRACKER ID.
//!
//! ## Architecture
//!
//! - **HTTP tests** use `tower::ServiceExt::oneshot` — zero network, zero
//!   port allocation, sub-millisecond per request.
//! - **WebSocket tests** boot a real TCP listener on a random port and
//!   connect via `tokio-tungstenite`, since WebSocket upgrades require a
//!   live connection.
//!
//! ## Usage
//!
//! ```bash
//! cargo test -p zp-hardening-tests
//! ```
//!
//! ## Test naming convention
//!
//! `test_{vuln_id}_{short_description}`
//!
//! Example: `test_auth_vuln_01_unauth_access`

pub mod harness;
pub mod payloads;
