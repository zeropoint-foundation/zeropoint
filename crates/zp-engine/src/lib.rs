//! ZeroPoint Engine — shared logic for scan, configure, vault, and providers.
//!
//! This crate is the single source of truth for tool discovery, credential
//! resolution, and configuration. Both `zp-server` (onboard WebSocket) and
//! `zp-cli` (terminal commands) depend on this crate instead of duplicating
//! logic or shelling out to each other.
//!
//! ## Modules
//!
//! - [`capability`] — MVC capability enum, manifest types, and resolution engine
//! - [`discovery`] — Manifest discovery + heuristic fallback with escalation tiers
//! - [`scan`] — Discover tools by looking for `.env.example` files
//! - [`configure`] — Semantic sed: resolve `.env.example` → `.env` using vault
//! - [`providers`] — Provider catalog, detection, and inference
//! - [`validate`] — Live connection tests for provider API keys
//! - [`vault`] — Thin convenience layer over `zp_trust::CredentialVault`

pub mod capability;
pub mod discovery;
pub mod scan;
pub mod configure;
pub mod providers;
pub mod validate;
pub mod vault;
