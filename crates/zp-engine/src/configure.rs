//! Configure engine — semantic sed for `.env` files.
//!
//! This module will eventually hold the full ConfigEngine (patterns, resolution,
//! env file processing). For now, it defines the structured result types that
//! the server uses to drive the UI, replacing stdout parsing.
//!
//! ## Migration plan
//!
//! Phase 1 (current): Define result types here, keep ConfigEngine in zp-cli.
//!   Server calls ConfigEngine via this module's structured API.
//!
//! Phase 2 (next): Move ConfigEngine, builtin_patterns(), CompiledPattern,
//!   Resolution, and all processing logic here. CLI becomes a thin wrapper.

use serde::Serialize;
use std::path::PathBuf;

// ============================================================================
// Result types (structured — no stdout parsing needed)
// ============================================================================

/// Result of auto-configuring one tool.
#[derive(Debug, Clone, Serialize)]
pub struct ToolConfigResult {
    /// Tool directory name
    pub name: String,
    /// Absolute path to tool directory
    pub path: PathBuf,
    /// What happened
    pub status: ConfigStatus,
}

/// Outcome of configuring a single tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigStatus {
    /// .env written with vault credentials + proxy URLs
    Configured,
    /// Missing vault credentials — lists what's needed
    SkippedMissing {
        missing_count: usize,
        missing_refs: Vec<String>,
    },
    /// .env already exists and overwrite not requested
    SkippedExists,
    /// Configuration failed
    Failed { error: String },
}

/// Complete auto-configure results.
#[derive(Debug, Clone, Serialize)]
pub struct AutoConfigResults {
    /// Per-tool results
    pub tools: Vec<ToolConfigResult>,
    /// Number successfully configured
    pub configured_count: usize,
    /// Number skipped (missing creds)
    pub skipped_missing_count: usize,
    /// Number skipped (existing .env)
    pub skipped_exists_count: usize,
    /// Number failed
    pub failed_count: usize,
    /// Whether proxy routing was enabled
    pub proxy_enabled: bool,
    /// Proxy port (if enabled)
    pub proxy_port: Option<u16>,
}
