//! Tool discovery — single source of truth.
//!
//! Scans a directory tree for AI tools with `.env.example` files,
//! checks their binary readiness (does `.env` exist with real values?),
//! and discovers plaintext credentials worth vaulting.
//!
//! Used by both `zp-server` (onboard WebSocket) and `zp-cli` (terminal).

use crate::providers;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

// ============================================================================
// Types
// ============================================================================

/// A discovered tool and its credential state.
#[derive(Debug, Clone, Serialize)]
pub struct ToolScanResult {
    /// Directory name (e.g., "pentagi", "zp-hedera")
    pub name: String,
    /// Absolute path to tool directory
    pub path: PathBuf,
    /// Binary readiness status
    pub status: ToolStatus,
    /// Provider var names found in .env.example (for catalog UI)
    pub provider_vars: Vec<String>,
    /// Plaintext credentials found in .env (for vault import)
    pub found_credentials: Vec<FoundCredential>,
}

/// Binary readiness: does .env exist with at least one real value?
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    /// Has .env with at least one non-placeholder value (credentials exposed)
    HasPlaintext,
    /// No .env or only placeholders
    Unconfigured,
}

/// A plaintext credential found in a tool's .env file.
#[derive(Debug, Clone, Serialize)]
pub struct FoundCredential {
    /// The env variable name (e.g., "ANTHROPIC_API_KEY")
    pub var_name: String,
    /// Detected or inferred provider ID
    pub provider: String,
    /// Masked value for display (e.g., "sk-a...1234")
    pub masked_value: String,
    /// The actual value (for vault import — handle with care)
    pub value: String,
    /// Which tool directory this was found in
    pub source_tool: String,
}

/// Aggregated credential group for a single provider.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderCredentialGroup {
    pub provider: String,
    pub values: Vec<AggregatedValue>,
    pub has_conflict: bool,
}

/// A unique credential value with source tracking.
#[derive(Debug, Clone, Serialize)]
pub struct AggregatedValue {
    pub var_name: String,
    pub masked_value: String,
    pub value: String,
    pub sources: Vec<String>,
}

/// Complete scan results.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResults {
    /// Per-tool results
    pub tools: Vec<ToolScanResult>,
    /// All unique providers found
    pub unique_providers: HashSet<String>,
    /// Aggregated credentials by provider (deduped, with conflict flags)
    pub credential_groups: Vec<ProviderCredentialGroup>,
    /// Total plaintext credentials found
    pub total_plaintext: usize,
}

// ============================================================================
// Core scan function
// ============================================================================

/// Scan a directory for AI tools and their credential state.
///
/// This is the single entry point for tool discovery. Both the server
/// (onboard WebSocket) and CLI (`zp configure scan`) call this.
pub fn scan_tools(scan_path: &Path) -> ScanResults {
    let mut tools = Vec::new();
    let mut unique_providers: HashSet<String> = HashSet::new();
    let mut all_found_creds: Vec<FoundCredential> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(scan_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Skip hidden dirs, node_modules, target, venv
            let dir_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if dir_name.starts_with('.')
                || dir_name == "node_modules"
                || dir_name == "target"
                || dir_name == "__pycache__"
                || dir_name == "venv"
                || dir_name == ".venv"
            {
                continue;
            }

            // Skip tools explicitly removed from governance
            if path.join(".zp-ignore").exists() {
                continue;
            }

            let env_example = path.join(".env.example");
            if !env_example.exists() {
                continue;
            }

            let result = scan_single_tool(&path, &dir_name);

            // Collect unique providers from .env.example
            for var in &result.provider_vars {
                if let Some(p) = providers::detect_provider(var) {
                    unique_providers.insert(p);
                }
            }

            // Collect all found credentials for aggregation
            all_found_creds.extend(result.found_credentials.clone());

            tools.push(result);
        }
    }

    let total_plaintext = all_found_creds.len();
    let credential_groups = aggregate_credentials(&all_found_creds);

    ScanResults {
        tools,
        unique_providers,
        credential_groups,
        total_plaintext,
    }
}

/// Scan a single tool directory for readiness and plaintext credentials.
fn scan_single_tool(tool_path: &Path, tool_name: &str) -> ToolScanResult {
    let mut provider_vars = Vec::new();
    let mut found_credentials = Vec::new();
    let mut has_real_values = false;

    // Parse .env.example for provider var names (catalog UI)
    let env_example = tool_path.join(".env.example");
    if let Ok(content) = std::fs::read_to_string(&env_example) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(key) = line.split('=').next() {
                let key = key.trim();
                if providers::detect_provider(key).is_some() {
                    provider_vars.push(key.to_string());
                }
            }
        }
    }

    // Parse .env for binary readiness + plaintext credential discovery
    let env_file = tool_path.join(".env");
    if env_file.exists() {
        if let Ok(content) = std::fs::read_to_string(&env_file) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, val)) = line.split_once('=') {
                    let key = key.trim();
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    let is_placeholder = val.is_empty()
                        || val.contains("YOUR_")
                        || val.contains("your_")
                        || val.contains("xxx")
                        || val.contains("CHANGEME")
                        || val == "sk-..."
                        || val.len() < 4;

                    if !is_placeholder {
                        has_real_values = true;
                        let provider = providers::detect_provider(key)
                            .unwrap_or_else(|| providers::infer_provider_from_var(key));
                        let masked = if val.len() > 8 {
                            format!("{}...{}", &val[..4], &val[val.len() - 4..])
                        } else {
                            "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}"
                                .to_string()
                        };
                        found_credentials.push(FoundCredential {
                            var_name: key.to_string(),
                            provider,
                            masked_value: masked,
                            value: val.to_string(),
                            source_tool: tool_name.to_string(),
                        });
                    }
                }
            }
        }
    }

    let status = if has_real_values {
        ToolStatus::HasPlaintext
    } else {
        ToolStatus::Unconfigured
    };

    ToolScanResult {
        name: tool_name.to_string(),
        path: tool_path.to_path_buf(),
        status,
        provider_vars,
        found_credentials,
    }
}

// ============================================================================
// Credential aggregation
// ============================================================================

/// Group credentials by provider, deduplicate identical values, flag conflicts.
fn aggregate_credentials(creds: &[FoundCredential]) -> Vec<ProviderCredentialGroup> {
    // Group by provider
    let mut by_provider: BTreeMap<String, Vec<&FoundCredential>> = BTreeMap::new();
    for cred in creds {
        by_provider
            .entry(cred.provider.clone())
            .or_default()
            .push(cred);
    }

    let mut groups = Vec::new();
    for (provider, creds) in &by_provider {
        // Deduplicate by (var_name, value) — same var with same value across
        // tools is just one credential used in multiple places, not a conflict.
        let mut unique_values: Vec<AggregatedValue> = Vec::new();
        let mut seen: HashSet<(String, String)> = HashSet::new();

        for c in creds {
            let key = (c.var_name.clone(), c.value.clone());
            if seen.contains(&key) {
                // Same var + same value already seen — just add source tool
                for uv in &mut unique_values {
                    if uv.var_name == c.var_name && uv.value == c.value
                        && !uv.sources.contains(&c.source_tool)
                    {
                        uv.sources.push(c.source_tool.clone());
                    }
                }
            } else {
                seen.insert(key);
                unique_values.push(AggregatedValue {
                    var_name: c.var_name.clone(),
                    masked_value: c.masked_value.clone(),
                    value: c.value.clone(),
                    sources: vec![c.source_tool.clone()],
                });
            }
        }

        // A real conflict: the SAME var_name has DIFFERENT values across tools.
        // Different var_names within the same provider (e.g. DOCKER_INSIDE vs
        // DOCKER_SOCKET) are not conflicts — they're distinct configuration.
        let mut var_value_count: BTreeMap<&str, usize> = BTreeMap::new();
        for uv in &unique_values {
            *var_value_count.entry(&uv.var_name).or_insert(0) += 1;
        }
        let has_conflict = var_value_count.values().any(|&count| count > 1);

        groups.push(ProviderCredentialGroup {
            provider: provider.clone(),
            values: unique_values,
            has_conflict,
        });
    }

    groups
}
