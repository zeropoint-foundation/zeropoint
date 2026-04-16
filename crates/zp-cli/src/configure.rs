//! ZeroPoint Configure — Semantic Sed for tool configuration.
//!
//! Reads a tool's `.env.example`, matches each variable against a registry of
//! `ConfigPattern` rules (built on `SanitizePattern` semantics), resolves
//! credentials from `zp-trust`'s `CredentialVault` via `CredentialInjector`,
//! and writes a fully populated `.env` file.
//!
//! ## Design Principles
//!
//! 1. **Reuses existing primitives**: `SanitizePattern` structure for matching,
//!    `CredentialInjector` for policy-gated vault access, `GovernanceEvent` for audit.
//! 2. **Semantic, not syntactic**: Understands that `ANTHROPIC_API_KEY` (PentAGI),
//!    `ANTHROPIC_API_KEY` (Ember), and a future `CLAUDE_API_KEY` all refer to
//!    the same vault credential.
//! 3. **Receipt-native**: Every resolved mapping produces an auditable record.
//! 4. **Fail-safe**: Unknown variables are flagged for human review, never guessed.
//!
//! ## Usage
//!
//! ```bash
//! # Register a provider credential in the vault
//! zp configure vault-add --provider anthropic --key sk-ant-...
//!
//! # Auto-configure a tool from its .env.example
//! zp configure tool --path ./pentagi --name pentagi
//!
//! # Dry run — show what would be resolved without writing
//! zp configure tool --path ./pentagi --name pentagi --dry-run
//!
//! # List all registered providers
//! zp configure providers
//! ```

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tracing::{debug, info};
use zp_trust::injector::{CredentialInjector, PolicyCheckFn, PolicyContext};
use zp_trust::vault::CredentialVault;

// ============================================================================
// Config Pattern — the semantic sed rule
// ============================================================================

/// A configuration pattern rule — the semantic sed primitive.
///
/// Built on the same structure as `zp_core::SanitizePattern`:
///   - `name`: human-readable identifier
///   - `pattern`: regex to match env var names
///   - `replacement`: vault credential name to resolve
///
/// Extended with:
///   - `provider`: which provider family this belongs to
///   - `field`: what kind of field (api_key, url, model, password, etc.)
///   - `default`: optional default value for non-secret fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPattern {
    /// Human-readable name for this rule
    pub name: String,
    /// Regex pattern to match against env variable names
    pub pattern: String,
    /// Provider family (anthropic, openai, ollama, postgres, etc.)
    pub provider: String,
    /// Field type within the provider
    pub field: ConfigField,
    /// Vault credential name to resolve (for secret fields)
    pub vault_ref: Option<String>,
    /// Default value (for non-secret fields like URLs, models)
    pub default: Option<String>,
}

/// The type of configuration field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigField {
    /// API key or token — always from vault
    ApiKey,
    /// Service URL — may have a default
    Url,
    /// Model name — may have a default
    Model,
    /// Database password — always from vault
    Password,
    /// Database connection string — from vault
    ConnectionString,
    /// Username — may be from vault or default
    Username,
    /// Boolean toggle — usually has a default
    Toggle,
    /// Generic secret (signing salt, encryption key) — from vault
    Secret,
    /// Non-secret configuration — passthrough
    Config,
}

impl ConfigField {
    /// Whether this field type requires vault access.
    pub fn requires_vault(&self) -> bool {
        matches!(
            self,
            ConfigField::ApiKey
                | ConfigField::Password
                | ConfigField::ConnectionString
                | ConfigField::Secret
        )
    }
}

// ============================================================================
// Resolution Result
// ============================================================================

/// The result of resolving a single env variable.
///
/// Some variant fields (notably `pattern_name`) and the `is_resolved`
/// helper are retained for diagnostic output and upcoming `zp configure
/// explain` surfaces. They are deliberately kept on the enum so the
/// resolution pipeline threads the information end-to-end; silence the
/// current dead-code noise without deleting the scaffolding.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Resolution {
    /// Resolved from vault via a matched pattern
    VaultResolved {
        var_name: String,
        pattern_name: String,
        provider: String,
        vault_ref: String,
        value: String,
    },
    /// Resolved with a default value from the pattern
    DefaultResolved {
        var_name: String,
        pattern_name: String,
        value: String,
    },
    /// Variable already has a value in the existing .env — keep it
    Preserved { var_name: String, value: String },
    /// No pattern matched — requires human review
    Unresolved {
        var_name: String,
        original_line: String,
    },
    /// Pattern matched but vault credential missing
    Missing {
        var_name: String,
        pattern_name: String,
        vault_ref: String,
    },
    /// Comment or blank line — passthrough
    Passthrough { line: String },
}

impl Resolution {
    /// Format this resolution as an env file line.
    pub fn to_env_line(&self) -> String {
        match self {
            Resolution::VaultResolved {
                var_name, value, ..
            } => {
                format!("{}={}", var_name, value)
            }
            Resolution::DefaultResolved {
                var_name, value, ..
            } => {
                format!("{}={}", var_name, value)
            }
            Resolution::Preserved { var_name, value } => {
                format!("{}={}", var_name, value)
            }
            Resolution::Unresolved { original_line, .. } => original_line.clone(),
            Resolution::Missing {
                var_name,
                vault_ref,
                ..
            } => {
                format!(
                    "{}= # MISSING: vault credential '{}' not found",
                    var_name, vault_ref
                )
            }
            Resolution::Passthrough { line } => line.clone(),
        }
    }

    /// Whether this resolution was successful (has a value).
    #[allow(dead_code)]
    pub fn is_resolved(&self) -> bool {
        matches!(
            self,
            Resolution::VaultResolved { .. }
                | Resolution::DefaultResolved { .. }
                | Resolution::Preserved { .. }
        )
    }
}

// ============================================================================
// Compiled Pattern (cached regex)
// ============================================================================

struct CompiledPattern {
    rule: ConfigPattern,
    regex: Regex,
}

// ============================================================================
// The Semantic Sed Engine
// ============================================================================

/// The configuration engine — semantic sed for `.env` files.
///
/// Matches env variable names against provider patterns, resolves values
/// from the vault, and produces a fully configured `.env` file.
pub struct ConfigEngine {
    /// Compiled pattern rules
    patterns: Vec<CompiledPattern>,
    /// When set, URL defaults are rewritten to point to the ZP proxy.
    /// Value is the ZP server port (e.g., 3000).
    proxy_port: Option<u16>,
}

impl ConfigEngine {
    /// Create a new ConfigEngine with the built-in provider patterns.
    pub fn new() -> Self {
        let rules = builtin_patterns();
        let patterns = rules
            .into_iter()
            .filter_map(|rule| {
                Regex::new(&rule.pattern)
                    .ok()
                    .map(|regex| CompiledPattern { rule, regex })
            })
            .collect();
        Self {
            patterns,
            proxy_port: None,
        }
    }

    /// Create a ConfigEngine with proxy mode enabled.
    ///
    /// When proxy mode is on, URL-type patterns resolve to the ZP proxy
    /// endpoint instead of the real provider URL. This routes all API calls
    /// through ZP's governance layer for policy checks, metering, and receipts.
    pub fn with_proxy(port: u16) -> Self {
        let rules = builtin_patterns();
        let patterns = rules
            .into_iter()
            .filter_map(|rule| {
                Regex::new(&rule.pattern)
                    .ok()
                    .map(|regex| CompiledPattern { rule, regex })
            })
            .collect();
        Self {
            patterns,
            proxy_port: Some(port),
        }
    }

    /// Create a ConfigEngine with custom patterns (for testing or extension).
    #[allow(dead_code)]
    pub fn with_patterns(rules: Vec<ConfigPattern>) -> Self {
        let patterns = rules
            .into_iter()
            .filter_map(|rule| {
                Regex::new(&rule.pattern)
                    .ok()
                    .map(|regex| CompiledPattern { rule, regex })
            })
            .collect();
        Self {
            patterns,
            proxy_port: None,
        }
    }

    /// If proxy mode is active, rewrite a URL default to the ZP proxy.
    fn proxy_url(&self, provider: &str, original_default: &str) -> String {
        match self.proxy_port {
            Some(port) => {
                // Preserve the original URL's path suffix (e.g. /v1 for OpenAI,
                // empty for Anthropic) so the proxy routes correctly.
                let suffix = original_default
                    .find("://")
                    .and_then(|i| original_default[i + 3..].find('/'))
                    .map(|i| {
                        let host_start = original_default.find("://").unwrap() + 3;
                        &original_default[host_start + i..]
                    })
                    .unwrap_or("");
                format!(
                    "http://localhost:{}/api/v1/proxy/{}{}",
                    port, provider, suffix
                )
            }
            None => original_default.to_string(),
        }
    }

    /// Provider coherence: after resolving credentials, ensure the tool's
    /// backend selector points to a provider we actually activated.
    ///
    /// Common pattern in tools:
    ///   LLM_BACKEND=nearai           # default — but user has anthropic in vault
    ///   # ANTHROPIC_API_KEY=sk-ant-...  # dormant — just got activated
    ///
    /// This method:
    ///   1. Finds any LLM_BACKEND / LLM_PROVIDER style variable in the resolutions
    ///   2. If it points to a provider we DON'T have credentials for, and we DO
    ///      have credentials for another provider, switch it
    ///   3. Respects priority: anthropic > openai > google > others
    fn apply_provider_coherence(
        &self,
        resolutions: &mut [Resolution],
        activated_providers: &[String],
    ) {
        // Known backend variable names
        const BACKEND_VARS: &[&str] = &[
            "LLM_BACKEND",
            "LLM_PROVIDER",
            "AI_PROVIDER",
            "DEFAULT_LLM_PROVIDER",
            "DEFAULT_PROVIDER",
        ];

        // Provider priority — first available wins
        const PROVIDER_PRIORITY: &[&str] = &[
            "anthropic",
            "openai",
            "google",
            "groq",
            "together",
            "deepseek",
            "mistral",
            "openrouter",
        ];

        // Find the best activated provider
        let best_provider = PROVIDER_PRIORITY
            .iter()
            .find(|p| activated_providers.iter().any(|a| a == *p));

        let best_provider = match best_provider {
            Some(p) => *p,
            None => return, // No recognized LLM provider activated
        };

        // Scan resolutions for backend selector variables.
        // Only activate the FIRST occurrence of each backend var —
        // subsequent occurrences become comments to avoid duplicates.
        let mut backend_set: std::collections::HashSet<String> = std::collections::HashSet::new();

        for resolution in resolutions.iter_mut() {
            match resolution {
                Resolution::Preserved {
                    ref var_name,
                    ref value,
                    ..
                }
                | Resolution::DefaultResolved {
                    ref var_name,
                    ref value,
                    ..
                } => {
                    if BACKEND_VARS.contains(&var_name.as_str()) {
                        if backend_set.contains(var_name.as_str()) {
                            // Duplicate — comment it out
                            *resolution = Resolution::Passthrough {
                                line: format!("# {}={} # (duplicate, set above)", var_name, value),
                            };
                        } else if !activated_providers
                            .iter()
                            .any(|a| value.contains(a.as_str()))
                        {
                            info!(
                                "Provider coherence: switching {} from '{}' to '{}'",
                                var_name, value, best_provider
                            );
                            backend_set.insert(var_name.clone());
                            *resolution = Resolution::DefaultResolved {
                                var_name: var_name.clone(),
                                pattern_name: "provider_coherence".into(),
                                value: best_provider.to_string(),
                            };
                        } else {
                            backend_set.insert(var_name.clone());
                        }
                    }
                }
                Resolution::Passthrough { ref line } => {
                    let trimmed = line.trim();
                    if trimmed.starts_with('#') {
                        let uncommented = trimmed.trim_start_matches('#').trim();
                        if let Some((key, _)) = uncommented.split_once('=') {
                            let key = key.trim();
                            if BACKEND_VARS.contains(&key) && !backend_set.contains(key) {
                                info!("Provider coherence: activating {} = {}", key, best_provider);
                                backend_set.insert(key.to_string());
                                *resolution = Resolution::DefaultResolved {
                                    var_name: key.to_string(),
                                    pattern_name: "provider_coherence".into(),
                                    value: best_provider.to_string(),
                                };
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Resolve a single env variable name against the pattern registry.
    ///
    /// Returns the first matching `ConfigPattern`, or `None` if no pattern matches.
    pub fn match_var(&self, var_name: &str) -> Option<&ConfigPattern> {
        for compiled in &self.patterns {
            if compiled.regex.is_match(var_name) {
                debug!(
                    var = var_name,
                    pattern = compiled.rule.name,
                    provider = compiled.rule.provider,
                    "Config pattern matched"
                );
                return Some(&compiled.rule);
            }
        }
        None
    }

    /// Process a complete `.env.example` file against the vault.
    ///
    /// For each line:
    /// 1. Comments and blank lines pass through unchanged.
    /// 2. Variables with existing values in `existing_env` are preserved.
    /// 3. Variables matching a pattern with `vault_ref` are resolved from vault.
    /// 4. Variables matching a pattern with `default` get the default value.
    /// 5. Unmatched variables are flagged for review.
    pub fn process_env_file(
        &self,
        template_path: &Path,
        existing_env: &HashMap<String, String>,
        vault: &CredentialVault,
        policy_check: PolicyCheckFn,
        tool_name: &str,
    ) -> io::Result<Vec<Resolution>> {
        let content = fs::read_to_string(template_path)?;
        let injector = CredentialInjector::new(vault, policy_check);
        let context = PolicyContext::new(format!("zp-configure:{}", tool_name));

        // ── Pass 1: Probe — discover what the vault can resolve ─────
        // Scan ALL lines (active + commented) to build a map of which
        // providers have credentials available. This lets Pass 2 make
        // globally-informed decisions regardless of line ordering.
        let mut available_providers: Vec<String> = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            // Extract key from either active or commented lines
            let key = if trimmed.starts_with('#') {
                let uncommented = trimmed.trim_start_matches('#').trim();
                uncommented
                    .split_once('=')
                    .map(|(k, _)| k.trim().to_string())
            } else {
                trimmed.split_once('=').map(|(k, _)| k.trim().to_string())
            };

            if let Some(key) = key {
                if let Some(pattern) = self.match_var(&key) {
                    if let Some(ref vault_ref) = pattern.vault_ref {
                        if injector
                            .inject_single(tool_name, vault_ref, &context)
                            .is_ok()
                            && !available_providers.contains(&pattern.provider)
                        {
                            available_providers.push(pattern.provider.clone());
                        }
                    }
                }
            }
        }

        if !available_providers.is_empty() {
            info!(
                "Vault probe: credentials available for providers: {:?}",
                available_providers
            );
        }

        // ── Pass 2: Resolve — process all lines with full knowledge ─
        let mut resolutions = Vec::new();
        let mut activated_providers: Vec<String> = Vec::new();
        // Track var names already resolved to prevent duplicates
        // (e.g., ANTHROPIC_API_KEY appearing twice in the template)
        let mut resolved_vars: std::collections::HashSet<String> = std::collections::HashSet::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Blank lines → passthrough
            if trimmed.is_empty() {
                resolutions.push(Resolution::Passthrough {
                    line: line.to_string(),
                });
                continue;
            }

            // ── Commented lines: activate if vault has credential ────
            if trimmed.starts_with('#') {
                let uncommented = trimmed.trim_start_matches('#').trim();

                if let Some((key, _val)) = uncommented.split_once('=') {
                    let key = key.trim();

                    // Skip if already resolved (dedup)
                    if resolved_vars.contains(key) {
                        resolutions.push(Resolution::Passthrough {
                            line: line.to_string(),
                        });
                        continue;
                    }

                    // Skip if existing .env already has this var active
                    if existing_env.contains_key(key) {
                        resolutions.push(Resolution::Passthrough {
                            line: line.to_string(),
                        });
                        continue;
                    }

                    if let Some(pattern) = self.match_var(key) {
                        // Credential field — activate if vault has it
                        if let Some(ref vault_ref) = pattern.vault_ref {
                            if let Ok(value_bytes) =
                                injector.inject_single(tool_name, vault_ref, &context)
                            {
                                let value = String::from_utf8_lossy(&value_bytes).to_string();
                                info!("Activating dormant {} (vault has {})", key, vault_ref);
                                activated_providers.push(pattern.provider.clone());
                                resolved_vars.insert(key.to_string());
                                resolutions.push(Resolution::VaultResolved {
                                    var_name: key.to_string(),
                                    pattern_name: pattern.name.clone(),
                                    provider: pattern.provider.clone(),
                                    vault_ref: vault_ref.clone(),
                                    value,
                                });
                                continue;
                            }
                        }

                        // Default field (model, URL) — activate if the provider
                        // has credentials available (known from Pass 1).
                        // Url-field defaults are only activated in proxy mode;
                        // otherwise we'd write provider base-URL vars (e.g.
                        // ANTHROPIC_BASE_URL) that flip SDKs into "custom
                        // endpoint" mode and break native API-key auth.
                        if let Some(ref default) = pattern.default {
                            let is_url_without_proxy =
                                pattern.field == ConfigField::Url && self.proxy_port.is_none();
                            if available_providers.contains(&pattern.provider)
                                && !is_url_without_proxy
                            {
                                info!(
                                    "Activating dormant {} with default (provider {} available)",
                                    key, pattern.provider
                                );
                                let resolved_value = if pattern.field == ConfigField::Url
                                    && self.proxy_port.is_some()
                                {
                                    self.proxy_url(&pattern.provider, default)
                                } else {
                                    default.clone()
                                };
                                resolved_vars.insert(key.to_string());
                                resolutions.push(Resolution::DefaultResolved {
                                    var_name: key.to_string(),
                                    pattern_name: pattern.name.clone(),
                                    value: resolved_value,
                                });
                                continue;
                            }
                        }
                    }
                }

                // No match, no credential, or provider not available — keep as comment
                resolutions.push(Resolution::Passthrough {
                    line: line.to_string(),
                });
                continue;
            }

            // ── Active lines: resolve as before ─────────────────────
            let (var_name, existing_value) = match trimmed.split_once('=') {
                Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
                None => {
                    resolutions.push(Resolution::Passthrough {
                        line: line.to_string(),
                    });
                    continue;
                }
            };

            // Skip if already resolved from a commented-out line above
            if resolved_vars.contains(&var_name) {
                resolutions.push(Resolution::Passthrough {
                    line: format!("# {} # (already resolved above)", trimmed),
                });
                continue;
            }

            let clean_value = existing_value
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();

            // Preserve existing non-empty values
            if let Some(existing) = existing_env.get(&var_name) {
                if !existing.is_empty() {
                    resolutions.push(Resolution::Preserved {
                        var_name,
                        value: existing.clone(),
                    });
                    continue;
                }
            }

            // Match against patterns
            match self.match_var(&var_name) {
                Some(pattern) => {
                    if let Some(ref vault_ref) = pattern.vault_ref {
                        match injector.inject_single(tool_name, vault_ref, &context) {
                            Ok(value_bytes) => {
                                let value = String::from_utf8_lossy(&value_bytes).to_string();
                                activated_providers.push(pattern.provider.clone());
                                resolutions.push(Resolution::VaultResolved {
                                    var_name,
                                    pattern_name: pattern.name.clone(),
                                    provider: pattern.provider.clone(),
                                    vault_ref: vault_ref.clone(),
                                    value,
                                });
                            }
                            Err(_) => {
                                if let Some(ref default) = pattern.default {
                                    resolutions.push(Resolution::DefaultResolved {
                                        var_name,
                                        pattern_name: pattern.name.clone(),
                                        value: default.clone(),
                                    });
                                } else {
                                    resolutions.push(Resolution::Missing {
                                        var_name,
                                        pattern_name: pattern.name.clone(),
                                        vault_ref: vault_ref.clone(),
                                    });
                                }
                            }
                        }
                    } else if let Some(ref default) = pattern.default {
                        // Url-field defaults are only emitted in proxy mode.
                        // Otherwise we'd activate provider base-URL vars (e.g.
                        // ANTHROPIC_BASE_URL) that flip SDKs into "custom
                        // endpoint" mode and break native API-key auth.
                        if pattern.field == ConfigField::Url && self.proxy_port.is_none() {
                            resolutions.push(Resolution::Passthrough {
                                line: line.to_string(),
                            });
                        } else {
                            let resolved_value =
                                if pattern.field == ConfigField::Url && self.proxy_port.is_some() {
                                    self.proxy_url(&pattern.provider, default)
                                } else {
                                    default.clone()
                                };
                            resolutions.push(Resolution::DefaultResolved {
                                var_name,
                                pattern_name: pattern.name.clone(),
                                value: resolved_value,
                            });
                        }
                    } else if !clean_value.is_empty() {
                        resolutions.push(Resolution::Preserved {
                            var_name,
                            value: clean_value,
                        });
                    } else {
                        resolutions.push(Resolution::Unresolved {
                            var_name,
                            original_line: line.to_string(),
                        });
                    }
                }
                None => {
                    if !clean_value.is_empty() {
                        resolutions.push(Resolution::Preserved {
                            var_name,
                            value: clean_value,
                        });
                    } else {
                        resolutions.push(Resolution::Unresolved {
                            var_name: var_name.clone(),
                            original_line: line.to_string(),
                        });
                    }
                }
            }
        }

        // ── Pass 3: Provider coherence ──────────────────────────────
        // Now that we know which providers got activated, set the
        // backend selector to match. This happens last because the
        // LLM_BACKEND line might appear before the API_KEY lines.
        let all_activated: Vec<String> = available_providers
            .iter()
            .chain(activated_providers.iter())
            .cloned()
            .collect();
        if !all_activated.is_empty() {
            self.apply_provider_coherence(&mut resolutions, &all_activated);
        }

        Ok(resolutions)
    }

    /// Write resolved env to file.
    pub fn write_env_file(resolutions: &[Resolution], output_path: &Path) -> io::Result<()> {
        let mut file = fs::File::create(output_path)?;
        writeln!(file, "# Generated by: zp configure")?;
        writeln!(file, "# Timestamp: {}", chrono::Utc::now().to_rfc3339())?;
        writeln!(
            file,
            "# DO NOT commit this file — it contains vault-resolved secrets."
        )?;
        writeln!(file)?;

        for resolution in resolutions {
            writeln!(file, "{}", resolution.to_env_line())?;
        }

        Ok(())
    }

    /// Print a dry-run summary of resolutions.
    pub fn print_summary(resolutions: &[Resolution]) {
        let mut vault_count = 0;
        let mut default_count = 0;
        let mut preserved_count = 0;
        let mut unresolved_count = 0;
        let mut missing_count = 0;

        for r in resolutions {
            match r {
                Resolution::VaultResolved {
                    var_name,
                    provider,
                    vault_ref,
                    ..
                } => {
                    vault_count += 1;
                    println!(
                        "  \x1b[32m✓\x1b[0m {} ← vault:{} ({})",
                        var_name, vault_ref, provider
                    );
                }
                Resolution::DefaultResolved {
                    var_name, value, ..
                } => {
                    default_count += 1;
                    println!("  \x1b[34m•\x1b[0m {} = {} (default)", var_name, value);
                }
                Resolution::Preserved { var_name, .. } => {
                    preserved_count += 1;
                    println!("  \x1b[33m↺\x1b[0m {} (preserved)", var_name);
                }
                Resolution::Unresolved { var_name, .. } => {
                    unresolved_count += 1;
                    println!(
                        "  \x1b[90m?\x1b[0m {} (unresolved — review needed)",
                        var_name
                    );
                }
                Resolution::Missing {
                    var_name,
                    vault_ref,
                    ..
                } => {
                    missing_count += 1;
                    println!(
                        "  \x1b[31m✗\x1b[0m {} — vault credential '{}' not found",
                        var_name, vault_ref
                    );
                }
                Resolution::Passthrough { .. } => {}
            }
        }

        println!();
        println!(
            "Summary: {} vault-resolved, {} defaults, {} preserved, {} unresolved, {} missing",
            vault_count, default_count, preserved_count, unresolved_count, missing_count
        );
    }
}

// ============================================================================
// Built-in Provider Patterns — the semantic sed ruleset
// ============================================================================

/// Built-in configuration patterns for common providers across the ZP stack.
///
/// These cover the env var naming conventions observed in:
/// - PentAGI (375-line .env.example)
/// - Ember (124-line .env.example, fork of OpenMAIC)
/// - IronClaw (45-line env.example)
///
/// Pattern priority: more specific patterns first, broader catch-alls last.
pub fn builtin_patterns() -> Vec<ConfigPattern> {
    vec![
        // ===================================================================
        // Anthropic / Claude
        // ===================================================================
        ConfigPattern {
            name: "anthropic_api_key".into(),
            pattern: r"^(ANTHROPIC|CLAUDE)_API_KEY$".into(),
            provider: "anthropic".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("anthropic/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "anthropic_url".into(),
            pattern: r"^(ANTHROPIC|CLAUDE)_(SERVER_|BASE_)?URL$".into(),
            provider: "anthropic".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("https://api.anthropic.com".into()),
        },
        ConfigPattern {
            name: "anthropic_model".into(),
            pattern: r"^(ANTHROPIC|CLAUDE)_(MODEL|MODELS)$".into(),
            provider: "anthropic".into(),
            field: ConfigField::Model,
            vault_ref: None,
            default: None,
        },
        // ===================================================================
        // OpenAI / GPT
        // ===================================================================
        ConfigPattern {
            name: "openai_api_key".into(),
            pattern: r"^OPEN_?AI_KEY$".into(),
            provider: "openai".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("openai/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "openai_api_key_standard".into(),
            pattern: r"^OPENAI_API_KEY$".into(),
            provider: "openai".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("openai/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "openai_url".into(),
            pattern: r"^OPEN_?AI_(SERVER_|BASE_)?URL$".into(),
            provider: "openai".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("https://api.openai.com/v1".into()),
        },
        ConfigPattern {
            name: "openai_models".into(),
            pattern: r"^OPENAI_MODELS$".into(),
            provider: "openai".into(),
            field: ConfigField::Model,
            vault_ref: None,
            default: None,
        },
        // ===================================================================
        // OpenAI for TTS/ASR (semantic variants — same key, different purpose)
        // ===================================================================
        ConfigPattern {
            name: "tts_openai_key".into(),
            pattern: r"^TTS_OPENAI_API_KEY$".into(),
            provider: "openai".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("openai/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "tts_openai_url".into(),
            pattern: r"^TTS_OPENAI_BASE_URL$".into(),
            provider: "openai".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("https://api.openai.com/v1".into()),
        },
        ConfigPattern {
            name: "asr_openai_key".into(),
            pattern: r"^ASR_OPENAI_API_KEY$".into(),
            provider: "openai".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("openai/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "asr_openai_url".into(),
            pattern: r"^ASR_OPENAI_BASE_URL$".into(),
            provider: "openai".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("https://api.openai.com/v1".into()),
        },
        // ===================================================================
        // Google / Gemini
        // ===================================================================
        ConfigPattern {
            name: "gemini_api_key".into(),
            pattern: r"^(GEMINI|GOOGLE)_API_KEY$".into(),
            provider: "google".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("google/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "gemini_url".into(),
            pattern: r"^(GEMINI|GOOGLE)_(SERVER_|BASE_)?URL$".into(),
            provider: "google".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("https://generativelanguage.googleapis.com".into()),
        },
        ConfigPattern {
            name: "google_models".into(),
            pattern: r"^GOOGLE_MODELS$".into(),
            provider: "google".into(),
            field: ConfigField::Model,
            vault_ref: None,
            default: None,
        },
        // PentAGI-specific Google search keys (not LLM)
        ConfigPattern {
            name: "google_cx_key".into(),
            pattern: r"^GOOGLE_CX_KEY$".into(),
            provider: "google_search".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("google_search/cx_key".into()),
            default: None,
        },
        // ===================================================================
        // DeepSeek
        // ===================================================================
        ConfigPattern {
            name: "deepseek_api_key".into(),
            pattern: r"^DEEPSEEK_API_KEY$".into(),
            provider: "deepseek".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("deepseek/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "deepseek_url".into(),
            pattern: r"^DEEPSEEK_(SERVER_|BASE_)?URL$".into(),
            provider: "deepseek".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("https://api.deepseek.com".into()),
        },
        // ===================================================================
        // Qwen / Alibaba
        // ===================================================================
        ConfigPattern {
            name: "qwen_api_key".into(),
            pattern: r"^QWEN_API_KEY$".into(),
            provider: "qwen".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("qwen/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "qwen_url".into(),
            pattern: r"^QWEN_(SERVER_|BASE_)?URL$".into(),
            provider: "qwen".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("https://dashscope-us.aliyuncs.com/compatible-mode/v1".into()),
        },
        // TTS/ASR variants
        ConfigPattern {
            name: "tts_qwen_key".into(),
            pattern: r"^TTS_QWEN_API_KEY$".into(),
            provider: "qwen".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("qwen/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "asr_qwen_key".into(),
            pattern: r"^ASR_QWEN_API_KEY$".into(),
            provider: "qwen".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("qwen/api_key".into()),
            default: None,
        },
        // ===================================================================
        // Kimi / Moonshot
        // ===================================================================
        ConfigPattern {
            name: "kimi_api_key".into(),
            pattern: r"^KIMI_API_KEY$".into(),
            provider: "kimi".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("kimi/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "kimi_url".into(),
            pattern: r"^KIMI_(SERVER_|BASE_)?URL$".into(),
            provider: "kimi".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("https://api.moonshot.ai/v1".into()),
        },
        // ===================================================================
        // GLM / Zhipu AI
        // ===================================================================
        ConfigPattern {
            name: "glm_api_key".into(),
            pattern: r"^GLM_API_KEY$".into(),
            provider: "glm".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("glm/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "glm_url".into(),
            pattern: r"^GLM_(SERVER_|BASE_)?URL$".into(),
            provider: "glm".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("https://api.z.ai/api/paas/v4".into()),
        },
        // TTS variant
        ConfigPattern {
            name: "tts_glm_key".into(),
            pattern: r"^TTS_GLM_API_KEY$".into(),
            provider: "glm".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("glm/api_key".into()),
            default: None,
        },
        // ===================================================================
        // Ollama (local inference)
        // ===================================================================
        ConfigPattern {
            name: "ollama_url".into(),
            pattern: r"^OLLAMA_(SERVER_)?URL$".into(),
            provider: "ollama".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("http://host.docker.internal:11434".into()),
        },
        ConfigPattern {
            name: "ollama_api_key".into(),
            pattern: r"^OLLAMA_(SERVER_)?API_KEY$".into(),
            provider: "ollama".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("ollama/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "ollama_model".into(),
            pattern: r"^OLLAMA_(SERVER_)?MODEL$".into(),
            provider: "ollama".into(),
            field: ConfigField::Model,
            vault_ref: None,
            default: None,
        },
        ConfigPattern {
            name: "ollama_pull_enabled".into(),
            pattern: r"^OLLAMA_SERVER_PULL_MODELS_ENABLED$".into(),
            provider: "ollama".into(),
            field: ConfigField::Toggle,
            vault_ref: None,
            default: Some("true".into()),
        },
        ConfigPattern {
            name: "ollama_load_enabled".into(),
            pattern: r"^OLLAMA_SERVER_LOAD_MODELS_ENABLED$".into(),
            provider: "ollama".into(),
            field: ConfigField::Toggle,
            vault_ref: None,
            default: Some("true".into()),
        },
        // ===================================================================
        // AWS Bedrock
        // ===================================================================
        ConfigPattern {
            name: "bedrock_access_key".into(),
            pattern: r"^BEDROCK_ACCESS_KEY_ID$".into(),
            provider: "bedrock".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("bedrock/access_key_id".into()),
            default: None,
        },
        ConfigPattern {
            name: "bedrock_secret_key".into(),
            pattern: r"^BEDROCK_SECRET_ACCESS_KEY$".into(),
            provider: "bedrock".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("bedrock/secret_access_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "bedrock_session_token".into(),
            pattern: r"^BEDROCK_SESSION_TOKEN$".into(),
            provider: "bedrock".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("bedrock/session_token".into()),
            default: None,
        },
        ConfigPattern {
            name: "bedrock_region".into(),
            pattern: r"^BEDROCK_REGION$".into(),
            provider: "bedrock".into(),
            field: ConfigField::Config,
            vault_ref: None,
            default: Some("us-east-1".into()),
        },
        // ===================================================================
        // Embedding providers
        // ===================================================================
        ConfigPattern {
            name: "embedding_url".into(),
            pattern: r"^EMBEDDING_(URL|BASE_URL)$".into(),
            provider: "embedding".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("http://host.docker.internal:11434".into()),
        },
        ConfigPattern {
            name: "embedding_key".into(),
            pattern: r"^EMBEDDING_KEY$".into(),
            provider: "embedding".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("embedding/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "embedding_model".into(),
            pattern: r"^EMBEDDING_MODEL$".into(),
            provider: "embedding".into(),
            field: ConfigField::Model,
            vault_ref: None,
            default: Some("nomic-embed-text".into()),
        },
        ConfigPattern {
            name: "embedding_provider".into(),
            pattern: r"^EMBEDDING_PROVIDER$".into(),
            provider: "embedding".into(),
            field: ConfigField::Config,
            vault_ref: None,
            default: Some("ollama".into()),
        },
        // ===================================================================
        // Search engines
        // ===================================================================
        ConfigPattern {
            name: "tavily_key".into(),
            pattern: r"^TAVILY_API_KEY$".into(),
            provider: "tavily".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("tavily/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "perplexity_key".into(),
            pattern: r"^PERPLEXITY_API_KEY$".into(),
            provider: "perplexity".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("perplexity/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "traversaal_key".into(),
            pattern: r"^TRAVERSAAL_API_KEY$".into(),
            provider: "traversaal".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("traversaal/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "duckduckgo_enabled".into(),
            pattern: r"^DUCKDUCKGO_ENABLED$".into(),
            provider: "duckduckgo".into(),
            field: ConfigField::Toggle,
            vault_ref: None,
            default: Some("true".into()),
        },
        // ===================================================================
        // PostgreSQL (PentAGI, Langfuse, IronClaw)
        // ===================================================================
        ConfigPattern {
            name: "postgres_password".into(),
            pattern: r"^(PENTAGI_)?POSTGRES_PASSWORD$".into(),
            provider: "postgres".into(),
            field: ConfigField::Password,
            vault_ref: Some("postgres/password".into()),
            default: None,
        },
        ConfigPattern {
            name: "postgres_user".into(),
            pattern: r"^(PENTAGI_)?POSTGRES_USER$".into(),
            provider: "postgres".into(),
            field: ConfigField::Username,
            vault_ref: None,
            default: Some("postgres".into()),
        },
        ConfigPattern {
            name: "postgres_db".into(),
            pattern: r"^(PENTAGI_)?POSTGRES_DB$".into(),
            provider: "postgres".into(),
            field: ConfigField::Config,
            vault_ref: None,
            default: None,
        },
        ConfigPattern {
            name: "database_url".into(),
            pattern: r"^DATABASE_URL$".into(),
            provider: "postgres".into(),
            field: ConfigField::ConnectionString,
            vault_ref: Some("postgres/database_url".into()),
            default: None,
        },
        // ===================================================================
        // Langfuse subsystem passwords
        // ===================================================================
        ConfigPattern {
            name: "langfuse_postgres_password".into(),
            pattern: r"^LANGFUSE_POSTGRES_PASSWORD$".into(),
            provider: "langfuse".into(),
            field: ConfigField::Password,
            vault_ref: Some("langfuse/postgres_password".into()),
            default: None,
        },
        ConfigPattern {
            name: "langfuse_clickhouse_password".into(),
            pattern: r"^LANGFUSE_CLICKHOUSE_PASSWORD$".into(),
            provider: "langfuse".into(),
            field: ConfigField::Password,
            vault_ref: Some("langfuse/clickhouse_password".into()),
            default: None,
        },
        ConfigPattern {
            name: "langfuse_redis_auth".into(),
            pattern: r"^LANGFUSE_REDIS_AUTH$".into(),
            provider: "langfuse".into(),
            field: ConfigField::Password,
            vault_ref: Some("langfuse/redis_password".into()),
            default: None,
        },
        ConfigPattern {
            name: "langfuse_salt".into(),
            pattern: r"^LANGFUSE_SALT$".into(),
            provider: "langfuse".into(),
            field: ConfigField::Secret,
            vault_ref: Some("langfuse/salt".into()),
            default: None,
        },
        ConfigPattern {
            name: "langfuse_encryption_key".into(),
            pattern: r"^LANGFUSE_ENCRYPTION_KEY$".into(),
            provider: "langfuse".into(),
            field: ConfigField::Secret,
            vault_ref: Some("langfuse/encryption_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "langfuse_nextauth_secret".into(),
            pattern: r"^LANGFUSE_NEXTAUTH_SECRET$".into(),
            provider: "langfuse".into(),
            field: ConfigField::Secret,
            vault_ref: Some("langfuse/nextauth_secret".into()),
            default: None,
        },
        ConfigPattern {
            name: "langfuse_s3_access_key".into(),
            pattern: r"^LANGFUSE_S3_ACCESS_KEY_ID$".into(),
            provider: "langfuse".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("langfuse/s3_access_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "langfuse_s3_secret_key".into(),
            pattern: r"^LANGFUSE_S3_SECRET_ACCESS_KEY$".into(),
            provider: "langfuse".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("langfuse/s3_secret_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "langfuse_public_key".into(),
            pattern: r"^LANGFUSE_(PUBLIC_KEY|INIT_PROJECT_PUBLIC_KEY)$".into(),
            provider: "langfuse".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("langfuse/public_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "langfuse_secret_key".into(),
            pattern: r"^LANGFUSE_(SECRET_KEY|INIT_PROJECT_SECRET_KEY)$".into(),
            provider: "langfuse".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("langfuse/secret_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "langfuse_init_password".into(),
            pattern: r"^LANGFUSE_INIT_USER_PASSWORD$".into(),
            provider: "langfuse".into(),
            field: ConfigField::Password,
            vault_ref: Some("langfuse/init_password".into()),
            default: None,
        },
        // ===================================================================
        // Neo4j (Graphiti knowledge graph)
        // ===================================================================
        ConfigPattern {
            name: "neo4j_password".into(),
            pattern: r"^NEO4J_PASSWORD$".into(),
            provider: "neo4j".into(),
            field: ConfigField::Password,
            vault_ref: Some("neo4j/password".into()),
            default: None,
        },
        ConfigPattern {
            name: "neo4j_user".into(),
            pattern: r"^NEO4J_USER$".into(),
            provider: "neo4j".into(),
            field: ConfigField::Username,
            vault_ref: None,
            default: Some("neo4j".into()),
        },
        // ===================================================================
        // Graphiti
        // ===================================================================
        ConfigPattern {
            name: "graphiti_enabled".into(),
            pattern: r"^GRAPHITI_ENABLED$".into(),
            provider: "graphiti".into(),
            field: ConfigField::Toggle,
            vault_ref: None,
            default: Some("true".into()),
        },
        ConfigPattern {
            name: "graphiti_url".into(),
            pattern: r"^GRAPHITI_URL$".into(),
            provider: "graphiti".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("http://graphiti:8000".into()),
        },
        // ===================================================================
        // PentAGI-specific security
        // ===================================================================
        ConfigPattern {
            name: "cookie_signing_salt".into(),
            pattern: r"^COOKIE_SIGNING_SALT$".into(),
            provider: "pentagi".into(),
            field: ConfigField::Secret,
            vault_ref: Some("pentagi/cookie_salt".into()),
            default: None,
        },
        // ===================================================================
        // OAuth (Google, GitHub)
        // ===================================================================
        ConfigPattern {
            name: "oauth_google_client_id".into(),
            pattern: r"^OAUTH_GOOGLE_CLIENT_ID$".into(),
            provider: "oauth_google".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("oauth_google/client_id".into()),
            default: None,
        },
        ConfigPattern {
            name: "oauth_google_client_secret".into(),
            pattern: r"^OAUTH_GOOGLE_CLIENT_SECRET$".into(),
            provider: "oauth_google".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("oauth_google/client_secret".into()),
            default: None,
        },
        ConfigPattern {
            name: "oauth_github_client_id".into(),
            pattern: r"^OAUTH_GITHUB_CLIENT_ID$".into(),
            provider: "oauth_github".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("oauth_github/client_id".into()),
            default: None,
        },
        ConfigPattern {
            name: "oauth_github_client_secret".into(),
            pattern: r"^OAUTH_GITHUB_CLIENT_SECRET$".into(),
            provider: "oauth_github".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("oauth_github/client_secret".into()),
            default: None,
        },
        // ===================================================================
        // NEAR AI (IronClaw)
        // ===================================================================
        ConfigPattern {
            name: "nearai_api_key".into(),
            pattern: r"^NEARAI_API_KEY$".into(),
            provider: "nearai".into(),
            field: ConfigField::ApiKey,
            vault_ref: Some("nearai/api_key".into()),
            default: None,
        },
        ConfigPattern {
            name: "nearai_url".into(),
            pattern: r"^NEARAI_BASE_URL$".into(),
            provider: "nearai".into(),
            field: ConfigField::Url,
            vault_ref: None,
            default: Some("https://cloud-api.near.ai".into()),
        },
        ConfigPattern {
            name: "nearai_model".into(),
            pattern: r"^NEARAI_MODEL$".into(),
            provider: "nearai".into(),
            field: ConfigField::Model,
            vault_ref: None,
            default: None,
        },
        // ===================================================================
        // Gateway / Auth tokens (IronClaw)
        // ===================================================================
        ConfigPattern {
            name: "gateway_auth_token".into(),
            pattern: r"^GATEWAY_AUTH_TOKEN$".into(),
            provider: "gateway".into(),
            field: ConfigField::Secret,
            vault_ref: Some("gateway/auth_token".into()),
            default: None,
        },
        // ===================================================================
        // Broad catch-all: any *_API_KEY not matched above
        // ===================================================================
        ConfigPattern {
            name: "generic_api_key".into(),
            pattern: r"^[A-Z_]+_API_KEY$".into(),
            provider: "unknown".into(),
            field: ConfigField::ApiKey,
            vault_ref: None, // No vault ref — flag for review
            default: None,
        },
    ]
}

// ============================================================================
// Parse existing .env file into a HashMap
// ============================================================================

/// Parse an existing `.env` file into a key-value map.
pub fn parse_env_file(path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = trimmed.split_once('=') {
                let clean_value = value.split('#').next().unwrap_or("").trim();
                if !clean_value.is_empty() {
                    map.insert(key.trim().to_string(), clean_value.to_string());
                }
            }
        }
    }
    map
}

// ============================================================================
// CLI Entry Points
// ============================================================================

/// Run `zp configure tool` — resolve a tool's .env from vault.
pub fn run_tool(
    tool_path: &Path,
    tool_name: &str,
    dry_run: bool,
    vault: &CredentialVault,
    policy_check: PolicyCheckFn,
) -> i32 {
    // Find the .env.example template
    let template = tool_path.join(".env.example");
    if !template.exists() {
        eprintln!("Error: no .env.example found at {}", template.display());
        return 1;
    }

    // Parse existing .env if present
    let existing_env_path = tool_path.join(".env");
    let existing_env = if existing_env_path.exists() {
        parse_env_file(&existing_env_path)
    } else {
        HashMap::new()
    };

    let engine = ConfigEngine::new();

    println!("ZeroPoint Configure — Semantic Sed");
    println!("Tool: {}", tool_name);
    println!("Template: {}", template.display());
    if existing_env_path.exists() {
        println!(
            "Existing .env: {} ({} values)",
            existing_env_path.display(),
            existing_env.len()
        );
    }
    println!();

    match engine.process_env_file(&template, &existing_env, vault, policy_check, tool_name) {
        Ok(resolutions) => {
            ConfigEngine::print_summary(&resolutions);

            if dry_run {
                println!("\n(dry run — no files written)");
                return 0;
            }

            // Write the resolved .env
            let output_path = tool_path.join(".env");
            match ConfigEngine::write_env_file(&resolutions, &output_path) {
                Ok(_) => {
                    println!("\nWrote: {}", output_path.display());
                    info!(tool = tool_name, path = %output_path.display(), "Configuration written");
                    0
                }
                Err(e) => {
                    eprintln!("Error writing .env: {}", e);
                    1
                }
            }
        }
        Err(e) => {
            eprintln!("Error processing template: {}", e);
            1
        }
    }
}

/// Run `zp configure providers` — list registered providers in vault.
pub fn run_providers(vault: &CredentialVault) -> i32 {
    let credentials = vault.list();
    if credentials.is_empty() {
        println!("No provider credentials registered in vault.");
        println!("Use 'zp configure vault-add --provider <name> --key <value>' to add one.");
        return 0;
    }

    println!("Registered vault credentials:");
    println!();

    // Group by provider (credential names are "provider/field")
    let mut providers: HashMap<String, Vec<String>> = HashMap::new();
    for name in &credentials {
        let provider = name.split('/').next().unwrap_or(name);
        providers
            .entry(provider.to_string())
            .or_default()
            .push(name.clone());
    }

    for (provider, refs) in &providers {
        println!("  \x1b[1m{}\x1b[0m", provider);
        for r in refs {
            let field = r.split('/').nth(1).unwrap_or("?");
            println!("    {} (vault:{})", field, r);
        }
        println!();
    }

    0
}

/// Run `zp configure vault-add` — store a credential in the vault.
pub fn run_vault_add(
    vault: &mut CredentialVault,
    provider: &str,
    field: &str,
    value: &str,
    vault_path: &Path,
) -> i32 {
    let vault_ref = format!("{}/{}", provider, field);
    match vault.store(&vault_ref, value.as_bytes()) {
        Ok(_) => {
            // Persist to disk so credentials survive across invocations
            if let Err(e) = vault.save(vault_path) {
                eprintln!(
                    "Warning: credential stored in memory but failed to persist: {}",
                    e
                );
                eprintln!("Vault path: {}", vault_path.display());
                // Still return success — the credential IS stored for this session
            } else {
                println!(
                    "Stored credential: {} ({} bytes, persisted)",
                    vault_ref,
                    value.len()
                );
            }
            info!(vault_ref = vault_ref, "Credential stored in vault");
            0
        }
        Err(e) => {
            eprintln!("Error storing credential: {}", e);
            1
        }
    }
}

// ============================================================================
// Scan — auto-discovery of configurable tools
// ============================================================================

/// A discovered tool with its env template and analysis.
#[derive(Debug, Clone)]
pub struct DiscoveredTool {
    /// Human-readable tool name (derived from directory name)
    pub name: String,
    /// Path to the tool's project directory
    pub path: std::path::PathBuf,
    /// Path to the env template file found
    pub template: std::path::PathBuf,
    /// Total number of env variables in template
    pub total_vars: usize,
    /// Variables that need vault credentials (API keys, passwords, etc.)
    pub vault_vars: Vec<String>,
    /// Variables already satisfied by vault contents
    pub satisfied: Vec<String>,
    /// Variables that need credentials not yet in vault
    pub missing: Vec<String>,
    /// Variables with defaults (URL, model, toggle — no vault needed)
    #[allow(dead_code)]
    pub defaulted: Vec<String>,
    /// Variables not matched by any pattern (need human review)
    pub unrecognized: Vec<String>,
}

/// Well-known env template filenames, in priority order.
const ENV_TEMPLATE_NAMES: &[&str] = &[
    ".env.example",
    ".env.sample",
    ".env.template",
    "env.example",
    ".env.defaults",
];

/// Well-known subdirectories where env templates may live (e.g., IronClaw's deploy/).
const ENV_SUBDIRS: &[&str] = &["", "deploy", "docker", "config", ".config"];

/// Find the env template for a given directory, checking well-known names and subdirs.
fn find_env_template(dir: &Path) -> Option<std::path::PathBuf> {
    for subdir in ENV_SUBDIRS {
        let base = if subdir.is_empty() {
            dir.to_path_buf()
        } else {
            dir.join(subdir)
        };
        for name in ENV_TEMPLATE_NAMES {
            let candidate = base.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Analyze a tool's env template against the current vault contents.
fn analyze_tool(
    dir: &Path,
    template: &Path,
    engine: &ConfigEngine,
    vault: &CredentialVault,
) -> DiscoveredTool {
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());

    let content = fs::read_to_string(template).unwrap_or_default();
    let mut total_vars = 0;
    let mut vault_vars = Vec::new();
    let mut satisfied = Vec::new();
    let mut missing = Vec::new();
    let mut defaulted = Vec::new();
    let mut unrecognized = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse VAR_NAME=value
        if let Some(eq_pos) = trimmed.find('=') {
            let var_name = trimmed[..eq_pos].trim();
            if var_name.is_empty() {
                continue;
            }
            total_vars += 1;

            match engine.match_var(var_name) {
                Some(pattern) => {
                    if pattern.field.requires_vault() {
                        vault_vars.push(var_name.to_string());
                        if let Some(ref vr) = pattern.vault_ref {
                            // Check if this vault_ref is satisfied
                            if vault.retrieve(vr).is_ok() {
                                satisfied.push(var_name.to_string());
                            } else {
                                missing.push(var_name.to_string());
                            }
                        } else {
                            missing.push(var_name.to_string());
                        }
                    } else {
                        defaulted.push(var_name.to_string());
                    }
                }
                None => {
                    unrecognized.push(var_name.to_string());
                }
            }
        }
    }

    DiscoveredTool {
        name,
        path: dir.to_path_buf(),
        template: template.to_path_buf(),
        total_vars,
        vault_vars,
        satisfied,
        missing,
        defaulted,
        unrecognized,
    }
}

/// Discover configurable tools in a directory tree.
///
/// Reusable by both `run_scan` and `zp onboard`.
pub fn discover_tools_in(
    scan_path: &Path,
    depth: usize,
    engine: &ConfigEngine,
    vault: &CredentialVault,
) -> Vec<DiscoveredTool> {
    let mut discovered: Vec<DiscoveredTool> = Vec::new();

    // Check the scan_path itself
    if let Some(template) = find_env_template(scan_path) {
        discovered.push(analyze_tool(scan_path, &template, engine, vault));
    }

    // Walk immediate children (depth 1) or deeper
    if let Ok(entries) = fs::read_dir(scan_path) {
        for entry in entries.filter_map(|e| e.ok()) {
            let child = entry.path();
            if !child.is_dir() {
                continue;
            }
            let dir_name = child
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
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

            if let Some(template) = find_env_template(&child) {
                discovered.push(analyze_tool(&child, &template, engine, vault));
            }

            if depth >= 2 {
                if let Ok(grandchildren) = fs::read_dir(&child) {
                    for gc in grandchildren.filter_map(|e| e.ok()) {
                        let gc_path = gc.path();
                        if !gc_path.is_dir() {
                            continue;
                        }
                        let gc_name = gc_path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        if gc_name.starts_with('.')
                            || gc_name == "node_modules"
                            || gc_name == "target"
                        {
                            continue;
                        }
                        if let Some(template) = find_env_template(&gc_path) {
                            discovered.push(analyze_tool(&gc_path, &template, engine, vault));
                        }
                    }
                }
            }
        }
    }

    discovered
}

/// Run `zp configure scan` — discover configurable tools and report readiness.
pub fn run_scan(scan_path: &Path, vault: &CredentialVault, depth: usize) -> i32 {
    let engine = ConfigEngine::new();

    println!("ZeroPoint Configure — Scan");
    println!("Scanning: {}", scan_path.display());
    println!();

    let discovered = discover_tools_in(scan_path, depth, &engine, vault);

    if discovered.is_empty() {
        println!("No configurable tools found.");
        println!("Looked for: {:?}", ENV_TEMPLATE_NAMES);
        return 0;
    }

    // Print results
    println!("Found {} configurable tool(s):\n", discovered.len());

    let vault_creds = vault.list();
    let mut total_ready = 0;

    for tool in &discovered {
        let status = if tool.missing.is_empty() && tool.unrecognized.is_empty() {
            total_ready += 1;
            "READY"
        } else if tool.missing.is_empty() {
            total_ready += 1;
            "READY (some vars unrecognized)"
        } else {
            "NEEDS CREDENTIALS"
        };

        println!("  {} [{}]", tool.name, status);
        println!("    template: {}", tool.template.display());
        println!(
            "    vars: {} total, {} need vault, {} satisfied, {} missing",
            tool.total_vars,
            tool.vault_vars.len(),
            tool.satisfied.len(),
            tool.missing.len()
        );

        if !tool.missing.is_empty() {
            println!("    missing:");
            for var in &tool.missing {
                // Show which vault_ref it needs
                if let Some(pattern) = engine.match_var(var) {
                    if let Some(ref vr) = pattern.vault_ref {
                        println!("      {} -> vault:{}", var, vr);
                    } else {
                        println!("      {} (needs manual entry)", var);
                    }
                } else {
                    println!("      {}", var);
                }
            }
        }

        if !tool.unrecognized.is_empty() {
            println!("    unrecognized ({}):", tool.unrecognized.len());
            for var in tool.unrecognized.iter().take(5) {
                println!("      {}", var);
            }
            if tool.unrecognized.len() > 5 {
                println!("      ... and {} more", tool.unrecognized.len() - 5);
            }
        }
        println!();
    }

    // Summary
    println!("---");
    println!("Vault: {} credential(s) stored", vault_creds.len());
    println!(
        "Tools: {}/{} ready to configure",
        total_ready,
        discovered.len()
    );

    if total_ready < discovered.len() {
        println!("\nTo add missing credentials:");
        // Collect unique missing vault_refs
        let mut needed: Vec<String> = Vec::new();
        for tool in &discovered {
            for var in &tool.missing {
                if let Some(pattern) = engine.match_var(var) {
                    if let Some(ref vr) = pattern.vault_ref {
                        if !needed.contains(vr) {
                            needed.push(vr.clone());
                        }
                    }
                }
            }
        }
        for vr in &needed {
            let parts: Vec<&str> = vr.splitn(2, '/').collect();
            if parts.len() == 2 {
                println!(
                    "  zp configure vault-add --provider {} --field {}",
                    parts[0], parts[1]
                );
            }
        }
    }

    if total_ready > 0 {
        println!("\nTo configure a ready tool:");
        for tool in &discovered {
            if tool.missing.is_empty() {
                println!(
                    "  zp configure tool --path {} --name {}",
                    tool.path.display(),
                    tool.name
                );
            }
        }
    }

    0
}

// ============================================================================
// Auto — scan + configure all ready tools in one shot
// ============================================================================

/// Result of auto-configuring one tool. `name` and `path` are retained
/// for the upcoming summary/reporting surface; silence dead-code until
/// the reporter is wired up.
#[allow(dead_code)]
#[derive(Debug)]
pub struct AutoResult {
    pub name: String,
    pub path: std::path::PathBuf,
    pub status: AutoStatus,
}

#[derive(Debug, PartialEq)]
pub enum AutoStatus {
    /// Tool was configured successfully
    Configured,
    /// Tool was skipped — missing vault credentials
    SkippedMissing { missing_refs: Vec<String> },
    /// Tool was skipped — already has a .env and --no-overwrite was set
    SkippedExists,
    /// Tool configuration failed
    Failed { error: String },
}

/// Run `zp configure auto` — discover and configure all ready tools.
pub fn run_auto(
    scan_path: &Path,
    vault: &CredentialVault,
    policy_check: PolicyCheckFn,
    depth: usize,
    dry_run: bool,
    overwrite: bool,
    proxy_port: Option<u16>,
) -> i32 {
    let engine = match proxy_port {
        Some(port) => ConfigEngine::with_proxy(port),
        None => ConfigEngine::new(),
    };

    println!("ZeroPoint Configure — Auto");
    println!("Scanning: {}", scan_path.display());
    println!("Mode: {}", if dry_run { "dry run" } else { "live" });
    if let Some(port) = proxy_port {
        println!("Proxy: http://localhost:{}/api/v1/proxy/{{provider}}", port);
    }
    println!();

    // Phase 1: Discover
    let mut discovered: Vec<DiscoveredTool> = Vec::new();

    if let Some(template) = find_env_template(scan_path) {
        discovered.push(analyze_tool(scan_path, &template, &engine, vault));
    }

    if let Ok(entries) = fs::read_dir(scan_path) {
        for entry in entries.filter_map(|e| e.ok()) {
            let child = entry.path();
            if !child.is_dir() {
                continue;
            }
            let dir_name = child
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
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

            if let Some(template) = find_env_template(&child) {
                discovered.push(analyze_tool(&child, &template, &engine, vault));
            }

            if depth >= 2 {
                if let Ok(grandchildren) = fs::read_dir(&child) {
                    for gc in grandchildren.filter_map(|e| e.ok()) {
                        let gc_path = gc.path();
                        if !gc_path.is_dir() {
                            continue;
                        }
                        let gc_name = gc_path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        if gc_name.starts_with('.')
                            || gc_name == "node_modules"
                            || gc_name == "target"
                        {
                            continue;
                        }
                        if let Some(template) = find_env_template(&gc_path) {
                            discovered.push(analyze_tool(&gc_path, &template, &engine, vault));
                        }
                    }
                }
            }
        }
    }

    if discovered.is_empty() {
        println!("No configurable tools found.");
        return 0;
    }

    println!("Discovered {} tool(s)\n", discovered.len());

    // ── MVC Phase: Capability-aware resolution ──────────────────────
    // Try MVC discovery first for each tool. If a tool has a manifest or
    // can be heuristically inferred, use capability-based resolution.
    // Fall back to legacy var-matching only for tools MVC can't handle.
    let catalog = zp_engine::providers::load_catalog();
    let vault_providers = extract_vault_providers(vault);

    let mut mvc_results: Vec<AutoResult> = Vec::new();
    let mut legacy_tools: Vec<&DiscoveredTool> = Vec::new();

    for tool in &discovered {
        let mvc_discovery = zp_engine::discovery::discover_tool(&tool.path);

        // Only use MVC path if we got at least medium confidence
        if mvc_discovery.confidence >= zp_engine::capability::Confidence::Medium {
            let resolved = zp_engine::capability::resolve_tool(
                &mvc_discovery.manifest,
                &tool.path,
                &catalog,
                &vault_providers,
            );

            let source_label = match &mvc_discovery.source {
                zp_engine::discovery::ManifestSource::File(_) => "manifest",
                zp_engine::discovery::ManifestSource::Inferred => "inferred",
            };

            if !resolved.ready {
                // Missing required capabilities
                let missing_caps = resolved.missing_required.clone();
                println!(
                    "  SKIP  {} ({}) — missing capability: {}",
                    tool.name,
                    source_label,
                    missing_caps.join(", ")
                );
                // Show which providers could satisfy each missing capability
                for cap in &missing_caps {
                    let providers = zp_engine::providers::ProviderProfile::providers_for_capability(
                        &catalog, cap,
                    );
                    if !providers.is_empty() {
                        let names: Vec<&str> = providers.iter().map(|p| p.name.as_str()).collect();
                        println!("          → add a key for: {}", names.join(", "));
                    }
                }
                mvc_results.push(AutoResult {
                    name: tool.name.clone(),
                    path: tool.path.clone(),
                    status: AutoStatus::SkippedMissing {
                        missing_refs: missing_caps,
                    },
                });
                continue;
            }

            // Skip if .env exists and --no-overwrite
            let env_path = tool.path.join(".env");
            if env_path.exists() && !overwrite {
                println!(
                    "  SKIP  {} — .env already exists (use --overwrite to replace)",
                    tool.name
                );
                mvc_results.push(AutoResult {
                    name: tool.name.clone(),
                    path: tool.path.clone(),
                    status: AutoStatus::SkippedExists,
                });
                continue;
            }

            // Print capability resolution tree
            println!(
                "  CONFIG  {} ({}, {} confidence)",
                tool.name, source_label, resolved.confidence
            );
            for cap_res in &resolved.capabilities {
                let symbol = match &cap_res.status {
                    zp_engine::capability::ResolutionStatus::Resolved { provider_id } => {
                        format!("✓ {} → {}", cap_res.capability, provider_id)
                    }
                    zp_engine::capability::ResolutionStatus::Shared {
                        shared_with,
                        provider_id,
                    } => {
                        format!(
                            "✓ {} → {} (shared with {})",
                            cap_res.capability, provider_id, shared_with
                        )
                    }
                    zp_engine::capability::ResolutionStatus::DefaultLocal => {
                        format!("✓ {} → local default", cap_res.capability)
                    }
                    zp_engine::capability::ResolutionStatus::AutoGenerated => {
                        format!("✓ {} → auto-generated", cap_res.capability)
                    }
                    zp_engine::capability::ResolutionStatus::Missing => {
                        format!("✗ {} — not available", cap_res.capability)
                    }
                    zp_engine::capability::ResolutionStatus::NeedsAttention { reason } => {
                        format!("⚠ {} — {}", cap_res.capability, reason)
                    }
                };
                let req_label = if cap_res.required { "" } else { " (optional)" };
                println!("          {}{}", symbol, req_label);
            }

            // Surface attention items
            if !mvc_discovery.attention_items.is_empty() {
                println!("          ── attention ──");
                for item in &mvc_discovery.attention_items {
                    println!("          ⚠ {} — {}", item.subject, item.reason);
                    if let Some(ref sug) = item.suggestion {
                        println!("            → {}", sug);
                    }
                }
            }

            if !resolved.needs_attention.is_empty() {
                for note in &resolved.needs_attention {
                    println!("          ⚠ {}", note);
                }
            }

            // MVC resolution succeeded — now process the .env file using the
            // legacy engine for the actual file writing (MVC resolves capabilities
            // but we still need the var-level template processing for now).
            // TODO(Phase E): Replace with native MVC env writer.
            let existing_env = if env_path.exists() && !overwrite {
                parse_env_file(&env_path)
            } else {
                HashMap::new()
            };

            match engine.process_env_file(
                &tool.template,
                &existing_env,
                vault,
                policy_check,
                &tool.name,
            ) {
                Ok(resolutions) => {
                    if dry_run {
                        let resolved_count = resolutions
                            .iter()
                            .filter(|r| {
                                matches!(
                                    r,
                                    Resolution::VaultResolved { .. }
                                        | Resolution::DefaultResolved { .. }
                                )
                            })
                            .count();
                        println!(
                            "          would resolve {}/{} variables",
                            resolved_count, tool.total_vars
                        );
                    } else {
                        match ConfigEngine::write_env_file(&resolutions, &env_path) {
                            Ok(_) => {
                                println!("          wrote {}", env_path.display());
                                info!(
                                    tool = tool.name,
                                    path = %env_path.display(),
                                    source = source_label,
                                    confidence = %resolved.confidence,
                                    "MVC auto-configured"
                                );
                            }
                            Err(e) => {
                                eprintln!("          error writing .env: {}", e);
                                mvc_results.push(AutoResult {
                                    name: tool.name.clone(),
                                    path: tool.path.clone(),
                                    status: AutoStatus::Failed {
                                        error: e.to_string(),
                                    },
                                });
                                continue;
                            }
                        }
                    }
                    mvc_results.push(AutoResult {
                        name: tool.name.clone(),
                        path: tool.path.clone(),
                        status: AutoStatus::Configured,
                    });
                }
                Err(e) => {
                    eprintln!("          error processing template: {}", e);
                    mvc_results.push(AutoResult {
                        name: tool.name.clone(),
                        path: tool.path.clone(),
                        status: AutoStatus::Failed {
                            error: e.to_string(),
                        },
                    });
                }
            }
        } else {
            // Low confidence or no env template — fall back to legacy path
            legacy_tools.push(tool);
        }
    }

    // ── Legacy Phase: Var-level resolution for remaining tools ──────
    let mut results: Vec<AutoResult> = mvc_results;

    for tool in legacy_tools {
        // Skip if missing credentials — but only when ALL credential vars are
        // missing.  Many tools (like Ember) have numerous optional provider vars
        // in .env.example; skipping those tools is wrong when at least one
        // provider is already satisfied.
        if !tool.missing.is_empty() {
            let missing_refs: Vec<String> = tool
                .missing
                .iter()
                .filter_map(|var| engine.match_var(var).and_then(|p| p.vault_ref.clone()))
                .collect();
            if !missing_refs.is_empty() && tool.satisfied.is_empty() {
                // No credentials resolved at all — genuinely unconfigurable.
                println!(
                    "  SKIP  {} (legacy) — missing {} credential(s): {}",
                    tool.name,
                    missing_refs.len(),
                    missing_refs.join(", ")
                );
                results.push(AutoResult {
                    name: tool.name.clone(),
                    path: tool.path.clone(),
                    status: AutoStatus::SkippedMissing { missing_refs },
                });
                continue;
            } else if !missing_refs.is_empty() {
                // Some credentials resolved, some missing — proceed with what
                // we have.  Tools with multi-provider support (LLM routers, etc.)
                // work fine with partial credential coverage.
                println!("  CONFIG  {} (legacy, partial) — {}/{} credential(s) resolved, {} optional missing",
                    tool.name,
                    tool.satisfied.len(),
                    tool.satisfied.len() + missing_refs.len(),
                    missing_refs.len());
            }
            // Vars that require_vault() but lack a vault_ref are pattern gaps,
            // not user-actionable missing credentials — proceed normally.
        }

        // Skip if .env exists and --no-overwrite
        let env_path = tool.path.join(".env");
        if env_path.exists() && !overwrite {
            println!(
                "  SKIP  {} — .env already exists (use --overwrite to replace)",
                tool.name
            );
            results.push(AutoResult {
                name: tool.name.clone(),
                path: tool.path.clone(),
                status: AutoStatus::SkippedExists,
            });
            continue;
        }

        // Configure this tool
        println!("  CONFIG  {} (legacy) ...", tool.name);

        // When overwriting, start fresh — don't preserve old values
        let existing_env = if env_path.exists() && !overwrite {
            parse_env_file(&env_path)
        } else {
            HashMap::new()
        };

        match engine.process_env_file(
            &tool.template,
            &existing_env,
            vault,
            policy_check,
            &tool.name,
        ) {
            Ok(resolutions) => {
                if dry_run {
                    let resolved_count = resolutions
                        .iter()
                        .filter(|r| {
                            matches!(
                                r,
                                Resolution::VaultResolved { .. }
                                    | Resolution::DefaultResolved { .. }
                            )
                        })
                        .count();
                    println!(
                        "          would resolve {}/{} variables",
                        resolved_count, tool.total_vars
                    );
                    results.push(AutoResult {
                        name: tool.name.clone(),
                        path: tool.path.clone(),
                        status: AutoStatus::Configured,
                    });
                } else {
                    match ConfigEngine::write_env_file(&resolutions, &env_path) {
                        Ok(_) => {
                            println!("          wrote {}", env_path.display());
                            info!(tool = tool.name, path = %env_path.display(), "Legacy auto-configured");
                            results.push(AutoResult {
                                name: tool.name.clone(),
                                path: tool.path.clone(),
                                status: AutoStatus::Configured,
                            });
                        }
                        Err(e) => {
                            eprintln!("          error writing .env: {}", e);
                            results.push(AutoResult {
                                name: tool.name.clone(),
                                path: tool.path.clone(),
                                status: AutoStatus::Failed {
                                    error: e.to_string(),
                                },
                            });
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("          error processing template: {}", e);
                results.push(AutoResult {
                    name: tool.name.clone(),
                    path: tool.path.clone(),
                    status: AutoStatus::Failed {
                        error: e.to_string(),
                    },
                });
            }
        }
    }

    // Phase 3: Summary
    println!();
    println!("---");
    let configured = results
        .iter()
        .filter(|r| r.status == AutoStatus::Configured)
        .count();
    let skipped_missing = results
        .iter()
        .filter(|r| matches!(r.status, AutoStatus::SkippedMissing { .. }))
        .count();
    let skipped_exists = results
        .iter()
        .filter(|r| r.status == AutoStatus::SkippedExists)
        .count();
    let failed = results
        .iter()
        .filter(|r| matches!(r.status, AutoStatus::Failed { .. }))
        .count();

    println!("Configured: {}", configured);
    if skipped_missing > 0 {
        println!("Skipped (missing creds): {}", skipped_missing);
    }
    if skipped_exists > 0 {
        println!("Skipped (existing .env): {}", skipped_exists);
    }
    if failed > 0 {
        println!("Failed: {}", failed);
    }

    if dry_run {
        println!("\n(dry run — no files were written)");
    }

    // Show what's needed for skipped tools
    if skipped_missing > 0 {
        println!("\nTo configure skipped tools, add missing credentials:");
        let mut needed: Vec<String> = Vec::new();
        for r in &results {
            if let AutoStatus::SkippedMissing { ref missing_refs } = r.status {
                for vr in missing_refs {
                    if !needed.contains(vr) {
                        needed.push(vr.clone());
                    }
                }
            }
        }
        for vr in &needed {
            let parts: Vec<&str> = vr.splitn(2, '/').collect();
            if parts.len() == 2 {
                println!(
                    "  zp configure vault-add --provider {} --field {}",
                    parts[0], parts[1]
                );
            }
        }
        println!(
            "\nThen re-run: zp configure auto --path {}",
            scan_path.display()
        );
    }

    if failed > 0 {
        1
    } else {
        0
    }
}

// ============================================================================
// MVC helpers
// ============================================================================

/// Extract provider IDs from vault credential refs.
///
/// Vault stores credentials as `"provider/field"` (e.g., `"anthropic/api_key"`).
/// This extracts unique provider IDs so the MVC engine knows what's available.
fn extract_vault_providers(vault: &CredentialVault) -> Vec<String> {
    let mut providers: Vec<String> = vault
        .list()
        .iter()
        .filter_map(|ref_name| ref_name.split('/').next().map(String::from))
        .collect();
    providers.sort();
    providers.dedup();
    providers
}

/// Run `zp configure manifest` — generate a draft `.zp-configure.toml`.
///
/// Analyzes a tool's `.env.example` heuristically and writes a manifest
/// the user can review and commit. This is the Tier 3 → Tier 4 escalation
/// path: inferred knowledge → permanent high-confidence manifest.
pub fn run_manifest(tool_path: &Path) -> i32 {
    let discovery = zp_engine::discovery::discover_tool(tool_path);

    let tool_name = tool_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());

    println!("ZeroPoint Configure — Manifest Generator");
    println!("Tool: {} ({})", tool_name, tool_path.display());
    println!();

    match &discovery.source {
        zp_engine::discovery::ManifestSource::File(p) => {
            println!("  INFO  Manifest already exists: {}", p.display());
            println!("         Regenerating from current state.\n");
        }
        zp_engine::discovery::ManifestSource::Inferred => {
            println!("  INFO  No manifest found — inferring from .env.example\n");
        }
    }

    // Show what was discovered
    let m = &discovery.manifest;
    println!("  Required capabilities: {}", m.required.len());
    for req in &m.required {
        let vars = if req.env_vars.is_empty() {
            String::new()
        } else {
            format!(" ({})", req.env_vars.join(", "))
        };
        println!("    • {}{}", req.capability, vars);
    }

    if !m.optional.is_empty() {
        println!("  Optional capabilities: {}", m.optional.len());
        for opt in &m.optional {
            println!("    • {}", opt.capability);
        }
    }

    if let Some(ref ag) = m.auto_generate {
        if !ag.secrets.is_empty() {
            println!("  Auto-generate secrets: {}", ag.secrets.len());
        }
    }

    if !discovery.attention_items.is_empty() {
        println!();
        println!("  ⚠ Attention items ({}):", discovery.attention_items.len());
        for item in &discovery.attention_items {
            println!("    • {} — {}", item.subject, item.reason);
            if let Some(ref sug) = item.suggestion {
                println!("      → {}", sug);
            }
        }
    }

    println!("\n  Confidence: {}", discovery.confidence);

    // Generate the TOML
    let toml_str = zp_engine::discovery::generate_manifest_toml(&discovery);
    let manifest_path = tool_path.join(".zp-configure.toml");

    match fs::write(&manifest_path, &toml_str) {
        Ok(_) => {
            println!("\n  ✓ Wrote {}", manifest_path.display());
            println!("    Review and commit to lock in high-confidence resolution.");
            0
        }
        Err(e) => {
            eprintln!("\n  ✗ Failed to write manifest: {}", e);
            // Print to stdout as fallback
            println!("\n--- Generated manifest (copy manually) ---\n");
            println!("{}", toml_str);
            1
        }
    }
}

// ============================================================================
// Validate — live credential connection tests
// ============================================================================

/// Validate vault credentials against their respective provider APIs.
///
/// Reads all vault entries, matches them to providers, and runs lightweight
/// health checks (e.g., `GET /v1/models`) to verify keys are live.
pub fn run_validate(
    vault: &CredentialVault,
    filter_provider: Option<&str>,
    json_output: bool,
) -> i32 {
    use zp_engine::validate;

    let vault_refs = vault.list();
    if vault_refs.is_empty() {
        eprintln!();
        eprintln!("  No credentials in vault. Run `zp configure vault-add` first.");
        eprintln!();
        return 1;
    }

    // Build credential list from vault
    let retrieve = |name: &str| -> Option<Vec<u8>> { vault.retrieve(name).ok() };
    let mut creds = validate::credentials_from_vault_refs(&vault_refs, &retrieve);

    // Apply provider filter if specified
    if let Some(provider) = filter_provider {
        creds.retain(|c| c.provider_id == provider);
        if creds.is_empty() {
            eprintln!();
            eprintln!("  No credentials found for provider '{provider}'.");
            eprintln!("  Available: {}", vault_refs.join(", "));
            eprintln!();
            return 1;
        }
    }

    println!();
    println!("  ZeroPoint Credential Validator");
    println!(
        "  Testing {} credential(s) against live APIs...",
        creds.len()
    );
    println!();

    // Run the async validation — we're inside #[tokio::main] so use the
    // existing runtime via block_in_place + Handle::current().
    let report = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(validate::validate_credentials(&creds))
    });

    if json_output {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("  Failed to serialize report: {}", e);
                return 1;
            }
        }
    } else {
        print!("{}", validate::format_report(&report));
    }

    // Exit code: 0 if no invalid, 1 if any invalid
    if report.invalid > 0 {
        1
    } else {
        0
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_key_matches() {
        let engine = ConfigEngine::new();
        // PentAGI style
        let m = engine.match_var("ANTHROPIC_API_KEY");
        assert!(m.is_some());
        assert_eq!(m.unwrap().provider, "anthropic");
        assert_eq!(m.unwrap().vault_ref.as_deref(), Some("anthropic/api_key"));
    }

    #[test]
    fn test_openai_key_variations() {
        let engine = ConfigEngine::new();
        // PentAGI uses OPEN_AI_KEY
        let m1 = engine.match_var("OPEN_AI_KEY");
        assert!(m1.is_some());
        assert_eq!(m1.unwrap().provider, "openai");

        // OpenMAIC uses OPENAI_API_KEY
        let m2 = engine.match_var("OPENAI_API_KEY");
        assert!(m2.is_some());
        assert_eq!(m2.unwrap().provider, "openai");
    }

    #[test]
    fn test_tts_asr_resolve_to_same_provider() {
        let engine = ConfigEngine::new();
        let tts = engine.match_var("TTS_OPENAI_API_KEY");
        let asr = engine.match_var("ASR_OPENAI_API_KEY");
        let base = engine.match_var("OPENAI_API_KEY");

        assert!(tts.is_some());
        assert!(asr.is_some());
        assert!(base.is_some());

        // All three should resolve to the same vault credential
        assert_eq!(tts.unwrap().vault_ref, base.unwrap().vault_ref);
        assert_eq!(asr.unwrap().vault_ref.as_deref(), Some("openai/api_key"));
    }

    #[test]
    fn test_ollama_url_variations() {
        let engine = ConfigEngine::new();
        // PentAGI style
        let m = engine.match_var("OLLAMA_SERVER_URL");
        assert!(m.is_some());
        assert_eq!(m.unwrap().provider, "ollama");
        assert_eq!(
            m.unwrap().default.as_deref(),
            Some("http://host.docker.internal:11434")
        );
    }

    #[test]
    fn test_postgres_password_variants() {
        let engine = ConfigEngine::new();
        let m1 = engine.match_var("POSTGRES_PASSWORD");
        let m2 = engine.match_var("PENTAGI_POSTGRES_PASSWORD");
        assert!(m1.is_some());
        assert!(m2.is_some());
        assert_eq!(m1.unwrap().vault_ref.as_deref(), Some("postgres/password"));
        assert_eq!(m2.unwrap().vault_ref.as_deref(), Some("postgres/password"));
    }

    #[test]
    fn test_langfuse_secrets() {
        let engine = ConfigEngine::new();
        let salt = engine.match_var("LANGFUSE_SALT");
        assert!(salt.is_some());
        assert_eq!(salt.unwrap().field, ConfigField::Secret);

        let enc = engine.match_var("LANGFUSE_ENCRYPTION_KEY");
        assert!(enc.is_some());
        assert!(enc.unwrap().field.requires_vault());
    }

    #[test]
    fn test_database_url_ironclaw() {
        let engine = ConfigEngine::new();
        let m = engine.match_var("DATABASE_URL");
        assert!(m.is_some());
        assert_eq!(m.unwrap().provider, "postgres");
        assert_eq!(m.unwrap().field, ConfigField::ConnectionString);
    }

    #[test]
    fn test_generic_api_key_catchall() {
        let engine = ConfigEngine::new();
        // Some unknown provider
        let m = engine.match_var("SILICONFLOW_API_KEY");
        assert!(m.is_some());
        // The generic catch-all has no vault_ref — flags for review
        // (Actually, if a specific provider isn't in the list, the catch-all matches)
    }

    #[test]
    fn test_non_secret_not_vault() {
        let engine = ConfigEngine::new();
        let m = engine.match_var("EMBEDDING_MODEL");
        assert!(m.is_some());
        assert_eq!(m.unwrap().field, ConfigField::Model);
        assert!(!m.unwrap().field.requires_vault());
    }

    #[test]
    fn test_vault_round_trip() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault
            .store("anthropic/api_key", b"sk-ant-test-key-123")
            .unwrap();

        let retrieved = vault.retrieve("anthropic/api_key").unwrap();
        assert_eq!(retrieved, b"sk-ant-test-key-123");
    }

    #[test]
    fn test_config_field_requires_vault() {
        assert!(ConfigField::ApiKey.requires_vault());
        assert!(ConfigField::Password.requires_vault());
        assert!(ConfigField::Secret.requires_vault());
        assert!(ConfigField::ConnectionString.requires_vault());

        assert!(!ConfigField::Url.requires_vault());
        assert!(!ConfigField::Model.requires_vault());
        assert!(!ConfigField::Toggle.requires_vault());
        assert!(!ConfigField::Config.requires_vault());
    }

    // ========================================================================
    // Scan tests
    // ========================================================================

    #[test]
    fn test_find_env_template_standard() {
        let dir = std::env::temp_dir().join("zp-scan-test-standard");
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join(".env.example"), "FOO=bar\n").unwrap();

        let found = find_env_template(&dir);
        assert!(found.is_some());
        assert!(found.unwrap().ends_with(".env.example"));

        let _ = fs::remove_file(dir.join(".env.example"));
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_find_env_template_in_subdir() {
        // IronClaw pattern: deploy/env.example
        let dir = std::env::temp_dir().join("zp-scan-test-subdir");
        let deploy = dir.join("deploy");
        let _ = fs::create_dir_all(&deploy);
        fs::write(deploy.join("env.example"), "DB_URL=postgres://\n").unwrap();

        let found = find_env_template(&dir);
        assert!(found.is_some());
        let path = found.unwrap();
        assert!(path.to_string_lossy().contains("deploy"));
        assert!(path.to_string_lossy().contains("env.example"));

        let _ = fs::remove_file(deploy.join("env.example"));
        let _ = fs::remove_dir(&deploy);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_find_env_template_none() {
        let dir = std::env::temp_dir().join("zp-scan-test-empty");
        let _ = fs::create_dir_all(&dir);

        let found = find_env_template(&dir);
        assert!(found.is_none());

        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_analyze_tool_categorizes_vars() {
        let dir = std::env::temp_dir().join("zp-scan-test-analyze");
        let _ = fs::create_dir_all(&dir);

        let template = dir.join(".env.example");
        fs::write(
            &template,
            "\
# API Keys
OPENAI_API_KEY=
ANTHROPIC_API_KEY=sk-ant-placeholder

# Models
LLM_MODEL=gpt-4

# URLs
OLLAMA_SERVER_URL=http://localhost:11434

# Unknown
MY_CUSTOM_THING=whatever
",
        )
        .unwrap();

        let engine = ConfigEngine::new();
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);
        // Put anthropic key in vault so it shows as satisfied
        vault
            .store("anthropic/api_key", b"sk-ant-real-key")
            .unwrap();

        let result = analyze_tool(&dir, &template, &engine, &vault);

        assert_eq!(result.total_vars, 5);
        // ANTHROPIC_API_KEY should be satisfied (in vault)
        assert!(result.satisfied.contains(&"ANTHROPIC_API_KEY".to_string()));
        // OPENAI_API_KEY should be missing (not in vault)
        assert!(result.missing.contains(&"OPENAI_API_KEY".to_string()));
        // OLLAMA_SERVER_URL is a Url field (no vault needed) → defaulted
        assert!(result.defaulted.contains(&"OLLAMA_SERVER_URL".to_string()));
        // MY_CUSTOM_THING is unknown → unrecognized
        assert!(result.unrecognized.contains(&"MY_CUSTOM_THING".to_string()));
        // Both API keys need vault
        assert_eq!(result.vault_vars.len(), 2);

        let _ = fs::remove_file(&template);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_scan_discovers_multiple_tools() {
        let root = std::env::temp_dir().join("zp-scan-test-multi");
        let tool_a = root.join("pentagi-mock");
        let tool_b = root.join("openm-mock");
        let _ = fs::create_dir_all(&tool_a);
        let _ = fs::create_dir_all(&tool_b);

        fs::write(
            tool_a.join(".env.example"),
            "OPENAI_API_KEY=\nLLM_MODEL=gpt-4\n",
        )
        .unwrap();
        fs::write(
            tool_b.join(".env.example"),
            "ANTHROPIC_API_KEY=\nTTS_MODEL=tts-1\n",
        )
        .unwrap();

        let master_key = [0x42u8; 32];
        let vault = CredentialVault::new(&master_key);

        // run_scan prints to stdout — we just verify it returns 0 (success)
        let exit_code = run_scan(&root, &vault, 1);
        assert_eq!(exit_code, 0);

        // Cleanup
        let _ = fs::remove_file(tool_a.join(".env.example"));
        let _ = fs::remove_file(tool_b.join(".env.example"));
        let _ = fs::remove_dir(&tool_a);
        let _ = fs::remove_dir(&tool_b);
        let _ = fs::remove_dir(&root);
    }

    // ========================================================================
    // Auto tests
    // ========================================================================

    /// Permissive policy for tests — allows all vault access.
    fn test_policy(
        _cred: &str,
        _purpose: &str,
        _ctx: &PolicyContext,
    ) -> zp_trust::injector::InjectorResult<()> {
        Ok(())
    }

    #[test]
    fn test_auto_configures_ready_tool() {
        let root = std::env::temp_dir().join("zp-auto-test-ready");
        let tool = root.join("my-tool");
        let _ = fs::create_dir_all(&tool);

        // A simple template — only needs openai key
        fs::write(
            tool.join(".env.example"),
            "\
OPENAI_API_KEY=
LLM_MODEL=gpt-4
OLLAMA_SERVER_URL=http://localhost:11434
",
        )
        .unwrap();

        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);
        vault.store("openai/api_key", b"sk-test-auto-key").unwrap();

        // Run auto in live mode
        let exit_code = run_auto(&root, &vault, test_policy, 1, false, false, None);
        assert_eq!(exit_code, 0);

        // Verify .env was written
        let env_path = tool.join(".env");
        assert!(env_path.exists(), ".env should have been created");
        let content = fs::read_to_string(&env_path).unwrap();
        assert!(
            content.contains("sk-test-auto-key"),
            ".env should contain the resolved key"
        );

        // Cleanup
        let _ = fs::remove_file(env_path);
        let _ = fs::remove_file(tool.join(".env.example"));
        let _ = fs::remove_dir(&tool);
        let _ = fs::remove_dir(&root);
    }

    #[test]
    fn test_auto_skips_missing_credentials() {
        let root = std::env::temp_dir().join("zp-auto-test-skip");
        let tool = root.join("needs-creds");
        let _ = fs::create_dir_all(&tool);

        fs::write(tool.join(".env.example"), "ANTHROPIC_API_KEY=\n").unwrap();

        let master_key = [0x42u8; 32];
        let vault = CredentialVault::new(&master_key); // empty vault

        let exit_code = run_auto(&root, &vault, test_policy, 1, false, false, None);
        assert_eq!(exit_code, 0);

        // .env should NOT have been created
        assert!(
            !tool.join(".env").exists(),
            ".env should not exist for tool with missing creds"
        );

        let _ = fs::remove_file(tool.join(".env.example"));
        let _ = fs::remove_dir(&tool);
        let _ = fs::remove_dir(&root);
    }

    #[test]
    fn test_auto_skips_existing_env_without_overwrite() {
        let root = std::env::temp_dir().join("zp-auto-test-nooverwrite");
        let tool = root.join("has-env");
        let _ = fs::create_dir_all(&tool);

        fs::write(tool.join(".env.example"), "OPENAI_API_KEY=\n").unwrap();
        fs::write(tool.join(".env"), "OPENAI_API_KEY=sk-original-key\n").unwrap();

        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);
        vault.store("openai/api_key", b"sk-new-key").unwrap();

        // Without --overwrite
        let exit_code = run_auto(&root, &vault, test_policy, 1, false, false, None);
        assert_eq!(exit_code, 0);

        // Original .env should be untouched
        let content = fs::read_to_string(tool.join(".env")).unwrap();
        assert!(
            content.contains("sk-original-key"),
            "original .env should be preserved"
        );

        let _ = fs::remove_file(tool.join(".env"));
        let _ = fs::remove_file(tool.join(".env.example"));
        let _ = fs::remove_dir(&tool);
        let _ = fs::remove_dir(&root);
    }

    #[test]
    fn test_auto_overwrites_when_flag_set() {
        let root = std::env::temp_dir().join("zp-auto-test-overwrite");
        let tool = root.join("overwrite-me");
        let _ = fs::create_dir_all(&tool);

        fs::write(tool.join(".env.example"), "OPENAI_API_KEY=\n").unwrap();
        fs::write(tool.join(".env"), "OPENAI_API_KEY=sk-old-key\n").unwrap();

        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);
        vault.store("openai/api_key", b"sk-fresh-key").unwrap();

        // With --overwrite
        let exit_code = run_auto(&root, &vault, test_policy, 1, false, true, None);
        assert_eq!(exit_code, 0);

        // .env should now have the new key
        let content = fs::read_to_string(tool.join(".env")).unwrap();
        assert!(
            content.contains("sk-fresh-key"),
            ".env should contain the new key after overwrite"
        );

        let _ = fs::remove_file(tool.join(".env"));
        let _ = fs::remove_file(tool.join(".env.example"));
        let _ = fs::remove_dir(&tool);
        let _ = fs::remove_dir(&root);
    }

    #[test]
    fn test_auto_dry_run_writes_nothing() {
        let root = std::env::temp_dir().join("zp-auto-test-dryrun");
        let tool = root.join("dry-tool");
        let _ = fs::create_dir_all(&tool);

        fs::write(tool.join(".env.example"), "OPENAI_API_KEY=\n").unwrap();

        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);
        vault.store("openai/api_key", b"sk-dry-key").unwrap();

        let exit_code = run_auto(&root, &vault, test_policy, 1, true, false, None);
        assert_eq!(exit_code, 0);

        // Dry run — no .env should be written
        assert!(
            !tool.join(".env").exists(),
            "dry run should not create .env"
        );

        let _ = fs::remove_file(tool.join(".env.example"));
        let _ = fs::remove_dir(&tool);
        let _ = fs::remove_dir(&root);
    }

    // ========================================================================
    // Proxy mode tests
    // ========================================================================

    #[test]
    fn test_proxy_url_rewriting() {
        let engine = ConfigEngine::with_proxy(3000);

        // Match an OpenAI URL pattern
        let m = engine.match_var("OPENAI_BASE_URL");
        assert!(m.is_some());
        let pattern = m.unwrap();
        assert_eq!(pattern.field, ConfigField::Url);

        // The proxy_url method should rewrite
        let url = engine.proxy_url("openai", "https://api.openai.com/v1");
        assert_eq!(url, "http://localhost:3000/api/v1/proxy/openai/v1");
    }

    #[test]
    fn test_proxy_url_anthropic() {
        let engine = ConfigEngine::with_proxy(4000);
        let url = engine.proxy_url("anthropic", "https://api.anthropic.com");
        assert_eq!(url, "http://localhost:4000/api/v1/proxy/anthropic");
    }

    #[test]
    fn test_no_proxy_preserves_defaults() {
        let engine = ConfigEngine::new();
        let url = engine.proxy_url("openai", "https://api.openai.com/v1");
        assert_eq!(url, "https://api.openai.com/v1");
    }

    #[test]
    fn test_auto_with_proxy_rewrites_urls() {
        let root = std::env::temp_dir().join("zp-auto-test-proxy");
        let tool = root.join("proxy-tool");
        let _ = fs::create_dir_all(&tool);

        fs::write(
            tool.join(".env.example"),
            "\
OPENAI_API_KEY=
OPENAI_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4
",
        )
        .unwrap();

        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);
        vault.store("openai/api_key", b"sk-test-proxy-key").unwrap();

        // Run auto with proxy mode on port 3000
        let exit_code = run_auto(&root, &vault, test_policy, 1, false, false, Some(3000));
        assert_eq!(exit_code, 0);

        // Verify .env was written with proxy URL
        let env_path = tool.join(".env");
        assert!(env_path.exists());
        let content = fs::read_to_string(&env_path).unwrap();
        assert!(
            content.contains("localhost:3000/api/v1/proxy/openai"),
            "URL should be rewritten to proxy"
        );
        assert!(
            content.contains("sk-test-proxy-key"),
            "API key should still be resolved from vault"
        );

        // Cleanup
        let _ = fs::remove_file(env_path);
        let _ = fs::remove_file(tool.join(".env.example"));
        let _ = fs::remove_dir(&tool);
        let _ = fs::remove_dir(&root);
    }
}
