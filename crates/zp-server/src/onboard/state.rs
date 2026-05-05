//! Onboard session state — tracks progress through the 8-step flow.

use serde::Serialize;
use zp_core::paths as zp_paths;

/// Tracks the onboard session state so reconnects can resume.
#[derive(Debug, Clone, Serialize, Default)]
pub struct OnboardState {
    /// Current step (0-8)
    pub step: u8,
    /// Platform detection result
    pub platform_detected: bool,
    /// Selected sovereignty mode
    pub sovereignty_mode: Option<String>,
    /// Genesis ceremony complete
    pub genesis_complete: bool,
    /// Genesis public key (hex)
    pub genesis_public_key: Option<String>,
    /// Operator name
    pub operator_name: Option<String>,
    /// Vault master key (resolved during Step 3, zeroized on drop)
    #[serde(skip)]
    pub vault_key: Option<[u8; 32]>,
    /// Inference posture: "local", "cloud", or "mixed"
    pub inference_posture: Option<String>,
    /// Whether any local inference runtime was detected
    pub local_inference_available: bool,
    /// Path used in Step 5 scan (retained for configure)
    pub scan_path: Option<String>,
    /// Number of tools discovered
    pub tools_discovered: usize,
    /// Number of credentials stored
    pub credentials_stored: usize,
    /// Number of tools configured
    pub tools_configured: usize,
}

impl OnboardState {
    /// Reconstruct state from filesystem reality.
    ///
    /// Probes ~/ZeroPoint/ for genesis, vault, configured tools,
    /// and inference posture. Returns the furthest step the user
    /// has actually completed.
    ///
    /// If `cached_vault_key` is provided (from AppState), uses it instead
    /// of hitting the OS Keychain again. This eliminates repeated macOS
    /// Keychain prompts during the session.
    /// Convenience wrapper — resolves vault key from keychain (may prompt on macOS).
    pub fn from_filesystem() -> Self {
        Self::from_filesystem_with_vault(None)
    }

    pub fn from_filesystem_with_vault(cached_vault_key: Option<&[u8; 32]>) -> Self {
        let mut state = Self::default();
        let home = match zp_paths::home() {
            Ok(h) => h,
            Err(_) => return state,
        };

        // ── Genesis ──
        let genesis_path = home.join("genesis.json");
        if genesis_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&genesis_path) {
                if let Ok(record) = serde_json::from_str::<serde_json::Value>(&content) {
                    state.genesis_complete = true;
                    state.platform_detected = true;
                    state.genesis_public_key = record
                        .get("genesis_public_key")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    state.operator_name = record
                        .get("operator")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    state.sovereignty_mode = record
                        .get("sovereignty_mode")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    state.step = 3; // Past genesis
                }
            }

            // Use cached vault key from AppState (resolved once at startup).
            // Falls back to keychain only if no cache was provided.
            if let Some(key) = cached_vault_key {
                state.vault_key = Some(*key);
            } else if let Ok(keyring) = zp_keys::Keyring::open(zp_paths::keys_dir().unwrap_or_default()) {
                if let Ok(resolved) = zp_keys::resolve_vault_key(&keyring) {
                    state.vault_key = Some(*resolved.key);
                }
            }
        }

        // ── Vault ──
        // Only count vault credentials when genesis exists — they're
        // encrypted with a key derived from the genesis secret, so
        // they're meaningless (and misleading) without one.
        let vault_path = home.join("vault.json");
        if state.genesis_complete && vault_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&vault_path) {
                if let Ok(vault) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(obj) = vault.as_object() {
                        state.credentials_stored = obj.len();
                        if state.credentials_stored > 0 {
                            state.step = state.step.max(6);
                        }
                    }
                }
            }
        }

        // ── Inference posture ──
        let inference_path = home.join("config").join("inference.toml");
        if inference_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&inference_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with("posture") {
                        if let Some(val) = line.split('=').nth(1) {
                            let val = val.trim().trim_matches('"').trim_matches('\'');
                            state.inference_posture = Some(val.to_string());
                            state.step = state.step.max(4);
                        }
                    }
                }
            }
        } else if state.genesis_complete {
            // If genesis exists but no inference config, default to mixed
            state.inference_posture = Some("mixed".to_string());
        }

        // ── Scan path + tools discovery ──
        // Check default scan path for tools
        let scan_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("projects");

        if scan_path.exists() && state.genesis_complete {
            let mut tool_count = 0;

            if let Ok(entries) = std::fs::read_dir(&scan_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_dir() {
                        continue;
                    }
                    if path.join(".env.example").exists() {
                        tool_count += 1;
                    }
                }
            }

            if tool_count > 0 {
                state.scan_path = Some("~/projects".to_string());
                state.tools_discovered = tool_count;
            }
        }

        // ── Cap step based on what's actually ready ──
        // Don't jump past scan/credentials if vault is empty.
        // The scan must run to discover plaintext credentials
        // before configure can do anything useful.
        if state.genesis_complete && state.credentials_stored == 0 {
            state.step = state.step.min(5); // Land at scan step
        }

        // Detect local inference availability
        state.local_inference_available = which::which("ollama").is_ok();

        state
    }
}
