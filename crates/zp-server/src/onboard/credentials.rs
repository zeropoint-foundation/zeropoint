//! Vault store, bulk import, provider catalog, and credential validation.

use super::{OnboardAction, OnboardEvent, OnboardState};
use serde::{Deserialize, Serialize};
use zp_engine::validate::{self, CredentialToValidate, ValidationStatus};

// ============================================================================
// Provider catalog — data-driven, TOML-backed
// ============================================================================

/// Embedded default catalog. Overridden by ~/.zeropoint/config/providers.toml.
const PROVIDERS_DEFAULT_TOML: &str = include_str!("../../assets/providers-default.toml");

/// A known AI/LLM provider loaded from the TOML catalog.
///
/// NOTE: This is a local copy for the onboard module. The canonical type
/// lives in `zp_engine::providers::ProviderProfile`. These must stay in sync.
/// TODO(Phase B): Replace with `use zp_engine::providers::ProviderProfile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderProfile {
    id: String,
    name: String,
    category: String,
    env_patterns: Vec<String>,
    #[serde(default)]
    key_hint: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    key_url: String,
    #[serde(default)]
    docs_url: String,
    #[serde(default)]
    supports_org: bool,
    #[serde(default)]
    source_url: String,
    #[serde(default)]
    last_verified: String,
    #[serde(default)]
    coverage: String,
    // ── MVC fields (Phase A) ─────────────────────────────────
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    openai_compatible: Option<bool>,
    #[serde(default)]
    openai_proxy: Option<bool>,
    #[serde(default)]
    aggregator: Option<bool>,
    #[serde(default)]
    routing: Option<String>,
}

/// Result of scanning the user's environment against the provider catalog.
#[derive(Debug, Clone, Serialize)]
struct DetectedProvider {
    #[serde(flatten)]
    profile: ProviderProfile,
    detected_vars: Vec<String>,
    detected: bool,
}

/// Wrapper for TOML deserialization.
#[derive(Debug, Deserialize)]
struct ProviderCatalogFile {
    #[serde(default)]
    providers: Vec<ProviderProfile>,
}

/// Load the provider catalog: embedded defaults merged with user overrides.
fn load_provider_catalog() -> Vec<ProviderProfile> {
    let mut catalog: Vec<ProviderProfile> =
        toml::from_str::<ProviderCatalogFile>(PROVIDERS_DEFAULT_TOML)
            .map(|f| f.providers)
            .unwrap_or_default();

    let user_path = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(|h| {
            std::path::Path::new(&h)
                .join(".zeropoint")
                .join("config")
                .join("providers.toml")
        });

    if let Some(path) = user_path {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(user_catalog) = toml::from_str::<ProviderCatalogFile>(&content) {
                for user_provider in user_catalog.providers {
                    if let Some(pos) = catalog.iter().position(|p| p.id == user_provider.id) {
                        catalog[pos] = user_provider;
                    } else {
                        catalog.push(user_provider);
                    }
                }
            }
        }
    }

    catalog
}

/// Scan environment variables against the provider catalog.
fn scan_providers(catalog: &[ProviderProfile]) -> Vec<DetectedProvider> {
    let env_vars: std::collections::HashMap<String, String> = std::env::vars().collect();

    let mut results: Vec<DetectedProvider> = catalog
        .iter()
        .map(|profile| {
            let detected_vars: Vec<String> = profile
                .env_patterns
                .iter()
                .filter(|pattern| env_vars.keys().any(|k| k == pattern.as_str()))
                .cloned()
                .collect();

            let detected = !detected_vars.is_empty();

            DetectedProvider {
                profile: profile.clone(),
                detected_vars,
                detected,
            }
        })
        .collect();

    results.sort_by(|a, b| {
        b.detected
            .cmp(&a.detected)
            .then_with(|| a.profile.category.cmp(&b.profile.category))
            .then_with(|| a.profile.name.cmp(&b.profile.name))
    });

    results
}

/// Handle the "get_provider_catalog" action.
///
/// In addition to the catalog itself, this checks the vault for already-stored
/// credentials so the frontend can show checkmarks on cards that are done.
pub async fn handle_get_provider_catalog(state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    events.push(OnboardEvent::terminal("Loading provider catalog..."));

    let catalog = load_provider_catalog();
    let results = scan_providers(&catalog);

    let detected_count = results.iter().filter(|r| r.detected).count();
    let total = results.len();

    // ── Check vault for already-stored credential refs ──────────────
    // This lets the frontend mark cards as "stored" on initial render,
    // even after a WS reconnect or page refresh.
    let mut stored_refs: Vec<String> = Vec::new();
    if let Some(vault_key) = &state.vault_key {
        let vault_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".zeropoint")
            .join("vault.json");

        if vault_path.exists() {
            match zp_trust::CredentialVault::load_or_create(vault_key, &vault_path) {
                Ok(vault) => {
                    stored_refs = vault.list();
                }
                Err(e) => {
                    tracing::warn!("Could not open vault to check stored refs: {}", e);
                }
            }
        }
    }

    events.push(OnboardEvent::terminal(&format!(
        "Catalog: {} providers · {} detected in environment · {} in vault",
        total,
        detected_count,
        stored_refs.len()
    )));

    events.push(OnboardEvent::new(
        "provider_catalog",
        serde_json::json!({
            "providers": results,
            "detected_count": detected_count,
            "total_count": total,
            "stored_refs": stored_refs,
        }),
    ));

    events
}

/// Typed parameters for vault_store action.
/// Phase 2.8 (P2-4): replaces loose `.get().and_then()` extraction.
#[derive(Debug, serde::Deserialize)]
struct VaultStoreParams {
    vault_ref: Option<String>,
    value: Option<String>,
}

/// Store a single credential in the vault.
pub async fn handle_vault_store(
    action: &OnboardAction,
    state: &mut OnboardState,
) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    // Phase 2.8 (P2-4): typed parameter extraction
    let params: VaultStoreParams = serde_json::from_value(action.params.clone())
        .unwrap_or(VaultStoreParams { vault_ref: None, value: None });

    let vault_ref = match params.vault_ref.as_deref() {
        Some(r) => r,
        None => {
            events.push(OnboardEvent::error(
                "vault_store requires 'vault_ref' parameter",
            ));
            return events;
        }
    };

    let value = match params.value.as_deref() {
        Some(v) => v,
        None => {
            events.push(OnboardEvent::error(
                "vault_store requires 'value' parameter",
            ));
            return events;
        }
    };

    // Mask value for display
    let masked = if value.len() > 10 {
        format!("{}••••{}", &value[..6], &value[value.len() - 2..])
    } else {
        "••••••".to_string()
    };

    // Resolve vault key from onboard state (set during Step 3)
    let vault_key = match &state.vault_key {
        Some(k) => *k,
        None => {
            events.push(OnboardEvent::error(
                "Vault key not available — complete Step 3 first",
            ));
            return events;
        }
    };

    // Open (or create) the vault file at ~/.zeropoint/vault.json
    let vault_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint")
        .join("vault.json");

    let mut vault = match zp_trust::CredentialVault::load_or_create(&vault_key, &vault_path) {
        Ok(v) => v,
        Err(e) => {
            events.push(OnboardEvent::error(&format!("Failed to open vault: {}", e)));
            return events;
        }
    };

    // Check if this credential already exists in the vault
    let existing_refs = vault.list();
    let is_replacement = existing_refs.iter().any(|r| r == vault_ref);

    // Encrypt and store the credential
    if let Err(e) = vault.store(vault_ref, value.as_bytes()) {
        events.push(OnboardEvent::error(&format!(
            "Vault encryption failed: {}",
            e
        )));
        return events;
    }

    // Persist to disk
    if let Err(e) = vault.save(&vault_path) {
        events.push(OnboardEvent::error(&format!("Vault save failed: {}", e)));
        return events;
    }

    // Only increment count for genuinely new credentials
    if !is_replacement {
        state.credentials_stored += 1;
    }

    let action_verb = if is_replacement { "Updated" } else { "Stored" };

    events.push(OnboardEvent::terminal(&format!(
        "✓ Encrypted and {}: {} ({})",
        action_verb.to_lowercase(),
        vault_ref,
        masked
    )));

    events.push(OnboardEvent::new(
        "credential_stored",
        serde_json::json!({
            "vault_ref": vault_ref,
            "masked_value": masked,
            "total_stored": state.credentials_stored,
            "replaced": is_replacement,
        }),
    ));

    events
}

/// Bulk-import found plaintext credentials into the vault.
///
/// Uses the same CredentialVault (ChaCha20-Poly1305 encrypted) as individual
/// vault_store, so the formats are always consistent. Previous versions wrote
/// raw JSON which poisoned the vault for subsequent encrypted operations.
pub async fn handle_vault_import_all(
    action: &OnboardAction,
    state: &mut OnboardState,
) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let credentials = match action.params.get("credentials").and_then(|v| v.as_array()) {
        Some(c) => c,
        None => {
            events.push(OnboardEvent::error(
                "vault_import_all requires 'credentials' array",
            ));
            return events;
        }
    };

    // Vault key is required for encrypted storage
    let vault_key = match &state.vault_key {
        Some(k) => *k,
        None => {
            events.push(OnboardEvent::error(
                "Vault key not available — complete Step 3 first",
            ));
            return events;
        }
    };

    let vault_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint")
        .join("vault.json");

    // Open (or create) the encrypted vault — same format as vault_store
    let mut vault = match zp_trust::CredentialVault::load_or_create(&vault_key, &vault_path) {
        Ok(v) => v,
        Err(e) => {
            events.push(OnboardEvent::error(&format!("Failed to open vault: {}", e)));
            return events;
        }
    };

    events.push(OnboardEvent::terminal(&format!(
        "Importing {} credential(s) into vault...",
        credentials.len()
    )));

    let mut stored = 0;
    for cred in credentials {
        let provider = cred
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let var_name = cred
            .get("var_name")
            .and_then(|v| v.as_str())
            .unwrap_or("api_key");
        let value = match cred.get("value").and_then(|v| v.as_str()) {
            Some(v) => v,
            None => continue,
        };

        let vault_ref = format!("{}/{}", provider, var_name.to_lowercase());

        // Mask value for display
        let masked = if value.len() > 8 {
            format!("{}...{}", &value[..4], &value[value.len() - 4..])
        } else {
            "••••••••".to_string()
        };

        // Encrypt and store in the vault (same path as vault_store)
        if let Err(e) = vault.store(&vault_ref, value.as_bytes()) {
            events.push(OnboardEvent::terminal(&format!(
                "  ✗ {} — encryption failed: {}",
                var_name, e
            )));
            continue;
        }

        stored += 1;
        state.credentials_stored += 1;

        events.push(OnboardEvent::new(
            "credential_stored",
            serde_json::json!({
                "vault_ref": vault_ref,
                "provider": provider,
                "var_name": var_name,
                "masked_value": masked,
                "total_stored": state.credentials_stored,
            }),
        ));

        events.push(OnboardEvent::terminal(&format!(
            "  ✓ {} → vault:{}",
            var_name, vault_ref
        )));
    }

    // Persist all encrypted credentials to disk in one atomic write
    if stored > 0 {
        if let Err(e) = vault.save(&vault_path) {
            events.push(OnboardEvent::error(&format!("Vault save failed: {}", e)));
            return events;
        }
    }

    events.push(OnboardEvent::terminal(&format!(
        "\n{} credential(s) secured in vault",
        stored
    )));

    events.push(OnboardEvent::new(
        "import_complete",
        serde_json::json!({
            "imported": stored,
            "total_stored": state.credentials_stored,
        }),
    ));

    events
}

// ============================================================================
// Credential validation — live connection tests
// ============================================================================

/// Validate a single credential immediately after vault storage.
///
/// The frontend sends this right after `vault_store` so the user gets instant
/// feedback on whether their API key is live.
pub async fn handle_validate_credential(
    action: &OnboardAction,
    _state: &mut OnboardState,
) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let provider_id = match action.params.get("provider_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => {
            events.push(OnboardEvent::error(
                "validate_credential requires 'provider_id'",
            ));
            return events;
        }
    };

    let value = match action.params.get("value").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => {
            events.push(OnboardEvent::error("validate_credential requires 'value'"));
            return events;
        }
    };

    let var_name = action
        .params
        .get("var_name")
        .and_then(|v| v.as_str())
        .unwrap_or("api_key")
        .to_string();

    let cred = CredentialToValidate {
        provider_id: provider_id.clone(),
        var_name: var_name.clone(),
        value,
    };

    let report = validate::validate_credentials(&[cred]).await;

    if let Some(result) = report.results.first() {
        let status_str = match &result.status {
            ValidationStatus::Valid => "valid",
            ValidationStatus::Invalid => "invalid",
            ValidationStatus::Unreachable => "unreachable",
            ValidationStatus::Unsupported => "unsupported",
            ValidationStatus::Skipped => "skipped",
        };

        let status_icon = match &result.status {
            ValidationStatus::Valid => "✓",
            ValidationStatus::Invalid => "✗",
            ValidationStatus::Unreachable => "⚠",
            ValidationStatus::Unsupported => "○",
            ValidationStatus::Skipped => "–",
        };

        events.push(OnboardEvent::terminal(&format!(
            "{} {} — {} ({}ms)",
            status_icon, result.provider_name, result.detail, result.latency_ms
        )));

        events.push(OnboardEvent::new(
            "credential_validated",
            serde_json::json!({
                "provider_id": result.provider_id,
                "provider_name": result.provider_name,
                "var_name": result.var_name,
                "status": status_str,
                "detail": result.detail,
                "latency_ms": result.latency_ms,
            }),
        ));
    }

    events
}

/// Validate all credentials currently in the vault.
///
/// Called before the configure step so the user sees a full health dashboard
/// of their stored credentials.
pub async fn handle_validate_all(
    action: &OnboardAction,
    state: &mut OnboardState,
) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    events.push(OnboardEvent::terminal("Running credential health check..."));

    // Open vault and read all stored credentials
    let vault_key = match &state.vault_key {
        Some(k) => *k,
        None => {
            events.push(OnboardEvent::terminal(
                "⚠ Vault key not available — skipping validation",
            ));
            events.push(OnboardEvent::new(
                "validation_sweep",
                serde_json::json!({
                    "results": [],
                    "total": 0, "valid": 0, "invalid": 0,
                    "unreachable": 0, "unsupported": 0,
                    "error": "vault_key_missing",
                }),
            ));
            return events;
        }
    };

    let vault_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint")
        .join("vault.json");

    let vault = match zp_trust::CredentialVault::load_or_create(&vault_key, &vault_path) {
        Ok(v) => v,
        Err(e) => {
            events.push(OnboardEvent::terminal(&format!(
                "⚠ Cannot open vault: {}",
                e
            )));
            events.push(OnboardEvent::new(
                "validation_sweep",
                serde_json::json!({
                    "results": [],
                    "total": 0, "valid": 0, "invalid": 0,
                    "unreachable": 0, "unsupported": 0,
                    "error": "vault_open_failed",
                }),
            ));
            return events;
        }
    };

    // Optional provider filter
    let filter_provider = action
        .params
        .get("provider")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Build credentials list from vault refs
    let refs = vault.list();
    let mut creds: Vec<CredentialToValidate> = Vec::new();

    for vault_ref in &refs {
        // vault_ref format: "provider_id/var_name"
        let parts: Vec<&str> = vault_ref.splitn(2, '/').collect();
        if parts.len() != 2 {
            continue;
        }

        let provider_id = parts[0].to_string();
        let var_name = parts[1].to_string();

        // Apply filter if present
        if let Some(ref filter) = filter_provider {
            if &provider_id != filter {
                continue;
            }
        }

        // Decrypt value
        match vault.retrieve(vault_ref) {
            Ok(bytes) => {
                if let Ok(value) = String::from_utf8(bytes) {
                    creds.push(CredentialToValidate {
                        provider_id,
                        var_name,
                        value,
                    });
                }
            }
            Err(_) => {
                // Can't decrypt — skip
                tracing::warn!("Could not decrypt vault ref: {}", vault_ref);
            }
        }
    }

    if creds.is_empty() {
        events.push(OnboardEvent::terminal(
            "No credentials in vault to validate.",
        ));
        events.push(OnboardEvent::new(
            "validation_sweep",
            serde_json::json!({
                "results": [],
                "total": 0, "valid": 0, "invalid": 0,
                "unreachable": 0, "unsupported": 0,
            }),
        ));
        return events;
    }

    events.push(OnboardEvent::terminal(&format!(
        "Validating {} credential(s)...",
        creds.len()
    )));

    // Run validation
    let report = validate::validate_credentials(&creds).await;

    // Emit terminal lines for each result
    for result in &report.results {
        let icon = match &result.status {
            ValidationStatus::Valid => "✓",
            ValidationStatus::Invalid => "✗",
            ValidationStatus::Unreachable => "⚠",
            ValidationStatus::Unsupported => "○",
            ValidationStatus::Skipped => "–",
        };
        let color_hint = match &result.status {
            ValidationStatus::Valid => "success",
            ValidationStatus::Invalid => "error",
            _ => "warn",
        };

        events.push(OnboardEvent::new("terminal", serde_json::json!({
            "line": format!("  {} {} — {} ({}ms)", icon, result.provider_name, result.detail, result.latency_ms),
            "cls": color_hint,
        })));
    }

    events.push(OnboardEvent::terminal(&format!(
        "\n{} valid · {} invalid · {} unreachable · {} unsupported",
        report.valid, report.invalid, report.unreachable, report.unsupported
    )));

    // Serialize results for the frontend
    let results_json: Vec<serde_json::Value> = report
        .results
        .iter()
        .map(|r| {
            let status_str = match &r.status {
                ValidationStatus::Valid => "valid",
                ValidationStatus::Invalid => "invalid",
                ValidationStatus::Unreachable => "unreachable",
                ValidationStatus::Unsupported => "unsupported",
                ValidationStatus::Skipped => "skipped",
            };
            serde_json::json!({
                "provider_id": r.provider_id,
                "provider_name": r.provider_name,
                "var_name": r.var_name,
                "status": status_str,
                "detail": r.detail,
                "latency_ms": r.latency_ms,
            })
        })
        .collect();

    events.push(OnboardEvent::new(
        "validation_sweep",
        serde_json::json!({
            "results": results_json,
            "total": report.total,
            "valid": report.valid,
            "invalid": report.invalid,
            "unreachable": report.unreachable,
            "unsupported": report.unsupported,
        }),
    ));

    events
}
