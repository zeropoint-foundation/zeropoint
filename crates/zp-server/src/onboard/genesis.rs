//! Genesis ceremony + vault key check.
//!
//! Design principles:
//! 1. Honest — no silent fallback. If a provider fails, the ceremony fails
//!    and tells the user exactly what happened. They choose what to do next.
//! 2. Linear — generate keys → validate provider → enroll → save → record.
//! 3. Coherent — the genesis.json record always reflects what actually happened.
//!    If it says "trezor", the secret is actually gated by a Trezor.

use super::{OnboardAction, OnboardEvent, OnboardState};
use zp_core::paths as zp_paths;

/// Typed parameters for the genesis ceremony action.
/// Phase 2.8 (P2-4): replaces loose `.get().and_then()` extraction.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisParams {
    #[serde(default = "default_operator_name")]
    operator_name: String,
    #[serde(default = "default_sovereignty_mode")]
    sovereignty_mode: String,
}
fn default_operator_name() -> String { "Operator".to_string() }
fn default_sovereignty_mode() -> String { "auto".to_string() }

/// Create Genesis + Operator keys.
pub async fn handle_genesis(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    // Phase 2.8 (P2-4): typed parameter extraction with schema validation.
    // Falls back to defaults if params don't match the schema — backward compatible
    // with existing clients that may send extra fields during onboarding.
    let params: GenesisParams = serde_json::from_value(action.params.clone())
        .unwrap_or(GenesisParams {
            operator_name: default_operator_name(),
            sovereignty_mode: default_sovereignty_mode(),
        });
    let operator_name = params.operator_name.as_str();
    let sovereignty = params.sovereignty_mode.as_str();

    events.push(OnboardEvent::terminal(""));
    events.push(OnboardEvent::terminal("ZeroPoint Genesis"));
    events.push(OnboardEvent::terminal("─────────────────"));

    // ── Step 1: Generate keypair ──────────────────────────────────
    events.push(OnboardEvent::terminal(
        "Generating operator keypair...        ✓ Ed25519",
    ));

    let genesis = zp_keys::hierarchy::GenesisKey::generate(operator_name);
    let operator = zp_keys::hierarchy::OperatorKey::generate(operator_name, &genesis, None);

    // ── Step 2: Seal constitutional bedrock ───────────────────────
    let bedrock_gates = [
        "HarmPrincipleRule:constitutional",
        "SovereigntyRule:constitutional",
        "CatastrophicActionRule:operational",
        "BulkOperationRule:operational",
        "ReputationGateRule:operational",
    ];
    let constitutional_hash = blake3::hash(bedrock_gates.join("\n").as_bytes())
        .to_hex()
        .to_string();

    events.push(OnboardEvent::terminal(
        "Sealing constitutional bedrock...     ✓ 5 gates installed",
    ));

    // ── Step 3: Resolve sovereignty mode ──────────────────────────
    let sovereignty_mode = if sovereignty == "auto" || sovereignty.is_empty() {
        let caps = zp_keys::detect_all_providers();
        // Auto-detect: pick the best CEREMONY-READY provider
        caps.iter()
            .find(|c| c.available && c.mode.is_ceremony_ready() && c.mode.requires_hardware())
            .or_else(|| {
                caps.iter().find(|c| {
                    c.available
                        && c.mode.is_ceremony_ready()
                        && c.mode == zp_keys::SovereigntyMode::LoginPassword
                })
            })
            .or_else(|| {
                caps.iter()
                    .find(|c| c.available && c.mode.is_ceremony_ready())
            })
            .map(|c| c.mode)
            .unwrap_or(zp_keys::SovereigntyMode::FileBased)
    } else {
        zp_keys::SovereigntyMode::from_onboard_str(sovereignty).resolve()
    };

    // ── Step 3b: Validate provider is ceremony-ready ─────────────
    // The ceremony MUST NOT proceed with an unimplemented provider.
    // This is the integrity check — if you can't deliver, don't promise.
    if !sovereignty_mode.is_ceremony_ready() {
        let name = sovereignty_mode.display_name();
        events.push(OnboardEvent::terminal(&format!(
            "✗ {} provider is not yet fully implemented.",
            name
        )));
        events.push(OnboardEvent::terminal(
            "  The Genesis ceremony requires a provider that can store and retrieve",
        ));
        events.push(OnboardEvent::terminal(
            "  your secret. Select a different sovereignty provider to continue.",
        ));
        events.push(OnboardEvent::new(
            "genesis_failed",
            serde_json::json!({
                "reason": "provider_not_implemented",
                "mode": sovereignty_mode.to_string(),
                "display_name": name,
                "message": format!("{} is detection-only. Full implementation coming soon.", name),
            }),
        ));
        return events;
    }

    // ── Step 4: Persist keys ──────────────────────────────────────
    let home = zp_paths::home()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));

    // Check if already initialized (a complete genesis record with operator field)
    let has_genesis = if let Ok(contents) = std::fs::read_to_string(home.join("genesis.json")) {
        serde_json::from_str::<serde_json::Value>(&contents)
            .ok()
            .and_then(|v| v.get("operator").and_then(|o| o.as_str()).map(|_| true))
            .unwrap_or(false)
    } else {
        false
    };
    if has_genesis {
        events.push(OnboardEvent::terminal(""));
        events.push(OnboardEvent::terminal(
            "⚠ ZeroPoint is already initialized.",
        ));
        events.push(OnboardEvent::terminal(
            "  Remove ~/ZeroPoint/ to re-initialize.",
        ));

        if let Ok(genesis_json) = std::fs::read_to_string(home.join("genesis.json")) {
            if let Ok(record) = serde_json::from_str::<serde_json::Value>(&genesis_json) {
                state.genesis_complete = true;
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
                state.step = 3;

                events.push(OnboardEvent::new(
                    "genesis_complete",
                    serde_json::json!({
                        "already_initialized": true,
                        "operator": state.operator_name,
                        "genesis_public_key": state.genesis_public_key,
                        "sovereignty_mode": state.sovereignty_mode,
                    }),
                ));
            }
        }
        return events;
    }

    let keyring = match zp_keys::Keyring::open(home.join("keys")) {
        Ok(k) => k,
        Err(e) => {
            events.push(OnboardEvent::error(&format!(
                "Failed to create keyring: {}",
                e
            )));
            return events;
        }
    };

    // ── Step 5: Enroll + save via sovereignty provider ────────────
    //
    // No silent fallback. The provider either succeeds or the ceremony
    // fails honestly. The user picks another provider if needed.
    let provider = zp_keys::provider_for(sovereignty_mode);

    events.push(OnboardEvent::terminal(&format!(
        "Sealing secret via {} provider...",
        provider.display_name()
    )));

    // Warn the browser that the server may block on an OS dialog or terminal
    // password prompt.  This prevents the "nothing happened" dead state
    // reported in result 028 — the UI can show a spinner or instruction.
    let provider_hint = match sovereignty_mode {
        zp_keys::SovereigntyMode::TouchId => "Touch ID will be requested — look for the biometric prompt",
        zp_keys::SovereigntyMode::WindowsHello => "Windows Hello verification will appear",
        zp_keys::SovereigntyMode::Fingerprint => "Place your finger on the reader when prompted",
        zp_keys::SovereigntyMode::FaceEnroll => "Camera will activate for face enrollment",
        mode if mode.requires_external_device() => "Confirm on your hardware device when prompted",
        _ => "Your system may request permission — check for a dialog or terminal prompt",
    };
    events.push(OnboardEvent::new(
        "awaiting_provider",
        serde_json::json!({
            "mode": sovereignty_mode.to_string(),
            "display_name": sovereignty_mode.display_name(),
            "hint": provider_hint,
        }),
    ));

    // Enrollment (face capture, hardware wallet pairing, etc.)
    if provider.detect().requires_enrollment {
        events.push(OnboardEvent::terminal(&format!(
            "Enrolling {} ...",
            provider.display_name()
        )));
        match provider.enroll() {
            Ok(Some(result)) => {
                events.push(OnboardEvent::terminal(&format!("✓ {}", result.summary)));
            }
            Ok(None) => {} // No enrollment action needed
            Err(e) => {
                events.push(OnboardEvent::terminal(&format!(
                    "✗ {} enrollment failed: {}",
                    provider.display_name(),
                    e
                )));
                events.push(OnboardEvent::new(
                    "genesis_failed",
                    serde_json::json!({
                        "reason": "enrollment_failed",
                        "mode": sovereignty_mode.to_string(),
                        "display_name": sovereignty_mode.display_name(),
                        "error": e.to_string(),
                        "is_transient": e.is_transient(),
                    }),
                ));
                return events;
            }
        }
    }

    // Save the secret via the provider
    let secret_in_credential_store = match provider.save_secret(&genesis.secret_key()) {
        Ok(()) => {
            // Provider owns the Genesis secret (Trezor, biometrics, etc.).
            // Keyring holds the certificate only; the Genesis secret we
            // still have in memory is passed to save_operator below.
            if let Err(e) = keyring.save_genesis(&genesis, false) {
                events.push(OnboardEvent::error(&format!(
                    "Failed to save certificate: {}",
                    e
                )));
                return events;
            }
            sovereignty_mode != zp_keys::SovereigntyMode::FileBased
        }
        Err(e) => {
            // Provider failed. No fallback — be honest about it.
            events.push(OnboardEvent::terminal(&format!(
                "✗ {} failed to store the Genesis secret: {}",
                provider.display_name(),
                e
            )));

            // Provide actionable guidance based on error type
            if e.is_transient() {
                events.push(OnboardEvent::terminal(
                    "  This may be temporary. Check the device and try again.",
                ));
            }
            if e.is_security_concern() {
                events.push(OnboardEvent::terminal(
                    "  ⚠ SECURITY: This may indicate a device mismatch. Verify your hardware.",
                ));
            }

            events.push(OnboardEvent::new(
                "genesis_failed",
                serde_json::json!({
                    "reason": "save_failed",
                    "mode": sovereignty_mode.to_string(),
                    "display_name": sovereignty_mode.display_name(),
                    "error": e.to_string(),
                    "is_transient": e.is_transient(),
                    "is_security_concern": e.is_security_concern(),
                }),
            ));
            return events;
        }
    };

    // Save operator key — pass Genesis secret in memory so the vault key
    // can be derived without this path assuming the credential store owns
    // the root (which it does not in HW-wallet / biometric modes).
    if let Err(e) = keyring.save_operator_with_genesis_secret(&operator, &genesis.secret_key()) {
        events.push(OnboardEvent::error(&format!(
            "Failed to save operator: {}",
            e
        )));
        return events;
    }

    // ── Step 6: Write genesis record ──────────────────────────────
    // This record is the canonical truth. sovereignty_mode reflects
    // what ACTUALLY gates the secret. No hw_fallback, no original_mode.
    let ceremony_timestamp = chrono::Utc::now().to_rfc3339();
    let genesis_pub_hex = hex::encode(genesis.public_key());
    let operator_pub_hex = hex::encode(operator.public_key());

    let genesis_record = serde_json::json!({
        "version": "2.0",
        "timestamp": &ceremony_timestamp,
        "operator": operator_name,
        "genesis_public_key": &genesis_pub_hex,
        "operator_public_key": &operator_pub_hex,
        "constitutional_hash": constitutional_hash,
        "algorithm": "Ed25519",
        "audit_chain": "BLAKE3",
        "sovereignty_mode": sovereignty_mode.to_string(),
        "constitutional_gates": [
            "HarmPrincipleRule",
            "SovereigntyRule",
            "CatastrophicActionRule",
            "BulkOperationRule",
            "ReputationGateRule",
        ],
    });

    let _ = std::fs::create_dir_all(&home);
    let _ = std::fs::create_dir_all(home.join("policies"));
    let _ = std::fs::create_dir_all(home.join("data"));

    // ── Step 6b: Build signed ceremony transcript ─────────────────
    //
    // The transcript is the cryptographic attestation of the ceremony:
    // Ed25519 signature by the Genesis key over BLAKE3 of a canonical
    // serialization of the transcript body. Fields mirror `genesis.json`
    // plus ceremony metadata so `security::assess` can cross-check the
    // unsigned record against it at startup.
    //
    // Ordering invariant (ARTEMIS 035 issue 2):
    // the transcript MUST be durable before `genesis.json` becomes visible.
    // If we crash between
    // the two writes, next startup sees no genesis.json → onboarding
    // re-runs cleanly. The previous implementation wrote genesis.json
    // first and treated transcript failures as non-fatal, which
    // produced the "record exists but signature missing" state 035
    // flagged.
    let provider_caps = provider.capabilities();
    let genesis_fingerprint = blake3::hash(genesis.public_key().as_ref())
        .to_hex()
        .to_string();

    // Collect biometric evidence if the provider supports it (v0.2).
    // This must be done AFTER the save_secret (which triggers the biometric)
    // and BEFORE building the transcript (which includes the evidence).
    let biometric_evidence = provider.biometric_evidence();
    let biometric_evidence_json = biometric_evidence
        .as_ref()
        .map(|e| serde_json::to_value(e).unwrap_or_default())
        .unwrap_or(serde_json::Value::Null);

    let transcript = serde_json::json!({
        "ceremony": "genesis",
        "version": "2.0",
        "timestamp": &ceremony_timestamp,
        "operator": operator_name,
        "sovereignty_mode": sovereignty_mode.to_string(),
        "sovereignty_category": format!("{:?}", sovereignty_mode.category()),
        "provider_capabilities": provider_caps,
        "genesis_public_key": &genesis_pub_hex,
        "genesis_fingerprint": &genesis_fingerprint,
        "operator_public_key": &operator_pub_hex,
        "constitutional_hash": &constitutional_hash,
        "algorithm": "Ed25519",
        "software_version": env!("CARGO_PKG_VERSION"),
        "platform": if cfg!(target_os = "macos") { "macos" }
                    else if cfg!(target_os = "linux") { "linux" }
                    else if cfg!(target_os = "windows") { "windows" }
                    else { "other" },
        // v0.2: Biometric evidence — nonce-challenge proving live biometric
        "biometric_evidence": biometric_evidence_json,
    });

    // Sign over BLAKE3(canonical transcript bytes). serde_json's Map is
    // BTreeMap-backed (no `preserve_order` feature), so `to_vec` emits
    // keys in alphabetical order — deterministic across sign/verify.
    let transcript_bytes = serde_json::to_vec(&transcript).unwrap_or_default();
    let transcript_hash = blake3::hash(&transcript_bytes);
    let transcript_sig_bytes = {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&genesis.secret_key());
        sk.sign(transcript_hash.as_bytes()).to_bytes()
    };

    let signed_transcript = serde_json::json!({
        "transcript": transcript,
        "signature": {
            "algorithm": "Ed25519",
            "hash": "BLAKE3",
            "value": hex::encode(transcript_sig_bytes),
        },
    });

    // Transcript write is now FATAL and atomic. A failure here means the
    // ceremony did not complete — returning early leaves the keyring and
    // provider in whatever state they reached, but ~/ZeroPoint/genesis.json
    // does not exist, so subsequent `zp serve` will offer re-onboarding.
    if let Err(e) = atomic_write_json(
        &home.join("genesis_transcript.json"),
        &signed_transcript,
    ) {
        events.push(OnboardEvent::error(&format!(
            "Failed to write ceremony transcript: {} — ceremony aborted, re-run onboarding",
            e
        )));
        return events;
    }
    events.push(OnboardEvent::terminal(
        "✓ Ceremony transcript signed and saved",
    ));

    // NOW write the canonical record. After this point the security
    // posture check will see the ceremony as complete and verified.
    if let Err(e) = atomic_write_json(&home.join("genesis.json"), &genesis_record) {
        events.push(OnboardEvent::error(&format!(
            "Failed to write genesis record: {}",
            e
        )));
        return events;
    }

    // ── Step 7: Report results ────────────────────────────────────
    let short_pub = &genesis_pub_hex[..8];

    if secret_in_credential_store {
        events.push(OnboardEvent::terminal(
            "✓ genesis record + secret sealed in OS credential store",
        ));
    } else {
        events.push(OnboardEvent::terminal(
            "✓ genesis record + secret written (file fallback)",
        ));
    }

    events.push(OnboardEvent::terminal(""));
    events.push(OnboardEvent::terminal(&format!(
        "Operator identity: {}...",
        short_pub
    )));
    events.push(OnboardEvent::terminal(&format!(
        "Constitutional hash: {}...",
        &constitutional_hash[..6]
    )));

    state.genesis_complete = true;
    state.genesis_public_key = Some(genesis_pub_hex.clone());
    state.operator_name = Some(operator_name.to_string());
    state.sovereignty_mode = Some(sovereignty_mode.to_string());
    state.step = 2;

    events.push(OnboardEvent::new(
        "genesis_complete",
        serde_json::json!({
            "operator": operator_name,
            "genesis_public_key": &genesis_pub_hex,
            "operator_public_key": &operator_pub_hex,
            "constitutional_hash": constitutional_hash,
            "sovereignty_mode": sovereignty_mode.to_string(),
            "secret_in_credential_store": secret_in_credential_store,
            "platform": if cfg!(target_os = "macos") { "macos" } else if cfg!(target_os = "linux") { "linux" } else { "other" },
        }),
    ));

    // Recovery kit for hardware-gated modes.
    if sovereignty_mode.requires_hardware() {
        match zp_keys::recovery::encode_mnemonic(&genesis.secret_key()) {
            Ok(mnemonic) => {
                events.push(OnboardEvent::new(
                    "recovery_kit",
                    serde_json::json!({
                        "words": mnemonic,
                        "word_count": 24,
                        "warning": "Write these down. This screen will not appear again.",
                    }),
                ));
            }
            Err(e) => {
                events.push(OnboardEvent::terminal(&format!(
                    "⚠ Could not generate recovery mnemonic: {}",
                    e
                )));
            }
        }
    }

    events
}

/// Write a JSON value to `path` atomically: serialize pretty, write to a
/// sibling tmp file, then `rename()` into place. On POSIX `rename` within
/// the same directory is atomic, so readers never see a half-written
/// file. Any I/O failure aborts cleanly — the tmp file may be left
/// behind but the target is unchanged.
fn atomic_write_json(path: &std::path::Path, value: &serde_json::Value) -> std::io::Result<()> {
    let body = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Verify vault key derivation.
pub async fn handle_vault_check(state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    events.push(OnboardEvent::terminal("Verifying vault key derivation..."));

    let _home = zp_paths::home()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));

    let keyring = match zp_keys::Keyring::open(zp_paths::keys_dir().unwrap_or_default()) {
        Ok(k) => k,
        Err(e) => {
            events.push(OnboardEvent::error(&format!("Cannot open keyring: {}", e)));
            return events;
        }
    };

    match zp_keys::resolve_vault_key(&keyring) {
        Ok(resolved) => {
            let source_name = match resolved.source {
                zp_keys::VaultKeySource::CredentialStore => "credential store",
                zp_keys::VaultKeySource::LegacyFileMigrated => "file (migrated)",
                zp_keys::VaultKeySource::LegacyEnvVar => "env var (legacy)",
            };
            events.push(OnboardEvent::terminal(&format!(
                "✓ Vault key derived from {}",
                source_name
            )));

            state.vault_key = Some(*resolved.key);
            state.step = 3;
            events.push(OnboardEvent::new(
                "vault_ready",
                serde_json::json!({
                    "source": source_name,
                }),
            ));
        }
        Err(e) => {
            events.push(OnboardEvent::error(&format!(
                "Vault key derivation failed: {}. Run `zp init` first.",
                e
            )));
        }
    }

    events
}

// ===========================================================================
// Post-genesis sovereignty upgrade
// ===========================================================================

/// Upgrade the sovereignty provider for an existing genesis.
///
/// Flow:
/// 1. Load the Genesis secret from the CURRENT provider
/// 2. Enroll + save via the NEW provider
/// 3. Update genesis.json with the new sovereignty_mode
/// 4. Append upgrade record to the genesis transcript
///
/// The old provider's entry is preserved as a fallback until the
/// operator confirms the upgrade works. This is intentional — if the
/// new biometric fails (e.g., face enrollment in bad lighting), they
/// can still access their identity via the old provider.
pub async fn handle_sovereignty_upgrade(
    action: &OnboardAction,
    _state: &mut OnboardState,
) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let new_mode_str = action
        .params
        .get("new_sovereignty_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if new_mode_str.is_empty() {
        events.push(OnboardEvent::error(
            "sovereignty_upgrade requires 'new_sovereignty_mode' parameter",
        ));
        return events;
    }

    let new_mode = zp_keys::SovereigntyMode::from_onboard_str(new_mode_str).resolve();

    events.push(OnboardEvent::terminal(&format!(
        "Upgrading sovereignty to {}...",
        new_mode.display_name()
    )));

    // ── Step 1: Load current genesis record ──────────────────────
    let home = zp_paths::home()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));

    let genesis_path = home.join("genesis.json");
    let genesis_json = match std::fs::read_to_string(&genesis_path) {
        Ok(j) => j,
        Err(e) => {
            events.push(OnboardEvent::error(&format!(
                "No genesis record found: {} — run genesis first",
                e
            )));
            return events;
        }
    };

    let mut genesis_record: serde_json::Value = match serde_json::from_str(&genesis_json) {
        Ok(v) => v,
        Err(e) => {
            events.push(OnboardEvent::error(&format!(
                "Corrupt genesis record: {}",
                e
            )));
            return events;
        }
    };

    let current_mode_str = genesis_record
        .get("sovereignty_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("login_password");
    let current_mode = zp_keys::SovereigntyMode::from_onboard_str(current_mode_str).resolve();

    if current_mode == new_mode {
        events.push(OnboardEvent::terminal(&format!(
            "Already using {} — no upgrade needed",
            new_mode.display_name()
        )));
        return events;
    }

    // ── Step 2: Load secret from current provider ────────────────
    let current_provider = zp_keys::provider_for(current_mode);
    events.push(OnboardEvent::terminal(&format!(
        "Loading secret from current {} provider...",
        current_provider.display_name()
    )));

    let secret = match current_provider.load_secret() {
        Ok(s) => s,
        Err(e) => {
            events.push(OnboardEvent::error(&format!(
                "Cannot load secret from {}: {} — upgrade aborted",
                current_provider.display_name(),
                e
            )));
            return events;
        }
    };

    // ── Step 3: Upgrade to new provider ──────────────────────────
    let new_provider = zp_keys::provider_for(new_mode);

    if !new_mode.is_ceremony_ready() {
        events.push(OnboardEvent::error(&format!(
            "{} is not fully implemented yet — cannot upgrade",
            new_provider.display_name()
        )));
        return events;
    }

    // Warn the browser about incoming biometric/hardware prompt
    events.push(OnboardEvent::new(
        "awaiting_provider",
        serde_json::json!({
            "mode": new_mode.to_string(),
            "display_name": new_mode.display_name(),
            "hint": format!("{} enrollment will begin — follow the prompts", new_mode.display_name()),
        }),
    ));

    match new_provider.upgrade_from(&secret) {
        Ok(result) => {
            if let Some(ref enrollment) = result {
                events.push(OnboardEvent::terminal(&format!(
                    "✓ {}",
                    enrollment.summary
                )));
            }
        }
        Err(e) => {
            events.push(OnboardEvent::error(&format!(
                "{} upgrade failed: {} — your {} access is unchanged",
                new_provider.display_name(),
                e,
                current_provider.display_name()
            )));
            return events;
        }
    }

    // ── Step 4: Update genesis.json ──────────────────────────────
    let upgrade_timestamp = chrono::Utc::now().to_rfc3339();

    // Record previous mode for audit trail
    let previous_modes: Vec<serde_json::Value> = genesis_record
        .get("previous_sovereignty_modes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut updated_modes = previous_modes;
    updated_modes.push(serde_json::json!({
        "mode": current_mode.to_string(),
        "upgraded_at": &upgrade_timestamp,
    }));

    genesis_record["sovereignty_mode"] = serde_json::Value::String(new_mode.to_string());
    genesis_record["previous_sovereignty_modes"] = serde_json::Value::Array(updated_modes);
    genesis_record["last_sovereignty_upgrade"] =
        serde_json::Value::String(upgrade_timestamp.clone());

    // Collect biometric evidence from the new provider
    let biometric_evidence = new_provider.biometric_evidence();

    // ── Step 5: Append upgrade record to transcript ──────────────
    let transcript_path = home.join("genesis_transcript.json");
    let mut transcript_doc: serde_json::Value =
        match std::fs::read_to_string(&transcript_path).and_then(|s| {
            serde_json::from_str(&s)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }) {
            Ok(v) => v,
            Err(e) => {
                events.push(OnboardEvent::error(&format!(
                    "Cannot read transcript: {} — upgrade saved to genesis.json \
                     but transcript not updated",
                    e
                )));
                // Still save genesis.json even if transcript update fails
                let _ = atomic_write_json(&genesis_path, &genesis_record);
                return events;
            }
        };

    let upgrade_record = serde_json::json!({
        "ceremony": "sovereignty_upgrade",
        "version": "1.0",
        "timestamp": &upgrade_timestamp,
        "from_mode": current_mode.to_string(),
        "to_mode": new_mode.to_string(),
        "provider_capabilities": new_provider.capabilities(),
        "biometric_evidence": biometric_evidence
            .as_ref()
            .map(|e| serde_json::to_value(e).unwrap_or_default())
            .unwrap_or(serde_json::Value::Null),
        "software_version": env!("CARGO_PKG_VERSION"),
    });

    let upgrade_bytes = serde_json::to_vec(&upgrade_record).unwrap_or_default();
    let upgrade_hash = blake3::hash(&upgrade_bytes);

    // Append to the transcript as an "upgrades" array
    if let Some(upgrades_arr) = transcript_doc
        .as_object_mut()
        .and_then(|m| {
            m.entry("upgrades")
                .or_insert_with(|| serde_json::Value::Array(Vec::new()))
                .as_array_mut()
        })
    {
        upgrades_arr.push(serde_json::json!({
            "record": upgrade_record,
            "hash": upgrade_hash.to_hex().to_string(),
        }));
    }

    // Write transcript first (ordering invariant)
    if let Err(e) = atomic_write_json(&transcript_path, &transcript_doc) {
        events.push(OnboardEvent::error(&format!(
            "Failed to update transcript: {} — upgrade saved to genesis.json only",
            e
        )));
    }

    // Then write genesis.json
    if let Err(e) = atomic_write_json(&genesis_path, &genesis_record) {
        events.push(OnboardEvent::error(&format!(
            "Failed to update genesis.json: {}",
            e
        )));
        return events;
    }

    events.push(OnboardEvent::terminal(&format!(
        "✓ Sovereignty upgraded: {} → {}",
        current_mode.display_name(),
        new_mode.display_name()
    )));
    events.push(OnboardEvent::terminal(
        "  Previous provider entry preserved as fallback. Run `zp doctor` to verify.",
    ));

    events.push(OnboardEvent::new(
        "sovereignty_upgraded",
        serde_json::json!({
            "from_mode": current_mode.to_string(),
            "to_mode": new_mode.to_string(),
            "timestamp": &upgrade_timestamp,
            "has_biometric_evidence": biometric_evidence.is_some(),
        }),
    ));

    events
}
