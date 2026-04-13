//! Genesis ceremony + vault key check.
//!
//! Design principles:
//! 1. Honest — no silent fallback. If a provider fails, the ceremony fails
//!    and tells the user exactly what happened. They choose what to do next.
//! 2. Linear — generate keys → validate provider → enroll → save → record.
//! 3. Coherent — the genesis.json record always reflects what actually happened.
//!    If it says "trezor", the secret is actually gated by a Trezor.

use super::{OnboardAction, OnboardEvent, OnboardState};

/// Create Genesis + Operator keys.
pub async fn handle_genesis(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    // Extract parameters
    let operator_name = action
        .params
        .get("operator_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Operator");
    let sovereignty = action
        .params
        .get("sovereignty_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");

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
    let home = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint");

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
            "  Remove ~/.zeropoint/ to re-initialize.",
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

    if let Err(e) = std::fs::write(
        home.join("genesis.json"),
        serde_json::to_string_pretty(&genesis_record).unwrap(),
    ) {
        events.push(OnboardEvent::error(&format!(
            "Failed to write genesis record: {}",
            e
        )));
        return events;
    }

    // ── Step 6b: Write ceremony transcript ───────────────────────
    // A signed, immutable record of the Genesis ceremony for audit.
    // This captures everything needed to verify the ceremony happened
    // correctly: who, when, what provider, what capabilities, and the
    // resulting public key fingerprint. Signed by the Genesis key itself
    // to prove the transcript was created by the same ceremony.
    let provider_caps = provider.capabilities();
    let genesis_fingerprint = blake3::hash(genesis.public_key().as_ref())
        .to_hex()
        .to_string();

    let transcript = serde_json::json!({
        "ceremony": "genesis",
        "version": "1.0",
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
    });

    // Sign the transcript with the Genesis key for tamper evidence
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

    if let Err(e) = std::fs::write(
        home.join("genesis_transcript.json"),
        serde_json::to_string_pretty(&signed_transcript).unwrap(),
    ) {
        // Non-fatal — the ceremony itself succeeded even if transcript fails
        tracing::warn!("Failed to write ceremony transcript: {}", e);
        events.push(OnboardEvent::terminal(&format!(
            "⚠ Could not save ceremony transcript: {}",
            e
        )));
    } else {
        events.push(OnboardEvent::terminal(
            "✓ Ceremony transcript signed and saved",
        ));
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

/// Verify vault key derivation.
pub async fn handle_vault_check(state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    events.push(OnboardEvent::terminal("Verifying vault key derivation..."));

    let home = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint");

    let keyring = match zp_keys::Keyring::open(home.join("keys")) {
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
