//! `zp init` — bootstrap a new ZeroPoint environment.
//!
//! Generates the operator keypair, seals the constitutional bedrock,
//! writes the genesis record and zeropoint.toml. This is the first
//! command a developer runs.

use std::path::PathBuf;

use chrono::Utc;
use zp_keys::hierarchy::{GenesisKey, OperatorKey};
use zp_keys::keyring::Keyring;
use zp_keys::recovery;
use zp_keys::sovereignty::SovereigntyMode;

use crate::commands::resolve_zp_home;

/// Configuration for `zp init`.
pub struct InitConfig {
    /// Operator name / subject for the certificate.
    pub operator_name: String,
    /// Directory to initialize in (defaults to current dir).
    pub project_dir: PathBuf,
    /// Whether to store the genesis secret key (default: true for dev).
    pub store_genesis_secret: bool,
    /// How the genesis secret is gated (biometric / login password / file).
    pub sovereignty_mode: SovereigntyMode,
}

/// Run the init command.
pub fn run(config: &InitConfig) -> i32 {
    let zp_dir = config.project_dir.join(".zeropoint");
    let toml_path = config.project_dir.join("zeropoint.toml");

    // The keyring always lives at ~/.zeropoint/keys/ (home directory),
    // consistent with `zp keys`, `zp secure`, `zp guard`, and `zp policy`.
    // The project-local .zeropoint/ holds config, policies, and data only.

    // ── Guard: don't re-init ────────────────────────────────────
    // Check both the certificate file AND the credential store. A previous
    // `zp init` that succeeded fully will have both; a partial init might
    // have only the credential store entry or only the file.
    let home_zp = resolve_zp_home();
    let has_genesis_cert = home_zp.join("keys").join("genesis.json").exists();
    let has_genesis_secret = {
        let kr = Keyring::open(home_zp.join("keys")).ok();
        kr.is_some_and(|k| k.status().has_genesis_secret)
    };
    if has_genesis_cert || has_genesis_secret {
        eprintln!();
        eprintln!("  ZeroPoint is already initialized.");
        eprintln!("  Keyring: {}", home_zp.join("keys").display());
        eprintln!();
        eprintln!("  Remove ~/.zeropoint/ to re-initialize (this destroys all keys).");
        if has_genesis_secret && !has_genesis_cert {
            eprintln!(
                "  Note: Genesis secret found in credential store but genesis.json is missing."
            );
            eprintln!("  Run `zp init --force` to repair, or clear with `zp keys clear`.");
        }
        eprintln!();
        return 1;
    }

    // ── Banner ──────────────────────────────────────────────────
    eprintln!();
    eprintln!("  \x1b[1mZeroPoint Genesis\x1b[0m");
    eprintln!("  \x1b[2m─────────────────\x1b[0m");
    eprintln!();
    eprintln!("  \x1b[2mYou are creating your own cryptographic root of trust.\x1b[0m");
    eprintln!("  \x1b[2mNo accounts. No platforms. No one else holds your keys.\x1b[0m");
    eprintln!();

    // ── Step 1: Generate keypair ────────────────────────────────
    eprint!("  Generating operator keypair...        ");
    let genesis = GenesisKey::generate(&config.operator_name);
    let operator = OperatorKey::generate(&config.operator_name, &genesis, None);
    eprintln!("\x1b[32m✓\x1b[0m Ed25519");

    // ── Step 2: Seal constitutional bedrock ─────────────────────
    eprint!("  Sealing constitutional bedrock...     ");
    let constitutional_hash = seal_bedrock();
    eprintln!("\x1b[32m✓\x1b[0m 5 gates installed");

    // ── Step 3: Persist keys to ~/.zeropoint/keys/ ──────────────
    let keyring = match Keyring::open(home_zp.join("keys")) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("  \x1b[31m✗\x1b[0m Failed to create keyring: {}", e);
            return 1;
        }
    };

    // Tell the user what's about to happen BEFORE the OS dialog appears.
    if config.store_genesis_secret {
        let provider = zp_keys::provider_for(config.sovereignty_mode);
        eprintln!();
        eprintln!(
            "  \x1b[1mSovereignty: {}\x1b[0m",
            provider.display_name()
        );
        match config.sovereignty_mode {
            SovereigntyMode::TouchId => {
                eprintln!("  Your body is the credential — no password, no token, just you.");
                eprintln!("  The Genesis secret will be sealed in the Secure Enclave.");
                eprintln!();
                eprintln!("  \x1b[36m→ Place your finger on the sensor when prompted.\x1b[0m");
            }
            SovereigntyMode::WindowsHello => {
                eprintln!("  Your identity, verified locally through your own hardware.");
                eprintln!("  The Genesis secret will be locked in the TPM.");
                eprintln!();
                eprintln!("  \x1b[36m→ Verify with Windows Hello when prompted.\x1b[0m");
            }
            SovereigntyMode::Fingerprint => {
                eprintln!("  Physical presence required — your fingerprint gates every operation.");
                eprintln!();
                eprintln!("  \x1b[36m→ Place your finger on the reader when prompted.\x1b[0m");
            }
            SovereigntyMode::FaceEnroll => {
                eprintln!("  Your face becomes the key. A compact local template — no images stored,");
                eprintln!("  no cloud, no third party ever sees it.");
                eprintln!();
                eprintln!("  \x1b[36m→ Look at the webcam when it activates.\x1b[0m");
            }
            SovereigntyMode::LoginPassword => {
                eprintln!("  Your OS credential store guards the Genesis secret.");
                eprintln!("  \x1b[2mYou can upgrade to biometric or hardware wallet later\x1b[0m");
                eprintln!("  \x1b[2mwithout re-keying.\x1b[0m");
                if cfg!(target_os = "macos") {
                    eprintln!();
                    eprintln!("  \x1b[36m→ Click Allow if macOS requests keychain access.\x1b[0m");
                }
            }
            mode if mode.requires_external_device() => {
                eprintln!(
                    "  Your {} holds the key. The secret never touches software —",
                    mode.display_name()
                );
                eprintln!("  it's derived directly from the hardware.");
                eprintln!();
                eprintln!(
                    "  \x1b[36m→ Ensure your {} is connected via USB.\x1b[0m",
                    mode.display_name()
                );
            }
            _ => {}
        }
        eprintln!();
    } else {
        eprint!("  Writing genesis record...             ");
    }

    // Save genesis key with sovereignty-mode-aware storage via provider system.
    // Track actual_mode so genesis record reflects what actually happened after any fallback.
    let (secret_in_credential_store, actual_mode) = if config.store_genesis_secret {
        let provider = zp_keys::provider_for(config.sovereignty_mode);
        let mut enrollment_failed = false;

        // Run enrollment if needed (face capture, hardware wallet pairing, etc.)
        if provider.detect().requires_enrollment {
            if let Err(e) = provider.enroll() {
                eprintln!(
                    "  \x1b[33m⚠\x1b[0m {} enrollment failed: {}",
                    provider.display_name(),
                    e
                );
                eprintln!("  Falling back to login password mode...");
                enrollment_failed = true;
            }
        }

        if enrollment_failed {
            // Fall back to login password
            match keyring.save_genesis(&genesis, true) {
                Ok(in_cred) => (in_cred, SovereigntyMode::LoginPassword),
                Err(e2) => {
                    eprintln!("  \x1b[31m✗\x1b[0m Failed to save genesis key: {}", e2);
                    return 1;
                }
            }
        } else {
            // Save secret through the provider
            match provider.save_secret(&genesis.secret_key()) {
                Ok(()) => {
                    // The provider already stored the secret (HW wallet,
                    // biometric enclave, FileBased chmod-600 file, etc.).
                    // Keyring holds only the certificate; the Genesis secret
                    // we still have in memory is passed to save_operator
                    // explicitly below to derive the vault key.
                    if let Err(e) = keyring.save_genesis(&genesis, false) {
                        eprintln!(
                            "  \x1b[31m✗\x1b[0m Failed to save genesis certificate: {}",
                            e
                        );
                        return 1;
                    }
                    (
                        config.sovereignty_mode != SovereigntyMode::FileBased,
                        config.sovereignty_mode,
                    )
                }
                Err(e) => {
                    eprintln!(
                        "  \x1b[33m⚠\x1b[0m {} save failed: {}",
                        provider.display_name(),
                        e
                    );
                    eprintln!("  Falling back to login password mode...");
                    match keyring.save_genesis(&genesis, true) {
                        Ok(in_cred) => (in_cred, SovereigntyMode::LoginPassword),
                        Err(e2) => {
                            eprintln!("  \x1b[31m✗\x1b[0m Failed to save genesis key: {}", e2);
                            return 1;
                        }
                    }
                }
            }
        }
    } else {
        match keyring.save_genesis(&genesis, false) {
            Ok(in_cred_store) => (in_cred_store, config.sovereignty_mode),
            Err(e) => {
                eprintln!("  \x1b[31m✗\x1b[0m Failed to save genesis key: {}", e);
                return 1;
            }
        }
    };
    // Canon save: pass the Genesis secret we still have in memory so the
    // operator secret can be vaulted under a derived key — works across
    // every sovereignty provider (Keychain, Touch ID, Trezor, biometrics,
    // FileBased) without the keyring having to know which one owns root.
    if let Err(e) = keyring.save_operator_with_genesis_secret(&operator, &genesis.secret_key()) {
        eprintln!("\x1b[31m✗\x1b[0m");
        eprintln!("  Failed to save operator key: {}", e);
        return 1;
    }

    // Write genesis record to ~/.zeropoint/genesis.json
    let genesis_record = serde_json::json!({
        "version": "2.0",
        "timestamp": Utc::now().to_rfc3339(),
        "operator": config.operator_name,
        "genesis_public_key": hex::encode(genesis.public_key()),
        "operator_public_key": hex::encode(operator.public_key()),
        "constitutional_hash": constitutional_hash,
        "algorithm": "Ed25519",
        "audit_chain": "BLAKE3",
        "sovereignty_mode": actual_mode.to_string(),
        "constitutional_gates": [
            "HarmPrincipleRule",
            "SovereigntyRule",
            "CatastrophicActionRule",
            "BulkOperationRule",
            "ReputationGateRule",
        ],
    });

    let genesis_path = home_zp.join("genesis.json");
    if let Err(e) = std::fs::write(
        &genesis_path,
        serde_json::to_string_pretty(&genesis_record).unwrap(),
    ) {
        eprintln!("\x1b[31m✗\x1b[0m");
        eprintln!("  Failed to write genesis record: {}", e);
        return 1;
    }

    // Create home-level directories for policies and data
    let _ = std::fs::create_dir_all(home_zp.join("policies"));
    let _ = std::fs::create_dir_all(home_zp.join("data"));

    // Also create project-local .zeropoint/ for config and project-specific overrides
    let _ = std::fs::create_dir_all(zp_dir.join("policies"));
    let _ = std::fs::create_dir_all(zp_dir.join("data"));

    if secret_in_credential_store {
        eprintln!("\x1b[32m✓\x1b[0m genesis record + secret sealed in OS credential store");
    } else if config.store_genesis_secret {
        eprintln!("\x1b[32m✓\x1b[0m genesis record + secret written (file fallback)");
    } else {
        eprintln!("\x1b[32m✓\x1b[0m genesis record written (certificate only)");
    }

    // ── Step 4: Write zeropoint.toml ────────────────────────────
    if !toml_path.exists() {
        let toml_content = format!(
            r#"# ZeroPoint configuration
# Generated by `zp init` on {}

[server]
bind = "127.0.0.1"
port = 3000

[identity]
operator = "{}"
key_path = "~/.zeropoint/keys"
# How the genesis secret is gated: "biometric", "login_password", or "file_based"
sovereignty_mode = "{}"

[policy]
# Custom WASM gates, evaluated after constitutional bedrock.
# Add .wasm files to .zeropoint/policies/ and list them here.
gates = []

[audit]
data_dir = ".zeropoint/data"
"#,
            Utc::now().format("%Y-%m-%d"),
            config.operator_name,
            config.sovereignty_mode,
        );
        let _ = std::fs::write(&toml_path, toml_content);
    }

    // ── Summary ─────────────────────────────────────────────────
    let genesis_pub = hex::encode(genesis.public_key());
    let short_pub = &genesis_pub[..8];

    eprintln!();
    eprintln!("  \x1b[1mGenesis Complete\x1b[0m");
    eprintln!("  \x1b[2m────────────────\x1b[0m");
    eprintln!("  Operator identity: \x1b[36m{}...\x1b[0m", short_pub);
    eprintln!(
        "  Constitutional hash: \x1b[36m{}...\x1b[0m",
        &constitutional_hash[..6]
    );
    eprintln!();
    if secret_in_credential_store {
        let store_name = if cfg!(target_os = "macos") {
            "macOS Keychain"
        } else if cfg!(target_os = "linux") {
            "Secret Service"
        } else if cfg!(target_os = "windows") {
            "Windows Credential Manager"
        } else {
            "OS credential store"
        };
        eprintln!(
            "  \x1b[32m✓\x1b[0m Genesis secret sealed in {}.",
            store_name,
        );
        eprintln!(
            "  \x1b[32m✓\x1b[0m Gated by {} — your sovereignty boundary.",
            actual_mode.display_name()
        );
        if actual_mode != SovereigntyMode::FileBased {
            eprintln!(
                "  \x1b[32m✓\x1b[0m No secret key files on disk. {} required for vault access.",
                actual_mode.display_name()
            );
        }
    } else if config.store_genesis_secret {
        if actual_mode == SovereigntyMode::FileBased {
            eprintln!("  Genesis secret stored in ~/.zeropoint/keys/genesis.secret");
            eprintln!("  \x1b[2mFor production use, consider biometric or hardware wallet sovereignty.\x1b[0m");
        } else {
            eprintln!(
                "  \x1b[33mNote:\x1b[0m Genesis secret stored in ~/.zeropoint/keys/genesis.secret"
            );
            eprintln!("  (OS credential store unavailable — will auto-migrate when available)");
        }
    }

    // ── Recovery kit (hardware-gated modes) ─────────────────────
    if actual_mode.requires_hardware() && config.store_genesis_secret {
        match recovery::encode_mnemonic(&genesis.secret_key()) {
            Ok(mnemonic) => {
                eprintln!();
                eprintln!("  \x1b[1;33m┌─ Recovery Kit ──────────────────────────────────────────┐\x1b[0m");
                eprintln!("  \x1b[33m│\x1b[0m                                                        \x1b[33m│\x1b[0m");
                eprintln!("  \x1b[33m│\x1b[0m  Write down these 24 words. Store them offline.         \x1b[33m│\x1b[0m");
                eprintln!("  \x1b[33m│\x1b[0m  This screen will not appear again.                     \x1b[33m│\x1b[0m");
                eprintln!("  \x1b[33m│\x1b[0m                                                        \x1b[33m│\x1b[0m");
                for row in 0..6 {
                    let i = row * 4;
                    eprintln!(
                        "  \x1b[33m│\x1b[0m  {:>2}. {:<12} {:>2}. {:<12} {:>2}. {:<12} {:>2}. {:<12}\x1b[33m│\x1b[0m",
                        i + 1, mnemonic[i],
                        i + 2, mnemonic[i + 1],
                        i + 3, mnemonic[i + 2],
                        i + 4, mnemonic[i + 3],
                    );
                }
                eprintln!("  \x1b[33m│\x1b[0m                                                        \x1b[33m│\x1b[0m");
                eprintln!("  \x1b[33m│\x1b[0m  These words ARE your Genesis secret.                   \x1b[33m│\x1b[0m");
                eprintln!("  \x1b[33m│\x1b[0m  Recovery: `zp recover --biometric-reset`                \x1b[33m│\x1b[0m");
                eprintln!(
                    "  \x1b[1;33m└────────────────────────────────────────────────────────┘\x1b[0m"
                );
            }
            Err(e) => {
                eprintln!(
                    "  \x1b[33m⚠\x1b[0m Could not generate recovery mnemonic: {}",
                    e
                );
                eprintln!("  You can generate it later with `zp keys recovery-kit`");
            }
        }
    }

    eprintln!();
    eprintln!("  Sovereignty mode: \x1b[1m{}\x1b[0m", actual_mode.display_name());
    if actual_mode.requires_hardware() || actual_mode == SovereigntyMode::TouchId {
        eprintln!("  \x1b[2mYour keys, your hardware, your rules. No institution mediates.\x1b[0m");
    }
    eprintln!();
    eprintln!("  Next: \x1b[1m`zp onboard`\x1b[0m to set up your AI tools.");
    eprintln!();

    0
}

/// Compute a deterministic hash of the constitutional gate set.
///
/// This is a BLAKE3 hash of the canonical gate names, providing a
/// fingerprint that proves which bedrock rules were active at genesis.
fn seal_bedrock() -> String {
    let gates = [
        "HarmPrincipleRule:constitutional",
        "SovereigntyRule:constitutional",
        "CatastrophicActionRule:operational",
        "BulkOperationRule:operational",
        "ReputationGateRule:operational",
    ];
    let content = gates.join("\n");
    let hash = blake3::hash(content.as_bytes());
    hash.to_hex().to_string()
}
