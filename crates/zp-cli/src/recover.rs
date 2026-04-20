//! `zp recover` — restore a Genesis identity from its 24-word BIP-39 mnemonic.
//!
//! This is the nuclear recovery path: when the OS credential store is lost
//! (Keychain wiped, migrated machine, factory reset), the 24 words from the
//! genesis ceremony can reconstruct the full identity.
//!
//! Flow:
//! 1. Read 24 words from stdin (interactive prompt)
//! 2. Load genesis certificate from ~/ZeroPoint/keys/genesis.json
//! 3. Decode mnemonic → 32-byte secret
//! 4. Verify the derived Ed25519 public key matches the certificate
//! 5. Re-seal the genesis secret into the OS credential store
//! 6. Verify operator key can be unlocked (if operator.secret.enc exists)
//! 7. Report success

use std::io::{self, BufRead, Write};

use crate::commands::resolve_zp_home;

/// Run the recover command.
///
/// Returns 0 on success, 1 on failure.
pub fn run() -> i32 {
    let home = resolve_zp_home();
    let keys_dir = home.join("keys");

    // ── Pre-flight checks ────────────────────────────────────────
    let genesis_cert_path = keys_dir.join("genesis.json");
    if !genesis_cert_path.exists() {
        eprintln!(
            "  \x1b[31m✗\x1b[0m No genesis.json found at {}",
            genesis_cert_path.display()
        );
        eprintln!("  Recovery requires an existing genesis certificate on disk.");
        eprintln!("  If this is a fresh machine, copy genesis.json from a backup first.");
        return 1;
    }

    let keyring = match zp_keys::keyring::Keyring::open(&keys_dir) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("  \x1b[31m✗\x1b[0m Cannot open keyring: {}", e);
            return 1;
        }
    };

    // ── Load the genesis public key ──────────────────────────────
    let cert = match keyring.load_genesis_certificate() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  \x1b[31m✗\x1b[0m Cannot load genesis certificate: {}", e);
            return 1;
        }
    };

    let pubkey_hex = &cert.body.public_key;
    let pubkey_bytes: [u8; 32] = match hex::decode(pubkey_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            eprintln!("  \x1b[31m✗\x1b[0m Genesis certificate has invalid public key hex");
            return 1;
        }
    };
    let expected_pubkey = match ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("  \x1b[31m✗\x1b[0m Genesis certificate has invalid Ed25519 public key: {}", e);
            return 1;
        }
    };

    eprintln!();
    eprintln!("  \x1b[1mZeroPoint Identity Recovery\x1b[0m");
    eprintln!();
    eprintln!("  Genesis public key: {}…", &pubkey_hex[..16]);
    eprintln!();
    eprintln!("  Enter your 24-word recovery mnemonic.");
    eprintln!("  Words can be space-separated on one line, or one per line.");
    eprintln!("  Press Enter on a blank line (or Ctrl-D) when done.");
    eprintln!();

    // ── Read mnemonic from stdin ─────────────────────────────────
    let words = match read_mnemonic() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("  \x1b[31m✗\x1b[0m {}", e);
            return 1;
        }
    };

    if words.len() != 24 {
        eprintln!(
            "  \x1b[31m✗\x1b[0m Expected 24 words, got {}. Check your mnemonic.",
            words.len()
        );
        return 1;
    }

    // ── Verify mnemonic against genesis public key ───────────────
    // Verify BEFORE prompting for overwrite — reject wrong words early
    // so piped input works and users don't confirm an action that will
    // fail anyway.
    eprint!("  Verifying mnemonic… ");
    let secret = match zp_keys::verify_recovery(&words, &expected_pubkey) {
        Ok(s) => {
            eprintln!("\x1b[32m✓\x1b[0m match");
            s
        }
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m");
            eprintln!();
            eprintln!("  {}", e);
            eprintln!();
            eprintln!("  The mnemonic does not produce the expected genesis keypair.");
            eprintln!("  Check for typos or confirm you have the right recovery kit.");
            return 1;
        }
    };

    // ── Confirm overwrite if credential store already has a secret ─
    let status = keyring.status();
    if status.has_genesis_secret {
        eprintln!();
        eprintln!("  \x1b[33m⚠\x1b[0m Genesis secret is already present in the credential store.");
        eprint!("  Overwrite with the recovered secret? [y/N] ");
        let _ = io::stdout().flush();
        let mut answer = String::new();
        if io::stdin().lock().read_line(&mut answer).is_err() || !answer.trim().eq_ignore_ascii_case("y") {
            eprintln!("  Aborted. The credential store was not modified.");
            return 0;
        }
    }

    // ── Re-seal genesis secret to credential store ───────────────
    eprint!("  Sealing genesis secret to credential store… ");

    // Build a GenesisKey from parts so we can use save_genesis
    let genesis_key = match zp_keys::GenesisKey::from_parts(secret, cert) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m");
            eprintln!("  Failed to reconstruct genesis key: {}", e);
            return 1;
        }
    };

    match keyring.save_genesis(&genesis_key, true) {
        Ok(_) => eprintln!("\x1b[32m✓\x1b[0m"),
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m");
            eprintln!("  {}", e);
            eprintln!();
            eprintln!("  The mnemonic is correct but the credential store is unavailable.");
            eprintln!("  Enable Keychain / Secret Service and try again.");
            return 1;
        }
    }

    // ── Verify operator key can be unlocked ──────────────────────
    let operator_enc = keys_dir.join("operator.secret.enc");
    if operator_enc.exists() {
        eprint!("  Verifying operator key unlock… ");
        match keyring.load_operator_with_genesis_secret(&genesis_key.secret_key()) {
            Ok(_op) => {
                eprintln!("\x1b[32m✓\x1b[0m operator key decrypted successfully");
            }
            Err(e) => {
                eprintln!("\x1b[33m⚠\x1b[0m");
                eprintln!("  Operator key could not be decrypted: {}", e);
                eprintln!("  The genesis secret is restored, but you may need to");
                eprintln!("  re-issue the operator key with `zp init`.");
            }
        }
    } else if keys_dir.join("operator.json").exists() {
        eprintln!("  \x1b[36mℹ\x1b[0m operator.json present but no encrypted secret on disk.");
        eprintln!("    The operator secret may be in the credential store already.");
    }

    // ── Done ─────────────────────────────────────────────────────
    eprintln!();
    eprintln!("  \x1b[1;32m✓ Recovery complete.\x1b[0m");
    eprintln!();
    eprintln!("  Your genesis identity has been restored to the credential store.");
    eprintln!("  Run `zp keys list` to verify, or `zp serve` to start the server.");
    eprintln!();

    0
}

/// Read a 24-word mnemonic from stdin.
///
/// Accepts words space-separated on one line, or one per line.
/// Stops at blank line or EOF.
fn read_mnemonic() -> Result<Vec<String>, String> {
    let stdin = io::stdin();
    let mut all_words: Vec<String> = Vec::new();

    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("Failed to read input: {}", e))?;
        let trimmed = line.trim();

        // Blank line = done
        if trimmed.is_empty() && !all_words.is_empty() {
            break;
        }

        // Split on whitespace — handles "word1 word2 ... word24" on one line
        for word in trimmed.split_whitespace() {
            all_words.push(word.to_lowercase());
        }

        // If we already have 24, stop
        if all_words.len() >= 24 {
            break;
        }
    }

    if all_words.is_empty() {
        return Err("No words entered.".into());
    }

    Ok(all_words)
}
