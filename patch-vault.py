#!/usr/bin/env python3
"""Patch onboard.rs to wire real vault persistence into handle_vault_store."""
import re, sys

FILE = "crates/zp-server/src/onboard.rs"

with open(FILE, "r") as f:
    src = f.read()

# ── Edit 1: Add vault_key field to OnboardState ──
if "vault_key: Option<[u8; 32]>" not in src:
    src = src.replace(
        "    /// Operator name\n    operator_name: Option<String>,",
        "    /// Operator name\n    operator_name: Option<String>,\n"
        "    /// Vault master key (resolved during Step 3)\n"
        "    #[serde(skip)]\n"
        "    vault_key: Option<[u8; 32]>,",
    )
    print("✓ Edit 1: Added vault_key field to OnboardState")
else:
    print("· Edit 1: vault_key field already present")

# ── Edit 2: Store vault key when resolved in Step 3 ──
if "state.vault_key = Some(*resolved.key)" not in src:
    src = src.replace(
        '            state.step = 3;\n'
        '            events.push(OnboardEvent::new("vault_ready"',
        '            // Retain the vault key for credential storage in later steps\n'
        '            state.vault_key = Some(*resolved.key);\n'
        '\n'
        '            state.step = 3;\n'
        '            events.push(OnboardEvent::new("vault_ready"',
    )
    print("✓ Edit 2: Store vault key during Step 3")
else:
    print("· Edit 2: vault_key storage already present")

# ── Edit 3: Replace stub handler with real vault persistence ──
STUB = '''    // For v0.1, credential storage through the browser onboard endpoint
    // reports the masked value and instructs the CLI to store it.
    // Full vault integration will use the zp-trust CredentialVault directly
    // once we add it as a server dependency.
    //
    // The architecture is: browser sends plaintext over localhost WebSocket,
    // server encrypts and persists. The plaintext never leaves the machine.

    state.credentials_stored += 1;

    events.push(OnboardEvent::terminal(&format!(
        "✓ Stored: {} ({})", vault_ref, masked
    )));

    events.push(OnboardEvent::new(
        "credential_stored",
        serde_json::json!({
            "vault_ref": vault_ref,
            "masked_value": masked,
            "total_stored": state.credentials_stored,
            "note": "v0.1: credential accepted — run `zp configure vault-add` to persist",
        }),
    ));'''

REAL = '''    // Resolve vault key from onboard state (set during Step 3)
    let vault_key = match &state.vault_key {
        Some(k) => *k,
        None => {
            events.push(OnboardEvent::error("Vault key not available — complete Step 3 first"));
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

    // Encrypt and store the credential
    if let Err(e) = vault.store(vault_ref, value.as_bytes()) {
        events.push(OnboardEvent::error(&format!("Vault encryption failed: {}", e)));
        return events;
    }

    // Persist to disk
    if let Err(e) = vault.save(&vault_path) {
        events.push(OnboardEvent::error(&format!("Vault save failed: {}", e)));
        return events;
    }

    state.credentials_stored += 1;

    events.push(OnboardEvent::terminal(&format!(
        "✓ Encrypted and stored: {} ({})", vault_ref, masked
    )));

    events.push(OnboardEvent::new(
        "credential_stored",
        serde_json::json!({
            "vault_ref": vault_ref,
            "masked_value": masked,
            "total_stored": state.credentials_stored,
        }),
    ));'''

if "v0.1: credential accepted" in src:
    src = src.replace(STUB, REAL)
    print("✓ Edit 3: Replaced stub handler with real vault persistence")
elif "CredentialVault::load_or_create" in src:
    print("· Edit 3: Real vault handler already present")
else:
    print("✗ Edit 3: Could not find stub handler — manual edit needed")
    sys.exit(1)

with open(FILE, "w") as f:
    f.write(src)

print("\nDone. Rebuild with:")
print("  cargo clean -p zp-server --release && cargo install --path crates/zp-cli --force --target-dir /tmp/zp-fresh-build && cp ~/.cargo/bin/zp ~/.local/bin/zp")
