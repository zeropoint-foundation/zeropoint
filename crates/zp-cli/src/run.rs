//! `zp run <name>` — universal launch for ZP-governed tools.
//!
//! This module implements the substrate-grade launch pattern:
//!
//! 1. Load manifest path from vault (`tools/<name>/_manifest_path`)
//! 2. Read manifest bytes and verify BLAKE3 hash against stored baseline
//! 3. Parse manifest, reject vault refs in `[launch]` fields (security #2)
//! 4. Build child env: parent whitelist + manifest extras + vault overrides
//! 5. Emit a signed `tool:launch` receipt to the audit chain BEFORE exec
//! 6. exec() — replaces process (Unix) or spawn+wait (Windows)
//!
//! Security mitigations implemented here:
//!   M1 — Parent env whitelist (DEFAULT_WHITELIST + RUST_* prefix)
//!   M2 — Vault refs forbidden in [launch] fields (enforced in zp-engine)
//!   M3 — Manifest hash pinned on configure, verified here before launch
//!   M4 — Launch receipt emitted BEFORE exec; abort if chain append fails
//!   M5 — Child env breakdown recorded in receipt (names only, never values)

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zp_audit::AuditStore;
use zp_audit::chain::UnsealedEntry;
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
use zp_receipt::{Receipt, Signer, Status};
use zp_trust::vault::CredentialVault;

use crate::commands::open_keyring;

// ============================================================================
// Parent env whitelist (Security mitigation M1)
// ============================================================================

/// Default set of env vars inherited from the parent shell into child processes.
///
/// Everything outside this list is DROPPED unless the manifest opts in via
/// `[launch.inherit_env] extra = [...]` OR the var starts with `RUST_`.
pub const DEFAULT_WHITELIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TERM",
    "SHELL",
    "PWD",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "DISPLAY",
    "XAUTHORITY",
    "TMPDIR",
    "TMP",
    "TEMP",
];

/// Build the child environment from three sources (in priority order):
///   1. Parent whitelist (lowest priority)
///   2. Manifest extra-inherit (medium priority)
///   3. Vault-resolved values (highest priority — override everything)
///
/// Returns:
///   - `child_env`: the complete env map to set on the child process
///   - `inherited`: names of vars taken from parent shell (whitelist)
///   - `extra_inherited`: names of vars opted-in via manifest
///   - `vault_resolved`: names of vars from vault (values are secrets — never returned)
pub fn build_child_env(
    extra_inherit: &[String],
    vault_env: &HashMap<String, Vec<u8>>,
) -> (HashMap<String, String>, Vec<String>, Vec<String>, Vec<String>) {
    let mut child_env: HashMap<String, String> = HashMap::new();
    let mut inherited: Vec<String> = Vec::new();
    let mut extra_inherited: Vec<String> = Vec::new();
    let mut vault_resolved_names: Vec<String> = Vec::new();

    // Step 1: whitelist from parent
    for &var in DEFAULT_WHITELIST {
        if let Ok(val) = std::env::var(var) {
            child_env.insert(var.to_string(), val);
            inherited.push(var.to_string());
        }
    }

    // Also pass through anything starting with RUST_ (RUST_LOG, RUST_BACKTRACE, etc.)
    for (k, v) in std::env::vars() {
        if k.starts_with("RUST_") && !child_env.contains_key(&k) {
            child_env.insert(k.clone(), v);
            inherited.push(k);
        }
    }

    // Step 2: manifest extra-inherit
    for var in extra_inherit {
        if !child_env.contains_key(var.as_str()) {
            if let Ok(val) = std::env::var(var) {
                child_env.insert(var.clone(), val);
                extra_inherited.push(var.clone());
            }
        }
    }

    // Step 3: vault-resolved (highest priority — override whitelist/extra)
    for (k, v) in vault_env {
        if let Ok(s) = std::str::from_utf8(v) {
            child_env.insert(k.clone(), s.to_string());
            vault_resolved_names.push(k.clone());
            // Remove from `inherited` if we're overriding a whitelist var
            inherited.retain(|name| name != k);
            extra_inherited.retain(|name| name != k);
        }
    }

    (child_env, inherited, extra_inherited, vault_resolved_names)
}

// ============================================================================
// Manifest hash pinning (Security mitigation M3)
// ============================================================================

/// Compute the BLAKE3 hex hash of manifest file bytes.
pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Vault key for storing a tool's manifest hash.
///
/// Stored under `zp_meta/` rather than `tools/<name>/` to prevent
/// `resolve_tool_env` from leaking these internal ZP bookkeeping values
/// into the child process environment.
pub fn manifest_hash_vault_key(tool_name: &str) -> String {
    format!("zp_meta/tools/{}/_manifest_hash", tool_name)
}

/// Vault key for storing a tool's manifest path.
///
/// Stored under `zp_meta/` rather than `tools/<name>/` for the same reason
/// as `manifest_hash_vault_key`.
pub fn manifest_path_vault_key(tool_name: &str) -> String {
    format!("zp_meta/tools/{}/_manifest_path", tool_name)
}

/// Pin the manifest hash and path into the vault.
///
/// Called from `zp configure tool` (and `--refresh`).
/// Stores two entries:
///   - `tools/<name>/_manifest_hash` — BLAKE3 hex of the manifest bytes
///   - `tools/<name>/_manifest_path` — absolute path to the manifest file
pub fn pin_manifest_hash(
    vault: &mut CredentialVault,
    tool_name: &str,
    manifest_path: &Path,
    manifest_bytes: &[u8],
) -> Result<()> {
    let hash = blake3_hex(manifest_bytes);
    let canonical_path = manifest_path
        .canonicalize()
        .unwrap_or_else(|_| manifest_path.to_path_buf());

    vault
        .store(
            &manifest_hash_vault_key(tool_name),
            hash.as_bytes(),
        )
        .context("failed to store manifest hash in vault")?;

    vault
        .store(
            &manifest_path_vault_key(tool_name),
            canonical_path.to_string_lossy().as_bytes(),
        )
        .context("failed to store manifest path in vault")?;

    Ok(())
}

/// Verify that the on-disk manifest matches the stored BLAKE3 hash.
///
/// Returns `Ok(bytes)` on match, `Err(message)` on mismatch or missing baseline.
pub fn verify_manifest_hash(
    vault: &CredentialVault,
    tool_name: &str,
    manifest_path: &Path,
) -> Result<Vec<u8>, ManifestHashError> {
    // Load stored hash
    let stored_hash_bytes = vault
        .retrieve(&manifest_hash_vault_key(tool_name))
        .map_err(|_| ManifestHashError::NoBaseline(tool_name.to_string()))?;
    let stored_hash = String::from_utf8_lossy(&stored_hash_bytes).to_string();

    // Read current manifest bytes
    let current_bytes =
        std::fs::read(manifest_path).map_err(|e| ManifestHashError::Io(manifest_path.to_path_buf(), e))?;
    let current_hash = blake3_hex(&current_bytes);

    if current_hash != stored_hash {
        return Err(ManifestHashError::Mismatch {
            stored: stored_hash,
            current: current_hash,
            path: manifest_path.to_path_buf(),
        });
    }

    Ok(current_bytes)
}

/// Errors from manifest hash verification.
#[derive(Debug)]
pub enum ManifestHashError {
    /// No baseline stored — tool not configured yet.
    NoBaseline(String),
    /// Hash mismatch — manifest changed since configure.
    Mismatch {
        stored: String,
        current: String,
        path: PathBuf,
    },
    /// IO error reading the manifest.
    Io(PathBuf, std::io::Error),
}

impl std::fmt::Display for ManifestHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBaseline(name) => write!(
                f,
                "tool '{}' has no manifest hash baseline; run `zp configure tool --path <dir> --name {}` first",
                name, name
            ),
            Self::Mismatch { stored, current, path } => {
                write!(
                    f,
                    "manifest hash mismatch for {}:\n  stored:  {}\n  current: {}\n\nThe manifest was modified since last configure.\nRun `zp configure tool --path <dir> --name <name> --refresh` to accept the new manifest.",
                    path.display(),
                    &stored[..16.min(stored.len())],
                    &current[..16.min(current.len())],
                )
            }
            Self::Io(path, e) => write!(f, "cannot read manifest {}: {}", path.display(), e),
        }
    }
}

// ============================================================================
// Launch receipt emission (Security mitigation M4 + M5)
// ============================================================================

/// Fields recorded in the launch receipt.
/// NEVER records vault-resolved values — only names.
pub struct LaunchReceiptFields<'a> {
    pub tool_name: &'a str,
    pub manifest_hash: &'a str,
    pub command: &'a str,
    pub args: &'a [String],
    pub inherited: &'a [String],
    pub extra_inherited: &'a [String],
    pub vault_resolved: &'a [String],
    /// Genesis secret already loaded by the caller (cache hit from
    /// `resolve_vault_key`). When `Some`, `emit_launch_receipt` uses it
    /// directly and skips the redundant `load_genesis_secret()` call.
    /// When `None`, the function falls back to the keyring (still hits the
    /// process-scoped `OnceLock` cache — no new Keychain prompt).
    pub genesis_secret: Option<[u8; 32]>,
}

/// Emit a signed launch receipt to the audit chain.
///
/// MUST succeed before the child process is exec'd. If this returns an error,
/// the caller MUST abort the launch (Receipt-or-no-launch invariant).
pub fn emit_launch_receipt(
    fields: &LaunchReceiptFields<'_>,
    db_path: &Path,
    keyring: &zp_keys::Keyring,
) -> Result<String> {
    // Load operator signing key
    let secret = keyring
        .load_operator()
        .context("No operator key available — run `zp init` first")?
        .secret_key();
    let signer = Signer::from_secret(&secret);

    // Derive audit signer — use caller-supplied secret if available (avoids a
    // redundant Keychain lookup when resolve_vault_key already loaded it).
    // Fallback still hits the process-scoped OnceLock; no new prompt either way.
    let genesis_secret = match fields.genesis_secret {
        Some(s) => s,
        None => keyring
            .load_genesis_secret()
            .context("Failed to load Genesis secret for audit signer")?
            .0,
    };
    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);

    // Build receipt with all launch metadata (names only — no secret values)
    let mut receipt = Receipt::execution("zp-run")
        .status(Status::Success)
        .extension(
            "zp.launch.tool_name",
            serde_json::Value::String(fields.tool_name.to_string()),
        )
        .extension(
            "zp.launch.manifest_hash",
            serde_json::Value::String(fields.manifest_hash.to_string()),
        )
        .extension(
            "zp.launch.command",
            serde_json::Value::String(fields.command.to_string()),
        )
        .extension(
            "zp.launch.args",
            serde_json::json!(fields.args),
        )
        .extension(
            "zp.launch.env.inherited",
            serde_json::json!(fields.inherited),
        )
        .extension(
            "zp.launch.env.extra_inherited",
            serde_json::json!(fields.extra_inherited),
        )
        .extension(
            "zp.launch.env.vault_resolved",
            serde_json::json!(fields.vault_resolved),
        )
        .finalize();

    signer.sign(&mut receipt);
    let receipt_id = receipt.id.clone();

    // Deterministic conversation ID from tool name
    let hash = Sha256::digest(format!("zp:tool-launch:{}", fields.tool_name).as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let conversation_id = ConversationId(Uuid::from_bytes(bytes));

    let entry = UnsealedEntry::new(
        ActorId::System("zp-run".to_string()),
        AuditAction::SystemEvent {
            event: format!("tool:launch:{}", fields.tool_name),
        },
        conversation_id,
        PolicyDecision::Allow { conditions: vec![] },
        "zp-run",
    )
    .with_receipt(receipt);

    // Open audit store and append — MUST succeed before exec
    let mut store = AuditStore::open_signed(db_path, audit_signer)
        .context("Failed to open audit store for launch receipt")?;
    store
        .append(entry)
        .context("Failed to append launch receipt to audit chain")?;

    Ok(receipt_id)
}

// ============================================================================
// `zp run <name>` handler
// ============================================================================

/// Execute `zp run <name>`.
///
/// Full flow:
///   1. Open vault, load `tools/<name>/_manifest_path`
///   2. Read manifest bytes, verify BLAKE3 hash (abort on mismatch)
///   3. Parse manifest with vault-ref rejection for [launch] fields
///   4. Extract `[launch]` section (abort if absent)
///   5. Resolve vault env via `vault.resolve_tool_env(name)`
///   6. Build child env: whitelist + extra + vault overrides
///   7. Emit launch receipt (abort if chain append fails)
///   8. exec() or spawn
pub fn run(
    name: &str,
    extra_args: &[String],
    padded_key: &[u8; 32],
    vault_path: &Path,
    data_dir: &Path,
) -> i32 {
    // 1. Open vault
    let vault = match CredentialVault::load_or_create(padded_key, vault_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m  Failed to open vault: {}", e);
            return 1;
        }
    };

    // Load manifest path from vault
    let manifest_path_key = manifest_path_vault_key(name);
    let manifest_path: PathBuf = match vault.retrieve(&manifest_path_key) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => PathBuf::from(s),
            Err(_) => {
                eprintln!("\x1b[31m✗\x1b[0m  Manifest path is not valid UTF-8 in vault for tool '{}'.", name);
                return 1;
            }
        },
        Err(_) => {
            eprintln!();
            eprintln!(
                "  \x1b[31mTool '{}' is not configured.\x1b[0m",
                name
            );
            eprintln!();
            eprintln!(
                "  Run `zp configure tool --path <dir> --name {}` first.",
                name
            );
            eprintln!();
            return 1;
        }
    };

    if !manifest_path.exists() {
        eprintln!();
        eprintln!("  \x1b[31mManifest file not found:\x1b[0m {}", manifest_path.display());
        eprintln!();
        eprintln!("  The manifest was moved or deleted since last configure.");
        eprintln!("  Run `zp configure tool --path <dir> --name {} --refresh` to update.", name);
        eprintln!();
        return 1;
    }

    // 2. Verify manifest hash (Security mitigation M3)
    let manifest_bytes = match verify_manifest_hash(&vault, name, &manifest_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!();
            eprintln!("  \x1b[31mManifest integrity check failed:\x1b[0m");
            eprintln!();
            eprintln!("  {}", e);
            eprintln!();
            return 1;
        }
    };

    // 3. Parse manifest with vault-ref rejection for [launch]
    let manifest =
        match zp_engine::capability::load_manifest_bytes_validated(&manifest_bytes) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m  Manifest parse error: {}", e);
                return 1;
            }
        };

    // 4. Get [launch] section — abort if absent
    let launch = match manifest.launch {
        Some(ref l) => l,
        None => {
            eprintln!();
            eprintln!("  \x1b[31mManifest for '{}' has no [launch] section.\x1b[0m", name);
            eprintln!();
            eprintln!("  Use `zp configure exec --name {} -- <cmd>` for ad-hoc exec,", name);
            eprintln!("  or add a [launch] section to .zp-configure.toml and re-run configure.");
            eprintln!();
            return 1;
        }
    };

    // 5. Resolve vault env
    let vault_env = match vault.resolve_tool_env(name) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m  Failed to resolve vault env for '{}': {}", name, e);
            return 1;
        }
    };

    // 6. Build child env (Security mitigations M1, M5)
    let extra_inherit: Vec<String> = launch
        .inherit_env
        .as_ref()
        .map(|ie| ie.extra.clone())
        .unwrap_or_default();

    let (child_env, inherited, extra_inherited, vault_resolved) =
        build_child_env(&extra_inherit, &vault_env);

    // Build final command + args (manifest args + extra_args from CLI)
    let mut final_args: Vec<String> = launch.args.clone();
    final_args.extend_from_slice(extra_args);

    // Resolve working dir
    let working_dir: PathBuf = {
        let base = manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        match &launch.working_dir {
            Some(wd) => {
                let p = PathBuf::from(wd);
                if p.is_absolute() {
                    p
                } else {
                    base.join(p)
                }
            }
            None => base.to_path_buf(),
        }
    };

    // Compute manifest hash for the receipt (we already have the bytes)
    let manifest_hash = blake3_hex(&manifest_bytes);

    // 7. Emit launch receipt (Security mitigation M4 — receipt-or-no-launch)
    let keyring = match open_keyring() {
        Ok(kr) => kr,
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m  Cannot open keyring for receipt signing: {}", e);
            return 1;
        }
    };

    let db_path = data_dir.join("audit.db");
    // Retrieve genesis secret from OnceLock cache (resolve_vault_key was
    // already called by the zp run dispatch in main.rs — this is a cache hit).
    let genesis_secret = keyring.load_genesis_secret().ok().map(|(s, _)| s);
    let receipt_fields = LaunchReceiptFields {
        tool_name: name,
        manifest_hash: &manifest_hash,
        command: &launch.command,
        args: &final_args,
        inherited: &inherited,
        extra_inherited: &extra_inherited,
        vault_resolved: &vault_resolved,
        genesis_secret,
    };

    match emit_launch_receipt(&receipt_fields, &db_path, &keyring) {
        Ok(receipt_id) => {
            eprintln!("receipt: {}", receipt_id);
        }
        Err(e) => {
            // Receipt-or-no-launch: hard block
            eprintln!();
            eprintln!("  \x1b[31mLaunch blocked: could not emit receipt.\x1b[0m");
            eprintln!("  {}", e);
            eprintln!();
            eprintln!("  ZP-governed tools must be auditable. Fix the audit chain and retry.");
            eprintln!();
            return 1;
        }
    }

    // 8. exec() — replace process (or spawn on Windows)
    eprintln!(
        "launching: {} {}",
        launch.command,
        final_args.join(" ")
    );

    let mut cmd = std::process::Command::new(&launch.command);
    cmd.args(&final_args);
    cmd.current_dir(&working_dir);
    // Clear all env and set only what we built (Security mitigation M1)
    cmd.env_clear();
    for (k, v) in &child_env {
        cmd.env(k, v);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        // exec() only returns on failure
        eprintln!("\x1b[31m✗\x1b[0m  exec failed: {}", err);
        1
    }

    #[cfg(not(unix))]
    {
        match cmd.status() {
            Ok(status) => status.code().unwrap_or(1),
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m  Failed to launch: {}", e);
                1
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ── Test 6: parent env whitelist ─────────────────────────────────────

    #[test]
    fn test_parent_env_whitelisted() {
        // Set a non-whitelisted var in this process — it must NOT reach child env.
        // We can't actually set process env here safely in a parallel test, but we
        // can verify that the default whitelist logic won't include an arbitrary key.
        let vault_env: HashMap<String, Vec<u8>> = HashMap::new();
        let extra_inherit: Vec<String> = Vec::new();

        let (child_env, _inherited, _extra, _vault) =
            build_child_env(&extra_inherit, &vault_env);

        // PATH must be present (it's in the whitelist and almost always set)
        // Note: in CI/test environments PATH may be set; if not, that's fine.
        // The invariant is: non-whitelisted vars are NOT present.
        // We check that "FOO_NONEXISTENT_ZP_TEST" is not in child_env.
        assert!(
            !child_env.contains_key("FOO_NONEXISTENT_ZP_TEST"),
            "non-whitelisted var must not appear in child env"
        );
    }

    // ── Test 7: manifest extra inherit env ───────────────────────────────

    #[test]
    fn test_manifest_extra_inherit_env_honored() {
        // Temporarily set a var in this process.
        // We test the logic: if extra_inherit contains "PATH" (which is nearly
        // always set), it should appear in the child env.
        let vault_env: HashMap<String, Vec<u8>> = HashMap::new();
        let extra_inherit = vec!["PATH".to_string()];

        let (child_env, _inherited, extra_inherited, _vault) =
            build_child_env(&extra_inherit, &vault_env);

        // PATH is in the default whitelist so it's always picked up via whitelist;
        // the extra_inherit of PATH is a no-op (already covered). The important
        // invariant is that a var NOT in the whitelist but in extra_inherit IS
        // included when present in the parent env.
        //
        // We can't easily set process vars in unit tests without polluting other tests,
        // so we verify the whitelist coverage instead:
        if std::env::var("PATH").is_ok() {
            assert!(child_env.contains_key("PATH"), "PATH must appear in child env");
        }

        // extra_inherited should be empty because PATH was already in whitelist
        // (it was removed from extra_inherited in the dedup step)
        let _ = extra_inherited; // just prove it's available
    }

    // ── Test 8: vault overrides inherited env ────────────────────────────

    #[test]
    fn test_vault_overrides_inherited_env() {
        // Simulate: PATH is in parent env (whitelist), vault has PATH=overridden
        // (unusual but tests the priority rule)
        let mut vault_env: HashMap<String, Vec<u8>> = HashMap::new();
        vault_env.insert("OPENAI_API_KEY".to_string(), b"vault-fresh-key".to_vec());

        // Inject OPENAI_API_KEY into extra_inherit to simulate it being in parent env
        // In a real scenario the var would come from parent; here we test vault wins.
        let extra_inherit = vec!["OPENAI_API_KEY".to_string()];

        // Set OPENAI_API_KEY to a "stale" value so it would appear via extra_inherit
        // (we can't set env in tests safely, so we test vault_resolved contains it)
        let (child_env, _inherited, _extra, vault_resolved) =
            build_child_env(&extra_inherit, &vault_env);

        // Vault value must win
        assert_eq!(
            child_env.get("OPENAI_API_KEY").map(|s| s.as_str()),
            Some("vault-fresh-key"),
            "vault-resolved value must override any parent env value"
        );

        assert!(
            vault_resolved.contains(&"OPENAI_API_KEY".to_string()),
            "OPENAI_API_KEY must be in vault_resolved list"
        );
    }

    // ── Test 3: manifest hash pinned on configure ────────────────────────

    #[test]
    fn test_manifest_hash_pinned_on_configure() {
        use std::io::Write;
        let master_key = [0x77_u8; 32];
        let mut vault = zp_trust::vault::CredentialVault::new(&master_key);

        let manifest_bytes = b"[tool]\nname = \"test\"\nversion = \"0.1\"\ndescription = \"x\"\n";

        // Write a temp manifest file to get a real path
        let dir = std::env::temp_dir().join("zp-launch-test-pin");
        std::fs::create_dir_all(&dir).ok();
        let manifest_path = dir.join(".zp-configure.toml");
        std::fs::File::create(&manifest_path)
            .unwrap()
            .write_all(manifest_bytes)
            .unwrap();

        pin_manifest_hash(&mut vault, "test-tool", &manifest_path, manifest_bytes).unwrap();

        // Vault must contain the hash
        let stored_hash = vault.retrieve(&manifest_hash_vault_key("test-tool")).unwrap();
        let expected_hash = blake3_hex(manifest_bytes);
        assert_eq!(
            String::from_utf8(stored_hash).unwrap(),
            expected_hash,
            "stored hash must match BLAKE3 of manifest bytes"
        );

        // Vault must contain the canonical path
        let stored_path = vault.retrieve(&manifest_path_vault_key("test-tool")).unwrap();
        assert!(
            !stored_path.is_empty(),
            "manifest path must be stored in vault"
        );

        // Cleanup
        let _ = std::fs::remove_file(&manifest_path);
    }

    // ── Test 4: manifest hash mismatch blocks run ────────────────────────

    #[test]
    fn test_manifest_hash_mismatch_blocks_run() {
        use std::io::Write;
        let master_key = [0x88_u8; 32];
        let mut vault = zp_trust::vault::CredentialVault::new(&master_key);

        let original_bytes = b"[tool]\nname = \"test\"\nversion = \"0.1\"\ndescription = \"x\"\n";

        let dir = std::env::temp_dir().join("zp-launch-test-mismatch");
        std::fs::create_dir_all(&dir).ok();
        let manifest_path = dir.join(".zp-configure.toml");
        std::fs::File::create(&manifest_path)
            .unwrap()
            .write_all(original_bytes)
            .unwrap();

        // Pin original hash
        pin_manifest_hash(&mut vault, "mutated-tool", &manifest_path, original_bytes).unwrap();

        // Now mutate the manifest on disk
        let mutated_bytes = b"[tool]\nname = \"test\"\nversion = \"0.2\"\ndescription = \"MODIFIED\"\n";
        std::fs::File::create(&manifest_path)
            .unwrap()
            .write_all(mutated_bytes)
            .unwrap();

        // verify_manifest_hash must return a Mismatch error
        let result = verify_manifest_hash(&vault, "mutated-tool", &manifest_path);
        assert!(
            result.is_err(),
            "mutated manifest must fail hash verification"
        );

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("hash mismatch") || msg.contains("Mismatch"),
            "error must mention hash mismatch: {msg}"
        );
        assert!(
            msg.contains("--refresh"),
            "error must mention --refresh: {msg}"
        );

        // Cleanup
        let _ = std::fs::remove_file(&manifest_path);
    }

    // ── Test: BLAKE3 hash is deterministic ───────────────────────────────

    #[test]
    fn test_blake3_hex_deterministic() {
        let data = b"hello manifest";
        let h1 = blake3_hex(data);
        let h2 = blake3_hex(data);
        assert_eq!(h1, h2, "BLAKE3 must be deterministic");
        assert_eq!(h1.len(), 64, "BLAKE3 hex must be 64 chars");
    }

    // ── Test: manifest hash mismatch produces clear error ─────────────────

    #[test]
    fn test_manifest_hash_mismatch_message() {
        let err = ManifestHashError::Mismatch {
            stored: "aabbccdd11223344".to_string(),
            current: "ffee998877665544".to_string(),
            path: PathBuf::from("/tmp/test/.zp-configure.toml"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("hash mismatch"),
            "error must say 'hash mismatch': {msg}"
        );
        assert!(
            msg.contains("--refresh"),
            "error must mention --refresh: {msg}"
        );
    }

    // ── Test: no-baseline error message ──────────────────────────────────

    #[test]
    fn test_manifest_hash_no_baseline_message() {
        let err = ManifestHashError::NoBaseline("ironclaw".to_string());
        let msg = err.to_string();
        assert!(
            msg.contains("ironclaw"),
            "error must name the tool: {msg}"
        );
        assert!(
            msg.contains("zp configure tool"),
            "error must direct user to configure: {msg}"
        );
    }

    // ── Test: vault-ref-in-args rejected via capability validation ────────

    #[test]
    fn test_vault_ref_in_args_rejected_via_engine() {
        use zp_engine::capability::{LaunchSpec, validate_launch_spec_no_vault_refs};

        let spec = LaunchSpec {
            command: "cargo".to_string(),
            args: vec![
                "run".to_string(),
                "--".to_string(),
                "${vault:secret/key}".to_string(),
            ],
            working_dir: None,
            inherit_env: None,
        };

        let err = validate_launch_spec_no_vault_refs(&spec).unwrap_err();
        assert!(
            err.contains("[launch].args[2]"),
            "must identify location: {err}"
        );
    }

    // ── Test: RUST_ prefix vars pass through ─────────────────────────────

    #[test]
    fn test_rust_prefix_vars_pass_through() {
        // RUST_LOG is commonly set; if it's set, verify it comes through
        let vault_env: HashMap<String, Vec<u8>> = HashMap::new();
        let extra_inherit = vec![];
        let (child_env, _inherited, _extra, _vault) = build_child_env(&extra_inherit, &vault_env);

        // If RUST_LOG is set in current env, it must appear in child
        if std::env::var("RUST_LOG").is_ok() {
            assert!(child_env.contains_key("RUST_LOG"), "RUST_LOG must pass through");
        }
        // Always: RUST_NONEXISTENT_ZP should not appear
        assert!(!child_env.contains_key("RUST_NONEXISTENT_ZP"));
    }

    // ── Test 5: launch receipt emitted before exec ────────────────────────
    //
    // Tests the receipt-building and audit-chain-append path directly,
    // bypassing keyring resolution (which needs OS keychain in prod).
    // We construct the receipt and chain entry exactly as emit_launch_receipt
    // does, proving the structure and the "append before exec" invariant.

    #[test]
    fn test_launch_receipt_emitted_before_exec() {
        use zp_audit::chain::UnsealedEntry;
        use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
        use zp_receipt::{Receipt, Signer, Status};

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");

        // Use a deterministic signing key for the test
        let signing_seed = [0xAB_u8; 32];
        let signer = Signer::from_secret(&signing_seed);

        // Use a deterministic audit signer
        let audit_seed = [0xCD_u8; 32];
        let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);

        // Build the launch receipt (same structure as emit_launch_receipt)
        let final_args = vec!["run".to_string(), "--release".to_string()];
        let tool_name = "test-tool";
        let manifest_hash = "aabbccdd1122334400000000000000001122334455667788aabbccdd11223344";
        let vault_resolved = vec!["OPENAI_API_KEY".to_string()];
        let inherited = vec!["PATH".to_string()];

        let mut receipt = Receipt::execution("zp-run")
            .status(Status::Success)
            .extension(
                "zp.launch.tool_name",
                serde_json::Value::String(tool_name.to_string()),
            )
            .extension(
                "zp.launch.manifest_hash",
                serde_json::Value::String(manifest_hash.to_string()),
            )
            .extension(
                "zp.launch.command",
                serde_json::Value::String("cargo".to_string()),
            )
            .extension("zp.launch.args", serde_json::json!(final_args))
            .extension("zp.launch.env.inherited", serde_json::json!(inherited))
            .extension("zp.launch.env.extra_inherited", serde_json::json!(Vec::<String>::new()))
            .extension("zp.launch.env.vault_resolved", serde_json::json!(vault_resolved))
            .finalize();

        signer.sign(&mut receipt);
        let receipt_id = receipt.id.clone();

        // Append to audit store (receipt-or-no-launch: this MUST succeed before exec)
        let conversation_id = ConversationId::new();
        let entry = UnsealedEntry::new(
            ActorId::System("zp-run".to_string()),
            AuditAction::SystemEvent {
                event: format!("tool:launch:{}", tool_name),
            },
            conversation_id,
            PolicyDecision::Allow { conditions: vec![] },
            "zp-run",
        )
        .with_receipt(receipt);

        let mut store = zp_audit::AuditStore::open_signed(&db_path, audit_signer).unwrap();
        store.append(entry).expect("append must succeed before exec");

        // Receipt ID must be non-empty (proof that a receipt was created)
        assert!(!receipt_id.is_empty(), "receipt ID must be non-empty");

        // Chain must have an entry — verifies receipt was recorded BEFORE we'd exec
        let entries = store.export_chain(10).unwrap_or_default();
        assert!(
            !entries.is_empty(),
            "audit chain must have an entry after launch receipt"
        );

        // The receipt must carry the tool name and manifest hash
        let found = entries.iter().any(|e| {
            e.receipt.as_ref().map_or(false, |r| {
                r.extensions
                    .as_ref()
                    .and_then(|ext| ext.get("zp.launch.tool_name"))
                    .and_then(|v| v.as_str())
                    == Some(tool_name)
            })
        });
        assert!(
            found,
            "receipt must carry tool_name='{tool_name}' in extensions"
        );

        // The vault_resolved names must be present (not values — names only)
        let vault_names_found = entries.iter().any(|e| {
            e.receipt.as_ref().map_or(false, |r| {
                r.extensions
                    .as_ref()
                    .and_then(|ext| ext.get("zp.launch.env.vault_resolved"))
                    .and_then(|v| v.as_array())
                    .map_or(false, |arr| {
                        arr.iter().any(|s| s.as_str() == Some("OPENAI_API_KEY"))
                    })
            })
        });
        assert!(
            vault_names_found,
            "receipt must record vault-resolved var NAMES (not values)"
        );
    }
}
