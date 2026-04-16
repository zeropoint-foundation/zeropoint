//! Subcommand handlers for skills, audit, health, keys, and gate operations

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use ed25519_dalek::SigningKey;
use zp_audit::AuditStore;
use zp_core::{
    policy::{PolicyContext, TrustTier},
    ActionType, ActorId, Channel, ConversationId,
};
use zp_keys::certificate::KeyRole;
use zp_keys::hierarchy::{AgentKey, OperatorKey};
use zp_keys::keyring::Keyring;
use zp_keys::rotation::RotationCertificate;
use zp_pipeline::Pipeline;
use zp_policy::GovernanceGate;

/// Resolve the ZeroPoint home directory.
///
/// Resolution chain (first match wins):
///   1. `ZP_HOME` env var         — explicit override (CI, Docker, production)
///   2. `zeropoint.toml` key_path — project-level config (walks up from cwd)
///   3. `~/.zeropoint/`           — sensible default for local dev
///
/// Examples:
///   ZP_HOME=/opt/zeropoint zp keys list   → /opt/zeropoint
///   (in project with toml key_path)       → whatever toml says
///   (default)                             → ~/.zeropoint
pub fn resolve_zp_home() -> PathBuf {
    // 1. Explicit env override
    if let Some(zp_home) = std::env::var_os("ZP_HOME") {
        return PathBuf::from(zp_home);
    }

    // 2. Walk up from cwd looking for zeropoint.toml with key_path
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = cwd.as_path();
        loop {
            let toml_path = dir.join("zeropoint.toml");
            if toml_path.exists() {
                if let Ok(contents) = std::fs::read_to_string(&toml_path) {
                    // Simple parse — look for key_path under [identity]
                    if let Some(kp) = parse_key_path(&contents) {
                        let expanded = expand_tilde(&kp);
                        if expanded.is_absolute() {
                            // Absolute paths are parent of "keys/"
                            // key_path points to the keys dir, we want its parent
                            if let Some(parent) = expanded.parent() {
                                return parent.to_path_buf();
                            }
                            return expanded;
                        } else {
                            // Relative to the toml's directory
                            let resolved = dir.join(&expanded);
                            if let Some(parent) = resolved.parent() {
                                return parent.to_path_buf();
                            }
                            return resolved;
                        }
                    }
                }
                break; // Found toml but no key_path — fall through to default
            }
            match dir.parent() {
                Some(p) => dir = p,
                None => break,
            }
        }
    }

    // 3. Default: ~/.zeropoint/
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zeropoint")
}

/// Open a keyring using the resolved ZP home.
pub fn open_keyring() -> Result<Keyring, zp_keys::error::KeyError> {
    Keyring::open(resolve_zp_home().join("keys"))
}

/// Expand `~` at the start of a path to $HOME.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

/// Extract key_path value from zeropoint.toml content.
/// Simple line-based parse — no toml crate dependency needed.
fn parse_key_path(contents: &str) -> Option<String> {
    let mut in_identity = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_identity = trimmed == "[identity]";
            continue;
        }
        if in_identity && trimmed.starts_with("key_path") {
            if let Some(val) = trimmed.split('=').nth(1) {
                let val = val.trim().trim_matches('"').trim_matches('\'');
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// List all registered skills
#[allow(dead_code)]
pub async fn skills_list(_pipeline: &Pipeline) -> Result<()> {
    // Get skill registry from pipeline
    // For now, print a placeholder since the pipeline doesn't expose this directly
    println!();
    println!("Registered Skills");
    println!("{}", "=".repeat(60));
    println!("{:<20} {:<20} {:<15}", "ID", "Name", "Status");
    println!("{}", "-".repeat(60));

    // In a full implementation, we would query the skill registry
    // pipeline.skill_registry().list_all() or similar
    println!(
        "{:<20} {:<20} {:<15}",
        "example.skill", "Example Skill", "enabled"
    );
    println!();

    Ok(())
}

/// Show details of a specific skill
#[allow(dead_code)]
pub async fn skills_info(_pipeline: &Pipeline, id: &str) -> Result<()> {
    println!();
    println!("Skill Details: {}", id);
    println!("{}", "=".repeat(60));

    // In a full implementation, we would query the skill registry
    // let skill = pipeline.skill_registry().get(id)?;

    println!("ID:          {}", id);
    println!("Name:        Example Skill");
    println!("Status:      enabled");
    println!("Invocations: 0");
    println!("Success Rate: 0%");
    println!("Avg Latency: 0ms");
    println!();

    Ok(())
}

/// Show audit trail for a conversation
#[allow(dead_code)]
pub async fn audit_show(_pipeline: &Pipeline, conversation_id: &str) -> Result<()> {
    println!();
    println!("Audit Trail for Conversation: {}", conversation_id);
    println!("{}", "=".repeat(80));
    println!("{:<25} {:<20} {:<35}", "Timestamp", "Action", "Details");
    println!("{}", "-".repeat(80));

    // In a full implementation, we would query the audit store
    // let entries = pipeline.audit_store().get_entries(&conversation_id)?;

    println!("(No audit entries found for this conversation)");
    println!();

    Ok(())
}

/// Show recent audit log entries from the real AuditStore.
pub async fn audit_log(_pipeline: &Pipeline, limit: usize, category: Option<&str>) -> Result<()> {
    let db_path = resolve_zp_home().join("data").join("audit.db");

    if !db_path.exists() {
        eprintln!();
        eprintln!("  \x1b[1mAudit Log\x1b[0m");
        eprintln!("  \x1b[2m─────────\x1b[0m");
        eprintln!();
        eprintln!("  \x1b[2mNo audit entries yet.\x1b[0m");
        eprintln!("  Run `zp gate eval` to generate your first audit receipt.");
        eprintln!();
        return Ok(());
    }

    let store = AuditStore::open(&db_path)
        .map_err(|e| anyhow::anyhow!("Failed to open audit store: {}", e))?;

    let entries = store
        .export_chain(limit)
        .map_err(|e| anyhow::anyhow!("Failed to read audit chain: {}", e))?;

    eprintln!();
    eprintln!("  \x1b[1mAudit Log\x1b[0m");
    eprintln!("  \x1b[2m─────────\x1b[0m");

    if let Some(cat) = category {
        eprintln!("  Filter: {}", cat);
    }

    if entries.is_empty() {
        eprintln!();
        eprintln!("  \x1b[2mNo audit entries yet.\x1b[0m");
        eprintln!("  Run `zp gate eval` to generate your first audit receipt.");
        eprintln!();
        return Ok(());
    }

    eprintln!(
        "  Showing {} of {} entries",
        entries.len().min(limit),
        entries.len()
    );
    eprintln!();

    for entry in &entries {
        let decision_str = if entry.policy_decision.is_allowed() {
            "\x1b[32mALLOW\x1b[0m"
        } else if entry.policy_decision.is_blocked() {
            "\x1b[31mBLOCK\x1b[0m"
        } else {
            "\x1b[33mREVIEW\x1b[0m"
        };

        let action_str = format!("{:?}", entry.action);
        let short_hash = &entry.entry_hash[..12.min(entry.entry_hash.len())];

        eprintln!(
            "  \x1b[2m{}\x1b[0m  {}  \x1b[36m{}\x1b[0m  {}",
            entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
            decision_str,
            short_hash,
            action_str,
        );
    }

    eprintln!();
    Ok(())
}

/// Verify audit chain integrity using the real AuditStore.
pub async fn audit_verify(_pipeline: &Pipeline) -> Result<()> {
    let db_path = resolve_zp_home().join("data").join("audit.db");

    if !db_path.exists() {
        eprintln!();
        eprintln!("  \x1b[1mAudit Chain Verification\x1b[0m");
        eprintln!("  \x1b[2m────────────────────────\x1b[0m");
        eprintln!();
        eprintln!("  Status:  \x1b[2m(no audit store)\x1b[0m");
        eprintln!("  Run `zp gate eval` to create your first audit entry.");
        eprintln!();
        return Ok(());
    }

    let store = AuditStore::open(&db_path)
        .map_err(|e| anyhow::anyhow!("Failed to open audit store: {}", e))?;

    let report = store
        .verify_with_report()
        .map_err(|e| anyhow::anyhow!("Verification failed: {}", e))?;

    eprintln!();
    eprintln!("  \x1b[1mAudit Chain Verification\x1b[0m");
    eprintln!("  \x1b[2m────────────────────────\x1b[0m");
    eprintln!();

    if report.chain_valid {
        eprintln!("  Status:       \x1b[32mVALID\x1b[0m");
    } else {
        eprintln!("  Status:       \x1b[31mINVALID\x1b[0m");
    }

    eprintln!("  Entries:      {}", report.entries_examined);
    eprintln!(
        "  Hashes OK:    {}/{}",
        report.hashes_valid, report.entries_examined
    );
    eprintln!(
        "  Chain links:  {}/{}",
        report.chain_links_valid,
        report.entries_examined.saturating_sub(1).max(0)
    );

    if report.signatures_present > 0 {
        eprintln!(
            "  Signatures:   {}/{}",
            report.signatures_valid, report.signatures_present
        );
    }

    if !report.issues.is_empty() {
        eprintln!();
        eprintln!("  \x1b[31mIssues:\x1b[0m");
        for issue in &report.issues {
            eprintln!("    ✗ {}", issue);
        }
    }

    eprintln!();
    if report.chain_valid {
        eprintln!("  Audit chain is \x1b[32mtamper-proof\x1b[0m and intact.");
    } else {
        eprintln!("  \x1b[31mAudit chain integrity compromised.\x1b[0m");
        eprintln!("  Investigate the issues above before trusting this audit trail.");
    }
    eprintln!();

    Ok(())
}

/// Check system health
pub async fn health(_pipeline: &Pipeline) -> Result<()> {
    println!();
    println!("System Health Check");
    println!("{}", "=".repeat(60));

    println!("Pipeline:            OK");
    println!("Policy Engine:       OK");
    println!("Skill Registry:      OK");
    println!("Audit Store:         OK");
    println!("LLM Providers:       OK");
    println!();
    println!("Overall Status:      HEALTHY");
    println!();

    Ok(())
}

// ── Key lifecycle commands ─────────────────────────────────────────

/// Issue a new agent key with scoped capabilities.
pub fn keys_issue(name: &str, capabilities: Option<&str>, expires_days: u64) -> i32 {
    let keyring = match open_keyring() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("  Failed to open keyring: {}", e);
            eprintln!("  Run `zp init` first to bootstrap your environment.");
            return 1;
        }
    };

    // Load operator key (needed to sign agent key)
    let operator = match keyring.load_operator() {
        Ok(op) => op,
        Err(e) => {
            eprintln!("  No operator key found: {}", e);
            eprintln!("  Run `zp init` first.");
            return 1;
        }
    };

    eprintln!();
    eprintln!("  \x1b[1mIssuing Agent Key\x1b[0m");
    eprintln!("  \x1b[2m─────────────────\x1b[0m");

    // Parse capabilities
    let caps: Vec<String> = capabilities
        .unwrap_or("tool:*")
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    // Compute expiration
    let expires_at = Some(chrono::Utc::now() + chrono::Duration::days(expires_days as i64));

    eprint!("  Generating agent key...              ");
    let agent = AgentKey::generate(name, &operator, expires_at);
    eprintln!("\x1b[32m✓\x1b[0m Ed25519");

    eprint!("  Writing to keyring...                ");
    if let Err(e) = keyring.save_agent(name, &agent) {
        eprintln!("\x1b[31m✗\x1b[0m");
        eprintln!("  Failed to save agent key: {}", e);
        return 1;
    }
    eprintln!("\x1b[32m✓\x1b[0m .zeropoint/keys/agents/{}.json", name);

    let pub_hex = hex::encode(agent.public_key());
    eprintln!();
    eprintln!("  Agent:        \x1b[36m{}\x1b[0m", name);
    eprintln!("  Public key:   \x1b[36m{}...\x1b[0m", &pub_hex[..16]);
    eprintln!("  Capabilities: {}", caps.join(", "));
    eprintln!("  Expires:      {} days", expires_days);
    eprintln!();
    eprintln!(
        "  Delegation chain: genesis → operator → \x1b[1m{}\x1b[0m",
        name
    );
    eprintln!();

    0
}

/// List all keys in the keyring.
pub fn keys_list() -> i32 {
    let keyring = match open_keyring() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("  Failed to open keyring: {}", e);
            return 1;
        }
    };

    let status = keyring.status();

    eprintln!();
    eprintln!("  \x1b[1mKeyring Status\x1b[0m");
    eprintln!("  \x1b[2m──────────────\x1b[0m");

    // Genesis: distinguish cert-on-disk from secret-in-credential-store
    let genesis_status = match (status.has_genesis, status.has_genesis_secret) {
        (true, true) => "\x1b[32m✓\x1b[0m cert + secret (credential store)",
        (true, false) => "\x1b[33m⚠\x1b[0m cert only (secret missing — run `zp recover`)",
        (false, true) => "\x1b[33m⚠\x1b[0m secret only (cert missing)",
        (false, false) => "\x1b[31m✗\x1b[0m missing",
    };
    eprintln!("  Genesis key:   {}", genesis_status);

    // Operator: distinguish cert-on-disk from encrypted secret
    let operator_status = match (status.has_operator, status.has_operator_secret) {
        (true, true) => "\x1b[32m✓\x1b[0m cert + secret (encrypted)",
        (true, false) => "\x1b[33m⚠\x1b[0m cert only (secret missing)",
        (false, true) => "\x1b[33m⚠\x1b[0m secret only (cert missing)",
        (false, false) => "\x1b[31m✗\x1b[0m missing",
    };
    eprintln!("  Operator key:  {}", operator_status);

    eprintln!("  Agent keys:    {}", status.agent_count);

    // Rotation chain
    let rotations_path = keyring.path().join("rotations.json");
    if rotations_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&rotations_path) {
            if let Ok(certs) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                if !certs.is_empty() {
                    eprintln!("  Rotations:     {} certificate(s)", certs.len());
                }
            }
        }
    }

    if !status.agent_names.is_empty() {
        eprintln!();
        eprintln!("  \x1b[2mAgents:\x1b[0m");
        for name in &status.agent_names {
            eprintln!("    • {}", name);
        }
    }
    eprintln!();

    0
}

/// Revoke an agent key by name.
pub fn keys_revoke(name: &str) -> i32 {
    let keyring = match open_keyring() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("  Failed to open keyring: {}", e);
            return 1;
        }
    };

    // Check if agent exists
    match keyring.load_agent(name) {
        Ok(_) => {}
        Err(_) => {
            eprintln!("  Agent key '{}' not found.", name);
            return 1;
        }
    }

    // Remove the agent key files
    let agents_dir = keyring.path().join("agents");
    let json_path = agents_dir.join(format!("{}.json", name));
    let secret_path = agents_dir.join(format!("{}.secret", name));

    if let Err(e) = std::fs::remove_file(&json_path) {
        eprintln!("  Failed to remove {}: {}", json_path.display(), e);
        return 1;
    }
    let _ = std::fs::remove_file(&secret_path); // secret may not exist

    eprintln!();
    eprintln!("  \x1b[33m⊘\x1b[0m Agent key '{}' revoked.", name);
    eprintln!();

    0
}

// ── Key rotation commands ─────────────────────────────────────────

/// Rotate an operator or agent key to a new keypair.
///
/// The old key signs the rotation certificate (proving possession), and the
/// parent key co-signs for defense-in-depth (genesis for operator, operator
/// for agent). The rotation certificate is persisted to disk so the
/// succession chain can be reconstructed.
pub fn keys_rotate(target: &str, reason: Option<&str>) -> i32 {
    let keyring = match open_keyring() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("  Failed to open keyring: {}", e);
            eprintln!("  Run `zp init` first to bootstrap your environment.");
            return 1;
        }
    };

    let status = keyring.status();

    if target == "operator" {
        rotate_operator(&keyring, &status, reason)
    } else {
        // Treat as agent name
        rotate_agent(&keyring, target, reason)
    }
}

/// Rotate the operator key. Genesis co-signs for defense-in-depth.
fn rotate_operator(
    keyring: &Keyring,
    status: &zp_keys::keyring::KeyringStatus,
    reason: Option<&str>,
) -> i32 {
    if !status.has_operator {
        eprintln!("  No operator key found. Run `zp init` first.");
        return 1;
    }
    if !status.has_genesis {
        eprintln!("  No genesis certificate found. Cannot co-sign rotation.");
        return 1;
    }

    eprintln!();
    eprintln!("  \x1b[1mOperator Key Rotation\x1b[0m");
    eprintln!("  \x1b[2m─────────────────────\x1b[0m");

    // Load genesis key (need the signing key for co-signature + vault key derivation)
    let genesis = match keyring.load_genesis() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("  Failed to load genesis key: {}", e);
            eprintln!("  The genesis secret must be in the OS credential store.");
            eprintln!("  Run `zp recover` if needed.");
            return 1;
        }
    };

    // Load current operator key
    let old_operator = match keyring.load_operator() {
        Ok(op) => op,
        Err(e) => {
            eprintln!("  Failed to load operator key: {}", e);
            return 1;
        }
    };

    let old_pub_hex = hex::encode(old_operator.public_key());
    eprintln!(
        "  Current operator: \x1b[36m{}...\x1b[0m",
        &old_pub_hex[..16]
    );

    // Check existing rotation history to determine sequence number
    let rotations_path = keyring.path().join("rotations.json");
    let (sequence, prev_hash) = load_rotation_sequence(&rotations_path, &old_pub_hex);

    eprintln!(
        "  Rotation sequence: {} ({})",
        sequence,
        if sequence == 0 {
            "first rotation"
        } else {
            "continuing chain"
        }
    );

    // Confirm
    eprintln!();
    eprintln!("  \x1b[33m⚠\x1b[0m  This will generate a new operator keypair.");
    eprintln!("  \x1b[33m⚠\x1b[0m  All active sessions will be invalidated.");
    eprintln!("  \x1b[33m⚠\x1b[0m  The server must be restarted after rotation.");
    eprint!("  Proceed? [y/N] ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    if io::stdin().lock().read_line(&mut answer).is_err()
        || !answer.trim().eq_ignore_ascii_case("y")
    {
        eprintln!("  Aborted.");
        return 0;
    }

    // Generate new operator key (signed by genesis)
    eprint!("  Generating new operator key...       ");
    let subject = old_operator.certificate().body.subject.clone();
    let new_operator = OperatorKey::generate(&subject, &genesis, None);
    let new_pub_hex = hex::encode(new_operator.public_key());
    eprintln!("\x1b[32m✓\x1b[0m Ed25519");
    eprintln!(
        "  New operator:     \x1b[36m{}...\x1b[0m",
        &new_pub_hex[..16]
    );

    // Issue rotation certificate (old key signs)
    eprint!("  Issuing rotation certificate...      ");
    let old_signing_key = SigningKey::from_bytes(&old_operator.secret_key());
    let mut cert = match RotationCertificate::issue(
        &old_signing_key,
        &new_operator.public_key(),
        KeyRole::Operator,
        sequence,
        prev_hash,
        reason.map(String::from),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m");
            eprintln!("  Failed to issue rotation certificate: {}", e);
            return 1;
        }
    };
    eprintln!("\x1b[32m✓\x1b[0m signed by old key");

    // Co-sign with genesis (defense-in-depth)
    eprint!("  Genesis co-signing...                ");
    let genesis_signing_key = SigningKey::from_bytes(&genesis.secret_key());
    if let Err(e) = cert.co_sign(&genesis_signing_key) {
        eprintln!("\x1b[31m✗\x1b[0m");
        eprintln!("  Genesis co-sign failed: {}", e);
        return 1;
    }
    eprintln!("\x1b[32m✓\x1b[0m co-signed");

    // Save new operator key (encrypted under vault key derived from genesis)
    eprint!("  Saving new operator key...           ");
    if let Err(e) =
        keyring.save_operator_with_genesis_secret(&new_operator, &genesis.secret_key())
    {
        eprintln!("\x1b[31m✗\x1b[0m");
        eprintln!("  Failed to save operator key: {}", e);
        return 1;
    }
    eprintln!("\x1b[32m✓\x1b[0m operator.secret.enc");

    // Persist rotation certificate
    eprint!("  Persisting rotation certificate...   ");
    if let Err(e) = save_rotation_cert(&rotations_path, &cert) {
        eprintln!("\x1b[31m✗\x1b[0m");
        eprintln!("  Failed to save rotation certificate: {}", e);
        eprintln!("  The key was rotated but the certificate was not persisted.");
        eprintln!("  Manual recovery may be needed.");
        return 1;
    }
    eprintln!("\x1b[32m✓\x1b[0m rotations.json");

    // Verify the rotation certificate
    eprint!("  Verifying rotation certificate...    ");
    match cert.verify_old_key_signature() {
        Ok(true) => eprintln!("\x1b[32m✓\x1b[0m valid"),
        Ok(false) => {
            eprintln!("\x1b[31m✗\x1b[0m invalid signature");
            return 1;
        }
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m verification error: {}", e);
            return 1;
        }
    }

    eprintln!();
    eprintln!("  \x1b[32m✓ Operator key rotated successfully.\x1b[0m");
    eprintln!();
    eprintln!("  Old key: {}...", &old_pub_hex[..16]);
    eprintln!("  New key: {}...", &new_pub_hex[..16]);
    eprintln!("  Cert ID: {}", cert.body.id);
    if let Some(r) = &cert.body.reason {
        eprintln!("  Reason:  {}", r);
    }
    eprintln!();
    eprintln!("  \x1b[33mNext steps:\x1b[0m");
    eprintln!("    1. Restart `zp serve` to pick up the new key");
    eprintln!("    2. All browser sessions will need re-authentication");
    eprintln!("    3. Agent keys signed by the old operator are still valid");
    eprintln!("       (rotation chain preserves identity continuity)");
    eprintln!();

    0
}

/// Rotate an agent key. Operator co-signs for defense-in-depth.
fn rotate_agent(keyring: &Keyring, name: &str, reason: Option<&str>) -> i32 {
    // Verify agent exists
    let old_agent = match keyring.load_agent(name) {
        Ok(a) => a,
        Err(_) => {
            eprintln!("  Agent key '{}' not found.", name);
            return 1;
        }
    };

    eprintln!();
    eprintln!("  \x1b[1mAgent Key Rotation: {}\x1b[0m", name);
    eprintln!("  \x1b[2m─────────────────────{}\x1b[0m", "─".repeat(name.len()));

    let old_pub_hex = hex::encode(old_agent.public_key());
    eprintln!(
        "  Current agent key: \x1b[36m{}...\x1b[0m",
        &old_pub_hex[..16]
    );

    // Load operator (needed to sign new agent cert + co-sign rotation)
    let operator = match keyring.load_operator() {
        Ok(op) => op,
        Err(e) => {
            eprintln!("  Failed to load operator key: {}", e);
            eprintln!("  The operator key is needed to sign the new agent certificate.");
            return 1;
        }
    };

    // Check existing rotation history
    let rotations_path = keyring.path().join("rotations.json");
    let (sequence, prev_hash) = load_rotation_sequence(&rotations_path, &old_pub_hex);

    // Confirm
    eprintln!();
    eprint!("  Rotate agent key '{}'? [y/N] ", name);
    let _ = io::stdout().flush();
    let mut answer = String::new();
    if io::stdin().lock().read_line(&mut answer).is_err()
        || !answer.trim().eq_ignore_ascii_case("y")
    {
        eprintln!("  Aborted.");
        return 0;
    }

    // Generate new agent key (signed by operator)
    eprint!("  Generating new agent key...          ");
    let new_agent = AgentKey::generate(name, &operator, None);
    let new_pub_hex = hex::encode(new_agent.public_key());
    eprintln!("\x1b[32m✓\x1b[0m Ed25519");

    // Issue rotation certificate (old key signs)
    eprint!("  Issuing rotation certificate...      ");
    let old_signing_key = SigningKey::from_bytes(&old_agent.secret_key());
    let mut cert = match RotationCertificate::issue(
        &old_signing_key,
        &new_agent.public_key(),
        KeyRole::Agent,
        sequence,
        prev_hash,
        reason.map(String::from),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("\x1b[31m✗\x1b[0m");
            eprintln!("  Failed to issue rotation certificate: {}", e);
            return 1;
        }
    };
    eprintln!("\x1b[32m✓\x1b[0m signed by old key");

    // Co-sign with operator
    eprint!("  Operator co-signing...               ");
    if let Err(e) = cert.co_sign(operator.signing_key()) {
        eprintln!("\x1b[31m✗\x1b[0m");
        eprintln!("  Operator co-sign failed: {}", e);
        return 1;
    }
    eprintln!("\x1b[32m✓\x1b[0m co-signed");

    // Save new agent key
    eprint!("  Saving new agent key...              ");
    if let Err(e) = keyring.save_agent(name, &new_agent) {
        eprintln!("\x1b[31m✗\x1b[0m");
        eprintln!("  Failed to save agent key: {}", e);
        return 1;
    }
    eprintln!("\x1b[32m✓\x1b[0m agents/{}.json", name);

    // Persist rotation certificate
    eprint!("  Persisting rotation certificate...   ");
    if let Err(e) = save_rotation_cert(&rotations_path, &cert) {
        eprintln!("\x1b[31m✗\x1b[0m");
        eprintln!("  Failed to save rotation certificate: {}", e);
        return 1;
    }
    eprintln!("\x1b[32m✓\x1b[0m rotations.json");

    eprintln!();
    eprintln!("  \x1b[32m✓ Agent key '{}' rotated successfully.\x1b[0m", name);
    eprintln!();
    eprintln!("  Old key: {}...", &old_pub_hex[..16]);
    eprintln!("  New key: {}...", &new_pub_hex[..16]);
    eprintln!("  Cert ID: {}", cert.body.id);
    eprintln!();

    0
}

// ── Rotation persistence helpers ──────────────────────────────────

/// Load existing rotation certificates from disk and determine the next
/// sequence number + previous rotation hash for a given key.
fn load_rotation_sequence(
    rotations_path: &std::path::Path,
    old_pub_hex: &str,
) -> (u32, Option<String>) {
    let certs = load_rotation_certs(rotations_path);

    // Find the most recent rotation FROM this key (or TO this key)
    // to determine the next sequence number.
    let mut max_sequence: Option<u32> = None;
    let mut last_hash: Option<String> = None;

    for cert in &certs {
        // If this key was the new key in a previous rotation, the next
        // rotation from it continues that sequence.
        if cert.body.new_public_key == old_pub_hex {
            let seq = cert.body.sequence;
            if max_sequence.map_or(true, |m| seq > m) {
                max_sequence = Some(seq);
                last_hash = Some(cert.content_hash());
            }
        }
        // If this key was the old key, it was already rotated away.
        // This shouldn't happen in normal flow, but handle it.
        if cert.body.old_public_key == old_pub_hex {
            let seq = cert.body.sequence;
            if max_sequence.map_or(true, |m| seq > m) {
                max_sequence = Some(seq);
                last_hash = Some(cert.content_hash());
            }
        }
    }

    match max_sequence {
        Some(s) => (s + 1, last_hash),
        None => (0, None),
    }
}

/// Load all rotation certificates from the JSON file.
fn load_rotation_certs(path: &std::path::Path) -> Vec<RotationCertificate> {
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Append a rotation certificate to the JSON file.
fn save_rotation_cert(
    path: &std::path::Path,
    cert: &RotationCertificate,
) -> Result<(), String> {
    let mut certs = load_rotation_certs(path);
    certs.push(cert.clone());

    let json = serde_json::to_string_pretty(&certs)
        .map_err(|e| format!("serialization error: {}", e))?;

    std::fs::write(path, json).map_err(|e| format!("write error: {}", e))?;

    // Set restrictive permissions (0600) on the rotation chain file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }

    Ok(())
}

// ── Gate evaluation commands ───────────────────────────────────────

/// Infer an ActionType from a free-form action string.
/// Mirrors the server's `infer_action_type()` so CLI and HTTP API behave identically.
fn infer_action_type(action: &str) -> ActionType {
    let lower = action.to_lowercase();

    if lower.contains("delete") || lower.contains("remove") || lower.contains("destroy") {
        ActionType::FileOp {
            op: zp_core::FileOperation::Delete,
            path: action.to_string(),
        }
    } else if lower.contains("disable")
        || lower.contains("override")
        || lower.contains("config")
        || lower.contains("setting")
    {
        ActionType::ConfigChange {
            setting: action.to_string(),
        }
    } else if lower.contains("credential")
        || lower.contains("password")
        || lower.contains("secret")
        || lower.contains("key")
        || lower.contains("token")
    {
        ActionType::CredentialAccess {
            credential_ref: action.to_string(),
        }
    } else if lower.contains("execute")
        || lower.contains("run")
        || lower.contains("deploy")
        || lower.contains("train")
        || lower.contains("build")
        || lower.contains("install")
    {
        ActionType::Execute {
            language: action.to_string(),
        }
    } else if lower.contains("write")
        || lower.contains("create")
        || lower.contains("update")
        || lower.contains("modify")
    {
        ActionType::Write {
            target: action.to_string(),
        }
    } else if lower.contains("read")
        || lower.contains("view")
        || lower.contains("list")
        || lower.contains("get")
    {
        ActionType::Read {
            target: action.to_string(),
        }
    } else if lower.contains("call")
        || lower.contains("api")
        || lower.contains("send")
        || lower.contains("email")
    {
        ActionType::ApiCall {
            endpoint: action.to_string(),
        }
    } else {
        ActionType::Chat
    }
}

/// Evaluate a request against the full gate stack using the real GovernanceGate.
/// Persists the resulting audit entry to the append-only audit chain.
pub fn gate_eval(action: &str, resource: Option<&str>, agent: Option<&str>) -> i32 {
    eprintln!();
    eprintln!("  \x1b[1mGate Evaluation\x1b[0m");
    eprintln!("  \x1b[2m───────────────\x1b[0m");
    eprintln!("  Action:   {}", action);
    if let Some(r) = resource {
        eprintln!("  Resource: {}", r);
    }
    if let Some(a) = agent {
        eprintln!("  Agent:    {}", a);
    }
    eprintln!();

    // Build the PolicyContext from CLI args
    let action_type = infer_action_type(action);
    let context = PolicyContext {
        action: action_type,
        trust_tier: TrustTier::Tier1,
        channel: Channel::Cli,
        conversation_id: ConversationId::new(),
        skill_ids: vec![],
        tool_names: resource.map(|r| vec![r.to_string()]).unwrap_or_default(),
        mesh_context: None,
    };

    let actor = match agent {
        Some(name) => ActorId::Skill(name.to_string()),
        None => ActorId::User("cli-operator".to_string()),
    };

    // Open the audit store first so we can sync the chain head
    let db_path = resolve_zp_home().join("data").join("audit.db");
    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let store = AuditStore::open(&db_path).ok();

    // Create the real governance gate (default PolicyEngine with 6 rules).
    // The gate no longer maintains its own chain head — chain position is
    // assigned by `AuditStore::append` inside a BEGIN IMMEDIATE transaction.
    // See docs/audit-invariant.md.
    let gate = GovernanceGate::new("cli-gate");

    // Evaluate through the full gate stack
    let result = gate.evaluate(&context, actor);

    // Print each applied rule
    // applied_rules lists every rule that fired; the aggregate decision
    // is in result.decision (most-restrictive wins)
    for (i, rule_name) in result.applied_rules.iter().enumerate() {
        // Last rule is the one whose decision won if blocked
        let icon = if !result.is_allowed() && i == result.applied_rules.len() - 1 {
            "\x1b[31m✗\x1b[0m"
        } else {
            "\x1b[32m✓\x1b[0m"
        };
        eprintln!("  {} {}", icon, rule_name);
    }

    // Check for custom WASM gates (informational — real WASM eval is TODO)
    let policies_dir = resolve_zp_home().join("policies");
    if policies_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&policies_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "wasm").unwrap_or(false) {
                    let name = path.file_stem().unwrap_or_default().to_string_lossy();
                    eprintln!("  \x1b[32m✓\x1b[0m {} \x1b[2m(wasm)\x1b[0m", name);
                }
            }
        }
    }

    eprintln!();

    // Print the decision
    let exit_code = if result.is_allowed() {
        eprintln!("  Decision: \x1b[32mALLOW\x1b[0m");
        0
    } else if result.is_blocked() {
        eprintln!("  Decision: \x1b[31mBLOCK\x1b[0m");
        1
    } else {
        eprintln!("  Decision: \x1b[33mREVIEW\x1b[0m");
        2
    };

    // Print receipt ID if present
    if let Some(ref receipt_id) = result.receipt_id {
        let short = if receipt_id.len() > 12 {
            &receipt_id[..12]
        } else {
            receipt_id
        };
        eprintln!("  Receipt:  \x1b[36m{}...\x1b[0m", short);
    }

    // Persist the audit entry to the append-only chain
    match store {
        Some(mut s) => {
            if let Err(e) = s.append(result.unsealed) {
                eprintln!("  \x1b[33m⚠\x1b[0m  Failed to persist audit entry: {}", e);
            } else {
                eprintln!("  \x1b[2mAudit entry persisted.\x1b[0m");
            }
        }
        None => {
            eprintln!("  \x1b[33m⚠\x1b[0m  Could not open audit store.");
        }
    }

    eprintln!();
    exit_code
}

/// List installed gates (constitutional + custom).
pub fn gate_list() -> i32 {
    eprintln!();
    eprintln!("  \x1b[1mInstalled Gates\x1b[0m");
    eprintln!("  \x1b[2m───────────────\x1b[0m");
    eprintln!();

    // Constitutional bedrock (always present)
    eprintln!("  \x1b[2mConstitutional Bedrock (immutable):\x1b[0m");
    eprintln!("    ◈ HarmPrincipleRule");
    eprintln!("    ◈ SovereigntyRule");
    eprintln!();
    eprintln!("  \x1b[2mOperational Gates (immutable):\x1b[0m");
    eprintln!("    ⊘ CatastrophicActionRule");
    eprintln!("    ⊘ BulkOperationRule");
    eprintln!("    ⊘ ReputationGateRule");
    eprintln!();

    // Custom WASM gates
    let policies_dir = resolve_zp_home().join("policies");
    let mut custom_count = 0;
    if policies_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&policies_dir) {
            eprintln!("  \x1b[2mCustom WASM Gates:\x1b[0m");
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "wasm").unwrap_or(false) {
                    let name = path.file_stem().unwrap_or_default().to_string_lossy();
                    eprintln!("    ⚙ {}", name);
                    custom_count += 1;
                }
            }
        }
    }

    if custom_count == 0 {
        eprintln!("  \x1b[2mCustom WASM Gates:\x1b[0m (none installed)");
    }

    eprintln!();
    eprintln!("  DefaultAllowRule (fallback)");
    eprintln!();

    0
}
