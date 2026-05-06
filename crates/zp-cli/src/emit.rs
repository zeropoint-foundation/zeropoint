//! `zp emit` — shell-callable receipt emission for orchestration hooks.
//!
//! This module provides the CLI surface for emitting signed receipts from
//! shell scripts, enabling Level 1 integration with any orchestration system
//! that exposes lifecycle hooks (Symphony, custom systems, CI pipelines).
//!
//! Usage examples:
//!   zp emit orchestrator:workspace:created --issue "PROJ-347" --agent "agent-12"
//!   zp emit orchestrator:run:authorized --issue "PROJ-347" --parent rcpt-abc123
//!   zp emit orchestrator:run:sealed --issue "PROJ-347" --meta exit_code=0
//!
//! Each invocation creates a signed ObservationClaim receipt, appends it to the
//! audit chain, and prints the receipt ID to stdout.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use sha2::{Sha256, Digest};
use uuid::Uuid;
use zp_audit::AuditStore;
use zp_audit::chain::UnsealedEntry;
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
use zp_receipt::{Receipt, Signer, Status};

use crate::commands::open_keyring;

/// Execute the `zp emit` command.
///
/// Creates a signed ObservationClaim receipt from the provided label and
/// metadata, appends it to the audit chain, and prints the receipt ID.
#[allow(clippy::too_many_arguments)]
pub fn run_emit(
    label: &str,
    issue_id: Option<&str>,
    agent_id: Option<&str>,
    parent_receipt_id: Option<&str>,
    upstream_genesis: Option<&str>,
    meta: &[(String, String)],
    audit_db: Option<&Path>,
    data_dir: &Path,
    json: bool,
) -> Result<()> {
    // Resolve audit store path
    let db_path = audit_db
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| data_dir.join("audit.db"));

    // Open keyring and get signing key — prefer agent key, fall back to operator
    let keyring = open_keyring().context("Failed to open keyring")?;
    let secret: [u8; 32] = if let Some(agent) = agent_id {
        match keyring.load_agent(agent) {
            Ok(k) => k.secret_key(),
            Err(_) => keyring
                .load_operator()
                .context("No signing key available — run `zp init` first")?
                .secret_key(),
        }
    } else {
        keyring
            .load_operator()
            .context("No operator key available — run `zp init` first")?
            .secret_key()
    };
    let signer = Signer::from_secret(&secret);

    // Build the receipt with extensions for orchestration metadata
    let executor_id = agent_id.unwrap_or("zp-cli");
    let mut builder = Receipt::observation(executor_id)
        .status(Status::Success)
        .extension(
            "zp.orchestrator.event",
            serde_json::Value::String(label.to_string()),
        );

    if let Some(issue) = issue_id {
        builder = builder.extension(
            "zp.orchestrator.issue_id",
            serde_json::Value::String(issue.to_string()),
        );
    }

    if let Some(agent) = agent_id {
        builder = builder.extension(
            "zp.orchestrator.agent_id",
            serde_json::Value::String(agent.to_string()),
        );
    }

    if let Some(upstream) = upstream_genesis {
        builder = builder.extension(
            "zp.orchestrator.upstream_genesis",
            serde_json::Value::String(upstream.to_string()),
        );
    }

    // Add user-supplied key=value metadata
    for (key, value) in meta {
        let ext_key = format!("zp.orchestrator.meta.{}", key);
        builder = builder.extension(
            &ext_key,
            serde_json::Value::String(value.clone()),
        );
    }

    if let Some(parent) = parent_receipt_id {
        builder = builder.parent(parent);
    }

    // Finalize the receipt (unsigned), then sign it
    let mut receipt = builder.finalize();
    signer.sign(&mut receipt);
    let receipt_id = receipt.id.clone();

    // Derive the audit signer from the Genesis secret
    let (genesis_secret, _) = keyring.load_genesis_secret()
        .context("Failed to load Genesis secret for audit signer")?;
    let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
    let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);

    // Open audit store and append
    let mut store = AuditStore::open_signed(&db_path, audit_signer)
        .context("Failed to open audit store")?;

    // Create a deterministic conversation ID from the issue ID so all receipts
    // for the same issue land in the same per-issue chain. Falls back to a
    // random UUID if no issue is specified.
    let conversation_id = if let Some(issue) = issue_id {
        // Deterministic UUID from SHA-256 of issue label (first 16 bytes → UUID v4 layout)
        let hash = Sha256::digest(format!("zp:issue:{}", issue).as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        // Set version (4) and variant (RFC 4122) bits
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        ConversationId(Uuid::from_bytes(bytes))
    } else {
        ConversationId::new()
    };

    let entry = UnsealedEntry::new(
        ActorId::System("zp-emit".to_string()),
        AuditAction::SystemEvent {
            event: format!("emit:{}", label),
        },
        conversation_id,
        PolicyDecision::Allow { conditions: vec![] },
        "zp-emit",
    )
    .with_receipt(receipt);

    store.append(entry).context("Failed to append to chain")?;

    // Output
    if json {
        println!(
            "{}",
            serde_json::json!({
                "receipt_id": receipt_id,
                "label": label,
                "issue_id": issue_id,
                "agent_id": agent_id,
                "parent_receipt_id": parent_receipt_id,
                "timestamp": Utc::now().to_rfc3339(),
            })
        );
    } else {
        println!("{}", receipt_id);
    }

    Ok(())
}
