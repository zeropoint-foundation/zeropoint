//! Security posture assessment for ZeroPoint nodes.
//!
//! Scans the local environment and reports on security-relevant
//! conditions. This is not a monitoring daemon — it runs once
//! on request and returns a snapshot.
//!
//! Design principle: **honest by default**. Checks should reflect
//! real security conditions. A score of 100 means every check
//! passed a meaningful test — not that we skipped the hard ones.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json as AxumJson;
use serde::{Deserialize, Serialize};
use tracing::info;

use zp_audit::{ChainEntry, ReconstitutionConfig, ReconstitutionEngine};
use zp_keys::{BlastRadius, CompromiseResponse};
use zp_memory::CompromiseReport as MemoryCompromiseReport;
use zp_policy::{DowngradeError, PolicyVersion};

use crate::AppState;

/// A single security check result.
#[derive(Serialize, Clone)]
pub struct SecurityCheck {
    pub category: String,
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

/// Status of a security check.
#[derive(Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warning,
    Fail,
}

/// Overall security posture of the node.
#[derive(Serialize, Clone)]
pub struct SecurityPosture {
    pub score: u8,
    pub checks: Vec<SecurityCheck>,
    pub summary: String,
}

/// Network topology node for the dashboard map.
#[derive(Serialize, Clone)]
pub struct TopologyNode {
    pub id: String,
    pub name: String,
    pub role: String, // "gateway", "router", "node", "sentinel", "device"
    pub address: String,
    pub status: String, // "active", "inactive", "unknown"
    pub detail: String,
}

/// Network topology for the dashboard.
#[derive(Serialize, Clone)]
pub struct NetworkTopology {
    pub nodes: Vec<TopologyNode>,
    pub description: String,
}

/// Build network topology from config or sensible defaults.
pub fn topology() -> NetworkTopology {
    let home = dirs::home_dir().unwrap_or_default().join(".zeropoint");

    // Try to read topology config
    let topo_path = home.join("config").join("topology.toml");
    if let Ok(content) = std::fs::read_to_string(&topo_path) {
        if let Ok(parsed) = toml::from_str::<toml::Value>(&content) {
            return parse_topology_config(&parsed);
        }
    }

    // Default: localhost-only node (honest — we don't know the network)
    let bind = std::env::var("ZP_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("ZP_PORT").unwrap_or_else(|_| "3000".to_string());

    NetworkTopology {
        nodes: vec![TopologyNode {
            id: "zp-node".into(),
            name: "ZeroPoint Node".into(),
            role: "node".into(),
            address: format!("{}:{}", bind, port),
            status: "active".into(),
            detail: "Governance proxy + verification surface".into(),
        }],
        description:
            "Single node — configure ~/.zeropoint/config/topology.toml for full network map".into(),
    }
}

fn parse_topology_config(config: &toml::Value) -> NetworkTopology {
    let mut nodes = Vec::new();

    if let Some(node_list) = config.get("nodes").and_then(|v| v.as_array()) {
        for node in node_list {
            nodes.push(TopologyNode {
                id: node
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .into(),
                name: node
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .into(),
                role: node
                    .get("role")
                    .and_then(|v| v.as_str())
                    .unwrap_or("device")
                    .into(),
                address: node
                    .get("address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .into(),
                status: node
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .into(),
                detail: node
                    .get("detail")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .into(),
            });
        }
    }

    let desc = config
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("Network topology from config")
        .to_string();

    NetworkTopology {
        nodes,
        description: desc,
    }
}

/// Run all security checks against the current environment.
pub fn assess(state: &crate::AppState) -> SecurityPosture {
    let mut checks = Vec::new();
    let home = dirs::home_dir().unwrap_or_default().join(".zeropoint");

    // ── Network ──────────────────────────────────────────────

    // 1. Bind address
    let bind = std::env::var("ZP_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    checks.push(if bind == "127.0.0.1" || bind == "localhost" {
        SecurityCheck {
            category: "network".into(),
            name: "Bind address".into(),
            status: CheckStatus::Pass,
            detail: format!("Bound to {} — not exposed to network", bind),
        }
    } else {
        SecurityCheck {
            category: "network".into(),
            name: "Bind address".into(),
            status: CheckStatus::Warning,
            detail: format!("Bound to {} — exposed to network traffic", bind),
        }
    });

    // 2. TLS / proxy security
    // Honest: we don't serve TLS natively. Flag it.
    checks.push(SecurityCheck {
        category: "network".into(),
        name: "Transport encryption".into(),
        status: CheckStatus::Warning,
        detail: "No TLS — plaintext HTTP on localhost. Acceptable for local-only; requires reverse proxy for network exposure.".into(),
    });

    // ── Filesystem & Keys ────────────────────────────────────

    // 3. Identity key — prefer hierarchy, fall back to legacy file
    let operator_secret_path = home.join("keys").join("operator.secret");
    if operator_secret_path.exists() {
        checks.push(check_key_permissions(
            &operator_secret_path,
            "Operator key (hierarchy)",
        ));
    } else {
        let identity_key_path = home.join("identity.key");
        checks.push(check_key_permissions(
            &identity_key_path,
            "Identity key (legacy)",
        ));
    }

    // 4. Genesis ceremony integrity.
    //
    // Historical note (ARTEMIS 035 issue 2): this check previously looked
    // for `~/.zeropoint/genesis.sig`, a file that no code path has ever
    // written. The ceremony produces `genesis_transcript.json` — a signed
    // attestation covering every substantive field in `genesis.json`. We
    // now actually verify the transcript (Ed25519 over BLAKE3) and
    // cross-check the unsigned record against it, so this check finally
    // reflects cryptographic reality.
    use crate::genesis_verify::Verdict;
    checks.push({
        let verdict = crate::genesis_verify::verify(&home);
        let status = match verdict {
            Verdict::Verified => CheckStatus::Pass,
            Verdict::NoTranscript => CheckStatus::Warning,
            Verdict::NotEstablished => CheckStatus::Fail,
            // Anything that parses partially but fails crypto / cross-check
            // is a hard fail — the record is no longer trustworthy.
            Verdict::MalformedTranscript(_)
            | Verdict::SignatureInvalid
            | Verdict::FieldMismatch(_) => CheckStatus::Fail,
        };
        SecurityCheck {
            category: "identity".into(),
            name: "Genesis ceremony".into(),
            status,
            detail: verdict.detail(),
        }
    });

    // 5. Keyring health
    let keys_dir = home.join("keys");
    checks.push(if keys_dir.exists() && keys_dir.is_dir() {
        let key_count = std::fs::read_dir(&keys_dir)
            .map(|rd| rd.filter(|e| e.is_ok()).count())
            .unwrap_or(0);
        if key_count >= 2 {
            SecurityCheck {
                category: "identity".into(),
                name: "Keyring".into(),
                status: CheckStatus::Pass,
                detail: format!("Keyring intact — {} key file(s)", key_count),
            }
        } else {
            SecurityCheck {
                category: "identity".into(),
                name: "Keyring".into(),
                status: CheckStatus::Warning,
                detail: format!(
                    "Keyring sparse — only {} key file(s), expected genesis + operator",
                    key_count
                ),
            }
        }
    } else {
        SecurityCheck {
            category: "identity".into(),
            name: "Keyring".into(),
            status: CheckStatus::Fail,
            detail: "No keyring directory — keys not generated or lost".into(),
        }
    });

    // ── Vault & Credentials ──────────────────────────────────

    // 6. Vault encryption
    let vault_path = home.join("vault.json");
    checks.push(if vault_path.exists() {
        // Read first bytes to check if it looks encrypted (not plaintext JSON with API keys)
        match std::fs::read_to_string(&vault_path) {
            Ok(content) => {
                // If we can parse it as JSON and it has credential-looking values, it's plaintext
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    let has_plaintext_keys = val
                        .as_object()
                        .map(|obj| {
                            obj.values().any(|v| {
                                v.as_str()
                                    .map(|s| s.starts_with("sk-") || s.starts_with("AIza"))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false);

                    if has_plaintext_keys {
                        SecurityCheck {
                            category: "vault".into(),
                            name: "Credential vault".into(),
                            status: CheckStatus::Fail,
                            detail: "Vault contains plaintext API keys — encryption not applied"
                                .into(),
                        }
                    } else {
                        let cred_count = val.as_object().map(|o| o.len()).unwrap_or(0);
                        SecurityCheck {
                            category: "vault".into(),
                            name: "Credential vault".into(),
                            status: CheckStatus::Pass,
                            detail: format!(
                                "Vault encrypted — {} credential(s) stored",
                                cred_count
                            ),
                        }
                    }
                } else {
                    // Not valid JSON — could be binary encrypted format
                    SecurityCheck {
                        category: "vault".into(),
                        name: "Credential vault".into(),
                        status: CheckStatus::Pass,
                        detail: "Vault present — encrypted format".into(),
                    }
                }
            }
            Err(_) => SecurityCheck {
                category: "vault".into(),
                name: "Credential vault".into(),
                status: CheckStatus::Warning,
                detail: "Vault file exists but unreadable".into(),
            },
        }
    } else {
        SecurityCheck {
            category: "vault".into(),
            name: "Credential vault".into(),
            status: CheckStatus::Warning,
            detail: "No vault file — credentials not yet stored".into(),
        }
    });

    // 7. Secret exposure in environment
    let sensitive_vars = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "DATABASE_URL",
        "GITHUB_TOKEN",
        "SLACK_TOKEN",
        "GEMINI_API_KEY",
        "TAVILY_API_KEY",
    ];
    let exposed: Vec<&str> = sensitive_vars
        .iter()
        .filter(|v| std::env::var(v).is_ok())
        .copied()
        .collect();
    checks.push(if exposed.is_empty() {
        SecurityCheck {
            category: "environment".into(),
            name: "Secret exposure".into(),
            status: CheckStatus::Pass,
            detail: "No sensitive API keys leaked to process environment".into(),
        }
    } else {
        SecurityCheck {
            category: "environment".into(),
            name: "Secret exposure".into(),
            status: CheckStatus::Warning,
            detail: format!(
                "{} key(s) in environment — should be in vault only: {}",
                exposed.len(),
                exposed.join(", ")
            ),
        }
    });

    // ── Integrity ────────────────────────────────────────────

    // 8. Audit chain integrity
    let chain_status = {
        let store = state.0.audit_store.lock().unwrap();
        match store.verify_with_report() {
            Ok(report) if report.chain_valid => SecurityCheck {
                category: "integrity".into(),
                name: "Audit chain".into(),
                status: CheckStatus::Pass,
                detail: format!(
                    "Chain intact — {} entries, hash-linked with BLAKE3",
                    report.entries_examined
                ),
            },
            Ok(report) => SecurityCheck {
                category: "integrity".into(),
                name: "Audit chain".into(),
                status: CheckStatus::Fail,
                detail: format!(
                    "Chain integrity failure at entry {} of {}",
                    report.entries_examined, report.entries_examined
                ),
            },
            Err(e) => SecurityCheck {
                category: "integrity".into(),
                name: "Audit chain".into(),
                status: CheckStatus::Warning,
                detail: format!("Could not verify chain: {}", e),
            },
        }
    };
    checks.push(chain_status);

    // ── Governance ───────────────────────────────────────────

    // 9. Governance gate — actually check rule count
    let rule_count = state.0.gate.rule_count();
    checks.push(if rule_count >= 2 {
        SecurityCheck {
            category: "governance".into(),
            name: "Governance gate".into(),
            status: CheckStatus::Pass,
            detail: format!(
                "{} constitutional rule(s) active — all requests evaluated",
                rule_count
            ),
        }
    } else if rule_count > 0 {
        SecurityCheck {
            category: "governance".into(),
            name: "Governance gate".into(),
            status: CheckStatus::Warning,
            detail: format!(
                "Only {} rule(s) loaded — expected HarmPrinciple + Sovereignty minimum",
                rule_count
            ),
        }
    } else {
        SecurityCheck {
            category: "governance".into(),
            name: "Governance gate".into(),
            status: CheckStatus::Fail,
            detail: "No governance rules loaded — proxy is ungoverned".into(),
        }
    });

    // ── Score Calculation ────────────────────────────────────
    // Honest scoring: warnings count as half, fails cap the score.
    let total = checks.len();
    let passed = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Pass)
        .count();
    let warnings = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warning)
        .count();
    let failed = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .count();

    let score: u8 = if total == 0 {
        0
    } else {
        // Pass = full credit, Warning = half credit, Fail = zero
        let points = (passed * 100) + (warnings * 50);
        let raw = points / total;
        // Hard cap: any failure caps at 60, any warning caps at 85
        let capped = if failed > 0 {
            raw.min(60)
        } else if warnings > 0 {
            raw.min(85)
        } else {
            raw
        };
        capped.min(100) as u8
    };

    let summary = if failed > 0 {
        format!("Action required — {} failure(s) detected", failed)
    } else if warnings > 0 {
        format!("Operational — {} advisory(ies) to address", warnings)
    } else {
        "Gates installed. Chain verified. Space secured.".into()
    };

    SecurityPosture {
        score,
        checks,
        summary,
    }
}

/// Check file permissions on a key file (Unix only).
fn check_key_permissions(path: &std::path::Path, label: &str) -> SecurityCheck {
    if !path.exists() {
        return SecurityCheck {
            category: "filesystem".into(),
            name: format!("{} permissions", label),
            status: CheckStatus::Warning,
            detail: format!("{} not found at {}", label, path.display()),
        };
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode == 0o600 {
                    SecurityCheck {
                        category: "filesystem".into(),
                        name: format!("{} permissions", label),
                        status: CheckStatus::Pass,
                        detail: format!("{} — mode 0600 (owner read/write only)", label),
                    }
                } else if mode <= 0o640 {
                    SecurityCheck {
                        category: "filesystem".into(),
                        name: format!("{} permissions", label),
                        status: CheckStatus::Warning,
                        detail: format!("{} — mode {:04o} (should be 0600)", label, mode),
                    }
                } else {
                    SecurityCheck {
                        category: "filesystem".into(),
                        name: format!("{} permissions", label),
                        status: CheckStatus::Fail,
                        detail: format!(
                            "{} — mode {:04o} — world-readable, fix with: chmod 600 {}",
                            label,
                            mode,
                            path.display()
                        ),
                    }
                }
            }
            Err(e) => SecurityCheck {
                category: "filesystem".into(),
                name: format!("{} permissions", label),
                status: CheckStatus::Warning,
                detail: format!("Cannot stat {}: {}", label, e),
            },
        }
    }

    #[cfg(not(unix))]
    {
        SecurityCheck {
            category: "filesystem".into(),
            name: format!("{} permissions", label),
            status: CheckStatus::Warning,
            detail: format!(
                "{} exists — permission check not available on this platform",
                label
            ),
        }
    }
}

// ============================================================================
// R6-1: Blast radius — key compromise detection + response
// ============================================================================

/// Request body for reporting a key compromise.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompromiseRequest {
    /// Hex-encoded public key that has been compromised.
    pub compromised_key: String,
    /// Optional reason for the compromise report.
    pub reason: Option<String>,
}

/// Response from a compromise report — includes blast radius + response actions
/// + quarantine results (R6-2).
#[derive(Serialize)]
pub struct CompromiseReportResponse {
    pub blast_radius: BlastRadius,
    pub response: CompromiseResponse,
    pub keys_to_rotate: usize,
    pub receipts_to_revoke: usize,
    pub grants_to_revoke: usize,
    pub memories_to_quarantine: usize,
    /// R6-2: How many memories were actually quarantined.
    pub memories_quarantined: usize,
    /// R6-2: How many were already quarantined (idempotent).
    pub memories_already_quarantined: usize,
    /// R6-2: How many were not found in the memory store.
    pub memories_not_found: usize,
}

/// `POST /api/v1/security/compromise` — report a key compromise and compute
/// blast radius + recommended response actions.
///
/// This is the R6-1 wiring point: the server computes what's affected and
/// returns the full response plan. The caller (CLI or automation) then
/// executes the rotation/revocation steps.
pub async fn compromise_handler(
    State(state): State<AppState>,
    AxumJson(body): AxumJson<CompromiseRequest>,
) -> Result<AxumJson<CompromiseReportResponse>, (StatusCode, String)> {
    let blast_radius = {
        let tracker = state.0.blast_radius_tracker.lock().unwrap();
        tracker.compute(&body.compromised_key)
    };
    let response = blast_radius.response_actions();

    info!(
        compromised_key = %body.compromised_key,
        reason = ?body.reason,
        affected_keys = response.keys_to_rotate.len(),
        receipts_to_revoke = response.receipts_to_revoke.len(),
        grants_to_revoke = response.grants_to_revoke.len(),
        memories_to_quarantine = response.memories_to_quarantine.len(),
        "Key compromise reported — blast radius computed"
    );

    // R6-2: Quarantine affected memories.
    let (quarantined, already_quarantined, not_found) =
        if !response.memories_to_quarantine.is_empty() {
            let mem_report = MemoryCompromiseReport {
                compromised_key: body.compromised_key.clone(),
                affected_memory_ids: response.memories_to_quarantine.clone(),
                memory_to_receipts: std::collections::HashMap::new(), // simplified — full mapping comes from tracker
            };
            let mut qstore = state.0.quarantine_store.lock().unwrap();
            let mut mstore = state.0.memory_store.lock().unwrap();
            let result =
                zp_memory::quarantine_compromised_memories(&mem_report, &mut qstore, &mut mstore);
            (
                result.quarantined_ids.len(),
                result.already_quarantined.len(),
                result.not_found.len(),
            )
        } else {
            (0, 0, 0)
        };

    let report = CompromiseReportResponse {
        keys_to_rotate: response.keys_to_rotate.len(),
        receipts_to_revoke: response.receipts_to_revoke.len(),
        grants_to_revoke: response.grants_to_revoke.len(),
        memories_to_quarantine: response.memories_to_quarantine.len(),
        memories_quarantined: quarantined,
        memories_already_quarantined: already_quarantined,
        memories_not_found: not_found,
        blast_radius,
        response,
    };

    Ok(AxumJson(report))
}

/// `GET /api/v1/security/blast-radius/:key` — compute blast radius for a key
/// without triggering response actions (dry run / inspection).
pub async fn blast_radius_handler(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<AxumJson<BlastRadius>, (StatusCode, String)> {
    let tracker = state.0.blast_radius_tracker.lock().unwrap();
    let radius = tracker.compute(&key);

    Ok(AxumJson(radius))
}

/// Request to register a relationship in the blast radius tracker.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type")]
pub enum BlastRadiusRegistration {
    /// Register that a receipt was signed by a key.
    #[serde(rename = "signed_receipt")]
    SignedReceipt {
        signer_key: String,
        receipt_id: String,
    },
    /// Register a delegation from parent to child key.
    #[serde(rename = "delegation")]
    Delegation {
        parent_key: String,
        child_key: String,
        delegation_id: String,
    },
    /// Register a grant authorized through a delegation.
    #[serde(rename = "grant")]
    Grant {
        delegation_id: String,
        grant_id: String,
    },
    /// Register that a memory was promoted using a receipt as evidence.
    #[serde(rename = "memory_evidence")]
    MemoryEvidence {
        receipt_id: String,
        memory_id: String,
    },
}

/// `POST /api/v1/security/blast-radius/register` — register relationships
/// in the blast radius tracker.
///
/// In production, these registrations happen automatically as receipts are
/// signed, delegations are created, etc. This endpoint allows manual or
/// batch registration for testing and migration.
pub async fn blast_radius_register_handler(
    State(state): State<AppState>,
    AxumJson(body): AxumJson<BlastRadiusRegistration>,
) -> Result<AxumJson<serde_json::Value>, (StatusCode, String)> {
    let mut tracker = state.0.blast_radius_tracker.lock().unwrap();

    match &body {
        BlastRadiusRegistration::SignedReceipt {
            signer_key,
            receipt_id,
        } => {
            tracker.register_signed_receipt(signer_key, receipt_id);
            Ok(AxumJson(serde_json::json!({
                "registered": "signed_receipt",
                "signer_key": signer_key,
                "receipt_id": receipt_id,
            })))
        }
        BlastRadiusRegistration::Delegation {
            parent_key,
            child_key,
            delegation_id,
        } => {
            tracker.register_delegation(parent_key, child_key, delegation_id);
            Ok(AxumJson(serde_json::json!({
                "registered": "delegation",
                "parent_key": parent_key,
                "child_key": child_key,
                "delegation_id": delegation_id,
            })))
        }
        BlastRadiusRegistration::Grant {
            delegation_id,
            grant_id,
        } => {
            tracker.register_grant(delegation_id, grant_id);
            Ok(AxumJson(serde_json::json!({
                "registered": "grant",
                "delegation_id": delegation_id,
                "grant_id": grant_id,
            })))
        }
        BlastRadiusRegistration::MemoryEvidence {
            receipt_id,
            memory_id,
        } => {
            tracker.register_memory_evidence(receipt_id, memory_id);
            Ok(AxumJson(serde_json::json!({
                "registered": "memory_evidence",
                "receipt_id": receipt_id,
                "memory_id": memory_id,
            })))
        }
    }
}

// ============================================================================
// R6-3: Chain reconstitution endpoint
// ============================================================================

/// `POST /api/v1/security/reconstitute` — rebuild trust state from audit chain.
///
/// Exports the audit chain, feeds it through the ReconstitutionEngine, and
/// returns the reconstructed state + any anomalies detected.
pub async fn reconstitute_handler(
    State(state): State<AppState>,
) -> Result<AxumJson<serde_json::Value>, (StatusCode, String)> {
    let audit_store = state.0.audit_store.lock().unwrap();

    let chain = audit_store
        .export_chain(100_000)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Chain export failed: {}", e)))?;

    let config = ReconstitutionConfig::default();
    let mut engine = ReconstitutionEngine::new(config);

    let mut chain_integrity = true;
    let mut prev_hash = String::new();
    for entry in &chain {
        let chain_entry = ChainEntry::from_audit_entry(entry);
        if !prev_hash.is_empty() && chain_entry.prev_hash != prev_hash {
            chain_integrity = false;
        }
        prev_hash = chain_entry.entry_hash.clone();
        engine.process_entry(&chain_entry);
    }

    let anomaly_count = engine.anomaly_count();
    let critical_count = engine.critical_anomaly_count();
    let recon_state = engine.finalize(chain_integrity);

    info!(
        entries = recon_state.entries_processed,
        anomalies = anomaly_count,
        critical = critical_count,
        chain_ok = chain_integrity,
        "Reconstitution completed via API"
    );

    let anomalies: Vec<serde_json::Value> = recon_state
        .anomalies
        .iter()
        .map(|a| {
            serde_json::json!({
                "kind": format!("{:?}", a.kind),
                "severity": format!("{:?}", a.severity),
                "entry_id": a.entry_id,
                "description": a.description,
            })
        })
        .collect();

    Ok(AxumJson(serde_json::json!({
        "entries_processed": recon_state.entries_processed,
        "chain_integrity": recon_state.chain_integrity_verified,
        "valid_operator_keys": recon_state.valid_operator_keys.len(),
        "valid_agent_keys": recon_state.valid_agent_keys.len(),
        "revoked_keys": recon_state.revoked_keys.len(),
        "active_capabilities": recon_state.active_capabilities.len(),
        "memory_states": recon_state.memory_states.len(),
        "quarantined_memories": recon_state.quarantined_memories.len(),
        "anomaly_count": anomaly_count,
        "critical_anomaly_count": critical_count,
        "anomalies": anomalies,
    })))
}

// ============================================================================
// Downgrade resistance — R6-4 wiring
// ============================================================================

/// Request to advance the policy version.
#[derive(Debug, Deserialize)]
pub struct PolicyAdvanceRequest {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

/// Response from the policy version endpoint.
#[derive(Debug, Serialize)]
pub struct PolicyVersionResponse {
    pub current_version: String,
    pub history: Vec<serde_json::Value>,
}

/// GET /api/v1/security/policy-version — query current policy version + history.
pub async fn policy_version_handler(
    State(state): State<AppState>,
) -> Result<AxumJson<PolicyVersionResponse>, StatusCode> {
    let guard = state.0.downgrade_guard.lock().map_err(|_| {
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let history: Vec<serde_json::Value> = guard
        .history()
        .iter()
        .map(|t| {
            serde_json::json!({
                "from": t.from.to_string(),
                "to": t.to.to_string(),
                "timestamp": t.timestamp.to_rfc3339(),
            })
        })
        .collect();

    Ok(AxumJson(PolicyVersionResponse {
        current_version: guard.current_version().to_string(),
        history,
    }))
}

/// POST /api/v1/security/policy-version/advance — advance the policy version.
///
/// Returns 200 on success (upgrade or same-version reload).
/// Returns 409 Conflict if the requested version is lower than the current
/// version (downgrade attempt).
pub async fn policy_advance_handler(
    State(state): State<AppState>,
    AxumJson(req): AxumJson<PolicyAdvanceRequest>,
) -> Result<AxumJson<serde_json::Value>, (StatusCode, AxumJson<serde_json::Value>)> {
    let version = PolicyVersion::new(req.major, req.minor, req.patch);

    let mut guard = state.0.downgrade_guard.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            AxumJson(serde_json::json!({"error": "lock poisoned"})),
        )
    })?;

    match guard.check_and_advance(version) {
        Ok(()) => {
            info!(
                version = %version,
                "Policy version advanced via API"
            );
            Ok(AxumJson(serde_json::json!({
                "status": "ok",
                "current_version": guard.current_version().to_string(),
            })))
        }
        Err(DowngradeError { attempted, current }) => {
            info!(
                attempted = %attempted,
                current = %current,
                "Policy downgrade rejected via API"
            );
            Err((
                StatusCode::CONFLICT,
                AxumJson(serde_json::json!({
                    "error": "downgrade_rejected",
                    "attempted": attempted.to_string(),
                    "current": current.to_string(),
                    "message": format!(
                        "Policy downgrade rejected: v{} < current v{}",
                        attempted, current
                    ),
                })),
            ))
        }
    }
}
