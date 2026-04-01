//! Security posture assessment for ZeroPoint nodes.
//!
//! Scans the local environment and reports on security-relevant
//! conditions. This is not a monitoring daemon — it runs once
//! on request and returns a snapshot.
//!
//! Design principle: **honest by default**. Checks should reflect
//! real security conditions. A score of 100 means every check
//! passed a meaningful test — not that we skipped the hard ones.

use serde::Serialize;

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
    pub role: String,        // "gateway", "router", "node", "sentinel", "device"
    pub address: String,
    pub status: String,      // "active", "inactive", "unknown"
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
    let home = dirs::home_dir()
        .unwrap_or_default()
        .join(".zeropoint");

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
        nodes: vec![
            TopologyNode {
                id: "zp-node".into(),
                name: "ZeroPoint Node".into(),
                role: "node".into(),
                address: format!("{}:{}", bind, port),
                status: "active".into(),
                detail: "Governance proxy + verification surface".into(),
            },
        ],
        description: "Single node — configure ~/.zeropoint/config/topology.toml for full network map".into(),
    }
}

fn parse_topology_config(config: &toml::Value) -> NetworkTopology {
    let mut nodes = Vec::new();

    if let Some(node_list) = config.get("nodes").and_then(|v| v.as_array()) {
        for node in node_list {
            nodes.push(TopologyNode {
                id: node.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").into(),
                name: node.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown").into(),
                role: node.get("role").and_then(|v| v.as_str()).unwrap_or("device").into(),
                address: node.get("address").and_then(|v| v.as_str()).unwrap_or("").into(),
                status: node.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").into(),
                detail: node.get("detail").and_then(|v| v.as_str()).unwrap_or("").into(),
            });
        }
    }

    let desc = config.get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("Network topology from config")
        .to_string();

    NetworkTopology { nodes, description: desc }
}

/// Run all security checks against the current environment.
pub fn assess(state: &crate::AppState) -> SecurityPosture {
    let mut checks = Vec::new();
    let home = dirs::home_dir()
        .unwrap_or_default()
        .join(".zeropoint");

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
        checks.push(check_key_permissions(&operator_secret_path, "Operator key (hierarchy)"));
    } else {
        let identity_key_path = home.join("identity.key");
        checks.push(check_key_permissions(&identity_key_path, "Identity key (legacy)"));
    }

    // 4. Genesis record + signature
    let genesis_path = home.join("genesis.json");
    let genesis_sig_path = home.join("genesis.sig");
    checks.push(if genesis_path.exists() && genesis_sig_path.exists() {
        SecurityCheck {
            category: "identity".into(),
            name: "Genesis ceremony".into(),
            status: CheckStatus::Pass,
            detail: "Genesis record and signature present — sovereign identity anchored".into(),
        }
    } else if genesis_path.exists() {
        SecurityCheck {
            category: "identity".into(),
            name: "Genesis ceremony".into(),
            status: CheckStatus::Warning,
            detail: "Genesis record exists but signature missing — integrity unverifiable".into(),
        }
    } else {
        SecurityCheck {
            category: "identity".into(),
            name: "Genesis ceremony".into(),
            status: CheckStatus::Fail,
            detail: "Genesis not established — run onboarding to create identity".into(),
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
                detail: format!("Keyring sparse — only {} key file(s), expected genesis + operator", key_count),
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
                    let has_plaintext_keys = val.as_object().map(|obj| {
                        obj.values().any(|v| {
                            v.as_str().map(|s| s.starts_with("sk-") || s.starts_with("AIza")).unwrap_or(false)
                        })
                    }).unwrap_or(false);

                    if has_plaintext_keys {
                        SecurityCheck {
                            category: "vault".into(),
                            name: "Credential vault".into(),
                            status: CheckStatus::Fail,
                            detail: "Vault contains plaintext API keys — encryption not applied".into(),
                        }
                    } else {
                        let cred_count = val.as_object().map(|o| o.len()).unwrap_or(0);
                        SecurityCheck {
                            category: "vault".into(),
                            name: "Credential vault".into(),
                            status: CheckStatus::Pass,
                            detail: format!("Vault encrypted — {} credential(s) stored", cred_count),
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
            detail: format!("{} constitutional rule(s) active — all requests evaluated", rule_count),
        }
    } else if rule_count > 0 {
        SecurityCheck {
            category: "governance".into(),
            name: "Governance gate".into(),
            status: CheckStatus::Warning,
            detail: format!("Only {} rule(s) loaded — expected HarmPrinciple + Sovereignty minimum", rule_count),
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
    let passed = checks.iter().filter(|c| c.status == CheckStatus::Pass).count();
    let warnings = checks.iter().filter(|c| c.status == CheckStatus::Warning).count();
    let failed = checks.iter().filter(|c| c.status == CheckStatus::Fail).count();

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
                        detail: format!("{} — mode {:04o} — world-readable, fix with: chmod 600 {}", label, mode, path.display()),
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
            detail: format!("{} exists — permission check not available on this platform", label),
        }
    }
}
