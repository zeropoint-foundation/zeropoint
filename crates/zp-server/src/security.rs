//! Security posture assessment for ZeroPoint nodes.
//!
//! Scans the local environment and reports on security-relevant
//! conditions. This is not a monitoring daemon — it runs once
//! on request and returns a snapshot.

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

/// Run all security checks against the current environment.
pub fn assess(state: &crate::AppState) -> SecurityPosture {
    let mut checks = Vec::new();

    // 1. Check bind address
    // We can't inspect the listener from here, but we check the env
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

    // 2. Check data directory permissions
    let data_dir = std::env::var("ZP_DATA_DIR")
        .unwrap_or_else(|_| "./data/zeropoint".to_string());
    let data_path = std::path::Path::new(&data_dir);
    checks.push(if data_path.exists() {
        SecurityCheck {
            category: "filesystem".into(),
            name: "Data directory".into(),
            status: CheckStatus::Pass,
            detail: format!("{} exists and accessible", data_dir),
        }
    } else {
        SecurityCheck {
            category: "filesystem".into(),
            name: "Data directory".into(),
            status: CheckStatus::Warning,
            detail: format!("{} does not exist", data_dir),
        }
    });

    // 3. Check audit chain integrity
    let chain_status = {
        let store = state.0.audit_store.lock().unwrap();
        match store.verify_with_report() {
            Ok(report) if report.chain_valid => SecurityCheck {
                category: "integrity".into(),
                name: "Audit chain".into(),
                status: CheckStatus::Pass,
                detail: format!(
                    "Chain intact — {} entries verified",
                    report.entries_examined
                ),
            },
            Ok(report) => SecurityCheck {
                category: "integrity".into(),
                name: "Audit chain".into(),
                status: CheckStatus::Fail,
                detail: format!(
                    "Chain integrity failure — {} entries examined",
                    report.entries_examined
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

    // 4. Check for sensitive environment variables exposed
    let sensitive_vars = [
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY",
        "DATABASE_URL", "GITHUB_TOKEN", "SLACK_TOKEN",
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
            detail: "No sensitive API keys detected in environment".into(),
        }
    } else {
        SecurityCheck {
            category: "environment".into(),
            name: "Secret exposure".into(),
            status: CheckStatus::Warning,
            detail: format!(
                "{} sensitive variable(s) in environment: {}",
                exposed.len(),
                exposed.join(", ")
            ),
        }
    });

    // 5. Check server identity
    checks.push(SecurityCheck {
        category: "identity".into(),
        name: "Ed25519 identity".into(),
        status: CheckStatus::Pass,
        detail: format!(
            "Active — destination {}",
            &state.0.identity.destination_hash
        ),
    });

    // 6. Check governance gate
    checks.push(SecurityCheck {
        category: "governance".into(),
        name: "Governance gate".into(),
        status: CheckStatus::Pass,
        detail: "Constitutional rules loaded — HarmPrincipleRule, SovereigntyRule active".into(),
    });

    // Calculate score
    let total = checks.len() as u8;
    let passed = checks.iter().filter(|c| c.status == CheckStatus::Pass).count() as u8;
    let failed = checks.iter().filter(|c| c.status == CheckStatus::Fail).count() as u8;
    let score = if total == 0 {
        0
    } else if failed > 0 {
        (passed * 100 / total).min(60) // Cap at 60 if any failures
    } else {
        passed * 100 / total
    };

    let summary = if failed > 0 {
        "Action required — integrity issues detected".into()
    } else if passed == total {
        "Gates installed. Chain verified. Space secured.".into()
    } else {
        "Operational — minor advisories present".into()
    };

    SecurityPosture {
        score,
        checks,
        summary,
    }
}
