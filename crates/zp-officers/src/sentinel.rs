//! Sentinel (Sen) — Security officer.
//!
//! Domain: Credential lifecycle, authentication integrity, access anomalies.
//! Proposes rotation and revocation. Never executes either.
//!
//! Watches the chain for gate denial patterns, delegation health, and
//! identity coherence. Watches vault key names for credential hygiene
//! (freshness signals, plaintext leak patterns). Reports security facts.
//! Doesn't make integrity judgments (Steward) or operational judgments (Forge).

use std::collections::HashMap;

use chrono::Utc;
use serde_json::json;
use tracing::debug;

use crate::finding::{Finding, Severity};
use crate::officer::{ChainReader, Officer, VaultKeyLister};
use zp_core::{AuditAction, AuditEntry};

/// The Sentinel officer — watches credential lifecycle, auth integrity,
/// and access anomalies.
pub struct Sentinel;

impl Sentinel {
    pub fn new() -> Self {
        Self
    }

    /// Analyze gate denial patterns for clusters or anomalies.
    ///
    /// Looks for:
    /// - High denial rate (more denials than allows)
    /// - Denial clusters (3+ denials in 60 seconds)
    /// - Repeated denials for the same actor (identity coherence issue)
    fn check_gate_denial_patterns(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        let mut denied_entries: Vec<&AuditEntry> = Vec::new();
        let mut allowed_count = 0usize;
        let mut denied_by_actor: HashMap<String, usize> = HashMap::new();

        for entry in &entries {
            if let AuditAction::SystemEvent { event } = &entry.action {
                if event.starts_with("gate:denied:") {
                    denied_entries.push(entry);
                    let actor = actor_label(&entry.actor);
                    *denied_by_actor.entry(actor).or_insert(0) += 1;
                } else if event.starts_with("gate:allowed:") {
                    allowed_count += 1;
                }
            }
        }

        let denied_count = denied_entries.len();
        let total = denied_count + allowed_count;

        // High denial rate
        if total > 10 && denied_count > allowed_count {
            let ratio = denied_count as f64 / total as f64;
            findings.push(Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "high_denial_rate".into(),
                severity: Severity::Warning,
                summary: format!(
                    "Gate denial rate {:.0}%: {} denied of {} total decisions",
                    ratio * 100.0,
                    denied_count,
                    total
                ),
                detail: json!({
                    "denied": denied_count,
                    "allowed": allowed_count,
                    "ratio": ratio,
                }),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            });
        }

        // Denial clusters — 3+ within 60 seconds
        if denied_entries.len() >= 3 {
            let mut cluster_start = 0usize;
            for i in 2..denied_entries.len() {
                let window = denied_entries[i].timestamp - denied_entries[cluster_start].timestamp;
                if window.num_seconds() <= 60 {
                    // We have at least 3 in 60s
                    let cluster_size = i - cluster_start + 1;
                    if cluster_size >= 3 {
                        findings.push(Finding {
                            officer: self.name(),
                            domain: self.domain(),
                            finding_type: "denial_cluster".into(),
                            severity: Severity::Warning,
                            summary: format!(
                                "{} gate denials within 60 seconds — possible access anomaly",
                                cluster_size
                            ),
                            detail: json!({
                                "cluster_size": cluster_size,
                                "window_seconds": 60,
                                "first_timestamp": denied_entries[cluster_start].timestamp.to_rfc3339(),
                                "last_timestamp": denied_entries[i].timestamp.to_rfc3339(),
                            }),
                            timestamp: Utc::now(),
                            cross_domain_depth: 0,
                        });
                        break; // One cluster finding per sweep
                    }
                } else {
                    cluster_start = i - 1;
                }
            }
        }

        // Repeated denials for the same actor
        for (actor, count) in &denied_by_actor {
            if *count >= 5 {
                findings.push(Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "repeated_actor_denial".into(),
                    severity: Severity::Warning,
                    summary: format!(
                        "Actor '{}' denied {} times — possible identity coherence issue",
                        actor, count
                    ),
                    detail: json!({
                        "actor": actor,
                        "denial_count": count,
                    }),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                });
            }
        }

        findings
    }

    /// Check delegation health: orphaned grants, high revocation rate.
    fn check_delegation_health(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        let mut active_grants: HashMap<String, usize> = HashMap::new();
        let mut revocations = 0usize;
        let mut total_grants = 0usize;

        for entry in &entries {
            if let AuditAction::SystemEvent { event } = &entry.action {
                if let Some(subject) = event.strip_prefix("delegation:granted:") {
                    *active_grants.entry(subject.to_string()).or_insert(0) += 1;
                    total_grants += 1;
                } else if let Some(subject) = event.strip_prefix("delegation:revoked:") {
                    active_grants.remove(subject);
                    revocations += 1;
                } else if let Some(subject) = event.strip_prefix("delegation:expired:") {
                    active_grants.remove(subject);
                }
            }
        }

        // High revocation ratio — security concern if many grants get revoked
        if total_grants > 5 && revocations > 0 {
            let ratio = revocations as f64 / total_grants as f64;
            if ratio > 0.5 {
                findings.push(Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "high_revocation_rate".into(),
                    severity: Severity::Info,
                    summary: format!(
                        "{} of {} delegations revoked ({:.0}%) — review delegation lifecycle",
                        revocations,
                        total_grants,
                        ratio * 100.0
                    ),
                    detail: json!({
                        "revocations": revocations,
                        "total_grants": total_grants,
                        "ratio": ratio,
                    }),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                });
            }
        }

        // Multiple active grants for the same subject — possible scope creep
        for (subject, count) in &active_grants {
            if *count > 3 {
                findings.push(Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "delegation_accumulation".into(),
                    severity: Severity::Warning,
                    summary: format!(
                        "Subject '{}' has {} active delegation grants — possible scope creep",
                        subject, count
                    ),
                    detail: json!({
                        "subject": subject,
                        "grant_count": count,
                    }),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                });
            }
        }

        findings
    }

    /// Check vault keys for credential hygiene concerns.
    ///
    /// Focuses on security-relevant signals that Steward doesn't cover:
    /// - Credential naming patterns suggesting plaintext leaks
    /// - Missing expected credential namespaces
    /// - Duplicate credentials across namespaces (shadow keys)
    fn check_credential_hygiene(&self, vault_keys: &VaultKeyLister) -> Vec<Finding> {
        let mut findings = Vec::new();
        let keys = vault_keys.all_keys();

        if keys.is_empty() {
            return findings;
        }

        // Check for plaintext secret patterns in key names (beyond Steward's
        // suspicious_patterns — Sentinel looks for full credential values)
        let credential_patterns = [
            "sk-ant-",  // Anthropic API key
            "sk-proj-", // OpenAI project API key
            "ghp_",     // GitHub personal access token
            "gho_",     // GitHub OAuth token
            "glpat-",   // GitLab personal access token
            "xoxb-",    // Slack bot token
            "xoxp-",    // Slack user token
            "AKIA",     // AWS access key
            "eyJ",      // JWT prefix (base64 of {"...)
            "-----BEGIN", // PEM key material
        ];

        for key in keys {
            for pattern in &credential_patterns {
                if key.contains(pattern) {
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "credential_in_key_name".into(),
                        severity: Severity::Error,
                        summary: format!(
                            "Vault key name contains credential pattern '{}' — likely plaintext secret stored as key name",
                            pattern
                        ),
                        detail: json!({
                            "key": key,
                            "pattern": pattern,
                        }),
                        timestamp: Utc::now(),
                        cross_domain_depth: 0,
                    });
                }
            }
        }

        // Check for shadow keys — same variable name under different namespaces
        let mut var_names: HashMap<String, Vec<String>> = HashMap::new();
        for key in keys {
            if let Some(var_name) = key.rsplit('/').next() {
                var_names
                    .entry(var_name.to_string())
                    .or_default()
                    .push(key.to_string());
            }
        }

        for (var, paths) in &var_names {
            if paths.len() > 1 {
                // Only flag if they're under different namespace prefixes
                let namespaces: std::collections::HashSet<&str> = paths
                    .iter()
                    .filter_map(|p| p.rsplit_once('/').map(|(ns, _)| ns))
                    .collect();
                if namespaces.len() > 1 {
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "shadow_credential".into(),
                        severity: Severity::Warning,
                        summary: format!(
                            "Variable '{}' exists under {} namespaces — possible credential drift",
                            var,
                            namespaces.len()
                        ),
                        detail: json!({
                            "variable": var,
                            "paths": paths,
                            "namespaces": namespaces.iter().collect::<Vec<_>>(),
                        }),
                        timestamp: Utc::now(),
                        cross_domain_depth: 0,
                    });
                }
            }
        }

        findings
    }

    /// Scan chain entries for plaintext secrets leaked into receipts.
    fn check_chain_secret_leaks(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(500) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        let secret_patterns = ["sk-ant-", "sk-proj-", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA"];

        for entry in &entries {
            // Check the receipt detail (serialized metadata) for secrets
            if let Some(receipt) = &entry.receipt {
                let receipt_str = serde_json::to_string(receipt).unwrap_or_default();
                for pattern in &secret_patterns {
                    if receipt_str.contains(pattern) {
                        findings.push(Finding {
                            officer: self.name(),
                            domain: self.domain(),
                            finding_type: "secret_in_chain".into(),
                            severity: Severity::Critical,
                            summary: format!(
                                "Possible plaintext secret (pattern '{}') found in chain entry {}",
                                pattern,
                                entry.id.0
                            ),
                            detail: json!({
                                "entry_id": entry.id.0.to_string(),
                                "pattern": pattern,
                                "timestamp": entry.timestamp.to_rfc3339(),
                            }),
                            timestamp: Utc::now(),
                            cross_domain_depth: 0,
                        });
                        break; // One finding per entry, even if multiple patterns match
                    }
                }
            }
        }

        findings
    }
}

/// Extract a human-readable label from an ActorId.
fn actor_label(actor: &zp_core::ActorId) -> String {
    match actor {
        zp_core::ActorId::System(s) => s.clone(),
        zp_core::ActorId::User(u) => u.clone(),
        _ => "unknown".into(),
    }
}

impl Officer for Sentinel {
    fn name(&self) -> &'static str {
        "sen"
    }

    fn domain(&self) -> &'static str {
        "security"
    }

    fn watch_patterns(&self) -> &[&'static str] {
        &[
            "gate:denied:",
            "delegation:revoked:",
            "delegation:expired:",
        ]
    }

    fn sweep(
        &self,
        chain: &ChainReader<'_>,
        vault_keys: &VaultKeyLister,
    ) -> Vec<Finding> {
        debug!("Sentinel sweep starting");

        let mut findings = Vec::new();

        findings.extend(self.check_gate_denial_patterns(chain));
        findings.extend(self.check_delegation_health(chain));
        findings.extend(self.check_credential_hygiene(vault_keys));
        findings.extend(self.check_chain_secret_leaks(chain));

        debug!(
            findings = findings.len(),
            "Sentinel sweep complete"
        );

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::officer::{ChainReader, VaultKeyLister};
    use zp_audit::store::AuditStore;

    fn test_store() -> AuditStore {
        AuditStore::open_readonly(":memory:").expect("open in-memory store")
    }

    #[test]
    fn sentinel_trait_impl() {
        let sen = Sentinel::new();
        assert_eq!(sen.name(), "sen");
        assert_eq!(sen.domain(), "security");
        assert!(!sen.watch_patterns().is_empty());
        assert!(sen.watch_patterns().contains(&"gate:denied:"));
    }

    #[test]
    fn sentinel_sweep_empty_chain() {
        let store = test_store();
        let chain = ChainReader::new(&store);
        let vault = VaultKeyLister::new(vec![]);
        let sen = Sentinel::new();

        let findings = sen.sweep(&chain, &vault);
        // Empty chain + empty vault = no findings
        assert!(findings.is_empty());
    }

    #[test]
    fn sentinel_detects_credential_in_key_name() {
        let vault = VaultKeyLister::new(vec![
            "tools/ironclaw/api_key".into(),
            "providers/anthropic/sk-ant-api03-real-key-value".into(), // leaked credential
            "tools/github/ghp_1234567890abcdef".into(),              // leaked GitHub token
        ]);

        let sen = Sentinel::new();
        let findings = sen.check_credential_hygiene(&vault);

        let leaks: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "credential_in_key_name")
            .collect();

        assert_eq!(leaks.len(), 2);
        assert!(leaks.iter().any(|f| f.summary.contains("sk-ant-")));
        assert!(leaks.iter().any(|f| f.summary.contains("ghp_")));
    }

    #[test]
    fn sentinel_detects_shadow_credentials() {
        let vault = VaultKeyLister::new(vec![
            "tools/ironclaw/API_KEY".into(),
            "providers/tools/ironclaw/API_KEY".into(), // shadow
        ]);

        let sen = Sentinel::new();
        let findings = sen.check_credential_hygiene(&vault);

        let shadows: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "shadow_credential")
            .collect();

        assert_eq!(shadows.len(), 1);
        assert!(shadows[0].summary.contains("API_KEY"));
    }

    #[test]
    fn finding_event_key_format() {
        let f = Finding {
            officer: "sen",
            domain: "security",
            finding_type: "denial_cluster".into(),
            severity: Severity::Warning,
            summary: "test".into(),
            detail: json!({}),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        };

        assert_eq!(f.event_key(), "officer:sen:security:denial_cluster");
    }
}
