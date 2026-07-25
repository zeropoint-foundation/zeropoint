//! Steward (Std) — Integrity officer.
//!
//! Domain: Chain integrity, vault coherence, configuration hygiene.
//! Reports structural facts. Doesn't make security judgments (Sentinel)
//! or operational judgments (Forge).

use chrono::Utc;
use serde_json::json;
use tracing::debug;

use crate::finding::{Finding, Severity};
use crate::officer::{ChainReader, Officer, VaultKeyLister};

/// The Steward officer — watches chain integrity and vault coherence.
pub struct Steward;

impl Steward {
    pub fn new() -> Self {
        Self
    }

    /// Check chain hash linkage and signature integrity.
    fn check_chain_integrity(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let report = match chain.verify() {
            Ok(r) => r,
            Err(e) => {
                return vec![Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "chain_verify_failed".into(),
                    severity: Severity::Error,
                    summary: format!("Chain verification could not run: {e}"),
                    detail: json!({"error": e.to_string()}),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                }];
            }
        };

        let mut findings = Vec::new();

        if report.chain_valid {
            // Note: signatures_valid is 0 on the fast path (verify_linkage_report
            // counts presence only; cryptographic verification is
            // ChainVerifier::verify's job). Text used to read "0/N signatures
            // valid" which read to consumers as "none are valid" — misleading.
            // Now reports presence explicitly and defers validity language to
            // the crypto layer. Regent misread the old text 2026-07-10 and
            // nearly invoked batch_sign in response.
            findings.push(Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "integrity_verified".into(),
                severity: Severity::Ok,
                summary: format!(
                    "Chain integrity verified: {} entries, {} hashes valid, {}/{} signatures present (cryptographic verification deferred to ChainVerifier)",
                    report.entries_examined,
                    report.hashes_valid,
                    report.signatures_present,
                    report.entries_examined,
                ),
                detail: json!({
                    "entries_examined": report.entries_examined,
                    "hashes_valid": report.hashes_valid,
                    "chain_links_valid": report.chain_links_valid,
                    "signatures_valid": report.signatures_valid,
                    "signatures_present": report.signatures_present,
                }),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            });
        } else {
            // Report each broken link individually
            for entry_report in &report.entries {
                if !entry_report.hash_valid {
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "hash_discontinuity".into(),
                        severity: Severity::Critical,
                        summary: format!(
                            "Hash mismatch at entry {}: recomputed hash differs from stored",
                            entry_report.entry_id
                        ),
                        detail: json!({
                            "entry_id": entry_report.entry_id,
                            "issue": entry_report.issue,
                        }),
                        timestamp: Utc::now(),
                        cross_domain_depth: 0,
                    });
                }
                if !entry_report.chain_link_valid {
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "chain_link_broken".into(),
                        severity: Severity::Critical,
                        summary: format!(
                            "Chain link broken at entry {}: prev_hash does not match prior entry",
                            entry_report.entry_id
                        ),
                        detail: json!({
                            "entry_id": entry_report.entry_id,
                            "issue": entry_report.issue,
                        }),
                        timestamp: Utc::now(),
                        cross_domain_depth: 0,
                    });
                }
                if entry_report.signature_valid == Some(false) {
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "signature_invalid".into(),
                        severity: Severity::Error,
                        summary: format!(
                            "Invalid signature on entry {}",
                            entry_report.entry_id
                        ),
                        detail: json!({
                            "entry_id": entry_report.entry_id,
                            "issue": entry_report.issue,
                        }),
                        timestamp: Utc::now(),
                        cross_domain_depth: 0,
                    });
                }
            }
        }

        // Unsigned entry ratio — if many entries lack signatures, that's notable
        if report.entries_examined > 0 {
            let unsigned_count = report.entries_examined - report.signatures_present;
            let unsigned_ratio = unsigned_count as f64 / report.entries_examined as f64;
            if unsigned_ratio > 0.1 && unsigned_count > 10 {
                findings.push(Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "unsigned_entry_ratio".into(),
                    severity: Severity::Warning,
                    summary: format!(
                        "{} of {} entries ({:.0}%) lack signatures",
                        unsigned_count,
                        report.entries_examined,
                        unsigned_ratio * 100.0,
                    ),
                    detail: json!({
                        "unsigned_count": unsigned_count,
                        "total_entries": report.entries_examined,
                        "unsigned_ratio": unsigned_ratio,
                    }),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                });
            }
        }

        findings
    }

    /// Check chain growth rate for anomalies.
    fn check_chain_growth(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        if entries.is_empty() {
            return vec![Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "chain_empty".into(),
                severity: Severity::Warning,
                summary: "Audit chain is empty".into(),
                detail: json!({}),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            }];
        }

        let mut findings = Vec::new();
        let now = Utc::now();

        // 2026-07-10 DIAGNOSTIC: Steward reporting chain_silence when chain is
        // active. Direct SQLite confirms recent_entries should return current
        // data. Log what we actually see so we can diagnose staleness source.
        tracing::info!(
            entries_returned = entries.len(),
            oldest_ts = entries.first().map(|e| e.timestamp.to_rfc3339()).unwrap_or_default(),
            newest_ts = entries.last().map(|e| e.timestamp.to_rfc3339()).unwrap_or_default(),
            now = %now.to_rfc3339(),
            "Steward chain_growth diagnostic: what did recent_entries(1000) see?"
        );

        // Check for suspicious silence — no entries in the last hour
        if let Some(newest) = entries.last() {
            let age = now - newest.timestamp;
            if age.num_hours() >= 1 {
                findings.push(Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "chain_silence".into(),
                    severity: Severity::Warning,
                    summary: format!(
                        "No chain entries in the last {} minutes",
                        age.num_minutes()
                    ),
                    detail: json!({
                        "last_entry_age_minutes": age.num_minutes(),
                        "last_entry_id": newest.id.0.to_string(),
                    }),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                });
            }
        }

        // Check for burst — more than 100 entries in the last 60 seconds
        let one_minute_ago = now - chrono::Duration::seconds(60);
        let burst_count = entries
            .iter()
            .filter(|e| e.timestamp >= one_minute_ago)
            .count();
        if burst_count > 100 {
            findings.push(Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "chain_burst".into(),
                severity: Severity::Warning,
                summary: format!("{burst_count} chain entries in the last 60 seconds"),
                detail: json!({
                    "burst_count": burst_count,
                    "window_seconds": 60,
                }),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            });
        }

        findings
    }

    /// Check vault key names for hygiene issues.
    fn check_vault_hygiene(&self, vault_keys: &VaultKeyLister) -> Vec<Finding> {
        let mut findings = Vec::new();
        let keys = vault_keys.all_keys();

        if keys.is_empty() {
            findings.push(Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "vault_empty".into(),
                severity: Severity::Info,
                summary: "Vault contains no entries".into(),
                detail: json!({}),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            });
            return findings;
        }

        // Check for suspicious patterns in key names that might indicate
        // leaked secrets (actual values used as key names).
        let suspicious_patterns = ["sk-", "sk_", "token_value", "password=", "secret="];
        for key in keys {
            for pattern in &suspicious_patterns {
                if key.to_lowercase().contains(pattern) {
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "suspicious_key_name".into(),
                        severity: Severity::Warning,
                        summary: format!(
                            "Vault key name '{}' contains pattern '{pattern}' — possible leaked secret in key name",
                            key
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

        // Check for empty namespaces (prefixes with no keys under them)
        // vs orphaned structure — keys without proper namespace prefix
        let namespaces = vault_keys.namespaces();
        let keys_without_namespace: Vec<&str> = keys
            .iter()
            .filter(|k| !k.contains('/'))
            .map(|k| k.as_str())
            .collect();

        if !keys_without_namespace.is_empty() {
            findings.push(Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "unnamespaced_keys".into(),
                severity: Severity::Info,
                summary: format!(
                    "{} vault keys lack a namespace prefix",
                    keys_without_namespace.len()
                ),
                detail: json!({
                    "count": keys_without_namespace.len(),
                    "keys": keys_without_namespace,
                }),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            });
        }

        // Summary finding
        findings.push(Finding {
            officer: self.name(),
            domain: self.domain(),
            finding_type: "vault_summary".into(),
            severity: Severity::Ok,
            summary: format!(
                "Vault: {} keys across {} namespaces",
                keys.len(),
                namespaces.len()
            ),
            detail: json!({
                "total_keys": keys.len(),
                "namespaces": namespaces,
            }),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        });

        findings
    }
}

impl Officer for Steward {
    fn name(&self) -> &'static str {
        "std"
    }

    fn domain(&self) -> &'static str {
        "integrity"
    }

    fn watch_patterns(&self) -> &[&'static str] {
        // Real-time triggers for Steward:
        // - Any chain entry could reveal hash discontinuity (but that's
        //   caught by verify, not per-entry). The primary real-time
        //   trigger is absence (caught by sweep, not watch).
        &[]
    }

    fn sweep(
        &self,
        chain: &ChainReader<'_>,
        vault_keys: &VaultKeyLister,
    ) -> Vec<Finding> {
        debug!("Steward sweep starting");

        let mut findings = Vec::new();

        findings.extend(self.check_chain_integrity(chain));
        findings.extend(self.check_chain_growth(chain));
        findings.extend(self.check_vault_hygiene(vault_keys));

        debug!(
            findings = findings.len(),
            "Steward sweep complete"
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
    fn steward_sweep_empty_chain() {
        let store = test_store();
        let chain = ChainReader::new(&store);
        let vault = VaultKeyLister::new(vec![]);
        let steward = Steward::new();

        let findings = steward.sweep(&chain, &vault);

        // Should produce chain_empty and vault_empty findings
        let types: Vec<&str> = findings.iter().map(|f| f.finding_type.as_str()).collect();
        assert!(types.contains(&"chain_empty"), "expected chain_empty finding, got: {types:?}");
    }

    #[test]
    fn steward_detects_suspicious_key_names() {
        let vault = VaultKeyLister::new(vec![
            "tools/ironclaw/api_key".into(),
            "providers/openai/sk-proj-abc123".into(), // suspicious
            "system/master_key".into(),
        ]);

        let store = test_store();
        let _chain = ChainReader::new(&store);
        let steward = Steward::new();

        let findings = steward.check_vault_hygiene(&vault);
        let suspicious: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "suspicious_key_name")
            .collect();

        assert_eq!(suspicious.len(), 1);
        assert!(suspicious[0].summary.contains("sk-"));
    }

    #[test]
    fn steward_reports_unnamespaced_keys() {
        let vault = VaultKeyLister::new(vec![
            "tools/ironclaw/key".into(),
            "orphan_key".into(), // no namespace
        ]);

        let store = test_store();
        let _chain = ChainReader::new(&store);
        let steward = Steward::new();

        let findings = steward.check_vault_hygiene(&vault);
        let unnamespaced: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == "unnamespaced_keys")
            .collect();

        assert_eq!(unnamespaced.len(), 1);
    }

    #[test]
    fn finding_event_key_format() {
        let f = Finding {
            officer: "std",
            domain: "integrity",
            finding_type: "hash_discontinuity".into(),
            severity: Severity::Critical,
            summary: "test".into(),
            detail: json!({}),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        };

        assert_eq!(f.event_key(), "officer:std:integrity:hash_discontinuity");
    }
}
