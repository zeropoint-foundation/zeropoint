//! Sweep runner — periodic and real-time officer activation with loop prevention.

use std::collections::HashSet;
use std::time::Instant;

use chrono::{DateTime, Utc};
use tracing::{debug, info};

use crate::finding::Finding;
use crate::officer::{ChainReader, Officer, VaultKeyLister};
use crate::posture::PostureScore;
use zp_core::AuditEntry;

/// Maximum cross-domain propagation depth. A finding at depth 2 will
/// not trigger further officer activations.
const MAX_CROSS_DOMAIN_DEPTH: u32 = 2;

/// Tracks state within a single sweep cycle for loop prevention.
pub struct SweepCycle {
    /// Findings already emitted this cycle, keyed by (officer_name, finding_type).
    emitted: HashSet<(String, String)>,
}

impl SweepCycle {
    pub fn new() -> Self {
        Self {
            emitted: HashSet::new(),
        }
    }

    /// Record that an officer emitted a finding of this type.
    pub fn record_emission(&mut self, officer: &str, finding_type: &str) {
        self.emitted
            .insert((officer.to_string(), finding_type.to_string()));
    }

    /// Check if this officer already emitted this finding type this cycle.
    pub fn has_emitted(&self, officer: &str, finding_type: &str) -> bool {
        self.emitted
            .contains(&(officer.to_string(), finding_type.to_string()))
    }
}

/// Extract the event string from an audit entry's action, if it's a SystemEvent.
fn extract_event(entry: &AuditEntry) -> Option<&str> {
    match &entry.action {
        zp_core::AuditAction::SystemEvent { event } => Some(event.as_str()),
        _ => None,
    }
}

/// Determines whether a chain entry should be dispatched to an officer.
///
/// Three rules prevent infinite loops:
/// 1. Self-skip: never dispatch an officer's own receipts back to itself.
/// 2. Depth cap: entries with `cross_domain_depth >= MAX_CROSS_DOMAIN_DEPTH` stop.
/// 3. Dedup: one finding per type per cycle per officer.
pub fn should_dispatch(
    entry: &AuditEntry,
    officer: &dyn Officer,
    cycle: &SweepCycle,
) -> bool {
    // Extract the event string from the SystemEvent action, if present.
    let event = match extract_event(entry) {
        Some(e) => e,
        None => return true, // Non-SystemEvent entries are always dispatchable.
    };

    // Rule 1: never dispatch an officer's own receipts back to itself.
    let self_prefix = format!("officer:{}:", officer.name());
    if event.starts_with(&self_prefix) {
        return false;
    }

    // Rule 2: check cross-domain depth from receipt detail.
    if let Some(receipt) = &entry.receipt {
        // Officer findings embed cross_domain_depth in receipt extensions.
        if let Some(exts) = &receipt.extensions {
            if let Some(depth_val) = exts.get("cross_domain_depth") {
                if depth_val.as_u64().unwrap_or(0) >= MAX_CROSS_DOMAIN_DEPTH as u64 {
                    return false;
                }
            }
        }
    }

    // Rule 3: check dedup — extract finding_type from receipt extensions.
    if let Some(receipt) = &entry.receipt {
        if let Some(exts) = &receipt.extensions {
            if let Some(finding_type) = exts.get("finding_type") {
                if let Some(ft) = finding_type.as_str() {
                    if cycle.has_emitted(officer.name(), ft) {
                        return false;
                    }
                }
            }
        }
    }

    true
}

/// Per-officer result from a single sweep cycle.
///
/// Used by the caller (`officers.rs`) to emit per-officer heartbeat receipts.
/// Each officer speaks for itself independently on the chain.
pub struct OfficerSweepResult {
    pub officer_name: &'static str,
    pub findings: Vec<Finding>,
    pub sweep_duration_ms: u64,
}

/// Result of running a full sweep cycle.
pub struct SweepResult {
    /// All findings from all officers this cycle (aggregate).
    pub findings: Vec<Finding>,
    /// Per-officer breakdown — used for heartbeat emission.
    pub per_officer: Vec<OfficerSweepResult>,
    /// Posture score computed from findings.
    pub posture: PostureScore,
    /// When this sweep completed.
    pub completed_at: DateTime<Utc>,
}

/// Run a full sweep cycle across all officers.
///
/// This is the main entry point called by the periodic timer.
/// It runs each officer's sweep, applies loop prevention, computes
/// posture score, and returns everything for the caller to emit
/// as chain receipts.
pub fn run_sweep(
    officers: &[Box<dyn Officer>],
    chain: &ChainReader<'_>,
    vault_keys: &VaultKeyLister,
) -> SweepResult {
    let mut cycle = SweepCycle::new();
    let mut all_findings = Vec::new();
    let mut per_officer: Vec<OfficerSweepResult> = Vec::new();

    for officer in officers {
        debug!(officer = officer.name(), "Running sweep");

        let t0 = Instant::now();
        let findings = officer.sweep(chain, vault_keys);
        let sweep_duration_ms = t0.elapsed().as_millis() as u64;

        let mut officer_findings = Vec::new();
        for finding in findings {
            cycle.record_emission(finding.officer, &finding.finding_type);
            officer_findings.push(finding);
        }

        // Clone into aggregate before moving into per_officer.
        for f in &officer_findings {
            all_findings.push(f.clone());
        }

        per_officer.push(OfficerSweepResult {
            officer_name: officer.name(),
            findings: officer_findings,
            sweep_duration_ms,
        });
    }

    let posture = PostureScore::compute(&all_findings);

    info!(
        officers = officers.len(),
        findings = all_findings.len(),
        posture_composite = format!("{:.2}", posture.composite),
        "Sweep cycle complete"
    );

    SweepResult {
        findings: all_findings,
        per_officer,
        posture,
        completed_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cleo::Cleo;
    use crate::forge::Forge;
    use crate::sentinel::Sentinel;
    use crate::steward::Steward;
    use zp_audit::store::AuditStore;

    #[test]
    fn sweep_cycle_dedup() {
        let mut cycle = SweepCycle::new();

        assert!(!cycle.has_emitted("std", "hash_discontinuity"));
        cycle.record_emission("std", "hash_discontinuity");
        assert!(cycle.has_emitted("std", "hash_discontinuity"));

        // Different officer, same finding type — not deduped.
        assert!(!cycle.has_emitted("sen", "hash_discontinuity"));
    }

    #[test]
    fn run_sweep_with_steward() {
        let store = AuditStore::open_readonly(":memory:").expect("open store");
        let chain = ChainReader::new(&store);
        let vault = VaultKeyLister::new(vec!["tools/test/key".into()]);

        let officers: Vec<Box<dyn Officer>> = vec![Box::new(Steward::new())];

        let result = run_sweep(&officers, &chain, &vault);

        // Should have at least the chain/vault summary findings.
        assert!(!result.findings.is_empty());
        // Posture should be computed.
        assert!(result.posture.composite >= 0.0);
        assert!(result.posture.composite <= 1.0);
    }

    #[test]
    fn run_sweep_full_cadre() {
        let store = AuditStore::open_readonly(":memory:").expect("open store");
        let chain = ChainReader::new(&store);
        let vault = VaultKeyLister::new(vec!["tools/test/key".into()]);

        let officers: Vec<Box<dyn Officer>> = vec![
            Box::new(Steward::new()),
            Box::new(Sentinel::new()),
            Box::new(Forge::new()),
            Box::new(Cleo::new()),
        ];

        let result = run_sweep(&officers, &chain, &vault);

        // Four officers ran
        assert_eq!(result.per_officer.len(), 4);

        // Verify officer names in order
        let names: Vec<&str> = result.per_officer.iter().map(|r| r.officer_name).collect();
        assert_eq!(names, vec!["std", "sen", "forge", "cleo"]);

        // Posture should be computed across all four domains
        assert!(result.posture.composite >= 0.0);
        assert!(result.posture.composite <= 1.0);
    }
}
