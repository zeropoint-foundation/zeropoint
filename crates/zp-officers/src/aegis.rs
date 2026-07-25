//! Aegis — Trajectory-aware constitutional monitor.
//!
//! Domain: Constitutional-trajectory monitoring. Reads the substrate's
//! own observation cadence over time — specifically officer-cadre heartbeat
//! coherence — and produces findings when trajectory-level patterns deviate
//! from declared discipline. Best-effort, advisory (not enforcement) per
//! `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md`.
//!
//! Aegis composes with the officer cadre as its trajectory-scope observer:
//! - Steward, Sentinel, Forge, Cleo each observe atomic substrate state
//!   in their declared scope (per `OFFICER-LENS-DECLARATIONS-2026-07.md`).
//! - Aegis observes those officers' cadence over time — whether they
//!   observe at all, not what they see.
//!
//! ## v1 scope: officer cadre coherence check
//!
//! Reads `officer:*:heartbeat` receipts across the recent chain, computes
//! per-officer last-seen age, and emits:
//!
//! - `officer:aegis:trajectory:coherent` (Ok) — all observed officers
//!   within 2× expected cadence
//! - `officer:aegis:trajectory:silent_officer:{name}` (Warning) — officer
//!   silent > 2× cadence but ≤ 4×
//! - `officer:aegis:trajectory:silent_officer:{name}` (Critical) — officer
//!   silent > 4× cadence
//! - `officer:aegis:trajectory:awaiting_cadre_history` (Info) — no
//!   heartbeats observed for any officer (fresh substrate or first cycle)
//!
//! Composes with `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md`: coherence
//! discipline cross-checks *what* officers see; Aegis cross-checks *whether*
//! officers see. Together they cover both dimensions of observation health.
//!
//! ## Future scope (deferred — pending Cartographer)
//!
//! Full trajectory-level detection per TRAJECTORY-AWARE §VI.1 requires the
//! Cartographer materializing an ontology of Trajectories, Decisions,
//! Insights, Artifacts, and Frictions. When Cartographer lands, Aegis
//! extends to detect misaligned trajectories relative to declared
//! constitutional invariants — decomposition attacks, sustained drift,
//! precedent divergence. v1 is the observable substrate-cadence subset
//! that composes without Cartographer.

use chrono::{DateTime, Utc};
use serde_json::json;

use crate::finding::{Finding, Severity};
use crate::officer::{ChainReader, Officer, VaultKeyLister};
use zp_core::{AuditAction, AuditEntry};

/// Expected officer sweep interval in seconds (matches OfficersConfig default of 900s).
///
/// Aegis's warning/critical thresholds are multiples of this baseline. If
/// operator changes `[officers].sweep_interval_secs` significantly, this
/// constant should track — Layer B canonical spec would eventually make
/// this a runtime-resolved config read rather than a compile-time constant.
const EXPECTED_OFFICER_INTERVAL_SECS: i64 = 900;

/// Multiples of EXPECTED_OFFICER_INTERVAL_SECS that trigger severity escalation.
const WARNING_STALENESS_MULTIPLIER: i64 = 2;
const CRITICAL_STALENESS_MULTIPLIER: i64 = 4;

/// Officer classes Aegis observes for cadence coherence.
/// Excludes Aegis itself to prevent self-observation loop and reflects
/// the current cadre roster. Extended when new officers land.
const OBSERVED_OFFICERS: &[&str] = &["std", "sen", "forge", "cleo"];

/// Chain read window — generous enough to span multiple expected sweep
/// cycles across process restarts (chain persists). 2000 entries typically
/// covers many hours of substrate activity comfortably.
const CHAIN_READ_WINDOW: usize = 2000;

/// The Aegis officer — trajectory-aware constitutional monitor.
///
/// Reads officer cadre coherence over time and emits trajectory-scope
/// findings about substrate observation health. Read-only observer;
/// never writes anything but findings via the sweep contract.
pub struct Aegis;

impl Aegis {
    pub fn new() -> Self {
        Self
    }

    /// Check officer heartbeat cadence across the observation window.
    ///
    /// Reads the chain then delegates to `evaluate_cadence` for the pure
    /// detection logic — the split lets tests exercise threshold behavior
    /// deterministically without an AuditStore.
    fn check_officer_cadre_cadence(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(CHAIN_READ_WINDOW) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        self.evaluate_cadence(&entries, Utc::now())
    }

    /// Pure detection function: compute cadence findings from a slice of
    /// entries plus an injected `now`. Extracted from `check_officer_cadre_cadence`
    /// so tests can seed synthetic entries and control the clock.
    pub(crate) fn evaluate_cadence(
        &self,
        entries: &[AuditEntry],
        now: DateTime<Utc>,
    ) -> Vec<Finding> {
        let mut per_officer_last_seen: std::collections::HashMap<
            &str,
            chrono::DateTime<chrono::Utc>,
        > = std::collections::HashMap::new();

        for entry in entries {
            if let AuditAction::SystemEvent { event } = &entry.action {
                for officer_name in OBSERVED_OFFICERS {
                    let expected = format!("officer:{}:heartbeat", officer_name);
                    if event == &expected {
                        per_officer_last_seen
                            .entry(officer_name)
                            .and_modify(|t| {
                                if entry.timestamp > *t {
                                    *t = entry.timestamp;
                                }
                            })
                            .or_insert(entry.timestamp);
                    }
                }
            }
        }

        // Fresh-substrate / cold-start case: no heartbeats from any officer
        // in the observation window. Distinguish this from "officers went
        // silent" — emit a single Info finding rather than N warnings.
        if per_officer_last_seen.is_empty() {
            return vec![Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "awaiting_cadre_history".into(),
                severity: Severity::Info,
                summary: format!(
                    "Aegis trajectory scan: no officer heartbeats in {} recent entries — awaiting cadre observation history",
                    entries.len()
                ),
                detail: json!({
                    "observation_window_entries": entries.len(),
                    "observed_officer_set": OBSERVED_OFFICERS,
                    "expected_interval_secs": EXPECTED_OFFICER_INTERVAL_SECS,
                    "trajectory_scope": "officer_cadre_cadence",
                    "status": "insufficient_history",
                }),
                timestamp: now,
                cross_domain_depth: 0,
            }];
        }

        let warning_threshold = EXPECTED_OFFICER_INTERVAL_SECS * WARNING_STALENESS_MULTIPLIER;
        let critical_threshold = EXPECTED_OFFICER_INTERVAL_SECS * CRITICAL_STALENESS_MULTIPLIER;

        let mut findings = Vec::new();
        let mut coherent_officers: Vec<&str> = Vec::new();
        let mut warning_officers: Vec<&str> = Vec::new();
        let mut critical_officers: Vec<&str> = Vec::new();

        for officer_name in OBSERVED_OFFICERS {
            let last_seen = per_officer_last_seen.get(officer_name);
            let age_secs = last_seen.map(|t| (now - *t).num_seconds());

            match age_secs {
                None => {
                    // This officer never emitted in window, but others did —
                    // structurally different from "fresh substrate". Warning.
                    warning_officers.push(officer_name);
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: format!("silent_officer:{}", officer_name),
                        severity: Severity::Warning,
                        summary: format!(
                            "Aegis: Officer '{}' has no heartbeat in observation window (other officers present)",
                            officer_name
                        ),
                        detail: json!({
                            "officer": officer_name,
                            "last_seen": null,
                            "observation_window_entries": entries.len(),
                            "expected_interval_secs": EXPECTED_OFFICER_INTERVAL_SECS,
                            "trajectory_class": "officer_cadre_silence",
                            "trajectory_scope": "officer_cadre_cadence",
                        }),
                        timestamp: now,
                        cross_domain_depth: 0,
                    });
                }
                Some(secs) if secs > critical_threshold => {
                    critical_officers.push(officer_name);
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: format!("silent_officer:{}", officer_name),
                        severity: Severity::Critical,
                        summary: format!(
                            "Aegis: Officer '{}' silent for {}s (>{}× expected {}s cadence)",
                            officer_name,
                            secs,
                            CRITICAL_STALENESS_MULTIPLIER,
                            EXPECTED_OFFICER_INTERVAL_SECS
                        ),
                        detail: json!({
                            "officer": officer_name,
                            "last_seen_age_secs": secs,
                            "critical_threshold_secs": critical_threshold,
                            "expected_interval_secs": EXPECTED_OFFICER_INTERVAL_SECS,
                            "trajectory_class": "officer_cadre_critical_silence",
                            "trajectory_scope": "officer_cadre_cadence",
                        }),
                        timestamp: now,
                        cross_domain_depth: 0,
                    });
                }
                Some(secs) if secs > warning_threshold => {
                    warning_officers.push(officer_name);
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: format!("silent_officer:{}", officer_name),
                        severity: Severity::Warning,
                        summary: format!(
                            "Aegis: Officer '{}' silent for {}s (>{}× expected {}s cadence)",
                            officer_name,
                            secs,
                            WARNING_STALENESS_MULTIPLIER,
                            EXPECTED_OFFICER_INTERVAL_SECS
                        ),
                        detail: json!({
                            "officer": officer_name,
                            "last_seen_age_secs": secs,
                            "warning_threshold_secs": warning_threshold,
                            "expected_interval_secs": EXPECTED_OFFICER_INTERVAL_SECS,
                            "trajectory_class": "officer_cadre_silence",
                            "trajectory_scope": "officer_cadre_cadence",
                        }),
                        timestamp: now,
                        cross_domain_depth: 0,
                    });
                }
                Some(_) => {
                    coherent_officers.push(officer_name);
                }
            }
        }

        // Summary finding — always emitted first so consumers get the
        // trajectory-scope roll-up before per-officer detail.
        let overall_severity = if !critical_officers.is_empty() {
            Severity::Critical
        } else if !warning_officers.is_empty() {
            Severity::Warning
        } else {
            Severity::Ok
        };

        let overall_type = if critical_officers.is_empty() && warning_officers.is_empty() {
            "coherent".to_string()
        } else if !critical_officers.is_empty() {
            "divergent:critical".to_string()
        } else {
            "divergent:warning".to_string()
        };

        findings.insert(
            0,
            Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: overall_type,
                severity: overall_severity,
                summary: format!(
                    "Aegis trajectory scan: {} coherent, {} warning, {} critical (observed officers: {:?})",
                    coherent_officers.len(),
                    warning_officers.len(),
                    critical_officers.len(),
                    OBSERVED_OFFICERS,
                ),
                detail: json!({
                    "coherent_officers": coherent_officers,
                    "warning_officers": warning_officers,
                    "critical_officers": critical_officers,
                    "observed_officer_set": OBSERVED_OFFICERS,
                    "expected_interval_secs": EXPECTED_OFFICER_INTERVAL_SECS,
                    "warning_threshold_secs": warning_threshold,
                    "critical_threshold_secs": critical_threshold,
                    "trajectory_scope": "officer_cadre_cadence",
                }),
                timestamp: now,
                cross_domain_depth: 0,
            },
        );

        findings
    }
}

impl Default for Aegis {
    fn default() -> Self {
        Self::new()
    }
}

impl Officer for Aegis {
    fn name(&self) -> &'static str {
        "aegis"
    }

    fn domain(&self) -> &'static str {
        "trajectory"
    }

    fn watch_patterns(&self) -> &[&'static str] {
        // v1: Aegis observes over time via periodic sweep, not per-entry
        // dispatch. When Cartographer trajectory receipts land, extend to
        // ["cartographer:trajectory:", "trajectory:declared:", ...].
        &[]
    }

    fn sweep(
        &self,
        chain: &ChainReader<'_>,
        _vault_keys: &VaultKeyLister,
    ) -> Vec<Finding> {
        self.check_officer_cadre_cadence(chain)
    }
}

#[cfg(test)]
mod tests {
    //! Tests exercise the pure `evaluate_cadence` function with synthetic
    //! `AuditEntry` slices — no AuditStore required. This keeps the test
    //! module free of transitive dev-deps (uuid/tempfile) and lets tests
    //! deterministically control the clock to exercise staleness thresholds.

    use super::*;
    use chrono::TimeZone;
    use zp_core::{
        ActorId, AuditAction, AuditEntry, AuditId, ConversationId, PolicyDecision,
    };

    /// Build a synthetic AuditEntry with the given event string and timestamp.
    /// Aegis only reads `action` and `timestamp`; the rest is filled with
    /// well-formed placeholder values so the struct is constructable.
    fn synthetic_entry(event: &str, ts: DateTime<Utc>) -> AuditEntry {
        AuditEntry {
            id: AuditId::new(),
            entry_hash: format!("test-hash-{}", ts.timestamp_nanos_opt().unwrap_or(0)),
            prev_hash: String::new(),
            actor: ActorId::System("test".into()),
            action: AuditAction::SystemEvent {
                event: event.to_string(),
            },
            conversation_id: ConversationId::new(),
            timestamp: ts,
            policy_decision: PolicyDecision::Allow { conditions: vec![] },
            policy_module: "test".into(),
            receipt: None,
            signatures: Vec::new(),
        }
    }

    fn heartbeat(officer: &str, ts: DateTime<Utc>) -> AuditEntry {
        synthetic_entry(&format!("officer:{}:heartbeat", officer), ts)
    }

    /// Reference "now" for all threshold tests — a fixed timestamp so
    /// staleness math is deterministic.
    fn ref_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 24, 12, 0, 0).unwrap()
    }

    #[test]
    fn aegis_names_and_domain() {
        let aegis = Aegis::new();
        assert_eq!(aegis.name(), "aegis");
        assert_eq!(aegis.domain(), "trajectory");
    }

    #[test]
    fn aegis_watch_patterns_empty_v1() {
        // v1 is periodic-sweep only, not event-driven.
        assert!(Aegis::new().watch_patterns().is_empty());
    }

    #[test]
    fn aegis_empty_entries_emits_awaiting_cadre_history() {
        let findings = Aegis::new().evaluate_cadence(&[], ref_now());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "awaiting_cadre_history");
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(
            findings[0].event_key(),
            "officer:aegis:trajectory:awaiting_cadre_history"
        );
    }

    #[test]
    fn aegis_no_heartbeats_but_other_entries_still_awaiting_history() {
        // Entries present but no heartbeats → fresh-substrate branch.
        let entries = vec![
            synthetic_entry("system:startup", ref_now()),
            synthetic_entry("officer:std:integrity:integrity_verified", ref_now()),
        ];
        let findings = Aegis::new().evaluate_cadence(&entries, ref_now());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "awaiting_cadre_history");
    }

    #[test]
    fn aegis_all_officers_present_emits_coherent() {
        let now = ref_now();
        let entries: Vec<AuditEntry> = OBSERVED_OFFICERS
            .iter()
            .map(|name| heartbeat(name, now))
            .collect();

        let findings = Aegis::new().evaluate_cadence(&entries, now);

        assert_eq!(findings.len(), 1, "expected exactly the summary finding");
        assert_eq!(findings[0].finding_type, "coherent");
        assert_eq!(findings[0].severity, Severity::Ok);
        assert_eq!(findings[0].event_key(), "officer:aegis:trajectory:coherent");

        let coherent = findings[0].detail["coherent_officers"].as_array().unwrap();
        assert_eq!(coherent.len(), OBSERVED_OFFICERS.len());
    }

    #[test]
    fn aegis_missing_officer_emits_warning_summary_and_detail() {
        let now = ref_now();
        // Everyone except Sentinel has a heartbeat.
        let entries: Vec<AuditEntry> = ["std", "forge", "cleo"]
            .iter()
            .map(|name| heartbeat(name, now))
            .collect();

        let findings = Aegis::new().evaluate_cadence(&entries, now);

        // Summary + one detail for sen.
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].finding_type, "divergent:warning");
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(
            findings[0].event_key(),
            "officer:aegis:trajectory:divergent:warning"
        );

        assert_eq!(findings[1].finding_type, "silent_officer:sen");
        assert_eq!(findings[1].severity, Severity::Warning);
        assert_eq!(
            findings[1].event_key(),
            "officer:aegis:trajectory:silent_officer:sen"
        );
    }

    #[test]
    fn aegis_stale_officer_past_warning_threshold_emits_warning() {
        let now = ref_now();
        let stale = now - chrono::Duration::seconds(EXPECTED_OFFICER_INTERVAL_SECS * 3);

        // Steward stale (3× interval > 2× threshold, < 4× threshold), others fresh.
        let entries = vec![
            heartbeat("std", stale),
            heartbeat("sen", now),
            heartbeat("forge", now),
            heartbeat("cleo", now),
        ];
        let findings = Aegis::new().evaluate_cadence(&entries, now);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].finding_type, "divergent:warning");
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[1].finding_type, "silent_officer:std");
        assert_eq!(findings[1].severity, Severity::Warning);
    }

    #[test]
    fn aegis_stale_officer_past_critical_threshold_emits_critical() {
        let now = ref_now();
        let very_stale = now - chrono::Duration::seconds(EXPECTED_OFFICER_INTERVAL_SECS * 5);

        // Cleo very stale (>4× threshold), others fresh.
        let entries = vec![
            heartbeat("std", now),
            heartbeat("sen", now),
            heartbeat("forge", now),
            heartbeat("cleo", very_stale),
        ];
        let findings = Aegis::new().evaluate_cadence(&entries, now);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].finding_type, "divergent:critical");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].event_key(),
            "officer:aegis:trajectory:divergent:critical"
        );
        assert_eq!(findings[1].finding_type, "silent_officer:cleo");
        assert_eq!(findings[1].severity, Severity::Critical);
    }

    #[test]
    fn aegis_critical_dominates_warning_in_summary() {
        // Mix of stale officers — summary reflects worst severity.
        let now = ref_now();
        let warning_stale = now - chrono::Duration::seconds(EXPECTED_OFFICER_INTERVAL_SECS * 3);
        let critical_stale = now - chrono::Duration::seconds(EXPECTED_OFFICER_INTERVAL_SECS * 5);

        let entries = vec![
            heartbeat("std", warning_stale),
            heartbeat("sen", critical_stale),
            heartbeat("forge", now),
            heartbeat("cleo", now),
        ];
        let findings = Aegis::new().evaluate_cadence(&entries, now);

        // Summary + std warning + sen critical = 3 findings.
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].finding_type, "divergent:critical");
        assert_eq!(findings[0].severity, Severity::Critical);

        let per_officer_types: std::collections::HashSet<String> =
            findings[1..].iter().map(|f| f.finding_type.clone()).collect();
        assert!(per_officer_types.contains("silent_officer:std"));
        assert!(per_officer_types.contains("silent_officer:sen"));
    }

    #[test]
    fn aegis_ignores_non_heartbeat_officer_events() {
        // A burst of officer findings (not heartbeats) must NOT count as
        // "officer observed" — Aegis specifically checks for heartbeats.
        let now = ref_now();
        let entries = vec![
            synthetic_entry("officer:std:integrity:integrity_verified", now),
            synthetic_entry("officer:sen:security:shadow_credential", now),
            synthetic_entry("officer:forge:tool_lifecycle_delta", now),
            synthetic_entry("officer:cleo:governance:authority_chain_valid", now),
        ];
        let findings = Aegis::new().evaluate_cadence(&entries, now);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "awaiting_cadre_history");
    }

    #[test]
    fn aegis_uses_most_recent_heartbeat_per_officer() {
        // Multiple heartbeats for same officer — most recent wins.
        let now = ref_now();
        let old = now - chrono::Duration::seconds(EXPECTED_OFFICER_INTERVAL_SECS * 10);

        // Steward has an ancient stale heartbeat AND a fresh one.
        let entries = vec![
            heartbeat("std", old),
            heartbeat("std", now),
            heartbeat("sen", now),
            heartbeat("forge", now),
            heartbeat("cleo", now),
        ];
        let findings = Aegis::new().evaluate_cadence(&entries, now);

        // Should be coherent — fresh heartbeat wins over ancient one.
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "coherent");
        assert_eq!(findings[0].severity, Severity::Ok);
    }

    #[test]
    fn aegis_event_key_format_is_stable() {
        // Lock in the receipt-event format per OFFICER-LENS-DECLARATIONS-2026-07.md.
        for (finding_type, expected_key) in &[
            ("coherent", "officer:aegis:trajectory:coherent"),
            ("divergent:warning", "officer:aegis:trajectory:divergent:warning"),
            ("divergent:critical", "officer:aegis:trajectory:divergent:critical"),
            (
                "awaiting_cadre_history",
                "officer:aegis:trajectory:awaiting_cadre_history",
            ),
            (
                "silent_officer:std",
                "officer:aegis:trajectory:silent_officer:std",
            ),
        ] {
            let f = Finding {
                officer: "aegis",
                domain: "trajectory",
                finding_type: finding_type.to_string(),
                severity: Severity::Ok,
                summary: "x".into(),
                detail: json!({}),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            };
            assert_eq!(f.event_key(), *expected_key);
        }
    }
}
