//! Substrate validation — deterministic structural audit primitive.
//!
//! Regent tool. Walks the chain, checks canonical disciplines, produces
//! structured findings + chain-anchored evidence receipt. Separates
//! deterministic structural validation from Regent's narration judgment.
//!
//! Motivated 2026-07-16 by Regent's first substrate validation attempt
//! (via raw chain_query synthesis) drifting from directive: missing hash
//! citations, missing checks, confabulating unsupported interpretations,
//! pivoting to security recommendations. Structural validation belongs in
//! Rust; narration belongs to the model. Same discipline as `zp officer
//! sweep` (P1.4) and `zp vault test` (P1.5) — Regent gets a canonical
//! primitive rather than synthesizing one from raw tools.
//!
//! ## Report shape
//!
//! The tool returns a structured JSON report with per-discipline health
//! checks and a chain-anchored `substrate:validation:regent:<id>` receipt
//! whose entry_hash is returned in the report so Regent can cite it.
//!
//! ## Checks (v1)
//!
//! - Chain integrity: latest Steward `integrity_verified` finding + chain tail
//! - Canary discipline: verified vs missed vs remediated counts in last hour
//! - Cognitive sandwich: composition + observer receipts per cycle in last hour
//! - Standing corrections: active count with domain + priority listing
//! - Officer heartbeats: per-officer count + age of most recent per class
//! - Receipt type inventory: known-prefix histogram + list of unknown prefixes
//! - Overall posture: rolled-up healthy/degraded/critical assessment
//!
//! ## Not yet checked (deferred to later phases)
//!
//! - Full KEEL invariant verification (structural claim checkers)
//! - Empirical Program four-claims (P4 verification stack)
//! - Coherence discipline invocation (spec drafted, not implemented)
//! - Cross-substrate validation (peer verification contract not implemented)

use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{info, warn};

use zp_audit::{AuditStore, UnsealedEntry};
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};

/// Regent conversation namespace (matches server::regent::regent_conv_id).
fn regent_conv_id() -> ConversationId {
    ConversationId(uuid::Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap())
}

/// Known receipt-type prefixes the substrate emits (as of 2026-07-16).
/// Used for receipt-inventory categorization. Anything not matching a
/// known prefix is flagged as unrecognized in the report.
///
/// **Not exhaustive** — this is the canonical set as of this spec's
/// authoring; substrate extension may add prefixes over time. The Layer B
/// registry per OBSERVER-COHERENCE-DISCIPLINE would eventually replace
/// this hardcoded list.
const KNOWN_RECEIPT_PREFIXES: &[&str] = &[
    // Officer findings + heartbeats
    "officer:std:",
    "officer:sen:",
    "officer:forge:",
    "officer:cleo:",
    "officer:aegis:",
    // Governance decisions and posture
    "governance_request:",
    "posture:computed",
    "delegation:granted:",
    "delegation:revoked:",
    "delegation:expired:",
    // Chain lifecycle
    "epoch:anchored:",
    "system:canonicalized:",
    "system:keychain:",
    "system:startup",
    "system:shutdown",
    // Regent-emitted
    "regent:intent:",
    "regent:tool:",
    "regent:remediation:",
    "regent:model_evaluated:",
    "regent:inference:",
    // Cognitive discipline sandwich
    "cognitive:input:composed",
    "cognitive:observer:verified",
    "cognitive:correction:standing",
    "cognitive:correction:revoked",
    "cognitive:correction:violated",
    // Cognitive act accounting (v0) — per COGNITIVE-ACT-ACCOUNTING-2026-07.md §6
    "cognitive:act:recorded",
    // Tie-off watch (Stage 1t) — per IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md
    // §"reopen_watch — the two tiers". Declared here ahead of the runtime
    // so a documented receipt does not surface as receipt-drift; the
    // canary cannot evaluate predicates yet.
    // Phase 6 long window — per EXECUTION-AUTHORITY-MODEL-2026-07.md
    "regent:awareness:session_profile",
    "improvement:tieoff:declared",
    "improvement:reopen:eligible",
    "improvement:reopen:review_due",
    // Canary discipline
    "chain:canary:",
    // Substrate validation (this tool's own emissions)
    "substrate:validation:regent:",
    // Sentinel-specific benign classifications
    "unregistered_known_app",
];

/// Run the canonical substrate validation.
///
/// Emits a `substrate:validation:regent:<id>` receipt with the report hash
/// and returns the full structured findings JSON to the caller (Regent's
/// tool dispatch loop).
pub fn run_substrate_validation(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
) -> serde_json::Value {
    let validation_id = uuid::Uuid::now_v7().to_string();
    let validated_at = chrono::Utc::now();
    let one_hour_ago = validated_at - chrono::Duration::hours(1);

    // Fetch a generous window of recent chain state for all downstream checks.
    // 1024 entries typically covers >1h of substrate activity comfortably.
    let recent_entries = {
        let store = match audit_store.lock() {
            Ok(s) => s,
            Err(e) => {
                return serde_json::json!({
                    "error": format!("audit store lock poisoned: {}", e),
                });
            }
        };
        match store.recent_entries(1024) {
            Ok(entries) => entries,
            Err(e) => {
                return serde_json::json!({
                    "error": format!("recent_entries failed: {}", e),
                });
            }
        }
    };

    // Compute the chain-head summary — highest rowid seen (proxy for tip).
    let chain_head = recent_entries
        .iter()
        .max_by_key(|e| e.timestamp)
        .map(|e| {
            serde_json::json!({
                "entry_hash": e.entry_hash,
                "timestamp": e.timestamp.to_rfc3339(),
            })
        })
        .unwrap_or_else(|| serde_json::json!(null));

    // ── Per-discipline checks ────────────────────────────────────────────
    let chain_integrity = check_chain_integrity(audit_store, &recent_entries);
    let canary_discipline = check_canary_discipline(&recent_entries, one_hour_ago);
    let cognitive_sandwich = check_cognitive_sandwich(&recent_entries, one_hour_ago);
    let standing_corrections = check_standing_corrections(audit_store);
    let officer_heartbeats = check_officer_heartbeats(&recent_entries, one_hour_ago);
    let receipt_inventory = check_receipt_inventory(&recent_entries);

    // ── Roll-up posture ──────────────────────────────────────────────────
    let posture = derive_posture(
        &chain_integrity,
        &canary_discipline,
        &cognitive_sandwich,
        &officer_heartbeats,
    );

    let notable_gaps = derive_notable_gaps(
        &chain_integrity,
        &canary_discipline,
        &cognitive_sandwich,
        &officer_heartbeats,
        &receipt_inventory,
    );

    // Assemble the full report.
    let report = serde_json::json!({
        "validation_id": validation_id,
        "validated_at": validated_at.to_rfc3339(),
        "chain_head": chain_head,
        "checks": {
            "chain_integrity": chain_integrity,
            "canary_discipline": canary_discipline,
            "cognitive_sandwich": cognitive_sandwich,
            "standing_corrections": standing_corrections,
            "officer_heartbeats": officer_heartbeats,
            "receipt_inventory": receipt_inventory,
        },
        "posture": posture,
        "notable_gaps": notable_gaps,
    });

    // ── Chain-anchor the validation as evidence ──────────────────────────
    let report_hash = hash_report(&report);
    let entry_hash = emit_validation_receipt(audit_store, &validation_id, &report_hash, &posture);

    // Attach the chain-anchoring metadata to the report so Regent can cite it.
    let mut report_with_receipt = report;
    if let Some(hash) = entry_hash {
        report_with_receipt["evidence_receipt"] = serde_json::json!({
            "event": format!("substrate:validation:regent:{}", validation_id),
            "entry_hash": hash,
            "report_hash": report_hash,
        });
    }

    info!(
        validation_id = %validation_id,
        posture = %posture,
        "substrate validation complete"
    );

    report_with_receipt
}

/// Check chain integrity via the audit store's verify_with_report + look
/// for Steward's most recent integrity_verified finding on chain.
fn check_chain_integrity(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    recent: &[zp_core::AuditEntry],
) -> serde_json::Value {
    let store = match audit_store.lock() {
        Ok(s) => s,
        Err(e) => {
            return serde_json::json!({
                "status": "unknown",
                "detail": format!("lock poisoned: {}", e),
            });
        }
    };

    let verify_result = store.verify_with_report();
    let latest_steward = recent
        .iter()
        .rev()
        .find(|e| {
            matches!(&e.action, AuditAction::SystemEvent { event }
                if event.starts_with("officer:std:integrity:integrity_verified")
                    || event == "officer:std:integrity:integrity_verified")
        })
        .map(|e| e.entry_hash.clone());

    match verify_result {
        Ok(report) => serde_json::json!({
            "status": if report.chain_valid { "ok" } else { "failed" },
            "entries_examined": report.entries_examined,
            "hashes_valid": report.hashes_valid,
            "signatures_present": report.signatures_present,
            "chain_links_valid": report.chain_links_valid,
            "steward_latest_integrity_verified_hash": latest_steward,
        }),
        Err(e) => serde_json::json!({
            "status": "unknown",
            "detail": format!("verify_with_report failed: {}", e),
            "steward_latest_integrity_verified_hash": latest_steward,
        }),
    }
}

/// Check canary discipline: count verified/missed/remediated in the window.
fn check_canary_discipline(
    recent: &[zp_core::AuditEntry],
    since: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let mut written = 0;
    let mut verified = 0;
    let mut missed = 0;
    let mut remediated = 0;
    let mut remediation_failed = 0;
    let mut unresponsive = 0;
    let mut last_verified: Option<(String, String)> = None;
    let mut last_probe_ms: Option<u64> = None;

    for e in recent.iter().filter(|e| e.timestamp >= since) {
        let event = match &e.action {
            AuditAction::SystemEvent { event } => event,
            _ => continue,
        };
        if event.starts_with("chain:canary:written") {
            written += 1;
        } else if event.starts_with("chain:canary:verified") {
            verified += 1;
            last_verified = Some((e.entry_hash.clone(), e.timestamp.to_rfc3339()));
            // Parse probe_ms=N from event string tail.
            if let Some(pos) = event.find("probe_ms=") {
                let tail = &event[pos + "probe_ms=".len()..];
                let end = tail.find(char::is_whitespace).unwrap_or(tail.len());
                if let Ok(n) = tail[..end].parse::<u64>() {
                    last_probe_ms = Some(n);
                }
            }
        } else if event.starts_with("chain:canary:missed") {
            missed += 1;
        } else if event.starts_with("chain:canary:remediated") {
            remediated += 1;
        } else if event.starts_with("chain:canary:remediation_failed") {
            remediation_failed += 1;
        } else if event.starts_with("chain:canary:unresponsive") {
            unresponsive += 1;
        }
    }

    let status = if remediation_failed > 0 {
        "critical"
    } else if missed > 0 && remediated == missed {
        "self_healed"
    } else if missed > 0 {
        "degraded"
    } else if written == 0 {
        // No canary activity in window — either not yet spawned or discipline down.
        "inactive"
    } else {
        "ok"
    };

    serde_json::json!({
        "status": status,
        "window_hours": 1,
        "canaries_written": written,
        "canaries_verified": verified,
        "canaries_missed": missed,
        "canaries_remediated": remediated,
        "canaries_remediation_failed": remediation_failed,
        "canaries_unresponsive": unresponsive,
        "last_verified_hash": last_verified.as_ref().map(|(h, _)| h),
        "last_verified_at": last_verified.as_ref().map(|(_, t)| t),
        "last_probe_ms": last_probe_ms,
    })
}

/// Check cognitive discipline sandwich: composition + observer receipts per cycle.
fn check_cognitive_sandwich(
    recent: &[zp_core::AuditEntry],
    since: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let mut compositions = 0;
    let mut observer_verifieds = 0;
    let mut violations = 0;
    let mut last_composition: Option<(String, String)> = None;
    let mut last_observer: Option<(String, String)> = None;

    for e in recent.iter().filter(|e| e.timestamp >= since) {
        let event = match &e.action {
            AuditAction::SystemEvent { event } => event,
            _ => continue,
        };
        if event.starts_with("cognitive:input:composed") {
            compositions += 1;
            last_composition = Some((e.entry_hash.clone(), e.timestamp.to_rfc3339()));
        } else if event.starts_with("cognitive:observer:verified") {
            observer_verifieds += 1;
            last_observer = Some((e.entry_hash.clone(), e.timestamp.to_rfc3339()));
            // Parse violations=N from event tail.
            if let Some(pos) = event.find("violations=") {
                let tail = &event[pos + "violations=".len()..];
                let end = tail.find(char::is_whitespace).unwrap_or(tail.len());
                if let Ok(n) = tail[..end].parse::<u64>() {
                    violations += n;
                }
            }
        } else if event.starts_with("cognitive:correction:violated") {
            // Standalone violation receipts count separately.
        }
    }

    // Sandwich health: compositions and observer verifications should be roughly
    // paired (one of each per Regent cycle). Significant imbalance is a sign
    // that one leg of the sandwich isn't firing.
    let status = if compositions == 0 && observer_verifieds == 0 {
        "inactive"
    } else if (compositions as i64 - observer_verifieds as i64).abs() > 3 {
        "imbalanced"
    } else if violations > 0 {
        "violations_present"
    } else {
        "ok"
    };

    serde_json::json!({
        "status": status,
        "window_hours": 1,
        "cognitive_input_composed_count": compositions,
        "cognitive_observer_verified_count": observer_verifieds,
        "violations_last_hour": violations,
        "last_composition_hash": last_composition.as_ref().map(|(h, _)| h),
        "last_composition_at": last_composition.as_ref().map(|(_, t)| t),
        "last_observer_hash": last_observer.as_ref().map(|(h, _)| h),
        "last_observer_at": last_observer.as_ref().map(|(_, t)| t),
    })
}

/// Check standing corrections: active count via CorrectionIndex.
fn check_standing_corrections(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
) -> serde_json::Value {
    use zp_regent::corrections::{CorrectionIndex, EVENT_PREFIX_REVOKED, EVENT_PREFIX_STANDING};

    let store = match audit_store.lock() {
        Ok(s) => s,
        Err(e) => {
            return serde_json::json!({
                "status": "unknown",
                "detail": format!("lock poisoned: {}", e),
            });
        }
    };

    let mut correction_entries = store
        .search_chain_by_action_keyword(EVENT_PREFIX_STANDING, 1024)
        .unwrap_or_default();
    let mut revocation_entries = store
        .search_chain_by_action_keyword(EVENT_PREFIX_REVOKED, 1024)
        .unwrap_or_default();
    correction_entries.append(&mut revocation_entries);
    drop(store);

    let index = CorrectionIndex::build(&correction_entries, chrono::Utc::now());
    let summary: Vec<serde_json::Value> = index
        .all()
        .iter()
        .map(|c| {
            serde_json::json!({
                "correction_id": c.correction.correction_id,
                "domain": c.correction.domain,
                "priority": c.correction.priority,
                "correction_type": format!("{:?}", c.correction.correction_type).to_lowercase(),
                "entry_hash": c.entry_hash,
            })
        })
        .collect();

    serde_json::json!({
        "status": "ok",
        "active_count": index.len(),
        "corrections": summary,
    })
}

/// Check officer heartbeats: count per officer + age of most recent per class.
fn check_officer_heartbeats(
    recent: &[zp_core::AuditEntry],
    since: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    let now = chrono::Utc::now();
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    let mut last_seen: BTreeMap<String, chrono::DateTime<chrono::Utc>> = BTreeMap::new();

    let officer_classes = ["std", "sen", "forge", "cleo", "aegis"];

    for e in recent.iter().filter(|e| e.timestamp >= since) {
        let event = match &e.action {
            AuditAction::SystemEvent { event } => event,
            _ => continue,
        };
        for class in officer_classes {
            let prefix = format!("officer:{}:heartbeat", class);
            if event == &prefix {
                *counts.entry(class.to_string()).or_insert(0) += 1;
                last_seen
                    .entry(class.to_string())
                    .and_modify(|t| {
                        if e.timestamp > *t {
                            *t = e.timestamp;
                        }
                    })
                    .or_insert(e.timestamp);
            }
        }
    }

    // Assess per-class staleness. Officer cadre interval is ~900s (15 min);
    // heartbeat missing for >2x that is degraded, >4x is critical.
    let mut per_class: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut worst_status = "ok";
    for class in officer_classes {
        let count = *counts.get(class).unwrap_or(&0);
        let age_secs = last_seen.get(class).map(|t| (now - *t).num_seconds());
        let class_status = match age_secs {
            None => {
                if worst_status == "ok" {
                    worst_status = "missing";
                }
                "missing"
            }
            Some(secs) if secs > 3600 => {
                if worst_status != "critical" && worst_status != "missing" {
                    worst_status = "critical";
                }
                "critical"
            }
            Some(secs) if secs > 1800 => {
                if worst_status == "ok" {
                    worst_status = "degraded";
                }
                "degraded"
            }
            Some(_) => "ok",
        };
        per_class.insert(
            class.to_string(),
            serde_json::json!({
                "count_last_hour": count,
                "last_seen_age_secs": age_secs,
                "status": class_status,
            }),
        );
    }

    serde_json::json!({
        "status": worst_status,
        "expected_interval_secs": 900,
        "per_officer": per_class,
    })
}

/// Categorize recent receipts by prefix; flag unrecognized types.
fn check_receipt_inventory(recent: &[zp_core::AuditEntry]) -> serde_json::Value {
    let mut counts_by_prefix: BTreeMap<String, u32> = BTreeMap::new();
    let mut unknown_samples: BTreeMap<String, u32> = BTreeMap::new();

    for e in recent.iter() {
        let event = match &e.action {
            AuditAction::SystemEvent { event } => event,
            _ => {
                *counts_by_prefix.entry("<non-system-event>".to_string()).or_insert(0) += 1;
                continue;
            }
        };
        // Find matching known prefix (longest match wins for categorization).
        let matched = KNOWN_RECEIPT_PREFIXES
            .iter()
            .filter(|p| event.starts_with(*p))
            .max_by_key(|p| p.len())
            .copied();
        match matched {
            Some(prefix) => {
                *counts_by_prefix.entry(prefix.to_string()).or_insert(0) += 1;
            }
            None => {
                // Take the first colon-separated token (or the whole string) as a "type" bucket.
                let bucket = event
                    .split_whitespace()
                    .next()
                    .and_then(|t| t.split(':').next())
                    .unwrap_or(event)
                    .to_string();
                *unknown_samples.entry(bucket).or_insert(0) += 1;
            }
        }
    }

    let status = if unknown_samples.is_empty() { "ok" } else { "unrecognized_present" };

    serde_json::json!({
        "status": status,
        "known_prefix_counts": counts_by_prefix,
        "unrecognized_prefix_counts": unknown_samples,
    })
}

/// Compute an overall posture assessment from per-check results.
fn derive_posture(
    chain_integrity: &serde_json::Value,
    canary: &serde_json::Value,
    sandwich: &serde_json::Value,
    heartbeats: &serde_json::Value,
) -> String {
    let integrity_status = chain_integrity["status"].as_str().unwrap_or("unknown");
    let canary_status = canary["status"].as_str().unwrap_or("unknown");
    let sandwich_status = sandwich["status"].as_str().unwrap_or("unknown");
    let heartbeat_status = heartbeats["status"].as_str().unwrap_or("unknown");

    // Any single critical fault escalates the whole posture.
    if integrity_status == "failed"
        || canary_status == "critical"
        || heartbeat_status == "critical"
    {
        return "critical".to_string();
    }
    // Degradation on any discipline downgrades to degraded.
    if integrity_status == "unknown"
        || canary_status == "degraded"
        || canary_status == "inactive"
        || sandwich_status == "imbalanced"
        || sandwich_status == "inactive"
        || heartbeat_status == "degraded"
        || heartbeat_status == "missing"
    {
        return "degraded".to_string();
    }
    "healthy".to_string()
}

/// Collect notable gaps for Regent to narrate.
fn derive_notable_gaps(
    chain_integrity: &serde_json::Value,
    canary: &serde_json::Value,
    sandwich: &serde_json::Value,
    heartbeats: &serde_json::Value,
    inventory: &serde_json::Value,
) -> Vec<String> {
    let mut gaps = Vec::new();
    if chain_integrity["status"].as_str() == Some("failed") {
        gaps.push("Chain integrity check failed — investigate hash-linkage or signature validity.".to_string());
    }
    if canary["status"].as_str() == Some("critical") {
        gaps.push(
            "Canary Tier 1 remediation insufficient — Tier 2 (Connection rebuild) may be required.".to_string(),
        );
    }
    if canary["status"].as_str() == Some("inactive") {
        gaps.push("No canary activity in the last hour — discipline may not be spawned.".to_string());
    }
    if sandwich["status"].as_str() == Some("imbalanced") {
        gaps.push(
            "Cognitive sandwich imbalance — composition and observer receipt counts diverge; one leg may be failing.".to_string(),
        );
    }
    if let Some(map) = heartbeats["per_officer"].as_object() {
        for (officer, data) in map {
            let status = data["status"].as_str().unwrap_or("unknown");
            if status == "missing" || status == "critical" {
                gaps.push(format!("Officer {} heartbeat {} — expected cadence 900s.", officer, status));
            }
        }
    }
    if let Some(unknowns) = inventory["unrecognized_prefix_counts"].as_object() {
        if !unknowns.is_empty() {
            let names: Vec<String> = unknowns.keys().cloned().collect();
            gaps.push(format!(
                "Unrecognized receipt-type prefixes in recent chain: {}. Consider adding to known-prefix registry or investigating source.",
                names.join(", ")
            ));
        }
    }
    gaps
}

/// SHA-256 hash of the canonical JSON representation of the report.
/// Used to give validation receipts a stable content hash.
fn hash_report(report: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(report).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    format!("{:x}", hasher.finalize())
}

/// Emit the substrate:validation:regent:<id> receipt with the report hash.
fn emit_validation_receipt(
    audit_store: &Arc<std::sync::Mutex<AuditStore>>,
    validation_id: &str,
    report_hash: &str,
    posture: &str,
) -> Option<String> {
    let event = format!(
        "substrate:validation:regent:{} posture={} report_hash={}",
        validation_id,
        posture,
        &report_hash[..report_hash.len().min(16)]
    );
    let entry = UnsealedEntry {
        actor: ActorId::System("regent".to_string()),
        action: AuditAction::SystemEvent { event },
        conversation_id: regent_conv_id(),
        policy_decision: PolicyDecision::Allow {
            conditions: Vec::new(),
        },
        policy_module: "substrate-validation".to_string(),
        receipt: None,
    };

    match audit_store.lock() {
        Ok(mut store) => match store.append(entry) {
            Ok(sealed) => Some(sealed.entry_hash),
            Err(e) => {
                warn!("substrate validation receipt emission failed: {}", e);
                None
            }
        },
        Err(e) => {
            warn!("substrate validation receipt lock poisoned: {}", e);
            None
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_store() -> (Arc<std::sync::Mutex<AuditStore>>, TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("substrate_validate_test.db");
        let store = AuditStore::open_unsigned(&path).expect("open store");
        (Arc::new(std::sync::Mutex::new(store)), tmp)
    }

    fn write_event(store: &Arc<std::sync::Mutex<AuditStore>>, event: &str) {
        let entry = UnsealedEntry {
            actor: ActorId::System("test".to_string()),
            action: AuditAction::SystemEvent {
                event: event.to_string(),
            },
            conversation_id: regent_conv_id(),
            policy_decision: PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "test".to_string(),
            receipt: None,
        };
        store.lock().unwrap().append(entry).expect("append");
    }

    #[test]
    fn validation_on_empty_chain_produces_report_without_panic() {
        let (store, _tmp) = temp_store();
        let report = run_substrate_validation(&store);
        assert!(report["validation_id"].is_string());
        assert!(report["validated_at"].is_string());
        // Empty chain: canary inactive, cognitive inactive → posture degraded.
        assert_eq!(report["posture"].as_str(), Some("degraded"));
    }

    #[test]
    fn validation_emits_chain_anchored_receipt() {
        let (store, _tmp) = temp_store();
        let report = run_substrate_validation(&store);
        assert!(report["evidence_receipt"]["entry_hash"].is_string());
        // Check the substrate:validation:regent:<id> event landed on chain.
        let count = store
            .lock()
            .unwrap()
            .search_chain_by_action_keyword("substrate:validation:regent:", 10)
            .unwrap()
            .len();
        assert!(count >= 1);
    }

    #[test]
    fn canary_check_counts_verified_and_missed() {
        let (store, _tmp) = temp_store();
        write_event(&store, "chain:canary:written 0");
        write_event(&store, "chain:canary:verified chain_reader 0 probe_ms=5");
        write_event(&store, "chain:canary:written 1");
        write_event(&store, "chain:canary:missed chain_reader 1 probe_ms=8 probed_entries=100");
        write_event(&store, "chain:canary:remediated chain_reader 1 method=cache_flush");

        let report = run_substrate_validation(&store);
        let canary = &report["checks"]["canary_discipline"];
        assert_eq!(canary["canaries_written"].as_u64(), Some(2));
        assert_eq!(canary["canaries_verified"].as_u64(), Some(1));
        assert_eq!(canary["canaries_missed"].as_u64(), Some(1));
        assert_eq!(canary["canaries_remediated"].as_u64(), Some(1));
        // Self-healed: missed count == remediated count.
        assert_eq!(canary["status"].as_str(), Some("self_healed"));
    }

    #[test]
    fn cognitive_sandwich_check_pairs_composition_and_observer() {
        let (store, _tmp) = temp_store();
        write_event(
            &store,
            "cognitive:input:composed matrix=v1.0 corrections=5/abc findings=0/ chain=50 delegations=10 reason=test",
        );
        write_event(
            &store,
            "cognitive:observer:verified corrections=5 patterns=5 violations=0 max_severity=Informational",
        );

        let report = run_substrate_validation(&store);
        let sandwich = &report["checks"]["cognitive_sandwich"];
        assert_eq!(sandwich["cognitive_input_composed_count"].as_u64(), Some(1));
        assert_eq!(sandwich["cognitive_observer_verified_count"].as_u64(), Some(1));
        assert_eq!(sandwich["violations_last_hour"].as_u64(), Some(0));
        assert_eq!(sandwich["status"].as_str(), Some("ok"));
    }

    #[test]
    fn observer_verified_with_violations_flagged() {
        let (store, _tmp) = temp_store();
        write_event(&store, "cognitive:input:composed matrix=v1.0 corrections=5/abc findings=0/ chain=50 delegations=10 reason=test");
        write_event(
            &store,
            "cognitive:observer:verified corrections=5 patterns=5 violations=2 max_severity=Critical",
        );

        let report = run_substrate_validation(&store);
        let sandwich = &report["checks"]["cognitive_sandwich"];
        assert_eq!(sandwich["violations_last_hour"].as_u64(), Some(2));
        assert_eq!(sandwich["status"].as_str(), Some("violations_present"));
    }

    #[test]
    fn officer_heartbeat_check_reports_per_class() {
        let (store, _tmp) = temp_store();
        write_event(&store, "officer:std:heartbeat");
        write_event(&store, "officer:sen:heartbeat");
        write_event(&store, "officer:forge:heartbeat");
        write_event(&store, "officer:cleo:heartbeat");
        // Aegis intentionally missing.

        let report = run_substrate_validation(&store);
        let hb = &report["checks"]["officer_heartbeats"]["per_officer"];
        assert_eq!(hb["std"]["count_last_hour"].as_u64(), Some(1));
        assert_eq!(hb["sen"]["count_last_hour"].as_u64(), Some(1));
        assert_eq!(hb["forge"]["count_last_hour"].as_u64(), Some(1));
        assert_eq!(hb["cleo"]["count_last_hour"].as_u64(), Some(1));
        assert_eq!(hb["aegis"]["count_last_hour"].as_u64(), Some(0));
        // Missing Aegis triggers "missing" status downgrade.
        assert_eq!(
            report["checks"]["officer_heartbeats"]["status"].as_str(),
            Some("missing")
        );
    }

    #[test]
    fn receipt_inventory_flags_unknown_prefixes() {
        let (store, _tmp) = temp_store();
        write_event(&store, "officer:std:heartbeat"); // known
        write_event(&store, "chain:canary:written 0"); // known
        write_event(&store, "some_new_thing:happening"); // unknown

        let report = run_substrate_validation(&store);
        let inv = &report["checks"]["receipt_inventory"];
        assert_eq!(inv["status"].as_str(), Some("unrecognized_present"));
        assert!(inv["unrecognized_prefix_counts"]["some_new_thing"].as_u64().is_some());
    }

    #[test]
    fn notable_gaps_include_missing_officers_and_unknowns() {
        let (store, _tmp) = temp_store();
        write_event(&store, "some_unknown_event:foo");
        let report = run_substrate_validation(&store);
        let gaps = report["notable_gaps"].as_array().unwrap();
        // Should mention missing officers AND unknown prefixes.
        assert!(gaps.iter().any(|g| g.as_str().unwrap_or("").contains("Officer")));
        assert!(gaps.iter().any(|g| g.as_str().unwrap_or("").contains("Unrecognized")));
    }

    #[test]
    fn posture_healthy_requires_all_disciplines_ok() {
        let (store, _tmp) = temp_store();
        // Cognitive sandwich present with matching counts.
        for _ in 0..2 {
            write_event(
                &store,
                "cognitive:input:composed matrix=v1.0 corrections=5/abc findings=0/ chain=50 delegations=10 reason=test",
            );
            write_event(
                &store,
                "cognitive:observer:verified corrections=5 patterns=5 violations=0 max_severity=Informational",
            );
        }
        // Canary healthy.
        write_event(&store, "chain:canary:written 0");
        write_event(&store, "chain:canary:verified chain_reader 0 probe_ms=3");
        // All officer heartbeats present.
        for class in ["std", "sen", "forge", "cleo", "aegis"] {
            write_event(&store, &format!("officer:{}:heartbeat", class));
        }

        let report = run_substrate_validation(&store);
        assert_eq!(report["posture"].as_str(), Some("healthy"));
    }
}
