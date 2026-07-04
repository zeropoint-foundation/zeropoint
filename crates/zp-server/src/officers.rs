//! System Officer Cadre — periodic sweep timer and finding emission.
//!
//! Wires the officer cadre into `zp-server`. The periodic sweep fires every
//! N minutes, runs each enabled officer's diagnostic suite, and emits
//! findings as signed chain receipts.
//!
//! **Tier 1 scope (this file):**
//! - Periodic sweep timer only.
//! - Tier 1 (chain receipt) output, quiet sweep mode (single all-clear receipt
//!   when everything is Ok/Info).
//! - `ActorId::System("officer:{name}")` labels entries; the audit store's
//!   Genesis-derived signer signs them. Per-officer signing keys are Tier 2.
//!
//! **Not yet implemented (Tier 2+):**
//! - Real-time chain watcher: subscribe to new entries and trigger officers
//!   on pattern matches (e.g., `gate:denied:*` → Sentinel). The notifier
//!   hook exists (`AuditStore::set_notifier`) — ready to wire in.
//! - Tier 2 LLM assessments with significance threshold + budget cap.
//! - Tier 3 Operator notifications with exponential backoff.
//!
//! See `docs/design/SYSTEM-OFFICER-CADRE-2026-06.md` for the full spec.

use std::sync::{Mutex, OnceLock};

use tracing::{debug, info, warn};
use zp_officers::officer::Officer;
use uuid::Uuid;

use zp_audit::{AuditStore, UnsealedEntry};
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};

use zp_officers::{
    cleo::Cleo,
    finding::Severity,
    forge::Forge,
    sweep::OfficerSweepResult,
    officer::{ChainReader, VaultKeyLister},
    posture::PostureScore,
    proposal::OfficerDelegation,
    request::{consolidate, GovernanceRequest},
    sentinel::Sentinel,
    steward::Steward,
    sweep::run_sweep,
};

// ── Conversation namespace ────────────────────────────────────────────────────

/// Dedicated `ConversationId` for all officer finding receipts.
///
/// Using a fixed namespace lets callers query officer entries without
/// scanning the full chain — same pattern as `tool_lifecycle_conv_id()`.
/// UUID `00000000-0001-7000-8001-000000000001` — officer cadre namespace.
fn officer_conv_id() -> &'static ConversationId {
    static ID: OnceLock<ConversationId> = OnceLock::new();
    ID.get_or_init(|| {
        ConversationId(Uuid::parse_str("00000000-0001-7000-8001-000000000001").unwrap())
    })
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Runtime configuration for the officer sweep task.
///
/// Populated from `[officers]` in `config.toml` via `ServerConfig`.
pub struct OfficersConfig {
    pub enabled: bool,
    pub sweep_interval_secs: u64,
    pub steward_enabled: bool,
    pub sentinel_enabled: bool,
    pub forge_enabled: bool,
    pub cleo_enabled: bool,
}

// ── Emission helpers ──────────────────────────────────────────────────────────

/// Emit a single finding as a Tier 1 chain receipt.
///
/// Event format: `officer:{name}:{domain}:{finding_type}`.
/// Actor: `officer:{name}` — the chain distinguishes officers by this label.
///
/// TODO(tier2): attach receipt extensions (`finding_type`, `cross_domain_depth`)
/// when the real-time chain watcher is added. For Tier 1 (sweep-only),
/// in-memory `SweepCycle` dedup is sufficient.
fn emit_finding(
    audit_store: &std::sync::Arc<Mutex<AuditStore>>,
    finding: &zp_officers::finding::Finding,
) -> bool {
    let mut store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let action = AuditAction::SystemEvent {
        event: finding.event_key(),
    };
    let policy_decision = PolicyDecision::Allow {
        conditions: vec![finding.summary.clone()],
    };
    let unsealed = UnsealedEntry::new(
        ActorId::System(format!("officer:{}", finding.officer)),
        action,
        officer_conv_id().clone(),
        policy_decision,
        "officer-sweep",
    );

    store.append(unsealed).is_ok()
}

/// Emit the quiet-sweep all-clear receipt.
///
/// Emit a per-officer heartbeat receipt on every sweep cycle.
///
/// This is the independent voice of each officer on the chain. Emitted
/// unconditionally — even on a clean run — so that other officers (Sentinel,
/// Forge) can read each officer's sweep cadence and last-known status without
/// depending on whether any findings were elevated enough to emit individually.
///
/// Event format: `officer:{name}:heartbeat`
/// Actor: `officer:{name}` — the officer speaks for itself.
fn emit_heartbeat(
    audit_store: &std::sync::Arc<Mutex<AuditStore>>,
    result: &OfficerSweepResult,
    completed_at: &chrono::DateTime<chrono::Utc>,
) {
    let max_severity = result
        .findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Ok);

    let mut store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    let action = AuditAction::SystemEvent {
        event: format!("officer:{}:heartbeat", result.officer_name),
    };
    let policy_decision = PolicyDecision::Allow {
        conditions: vec![
            format!("domain={}", result.officer_name),
            format!("finding_count={}", result.findings.len()),
            format!("max_severity={:?}", max_severity),
            format!("sweep_duration_ms={}", result.sweep_duration_ms),
            format!("timestamp={}", completed_at.to_rfc3339()),
        ],
    };
    let unsealed = UnsealedEntry::new(
        ActorId::System(format!("officer:{}", result.officer_name)),
        action,
        officer_conv_id().clone(),
        policy_decision,
        &format!("officer-{}", result.officer_name),
    );
    store.append(unsealed).ok();
}

/// Used when the highest severity across all findings is `Ok` or `Info`.
/// One receipt per sweep instead of N — keeps the chain lean on quiet systems.
/// See design doc §6 R3 (finding receipt volume risk).
fn emit_sweep_clear(
    audit_store: &std::sync::Arc<Mutex<AuditStore>>,
    officer_names: &[&'static str],
    posture_composite: f64,
) {
    let mut store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return,
    };
    let action = AuditAction::SystemEvent {
        event: "system:sweep:officers:all_clear".to_string(),
    };
    let policy_decision = PolicyDecision::Allow {
        conditions: vec![
            format!("officers=[{}]", officer_names.join(",")),
            format!("posture={:.2}", posture_composite),
        ],
    };
    let unsealed = UnsealedEntry::new(
        ActorId::System("officer-cadre".to_string()),
        action,
        officer_conv_id().clone(),
        policy_decision,
        "officer-sweep",
    );
    store.append(unsealed).ok();
}

/// Emit the `posture:computed` receipt at the end of every sweep.
///
/// Always emitted — even on an all-clear cycle — because posture trend
/// over time is a calibration input. See design doc §4.6.
fn emit_posture_receipt(
    audit_store: &std::sync::Arc<Mutex<AuditStore>>,
    posture: &PostureScore,
) {
    let mut store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return,
    };
    let action = AuditAction::SystemEvent {
        event: "posture:computed".to_string(),
    };
    let policy_decision = PolicyDecision::Allow {
        conditions: vec![
            format!("composite={:.2}", posture.composite),
            format!("integrity={:.2}", posture.integrity),
            format!("security={:.2}", posture.security),
            format!("operations={:.2}", posture.operations),
            format!("governance={:.2}", posture.governance),
            format!("trend={:?}", posture.trend),
        ],
    };
    let unsealed = UnsealedEntry::new(
        ActorId::System("officer-cadre".to_string()),
        action,
        officer_conv_id().clone(),
        policy_decision,
        "officer-posture",
    );
    store.append(unsealed).ok();
}

// ── Proposal emission ────────────────────────────────────────────────────────

/// Emit a proposal as a chain receipt.
///
/// Event format: `proposal:{officer}:{mutation_kind}:{tool}` (from `Proposal::event_key()`).
/// The full proposal is serialized into the receipt body for downstream consumers.
fn emit_proposal(
    audit_store: &std::sync::Arc<Mutex<AuditStore>>,
    proposal: &zp_officers::proposal::Proposal,
) -> bool {
    let mut store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let action = AuditAction::SystemEvent {
        event: proposal.event_key(),
    };
    let policy_decision = PolicyDecision::Allow {
        conditions: vec![
            format!("tool={}", proposal.mutation.tool_name()),
            format!("mutation={}", proposal.mutation.kind_label()),
            format!("summary={}", proposal.mutation.summary()),
        ],
    };
    let unsealed = UnsealedEntry::new(
        ActorId::System(format!("officer:{}", proposal.proposed_by)),
        action,
        officer_conv_id().clone(),
        policy_decision,
        "officer-proposal",
    );
    store.append(unsealed).is_ok()
}

// ── Governance request emission ──────────────────────────────────────────────

/// Emit a consolidated governance request as a chain receipt.
///
/// Governance requests merge findings from multiple officers about the same
/// subject into one operator-facing decision point. The receipt carries the
/// full serialized request for downstream cockpit consumption.
///
/// Event format: `governance_request:{severity}:{subject_key}` (from `GovernanceRequest::event_key()`).
fn emit_governance_request(
    audit_store: &std::sync::Arc<Mutex<AuditStore>>,
    request: &GovernanceRequest,
) -> bool {
    let mut store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let action = AuditAction::SystemEvent {
        event: request.event_key(),
    };

    // Conditions carry the operator-facing summary and concern count
    // for quick chain scanning without deserializing the full request.
    let policy_decision = PolicyDecision::Allow {
        conditions: vec![
            format!("subject={}", request.subject.display_label()),
            format!("concerns={}", request.concerns.len()),
            format!("actions={}", request.recommended_actions.len()),
            format!("severity={:?}", request.severity),
        ],
    };

    let unsealed = UnsealedEntry::new(
        ActorId::System("officer-cadre".to_string()),
        action,
        officer_conv_id().clone(),
        policy_decision,
        "governance-request",
    );
    store.append(unsealed).is_ok()
}

// ── Officer attestation emission ────────────────────────────────────────────

/// Emit an officer attestation for a governed tool.
///
/// An attestation is an officer's explicit sign-off: "I swept this tool and
/// found no Warning+ issues." Required for the Hardened facet — silence is
/// not approval. Each enabled officer attests independently; the chain
/// records who said what.
///
/// Event format: `officer:{name}:attested:{tool}`
fn emit_attestation(
    audit_store: &std::sync::Arc<Mutex<AuditStore>>,
    officer_name: &str,
    tool_name: &str,
) -> bool {
    let mut store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let action = AuditAction::SystemEvent {
        event: format!("officer:{}:attested:{}", officer_name, tool_name),
    };
    let policy_decision = PolicyDecision::Allow {
        conditions: vec![
            format!("tool={}", tool_name),
            format!("officer={}", officer_name),
            "sweep_clean=true".to_string(),
        ],
    };
    let unsealed = UnsealedEntry::new(
        ActorId::System(format!("officer:{}", officer_name)),
        action,
        officer_conv_id().clone(),
        policy_decision,
        "officer-attestation",
    );
    store.append(unsealed).is_ok()
}

// ── Officer delegation scanning ─────────────────────────────────────────────

/// Scan the chain for governance:propose delegation receipts targeting officers.
///
/// Delegation receipts have event format `delegation:granted:officer:{name}`
/// and serialize a `CapabilityGrant` in the receipt body. This function
/// reconstructs per-officer delegations from those receipts.
///
/// Returns a map of officer name → OfficerDelegation.
fn collect_officer_delegations(
    chain: &ChainReader<'_>,
) -> std::collections::HashMap<&'static str, OfficerDelegation> {
    use zp_officers::proposal::GOVERNANCE_PROPOSE_CAPABILITY;

    let mut delegations = std::collections::HashMap::new();

    // Scan recent chain for delegation:granted:officer:* entries.
    let entries = match chain.search_by_keyword("delegation:granted:officer:", 500) {
        Ok(e) => e,
        Err(_) => return delegations,
    };

    // Group grants by officer name.
    let mut grants_by_officer: std::collections::HashMap<String, Vec<zp_core::CapabilityGrant>> =
        std::collections::HashMap::new();

    for entry in &entries {
        if let AuditAction::SystemEvent { event } = &entry.action {
            if let Some(officer_name) = event.strip_prefix("delegation:granted:officer:") {
                // Try to deserialize the grant from the receipt body.
                // The body is in the receipt's extensions or in the policy decision conditions.
                // For now, check receipt extensions for the serialized grant.
                if let Some(receipt) = &entry.receipt {
                    if let Some(exts) = &receipt.extensions {
                        if let Some(grant_json) = exts.get("grant") {
                            if let Ok(grant) = serde_json::from_value::<zp_core::CapabilityGrant>(
                                grant_json.clone(),
                            ) {
                                // Only keep governance:propose grants.
                                if let zp_core::GrantedCapability::Custom { name, .. } =
                                    &grant.capability
                                {
                                    if name == GOVERNANCE_PROPOSE_CAPABILITY {
                                        grants_by_officer
                                            .entry(officer_name.to_string())
                                            .or_default()
                                            .push(grant);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Build OfficerDelegation for each known officer.
    for (name, officer_name_static) in [
        ("std", "std"),
        ("sen", "sen"),
        ("forge", "forge"),
        ("cleo", "cleo"),
    ] {
        if let Some(grants) = grants_by_officer.get(name) {
            delegations.insert(officer_name_static, OfficerDelegation::from_grants(grants));
        }
    }

    delegations
}

/// Get the delegation for a specific officer, falling back to no delegation.
fn get_officer_delegation(
    delegations: &std::collections::HashMap<&'static str, OfficerDelegation>,
    officer_name: &str,
) -> OfficerDelegation {
    delegations
        .get(officer_name)
        .cloned()
        .unwrap_or_else(OfficerDelegation::none)
}

// ── Vault key listing ─────────────────────────────────────────────────────────

/// Collect vault key names for the sweep.
///
/// Officers see key *names* only, never secret values (R1 privilege invariant).
/// Returns an empty list if:
/// - The vault key hasn't resolved yet (background thread still running).
/// - The vault is unavailable or corrupt.
///
/// Steward will report these conditions via findings rather than silently
/// skipping — an empty `VaultKeyLister` is a meaningful signal.
fn collect_vault_key_names(
    vault_key: &OnceLock<Option<zp_keys::ResolvedVaultKey>>,
    data_dir: &str,
) -> Vec<String> {
    let resolved = match vault_key.get().and_then(|k| k.as_ref()) {
        Some(k) => k,
        None => {
            debug!("Officer sweep: vault key not yet resolved — vault checks will use empty lister");
            return vec![];
        }
    };

    let vault_path = zp_core::paths::vault_path()
        .unwrap_or_else(|_| std::path::PathBuf::from(data_dir).join("vault.json"));

    match zp_trust::CredentialVault::load_or_create(&resolved.key, &vault_path) {
        Ok(vault) => vault.list(),
        Err(e) => {
            warn!("Officer sweep: vault open failed — vault checks will use empty lister: {}", e);
            vec![]
        }
    }
}

// ── Sweep task ────────────────────────────────────────────────────────────────

/// Spawn the periodic officer sweep task.
///
/// Fires every `config.sweep_interval_secs` (default: 900 = 15 min).
/// Skips the immediate first tick so the server can finish startup before
/// the first sweep fires.
///
/// Each sweep cycle:
/// 1. Collects vault key names (brief, outside the audit store lock).
/// 2. Acquires the audit store lock, runs all officer sweeps, releases.
///    For Tier 1, sweeps complete in milliseconds — lock contention is negligible.
/// 3. Always emits one `officer:{name}:heartbeat` per officer (the layered observer contract).
/// 4. Quiet mode: if all findings are Ok/Info, emits one `system:sweep:officers:all_clear`.
///    Otherwise, emits individual finding receipts for Warning+ findings.
/// 5. Always emits `posture:computed`.
///
/// Staggering (Steward → Sentinel → Forge at 5-min offsets): applied in the
/// `run_sweep` call order when multiple officers are present. No-op for Tier 1
/// (Steward only). See design doc §8 open question on staggering.
///
/// TODO(tier2): if LLM reasoning is added inside officer sweeps, snapshot
/// chain entries before acquiring the lock and release before calling the LLM.
pub fn spawn_sweep_task(
    config: OfficersConfig,
    state: std::sync::Arc<crate::AppStateInner>,
) {
    if !config.enabled {
        debug!("Officer cadre disabled (`[officers] enabled = false`) — sweep task not spawned");
        return;
    }

    tokio::spawn(async move {
        let interval_secs = config.sweep_interval_secs.max(1);
        let mut ticker = tokio::time::interval(
            tokio::time::Duration::from_secs(interval_secs),
        );
        // MissedTickBehavior::Skip: if a sweep takes longer than the interval
        // (shouldn't happen in Tier 1, but defensive), skip missed ticks
        // rather than firing a burst to catch up.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate t=0 tick — first real sweep fires after one
        // full interval, giving the server time to finish startup.
        ticker.tick().await;

        // ── Build officer roster ──────────────────────────────────────────
        // Order matters for future staggering: Steward → Sentinel → Forge.
        // Order matters for future staggering: Steward → Sentinel → Forge → Cleo.
        let mut officers: Vec<Box<dyn zp_officers::officer::Officer>> = Vec::new();
        if config.steward_enabled {
            officers.push(Box::new(Steward::new()));
        }
        if config.sentinel_enabled {
            officers.push(Box::new(Sentinel::new()));
        }
        if config.forge_enabled {
            officers.push(Box::new(Forge::new()));
        }
        if config.cleo_enabled {
            officers.push(Box::new(Cleo::new()));
        }

        if officers.is_empty() {
            info!("Officer cadre: no officers enabled — sweep task idle");
            return;
        }

        let officer_names: Vec<&'static str> = officers.iter().map(|o| o.name()).collect();
        info!(
            officers = ?officer_names,
            interval_secs,
            "Officer cadre started",
        );

        let mut last_posture: Option<PostureScore> = None;

        loop {
            ticker.tick().await;
            debug!(officers = officers.len(), "Officer sweep starting");

            // Step 1: collect vault key names outside the audit store lock.
            let vault_key_names =
                collect_vault_key_names(&state.vault_key, &state.data_dir);
            let vault_keys = VaultKeyLister::new(vault_key_names);

            // Step 2: acquire lock → run sweep → release.
            let result = {
                let store = match state.audit_store.lock() {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Officer sweep: audit store lock poisoned: {}", e);
                        continue;
                    }
                };
                let chain = ChainReader::new(&store);
                run_sweep(&officers, &chain, &vault_keys)
            }; // MutexGuard dropped here — lock released.

            // Apply trend before emitting the posture receipt.
            let posture = result.posture.with_trend(last_posture.as_ref());

            // Step 3: per-officer heartbeats — always emitted, one per officer.
            // Each officer speaks for itself on the chain regardless of findings.
            // This is the contract the layered observer model depends on: Sentinel
            // and Forge can read Steward's heartbeat to know it ran and what it saw,
            // without relying on whether any finding was elevated enough to emit.
            for officer_result in &result.per_officer {
                emit_heartbeat(&state.audit_store, officer_result, &result.completed_at);
            }

            // Step 4: quiet sweep mode.
            let highest = result
                .findings
                .iter()
                .map(|f| f.severity)
                .max()
                .unwrap_or(Severity::Ok);

            let emitted = if highest <= Severity::Info {
                // All clear — one receipt, not N.
                emit_sweep_clear(&state.audit_store, &officer_names, posture.composite);
                0usize
            } else {
                // Emit individual receipts for Warning+ findings only.
                // Ok/Info findings are still captured in the posture score
                // but don't need their own chain entry.
                let mut n = 0;
                for finding in &result.findings {
                    if finding.severity > Severity::Info {
                        if emit_finding(&state.audit_store, finding) {
                            n += 1;
                        }
                    }
                }
                n
            };

            // Step 5: Band 2 proposals — delegation-gated.
            // Only officers with governance:propose delegation can emit proposals.
            // Currently only Forge has a propose() method; other officers will
            // gain it as their domains mature.
            let (authorized_proposals, proposals_emitted) = if config.forge_enabled {
                let authorized: Vec<zp_officers::proposal::Proposal> = {
                    let store = match state.audit_store.lock() {
                        Ok(s) => s,
                        Err(_) => {
                            warn!("Officer proposals: audit store lock poisoned");
                            continue;
                        }
                    };
                    let chain = ChainReader::new(&store);
                    let delegations = collect_officer_delegations(&chain);
                    let delegation = get_officer_delegation(&delegations, "forge");
                    let forge = Forge::new();
                    let mut proposals = forge.propose(&chain);
                    proposals.extend(forge.propose_from_findings(&result.findings));
                    delegation.filter_proposals(proposals)
                }; // lock released

                let mut n = 0usize;
                for proposal in &authorized {
                    if emit_proposal(&state.audit_store, proposal) {
                        n += 1;
                    }
                }
                if n > 0 {
                    debug!(proposals = n, "Forge proposals emitted (Band 2)");
                }

                (authorized, n)
            } else {
                (Vec::new(), 0usize)
            };

            // Step 5b: consolidate findings + proposals into governance requests.
            // One request per subject — the cockpit's operator-facing decision surface.
            let governance_requests = consolidate(&result.findings, &authorized_proposals);
            let mut governance_emitted = 0usize;
            for req in &governance_requests {
                // Only emit requests with Warning+ severity — Info-level
                // consolidations are captured in posture but don't need
                // their own chain entry (same quiet-sweep principle as Step 4).
                if req.severity > Severity::Info {
                    if emit_governance_request(&state.audit_store, req) {
                        governance_emitted += 1;
                    }
                }
            }

            // Step 5c: officer attestations for governed tools.
            // Each officer that found no Warning+ issues for a governed tool
            // emits an attestation receipt. Required for Hardened facet —
            // silence is not approval; the chain must carry explicit sign-off.
            {
                use zp_officers::governance_posture::{
                    compute_postures, GovernanceFacet, RegisteredToolInfo,
                    ToolRegistrySnapshot, UnregisteredTools,
                };

                // Build port registry snapshot.
                let bindings = state.port_registry.list();
                let mut snapshot = ToolRegistrySnapshot::default();
                for b in &bindings {
                    snapshot.registered_tools.insert(
                        b.tool.clone(),
                        RegisteredToolInfo {
                            port: b.port,
                            pid: b.pid,
                            has_launch_command: b.launch_command.is_some(),
                        },
                    );
                }
                let unregistered = UnregisteredTools::new();

                // Compute postures to find governed tools.
                let postures = {
                    let store = match state.audit_store.lock() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let chain = ChainReader::new(&store);
                    compute_postures(&chain, &snapshot, &unregistered)
                };

                let governed_tools: Vec<&str> = postures
                    .iter()
                    .filter(|p| p.has(GovernanceFacet::Governed))
                    .map(|p| p.tool_name.as_str())
                    .collect();

                if !governed_tools.is_empty() {
                    // Build set of (officer, tool) pairs with Warning+ findings.
                    let mut warned: std::collections::HashSet<(String, String)> =
                        std::collections::HashSet::new();
                    for finding in &result.findings {
                        if finding.severity > Severity::Info {
                            if let Some(tool) = finding.detail.get("tool").and_then(|v| v.as_str()) {
                                warned.insert((finding.officer.to_string(), tool.to_string()));
                            }
                        }
                    }

                    // Dedup: find existing attestations on chain so we don't
                    // re-emit every sweep. Only emit when (officer, tool) pair
                    // has no prior attestation, or when a warning was found
                    // (which clears the prior attestation's validity — but we
                    // skip emission in that case via the warned set above).
                    let mut already_attested: std::collections::HashSet<(String, String)> =
                        std::collections::HashSet::new();
                    {
                        let store = match state.audit_store.lock() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let chain = ChainReader::new(&store);
                        if let Ok(entries) = chain.search_by_keyword("attested:", 500) {
                            for entry in &entries {
                                if let zp_core::AuditAction::SystemEvent { event } = &entry.action {
                                    if let Some(rest) = event.strip_prefix("officer:") {
                                        if let Some(pos) = rest.find(":attested:") {
                                            let officer_name = &rest[..pos];
                                            let tool_name = &rest[pos + ":attested:".len()..];
                                            if !tool_name.is_empty() {
                                                already_attested.insert((
                                                    officer_name.to_string(),
                                                    tool_name.to_string(),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let mut attestations = 0usize;
                    for officer in &officers {
                        for tool in &governed_tools {
                            let pair = (officer.name().to_string(), tool.to_string());
                            if !warned.contains(&pair) && !already_attested.contains(&pair) {
                                if emit_attestation(&state.audit_store, officer.name(), tool) {
                                    attestations += 1;
                                }
                            }
                        }
                    }
                    if attestations > 0 {
                        debug!(attestations, tools = governed_tools.len(), "Officer attestations emitted");
                    }
                }
            }

            // Step 6: posture receipt — always, every sweep.
            emit_posture_receipt(&state.audit_store, &posture);

            info!(
                officers = officers.len(),
                findings_total = result.findings.len(),
                findings_emitted = emitted,
                proposals_emitted,
                governance_requests = governance_requests.len(),
                governance_emitted,
                posture = format!("{:.2}", posture.composite),
                trend = format!("{:?}", posture.trend),
                "Officer sweep complete",
            );

            last_posture = Some(posture);
        }
    });
}

// ── Sensor-driven Forge activation ───────────────────────────────────────────

/// Spawn a task that listens for sensor events and triggers Forge sweeps.
///
/// This is the immune-system complement to the periodic sweep: sensor events
/// (file changes, process exits, new listeners) activate Forge immediately
/// rather than waiting for the next periodic cycle. Only Forge runs here —
/// Steward, Sentinel, and Cleo stay on their periodic timer.
///
/// **Deactivation (step 5).** After each sweep, governance posture is computed
/// for all tools. Hardened tools are marked dormant — subsequent sensor events
/// for those tools are skipped (zero compute). Any sensor fire that names a
/// dormant tool reactivates it: dormancy drops, sweep runs, posture recomputed.
/// Events without a tool name (e.g. `FileChanged` on `tool-ports.json`) always
/// trigger a sweep and clear all dormancy (the file could affect any tool).
/// Sensors stay registered regardless of dormancy (cheap kqueue watches).
pub fn spawn_sensor_forge_task(
    mut sensor_rx: tokio::sync::mpsc::Receiver<zp_sensors::SensorEvent>,
    state: std::sync::Arc<crate::AppStateInner>,
) {
    tokio::spawn(async move {
        let forge = Forge::new();
        let mut dormant: std::collections::HashSet<String> = std::collections::HashSet::new();

        info!("Sensor-driven Forge activation started");

        while let Some(event) = sensor_rx.recv().await {
            // ── Dormancy gate ────────────────────────────────────────────
            // Tool-specific events: if the tool is dormant, reactivate it.
            // Non-tool events (FileChanged, NewListenerDiscovered): clear
            // all dormancy since any tool could be affected.
            match event.tool_name() {
                Some(name) => {
                    if dormant.contains(name) {
                        info!(tool = name, "Reactivating dormant tool (sensor fire)");
                        dormant.remove(name);
                        emit_forge_lifecycle(&state.audit_store, name, "reactivated");
                    }
                }
                None => {
                    // Broad event — any tool could be affected.
                    if !dormant.is_empty() {
                        debug!(
                            count = dormant.len(),
                            "Clearing all dormancy (broad sensor event)"
                        );
                        for tool in dormant.drain() {
                            emit_forge_lifecycle(&state.audit_store, &tool, "reactivated");
                        }
                    }
                }
            }

            debug!(
                kind = event.kind_label(),
                dormant = dormant.len(),
                "Sensor event → Forge activation"
            );

            // Collect vault key names.
            let vault_key_names =
                collect_vault_key_names(&state.vault_key, &state.data_dir);
            let vault_keys = VaultKeyLister::new(vault_key_names);

            // Run Forge sweep under audit store lock.
            let mut findings = {
                let store = match state.audit_store.lock() {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Sensor Forge: audit store lock poisoned: {}", e);
                        continue;
                    }
                };
                let chain = ChainReader::new(&store);
                forge.sweep(&chain, &vault_keys)
            };

            // ── NewListenerDiscovered: run Sentinel + Forge assessments ────
            // The sweep reads the chain; these assessments evaluate the
            // specific process the sensor just discovered.
            if let zp_sensors::SensorEvent::NewListenerDiscovered {
                pid, process_name, ports, context, ..
            } = &event {
                let ports_json: Vec<serde_json::Value> = ports
                    .iter()
                    .map(|p| serde_json::json!({
                        "port": p.port,
                        "protocol": &p.protocol,
                        "socket": &p.socket,
                    }))
                    .collect();
                let context_json = serde_json::to_value(context)
                    .unwrap_or(serde_json::Value::Null);

                // Sentinel: security assessment (root? network-exposed? unusual parent?)
                let sentinel = Sentinel::new();
                findings.extend(
                    sentinel.assess_unauthorized_listener(
                        *pid, process_name, &ports_json, &context_json,
                    )
                );

                // Forge: operations assessment (should this be governed?)
                findings.extend(
                    forge.assess_unregistered_listener(
                        *pid, process_name, &ports_json, &context_json,
                    )
                );
            }

            // Emit findings for Warning+ severity.
            let mut emitted = 0usize;
            for finding in &findings {
                if finding.severity > Severity::Info {
                    if emit_finding(&state.audit_store, finding) {
                        emitted += 1;
                    }
                }
            }

            // ── Band 2 proposals (delegation-gated) ─────────────────────
            let authorized_proposals = {
                let store = match state.audit_store.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        if emitted > 0 {
                            info!(trigger = event.kind_label(), findings = findings.len(), emitted, "Sensor Forge sweep complete");
                        }
                        continue;
                    }
                };
                let chain = ChainReader::new(&store);
                let delegations = collect_officer_delegations(&chain);
                let delegation = get_officer_delegation(&delegations, "forge");
                // Merge chain-reading proposals with findings-based proposals.
                let mut proposals = forge.propose(&chain);
                proposals.extend(forge.propose_from_findings(&findings));
                delegation.filter_proposals(proposals)
            }; // lock released

            let mut proposals_emitted_count = 0usize;
            for proposal in &authorized_proposals {
                if emit_proposal(&state.audit_store, proposal) {
                    proposals_emitted_count += 1;
                }
            }

            // ── Consolidate into governance requests ────────────────────
            let governance_requests = consolidate(&findings, &authorized_proposals);
            let mut governance_emitted = 0usize;
            for req in &governance_requests {
                if req.severity > Severity::Info {
                    if emit_governance_request(&state.audit_store, req) {
                        governance_emitted += 1;
                    }
                }
            }

            if emitted > 0 || proposals_emitted_count > 0 || governance_emitted > 0 {
                info!(
                    trigger = event.kind_label(),
                    findings = findings.len(),
                    emitted,
                    proposals = proposals_emitted_count,
                    governance_requests = governance_requests.len(),
                    governance_emitted,
                    "Sensor-driven Forge sweep complete"
                );
            }

            // ── Post-sweep dormancy computation ──────────────────────────
            // Compute governance posture. Tools that reach Hardened go dormant.
            {
                use zp_officers::governance_posture::{
                    compute_postures, GovernanceFacet, RegisteredToolInfo,
                    ToolRegistrySnapshot, UnregisteredTools,
                };

                let data_path = std::path::Path::new(&state.data_dir);
                let registry = crate::tool_ports::PortRegistry::new(data_path);
                let bindings = registry.list();

                let mut snapshot = ToolRegistrySnapshot::default();
                for b in &bindings {
                    snapshot.registered_tools.insert(
                        b.tool.clone(),
                        RegisteredToolInfo {
                            port: b.port,
                            pid: b.pid,
                            has_launch_command: b.launch_command.is_some(),
                        },
                    );
                }

                let unregistered = UnregisteredTools::new();

                let postures = {
                    let store = match state.audit_store.lock() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let chain = ChainReader::new(&store);
                    compute_postures(&chain, &snapshot, &unregistered)
                };

                for p in &postures {
                    if p.has(GovernanceFacet::Hardened) && !dormant.contains(&p.tool_name) {
                        info!(tool = %p.tool_name, "Tool hardened — Forge deactivating");
                        dormant.insert(p.tool_name.clone());
                        emit_forge_lifecycle(&state.audit_store, &p.tool_name, "deactivated");
                    }
                }
            }

            if !dormant.is_empty() {
                debug!(dormant = ?dormant, "Forge dormancy state");
            }
        }

        debug!("Sensor event channel closed, Forge sensor task exiting");
    });
}

/// Emit a Forge lifecycle receipt (deactivated/reactivated).
fn emit_forge_lifecycle(
    audit_store: &std::sync::Arc<Mutex<AuditStore>>,
    tool_name: &str,
    action: &str,
) {
    let mut store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return,
    };
    let unsealed = UnsealedEntry::new(
        ActorId::System("officer:forge".to_string()),
        AuditAction::SystemEvent {
            event: format!("forge:{}:{}", action, tool_name),
        },
        officer_conv_id().clone(),
        PolicyDecision::Allow {
            conditions: vec![format!("tool={}", tool_name)],
        },
        "forge-lifecycle",
    );
    store.append(unsealed).ok();
}
