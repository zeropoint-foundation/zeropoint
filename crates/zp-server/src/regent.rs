//! Regent integration — wires the cognitive loop into zp-server.
//!
//! Handles:
//! - Constructing the Regent from server config
//! - Implementing `IntentExecutor` to bridge intents to chain receipts
//! - Gate evaluation and tool dispatch for `Intent::Execute`
//! - Spawning the cognitive loop
//! - Providing the `RegentHandle` for cockpit surfaces

use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use zp_audit::{AuditStore, UnsealedEntry};
use zp_core::{ActorId, AuditAction, CapabilityGrant, ConversationId, GrantedCapability, PolicyDecision};
use zp_core::policy::ActionType;
use zp_policy::GovernanceGate;

use zp_regent::config::RegentConfig;
use zp_regent::error::RegentError;
use zp_regent::inference::InferenceBackend;
use zp_regent::intent::Intent;
use zp_regent::loop_runner::{IntentExecutor, IntentOutcome, RegentHandle};
use zp_regent::regent::Regent;

/// The Regent's tool surface: capability name and delegation scope.
///
/// **Single source of truth.** Both the `CapabilityGrant` the gate honours and
/// the `DelegationSummary` list the Regent perceives are built from this array.
/// They were previously two hand-maintained lists and drifted: `browser_use`
/// appeared in the perceived-delegation list but not in the grant, so the
/// Regent believed she held a capability the gate would deny (2026-07-26).
///
/// Presence in this array **is** the grant. Adding an entry grants the
/// capability; that is an authority decision, not a lint fix.
///
/// `browser_use` was granted 2026-07-26. Three defects were closed at the
/// same time, because granting is what made them reachable: the domain gate
/// was a substring test against the whole URL, the three Python parameter
/// interpolations escaped only single quotes, and the `js` action carried no
/// URL and so never reached the gate at all. The gate is now host-anchored,
/// parameters are encoded as JSON string literals, and `js` pre-flights
/// `page_info()` and is held to the same allowlist, failing closed when the
/// focused tab's URL cannot be read.
///
/// The `web:allowed_domains` scope selector is not yet read by anything —
/// `ALLOWED_DOMAINS` is a hardcoded const in the dispatch arm. The grant is
/// genuinely narrow, but narrower than the delegation advertises; moving the
/// list onto the delegation is the follow-up that makes the scope real.
const REGENT_TOOLS: &[(&str, &str)] = &[
    ("chain_query", "audit_chain"),
    ("governance_posture", "governance"),
    ("model_evaluate", "inference"),
    ("system_status", "system"),
    ("batch_sign", "audit_chain"),
    ("chain_compact", "audit_chain"),
    ("self_configure", "inference:endpoint,model,api_key"),
    ("memory_list", "cognition:memory_promotion"),
    ("memory_review", "cognition:memory_promotion:review_remembered"),
    ("substrate_validate", "substrate:validation:regent"),
    ("browser_use", "web:allowed_domains"),
];

// ── Conversation namespace ──────────────────────────────────────────────────

/// Dedicated `ConversationId` for all Regent receipts.
/// UUID `00000000-0002-7000-8001-000000000001` — regent namespace.
fn regent_conv_id() -> ConversationId {
    ConversationId(Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap())
}

/// Actor identity for the Regent in all gate evaluations and receipts.
fn regent_actor() -> ActorId {
    ActorId::System("regent".to_string())
}

// ── Receipt helper for background tasks ─────────────────────────────────────

/// Emit a receipt from a background task that doesn't have `&self`.
fn emit_receipt_to_store(store: &Arc<std::sync::Mutex<AuditStore>>, event: &str) {
    let mut guard = match store.lock() {
        Ok(s) => s,
        Err(e) => {
            warn!("shadow battery receipt: audit store lock poisoned: {}", e);
            return;
        }
    };
    let entry = UnsealedEntry {
        actor: regent_actor(),
        action: AuditAction::SystemEvent {
            event: event.to_string(),
        },
        conversation_id: regent_conv_id(),
        policy_decision: PolicyDecision::Allow {
            conditions: Vec::new(),
        },
        policy_module: "regent".to_string(),
        receipt: None,
    };
    if let Err(e) = guard.append(entry) {
        warn!("shadow battery receipt emission failed: {}", e);
    }
}

// ── IntentExecutor ──────────────────────────────────────────────────────────

/// Server-side intent executor — bridges Regent intents to chain receipts,
/// gate evaluation, tool dispatch, and response delivery.
pub struct ServerIntentExecutor {
    audit_store: Arc<std::sync::Mutex<AuditStore>>,
    gate: Arc<GovernanceGate>,
    /// Broadcast channel for SSE event delivery to cockpit surfaces.
    event_tx: tokio::sync::broadcast::Sender<crate::events::EventStreamItem>,
    /// Inference backend for tools that need model access (e.g. model_evaluate).
    inference: Arc<InferenceBackend>,
    /// System monitor — shared with the loop runner for system_status queries.
    system_monitor: Arc<tokio::sync::Mutex<zp_regent::awareness::SystemMonitor>>,
    /// Reference to the Regent for self_configure tool.
    regent: Arc<Mutex<Regent>>,
    /// Operator name from Genesis, for evaluation battery construction.
    operator_name: String,
    /// Genesis public key prefix, for evaluation battery construction.
    genesis_prefix: String,
    /// Memory promotion engine — for memory_list and memory_review tools.
    promotion_engine: Arc<std::sync::Mutex<zp_memory::PromotionEngine>>,
    /// Review queue — for memory_review tool (submit/decide reviews).
    review_queue: Option<Arc<std::sync::Mutex<zp_memory::ReviewQueue>>>,
    /// Shared reference to the vault key, resolved lazily by a background thread.
    /// The Regent checks this at `self_configure` time, not spawn time — avoids
    /// the startup race where the Regent spawns before keychain resolution finishes.
    vault_key: Arc<std::sync::OnceLock<Option<zp_keys::ResolvedVaultKey>>>,
    /// Path to vault.json on disk.
    vault_path: std::path::PathBuf,
}

impl ServerIntentExecutor {
    pub fn new(
        audit_store: Arc<std::sync::Mutex<AuditStore>>,
        gate: Arc<GovernanceGate>,
        event_tx: tokio::sync::broadcast::Sender<crate::events::EventStreamItem>,
        inference: Arc<InferenceBackend>,
        system_monitor: Arc<tokio::sync::Mutex<zp_regent::awareness::SystemMonitor>>,
        regent: Arc<Mutex<Regent>>,
        operator_name: String,
        genesis_prefix: String,
        promotion_engine: Arc<std::sync::Mutex<zp_memory::PromotionEngine>>,
        review_queue: Option<Arc<std::sync::Mutex<zp_memory::ReviewQueue>>>,
        vault_key: Arc<std::sync::OnceLock<Option<zp_keys::ResolvedVaultKey>>>,
        vault_path: std::path::PathBuf,
    ) -> Self {
        Self {
            audit_store,
            gate,
            event_tx,
            inference,
            system_monitor,
            regent,
            operator_name,
            genesis_prefix,
            promotion_engine,
            review_queue,
            vault_key,
            vault_path,
        }
    }

    /// Resolve the vault master key bytes lazily from the shared OnceLock.
    /// Returns None if the keychain thread hasn't finished yet or resolution failed.
    fn vault_master_key(&self) -> Option<[u8; 32]> {
        self.vault_key
            .get()
            .and_then(|k| k.as_ref())
            .map(|resolved| *resolved.key)
    }

    /// Emit a Regent intent as a chain receipt.
    fn emit_receipt(&self, event: &str, detail: Option<&str>) {
        let mut store = match self.audit_store.lock() {
            Ok(s) => s,
            Err(e) => {
                warn!("regent receipt: audit store lock poisoned: {}", e);
                return;
            }
        };

        // Encode detail into the event string — SystemEvent only has one field.
        let event_str = match detail {
            Some(d) => format!("{} | {}", event, d),
            None => event.to_string(),
        };

        let entry = UnsealedEntry {
            actor: regent_actor(),
            action: AuditAction::SystemEvent {
                event: event_str,
            },
            conversation_id: regent_conv_id(),
            policy_decision: PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "regent".to_string(),
            receipt: None,
        };

        if let Err(e) = store.append(entry) {
            warn!("regent receipt emission failed: {}", e);
        }
    }

    /// Emit a structured remediation receipt.
    ///
    /// These are the chain's memory of autonomous Regent actions —
    /// the foundation for the precedent system. Future cycles query
    /// for `regent:remediation:*` events to determine whether the
    /// Regent has precedent for autonomous action.
    fn emit_remediation_receipt(
        &self,
        tool: &str,
        finding_type: &str,
        entries_affected: u64,
        outcome: &str,
    ) {
        let mut store = match self.audit_store.lock() {
            Ok(s) => s,
            Err(e) => {
                warn!("regent remediation receipt: audit store lock poisoned: {}", e);
                return;
            }
        };

        // The event string encodes the remediation verb.
        // Metadata goes in a structured format parseable by precedent queries.
        let event = format!(
            "regent:remediation:{} finding_type={} entries_affected={} outcome={}",
            tool, finding_type, entries_affected, outcome,
        );

        let entry = UnsealedEntry {
            actor: regent_actor(),
            action: AuditAction::SystemEvent { event },
            conversation_id: regent_conv_id(),
            policy_decision: PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "regent".to_string(),
            receipt: None,
        };

        if let Err(e) = store.append(entry) {
            warn!("regent remediation receipt emission failed: {}", e);
        } else {
            info!(
                tool,
                finding_type,
                entries_affected,
                "regent: remediation receipt emitted — precedent established"
            );
        }
    }

    /// Spawn the shadow validation battery as a background task.
    ///
    /// Runs `run_battery` for each pending candidate, then updates pin
    /// state and emits chain receipts. The groomed model stays active
    /// throughout — operator interactions are never degraded.
    fn spawn_shadow_battery(&self) {
        let regent = Arc::clone(&self.regent);
        let inference = Arc::clone(&self.inference);
        let audit_store = Arc::clone(&self.audit_store);

        tokio::spawn(async move {
            // Snapshot candidates and dossier corpus while holding the lock briefly.
            let (candidates, active_model) = {
                let regent_guard = regent.lock().await;
                let candidates: Vec<(String, zp_regent::shadow_validation::EvaluationTier)> =
                    regent_guard
                        .shadow_candidates()
                        .into_iter()
                        .filter(|c| matches!(c.state, zp_regent::ShadowCandidateState::Pending))
                        .map(|c| {
                            let tier = zp_regent::shadow_validation::determine_tier(
                                &c.model,
                                regent_guard.dossier_corpus(),
                            );
                            (c.model.clone(), tier)
                        })
                        .collect();

                let active = regent_guard.config().reasoning_model.clone();
                (candidates, active)
            };

            if candidates.is_empty() {
                debug!("shadow battery: no pending candidates, skipping");
                return;
            }

            info!(
                count = candidates.len(),
                active = %active_model,
                "shadow battery: evaluating candidates"
            );

            // Run battery for each candidate.
            for (candidate_model, tier) in &candidates {
                let result = zp_regent::shadow_validation::run_battery(
                    &inference,
                    candidate_model,
                    *tier,
                )
                .await;

                // Emit per-check receipts.
                for check in &result.checks {
                    let event = format!(
                        "regent:config:inference:shadow_result | candidate={} check={} passed={} latency={}ms detail={}",
                        candidate_model, check.check, check.passed, check.latency_ms,
                        &check.detail[..check.detail.len().min(200)],
                    );
                    emit_receipt_to_store(&audit_store, &event);
                }

                // Update candidate state based on result.
                let mut regent_guard = regent.lock().await;
                if result.passed {
                    regent_guard.pass_shadow_candidate(candidate_model);
                    info!(
                        candidate = %candidate_model,
                        summary = %result.summary,
                        "shadow battery: candidate PASSED"
                    );
                } else {
                    regent_guard.reject_shadow_candidate(
                        candidate_model,
                        result.summary.clone(),
                    );
                    let event = format!(
                        "regent:config:inference:shadow_rejected | candidate={} reason={}",
                        candidate_model, result.summary,
                    );
                    emit_receipt_to_store(&audit_store, &event);
                    info!(
                        candidate = %candidate_model,
                        summary = %result.summary,
                        "shadow battery: candidate REJECTED"
                    );
                }
            }

            // After all candidates evaluated, check if any passed.
            // If exactly one passed, auto-promote it.
            // If multiple passed, leave for operator selection.
            let mut regent_guard = regent.lock().await;
            let passed: Vec<String> = regent_guard
                .shadow_candidates()
                .into_iter()
                .filter(|c| matches!(c.state, zp_regent::ShadowCandidateState::Passed))
                .map(|c| c.model.clone())
                .collect();

            if passed.len() == 1 {
                let winner = &passed[0];
                if let Some(old_model) = regent_guard.promote_shadow_candidate(winner) {
                    let event = format!(
                        "regent:config:inference | reasoning={} via=shadow_evaluation prior={}",
                        winner, old_model,
                    );
                    emit_receipt_to_store(&audit_store, &event);
                    info!(
                        model = %winner,
                        prior = %old_model,
                        "shadow battery: auto-promoted single passing candidate"
                    );
                }
            } else if passed.is_empty() {
                info!("shadow battery: all candidates rejected — groomed model stays active");
            } else {
                info!(
                    passed = ?passed,
                    "shadow battery: multiple candidates passed — awaiting operator selection"
                );
            }
        });
    }

    /// Dispatch a tool call. Phase 0+: substrate queries and model evaluation.
    async fn dispatch_tool(
        &self,
        tool: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RegentError> {
        match tool {
            "chain_query" => {
                let limit = params
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20) as usize;
                let filter = params
                    .get("filter")
                    .and_then(|v| v.as_str());
                let store = self
                    .audit_store
                    .lock()
                    .map_err(|e| RegentError::ChainRead(e.to_string()))?;

                let entries = if let Some(keyword) = filter {
                    // Filtered query — search for entries matching a keyword.
                    // Used by the precedent system: filter="regent:remediation:"
                    // finds all prior autonomous remediation receipts.
                    store
                        .search_chain_by_action_keyword(keyword, limit)
                        .map_err(|e| RegentError::ChainRead(e.to_string()))?
                } else {
                    store
                        .recent_entries(limit)
                        .map_err(|e| RegentError::ChainRead(e.to_string()))?
                };

                let summaries: Vec<_> = entries
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "id": e.id.0,
                            "action": format!("{:?}", e.action),
                            "actor": format!("{:?}", e.actor),
                            "timestamp": e.timestamp.to_rfc3339(),
                        })
                    })
                    .collect();
                Ok(serde_json::json!({
                    "entries": summaries,
                    "count": summaries.len(),
                }))
            }

            "governance_posture" => {
                let store = self
                    .audit_store
                    .lock()
                    .map_err(|e| RegentError::ChainRead(e.to_string()))?;
                let count = store
                    .entry_count()
                    .map_err(|e| RegentError::ChainRead(e.to_string()))?;
                Ok(serde_json::json!({
                    "chain_length": count,
                    "gate_active": true,
                }))
            }

            "model_evaluate" => {
                zp_regent::evaluation::dispatch_model_evaluate(
                    &self.inference,
                    params,
                    &self.operator_name,
                    &self.genesis_prefix,
                )
                .await
            }

            "system_status" => {
                zp_regent::awareness::dispatch_system_status(&self.system_monitor).await
            }

            "batch_sign" => {
                // Remediation tool: retroactively sign unsigned entries.
                // This is the Regent's immune response to Sentinel findings
                // about unsigned entries on the chain.
                let mut store = self
                    .audit_store
                    .lock()
                    .map_err(|e| RegentError::ChainRead(e.to_string()))?;
                let unsigned_before = store
                    .unsigned_entry_count()
                    .map_err(|e| RegentError::ChainRead(e.to_string()))?;
                if unsigned_before == 0 {
                    return Ok(serde_json::json!({
                        "signed": 0,
                        "message": "No unsigned entries found — chain is fully signed."
                    }));
                }
                let signed = store
                    .backfill_signatures()
                    .map_err(|e| RegentError::Execution(format!("batch_sign failed: {}", e)))?;
                // Release the store lock before emitting the remediation receipt,
                // which acquires its own lock.
                drop(store);
                info!(signed, "regent: batch_sign remediation completed");

                // Emit structured remediation receipt — the chain's memory of
                // this autonomous action. Future cycles query these for precedent.
                self.emit_remediation_receipt(
                    "batch_sign",
                    "unsigned_entries",
                    signed,
                    "signed",
                );

                Ok(serde_json::json!({
                    "signed": signed,
                    "message": format!("Signed {} previously unsigned entries.", signed)
                }))
            }

            "chain_compact" => {
                // Maintenance tool: archive old chain entries to keep the
                // active chain fast. Retains the most recent entries.
                let retain = params
                    .get("retain")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10_000) as usize;
                let mut store = self
                    .audit_store
                    .lock()
                    .map_err(|e| RegentError::ChainRead(e.to_string()))?;
                let total = store
                    .entry_count()
                    .map_err(|e| RegentError::ChainRead(e.to_string()))?;
                if (total as usize) <= retain {
                    return Ok(serde_json::json!({
                        "archived": 0,
                        "retained": total,
                        "message": format!("Chain has {} entries — below retain threshold of {}.", total, retain)
                    }));
                }
                let archived = store
                    .compact_chain(retain)
                    .map_err(|e| RegentError::Execution(format!("chain_compact failed: {}", e)))?;
                drop(store);
                info!(archived, retain, "regent: chain_compact maintenance completed");

                self.emit_remediation_receipt(
                    "chain_compact",
                    "chain_growth",
                    archived as u64,
                    "archived",
                );

                Ok(serde_json::json!({
                    "archived": archived,
                    "retained": retain,
                    "message": format!("Archived {} entries, retained {}.", archived, retain)
                }))
            }

            "browser_use" => {
                // Domain-restricted browser automation via browser-harness CLI.
                // (host, required path prefix). Matching is host-anchored:
                // the URL's parsed host must equal the entry or be a
                // subdomain of it, and the path must start with the prefix.
                //
                // Previously this was a substring test against the whole
                // URL, which `https://evil.example/?x=zeropoint.global`
                // and `https://zeropoint.global.attacker.net/` both passed.
                const ALLOWED_DOMAINS: &[(&str, &str)] = &[
                    ("zeropoint.global", "/"),
                    ("zeropointfoundation.org", "/"),
                    ("github.com", "/zeropoint-foundation"),
                    ("localhost", "/"),
                    ("127.0.0.1", "/"),
                    ("example.com", "/"), // testing
                ];

                /// Run one `browser-harness` invocation to completion.
                ///
                /// Extracted so the `js` action can pre-flight `page_info()`
                /// through the same path before its expression is allowed to
                /// run — the domain gate has to be enforced substrate-side,
                /// not by the generated Python.
                fn run_harness(py_code: &str) -> std::io::Result<std::process::Output> {
                    std::process::Command::new("browser-harness")
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .and_then(|mut child| {
                        use std::io::Write;
                        // Write script then DROP stdin to signal EOF.
                        // Without this, browser-harness waits for more input.
                        {
                            let stdin = child.stdin.take().unwrap();
                            let mut writer = std::io::BufWriter::new(stdin);
                            writer.write_all(py_code.as_bytes())?;
                            // writer + stdin dropped here → EOF sent
                        }
                        // Timeout: 15 seconds max for any browser action.
                        let start = std::time::Instant::now();
                        let timeout = std::time::Duration::from_secs(15);
                        loop {
                            match child.try_wait()? {
                                Some(_) => return child.wait_with_output(),
                                None if start.elapsed() > timeout => {
                                    let _ = child.kill();
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::TimedOut,
                                        "browser-harness timed out after 15s",
                                    ));
                                }
                                None => std::thread::sleep(std::time::Duration::from_millis(100)),
                            }
                        }
                    })
                }

                /// Encode a parameter as a Python string literal.
                ///
                /// JSON string syntax is a subset of Python's, so a
                /// `serde_json` encoding is a safe literal: quotes,
                /// backslashes, newlines and control characters are all
                /// escaped. The previous single-quote-only escape let a
                /// raw newline in `url`, `expression` or `selector` break
                /// out of the literal and execute as Python in the
                /// browser-harness process.
                fn py_str(s: &str) -> String {
                    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
                }

                /// Host-anchored allowlist check. Returns false on any URL
                /// that fails to parse, on non-http(s) schemes, and on any
                /// host that is not an exact match or a dot-boundary
                /// subdomain of an allowlisted host.
                fn domain_allowed(raw: &str, allow: &[(&str, &str)]) -> bool {
                    let parsed = match reqwest::Url::parse(raw) {
                        Ok(u) => u,
                        Err(_) => return false,
                    };
                    if !matches!(parsed.scheme(), "http" | "https") {
                        return false;
                    }
                    let host = match parsed.host_str() {
                        Some(h) => h.to_ascii_lowercase(),
                        None => return false,
                    };
                    let path = parsed.path();
                    allow.iter().any(|(d, prefix)| {
                        let d = d.to_ascii_lowercase();
                        let host_ok = host == d || host.ends_with(&format!(".{}", d));
                        host_ok && path.starts_with(prefix)
                    })
                }

                // Recover action + URL from params. Small models often emit
                // {"intent":"execute","tool":"browser_use"} with no params
                // even when the operator said "navigate to X". Default to
                // goto_url when a URL is present, page_info otherwise.
                let raw_action = params
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let raw_url = params.get("url").and_then(|v| v.as_str()).unwrap_or("");

                // If model didn't provide action but we have a URL, infer goto_url.
                // If neither, try to extract a URL from the operator's original
                // request stored in the recent chain context.
                let (action, url) = if !raw_action.is_empty() {
                    (raw_action.to_string(), raw_url.to_string())
                } else if !raw_url.is_empty() {
                    ("goto_url".to_string(), raw_url.to_string())
                } else {
                    // Last resort: scan allowed domains — if the operator likely
                    // named one, use it. This handles the common case where the
                    // model emits bare {"tool":"browser_use"} for "navigate to
                    // zeropoint.global".
                    // For now, default to page_info (safe, no URL needed).
                    ("page_info".to_string(), String::new())
                };

                // Domain gate: if action involves a URL, validate it.
                if !url.is_empty() {
                    if !domain_allowed(&url, ALLOWED_DOMAINS) {
                        return Ok(serde_json::json!({
                            "error": "domain_blocked",
                            "message": format!("URL '{}' is not in allowed_domains", url),
                            "allowed": ALLOWED_DOMAINS
                                .iter()
                                .map(|(d, p)| format!("{}{}", d, p))
                                .collect::<Vec<_>>(),
                        }));
                    }
                }

                // Build the Python snippet for browser-harness.
                // Always start with ensure_real_tab() to avoid hung-tab
                // timeouts (a tab with stalled JS blocks Runtime.evaluate).
                let py_code = match action.as_str() {
                    "goto_url" => {
                        if url.is_empty() {
                            return Ok(serde_json::json!({
                                "error": "missing_url",
                                "message": "goto_url requires a 'url' parameter",
                            }));
                        }
                        format!(
                            "ensure_real_tab()\ncdp(\"Page.bringToFront\")\ngoto_url({})\nwait(2)\ninfo = page_info()\nimport json; print(json.dumps(info))",
                            py_str(&url)
                        )
                    }
                    "page_info" => {
                        "ensure_real_tab()\ncdp(\"Page.bringToFront\")\ninfo = page_info()\nimport json; print(json.dumps(info))".to_string()
                    }
                    "js" => {
                        // Pre-flight: `js` carries no URL of its own, so the
                        // domain gate above never sees it. Read the focused
                        // tab's URL first and hold the expression to the same
                        // host-anchored allowlist every other action obeys.
                        let probe = run_harness(
                            "ensure_real_tab()\ncdp(\"Page.bringToFront\")\ninfo = page_info()\nimport json; print(json.dumps(info))",
                        );
                        let current_url = match probe {
                            Ok(out) if out.status.success() => {
                                let stdout = String::from_utf8_lossy(&out.stdout);
                                serde_json::from_str::<serde_json::Value>(stdout.trim())
                                    .ok()
                                    .and_then(|v| {
                                        v.get("url").and_then(|u| u.as_str()).map(String::from)
                                    })
                            }
                            _ => None,
                        };
                        // Fail closed: an unreadable tab is not an allowed tab.
                        let Some(current_url) = current_url else {
                            return Ok(serde_json::json!({
                                "error": "tab_url_unavailable",
                                "message": "Could not read the focused tab's URL; js refused.",
                            }));
                        };
                        if !domain_allowed(&current_url, ALLOWED_DOMAINS) {
                            return Ok(serde_json::json!({
                                "error": "domain_blocked",
                                "message": format!(
                                    "Focused tab '{}' is not in allowed_domains; js refused.",
                                    current_url
                                ),
                                "allowed": ALLOWED_DOMAINS
                                    .iter()
                                    .map(|(d, p)| format!("{}{}", d, p))
                                    .collect::<Vec<_>>(),
                            }));
                        }
                        let expr = params.get("expression").and_then(|v| v.as_str()).unwrap_or("null");
                        format!(
                            "ensure_real_tab()\ncdp(\"Page.bringToFront\")\nresult = js({})\nprint(result)",
                            py_str(expr)
                        )
                    }
                    "list_tabs" => {
                        "tabs = list_tabs()\nimport json; print(json.dumps([{{'url': t.get('url',''), 'title': t.get('title','')}} for t in tabs[:20]]))".to_string()
                    }
                    "wait_for_element" => {
                        let sel = params.get("selector").and_then(|v| v.as_str()).unwrap_or("body");
                        format!(
                            "ensure_real_tab()\ncdp(\"Page.bringToFront\")\nwait_for_element({})\nprint('found')",
                            py_str(sel)
                        )
                    }
                    _ => {
                        return Ok(serde_json::json!({
                            "error": "unknown_action",
                            "message": format!("browser_use action '{}' not recognized", action),
                            "supported": ["goto_url", "page_info", "js", "list_tabs", "wait_for_element"],
                        }));
                    }
                };

                let output = run_harness(&py_code);

                match output {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                        if out.status.success() {
                            // Try to parse as JSON; if not, return as string.
                            let result = serde_json::from_str::<serde_json::Value>(&stdout)
                                .unwrap_or_else(|_| serde_json::json!({"output": stdout}));
                            Ok(result)
                        } else {
                            Ok(serde_json::json!({
                                "error": "browser_harness_failed",
                                "stderr": stderr,
                                "exit_code": out.status.code(),
                            }))
                        }
                    }
                    Err(e) => {
                        Err(RegentError::Execution(format!("browser-harness spawn failed: {}", e)))
                    }
                }
            }

            "memory_list" => {
                // Query the memory promotion engine — stage filter, stats, review-due.
                let stage_filter = params
                    .get("stage")
                    .and_then(|v| v.as_str());

                let engine = self
                    .promotion_engine
                    .lock()
                    .map_err(|e| RegentError::ChainRead(format!("promotion engine lock: {}", e)))?;

                let all = engine.all_memories();
                let filtered: Vec<_> = if let Some(stage_str) = stage_filter {
                    all.iter()
                        .filter(|m| m.stage.to_string() == stage_str)
                        .collect()
                } else {
                    all.iter().collect()
                };

                let now = chrono::Utc::now();
                let mut by_stage: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
                let mut expired = 0usize;
                let mut review_due = 0usize;
                for m in &all {
                    *by_stage.entry(m.stage.to_string()).or_default() += 1;
                    if m.expires_at.map_or(false, |e| e <= now) {
                        expired += 1;
                    }
                    if m.review_due_at.map_or(false, |r| r <= now) {
                        review_due += 1;
                    }
                }

                let entries: Vec<_> = filtered
                    .iter()
                    .take(50) // cap output for cognitive context budget
                    .map(|m| {
                        serde_json::json!({
                            "id": m.id,
                            "stage": m.stage.to_string(),
                            "category": m.category,
                            "confidence": m.confidence,
                            "reinforcement_count": m.reinforcement_count,
                            "content_preview": &m.content[..m.content.len().min(120)],
                            "created_at": m.created_at.to_rfc3339(),
                            "expires_at": m.expires_at.map(|t| t.to_rfc3339()),
                            "review_due_at": m.review_due_at.map(|t| t.to_rfc3339()),
                        })
                    })
                    .collect();

                Ok(serde_json::json!({
                    "total": all.len(),
                    "shown": entries.len(),
                    "by_stage": by_stage,
                    "expired": expired,
                    "review_due": review_due,
                    "memories": entries,
                }))
            }

            "memory_review" => {
                // Act on RequiresReview promotions.
                // action: "approve" | "deny" | "list_pending"
                let action = params
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("list_pending");

                match action {
                    "list_pending" => {
                        let rq = self.review_queue.as_ref().ok_or_else(|| {
                            RegentError::Execution("review queue not initialized".to_string())
                        })?;
                        let queue = rq.lock().map_err(|e| {
                            RegentError::Execution(format!("review queue lock: {}", e))
                        })?;
                        let pending = queue.pending_reviews();
                        let items: Vec<_> = pending
                            .iter()
                            .map(|p| {
                                serde_json::json!({
                                    "review_id": p.id,
                                    "memory_id": p.memory_id,
                                    "current_stage": p.current_stage.to_string(),
                                    "target_stage": p.target_stage.to_string(),
                                    "evidence": p.evidence,
                                    "requestor": p.requestor,
                                    "requested_at": p.requested_at.to_rfc3339(),
                                })
                            })
                            .collect();
                        Ok(serde_json::json!({
                            "pending_count": items.len(),
                            "reviews": items,
                        }))
                    }
                    "approve" | "deny" => {
                        let review_id = params
                            .get("review_id")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                RegentError::Execution("review_id required for approve/deny".to_string())
                            })?;
                        let reason = params
                            .get("reason")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Regent review decision");

                        let rq = self.review_queue.as_ref().ok_or_else(|| {
                            RegentError::Execution("review queue not initialized".to_string())
                        })?;

                        // Look up the pending review to check target stage.
                        // The Regent can review Remembered; IdentityBearing requires operator.
                        {
                            let queue = rq.lock().map_err(|e| {
                                RegentError::Execution(format!("review queue lock: {}", e))
                            })?;
                            let pending = queue.pending_reviews();
                            if let Some(p) = pending.iter().find(|p| p.id == review_id) {
                                if p.target_stage == zp_memory::MemoryStage::IdentityBearing {
                                    return Ok(serde_json::json!({
                                        "error": "operator_required",
                                        "message": "IdentityBearing promotion requires operator review, not Regent.",
                                        "review_id": review_id,
                                        "memory_id": p.memory_id,
                                    }));
                                }
                            }
                        }

                        let decision = if action == "approve" {
                            zp_memory::ReviewDecision::Approve {
                                reviewer: "regent".to_string(),
                                comment: Some(reason.to_string()),
                            }
                        } else {
                            zp_memory::ReviewDecision::Reject {
                                reason: reason.to_string(),
                                action: zp_memory::ReviewAction::KeepAtCurrentStage,
                                reviewer: "regent".to_string(),
                            }
                        };

                        let mut queue = rq.lock().map_err(|e| {
                            RegentError::Execution(format!("review queue lock: {}", e))
                        })?;
                        let outcome = queue.process_decision(review_id, decision);

                        // If approved, execute the promotion from the returned request.
                        if let zp_memory::ReviewOutcome::Approved { ref promotion_request } = outcome {
                            let mut engine = self
                                .promotion_engine
                                .lock()
                                .map_err(|e| RegentError::ChainRead(format!("promotion engine lock: {}", e)))?;
                            let promote_result = engine.promote(promotion_request);
                            drop(engine);

                            self.emit_receipt(
                                "regent:memory:review_approve",
                                Some(&format!(
                                    "memory_id={}, target={}",
                                    promotion_request.memory_id, promotion_request.target_stage
                                )),
                            );

                            return Ok(serde_json::json!({
                                "action": "approved",
                                "review_id": review_id,
                                "memory_id": promotion_request.memory_id,
                                "target_stage": promotion_request.target_stage.to_string(),
                                "promotion_result": format!("{:?}", promote_result),
                            }));
                        }

                        self.emit_receipt(
                            &format!("regent:memory:review_{}", action),
                            Some(&format!("review_id={}", review_id)),
                        );

                        Ok(serde_json::json!({
                            "action": action,
                            "review_id": review_id,
                            "outcome": format!("{:?}", outcome),
                        }))
                    }
                    _ => Err(RegentError::Execution(format!(
                        "memory_review: unknown action '{}' — use list_pending, approve, or deny",
                        action
                    ))),
                }
            }

            "self_configure" => {
                // Self-modification tool: the Regent changes her own inference config.
                // API keys go to vault — never in cognitive context or chain receipts.
                let new_endpoint = params.get("endpoint").and_then(|v| v.as_str()).map(String::from);
                let new_api_key = params.get("api_key").and_then(|v| v.as_str());
                let new_reasoning = params.get("model").and_then(|v| v.as_str()).map(String::from);
                let new_routing = params.get("routing_model").and_then(|v| v.as_str()).map(String::from);
                let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);

                if new_endpoint.is_none() && new_api_key.is_none() && new_reasoning.is_none() && new_routing.is_none() {
                    // No changes — return current config.
                    let regent_guard = self.regent.lock().await;
                    let cfg = regent_guard.config();
                    let key_source_label = match &cfg.api_key_source {
                        zp_regent::config::ApiKeySource::None => "none",
                        zp_regent::config::ApiKeySource::Vault(_) => "vault",
                        zp_regent::config::ApiKeySource::RawLegacy(_) => "raw_legacy",
                    };
                    let provider = regent_guard.inference().provider();
                    let pin_status = match regent_guard.operator_pin() {
                        Some(pin) => {
                            let status_detail = match &pin.status {
                                zp_regent::PinStatus::Active => serde_json::json!({
                                    "state": "active",
                                }),
                                zp_regent::PinStatus::Evaluating { candidates, active_model } => {
                                    let candidate_list: Vec<serde_json::Value> = candidates.iter().map(|c| {
                                        serde_json::json!({
                                            "model": c.model,
                                            "state": format!("{:?}", c.state),
                                        })
                                    }).collect();
                                    serde_json::json!({
                                        "state": "evaluating",
                                        "candidates": candidate_list,
                                        "serving": active_model,
                                        "note": "shadow validation in progress — groomed model stays active",
                                    })
                                },
                                zp_regent::PinStatus::Rejected { candidate_model, reason } => serde_json::json!({
                                    "state": "rejected",
                                    "candidate": candidate_model,
                                    "reason": reason,
                                    "hint": "use force=true to override, or pick a different model",
                                }),
                            };
                            serde_json::json!({
                                "active": matches!(pin.status, zp_regent::PinStatus::Active),
                                "reasoning_model": pin.reasoning_model,
                                "routing_model": pin.routing_model,
                                "pinned_at": pin.pinned_at.to_rfc3339(),
                                "lifecycle": status_detail,
                                "hint": "use model='auto' to clear pin and let the router score from dossier corpus",
                            })
                        }
                        None => serde_json::json!({
                            "active": false,
                            "mode": "router scores from dossier corpus",
                        }),
                    };
                    return Ok(serde_json::json!({
                        "status": "current_config",
                        "endpoint": cfg.inference_endpoint,
                        "reasoning_model": cfg.reasoning_model,
                        "routing_model": cfg.routing_model,
                        "api_key_source": key_source_label,
                        "operator_pin": pin_status,
                        "provider": provider.name,
                        "auth_strategy": format!("{:?}", provider.auth),
                        "protocol": format!("{:?}", provider.response_format),
                    }));
                }

                // Handle API key: write to vault, never to cognitive context.
                let mut new_key_source: Option<zp_regent::config::ApiKeySource> = None;
                if let Some(raw_key) = new_api_key {
                    let vault_store_path = "system/regent/inference/api_key";
                    if let Some(vmk) = self.vault_master_key() {
                        match zp_trust::CredentialVault::load_or_create(&vmk, &self.vault_path) {
                            Ok(mut vault) => {
                                if let Err(e) = vault.store_tiered(
                                    vault_store_path,
                                    raw_key.as_bytes(),
                                    zp_trust::vault::VaultTier::System,
                                ) {
                                    return Err(RegentError::Execution(
                                        format!("failed to store API key in vault: {}", e)
                                    ));
                                }
                                if let Err(e) = vault.save(&self.vault_path) {
                                    return Err(RegentError::Execution(
                                        format!("failed to persist vault: {}", e)
                                    ));
                                }
                                new_key_source = Some(zp_regent::config::ApiKeySource::Vault(
                                    vault_store_path.to_string()
                                ));
                                info!("self_configure: API key stored in vault at {}", vault_store_path);
                            }
                            Err(e) => {
                                return Err(RegentError::Execution(
                                    format!("failed to open vault for API key storage: {}", e)
                                ));
                            }
                        }
                    } else {
                        return Err(RegentError::Execution(
                            "vault key not available — cannot store API key securely".to_string()
                        ));
                    }
                }

                info!(
                    new_endpoint = ?new_endpoint,
                    new_reasoning = ?new_reasoning,
                    new_routing = ?new_routing,
                    has_new_key = new_key_source.is_some(),
                    "regent: self_configure — reconfiguring inference"
                );

                let result = {
                    let mut regent_guard = self.regent.lock().await;
                    regent_guard.reconfigure_inference(
                        new_endpoint,
                        new_reasoning,
                        new_routing,
                        new_key_source.clone(),
                        force,
                    )
                };

                // If key was stored in vault, resolve it into the inference backend.
                if let Some(zp_regent::config::ApiKeySource::Vault(ref path)) = new_key_source {
                    if let Some(vmk) = self.vault_master_key() {
                        if let Ok(vault) = zp_trust::CredentialVault::load_or_create(&vmk, &self.vault_path) {
                            if let Ok(key_bytes) = vault.retrieve(path) {
                                if let Ok(key_str) = std::str::from_utf8(&key_bytes) {
                                    let mut regent_guard = self.regent.lock().await;
                                    regent_guard.inference_mut().set_resolved_key(key_str.to_string());
                                }
                            }
                        }
                    }
                }

                // Emit a config receipt — records key SOURCE, never the key value.
                let key_source_label = match &new_key_source {
                    Some(zp_regent::config::ApiKeySource::Vault(p)) => format!("vault:{}", p),
                    Some(_) => "changed".to_string(),
                    None => "unchanged".to_string(),
                };

                // Receipt type depends on whether we're evaluating or reconfigured.
                let receipt_event = if result["status"].as_str() == Some("evaluating") {
                    "regent:config:inference:shadow_start"
                } else {
                    "regent:config:inference"
                };
                self.emit_receipt(
                    receipt_event,
                    Some(&format!(
                        "reasoning={} routing={} api_key_source={} via={}",
                        result["changes"]["reasoning_model"]["to"].as_str().unwrap_or("?"),
                        result["changes"]["routing_model"]["to"].as_str().unwrap_or("?"),
                        key_source_label,
                        if force { "force_cut" } else if result["status"].as_str() == Some("evaluating") { "shadow_evaluation" } else { "direct" },
                    )),
                );

                // If entering shadow evaluation, spawn the battery as a background task.
                if result["status"].as_str() == Some("evaluating") {
                    self.spawn_shadow_battery();
                }

                Ok(result)
            }

            "substrate_validate" => {
                // Deterministic substrate validation primitive.
                //
                // Walks the chain, checks canonical disciplines (chain integrity,
                // canary, cognitive sandwich, standing corrections, officer
                // heartbeats, receipt inventory), emits a chain-anchored
                // `substrate:validation:regent:<id>` receipt, returns structured
                // findings for Regent to narrate.
                //
                // Separates deterministic structural validation from Regent's
                // narration judgment per SUBSTRATE-SELF-CONSTRUCTION discipline.
                // Regent authorized to invoke per standing correction
                // `regent.authority.substrate_validation`.
                let report = crate::substrate_validate::run_substrate_validation(
                    &self.audit_store,
                );
                Ok(report)
            }

            _ => Err(RegentError::Execution(format!("unknown tool: {}", tool))),
        }
    }
}

#[async_trait::async_trait]
impl IntentExecutor for ServerIntentExecutor {
    async fn execute(&self, intent: &Intent) -> Result<IntentOutcome, RegentError> {
        match intent {
            Intent::Respond { content, target_surface } => {
                let surface = target_surface.as_deref().unwrap_or("default");
                debug!(surface, content_len = content.len(), "regent: delivering response");
                self.emit_receipt(
                    "regent:intent:respond",
                    Some(&format!("surface={}, len={}", surface, content.len())),
                );

                // Broadcast the response to SSE listeners for cockpit delivery.
                let _ = self.event_tx.send(crate::events::EventStreamItem {
                    category: "regent".to_string(),
                    event_type: "regent:response".to_string(),
                    summary: Some(format!(
                        "Regent response ({} chars) via {}",
                        content.len(),
                        surface
                    )),
                    entry_hash: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });

                Ok(IntentOutcome::Delivered)
            }

            Intent::Delegate { task, capability, constraints: _ } => {
                debug!(
                    task = task.as_str(),
                    capability = capability.as_str(),
                    "regent: delegation intent"
                );
                self.emit_receipt(
                    "regent:intent:delegate",
                    Some(&format!("capability={}, task={}", capability, task)),
                );
                // TODO: sub-agent dispatch. For now, receipt only.
                Ok(IntentOutcome::Observed)
            }

            Intent::Execute { tool, params } => {
                debug!(tool = tool.as_str(), "regent: execute intent");

                // 1. Emit intent receipt
                self.emit_receipt(
                    "regent:intent:execute",
                    Some(&format!("tool={}", tool)),
                );

                // 2. Evaluate gate
                let context = zp_core::policy::PolicyContext {
                    action: ActionType::ToolCall {
                        name: tool.clone(),
                    },
                    trust_tier: zp_core::policy::TrustTier::Tier2,
                    channel: zp_core::Channel::Api,
                    conversation_id: regent_conv_id(),
                    skill_ids: vec![],
                    tool_names: vec![tool.clone()],
                    mesh_context: None,
                };
                let gate_result = self.gate.evaluate(&context, regent_actor());

                // 3. Append gate decision to chain
                {
                    let mut store = match self.audit_store.lock() {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("regent: audit store lock poisoned: {}", e);
                            return Err(RegentError::ChainRead(e.to_string()));
                        }
                    };
                    if let Err(e) = store.append(gate_result.unsealed.clone()) {
                        warn!("regent: gate receipt append failed: {}", e);
                    }
                }

                // 4. If blocked, return denial
                if gate_result.is_blocked() {
                    let reason = match &gate_result.decision {
                        PolicyDecision::Block { reason, .. } => reason.clone(),
                        _ => "policy denied".to_string(),
                    };
                    debug!(tool = tool.as_str(), reason = reason.as_str(), "regent: gate denied tool");
                    return Ok(IntentOutcome::ToolDenied {
                        tool: tool.clone(),
                        reason,
                    });
                }

                // 5. Dispatch tool
                let output = self.dispatch_tool(tool, params).await?;

                // 6. Emit completion receipt
                self.emit_receipt(
                    &format!("regent:tool:completed:{}", tool),
                    Some("success=true"),
                );

                debug!(tool = tool.as_str(), "regent: tool completed");
                Ok(IntentOutcome::ToolCompleted {
                    tool: tool.clone(),
                    output,
                })
            }

            Intent::Remember { key, content: _ } => {
                debug!(key = key.as_str(), "regent: remember intent");
                self.emit_receipt(
                    "regent:intent:remember",
                    Some(&format!("key={}", key)),
                );
                Ok(IntentOutcome::Observed)
            }

            Intent::RequestApproval { proposed_action, reason } => {
                info!(
                    action = proposed_action.as_str(),
                    reason = reason.as_str(),
                    "regent: requesting operator approval"
                );
                self.emit_receipt(
                    "regent:intent:request_approval",
                    Some(&format!("action={}", proposed_action)),
                );

                // Broadcast approval request to cockpit surfaces.
                let _ = self.event_tx.send(crate::events::EventStreamItem {
                    category: "regent".to_string(),
                    event_type: "regent:approval_request".to_string(),
                    summary: Some(format!("Approval needed: {}", proposed_action)),
                    entry_hash: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });

                Ok(IntentOutcome::ApprovalRequested)
            }

            Intent::Observe { observation } => {
                debug!(observation = observation.as_str(), "regent: observe");
                self.emit_receipt("regent:intent:observe", Some(observation));
                Ok(IntentOutcome::Observed)
            }

            Intent::Escalate { reason, prompt: _, estimated_tokens } => {
                info!(
                    reason = reason.as_str(),
                    estimated_tokens,
                    "regent: cloud escalation intent"
                );
                self.emit_receipt(
                    "regent:intent:escalate",
                    Some(&format!("reason={}, tokens={}", reason, estimated_tokens)),
                );
                // TODO: cloud escalation path with mandate validation.
                Ok(IntentOutcome::Observed)
            }

            Intent::Continue { .. } => {
                // Continue is handled by the loop runner's arc logic —
                // it never reaches the executor. If it does, treat as
                // a no-op observation to avoid panics.
                debug!("regent: Continue intent reached executor (unexpected); treating as observed");
                Ok(IntentOutcome::Observed)
            }
        }
    }
}

// ── Startup ─────────────────────────────────────────────────────────────────

/// Configuration for the Regent, populated from server config.
pub struct ServerRegentConfig {
    pub enabled: bool,
    pub inference_endpoint: String,
    /// Raw API key from config.toml — will be migrated to vault on first use.
    pub inference_api_key: Option<String>,
    pub reasoning_model: String,
    pub routing_model: String,
    pub loop_interval_secs: u64,
    pub display_name: String,
}

impl Default for ServerRegentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            inference_endpoint: "http://127.0.0.1:11434".to_string(),
            inference_api_key: None,
            reasoning_model: "qwen3:8b".to_string(),
            routing_model: "qwen3:1.7b".to_string(),
            loop_interval_secs: 60,
            display_name: "Regent".to_string(),
        }
    }
}

/// Spawn the Regent cognitive loop if enabled. Returns the handle.
pub async fn spawn_regent(
    config: ServerRegentConfig,
    audit_store: Arc<std::sync::Mutex<AuditStore>>,
    gate: Arc<GovernanceGate>,
    event_tx: tokio::sync::broadcast::Sender<crate::events::EventStreamItem>,
    data_dir: &str,
    promotion_engine: Arc<std::sync::Mutex<zp_memory::PromotionEngine>>,
    review_queue: Option<Arc<std::sync::Mutex<zp_memory::ReviewQueue>>>,
    vault_key: Arc<std::sync::OnceLock<Option<zp_keys::ResolvedVaultKey>>>,
) -> Option<RegentHandle> {
    if !config.enabled {
        debug!("Regent disabled (`[regent] enabled = false`) — cognitive loop not spawned");
        return None;
    }

    // Resolve vault path for Regent's scoped secret access.
    let vault_path = zp_core::paths::vault_path()
        .unwrap_or_else(|_| std::path::PathBuf::from(data_dir).join("vault.json"));

    // Convert raw API key from config.toml to ApiKeySource.
    // If vault is available, migrate the key to vault immediately.
    // Otherwise, use RawLegacy (transition path — key in memory).
    // Note: vault_key may not be resolved yet (background keychain thread).
    // We wait briefly here since this is a one-time migration path.
    let resolve_vmk = || -> Option<[u8; 32]> {
        vault_key.get()
            .and_then(|k| k.as_ref())
            .map(|resolved| *resolved.key)
    };
    let api_key_source = if let Some(raw_key) = config.inference_api_key {
        if let Some(vmk) = resolve_vmk() {
            // Migrate to vault on first startup.
            let vault_store_path = "system/regent/inference/api_key";
            match zp_trust::CredentialVault::load_or_create(&vmk, &vault_path) {
                Ok(mut vault) => {
                    if let Err(e) = vault.store_tiered(
                        vault_store_path,
                        raw_key.as_bytes(),
                        zp_trust::vault::VaultTier::System,
                    ) {
                        warn!("failed to migrate regent API key to vault: {} — using in-memory fallback", e);
                        zp_regent::config::ApiKeySource::RawLegacy(raw_key)
                    } else if let Err(e) = vault.save(&vault_path) {
                        warn!("failed to persist vault after API key migration: {} — using in-memory fallback", e);
                        zp_regent::config::ApiKeySource::RawLegacy(raw_key)
                    } else {
                        info!("migrated regent API key from config.toml to vault at {}", vault_store_path);
                        zp_regent::config::ApiKeySource::Vault(vault_store_path.to_string())
                    }
                }
                Err(e) => {
                    warn!("failed to open vault for API key migration: {} — using in-memory fallback", e);
                    zp_regent::config::ApiKeySource::RawLegacy(raw_key)
                }
            }
        } else {
            // No vault key available — use legacy path.
            warn!("vault key not available — regent API key stored in memory (will not persist across restarts)");
            zp_regent::config::ApiKeySource::RawLegacy(raw_key)
        }
    } else {
        // No key in config.toml — check vault for a previously-stored key
        // (e.g. from a prior self_configure session). Vault is source of truth.
        let vault_store_path = "system/regent/inference/api_key";
        if let Some(vmk) = resolve_vmk() {
            match zp_trust::CredentialVault::load_or_create(&vmk, &vault_path) {
                Ok(vault) => match vault.retrieve(vault_store_path) {
                    Ok(_) => {
                        info!("found existing regent API key in vault at {} — using vault source", vault_store_path);
                        zp_regent::config::ApiKeySource::Vault(vault_store_path.to_string())
                    }
                    Err(_) => {
                        debug!("no regent API key in vault — starting without cloud inference");
                        zp_regent::config::ApiKeySource::None
                    }
                },
                Err(_) => zp_regent::config::ApiKeySource::None,
            }
        } else {
            zp_regent::config::ApiKeySource::None
        }
    };

    let regent_config = RegentConfig {
        enabled: true,
        inference_endpoint: config.inference_endpoint,
        api_key_source: api_key_source.clone(),
        reasoning_model: config.reasoning_model,
        routing_model: config.routing_model,
        max_context_tokens: 8192,
        loop_interval_secs: config.loop_interval_secs,
        cloud_mandate: None,
        display_name: config.display_name,
    };

    let data_path = std::path::Path::new(data_dir);
    let mut inference_backend = InferenceBackend::new(&regent_config);

    // If key is in vault, resolve it now and inject into the backend.
    if let zp_regent::config::ApiKeySource::Vault(ref path) = api_key_source {
        if let Some(vmk) = resolve_vmk() {
            match zp_trust::CredentialVault::load_or_create(&vmk, &vault_path) {
                Ok(vault) => match vault.retrieve(path) {
                    Ok(key_bytes) => {
                        if let Ok(key_str) = std::str::from_utf8(&key_bytes) {
                            inference_backend.set_resolved_key(key_str.to_string());
                            info!("resolved regent inference API key from vault");
                        }
                    }
                    Err(e) => warn!("failed to resolve API key from vault: {}", e),
                },
                Err(e) => warn!("failed to open vault for API key resolution: {}", e),
            }
        }
    }

    let inference = Arc::new(inference_backend);

    // Load sovereign identity once — shared by both Regent and executor.
    // No independent load inside Regent::new(); this is the single owner.
    let sovereign = zp_regent::context::SovereignIdentity::load(data_path);
    if let Some(ref sov) = sovereign {
        info!(
            operator = %sov.operator_name,
            genesis_pubkey_prefix = %&sov.genesis_pubkey[..8.min(sov.genesis_pubkey.len())],
            "Regent loaded sovereign identity"
        );
    } else {
        warn!("Regent has no sovereign identity — genesis.json not found or malformed");
    }
    let (operator_name, genesis_prefix) = match &sovereign {
        Some(sov) => (
            sov.operator_name.clone(),
            sov.genesis_pubkey[..8.min(sov.genesis_pubkey.len())].to_string(),
        ),
        None => ("unknown".to_string(), "00000000".to_string()),
    };

    let mut regent = Regent::new(regent_config, data_path, sovereign);

    // Inject the vault-resolved key into the Regent's OWN InferenceBackend.
    // (spawn_regent also creates a separate backend for ServerIntentExecutor —
    // the Regent's backend is the one that does cognitive inference, so it
    // needs the key too.)
    if let zp_regent::config::ApiKeySource::Vault(ref path) = api_key_source {
        if let Some(vmk) = resolve_vmk() {
            if let Ok(vault) = zp_trust::CredentialVault::load_or_create(&vmk, &vault_path) {
                if let Ok(key_bytes) = vault.retrieve(path) {
                    if let Ok(key_str) = std::str::from_utf8(&key_bytes) {
                        regent.inference_mut().set_resolved_key(key_str.to_string());
                        info!("resolved regent inference API key from vault (regent backend)");
                    }
                }
            }
        }
    }

    // Load model dossier corpus — the router's evidence base.
    // Reads models/*/model_dossier.toml from the source tree.
    //
    // TIE-OFF (Stage 1t, 2026-07-26) — disposition: deferred.
    // This resolves the dossier corpus from CARGO_MANIFEST_DIR, which is
    // the *build host's* path. On any machine other than the one that
    // compiled the binary the read fails, load_from_dir warns and returns
    // an empty corpus, and every routing decision silently falls through
    // to route_from_config. ARTEMIS has therefore never exercised
    // dossier-based routing. The `.unwrap_or_else` below is dead code:
    // `.parent().parent()` cannot return None for a valid manifest dir.
    //
    // Not fixed here because where the dossier corpus should live at
    // runtime is an architecture decision, not a substitution — the
    // candidates (zp_core::paths data root, a config field, ZP_SOURCE_DIR)
    // differ in how they behave across Substrate Forms, and Sovereign Form
    // ships a built OS with no source tree at all.
    //
    // Reopen condition: the Substrate Form question is decided, OR any
    // attempt to run the server off a machine other than its build host.
    // See docs/design/CONNECTION-INTEGRITY-PROGRAM-2026-07.md §3 C7.
    let models_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")) // BUILD-PATH-TIEOFF: see above
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("models"))
        .unwrap_or_else(|| data_path.join("models"));
    let dossier_corpus = Arc::new(zp_regent::routing::DossierCorpus::load_from_dir(&models_dir));
    regent.set_dossier_corpus(dossier_corpus);

    // Reconstitute operator pin from chain — chain supersedes config.toml.
    // Scan recent entries for the most recent regent:config:inference* receipt.
    // Handles three receipt types:
    //   regent:config:inference           → active pin (restore normally)
    //   regent:config:inference:shadow_start → shadow was in progress (re-enter evaluating)
    //   regent:config:inference:shadow_rejected → shadow failed (set rejected state)
    // If the receipt says "auto", the pin is cleared (router scores freely).
    if let Ok(store) = audit_store.lock() {
        if let Ok(entries) = store.recent_entries(500) {
            for entry in &entries {
                if let zp_core::AuditAction::SystemEvent { ref event } = entry.action {
                    if event.starts_with("regent:config:inference") {
                        if let Some(detail) = event.split(" | ").nth(1) {
                            let mut reasoning: Option<String> = None;
                            let mut routing: Option<String> = None;

                            for part in detail.split_whitespace() {
                                if let Some(val) = part.strip_prefix("reasoning=") {
                                    reasoning = Some(val.to_string());
                                } else if let Some(val) = part.strip_prefix("routing=") {
                                    routing = Some(val.to_string());
                                }
                            }

                            let r_auto = reasoning.as_deref() == Some("auto");
                            let rt_auto = routing.as_deref() == Some("auto");

                            if r_auto && rt_auto {
                                regent.clear_operator_pin();
                                info!("chain reconstitution: operator pin cleared (auto)");
                            } else if event.starts_with("regent:config:inference:shadow_start") {
                                // Shadow was in progress when ZP shut down.
                                // Re-enter evaluating state — battery will re-run.
                                let candidate = reasoning.as_deref()
                                    .filter(|m| *m != "auto" && *m != "?")
                                    .unwrap_or("unknown")
                                    .to_string();
                                let active = regent.config().reasoning_model.clone();
                                regent.set_shadow_evaluating(
                                    candidate.clone(),
                                    active,
                                    routing.as_ref()
                                        .filter(|m| *m != "auto" && *m != "?")
                                        .cloned(),
                                );
                                info!(
                                    candidate = %candidate,
                                    "chain reconstitution: shadow evaluation was in progress, re-entering evaluating state"
                                );
                            } else if event.starts_with("regent:config:inference:shadow_rejected") {
                                // Shadow was rejected. Set rejected state so the
                                // Regent can surface findings on first interaction.
                                let candidate = reasoning.as_deref()
                                    .unwrap_or("unknown")
                                    .to_string();
                                regent.set_shadow_rejected(
                                    candidate.clone(),
                                    "shadow validation failed (see prior receipts)".to_string(),
                                );
                                info!(
                                    candidate = %candidate,
                                    "chain reconstitution: shadow evaluation was rejected"
                                );
                            } else {
                                // Normal regent:config:inference — active pin.
                                if let Some(ref m) = reasoning {
                                    if m != "auto" && m != "?" {
                                        regent.apply_chain_pin(Some(m.clone()), None);
                                    }
                                }
                                if let Some(ref m) = routing {
                                    if m != "auto" && m != "?" {
                                        regent.apply_chain_pin(None, Some(m.clone()));
                                    }
                                }
                                info!(
                                    reasoning = ?reasoning,
                                    routing = ?routing,
                                    "chain reconstitution: operator pin restored from receipt"
                                );
                            }
                        }
                        break; // Most recent receipt found — stop scanning.
                    }
                }
            }
        }
    }

    let regent = Arc::new(Mutex::new(regent));

    // System monitor — shared between the loop runner and the executor
    // so the Regent can query system_status and the loop can manage tasks.
    let system_monitor = Arc::new(tokio::sync::Mutex::new(
        zp_regent::awareness::SystemMonitor::new(inference.clone()),
    ));

    let executor = Arc::new(ServerIntentExecutor::new(
        audit_store.clone(),
        gate,
        event_tx.clone(),
        inference.clone(),
        system_monitor.clone(),
        regent.clone(),
        operator_name.clone(),
        genesis_prefix.clone(),
        promotion_engine,
        review_queue,
        vault_key,
        vault_path,
    ));

    // ── Regent startup delegation ───────────────────────────────────
    // Emit a scoped CapabilityGrant for the Regent's Phase 0 tools.
    // The gate checks this grant when evaluating regent tool calls.
    {
        let _grant = CapabilityGrant::new(
            "genesis".to_string(),                   // grantor: substrate itself
            "regent".to_string(),                     // grantee: regent actor
            GrantedCapability::ToolCall {
                tools: REGENT_TOOLS.iter().map(|(c, _)| c.to_string()).collect(),
            },
            format!("rcpt-regent-startup-{}", Uuid::now_v7()),
        );

        // Emit delegation receipt on the chain.
        let entry = UnsealedEntry {
            actor: ActorId::System("genesis".to_string()),
            action: AuditAction::SystemEvent {
                event: "delegation:granted:regent".to_string(),
            },
            conversation_id: regent_conv_id(),
            policy_decision: PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "regent-startup".to_string(),
            receipt: None,
        };

        if let Ok(mut store) = audit_store.lock() {
            if let Err(e) = store.append(entry) {
                warn!("regent startup delegation receipt failed: {}", e);
            } else {
                info!("regent startup delegation granted: chain_query, governance_posture, model_evaluate, system_status, batch_sign, chain_compact, self_configure, memory_list, memory_review, substrate_validate");
            }
        }
    }

    // Preload models into memory before starting the loop.
    // This eliminates cold-start latency on the first operator interaction.
    {
        let regent_guard = regent.lock().await;
        regent_guard.preload_models().await;
    }

    // Cognitive event channel — bridges zp-regent telemetry to the SSE stream.
    let (cognitive_tx, _) = zp_regent::events::event_channel();
    {
        let sse_tx = event_tx.clone();
        let mut cognitive_rx = cognitive_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match cognitive_rx.recv().await {
                    Ok(evt) => {
                        let item = crate::events::EventStreamItem {
                            category: "cognition".to_string(),
                            event_type: format!("regent:{}", evt.phase),
                            summary: evt.detail.clone(),
                            entry_hash: None,
                            timestamp: evt.timestamp.clone(),
                        };
                        let _ = sse_tx.send(item);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        debug!("cognitive event bridge lagged by {} events", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    // Build delegation summaries so the Regent knows its tools.
    // Eventually read from chain; for now, static from startup grant.
    // Built from REGENT_TOOLS so what the Regent perceives and what the
    // gate honours cannot disagree. Previously a parallel hand-maintained
    // list; see REGENT_TOOLS for the drift that motivated collapsing them.
    let delegations: Vec<zp_regent::context::DelegationSummary> = REGENT_TOOLS
        .iter()
        .map(|(capability, scope)| zp_regent::context::DelegationSummary {
            capability: capability.to_string(),
            scope: scope.to_string(),
            granted_at: chrono::Utc::now(),
            expires_at: None,
        })
        .collect();

    let handle = zp_regent::loop_runner::start_loop(
        regent,
        executor,
        audit_store,
        config.loop_interval_secs,
        Some(cognitive_tx),
        inference,
        system_monitor,
        operator_name,
        genesis_prefix,
        delegations,
    );

    info!("Regent cognitive loop started (models preloaded)");
    Some(handle)
}
