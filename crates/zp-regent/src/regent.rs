//! The Regent struct — the apex cognitive entity.
//!
//! The Regent is the operator's primary agent. It holds the cognitive
//! loop, the persona, the memory store, and the inference backend.
//! It does not hold mutable references to the chain or the gate —
//! those are passed in per-cycle, same pattern as officers.

use tracing::{debug, info, warn};

// Prompt templates loaded at compile time from prompts/ directory.
// Override at runtime by placing files in ~/ZeroPoint/assets/prompts/.
const PROMPT_UNIFIED_SYSTEM: &str = include_str!("../prompts/unified_system.md");
const PROMPT_UNIFIED_TOOLS: &str = include_str!("../prompts/unified_tools.md");
const PROMPT_UNIFIED_NO_TOOLS: &str = include_str!("../prompts/unified_no_tools.md");
const PROMPT_ROUTING_TOOLS: &str = include_str!("../prompts/routing_with_tools.md");
const PROMPT_ROUTING_NO_TOOLS: &str = include_str!("../prompts/routing_no_tools.md");
const PROMPT_COMPOSE: &str = include_str!("../prompts/compose.md");

use crate::config::RegentConfig;
use crate::context::{
    ChainSnapshot, CognitiveContext, CockpitSource, DelegationSummary,
    FindingSummary, MemoryFragment, OperatorInput, SovereignIdentity,
    SystemAwareness,
};
use crate::corrections::CorrectionIndex;
use crate::error::RegentError;
use crate::inference::{ChatMessage, InferenceBackend, InferenceRequest};
use crate::intent::Intent;
use crate::memory::MemoryStore;
use crate::persona::Persona;

use zp_officers::finding::Finding;
use zp_officers::officer::ChainReader;

// ── Cognitive Input Plane composition constants ─────────────────────────────

/// Matrix specification version (per COGNITIVE-INPUT-PLANE-2026-07.md §"Layer A / Layer B split").
/// Bumped when composition rules change via canonicalization ceremony.
const COGNITIVE_INPUT_MATRIX_VERSION: &str = "v1.0";

/// Upper bound on standing-correction chain query. Standing corrections are rare
/// operator events; 1024 comfortably covers even a mature substrate's active
/// correction corpus while bounding query cost.
const CORRECTION_SEARCH_LIMIT: usize = 1024;

/// Bound on the number of standing corrections presented at Tier 1 in a single
/// cycle. Set high enough to include realistic full active-correction sets while
/// bounding the context-window impact under adversarial correction floods.
const TIER1_CORRECTION_LIMIT: usize = 32;

/// Cheap categorisation of what triggered this perception, for composition receipts.
fn perception_invocation_reason(
    operator_input: &Option<OperatorInput>,
    work_arc: &Option<crate::context::WorkArc>,
    has_tool_results: bool,
) -> String {
    if operator_input.is_some() {
        "operator_directive".to_string()
    } else if work_arc.is_some() {
        "work_arc_continuation".to_string()
    } else if has_tool_results {
        "tool_dispatch_narration".to_string()
    } else {
        "autonomous_cycle".to_string()
    }
}

/// Cognitive mode per COGNITIVE-MODE-AND-AGENCY-2026-07.md §3.
///
/// Two modes are reachable today. Committed and Reactive are specified and
/// blocked on subsystems that do not exist (`regent:commitment:*`, breaker
/// state reaching the invocation reason) — see that doc's §3 table. Do not
/// invent mappings for them here; that would be a capability claim the
/// runtime cannot support.
///
/// `"continuation"` is a placeholder, not a mode — it marks that a
/// continuation cycle (`work_arc_continuation` / `tool_dispatch_narration`)
/// should inherit the mode of the cycle that opened the flow, per §3.1. No
/// flow tracking exists yet (m2), so resolution against the preceding act
/// receipt is deferred to the analysis layer rather than guessed here.
pub(crate) fn cognitive_mode(invocation_reason: &str) -> &'static str {
    match invocation_reason {
        "operator_directive" => "conversational",
        "autonomous_cycle" => "stewardship",
        "work_arc_continuation" | "tool_dispatch_narration" => "continuation",
        _ => "unknown",
    }
}

/// Render active standing corrections into a Tier 1 system-prompt section.
///
/// Standing corrections are chain-anchored operator claims that persist across
/// cognitive cycles. They live in the system prompt (above operator directive
/// in the user prompt) so they get the boundary-weight LLMs give to prompt
/// tops — per COGNITIVE-INPUT-PLANE-2026-07.md §"Priority ordering IS signal".
///
/// Returns an empty string when no corrections are active — the template's
/// `{standing_corrections_section}` placeholder disappears cleanly.
fn build_standing_corrections_section(context: &CognitiveContext) -> String {
    if context.standing_corrections.is_empty() {
        return String::new();
    }

    let mut out = String::from("STANDING CORRECTIONS (chain-anchored, operator-signed; these override any default behavior):\n");
    for active in &context.standing_corrections {
        let c = &active.correction;
        let type_label = match c.correction_type {
            crate::corrections::CorrectionType::Factual => "FACT",
            crate::corrections::CorrectionType::Boundary => "BOUNDARY",
            crate::corrections::CorrectionType::Prohibition => "PROHIBITION",
            crate::corrections::CorrectionType::Preference => "PREFERENCE",
        };
        out.push_str(&format!(
            "  • [{}] {} (priority {}): {}",
            type_label, c.domain, c.priority, c.content.assertion
        ));
        if let Some(ref neg) = c.content.negation {
            out.push_str(&format!("\n      DO NOT: {}", neg));
        }
        out.push('\n');
    }
    out.push_str("These corrections are load-bearing; violating them contradicts operator authority.");
    out
}

/// The Regent — ZeroPoint's apex cognitive entity.
///
/// Governs on behalf of the sovereign operator. Its authority is
/// always delegated, never inherent. Every action is chain-anchored
/// and officer-observed.
pub struct Regent {
    /// Configuration.
    config: RegentConfig,

    /// The persona — shapes how the Regent communicates.
    persona: Persona,

    /// Persistent memory across cognitive cycles.
    memory: MemoryStore,

    /// Local inference backend.
    inference: InferenceBackend,

    /// The sovereign operator's identity, loaded from Genesis at startup.
    /// None only if genesis.json doesn't exist or is malformed.
    sovereign: Option<SovereignIdentity>,

    /// How many cycles have run since startup.
    cycle_count: u64,

    /// Model dossier corpus — the router's evidence base.
    /// Loaded at startup from `models/*/model_dossier.toml`.
    /// None if no dossiers exist or the router is not yet active.
    dossier_corpus: Option<std::sync::Arc<crate::routing::DossierCorpus>>,

    /// Operator's explicit model pin — set via self_configure, cleared via
    /// self_configure with model="auto". When set, the router respects this
    /// over dossier scoring. When None, the router scores freely.
    operator_pin: Option<OperatorModelPin>,
}

/// An operator's explicit model selection — distinct from config defaults.
/// Set when the operator actively chooses a model via self_configure.
/// The receipt on chain provides audit trail; this is the operational state.
#[derive(Debug, Clone)]
pub struct OperatorModelPin {
    /// The pinned reasoning model (e.g. "zai-org/GLM-5.2").
    pub reasoning_model: Option<String>,
    /// The pinned routing model, if separately pinned.
    pub routing_model: Option<String>,
    /// When the pin was set (for informational purposes).
    pub pinned_at: chrono::DateTime<chrono::Utc>,
    /// Pin lifecycle status — evaluating, active, or rejected.
    pub status: PinStatus,
}

/// Pin lifecycle states for shadow-first model switching.
///
/// When the operator requests a model change, the pin enters `Evaluating`
/// while the validation battery runs against one or more candidates.
/// The groomed model stays active during this phase. On battery completion,
/// the best candidate is promoted to `Active` or findings are surfaced.
/// The operator can force-cut at any time, bypassing the shadow phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStatus {
    /// Shadow evaluation in progress. The `active_model` continues serving
    /// inference; one or more candidates are being validated in parallel.
    Evaluating {
        candidates: Vec<ShadowCandidate>,
        active_model: String,
    },
    /// Pin is live — this model serves inference.
    Active,
    /// Shadow evaluation completed with findings. The active model
    /// (pre-switch) remains in use until the operator acts.
    Rejected {
        candidate_model: String,
        reason: String,
    },
}

/// A candidate model under shadow evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowCandidate {
    /// The model identifier (e.g. "zai-org/GLM-5.2").
    pub model: String,
    /// Current evaluation state.
    pub state: ShadowCandidateState,
}

/// Per-candidate evaluation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowCandidateState {
    /// Battery not yet started.
    Pending,
    /// Battery in progress.
    Running,
    /// Battery passed — eligible for promotion.
    Passed,
    /// Battery failed.
    Failed { reason: String },
}

impl Regent {
    /// Create a new Regent from configuration.
    ///
    /// `sovereign` is loaded once at startup (in `spawn_regent`) and
    /// threaded through — the Regent never loads it independently.
    /// This eliminates the dual-load redundancy and ensures one
    /// sovereign identity for the entire process.
    pub fn new(
        config: RegentConfig,
        data_dir: &std::path::Path,
        sovereign: Option<SovereignIdentity>,
    ) -> Self {
        let inference = InferenceBackend::new(&config);
        let memory = MemoryStore::new(data_dir);
        let persona = Persona {
            name: config.display_name.clone(),
            ..Persona::default()
        };

        // If config models differ from compiled defaults, the operator
        // set them in config.toml — treat as a startup pin.
        let defaults = RegentConfig::default();
        let has_reasoning_pin = config.reasoning_model != defaults.reasoning_model;
        let has_routing_pin = config.routing_model != defaults.routing_model;
        let operator_pin = if has_reasoning_pin || has_routing_pin {
            Some(OperatorModelPin {
                reasoning_model: if has_reasoning_pin {
                    Some(config.reasoning_model.clone())
                } else {
                    None
                },
                routing_model: if has_routing_pin {
                    Some(config.routing_model.clone())
                } else {
                    None
                },
                pinned_at: chrono::Utc::now(),
                status: PinStatus::Active,
            })
        } else {
            None
        };

        Self {
            config,
            persona,
            memory,
            inference,
            sovereign,
            cycle_count: 0,
            dossier_corpus: None,
            operator_pin,
        }
    }

    /// Attach the model dossier corpus for inference routing.
    pub fn set_dossier_corpus(&mut self, corpus: std::sync::Arc<crate::routing::DossierCorpus>) {
        self.dossier_corpus = Some(corpus);
    }

    /// Clear the operator pin — router scores freely from dossier corpus.
    /// Also resets config models to compiled defaults so route_from_config
    /// doesn't accidentally use a stale pinned model name.
    pub fn clear_operator_pin(&mut self) {
        self.operator_pin = None;
        let defaults = RegentConfig::default();
        self.config.reasoning_model = defaults.reasoning_model;
        self.config.routing_model = defaults.routing_model;
    }

    /// Promote a shadow candidate to active — the validation battery passed.
    /// Updates config models and sets PinStatus::Active.
    /// Returns the promoted model name, or None if not evaluating.
    /// Promote a passing shadow candidate to active. Returns the prior
    /// active model name (for receipt/logging), or None if not evaluating.
    pub fn promote_shadow_candidate(&mut self, model: &str) -> Option<String> {
        let pin = self.operator_pin.as_mut()?;
        match &pin.status {
            PinStatus::Evaluating { candidates, active_model } => {
                if !candidates.iter().any(|c| c.model == model) {
                    return None;
                }
                let prior = active_model.clone();
                self.config.reasoning_model = model.to_string();
                pin.reasoning_model = Some(model.to_string());
                pin.status = PinStatus::Active;
                pin.pinned_at = chrono::Utc::now();
                info!(model = %model, prior = %prior, "shadow candidate promoted to active");
                Some(prior)
            }
            _ => None,
        }
    }

    /// Reject a shadow candidate — mark it as failed in the candidate list.
    /// If all candidates are now failed, transition the pin to Rejected.
    /// Returns the candidate model name, or None if not evaluating.
    pub fn reject_shadow_candidate(&mut self, model: &str, reason: String) -> Option<String> {
        let pin = self.operator_pin.as_mut()?;
        match &mut pin.status {
            PinStatus::Evaluating { candidates, .. } => {
                // Mark the specific candidate as failed.
                for c in candidates.iter_mut() {
                    if c.model == model {
                        c.state = ShadowCandidateState::Failed { reason: reason.clone() };
                    }
                }
                // If all candidates have resolved (passed or failed), check if
                // any passed. If none passed, transition to Rejected.
                let all_resolved = candidates.iter().all(|c| {
                    matches!(c.state, ShadowCandidateState::Passed | ShadowCandidateState::Failed { .. })
                });
                if all_resolved {
                    let any_passed = candidates.iter().any(|c| matches!(c.state, ShadowCandidateState::Passed));
                    if !any_passed {
                        let summary = candidates.iter()
                            .filter_map(|c| match &c.state {
                                ShadowCandidateState::Failed { reason } => Some(format!("{}: {}", c.model, reason)),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("; ");
                        pin.status = PinStatus::Rejected {
                            candidate_model: model.to_string(),
                            reason: summary,
                        };
                    }
                }
                info!(model = %model, "shadow candidate rejected");
                Some(model.to_string())
            }
            _ => None,
        }
    }

    /// Mark a shadow candidate as passed.
    pub fn pass_shadow_candidate(&mut self, model: &str) {
        if let Some(ref mut pin) = self.operator_pin {
            if let PinStatus::Evaluating { candidates, .. } = &mut pin.status {
                for c in candidates.iter_mut() {
                    if c.model == model {
                        c.state = ShadowCandidateState::Passed;
                    }
                }
            }
        }
    }

    /// Get the list of candidates currently under shadow evaluation.
    pub fn shadow_candidates(&self) -> Vec<&ShadowCandidate> {
        match &self.operator_pin {
            Some(OperatorModelPin { status: PinStatus::Evaluating { candidates, .. }, .. }) => {
                candidates.iter().collect()
            }
            _ => vec![],
        }
    }

    /// Check if the Regent is currently shadow-evaluating any model.
    pub fn is_shadow_evaluating(&self) -> bool {
        matches!(
            &self.operator_pin,
            Some(OperatorModelPin { status: PinStatus::Evaluating { .. }, .. })
        )
    }

    /// Set the pin to Evaluating state — used by chain reconstitution
    /// when a shadow_start receipt is found without a subsequent result.
    pub fn set_shadow_evaluating(
        &mut self,
        candidate: String,
        active: String,
        routing: Option<String>,
    ) {
        self.operator_pin = Some(OperatorModelPin {
            reasoning_model: Some(candidate.clone()),
            routing_model: routing,
            pinned_at: chrono::Utc::now(),
            status: PinStatus::Evaluating {
                candidates: vec![ShadowCandidate {
                    model: candidate,
                    state: ShadowCandidateState::Pending,
                }],
                active_model: active,
            },
        });
    }

    /// Set the pin to Rejected state — used by chain reconstitution
    /// when a shadow_rejected receipt is found.
    pub fn set_shadow_rejected(&mut self, candidate: String, reason: String) {
        self.operator_pin = Some(OperatorModelPin {
            reasoning_model: Some(candidate.clone()),
            routing_model: None,
            pinned_at: chrono::Utc::now(),
            status: PinStatus::Rejected {
                candidate_model: candidate,
                reason,
            },
        });
    }

    /// Apply a chain-sourced model pin. Updates both the pin and the config
    /// so the inference backend uses the right model name.
    pub fn apply_chain_pin(&mut self, reasoning: Option<String>, routing: Option<String>) {
        let pin = self.operator_pin.get_or_insert(OperatorModelPin {
            reasoning_model: None,
            routing_model: None,
            pinned_at: chrono::Utc::now(),
            status: PinStatus::Active,
        });
        if let Some(ref m) = reasoning {
            pin.reasoning_model = Some(m.clone());
            self.config.reasoning_model = m.clone();
        }
        if let Some(ref m) = routing {
            pin.routing_model = Some(m.clone());
            self.config.routing_model = m.clone();
        }
    }

    /// Resolve which model to use for a given intent category.
    ///
    /// Priority: operator pin > dossier scoring > config defaults.
    /// When pinned, the router is bypassed entirely — the operator's
    /// explicit choice takes precedence over all evidence-based scoring.
    fn resolve_model(
        &self,
        category: &crate::routing::IntentCategory,
        awareness: Option<&crate::context::SystemAwareness>,
    ) -> crate::routing::RouteDecision {
        // Operator pin takes priority over everything.
        if let Some(ref pin) = self.operator_pin {
            // During shadow evaluation, serve the active (groomed) model.
            // The candidate is being validated; the operator isn't degraded.
            let effective_model = match &pin.status {
                PinStatus::Evaluating { active_model, .. } => {
                    Some(active_model.as_str())
                }
                PinStatus::Rejected { .. } => {
                    // Rejected — fall through to router scoring.
                    // The pin records findings but doesn't direct inference.
                    None
                }
                PinStatus::Active => {
                    match category {
                        crate::routing::IntentCategory::Routing => {
                            pin.routing_model.as_deref().or(pin.reasoning_model.as_deref())
                        }
                        _ => pin.reasoning_model.as_deref(),
                    }
                }
            };
            if let Some(model) = effective_model {
                // Derive tier from backend protocol, not model name.
                let tier = match self.inference.protocol() {
                    crate::inference::InferenceProtocol::OpenAI => {
                        crate::routing::InferenceTier::Cloud {
                            provider: self.inference.provider().name.clone(),
                        }
                    }
                    crate::inference::InferenceProtocol::Ollama => {
                        crate::routing::InferenceTier::Local
                    }
                };
                let rationale = match &pin.status {
                    PinStatus::Evaluating { candidates, .. } => {
                        let names: Vec<&str> = candidates.iter().map(|c| c.model.as_str()).collect();
                        format!("operator pin (evaluating [{}]): serving {}", names.join(", "), model)
                    }
                    _ => format!("operator pin: {}", model),
                };
                return crate::routing::RouteDecision {
                    model: model.to_string(),
                    endpoint: self.config.inference_endpoint.clone(),
                    tier,
                    rationale,
                    alternatives_rejected: vec![],
                };
            }
        }

        // No pin — route through dossier corpus or config defaults.
        match &self.dossier_corpus {
            Some(corpus) if !corpus.is_empty() => {
                crate::routing::Router::route(category, corpus, awareness, &self.config)
            }
            _ => crate::routing::Router::route_from_config(category, &self.config),
        }
    }

    /// Dispatch an inference request to the right backend based on tier.
    /// Local → Ollama directly. Cloud → cloud endpoint (with fallback).
    async fn infer(&self, request: &InferenceRequest, tier: &crate::routing::InferenceTier) -> Result<String, RegentError> {
        match tier {
            crate::routing::InferenceTier::Local => self.inference.chat_local(request).await,
            crate::routing::InferenceTier::Cloud { .. } => self.inference.chat(request).await,
        }
    }

    /// Short label for the active model(s) — used in telemetry events.
    pub fn model_label(&self) -> String {
        if self.config.routing_model == self.config.reasoning_model {
            self.config.routing_model.clone()
        } else {
            format!("{}/{}", self.config.routing_model, self.config.reasoning_model)
        }
    }

    /// The cognitive loop: Perceive → Reason → Decide.
    ///
    /// This is the core of the Regent. Each call is one cycle:
    /// 1. **Perceive**: assemble cognitive context from chain state,
    ///    officer findings, operator input, and memory.
    /// 2. **Reason**: run local inference over the context to understand
    ///    what's happening and what matters.
    /// 3. **Decide**: produce an Intent — the Regent's chosen action.
    ///
    /// The caller (zp-server's loop runner) handles execution of the
    /// Intent: emitting receipts, dispatching to sub-agents, delivering
    /// responses through cockpit surfaces.
    pub async fn cycle(
        &mut self,
        chain: &ChainReader<'_>,
        findings: &[Finding],
        operator_input: Option<OperatorInput>,
        delegations: &[DelegationSummary],
        system_awareness: Option<SystemAwareness>,
    ) -> Result<Intent, RegentError> {
        self.cycle_count += 1;
        debug!(cycle = self.cycle_count, "regent cycle starting");

        // ── Phase 1: Perceive ──────────────────────────────────────────
        let context = self.perceive(chain, findings, operator_input, delegations, system_awareness, Vec::new(), None, None)?;

        // ── Phase 2: Reason ────────────────────────────────────────────
        let intent = self.reason(&context).await?;

        // ── Phase 3: Post-cycle memory maintenance ─────────────────────
        if let Err(e) = self.memory.flush() {
            warn!("memory flush failed: {}", e);
        }

        debug!(
            cycle = self.cycle_count,
            intent = intent.receipt_event(),
            "regent cycle complete"
        );

        Ok(intent)
    }

    /// Phase 1: Perceive — assemble cognitive context.
    ///
    /// Public within the crate so `run_cycle` can call perceive separately
    /// from reason — the sync/async split prevents holding a std::sync::Mutex
    /// guard across an await point.
    pub(crate) fn perceive(
        &mut self,
        chain: &ChainReader<'_>,
        findings: &[Finding],
        operator_input: Option<OperatorInput>,
        delegations: &[DelegationSummary],
        system_awareness: Option<SystemAwareness>,
        tool_results: Vec<crate::context::ToolResult>,
        work_arc: Option<crate::context::WorkArc>,
        prior_response: Option<crate::context::PriorResponse>,
    ) -> Result<CognitiveContext, RegentError> {
        // Read recent chain entries (compressed for context efficiency).
        let recent_entries = chain
            .recent_entries(50)
            .map_err(|e| RegentError::ChainRead(e.to_string()))?;

        let recent_chain: Vec<ChainSnapshot> = recent_entries
            .iter()
            .map(ChainSnapshot::from_entry)
            .collect();

        // Compress officer findings.
        let officer_findings: Vec<FindingSummary> = findings
            .iter()
            .map(FindingSummary::from_finding)
            .collect();

        // Retrieve relevant memories based on current context.
        let memory_fragments = self.retrieve_relevant_memories(&operator_input);

        // ── Standing corrections (Tier 1 cognitive input) ────────────────
        // Query the full chain — corrections live indefinitely once issued
        // (until superseded / revoked / expired). Search by both event
        // prefixes so revocations are included in the index build.
        let now = chrono::Utc::now();
        let mut correction_entries = chain
            .search_by_keyword(
                crate::corrections::EVENT_PREFIX_STANDING,
                CORRECTION_SEARCH_LIMIT,
            )
            .unwrap_or_default();
        let mut revocation_entries = chain
            .search_by_keyword(
                crate::corrections::EVENT_PREFIX_REVOKED,
                CORRECTION_SEARCH_LIMIT,
            )
            .unwrap_or_default();
        correction_entries.append(&mut revocation_entries);

        let index = CorrectionIndex::build(&correction_entries, now);
        let standing_corrections: Vec<crate::corrections::ActiveStandingCorrection> = index
            .top_k_by_priority(TIER1_CORRECTION_LIMIT)
            .into_iter()
            .cloned()
            .collect();

        // ── Composition provenance ──────────────────────────────────────
        // Structural hashes only — no content bloat on chain per cycle.
        //
        // Authorship: standing corrections are always operator-issued today
        // (`StandingCorrection::issued_by` is the operator's Genesis key —
        // no Regent-authored standing correction exists in this runtime),
        // and officer findings are always officer-authored by construction.
        // So `self_authorship_ratio` is 0.0 on every cycle until Regent
        // corpus authorship (Class 2/3 per §III.27) exists — the expected
        // baseline per ZEP-self-referential-authorship-2026-07.md §10.
        let standing_correction_authorship =
            crate::context::ClassAuthorship::all_operator(standing_corrections.len());
        let officer_finding_authorship =
            crate::context::ClassAuthorship::all_officer(officer_findings.len());
        let self_authorship_ratio = crate::context::tier_weighted_self_authorship_ratio(
            &standing_correction_authorship,
            &officer_finding_authorship,
        );

        let composition_summary = Some(crate::context::CompositionSummary {
            matrix_version: COGNITIVE_INPUT_MATRIX_VERSION.to_string(),
            standing_correction_count: standing_corrections.len(),
            standing_corrections_hash:
                crate::context::CompositionSummary::hash_corrections(&standing_corrections),
            standing_correction_authorship,
            officer_finding_count: officer_findings.len(),
            officer_findings_hash:
                crate::context::CompositionSummary::hash_findings(&officer_findings),
            officer_finding_authorship,
            recent_chain_count: recent_chain.len(),
            active_delegation_count: delegations.len(),
            invocation_reason: perception_invocation_reason(
                &operator_input,
                &work_arc,
                !tool_results.is_empty(),
            ),
            self_authorship_ratio,
        });

        Ok(CognitiveContext {
            assembled_at: now,
            sovereign: self.sovereign.clone(),
            recent_chain,
            officer_findings,
            posture_summary: None, // TODO: wire governance posture
            pending_input: operator_input,
            memory_fragments,
            standing_corrections,
            active_delegations: delegations.to_vec(),
            system_awareness,
            tool_results,
            work_arc,
            prior_response,
            composition_summary,
        })
    }

    /// Phase 2: Reason — two-tier inference over cognitive context.
    ///
    /// Tier 1 (routing): Small/fast model decides intent type.
    ///   - Execute → return immediately, caller dispatches tool.
    ///   - Observe → return immediately.
    ///   - Respond → escalate to Tier 2.
    ///
    /// Tier 2 (reasoning): Large model composes the actual response.
    ///   - Only fires for Respond intents.
    ///   - Full context, natural language output.
    ///
    /// Public within the crate so `run_cycle` can call it after perceive,
    /// with the AuditStore lock already dropped.
    pub(crate) async fn reason(&self, context: &CognitiveContext) -> Result<Intent, RegentError> {
        // If there's no operator input and no urgent findings, just observe.
        let has_urgent = context
            .officer_findings
            .iter()
            .any(|f| f.severity == "Error" || f.severity == "Critical");

        // Skip inference only when there's genuinely nothing to do:
        // no operator input, no urgent findings, and no tool results
        // from a prior turn that need narration.
        if context.pending_input.is_none() && !has_urgent && context.tool_results.is_empty() {
            return Ok(Intent::Observe {
                observation: format!(
                    "cycle {}: {} chain entries, {} findings, no input, no urgency",
                    self.cycle_count,
                    context.recent_chain.len(),
                    context.officer_findings.len(),
                ),
            });
        }

        // Fast path: same model for both tiers → single call with full
        // prompt. Two calls with the same model just doubles latency.
        if self.config.routing_model == self.config.reasoning_model {
            return self.unified_inference(context).await;
        }

        // ── Two-tier path: different models ───────────────────────────
        let intent = self.route(context).await?;

        match &intent {
            Intent::Execute { .. } | Intent::Observe { .. } => Ok(intent),

            Intent::Respond { .. } => {
                let composed = self.compose(context).await?;
                Ok(Intent::Respond {
                    content: composed,
                    target_surface: None,
                })
            }

            _ => Ok(intent),
        }
    }

    /// Single-model fast path: one inference call handles both routing
    /// and response generation. Used when routing_model == reasoning_model.
    async fn unified_inference(&self, context: &CognitiveContext) -> Result<Intent, RegentError> {
        let user_prompt = self.build_user_prompt(context);
        let has_delegations = !context.active_delegations.is_empty();

        // System prompt assembled from template files.
        let sovereign_section = match &context.sovereign {
            Some(sov) => format!(
                "IDENTITY: You serve operator {} (genesis public key: {}…).\nYou address this operator by name when relevant.",
                sov.operator_name,
                &sov.genesis_pubkey[..8.min(sov.genesis_pubkey.len())]
            ),
            None => "IDENTITY: No sovereign identity loaded.".to_string(),
        };

        let tool_section = if has_delegations {
            PROMPT_UNIFIED_TOOLS.trim()
        } else {
            PROMPT_UNIFIED_NO_TOOLS.trim()
        };

        let standing_corrections_section = build_standing_corrections_section(context);

        let system_prompt = PROMPT_UNIFIED_SYSTEM
            .replace("{sovereign_section}", &sovereign_section)
            .replace(
                "{standing_corrections_section}",
                &standing_corrections_section,
            )
            .replace("{tool_section}", tool_section);

        // Route through dossier corpus if available; fall back to config default.
        let route = self.resolve_model(
            &crate::routing::IntentCategory::Conversation,
            context.system_awareness.as_ref(),
        );

        info!(
            system_len = system_prompt.len(),
            user_len = user_prompt.len(),
            model = %route.model,
            rationale = %route.rationale,
            "regent UNIFIED inference"
        );

        let request = InferenceRequest {
            model: route.model,
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: system_prompt,
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: user_prompt,
                },
            ],
            // Constrained decoding — forces the model to produce valid JSON
            // matching this schema. Without this, small models output tool
            // names as plain text or produce malformed JSON with unescaped
            // quotes. The schema covers both respond and execute intents.
            format: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "intent": {
                        "type": "string",
                        "enum": ["execute", "respond", "observe", "continue", "request_approval"]
                    },
                    "tool": { "type": "string" },
                    "params": { "type": "object" },
                    "content": { "type": "string" },
                    "progress": { "type": "string" }
                },
                "required": ["intent"]
            })),
            temperature: 0.3,
            stream: false,
            options: Some(serde_json::json!({
                "num_predict": 512
            })),
            keep_alive: Some(serde_json::json!(-1)),
            think: Some(false),
        };

        let response = self.infer(&request, &route.tier).await?;

        info!(
            response_len = response.len(),
            response_preview = %if response.len() > 200 { &response[..200] } else { &response },
            "regent UNIFIED response"
        );

        if response.is_empty() {
            warn!("unified inference returned empty response");
            return Ok(Intent::Respond {
                content: "(regent: model returned empty response)".to_string(),
                target_surface: None,
            });
        }

        // Try to parse as JSON intent first; if that fails, treat the
        // entire response as a natural-language answer.
        match parse_intent(&response) {
            Ok(intent) => Ok(intent),
            Err(_) => {
                debug!(raw = %response, "unified response not valid JSON — treating as natural language");
                Ok(Intent::Respond {
                    content: response,
                    target_surface: None,
                })
            }
        }
    }

    /// Tier 1: Route — fast intent classification.
    ///
    /// Small model, minimal prompt, low token budget.
    /// Decides WHAT to do, not HOW to respond.
    async fn route(&self, context: &CognitiveContext) -> Result<Intent, RegentError> {
        let user_prompt = self.build_user_prompt(context);

        // Condensed context for the router — just enough to decide intent.
        let system_prompt = self.build_routing_prompt(context);

        let route = self.resolve_model(
            &crate::routing::IntentCategory::Routing,
            context.system_awareness.as_ref(),
        );

        info!(
            system_len = system_prompt.len(),
            user_len = user_prompt.len(),
            model = %route.model,
            rationale = %route.rationale,
            "regent ROUTE tier"
        );

        let request = InferenceRequest {
            model: route.model,
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: system_prompt,
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: user_prompt,
                },
            ],
            format: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "intent": {
                        "type": "string",
                        "enum": ["execute", "respond", "observe", "continue", "request_approval"]
                    },
                    "tool": { "type": "string" },
                    "params": { "type": "object" },
                    "progress": { "type": "string" }
                },
                "required": ["intent"]
            })),
            temperature: 0.1,
            stream: false,
            options: Some(serde_json::json!({
                "num_predict": 64
            })),
            keep_alive: Some(serde_json::json!(-1)),
            think: Some(false),
        };

        let response = self.infer(&request, &route.tier).await?;

        info!(
            response_len = response.len(),
            response = %response,
            "regent ROUTE response"
        );

        if response.is_empty() {
            warn!("routing model returned empty — falling through to respond");
            return Ok(Intent::Respond {
                content: String::new(),
                target_surface: None,
            });
        }

        parse_intent(&response)
    }

    /// Tier 2: Compose — deep reasoning for operator responses.
    ///
    /// Large model, full context, natural language output.
    /// Only called when Tier 1 decides the intent is Respond.
    async fn compose(&self, context: &CognitiveContext) -> Result<String, RegentError> {
        let persona_fragment = self.persona.system_prompt_fragment();
        let user_prompt = self.build_user_prompt(context);

        let sovereign_section = match &context.sovereign {
            Some(sov) => format!(
                "IDENTITY: You serve operator {} (genesis: {}…).",
                sov.operator_name,
                &sov.genesis_pubkey[..8.min(sov.genesis_pubkey.len())]
            ),
            None => "IDENTITY: No sovereign identity loaded.".to_string(),
        };

        let standing_corrections_section = build_standing_corrections_section(context);

        let available_actions = Self::build_available_actions(context);

        let system_prompt = PROMPT_COMPOSE
            .replace("{persona}", &persona_fragment)
            .replace("{sovereign_section}", &sovereign_section)
            .replace("{available_actions}", &available_actions)
            .replace(
                "{standing_corrections_section}",
                &standing_corrections_section,
            );

        let route = self.resolve_model(
            &crate::routing::IntentCategory::Conversation,
            context.system_awareness.as_ref(),
        );

        info!(
            system_len = system_prompt.len(),
            user_len = user_prompt.len(),
            model = %route.model,
            rationale = %route.rationale,
            "regent COMPOSE tier"
        );

        let request = InferenceRequest {
            model: route.model,
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: system_prompt,
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: user_prompt,
                },
            ],
            format: None,
            temperature: 0.3,
            stream: false,
            options: Some(serde_json::json!({
                "num_predict": 512
            })),
            keep_alive: Some(serde_json::json!(-1)),
            think: Some(false),
        };

        let response = self.infer(&request, &route.tier).await?;

        info!(
            response_len = response.len(),
            response_preview = %if response.len() > 200 { &response[..200] } else { &response },
            "regent COMPOSE response"
        );

        if response.is_empty() {
            return Ok("(regent: reasoning model returned empty response)".to_string());
        }

        Ok(response)
    }

    /// Build the routing prompt — minimal, for intent classification only.
    /// Call signature for a granted capability, for the routing menu.
    ///
    /// Presence is derived from active delegations; only the *syntax* is
    /// declared here. A capability with no entry is offered as `name()`.
    fn tool_signature(capability: &str) -> String {
        match capability {
            "chain_query" => "chain_query(limit:N)".to_string(),
            "model_evaluate" => "model_evaluate(model:\"name\")".to_string(),
            "memory_list" => "memory_list(stage?)".to_string(),
            "memory_review" => "memory_review(action,review_id?,reason?)".to_string(),
            other => format!("{other}()"),
        }
    }

    /// Routing-tier hint for capabilities a small model routinely mis-routes.
    /// Emitted only when the capability is actually delegated.
    fn tool_hint(capability: &str) -> Option<&'static str> {
        match capability {
            "self_configure" => Some(
                "- Operator asks what model, endpoint, or inference config you are running → {\"intent\":\"execute\",\"tool\":\"self_configure\",\"params\":{}}",
            ),
            "substrate_validate" => Some(
                "- Operator asks for substrate validation, health, or posture report → {\"intent\":\"execute\",\"tool\":\"substrate_validate\",\"params\":{}}",
            ),
            _ => None,
        }
    }

    /// Build the routing prompt.
    ///
    /// The tool menu is **derived from active delegations**, not hardcoded.
    /// Per the working heuristic *the chain configures the cockpit; cockpits
    /// are pure projections*: the Regent's tool menu is a cockpit affordance,
    /// and affordances are a projection of currently-granted capability over
    /// the verb set. A parallel hand-maintained list drifts — on 2026-07-26 a
    /// static menu omitted `self_configure`, so the routing model could never
    /// select it, and a standing correction requiring config verification
    /// became unsatisfiable. Deriving the menu makes that class of bug
    /// structurally impossible.
    fn build_routing_prompt(&self, context: &CognitiveContext) -> String {
        if context.active_delegations.is_empty() {
            return PROMPT_ROUTING_NO_TOOLS.trim().to_string();
        }

        let mut caps: Vec<&str> = context
            .active_delegations
            .iter()
            .map(|d| d.capability.as_str())
            .collect();
        caps.sort_unstable();
        caps.dedup();

        let tools = caps
            .iter()
            .map(|c| Self::tool_signature(c))
            .collect::<Vec<_>>()
            .join(", ");

        let hints = caps
            .iter()
            .filter_map(|c| Self::tool_hint(c))
            .map(|h| format!("{h}\n"))
            .collect::<String>();

        PROMPT_ROUTING_TOOLS
            .trim()
            .replace("{tools}", &tools)
            .replace("{tool_hints}", &hints)
    }

    /// The action menu, rendered for the composing tier.
    ///
    /// The compose model writes prose and cannot dispatch tools — routing does
    /// that. But without knowing what *can* be done it invents offers it cannot
    /// honour ("shall I check the active model for you?" when no such tool was
    /// reachable). Giving it the same derived list makes its offers accurate.
    fn build_available_actions(context: &CognitiveContext) -> String {
        if context.active_delegations.is_empty() {
            return "None. You cannot take actions this cycle — answer from context only."
                .to_string();
        }
        let mut caps: Vec<&str> = context
            .active_delegations
            .iter()
            .map(|d| d.capability.as_str())
            .collect();
        caps.sort_unstable();
        caps.dedup();
        caps.join(", ")
    }

    /// Build the user prompt from cognitive context.
    fn build_user_prompt(&self, context: &CognitiveContext) -> String {
        let mut parts = Vec::new();

        // Operator input FIRST — when the operator speaks, their request
        // is the primary directive. Everything else is context.
        // Small models latch onto the first substantial content; burying
        // operator input after officer findings causes confabulation
        // (model responds to findings, never reaches the actual request).
        if let Some(ref input) = context.pending_input {
            let source = match input.source {
                CockpitSource::Regent => "Regent",
                CockpitSource::Cli => "CLI",
                CockpitSource::Browser => "Browser",
                CockpitSource::Autonomous => "Autonomous",
            };
            parts.push(format!(
                "OPERATOR REQUEST (respond to THIS, not to findings below):\n{} ({source}): {}",
                "Operator", input.content,
            ));
        }

        // CONVERSATION CONTINUITY: the Regent's own prior turn.
        //
        // This was previously framed as a SELF-CHECK asking the Regent to
        // verify whether her prior response was confabulated. That framing
        // broke multi-turn threads: told to distrust her own last turn, a
        // small model resets to a neutral response and abandons whatever
        // the thread established. Observed 2026-07-26 — "shall I retrieve
        // that?" / "yes please" produced "I am here. What would you like
        // to do?" because the mirror instructed suspicion of the offer.
        //
        // Post-emission verification belongs to the Cognitive Self-Observer
        // (KEEL §II.17), which is implemented and running. Doing it here too
        // violates P8 (one canonical path per substrate concern) and the
        // prompt-side copy degrades cognition while the real one works.
        // This block is now neutral continuity context.
        if context.pending_input.is_some() {
            // Only mirror an actual conversational turn. `last_prior_response`
            // captures every non-error cycle response, including an autonomous
            // cycle's observe narration ("cycle 1: 55 chain entries, 0 findings,
            // no input, no urgency"). That is not something the Regent said *to
            // the operator*, and presenting it as such — then instructing her to
            // continue the conversation — makes her recite cycle telemetry at
            // the operator. Observed 2026-07-26 immediately after this block was
            // reframed from self-check to continuity: the prior framing had been
            // accidentally suppressing it by instructing distrust of the prior turn.
            //
            // A conversational turn is one that had an operator question.
            if let Some(prior) = context
                .prior_response
                .as_ref()
                .filter(|p| p.operator_question.is_some())
            {
                let q = prior.operator_question.as_deref().unwrap_or_default();
                // Truncate long responses to avoid burning context on the mirror.
                let r = if prior.response_content.len() > 300 {
                    format!("{}…", &prior.response_content[..300])
                } else {
                    prior.response_content.clone()
                };
                parts.push(format!(
                    "CONVERSATION SO FAR:\n\
                     Operator: \"{}\"\n\
                     You: \"{}\"\n\
                     Continue this conversation. If your previous turn offered to do \
                     something and the operator has now accepted, do that thing — do \
                     not offer again. Treat the exchange above as what you remember \
                     saying, not as something to evaluate.",
                    q, r,
                ));
            }
        }

        // Work arc context — if resuming a multi-cycle task.
        if let Some(ref arc) = context.work_arc {
            parts.push(format!(
                "WORK ARC IN PROGRESS (cycle {}/{}): {}\n\
                 You are mid-task. Use your tools to continue, then either:\n\
                 - \"continue\" with updated progress if more work remains\n\
                 - \"respond\" to tell the operator what you accomplished",
                arc.cycles_completed + 1, arc.max_cycles, arc.progress
            ));
        }

        // Tool results from prior turns in this cycle.
        // These appear when the Regent has already acted and needs to
        // compose a narration of what she did.
        if !context.tool_results.is_empty() {
            let results: Vec<String> = context
                .tool_results
                .iter()
                .map(|r| {
                    let status = if r.succeeded { "OK" } else { "FAILED" };
                    format!("[{}] {} → {}", status, r.tool, r.output)
                })
                .collect();
            parts.push(format!(
                "YOUR PRIOR ACTIONS THIS CYCLE:\n{}\n\
                 Now tell the operator the SPECIFIC results from your tool calls above. \
                 Include actual data: URLs, titles, status codes, counts — whatever the tool returned. \
                 Do NOT give a generic summary. Relay what you actually observed.",
                results.join("\n")
            ));
        }

        // Officer findings — attention-hierarchical.
        // When the operator is speaking, findings are compressed to a
        // one-line summary so the model's attention stays on the human.
        // Full findings only surface when no operator input is present
        // (stewardship mode) or when findings are critical-severity.
        if !context.officer_findings.is_empty() {
            let is_conversation = context.pending_input.is_some();
            if is_conversation {
                let critical: Vec<String> = context
                    .officer_findings
                    .iter()
                    .filter(|f| f.severity == "Critical")
                    .map(|f| format!("[{}] {}: {}", f.severity, f.officer, f.summary))
                    .collect();
                let total = context.officer_findings.len();
                if critical.is_empty() {
                    parts.push(format!(
                        "({} officer findings pending — none critical, will address in next idle cycle)",
                        total
                    ));
                } else {
                    parts.push(format!(
                        "CRITICAL findings ({}), plus {} other findings deferred:\n{}",
                        critical.len(),
                        total - critical.len(),
                        critical.join("\n")
                    ));
                }
            } else {
                // Stewardship mode — full findings.
                let findings: Vec<String> = context
                    .officer_findings
                    .iter()
                    .map(|f| format!("[{}] {}: {}", f.severity, f.officer, f.summary))
                    .collect();
                parts.push(format!("Officer findings:\n{}", findings.join("\n")));
            }
        }

        // Recent chain activity — compressed in conversation mode.
        if !context.recent_chain.is_empty() {
            let is_conversation = context.pending_input.is_some();
            if is_conversation {
                // Operator is talking — chain is background context, not primary.
                parts.push(format!(
                    "({} recent chain entries — available via chain_query if needed)",
                    context.recent_chain.len()
                ));
            } else {
                // Stewardship mode — full chain context for autonomous reasoning.
                let recent: Vec<String> = context
                    .recent_chain
                    .iter()
                    .rev()
                    .take(10)
                    .map(|e| {
                        format!(
                            "{}: {} ({}{})",
                            e.timestamp.format("%H:%M:%S"),
                            e.action_summary,
                            e.actor,
                            if e.signed { ", signed" } else { "" }
                        )
                    })
                    .collect();
                parts.push(format!("Recent chain:\n{}", recent.join("\n")));
            }
        }

        // Memory fragments.
        if !context.memory_fragments.is_empty() {
            let mems: Vec<String> = context
                .memory_fragments
                .iter()
                .map(|m| format!("[{}] {}", m.key, m.content))
                .collect();
            parts.push(format!("Relevant memories:\n{}", mems.join("\n")));
        }

        // Autonomous remediation prompt: when there are urgent findings
        // but no operator input, explicitly frame this as a remediation
        // cycle so the model knows to act rather than just describe.
        // Only fires on the first turn — once tool results exist, the
        // Regent has already acted and should now narrate.
        if context.pending_input.is_none() && context.tool_results.is_empty() {
            let has_urgent = context
                .officer_findings
                .iter()
                .any(|f| f.severity == "Error" || f.severity == "Critical");
            if has_urgent {
                parts.push(
                    "AUTONOMOUS CYCLE: No operator input. Officer findings above require your attention. \
                     If you have a tool that can fix a reported problem, use it now."
                        .to_string(),
                );
            }
        }

        parts.join("\n\n")
    }

    /// Retrieve memories relevant to the current context.
    fn retrieve_relevant_memories(
        &mut self,
        input: &Option<OperatorInput>,
    ) -> Vec<MemoryFragment> {
        let mut fragments = Vec::new();

        // If there's operator input, search for keyword matches.
        if let Some(ref input) = input {
            let keywords: Vec<&str> = input.content.split_whitespace().collect();
            for kw in keywords.iter().take(5) {
                if kw.len() < 4 {
                    continue; // Skip short words.
                }
                for entry in self.memory.search_by_keyword(kw) {
                    fragments.push(MemoryFragment {
                        key: entry.key.clone(),
                        content: entry.content.clone(),
                        relevance_score: 0.5, // MVP: no vector scoring yet.
                        stored_at: entry.created_at,
                    });
                }
            }
        }

        // Always include the most recent memories as background context.
        for entry in self.memory.recent(3) {
            if !fragments.iter().any(|f| f.key == entry.key) {
                fragments.push(MemoryFragment {
                    key: entry.key.clone(),
                    content: entry.content.clone(),
                    relevance_score: 0.3,
                    stored_at: entry.created_at,
                });
            }
        }

        // Deduplicate and limit.
        fragments.sort_by(|a, b| b.relevance_score.partial_cmp(&a.relevance_score).unwrap_or(std::cmp::Ordering::Equal));
        fragments.truncate(10);
        fragments
    }

    /// Access the Regent's persona (for cockpit rendering).
    pub fn persona(&self) -> &Persona {
        &self.persona
    }

    /// Access the Regent's config.
    pub fn config(&self) -> &RegentConfig {
        &self.config
    }

    /// Current operator model pin, if any.
    pub fn operator_pin(&self) -> Option<&OperatorModelPin> {
        self.operator_pin.as_ref()
    }

    /// Access to the dossier corpus — for shadow validation tier determination.
    pub fn dossier_corpus(&self) -> Option<&crate::routing::DossierCorpus> {
        self.dossier_corpus.as_deref()
    }

    /// Mutable access to the inference backend — for vault key injection.
    pub fn inference(&self) -> &InferenceBackend {
        &self.inference
    }

    pub fn inference_mut(&mut self) -> &mut InferenceBackend {
        &mut self.inference
    }

    /// How many cognitive cycles have run.
    pub fn cycle_count(&self) -> u64 {
        self.cycle_count
    }

    /// Check if the inference backend is healthy.
    pub async fn inference_healthy(&self) -> bool {
        self.inference.health_check().await.unwrap_or(false)
    }

    /// Preload routing and reasoning models into memory.
    ///
    /// Called at startup to eliminate cold-start latency on the first
    /// operator interaction. Models are pinned with keep_alive=-1.
    ///
    /// **Inference hygiene**: unloads all currently loaded models first
    /// to clear stale KV cache from prior ZP sessions. Without this,
    /// a model pinned with keep_alive=-1 survives ZP restarts and
    /// serves responses from the old session's prompt context.
    pub async fn preload_models(&self) {
        // Unload stale models — the substrate controls its inference layer.
        self.inference.unload_all().await;

        let mut models = vec![self.config.routing_model.as_str()];
        if self.config.reasoning_model != self.config.routing_model {
            models.push(self.config.reasoning_model.as_str());
        }
        self.inference.preload(&models).await;
    }

    /// Flush persistent memory to disk.
    pub fn flush_memory(&mut self) -> Result<(), std::io::Error> {
        self.memory.flush()
    }

    /// Reconfigure the inference backend at runtime.
    ///
    /// Called by the `self_configure` tool — the Regent changes her own
    /// cognitive substrate without a restart. Updates config fields and
    /// the inference backend in one atomic operation (behind the Mutex).
    pub fn reconfigure_inference(
        &mut self,
        endpoint: Option<String>,
        reasoning_model: Option<String>,
        routing_model: Option<String>,
        api_key_source: Option<crate::config::ApiKeySource>,
        force: bool,
    ) -> serde_json::Value {
        let old_endpoint = self.config.inference_endpoint.clone();
        let old_reasoning = self.config.reasoning_model.clone();
        let old_routing = self.config.routing_model.clone();
        let old_protocol = format!("{:?}", self.inference.protocol());

        // "auto" clears the operator pin — router takes over.
        let auto_reasoning = reasoning_model.as_deref() == Some("auto");
        let auto_routing = routing_model.as_deref() == Some("auto");

        if auto_reasoning && auto_routing {
            // Full auto — clear pin entirely, reset to defaults.
            self.operator_pin = None;
            let defaults = RegentConfig::default();
            self.config.reasoning_model = defaults.reasoning_model;
            self.config.routing_model = defaults.routing_model;
            info!("operator pin cleared — router will score from dossier corpus");
        } else if auto_reasoning {
            // Clear just the reasoning pin.
            if let Some(ref mut pin) = self.operator_pin {
                pin.reasoning_model = None;
            }
            self.config.reasoning_model = RegentConfig::default().reasoning_model;
        } else if auto_routing {
            // Clear just the routing pin.
            if let Some(ref mut pin) = self.operator_pin {
                pin.routing_model = None;
            }
            self.config.routing_model = RegentConfig::default().routing_model;
        }

        if let Some(ref ep) = endpoint {
            self.config.inference_endpoint = ep.clone();
        }
        if !auto_reasoning {
            if let Some(ref m) = reasoning_model {
                self.config.reasoning_model = m.clone();
            }
        }
        if !auto_routing {
            if let Some(ref m) = routing_model {
                self.config.routing_model = m.clone();
            }
        }
        if let Some(ref source) = api_key_source {
            self.config.api_key_source = source.clone();
        }

        // Set operator pin if models were explicitly changed (not auto).
        if reasoning_model.is_some() && !auto_reasoning
            || routing_model.is_some() && !auto_routing
        {
            if force {
                // Force-cut: pin immediately active, config updated above.
                let pin = self.operator_pin.get_or_insert(OperatorModelPin {
                    reasoning_model: None,
                    routing_model: None,
                    pinned_at: chrono::Utc::now(),
                    status: PinStatus::Active,
                });
                pin.status = PinStatus::Active;
                if let Some(ref m) = reasoning_model {
                    if !auto_reasoning {
                        pin.reasoning_model = Some(m.clone());
                        pin.pinned_at = chrono::Utc::now();
                    }
                }
                if let Some(ref m) = routing_model {
                    if !auto_routing {
                        pin.routing_model = Some(m.clone());
                        pin.pinned_at = chrono::Utc::now();
                    }
                }
            } else {
                // Shadow-first: enter evaluating state. The groomed model
                // stays active; the candidate will be validated before cut-over.
                let candidate = reasoning_model.as_ref()
                    .filter(|_| !auto_reasoning)
                    .cloned()
                    .unwrap_or_else(|| self.config.reasoning_model.clone());
                let active = old_reasoning.clone();

                // Don't update config models yet — the active model stays
                // until the shadow battery passes. Revert config to pre-change.
                self.config.reasoning_model = old_reasoning.clone();
                self.config.routing_model = old_routing.clone();

                self.operator_pin = Some(OperatorModelPin {
                    reasoning_model: Some(candidate.clone()),
                    routing_model: routing_model.as_ref()
                        .filter(|_| !auto_routing)
                        .cloned(),
                    pinned_at: chrono::Utc::now(),
                    status: PinStatus::Evaluating {
                        candidates: vec![ShadowCandidate {
                            model: candidate,
                            state: ShadowCandidateState::Pending,
                        }],
                        active_model: active,
                    },
                });
                info!(
                    pin = ?self.operator_pin,
                    "shadow-first: evaluating candidate, groomed model stays active"
                );
            }
        }

        // Reconfigure the inference backend (endpoint change).
        self.inference.reconfigure(
            self.config.inference_endpoint.clone(),
            None,
        );

        // If key source changed, update the backend.
        if let Some(source) = api_key_source {
            self.inference.set_api_key_source(source);
        }

        let new_protocol = format!("{:?}", self.inference.protocol());
        let provider = self.inference.provider();
        let key_source_label = match &self.config.api_key_source {
            crate::config::ApiKeySource::None => "none",
            crate::config::ApiKeySource::Vault(_) => "vault",
            crate::config::ApiKeySource::RawLegacy(_) => "raw_legacy",
        };

        // Build status based on pin state.
        let (status_label, note) = match &self.operator_pin {
            Some(OperatorModelPin { status: PinStatus::Evaluating { candidates, active_model }, .. }) => {
                let names: Vec<&str> = candidates.iter().map(|c| c.model.as_str()).collect();
                (
                    "evaluating",
                    format!(
                        "Shadow evaluation started for [{}]. You're still on {} while I validate prompt compatibility. \
                         Chain-anchored — pin reconstitutes from receipts at startup.",
                        names.join(", "), active_model,
                    ),
                )
            }
            _ => (
                "reconfigured",
                "Change is chain-anchored. Pin reconstitutes from the most recent regent:config:inference receipt at startup.".to_string(),
            ),
        };

        serde_json::json!({
            "status": status_label,
            "changes": {
                "endpoint": {
                    "from": old_endpoint,
                    "to": self.config.inference_endpoint,
                },
                "reasoning_model": {
                    "from": old_reasoning,
                    "to": self.config.reasoning_model,
                },
                "routing_model": {
                    "from": old_routing,
                    "to": self.config.routing_model,
                },
                "protocol": {
                    "from": old_protocol,
                    "to": new_protocol,
                },
                "api_key_source": key_source_label,
                "provider": provider.name,
                "auth_strategy": format!("{:?}", provider.auth),
            },
            "note": note,
        })
    }
}

// ── Intent parsing ──────────────────────────────────────────────────────────

/// Parse a model response into a structured Intent.
///
/// Strips markdown fences if present, then attempts JSON parse.
/// Falls through to `Intent::Respond` on any parse failure — the model's
/// raw text becomes the operator response. This means the Regent always
/// produces a valid intent, never a parse error that stops the loop.
pub fn parse_intent(response: &str) -> Result<Intent, RegentError> {
    let trimmed = strip_markdown_fences(response);

    // Try JSON parse on the raw response first.
    let value: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => {
            // JSON parse failed. If think tags are present, they may be
            // corrupting the JSON. Strip them and retry — but log the
            // presence as a diagnostic signal for model characterization.
            let cleaned = strip_think_tags(trimmed);
            if cleaned != trimmed {
                warn!(
                    original_len = trimmed.len(),
                    cleaned_len = cleaned.len(),
                    "parse_intent: think tags found in model output — stripping for JSON parse"
                );
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&cleaned) {
                    // Think tags were the only problem — JSON is valid underneath.
                    v
                } else if let Some(intent) = recover_execute_intent(&cleaned) {
                    return Ok(intent);
                } else {
                    debug!("parse_intent: still not valid JSON after stripping think tags");
                    return Ok(Intent::Respond {
                        content: response.to_string(),
                        target_surface: None,
                    });
                }
            } else if let Some(intent) = recover_execute_intent(trimmed) {
                // No think tags, but looks like a malformed tool dispatch.
                return Ok(intent);
            } else {
                // Not JSON and not recoverable — treat as text reply.
                debug!("parse_intent: not JSON, falling through to Respond");
                return Ok(Intent::Respond {
                    content: response.to_string(),
                    target_surface: None,
                });
            }
        }
    };

    // If the JSON doesn't have an "intent" field, the model has produced
    // something other than a structured intent — likely a raw context dump
    // or free-form JSON. Treat it as a confused response rather than
    // silently defaulting to "respond" with empty content.
    let intent_type = match value.get("intent").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => {
            // Detect context dump: JSON with chain/findings/memory keys.
            let is_context_dump = value.get("recent_chain").is_some()
                || value.get("officer_findings").is_some()
                || value.get("memory_fragments").is_some()
                || value.get("active_delegations").is_some();

            if is_context_dump {
                warn!("model returned raw cognitive context instead of intent — suppressing");
                return Ok(Intent::Respond {
                    content: "I received your message but couldn't formulate a proper response. \
                              Could you rephrase?".to_string(),
                    target_surface: None,
                });
            }

            // Other unstructured JSON — check if it has a "content" field
            // that looks like a response.
            if let Some(content) = value.get("content").and_then(|v| v.as_str()) {
                if !content.is_empty() {
                    return Ok(Intent::Respond {
                        content: content.to_string(),
                        target_surface: None,
                    });
                }
            }

            // Fallback: render the JSON as the response rather than
            // returning empty content the operator never sees.
            debug!("parse_intent: JSON without 'intent' field, treating as plain response");
            return Ok(Intent::Respond {
                content: response.to_string(),
                target_surface: None,
            });
        }
    };

    match intent_type {
        "execute" => {
            let raw_tool = value
                .get("tool")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RegentError::IntentParse("execute intent missing 'tool' field".to_string())
                })?;

            // Sanitize tool name. qwen3:1.7b sometimes embeds params inside
            // the tool string with escaped quotes, producing values like:
            //   chain_query","params":{"limit":5}}
            // Extract the actual tool name by matching known tools as prefixes.
            let (tool, recovered_params) = sanitize_tool_name(raw_tool);

            let params = if let Some(rp) = recovered_params {
                // Params were embedded in the tool string — use them.
                rp
            } else {
                value
                    .get("params")
                    .cloned()
                    .unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
            };

            if tool != raw_tool {
                warn!(
                    raw_tool,
                    sanitized = tool.as_str(),
                    "parse_intent: sanitized malformed tool name"
                );
            }

            Ok(Intent::Execute { tool, params })
        }

        "respond" => {
            let content = value
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let target_surface = value
                .get("target_surface")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            Ok(Intent::Respond {
                content,
                target_surface,
            })
        }

        "observe" => {
            let observation = value
                .get("content")
                .or_else(|| value.get("observation"))
                .and_then(|v| v.as_str())
                .unwrap_or("no observation")
                .to_string();
            Ok(Intent::Observe { observation })
        }

        "request_approval" => {
            let proposed_action = value
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("unspecified action")
                .to_string();
            let reason = value
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("no reason given")
                .to_string();
            Ok(Intent::RequestApproval {
                proposed_action,
                reason,
            })
        }

        "continue" => {
            let progress = value
                .get("progress")
                .and_then(|v| v.as_str())
                .unwrap_or("continuing")
                .to_string();
            Ok(Intent::Continue { progress })
        }

        "remember" => {
            let key = value
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("unnamed")
                .to_string();
            let content = value
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Intent::Remember { key, content })
        }

        "delegate" => {
            let task = value
                .get("task")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let capability = value
                .get("capability")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let constraints = value
                .get("constraints")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            Ok(Intent::Delegate {
                task,
                capability,
                constraints,
            })
        }

        _ => {
            // Unknown intent type — fall through to respond with raw content.
            debug!(
                intent_type,
                "parse_intent: unknown intent type, falling through to Respond"
            );
            Ok(Intent::Respond {
                content: response.to_string(),
                target_surface: None,
            })
        }
    }
}

/// Strip `<think>...</think>` blocks and stray `</think>` tags for JSON parsing.
///
/// Used only in `parse_intent` when the raw response fails JSON parse.
/// The inference layer intentionally preserves think tags in its output
/// so they can be logged as a diagnostic signal for model characterization.
/// This function strips them only when needed to attempt JSON recovery.
fn strip_think_tags(s: &str) -> String {
    let mut result = s.to_string();

    // Strip <think>...</think> blocks.
    while let Some(start) = result.find("<think>") {
        if let Some(end) = result[start..].find("</think>") {
            let remove_end = start + end + "</think>".len();
            result = format!("{}{}", &result[..start], &result[remove_end..]);
        } else {
            // Open <think> with no close — strip from <think> to end.
            result = result[..start].to_string();
            break;
        }
    }

    // Strip stray </think> tags (no matching open).
    result = result.replace("</think>", "");

    result.trim().to_string()
}

/// Attempt to recover an Execute intent from malformed JSON.
///
/// When constrained decoding is active, the model sometimes produces JSON
/// that is structurally valid per the grammar but semantically wrong — e.g.,
/// escaped quotes inside string values, or the entire tool+params serialized
/// into a single field. This function looks for recognizable patterns and
/// extracts the tool name, dispatching with empty params (the dispatch layer
/// provides defaults).
///
/// Known failure patterns from qwen3:1.7b:
/// - `{"intent":"execute","tool":"chain_query\",\"params\":{\"limit\":5}}`
///   (escaped quotes embedding params into the tool field)
/// - Tool name followed by `()` or `(limit:5)` style syntax
fn recover_execute_intent(raw: &str) -> Option<Intent> {
    // Must look like it contains an execute intent.
    if !raw.contains("execute") {
        return None;
    }

    // Known tool names — try to find one in the raw text.
    const TOOLS: &[&str] = &[
        "chain_query",
        "system_status",
        "governance_posture",
        "model_evaluate",
        "batch_sign",
        "chain_compact",
        "browser_use",
        "self_configure",
        "memory_list",
        "memory_review",
    ];

    for tool in TOOLS {
        if raw.contains(tool) {
            warn!(
                tool,
                raw_preview = &raw[..raw.len().min(120)],
                "parse_intent: recovered execute intent from malformed JSON"
            );
            return Some(Intent::Execute {
                tool: tool.to_string(),
                params: serde_json::Value::Object(serde_json::Map::new()),
            });
        }
    }

    None
}

/// Sanitize a tool name extracted from parsed JSON.
///
/// qwen3:1.7b sometimes produces valid JSON where the `tool` field contains
/// embedded params with escaped quotes:
///   `chain_query","params":{"limit":5}}`
///
/// This function checks if the raw tool value starts with a known tool name
/// and extracts just the name. If the garbage after the name looks like
/// embedded params, it attempts to recover those too.
///
/// Returns (sanitized_tool_name, optional_recovered_params).
fn sanitize_tool_name(raw: &str) -> (String, Option<serde_json::Value>) {
    const TOOLS: &[&str] = &[
        "chain_query",
        "system_status",
        "governance_posture",
        "model_evaluate",
        "batch_sign",
        "chain_compact",
        "browser_use",
        "self_configure",
        "memory_list",
        "memory_review",
    ];

    for tool in TOOLS {
        if raw.starts_with(tool) {
            if raw.len() == tool.len() {
                // Exact match — no sanitization needed.
                return (raw.to_string(), None);
            }

            // Tool name is a prefix of the raw value — there's garbage after it.
            // Try to extract params from the garbage.
            let remainder = &raw[tool.len()..];

            // Common pattern: `","params":{"limit":5}}` or `", "params": ...`
            // Try to find a JSON object in the remainder.
            if let Some(brace_start) = remainder.find('{') {
                let params_candidate = &remainder[brace_start..];
                if let Ok(params) = serde_json::from_str::<serde_json::Value>(params_candidate) {
                    // Successfully recovered params from the tool string.
                    debug!(
                        tool,
                        recovered_params = %params,
                        "sanitize_tool_name: recovered embedded params"
                    );
                    return (tool.to_string(), Some(params));
                }
            }

            // Couldn't recover params — just return the clean tool name.
            return (tool.to_string(), None);
        }
    }

    // Not a known tool prefix — return as-is.
    (raw.to_string(), None)
}

/// Strip markdown code fences from a model response.
///
/// Models often wrap JSON in ```json ... ``` blocks. This removes them
/// so the JSON parser sees clean input.
pub fn strip_markdown_fences(s: &str) -> &str {
    let trimmed = s.trim();

    // Check for ```json or ``` prefix.
    let without_prefix = if trimmed.starts_with("```json") {
        &trimmed[7..]
    } else if trimmed.starts_with("```") {
        &trimmed[3..]
    } else {
        return trimmed;
    };

    // Remove trailing ```.
    let without_suffix = if without_prefix.trim_end().ends_with("```") {
        let end = without_prefix.trim_end();
        &end[..end.len() - 3]
    } else {
        without_prefix
    };

    without_suffix.trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_execute_intent() {
        let json = r#"{"intent": "execute", "tool": "chain_query", "params": {"limit": 5}}"#;
        let intent = parse_intent(json).unwrap();
        match intent {
            Intent::Execute { tool, params } => {
                assert_eq!(tool, "chain_query");
                assert_eq!(params["limit"], 5);
            }
            other => panic!("expected Execute, got {:?}", other),
        }
    }

    #[test]
    fn parse_respond_intent() {
        let json = r#"{"intent": "respond", "content": "hello operator"}"#;
        let intent = parse_intent(json).unwrap();
        match intent {
            Intent::Respond { content, .. } => {
                assert_eq!(content, "hello operator");
            }
            other => panic!("expected Respond, got {:?}", other),
        }
    }

    #[test]
    fn parse_with_markdown_fences() {
        let fenced = "```json\n{\"intent\": \"observe\", \"content\": \"all quiet\"}\n```";
        let intent = parse_intent(fenced).unwrap();
        match intent {
            Intent::Observe { observation } => {
                assert_eq!(observation, "all quiet");
            }
            other => panic!("expected Observe, got {:?}", other),
        }
    }

    #[test]
    fn parse_plain_text_falls_through() {
        let text = "I don't have enough context to answer that question.";
        let intent = parse_intent(text).unwrap();
        match intent {
            Intent::Respond { content, .. } => {
                assert_eq!(content, text);
            }
            other => panic!("expected Respond fallthrough, got {:?}", other),
        }
    }

    #[test]
    fn strip_fences_json() {
        assert_eq!(
            strip_markdown_fences("```json\n{\"a\": 1}\n```"),
            "{\"a\": 1}"
        );
    }

    #[test]
    fn strip_fences_plain() {
        assert_eq!(
            strip_markdown_fences("```\n{\"a\": 1}\n```"),
            "{\"a\": 1}"
        );
    }

    #[test]
    fn strip_fences_none() {
        assert_eq!(strip_markdown_fences("{\"a\": 1}"), "{\"a\": 1}");
    }
}
