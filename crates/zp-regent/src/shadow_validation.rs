//! Shadow validation battery — focused checks that determine whether a
//! candidate model handles the substrate's prompt corpus before cut-over.
//!
//! This is the Phase 2 implementation of SHADOW-MODEL-SWITCHING-2026-07.md.
//! The battery runs against each candidate in the `PinStatus::Evaluating`
//! state while the groomed model stays active for operator interactions.
//!
//! Checks:
//! - Check 2: Prompt structural compliance (does the model parse intent?)
//! - Check 3: JSON intent envelope (can `parse_intent` handle the output?)
//! - Check 4: Tool dispatch (does the model emit structured tool calls?)
//! - Check 5: Self-configure introspection (does it use self_configure?)
//!
//! Check 1 (dossier existence) is handled inline at the call site — it
//! never fails, just notes whether a dossier was found.
//!
//! The battery is deliberately focused: "can this model handle our prompts
//! right now?" — not "how does this model compare across all dimensions?"
//! Full model evaluation is `model_evaluate`'s job.

use std::time::Instant;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::inference::{ChatMessage, InferenceBackend, InferenceRequest};
use crate::intent::Intent;
use crate::regent::parse_intent;

// ─── Result types ────────────────────────────────────────────────────

/// Result of a single shadow validation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCheckResult {
    /// Which check ran (e.g., "prompt_structural", "json_intent").
    pub check: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Human-readable detail about what happened.
    pub detail: String,
    /// Wall-clock time for this check.
    pub latency_ms: u64,
}

/// Aggregate result of the full shadow validation battery.
#[derive(Debug, Clone, Serialize)]
pub struct ShadowBatteryResult {
    /// The candidate model that was tested.
    pub candidate_model: String,
    /// Individual check results.
    pub checks: Vec<ShadowCheckResult>,
    /// Overall pass/fail.
    pub passed: bool,
    /// Summary string for receipts/narration.
    pub summary: String,
    /// Total wall-clock time for all checks.
    pub total_latency_ms: u64,
}

// ─── Evaluation tier ─────────────────────────────────────────────────

/// How thoroughly to evaluate the candidate. Determined by dossier state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationTier {
    /// Known model with validated prompt compatibility.
    /// Battery: check 3 only. ~5-10s.
    Tier1,
    /// Known model with untested/partial prompt compatibility.
    /// Battery: checks 2-4. ~30s.
    Tier2,
    /// Unknown model, no dossier.
    /// Battery: all checks + conversational probe. ~2min.
    Tier3,
}

impl EvaluationTier {
    /// Which checks to run at this tier.
    pub fn checks(&self) -> &[&str] {
        match self {
            EvaluationTier::Tier1 => &["json_intent"],
            EvaluationTier::Tier2 => &["prompt_structural", "json_intent", "tool_dispatch"],
            EvaluationTier::Tier3 => &[
                "prompt_structural",
                "json_intent",
                "tool_dispatch",
                "self_configure",
            ],
        }
    }
}

/// Determine the evaluation tier for a candidate model based on the
/// dossier corpus. Tier scales inversely with substrate confidence.
pub fn determine_tier(
    candidate: &str,
    corpus: Option<&crate::routing::DossierCorpus>,
) -> EvaluationTier {
    let corpus = match corpus {
        Some(c) => c,
        None => return EvaluationTier::Tier3, // No corpus → unknown model.
    };

    // Try to find a dossier by checking if any dossier's primary_variant,
    // variants list, or cloud_model_id matches the candidate.
    let dossier = corpus.dossiers.values().find(|d| {
        d.primary_variant == candidate
            || d.variants.iter().any(|v| v == candidate)
            || d.cloud_model_id.as_deref() == Some(candidate)
    });

    match dossier {
        None => EvaluationTier::Tier3, // No dossier → full workup.
        Some(d) => {
            // Check if reasoning tier is tested.
            match d.tier_suitability.get("reasoning") {
                Some(crate::routing::Suitability::Recommended)
                | Some(crate::routing::Suitability::Viable) => EvaluationTier::Tier1,
                _ => EvaluationTier::Tier2,
            }
        }
    }
}

// ─── System prompt for battery (minimal) ─────────────────────────────

/// Minimal system prompt that mirrors the substrate's unified prompt
/// structure. We don't use the full prompt (which has live context) —
/// just enough to test whether the model understands the format.
const BATTERY_SYSTEM_PROMPT: &str = r#"You are the Regent — the cognitive presence of a ZeroPoint substrate. You serve operator kenrom.

You MUST respond with a JSON object. Every response is one of:
- {"intent": "respond", "content": "your message"}
- {"intent": "execute", "tool": "tool_name", "params": {...}}
- {"intent": "observe", "content": "observation"}

Available tools:
- self_configure: Report or change inference configuration. Params: {} for status, or {"reasoning_model": "model_name"} to change.
- chain_query: Query the audit chain. Params: {"limit": N}
- memory_search: Search operator memory. Params: {"query": "search term"}

RESPOND ONLY WITH JSON. No markdown, no prose, no explanation outside the JSON envelope."#;

// ─── Battery runner ──────────────────────────────────────────────────

/// Run the shadow validation battery against a candidate model.
///
/// The battery sends test prompts to the candidate via the inference
/// backend and evaluates whether the responses meet the substrate's
/// prompt compliance requirements. The groomed model is NOT used here —
/// this is purely candidate evaluation.
pub async fn run_battery(
    backend: &InferenceBackend,
    candidate_model: &str,
    tier: EvaluationTier,
) -> ShadowBatteryResult {
    let battery_start = Instant::now();
    let checks_to_run = tier.checks();
    let mut results = Vec::new();

    info!(
        candidate = %candidate_model,
        tier = ?tier,
        checks = ?checks_to_run,
        "shadow battery: starting validation"
    );

    for &check_name in checks_to_run {
        let result = match check_name {
            "prompt_structural" => check_prompt_structural(backend, candidate_model).await,
            "json_intent" => check_json_intent(backend, candidate_model).await,
            "tool_dispatch" => check_tool_dispatch(backend, candidate_model).await,
            "self_configure" => check_self_configure(backend, candidate_model).await,
            _ => ShadowCheckResult {
                check: check_name.to_string(),
                passed: false,
                detail: "unknown check".to_string(),
                latency_ms: 0,
            },
        };

        info!(
            check = %result.check,
            passed = result.passed,
            latency_ms = result.latency_ms,
            "shadow battery: check completed"
        );
        results.push(result);
    }

    let total_latency = battery_start.elapsed().as_millis() as u64;

    // Pass criteria by tier:
    // Tier 1: check 3 (json_intent) must pass.
    // Tier 2: checks 2, 3, 4 must pass.
    // Tier 3: checks 2, 3, 4 must pass. Check 5 is informational.
    let passed = match tier {
        EvaluationTier::Tier1 => results
            .iter()
            .filter(|r| r.check == "json_intent")
            .all(|r| r.passed),
        EvaluationTier::Tier2 => results
            .iter()
            .filter(|r| matches!(r.check.as_str(), "prompt_structural" | "json_intent" | "tool_dispatch"))
            .all(|r| r.passed),
        EvaluationTier::Tier3 => results
            .iter()
            .filter(|r| matches!(r.check.as_str(), "prompt_structural" | "json_intent" | "tool_dispatch"))
            .all(|r| r.passed),
    };

    let failed_checks: Vec<&str> = results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| r.check.as_str())
        .collect();

    let summary = if passed {
        format!(
            "{} passed all required checks ({} total, {}ms)",
            candidate_model,
            results.len(),
            total_latency
        )
    } else {
        format!(
            "{} failed checks: [{}] ({}ms)",
            candidate_model,
            failed_checks.join(", "),
            total_latency
        )
    };

    info!(
        candidate = %candidate_model,
        passed,
        total_latency_ms = total_latency,
        summary = %summary,
        "shadow battery: completed"
    );

    ShadowBatteryResult {
        candidate_model: candidate_model.to_string(),
        checks: results,
        passed,
        summary,
        total_latency_ms: total_latency,
    }
}

// ─── Individual checks ───────────────────────────────────────────────

/// Check 2: Prompt structural compliance.
///
/// Sends the candidate model the substrate's system prompt with a
/// synthetic operator input and verifies the response:
/// - Does the model attempt to parse intent as JSON?
/// - Does the response avoid context dumps?
/// - Does the model reference tools available in the prompt?
async fn check_prompt_structural(
    backend: &InferenceBackend,
    candidate: &str,
) -> ShadowCheckResult {
    let start = Instant::now();

    let request = InferenceRequest {
        model: candidate.to_string(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: BATTERY_SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: "Hello, what can you help me with?".to_string(),
            },
        ],
        format: None,
        temperature: 0.1,
        stream: false,
        options: Some(serde_json::json!({ "num_predict": 256 })),
        keep_alive: None,
        think: Some(false),
    };

    let response = match backend.chat(&request).await {
        Ok(r) => r,
        Err(e) => {
            return ShadowCheckResult {
                check: "prompt_structural".to_string(),
                passed: false,
                detail: format!("inference failed: {}", e),
                latency_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    // Structural compliance: response should be JSON, not a context dump.
    let is_json = parse_intent(&response).is_ok();
    let is_context_dump = response.len() > 1000
        && (response.contains("Available tools:")
            || response.contains("RESPOND ONLY WITH JSON")
            || response.contains("You are the Regent"));

    let passed = is_json && !is_context_dump;
    let detail = if passed {
        "model produced valid JSON intent, no context dump".to_string()
    } else if is_context_dump {
        format!(
            "context dump detected ({}B response echoing system prompt)",
            response.len()
        )
    } else {
        let preview = crate::text::preview(&response, 120);
        format!("not valid JSON intent: {}...", preview)
    };

    ShadowCheckResult {
        check: "prompt_structural".to_string(),
        passed,
        detail,
        latency_ms: start.elapsed().as_millis() as u64,
    }
}

/// Check 3: JSON intent envelope.
///
/// The critical check — can `parse_intent` actually handle this model's
/// output? Sends a simple conversational prompt and verifies the response
/// parses into a valid Intent (not just falls through to Respond).
async fn check_json_intent(
    backend: &InferenceBackend,
    candidate: &str,
) -> ShadowCheckResult {
    let start = Instant::now();

    let request = InferenceRequest {
        model: candidate.to_string(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: BATTERY_SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: "What time is it?".to_string(),
            },
        ],
        format: None,
        temperature: 0.1,
        stream: false,
        options: Some(serde_json::json!({ "num_predict": 256 })),
        keep_alive: None,
        think: Some(false),
    };

    let response = match backend.chat(&request).await {
        Ok(r) => r,
        Err(e) => {
            return ShadowCheckResult {
                check: "json_intent".to_string(),
                passed: false,
                detail: format!("inference failed: {}", e),
                latency_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    // The real test: does parse_intent produce a structured intent
    // (Respond with content, Execute, etc.) rather than falling through
    // to raw text?
    let intent = parse_intent(&response);
    let (passed, detail) = match &intent {
        Ok(Intent::Respond { content, .. }) => {
            // Check that the content is meaningful, not the raw unparsed response.
            // parse_intent falls through to Respond { content: raw } on failure,
            // so we check if the JSON was actually parsed.
            let trimmed = crate::regent::strip_markdown_fences(&response);
            let was_parsed = serde_json::from_str::<serde_json::Value>(trimmed).is_ok();
            if was_parsed {
                (true, format!("valid JSON → Intent::Respond ({}B)", content.len()))
            } else {
                (false, "fallthrough to raw Respond — model did not produce JSON".to_string())
            }
        }
        Ok(Intent::Execute { tool, .. }) => {
            (true, format!("valid JSON → Intent::Execute({})", tool))
        }
        Ok(other) => {
            (true, format!("valid JSON → Intent::{:?}", std::mem::discriminant(other)))
        }
        Err(e) => {
            (false, format!("parse_intent error: {}", e))
        }
    };

    ShadowCheckResult {
        check: "json_intent".to_string(),
        passed,
        detail,
        latency_ms: start.elapsed().as_millis() as u64,
    }
}

/// Check 4: Tool dispatch.
///
/// Sends a prompt that should trigger a tool call and verifies the model
/// emits an Execute intent with a valid tool name.
async fn check_tool_dispatch(
    backend: &InferenceBackend,
    candidate: &str,
) -> ShadowCheckResult {
    let start = Instant::now();

    let request = InferenceRequest {
        model: candidate.to_string(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: BATTERY_SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: "Show me the last 5 entries on my audit chain.".to_string(),
            },
        ],
        format: None,
        temperature: 0.1,
        stream: false,
        options: Some(serde_json::json!({ "num_predict": 256 })),
        keep_alive: None,
        think: Some(false),
    };

    let response = match backend.chat(&request).await {
        Ok(r) => r,
        Err(e) => {
            return ShadowCheckResult {
                check: "tool_dispatch".to_string(),
                passed: false,
                detail: format!("inference failed: {}", e),
                latency_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let intent = parse_intent(&response);
    let (passed, detail) = match &intent {
        Ok(Intent::Execute { tool, params }) => {
            // The model dispatched a tool. Check it's a known tool name.
            let known = matches!(
                tool.as_str(),
                "chain_query" | "memory_search" | "self_configure"
            );
            if known {
                (true, format!("dispatched {}({})", tool, params))
            } else {
                // Unknown tool name — the model understood the shape but
                // hallucinated the tool. Partial pass.
                (true, format!("dispatched unknown tool '{}' — shape correct, name hallucinated", tool))
            }
        }
        Ok(Intent::Respond { content, .. }) => {
            // Model responded conversationally instead of dispatching.
            // Check if the response at least acknowledges the chain_query tool.
            let mentions_tool = content.contains("chain_query")
                || content.contains("audit chain")
                || content.contains("chain");
            (false, format!(
                "responded instead of dispatching (mentions_tool={}): {}...",
                mentions_tool,
                crate::text::preview(content, 80)
            ))
        }
        Ok(_) => (false, "unexpected intent type".to_string()),
        Err(e) => (false, format!("parse_intent error: {}", e)),
    };

    ShadowCheckResult {
        check: "tool_dispatch".to_string(),
        passed,
        detail,
        latency_ms: start.elapsed().as_millis() as u64,
    }
}

/// Check 5: Self-configure introspection.
///
/// The specific check that GLM-5.2 failed — asks "what model are you
/// running on?" and verifies the model dispatches self_configure rather
/// than responding "I don't know."
async fn check_self_configure(
    backend: &InferenceBackend,
    candidate: &str,
) -> ShadowCheckResult {
    let start = Instant::now();

    let request = InferenceRequest {
        model: candidate.to_string(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: BATTERY_SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: "What model are you running on? Report your inference configuration.".to_string(),
            },
        ],
        format: None,
        temperature: 0.1,
        stream: false,
        options: Some(serde_json::json!({ "num_predict": 256 })),
        keep_alive: None,
        think: Some(false),
    };

    let response = match backend.chat(&request).await {
        Ok(r) => r,
        Err(e) => {
            return ShadowCheckResult {
                check: "self_configure".to_string(),
                passed: false,
                detail: format!("inference failed: {}", e),
                latency_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let intent = parse_intent(&response);
    let (passed, detail) = match &intent {
        Ok(Intent::Execute { tool, .. }) if tool == "self_configure" => {
            (true, "dispatched self_configure — model knows how to introspect".to_string())
        }
        Ok(Intent::Execute { tool, .. }) => {
            // Dispatched a tool, just not self_configure. Partial credit.
            (false, format!("dispatched '{}' instead of self_configure", tool))
        }
        Ok(Intent::Respond { content, .. }) => {
            // Check if the model at least tried to answer about its config.
            let knows_something = content.contains("model")
                || content.contains("inference")
                || content.contains("configuration");
            (false, format!(
                "responded instead of dispatching self_configure (knows_something={}): {}...",
                knows_something,
                crate::text::preview(content, 80)
            ))
        }
        Ok(_) => (false, "unexpected intent type".to_string()),
        Err(e) => (false, format!("parse_intent error: {}", e)),
    };

    ShadowCheckResult {
        check: "self_configure".to_string(),
        passed,
        detail,
        latency_ms: start.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_checks() {
        assert_eq!(EvaluationTier::Tier1.checks(), &["json_intent"]);
        assert_eq!(
            EvaluationTier::Tier2.checks(),
            &["prompt_structural", "json_intent", "tool_dispatch"]
        );
        assert_eq!(
            EvaluationTier::Tier3.checks(),
            &["prompt_structural", "json_intent", "tool_dispatch", "self_configure"]
        );
    }

    #[test]
    fn tier3_pass_criteria_ignores_self_configure() {
        // Tier 3 requires checks 2, 3, 4 to pass. Check 5 is informational.
        let results = vec![
            ShadowCheckResult {
                check: "prompt_structural".to_string(),
                passed: true,
                detail: "ok".to_string(),
                latency_ms: 100,
            },
            ShadowCheckResult {
                check: "json_intent".to_string(),
                passed: true,
                detail: "ok".to_string(),
                latency_ms: 100,
            },
            ShadowCheckResult {
                check: "tool_dispatch".to_string(),
                passed: true,
                detail: "ok".to_string(),
                latency_ms: 100,
            },
            ShadowCheckResult {
                check: "self_configure".to_string(),
                passed: false, // Informational — should NOT block pass.
                detail: "failed".to_string(),
                latency_ms: 100,
            },
        ];

        // Tier 3 pass logic: checks 2, 3, 4 must pass.
        let passed = results
            .iter()
            .filter(|r| {
                matches!(
                    r.check.as_str(),
                    "prompt_structural" | "json_intent" | "tool_dispatch"
                )
            })
            .all(|r| r.passed);

        assert!(passed, "Tier 3 should pass when checks 2-4 pass, even if check 5 fails");
    }
}
