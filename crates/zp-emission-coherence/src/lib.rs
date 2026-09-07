//! zp-emission-coherence — Regent emission-coherence heuristics.
//!
//! Implements Heuristics 1–3 and composition/response-class logic per
//! `docs/design/REGENT-DOOM-LOOP-DETECTION-2026-07.md` (Class 8 of the
//! Cognitive Self-Observer catalog — post-emission structural check for
//! SLM doom-loop signatures).
//!
//! # Scope
//!
//! - **H1: N-gram repetition density** — implemented. Deterministic;
//!   no state needed; O(L·n).
//! - **H2: Response length distribution collapse** — implemented. Needs
//!   a rolling window (default N=20) of prior response lengths, held on
//!   [`EmissionAnalyzer`].
//! - **H3: Token entropy anomaly** — implemented. Requires per-token
//!   log-probability of the chosen token (most local backends expose
//!   this — Ollama, MLX, llama.cpp). Needs a baseline entropy from the
//!   model dossier; without one, this heuristic is skipped.
//! - **H4–H8** — not implemented in this crate. H4 needs an embedding
//!   backend; H5 needs per-model reasoning-trace parsing; H6–H8 need
//!   Cartographer materialization + officer runtime + baseline cycles
//!   per the doc's chronic-drift addendum. Land them as follow-on work.
//!
//! # Substrate integration
//!
//! This crate stops at typed [`Outcome`] values. Substrate-side, the
//! conversion to `zp_receipt::Receipt` is straightforward: the
//! `receipt_family` field on the outcome maps directly to the receipt
//! type key (`regent:emission:doom_loop_flagged` etc.), and `findings`
//! maps to per-heuristic evidence extensions under
//! `zp.emission.coherence.*`.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

mod entropy;
mod length;
mod ngram;

pub use entropy::token_entropy_anomaly;
pub use length::length_distribution_collapse;
pub use ngram::ngram_repetition_density;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One Regent response, in the shape emission-coherence heuristics consume.
#[derive(Debug, Clone)]
pub struct Response<'a> {
    /// Chain-anchored cycle identifier.
    pub cycle_id: &'a str,
    /// Model identifier (e.g., "qwen3:8b"). Used for baseline lookup and
    /// propagated onto receipts.
    pub model: &'a str,
    /// The output tokens the model produced.
    pub token_ids: &'a [u32],
    /// The decoded response text (for n-gram analysis at word granularity
    /// as well as token). Some heuristics prefer text; some prefer tokens.
    pub text: &'a str,
    /// Per-token log-probability of the CHOSEN token (not the full
    /// distribution). `-log P(t | context)` is the standard interpretation.
    /// When present and paired with a baseline, H3 fires. When absent, H3
    /// is skipped for this response.
    pub log_probs: Option<&'a [f64]>,
    /// Sampling parameters the response was produced under. Propagated
    /// onto the receipt for reproducibility.
    pub sampling_params: SamplingParams,
}

/// Sampling parameters used when the response was generated.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SamplingParams {
    pub temperature: f64,
    pub top_p: f64,
    pub seed: Option<u64>,
}

/// Severity of a heuristic firing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Heuristic flagged but signal is weak — R0 territory.
    Warning,
    /// Heuristic flagged with strong signal — R1/R2 territory.
    Critical,
}

/// Names of the heuristics. Serialized as snake_case strings that match
/// the doc's canonical labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeuristicName {
    /// H1
    NgramRepetitionDensity,
    /// H2
    ResponseLengthCollapse,
    /// H3
    TokenEntropyAnomaly,
    /// H4 (not implemented in this crate)
    PrecedentContextDegeneration,
    /// H5 (not implemented in this crate)
    ReasoningStepStagnation,
    /// H6 (not implemented in this crate)
    LexicalDiversityDrop,
    /// H7 (not implemented in this crate)
    StructuralVarianceCollapse,
    /// H8 (not implemented in this crate)
    BoilerplateCreep,
}

/// A single heuristic firing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub name: HeuristicName,
    pub severity: Severity,
    /// Heuristic-specific evidence, ready to inline under
    /// `zp.emission.coherence.<heuristic>.evidence` on the receipt.
    pub evidence: serde_json::Value,
}

/// Substrate response class per REGENT-DOOM-LOOP-DETECTION Part III.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseClass {
    /// R0 — log and continue. Single-heuristic single-response flag.
    LogAndContinue,
    /// R1 — retry with adjusted sampling. Two-heuristic composed OR
    /// single-heuristic window pattern.
    RetryAdjustedSampling,
    /// R2 — escalate. R1 retry also flagged, or two-heuristic composed
    /// across window, or reasoning-step-stagnation flag (H5 — not fired
    /// by this crate but the classification supports it if a caller
    /// injects a H5 finding).
    Escalate,
}

/// Receipt family this outcome maps to.
///
/// The substrate-side integration converts these to `zp_receipt::Receipt`
/// with matching `receipt_type` values. Naming matches
/// REGENT-DOOM-LOOP-DETECTION §"Receipt shapes".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptFamily {
    /// `regent:emission:doom_loop_flagged` — R0 case.
    DoomLoopFlagged,
    /// `regent:emission:doom_loop_suspected` — R1 case.
    DoomLoopSuspected,
    /// `regent:emission:doom_loop_confirmed` — R2 case.
    DoomLoopConfirmed,
    /// No signal — no receipt emitted.
    None,
}

impl ReceiptFamily {
    /// The canonical receipt-type string used by the substrate.
    pub fn receipt_type(self) -> Option<&'static str> {
        match self {
            ReceiptFamily::DoomLoopFlagged => Some("regent:emission:doom_loop_flagged"),
            ReceiptFamily::DoomLoopSuspected => Some("regent:emission:doom_loop_suspected"),
            ReceiptFamily::DoomLoopConfirmed => Some("regent:emission:doom_loop_confirmed"),
            ReceiptFamily::None => None,
        }
    }
}

/// The result of analyzing one response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub cycle_id: String,
    pub model: String,
    pub findings: Vec<Finding>,
    pub response_class: ResponseClass,
    pub receipt_family: ReceiptFamily,
    /// True if the response should be delivered to the operator surface.
    /// R0 delivers (false-positive risk); R1/R2 do not.
    pub deliverable: bool,
    /// Sampling adjustment recommended for the R1 retry, if applicable.
    /// Callers use this on the retry to actually vary the parameters.
    pub retry_sampling_adjustment: Option<SamplingAdjustment>,
}

/// Sampling-parameter deltas for R1 retry per the doc:
/// "temperature += 0.15, top_p += 0.05, and n-gram-repetition penalty
/// enabled at the sampling layer."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingAdjustment {
    pub delta_temperature: f64,
    pub delta_top_p: f64,
    pub enable_ngram_repetition_penalty: bool,
}

impl Default for SamplingAdjustment {
    fn default() -> Self {
        Self {
            delta_temperature: 0.15,
            delta_top_p: 0.05,
            enable_ngram_repetition_penalty: true,
        }
    }
}

// ---------------------------------------------------------------------------
// EmissionAnalyzer — stateful, holds rolling window for H2 and entropy
// baselines for H3.
// ---------------------------------------------------------------------------

/// Configuration for the [`EmissionAnalyzer`].
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Rolling window size for H2 (length-distribution collapse).
    /// Default: 20 per the doc.
    pub length_window_size: usize,
    /// Coefficient-of-variation threshold below which H2 fires.
    /// Default: 0.15 per the doc.
    pub length_cv_threshold: f64,
    /// Baseline entropy per model. Populated from the model dossier's
    /// `entropy_baseline` field. If a model has no entry here, H3 is
    /// skipped for that model.
    pub entropy_baselines: std::collections::HashMap<String, EntropyBaseline>,
    /// If true, treat single R1 as R2 (for testing / adversarial modes).
    pub escalate_r1_to_r2: bool,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            length_window_size: 20,
            length_cv_threshold: 0.15,
            entropy_baselines: std::collections::HashMap::new(),
            escalate_r1_to_r2: false,
        }
    }
}

/// Per-model entropy baseline the H3 heuristic compares against.
#[derive(Debug, Clone, Copy)]
pub struct EntropyBaseline {
    /// Mean per-token surprise = mean(-log P(chosen)) over the calibration
    /// battery. Populated in the model dossier's `entropy_baseline` field.
    pub mean: f64,
    /// Standard deviation of the calibration battery.
    pub std_dev: f64,
}

/// Stateful analyzer that holds rolling windows and entropy baselines.
pub struct EmissionAnalyzer {
    config: AnalyzerConfig,
    length_window: VecDeque<usize>,
}

impl EmissionAnalyzer {
    pub fn new(config: AnalyzerConfig) -> Self {
        let cap = config.length_window_size;
        Self {
            config,
            length_window: VecDeque::with_capacity(cap),
        }
    }

    /// Analyze one response. Updates internal state. Returns an [`Outcome`]
    /// with findings, response class, and receipt family.
    pub fn analyze(&mut self, response: &Response) -> Outcome {
        let mut findings: Vec<Finding> = Vec::new();

        // H1 — n-gram repetition density (stateless).
        if let Some(f) = ngram_repetition_density(response.text, response.token_ids) {
            findings.push(f);
        }

        // H2 — length distribution collapse. Push this response's length
        // into the rolling window, then evaluate against the (now-including)
        // window.
        self.push_length(response.token_ids.len());
        if let Some(f) = length_distribution_collapse(
            &self.length_window,
            self.config.length_cv_threshold,
            self.config.length_window_size,
        ) {
            findings.push(f);
        }

        // H3 — token entropy anomaly. Requires log_probs on the response
        // AND a baseline for this model.
        if let (Some(log_probs), Some(baseline)) = (
            response.log_probs,
            self.config.entropy_baselines.get(response.model),
        ) {
            if let Some(f) = token_entropy_anomaly(log_probs, baseline) {
                findings.push(f);
            }
        }

        let (response_class, receipt_family, deliverable, retry_adj) =
            classify(&findings, self.config.escalate_r1_to_r2);

        Outcome {
            cycle_id: response.cycle_id.to_string(),
            model: response.model.to_string(),
            findings,
            response_class,
            receipt_family,
            deliverable,
            retry_sampling_adjustment: retry_adj,
        }
    }

    fn push_length(&mut self, len: usize) {
        while self.length_window.len() >= self.config.length_window_size {
            self.length_window.pop_front();
        }
        self.length_window.push_back(len);
    }

    /// Read-only view of the current length window (for tests / debugging).
    pub fn length_window(&self) -> &VecDeque<usize> {
        &self.length_window
    }
}

// ---------------------------------------------------------------------------
// Composition — REGENT-DOOM-LOOP-DETECTION §Part II "Composed signal"
// and §Part III "Response classes".
// ---------------------------------------------------------------------------

fn classify(
    findings: &[Finding],
    escalate_r1_to_r2: bool,
) -> (
    ResponseClass,
    ReceiptFamily,
    bool,
    Option<SamplingAdjustment>,
) {
    if findings.is_empty() {
        return (
            ResponseClass::LogAndContinue,
            ReceiptFamily::None,
            true,
            None,
        );
    }

    // H5 (reasoning-step stagnation) is an auto-escalate per doc even
    // when it's the only finding. This crate doesn't fire H5 itself, but
    // callers may inject a H5 finding — respect it here.
    let has_h5 = findings
        .iter()
        .any(|f| f.name == HeuristicName::ReasoningStepStagnation);
    if has_h5 {
        return (
            ResponseClass::Escalate,
            ReceiptFamily::DoomLoopConfirmed,
            false,
            None,
        );
    }

    // Two-heuristic composed OR single-heuristic window-pattern → R1.
    // This crate can only observe per-response findings; the "window
    // pattern" case for H2 is expressed by H2 firing on the rolling
    // window (which by construction spans multiple cycles). So the
    // rule collapses to: 2+ findings → R1, single finding → R0.
    let acute_finding_count = findings
        .iter()
        .filter(|f| {
            matches!(
                f.name,
                HeuristicName::NgramRepetitionDensity
                    | HeuristicName::ResponseLengthCollapse
                    | HeuristicName::TokenEntropyAnomaly
                    | HeuristicName::PrecedentContextDegeneration
                    | HeuristicName::ReasoningStepStagnation
            )
        })
        .count();

    if acute_finding_count >= 2 {
        let class = if escalate_r1_to_r2 {
            ResponseClass::Escalate
        } else {
            ResponseClass::RetryAdjustedSampling
        };
        let family = if class == ResponseClass::Escalate {
            ReceiptFamily::DoomLoopConfirmed
        } else {
            ReceiptFamily::DoomLoopSuspected
        };
        let retry = if class == ResponseClass::RetryAdjustedSampling {
            Some(SamplingAdjustment::default())
        } else {
            None
        };
        return (class, family, false, retry);
    }

    // Single finding — R0 (log and continue, deliver).
    (
        ResponseClass::LogAndContinue,
        ReceiptFamily::DoomLoopFlagged,
        true,
        None,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn resp<'a>(model: &'a str, text: &'a str, tokens: &'a [u32]) -> Response<'a> {
        Response {
            cycle_id: "test",
            model,
            token_ids: tokens,
            text,
            log_probs: None,
            sampling_params: SamplingParams::default(),
        }
    }

    #[test]
    fn clean_response_no_findings() {
        let mut a = EmissionAnalyzer::new(AnalyzerConfig::default());
        let text = "The quick brown fox jumps over the lazy dog. This is a normal response with reasonable content and no repetition.";
        let tokens: Vec<u32> = (1..=25).collect();
        let out = a.analyze(&resp("qwen3:8b", text, &tokens));
        assert!(out.findings.is_empty());
        assert_eq!(out.response_class, ResponseClass::LogAndContinue);
        assert_eq!(out.receipt_family, ReceiptFamily::None);
        assert!(out.deliverable);
    }

    #[test]
    fn single_h1_flag_is_r0() {
        let mut a = EmissionAnalyzer::new(AnalyzerConfig::default());
        // 8-gram that repeats — will trip H1 immediately.
        let piece = "the quick brown fox jumps over the lazy ";
        let mut text = String::new();
        for _ in 0..3 {
            text.push_str(piece);
        }
        let tokens: Vec<u32> = (1..=50).collect();
        let out = a.analyze(&resp("qwen3:8b", &text, &tokens));
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.response_class, ResponseClass::LogAndContinue);
        assert_eq!(out.receipt_family, ReceiptFamily::DoomLoopFlagged);
        assert!(out.deliverable);
    }

    #[test]
    fn two_findings_compose_to_r1() {
        // Prime the length window to a highly-collapsed state (all 100)
        // then push one more response that also trips H1.
        let mut a = EmissionAnalyzer::new(AnalyzerConfig::default());
        for _ in 0..19 {
            let tokens: Vec<u32> = (1..=100).collect();
            a.analyze(&resp("qwen3:8b", "a b c d e", &tokens));
        }
        let piece = "the quick brown fox jumps over the lazy ";
        let mut text = String::new();
        for _ in 0..3 {
            text.push_str(piece);
        }
        let tokens: Vec<u32> = (1..=100).collect();
        let out = a.analyze(&resp("qwen3:8b", &text, &tokens));
        assert!(out.findings.len() >= 2);
        assert_eq!(out.response_class, ResponseClass::RetryAdjustedSampling);
        assert_eq!(out.receipt_family, ReceiptFamily::DoomLoopSuspected);
        assert!(!out.deliverable);
        assert!(out.retry_sampling_adjustment.is_some());
    }

    #[test]
    fn h3_fires_with_baseline_and_low_entropy() {
        let mut cfg = AnalyzerConfig::default();
        cfg.entropy_baselines.insert(
            "qwen3:8b".to_string(),
            EntropyBaseline {
                mean: 2.0,
                std_dev: 0.5,
            },
        );
        let mut a = EmissionAnalyzer::new(cfg);
        // Log-probs near zero mean model was very confident about every
        // token — mean(-log_p) near zero is well below baseline.
        let log_probs: Vec<f64> = vec![-0.01; 50];
        let response = Response {
            cycle_id: "test",
            model: "qwen3:8b",
            token_ids: &(1..=50).collect::<Vec<u32>>(),
            text: "some content",
            log_probs: Some(&log_probs),
            sampling_params: SamplingParams::default(),
        };
        let out = a.analyze(&response);
        assert!(out
            .findings
            .iter()
            .any(|f| f.name == HeuristicName::TokenEntropyAnomaly));
    }

    #[test]
    fn h5_alone_forces_r2() {
        let findings = vec![Finding {
            name: HeuristicName::ReasoningStepStagnation,
            severity: Severity::Critical,
            evidence: serde_json::json!({}),
        }];
        let (class, family, deliverable, _) = classify(&findings, false);
        assert_eq!(class, ResponseClass::Escalate);
        assert_eq!(family, ReceiptFamily::DoomLoopConfirmed);
        assert!(!deliverable);
    }

    #[test]
    fn escalate_r1_to_r2_mode() {
        let findings = vec![
            Finding {
                name: HeuristicName::NgramRepetitionDensity,
                severity: Severity::Critical,
                evidence: serde_json::json!({}),
            },
            Finding {
                name: HeuristicName::TokenEntropyAnomaly,
                severity: Severity::Critical,
                evidence: serde_json::json!({}),
            },
        ];
        let (class, family, deliverable, retry) = classify(&findings, true);
        assert_eq!(class, ResponseClass::Escalate);
        assert_eq!(family, ReceiptFamily::DoomLoopConfirmed);
        assert!(!deliverable);
        assert!(retry.is_none());
    }
}
