//! Layer 2 substrate-side inference classifier per
//! `docs/design/INFERENCE-ROUTING-DISCIPLINE-2026-07.md`.
//!
//! The classifier consumes an operator-declared **inference envelope** (a
//! chain-anchored set of authorized models per that spec's Layer 2
//! discipline) and picks which model to invoke for a given query. Every
//! decision is captured as a [`ClassifierDecision`] value ready for
//! chain-anchoring as a `regent:inference:classifier_decision:<decision_id>`
//! receipt per §"Layer 2 — Operator-declared envelope with substrate-side
//! selection".
//!
//! # Scope
//!
//! This module ships the mechanism. Substrate-side integration (calling
//! the classifier from `inference.rs` on every inference request, and
//! emitting the decision receipt via the audit store) is a deliberate
//! follow-on step so the mechanism can land and be exercised in tests
//! before the inference-call path is modified.
//!
//! # Envelope
//!
//! An [`InferenceEnvelope`] declares the substrate-authorized set of
//! models for the current cognitive-work context. Each authorized model
//! carries a [`ModelRole`] — `Primary`, `Fallback`, or `Shadow`. The
//! default classifier picks the first `Primary`, falling through to
//! `Fallback` if no primary is present, and treats `Shadow` entries as
//! observation-only per SHADOW-INFERENCE-COMPARISON-2026-07.
//!
//! First-shipping reality: most envelopes today are single-model. The
//! classifier still runs and still records a decision — evidence
//! accumulates even in the trivial case, which is the foundation for
//! empirical routing once multi-model envelopes become common.
//!
//! # Path note
//!
//! `docs/design/INFERENCE-ROUTING-DISCIPLINE-2026-07.md` names the target
//! path as `crates/zp-regent/src/inference/classifier.rs` (subdirectory
//! layout). The current crate uses flat files (`inference.rs`,
//! `routing.rs`, `intent.rs`); this module honors that convention as
//! `inference_classifier.rs` to avoid restructuring inference.rs today.
//! Later refactor to `inference/classifier.rs` is a doc-side reconciliation.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Envelope — the operator-declared set of authorized models
// ---------------------------------------------------------------------------

/// Role an authorized model plays within an inference envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRole {
    /// Preferred model for the envelope. The classifier chooses `Primary`
    /// first when one is present.
    Primary,
    /// Backup model. Chosen when no `Primary` is authorized (or when a
    /// future fallback-cause is materialized).
    Fallback,
    /// Observation-only model per SHADOW-INFERENCE-COMPARISON. The
    /// classifier never *routes* to a `Shadow` model; shadow evaluation
    /// dispatches to it in parallel via the shadow primitive.
    Shadow,
}

/// One model the operator has authorized for use by the substrate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedModel {
    /// Canonical model identifier — e.g., `"qwen3:8b"`,
    /// `"Qwen/Qwen3-8B"`, `"gpt-5.5-turbo"`. Must match the identifier
    /// used by the inference backend to actually invoke the model.
    pub model_id: String,
    /// Role this authorization plays in the envelope.
    pub role: ModelRole,
    /// Optional dossier reference — `models/<family>/model_dossier.toml`
    /// path or the dossier's canonical id. Populated when the model has
    /// been characterized per MODEL-DOSSIER-2026-07.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dossier_ref: Option<String>,
}

/// The operator-declared envelope of authorized inference paths for the
/// current cognitive-work context. In INFERENCE-ROUTING-DISCIPLINE-2026-07
/// terminology, this is a chain-anchored declaration produced by
/// CloudMandate-composed ceremony.
///
/// First-shipping shape: envelopes are constructed in-process from
/// current config. Operator envelope-declaration ceremony ships later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceEnvelope {
    /// All authorized models in the envelope, in operator-declared order.
    pub authorized_models: Vec<AuthorizedModel>,
    /// Optional receipt id that ratified this envelope, when materialized
    /// from a chain-anchored operator ceremony.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratification_receipt_id: Option<String>,
}

impl InferenceEnvelope {
    /// Construct a trivial envelope containing a single primary model.
    /// This is the shape most inference paths use today, before operator
    /// envelope-declaration ceremony ships.
    pub fn single(model_id: impl Into<String>) -> Self {
        Self {
            authorized_models: vec![AuthorizedModel {
                model_id: model_id.into(),
                role: ModelRole::Primary,
                dossier_ref: None,
            }],
            ratification_receipt_id: None,
        }
    }

    /// Whether this envelope has any authorized model.
    pub fn is_empty(&self) -> bool {
        self.authorized_models.is_empty()
    }

    /// Number of authorized models, excluding shadow-only entries.
    pub fn routable_count(&self) -> usize {
        self.authorized_models
            .iter()
            .filter(|m| m.role != ModelRole::Shadow)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Query hint — what the classifier knows about the query before dispatch
// ---------------------------------------------------------------------------

/// Hints the classifier can consult when choosing a model. All fields are
/// optional; the default classifier ignores them today and picks purely by
/// role. Present here so integrations can populate them incrementally
/// (workload-class inference from prompt, per-model dossier consultation)
/// without changing the classifier's public API.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryHint {
    /// Workload class the prompt appears to belong to. Values match
    /// MODEL-DOSSIER-2026-07's per-workload tracking:
    /// `chat | math | code | reasoning | tool_dispatch | other`.
    pub workload_class: Option<String>,
    /// Approximate prompt length in characters. Very long prompts may
    /// influence context-window fit selection.
    pub prompt_length: Option<usize>,
    /// Free-form label for the calling site (e.g., `"regent:dispatch"`,
    /// `"officer:sweep"`). Used for provenance only, not selection.
    pub caller: Option<String>,
}

// ---------------------------------------------------------------------------
// Decision — the classifier's output, ready for chain-anchoring
// ---------------------------------------------------------------------------

/// Reason the classifier chose a particular model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SelectionReason {
    /// Envelope contained exactly one routable model. Trivial choice.
    SoleAuthorized,
    /// Multi-model envelope, chose the primary.
    Primary,
    /// No primary present; chose a fallback.
    Fallback {
        /// Why the primary wasn't chosen — currently always
        /// `"no_primary_authorized"`. Future values include specific
        /// primary-failure signals.
        cause: String,
    },
    /// Envelope was empty. Classifier returned a decision but the caller
    /// must handle the no-model case — dispatch should not proceed.
    Empty,
}

/// One classifier decision. Serialized shape is what lands on the chain
/// as the `regent:inference:classifier_decision:<decision_id>` receipt
/// event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifierDecision {
    /// UUID for this specific decision — the receipt-type suffix.
    pub decision_id: String,
    /// The model_id that will be invoked. `None` when the envelope was
    /// empty; callers must abort dispatch in that case.
    pub chosen_model: Option<String>,
    /// Size of the envelope the decision was made from.
    pub envelope_size: usize,
    /// Number of routable (non-shadow) options.
    pub routable_count: usize,
    /// Why the classifier picked this model.
    pub selection_reason: SelectionReason,
    /// Query hint the classifier consulted (for provenance).
    pub query_hint: QueryHint,
    /// ISO-8601 UTC timestamp of the decision.
    pub timestamp: String,
}

impl ClassifierDecision {
    /// Canonical receipt-type key for this decision, using the doc's
    /// naming: `regent:inference:classifier_decision:<uuid>`.
    pub fn receipt_type(&self) -> String {
        format!("regent:inference:classifier_decision:{}", self.decision_id)
    }
}

// ---------------------------------------------------------------------------
// Classifier trait + default implementation
// ---------------------------------------------------------------------------

/// The classifier chooses one model from an envelope, producing a
/// chain-anchorable decision. Implementations may consult dossiers,
/// workload hints, per-model empirical evidence, or purely play the role
/// ordering — this trait is the seam that lets policy evolve without
/// touching the call site.
pub trait InferenceClassifier: Send + Sync {
    fn choose(&self, envelope: &InferenceEnvelope, query_hint: &QueryHint) -> ClassifierDecision;
}

/// Default classifier. Deterministic; picks the first `Primary` model,
/// falls back to the first `Fallback` if no primary present, ignores
/// `Shadow` entries. Doesn't consult dossiers, workload hints, or
/// per-model evidence today — those wire in as the substrate accumulates
/// the data to make informed decisions.
pub struct DefaultClassifier;

impl DefaultClassifier {
    pub fn new() -> Self {
        Self
    }

    /// Generate a UUID-shaped decision id without pulling a UUID crate
    /// dep. Uses seconds-since-epoch + a per-process monotonic counter
    /// so ids within a process are unique and roughly ordered.
    fn next_decision_id() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let epoch_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        // Not a real UUID; a distinct-per-decision string in the receipt-
        // key namespace. Substrate integration should substitute a real
        // UUID from the uuid crate when wiring in.
        format!("clf-{epoch_s}-{seq:012x}")
    }

    fn now_utc() -> String {
        // Avoid a chrono dep in the module — the substrate integration
        // will populate this from the same time source the audit store
        // uses. Fall back to unix epoch string.
        let epoch_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("unix:{epoch_s}")
    }
}

impl Default for DefaultClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl InferenceClassifier for DefaultClassifier {
    fn choose(&self, envelope: &InferenceEnvelope, query_hint: &QueryHint) -> ClassifierDecision {
        let envelope_size = envelope.authorized_models.len();
        let routable_count = envelope.routable_count();

        // Filter shadows.
        let routable: Vec<&AuthorizedModel> = envelope
            .authorized_models
            .iter()
            .filter(|m| m.role != ModelRole::Shadow)
            .collect();

        let (chosen, reason) = if routable.is_empty() {
            (None, SelectionReason::Empty)
        } else if routable.len() == 1 {
            (
                Some(routable[0].model_id.clone()),
                SelectionReason::SoleAuthorized,
            )
        } else if let Some(primary) = routable.iter().find(|m| m.role == ModelRole::Primary) {
            (Some(primary.model_id.clone()), SelectionReason::Primary)
        } else {
            // No primary; pick first fallback.
            (
                Some(routable[0].model_id.clone()),
                SelectionReason::Fallback {
                    cause: "no_primary_authorized".to_string(),
                },
            )
        };

        ClassifierDecision {
            decision_id: Self::next_decision_id(),
            chosen_model: chosen,
            envelope_size,
            routable_count,
            selection_reason: reason,
            query_hint: query_hint.clone(),
            timestamp: Self::now_utc(),
        }
    }
}

// ---------------------------------------------------------------------------
// Workload-class inference — heuristic hint for the classifier
// ---------------------------------------------------------------------------

/// Sub-classify a code-classified prompt by scope. Called only from
/// `infer_workload_class` after generic code markers have matched.
///
/// Scope categories (broadest wins):
///   - `code:repo_wide` — repository-level scope keywords
///     ("codebase", "the repo", "whole codebase", "across the project").
///   - `code:multi_file` — two or more distinct file-path-shaped tokens
///     mentioned, OR keywords like "across files" / "these files".
///   - `code:local_transform` — single-file mechanical work keywords
///     ("refactor", "rename", "extract", "convert this").
///   - `code` (catch-all) — no scope signal.
///
/// Scope precedence is broadest-first: a prompt with both a repo-wide
/// keyword and a local-transform verb classifies as `code:repo_wide`.
/// This matches the routing intent — bigger scope wants a bigger-
/// context model regardless of whether the operation itself is
/// mechanically simple.
fn classify_code_scope(original: &str, lower: &str) -> String {
    // repo_wide — strongest scope signal.
    let repo_wide_markers = [
        "codebase",
        "the repo",
        "the repository",
        "whole codebase",
        "entire codebase",
        "across the project",
        "throughout the code",
        "throughout the codebase",
        "every occurrence",
        "everywhere in the",
    ];
    if repo_wide_markers.iter().any(|m| lower.contains(m)) {
        return "code:repo_wide".to_string();
    }

    // multi_file — two-or-more distinct file paths OR explicit
    // multi-file language. Count file-path-shaped tokens (word ending
    // in a known code extension) on the ORIGINAL (case-preserved)
    // text so paths like `MyModule.rs` still match.
    let multi_file_markers = [
        "across files",
        "these files",
        "multiple files",
        "both files",
        "each of these files",
    ];
    if multi_file_markers.iter().any(|m| lower.contains(m)) {
        return "code:multi_file".to_string();
    }
    // File-path detection: count tokens matching *.{rs,py,ts,tsx,js,jsx,go,java,rb,md,toml,yaml,yml,json,html,css,c,cpp,h,hpp,sh}
    // via simple regex-free scan. Two or more distinct extensions-
    // bearing tokens → multi-file scope.
    let exts = [
        ".rs", ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".java", ".rb", ".md", ".toml", ".yaml",
        ".yml", ".json", ".html", ".css", ".c", ".cpp", ".h", ".hpp", ".sh",
    ];
    let mut distinct_paths: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for token in original.split(|c: char| {
        c.is_whitespace()
            || c == '('
            || c == ')'
            || c == ','
            || c == ';'
            || c == '\''
            || c == '"'
            || c == '`'
    }) {
        if token.len() < 3 {
            continue;
        }
        for ext in &exts {
            if token.ends_with(ext) && token.len() > ext.len() {
                distinct_paths.insert(token);
                break;
            }
        }
        if distinct_paths.len() >= 2 {
            return "code:multi_file".to_string();
        }
    }

    // local_transform — single-file mechanical work verbs.
    let local_transform_markers = [
        "refactor",
        "rename",
        "extract this",
        "extract into",
        "extract a function",
        "extract a method",
        "convert this to",
        "convert it to",
        "change this to",
        "replace this with",
        "inline this",
        "inline the",
        "pull this into",
    ];
    if local_transform_markers.iter().any(|m| lower.contains(m)) {
        return "code:local_transform".to_string();
    }

    // Fallback: generic code work with no scope signal.
    "code".to_string()
}

/// Attempt to classify the workload class of a prompt for
/// [`QueryHint::workload_class`]. Values match MODEL-DOSSIER-2026-07's
/// per-workload tracking: `chat | math | code | reasoning | tool_dispatch |
/// other`.
///
/// **Conservative on purpose.** Returns `Some(class)` only when the text
/// exhibits a fairly distinctive signature. Ambiguous text returns `None`
/// — better to leave the field unset than mislabel it, since dossier-
/// consulting policies will treat `None` as "no per-workload signal
/// available" rather than as `"chat"`.
///
/// The heuristic runs on the concatenated content of all messages in the
/// prompt. Case-insensitive substring matching keeps cost O(N) where N is
/// prompt length. No allocations beyond a single lowercased buffer.
///
/// Precedence when multiple classes match: `tool_dispatch` > `code` >
/// `reasoning` > `math` > `None` (chat fallback). This matches the
/// substrate's dispatch importance:
///
/// - A JSON tool-envelope response is the most prompt-shape-constrained
///   emission and should be classified first even if the prompt also
///   mentions math.
/// - Reasoning verbs ("prove that", "reason it out") are stronger signals
///   than the mathematical objects being reasoned about — "Prove that the
///   sum of two evens is even" is asking for reasoning even though it
///   mentions "sum of".
pub fn infer_workload_class(text: &str) -> Option<String> {
    let lower = text.to_lowercase();

    // tool_dispatch — the prompt is asking for a structured JSON envelope.
    // Signatures: explicit JSON scaffolding in the prompt itself, or ask
    // for "reply with JSON" language, or intent/tool key patterns.
    if lower.contains("{\"intent\":")
        || lower.contains("{\"tool\":")
        || lower.contains("reply only with json")
        || lower.contains("reply with the following json")
        || (lower.contains("json") && (lower.contains("intent") || lower.contains("tool")))
    {
        return Some("tool_dispatch".to_string());
    }

    // code — the prompt is asking for code or reasoning about code.
    // Signatures: language names, function/class syntax markers, common
    // programming verbs, or fenced code blocks.
    let code_markers = [
        "```",
        "fn ",
        "def ",
        "class ",
        "import ",
        "function ",
        "async fn",
        "pub fn",
        "public class",
        "console.log",
        "println!",
        "print(",
    ];
    let code_langs = [
        " rust",
        " python",
        " javascript",
        " typescript",
        " golang",
        " haskell",
        " c++",
        "sql query",
        "regex",
        "bash",
        "shell",
    ];
    if code_markers.iter().any(|m| lower.contains(m))
        || code_langs.iter().any(|m| lower.contains(m))
    {
        // Sub-classify by scope. Motivated by 2026-08-02 external signal
        // (Qwen 30B-A3B commercial-adopter framing video): the routing
        // decision within `code` benefits from knowing scope, because
        // local MoE models handle single-file/local work at near-frontier
        // quality but degrade on multi-file reasoning and long
        // autonomous chains where per-step reliability compounds.
        //
        // Scope precedence (broadest wins): repo_wide > multi_file >
        // local_transform > code (catch-all). A prompt saying "refactor
        // this function across the codebase" is repo_wide despite
        // carrying the local_transform "refactor" verb — the scope
        // signal is what decides routing.
        return Some(classify_code_scope(text, &lower));
    }

    // reasoning — multi-step logic, deduction, puzzle framing. Checked
    // before math because the reasoning-verb signal is stronger than the
    // mathematical object being reasoned about: "prove that <sum of ...>"
    // is asking for reasoning even when the object is a sum.
    // Signatures: explicit reasoning verbs, puzzle setups, prove-it framing.
    let reasoning_markers = [
        "reason it out",
        "reason step by step",
        "step-by-step",
        "prove that",
        "prove it",
        "logic puzzle",
        "if and only if",
        " therefore ",
        " deduce ",
        "explain your reasoning",
        "walk through",
        "chain of thought",
    ];
    if reasoning_markers.iter().any(|m| lower.contains(m)) {
        return Some("reasoning".to_string());
    }

    // math — the prompt is asking for a calculation, equation manipulation,
    // or numerical reasoning. Signatures: math verbs, equation notation,
    // integrals/derivatives, permutation/combination language.
    let math_markers = [
        "calculate",
        "compute",
        "derivative",
        "integral",
        "solve for",
        "equation",
        "coefficient",
        "polynomial",
        "permutation",
        "combination",
        "probability that",
        "arithmetic",
        " sum of ",
        " product of ",
        "square root",
        "logarithm",
    ];
    if math_markers.iter().any(|m| lower.contains(m)) {
        return Some("math".to_string());
    }

    // chat — the default fallback for conversational or open-ended prompts
    // that don't exhibit any of the above signatures. Returned as Some so
    // downstream consumers can distinguish "we ran the classifier and it
    // was chat-like" from `None` ("classifier didn't fire at all").
    //
    // Currently we return None instead of Some("chat") — err on the side
    // of not-labeling. Dossier consumers can treat missing as chat if
    // they want; leaving it unset is the honest default.
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn model(id: &str, role: ModelRole) -> AuthorizedModel {
        AuthorizedModel {
            model_id: id.to_string(),
            role,
            dossier_ref: None,
        }
    }

    #[test]
    fn single_model_envelope_yields_sole_authorized() {
        let env = InferenceEnvelope::single("qwen3:8b");
        let decision = DefaultClassifier::new().choose(&env, &QueryHint::default());
        assert_eq!(decision.chosen_model.as_deref(), Some("qwen3:8b"));
        assert!(matches!(
            decision.selection_reason,
            SelectionReason::SoleAuthorized
        ));
        assert_eq!(decision.envelope_size, 1);
        assert_eq!(decision.routable_count, 1);
    }

    #[test]
    fn primary_wins_in_multi_model_envelope() {
        let env = InferenceEnvelope {
            authorized_models: vec![
                model("fallback-model", ModelRole::Fallback),
                model("primary-model", ModelRole::Primary),
                model("shadow-model", ModelRole::Shadow),
            ],
            ratification_receipt_id: None,
        };
        let decision = DefaultClassifier::new().choose(&env, &QueryHint::default());
        assert_eq!(decision.chosen_model.as_deref(), Some("primary-model"));
        assert!(matches!(
            decision.selection_reason,
            SelectionReason::Primary
        ));
        assert_eq!(decision.envelope_size, 3);
        assert_eq!(decision.routable_count, 2);
    }

    #[test]
    fn no_primary_falls_back() {
        let env = InferenceEnvelope {
            authorized_models: vec![
                model("fb-a", ModelRole::Fallback),
                model("fb-b", ModelRole::Fallback),
            ],
            ratification_receipt_id: None,
        };
        let decision = DefaultClassifier::new().choose(&env, &QueryHint::default());
        assert_eq!(decision.chosen_model.as_deref(), Some("fb-a"));
        match decision.selection_reason {
            SelectionReason::Fallback { cause } => {
                assert_eq!(cause, "no_primary_authorized");
            }
            _ => panic!("expected Fallback"),
        }
    }

    #[test]
    fn empty_envelope_returns_empty_decision() {
        let env = InferenceEnvelope {
            authorized_models: vec![],
            ratification_receipt_id: None,
        };
        let decision = DefaultClassifier::new().choose(&env, &QueryHint::default());
        assert!(decision.chosen_model.is_none());
        assert!(matches!(decision.selection_reason, SelectionReason::Empty));
        assert_eq!(decision.envelope_size, 0);
        assert_eq!(decision.routable_count, 0);
    }

    #[test]
    fn shadow_only_envelope_yields_empty() {
        let env = InferenceEnvelope {
            authorized_models: vec![
                model("shadow-a", ModelRole::Shadow),
                model("shadow-b", ModelRole::Shadow),
            ],
            ratification_receipt_id: None,
        };
        let decision = DefaultClassifier::new().choose(&env, &QueryHint::default());
        assert!(decision.chosen_model.is_none());
        assert!(matches!(decision.selection_reason, SelectionReason::Empty));
        assert_eq!(decision.envelope_size, 2);
        assert_eq!(decision.routable_count, 0);
    }

    #[test]
    fn receipt_type_matches_doc_format() {
        let env = InferenceEnvelope::single("qwen3:8b");
        let decision = DefaultClassifier::new().choose(&env, &QueryHint::default());
        let rt = decision.receipt_type();
        assert!(rt.starts_with("regent:inference:classifier_decision:"));
        assert!(rt.len() > "regent:inference:classifier_decision:".len());
    }

    #[test]
    fn decision_ids_are_unique_within_process() {
        let env = InferenceEnvelope::single("qwen3:8b");
        let c = DefaultClassifier::new();
        let d1 = c.choose(&env, &QueryHint::default());
        let d2 = c.choose(&env, &QueryHint::default());
        assert_ne!(d1.decision_id, d2.decision_id);
    }

    #[test]
    fn decision_serializes_to_valid_json() {
        let env = InferenceEnvelope::single("qwen3:8b");
        let decision = DefaultClassifier::new().choose(&env, &QueryHint::default());
        let json = serde_json::to_string(&decision).unwrap();
        // Round-trip through serde to confirm shape stability.
        let back: ClassifierDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, decision);
    }

    #[test]
    fn query_hint_propagates_into_decision() {
        let env = InferenceEnvelope::single("qwen3:8b");
        let hint = QueryHint {
            workload_class: Some("code".to_string()),
            prompt_length: Some(1024),
            caller: Some("regent:dispatch".to_string()),
        };
        let decision = DefaultClassifier::new().choose(&env, &hint);
        assert_eq!(decision.query_hint, hint);
    }

    // ── Workload-class inference tests ──────────────────────────────────

    #[test]
    fn workload_class_none_for_bland_chat() {
        assert_eq!(infer_workload_class("Hello, how are you today?"), None);
        assert_eq!(
            infer_workload_class("Tell me about the history of aviation."),
            None
        );
    }

    #[test]
    fn workload_class_detects_code_from_fenced_block() {
        assert_eq!(
            infer_workload_class("Here's my code:\n```python\ndef f(): pass\n```"),
            Some("code".to_string())
        );
    }

    #[test]
    fn workload_class_detects_code_from_language_mention() {
        assert_eq!(
            infer_workload_class("Write a rust function that reverses a string."),
            Some("code".to_string())
        );
        assert_eq!(
            infer_workload_class("Give me a SQL query joining two tables."),
            Some("code".to_string())
        );
    }

    #[test]
    fn workload_class_detects_math() {
        assert_eq!(
            infer_workload_class("Calculate the derivative of x^2 * sin(x)."),
            Some("math".to_string())
        );
        assert_eq!(
            infer_workload_class("What is the probability that two random cards form a pair?"),
            Some("math".to_string())
        );
    }

    #[test]
    fn workload_class_detects_reasoning() {
        assert_eq!(
            infer_workload_class(
                "Alice sees Bob's hat. Bob sees Carol's. Reason it out — who wears red?"
            ),
            Some("reasoning".to_string())
        );
        assert_eq!(
            infer_workload_class("Prove that the sum of two evens is even."),
            Some("reasoning".to_string())
        );
    }

    #[test]
    fn workload_class_detects_tool_dispatch_from_json_scaffold() {
        assert_eq!(
            infer_workload_class(r#"Reply only with JSON: {"intent":"respond","content":"ok"}"#),
            Some("tool_dispatch".to_string())
        );
    }

    #[test]
    fn workload_class_detects_tool_dispatch_from_language() {
        assert_eq!(
            infer_workload_class("Return JSON with intent and tool fields."),
            Some("tool_dispatch".to_string())
        );
    }

    #[test]
    fn workload_class_precedence_tool_over_code() {
        // A prompt that mentions rust AND a JSON tool envelope: tool wins.
        let text = r#"Here's some rust: fn foo() {}. Now reply with {"intent":"respond"}"#;
        assert_eq!(
            infer_workload_class(text),
            Some("tool_dispatch".to_string())
        );
    }

    #[test]
    fn workload_class_precedence_reasoning_over_math() {
        // Regression: "prove that <sum of X>" is reasoning, not math.
        // The reasoning-verb signal is stronger than the mathematical
        // object being reasoned about.
        assert_eq!(
            infer_workload_class("Prove that the sum of two evens is even."),
            Some("reasoning".to_string())
        );
        // Sanity check the reverse — pure math prompts still classify math.
        assert_eq!(
            infer_workload_class("Calculate the sum of the first 100 primes."),
            Some("math".to_string())
        );
    }

    #[test]
    fn workload_class_is_case_insensitive() {
        assert_eq!(
            infer_workload_class("CALCULATE the DERIVATIVE."),
            Some("math".to_string())
        );
    }

    // ── Code scope sub-classification (2026-08-02) ──────────────────────

    #[test]
    fn code_scope_repo_wide_beats_local_transform() {
        // A prompt with both a repo-wide keyword and a local-transform
        // verb classifies as repo_wide. Motivated by the "scope wins
        // over operation" routing principle.
        assert_eq!(
            infer_workload_class("Refactor this function across the codebase."),
            Some("code:repo_wide".to_string())
        );
    }

    #[test]
    fn code_scope_repo_wide_from_keyword_alone() {
        assert_eq!(
            infer_workload_class("How is this typescript pattern used throughout the codebase?"),
            Some("code:repo_wide".to_string())
        );
    }

    #[test]
    fn code_scope_multi_file_from_explicit_language() {
        assert_eq!(
            infer_workload_class("Update the rust imports across files where this trait is used."),
            Some("code:multi_file".to_string())
        );
    }

    #[test]
    fn code_scope_multi_file_from_two_paths() {
        // Two distinct file paths mentioned → multi_file. The " rust"
        // marker triggers the outer code detector; the .rs paths trigger
        // the sub-classifier's path count.
        assert_eq!(
            infer_workload_class(
                "Compare `src/foo.rs` with `src/bar.rs` — these rust files diverge, why?"
            ),
            Some("code:multi_file".to_string())
        );
    }

    #[test]
    fn code_scope_single_path_stays_local() {
        // Only one file mentioned → not multi_file. Falls to local_transform
        // because "refactor" is present.
        assert_eq!(
            infer_workload_class("Refactor `src/foo.rs` — this rust function should use async."),
            Some("code:local_transform".to_string())
        );
    }

    #[test]
    fn code_scope_local_transform_from_verb() {
        assert_eq!(
            infer_workload_class("Refactor this rust function to be more idiomatic."),
            Some("code:local_transform".to_string())
        );
        assert_eq!(
            infer_workload_class("Rename this variable in the python function."),
            Some("code:local_transform".to_string())
        );
    }

    #[test]
    fn code_scope_generic_fallback() {
        // Existing "just code" prompts with no scope signal fall through
        // to the generic code bucket. Guards backward compat with the
        // pre-2026-08-02 classifier output for common prompts.
        assert_eq!(
            infer_workload_class("Write a rust function that reverses a string."),
            Some("code".to_string())
        );
        assert_eq!(
            infer_workload_class("Here's my code:\n```python\ndef f(): pass\n```"),
            Some("code".to_string())
        );
    }
}
