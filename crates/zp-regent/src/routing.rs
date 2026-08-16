//! Inference routing — sovereign model selection.
//!
//! The substrate routes inference requests to models using chain-anchored
//! evidence: dossier characterization, evaluation history, fallback record,
//! and system pressure. The routing decision is auditable, governable, and
//! sovereign — no external router decides which model handles a given task.
//!
//! See `docs/design/INFERENCE-ROUTING-DISCIPLINE-2026-07.md` for the full design.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info, warn};

use crate::context::SystemAwareness;

// ─── Intent categories ────────────────────────────────────────────

/// Why the Regent is calling inference — maps to capability requirements.
///
/// The cognitive loop knows whether it's in conversation mode (operator
/// input present) or stewardship mode (autonomous). Tool dispatch is
/// explicit. Evaluation always targets a specific model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentCategory {
    /// Fast, accurate classification. JSON compliance mandatory.
    /// Small model acceptable. Used for intent parsing.
    Routing,

    /// Operator-facing response. Strong instruction-following required.
    /// Quality matters more than speed. Must be context-dump-safe.
    Conversation,

    /// Autonomous governance. Adequate reasoning, higher latency
    /// tolerable. Chain analysis, finding interpretation, remediation
    /// planning.
    Stewardship,

    /// Composing tool call parameters. Structured output compliance
    /// mandatory. Parameterized JSON.
    ToolDispatch,

    /// Must hit a specific model. Deterministic targeting, no routing.
    /// Used by model_evaluate tool and validation battery.
    Evaluation { target_model: String },
}

impl std::fmt::Display for IntentCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Routing => write!(f, "routing"),
            Self::Conversation => write!(f, "conversation"),
            Self::Stewardship => write!(f, "stewardship"),
            Self::ToolDispatch => write!(f, "tool_dispatch"),
            Self::Evaluation { target_model } => write!(f, "evaluation:{}", target_model),
        }
    }
}

// ─── Suitability ──────────────────────────────────────────────────

/// How suitable a model is for a given tier, per its dossier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Suitability {
    /// Model is blocked for this tier — known failure mode.
    Blocked,
    /// Not tested yet — unknown quality.
    Untested,
    /// Tested but not ideal — works with caveats.
    NotRecommended,
    /// Tested, works well — acceptable choice.
    Viable,
    /// Best available for this tier — validated through full battery.
    Recommended,
}

impl Suitability {
    fn from_str(s: &str) -> Self {
        match s {
            "blocked" => Self::Blocked,
            "untested" => Self::Untested,
            "not_recommended" => Self::NotRecommended,
            "viable" => Self::Viable,
            "recommended" => Self::Recommended,
            _ => Self::Untested,
        }
    }

    /// Whether this model is eligible for routing (not blocked).
    fn is_eligible(&self) -> bool {
        !matches!(self, Self::Blocked)
    }
}

// ─── Route decision ───────────────────────────────────────────────

/// The output of the routing function — which model to use and why.
#[derive(Debug, Clone, Serialize)]
pub struct RouteDecision {
    /// Which model to use (e.g. "qwen3:8b", "zai-org/GLM-5.2").
    pub model: String,
    /// Which endpoint to hit.
    pub endpoint: String,
    /// Whether this is a cloud or local model.
    pub tier: InferenceTier,
    /// Why this model was selected (for chain receipt / logging).
    pub rationale: String,
    /// Models that were considered but not selected.
    pub alternatives_rejected: Vec<String>,
}

/// Whether inference runs locally or via cloud API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InferenceTier {
    /// Local Ollama — no network, no cost, no auth.
    Local,
    /// Cloud API — network-dependent, costs tokens, requires auth.
    Cloud { provider: String },
}

// ─── Model candidate ──────────────────────────────────────────────

/// A model under consideration by the router, with its evidence.
#[derive(Debug, Clone)]
struct Candidate {
    /// Model identifier (e.g. "qwen3:8b", "zai-org/GLM-5.2").
    model: String,
    /// Endpoint to reach this model.
    endpoint: String,
    /// Local or cloud.
    tier: InferenceTier,
    /// Dossier suitability for the requested intent category.
    suitability: Suitability,
    /// Whether the model is currently loaded in Ollama (local only).
    is_loaded: bool,
    /// Recent fallback count (higher = less reliable).
    /// TODO: wire fallback history from chain once receipt querying lands.
    _recent_failures: u32,
    /// Composite score — higher is better.
    score: f64,
}

// ─── Dossier corpus ───────────────────────────────────────────────

/// A single model family's characterization, extracted from its
/// `model_dossier.toml`. Runtime projection — the TOML file is truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDossier {
    /// Model family name (e.g. "qwen3", "glm5").
    pub family: String,
    /// Primary variant (e.g. "qwen3:8b", "zai-org/GLM-5.2").
    pub primary_variant: String,
    /// All tested variants.
    pub variants: Vec<String>,
    /// Tier suitability ratings, keyed by tier name.
    pub tier_suitability: HashMap<String, Suitability>,
    /// Variant recommended per tier (e.g. routing → "qwen3:1.7b").
    pub tier_variants: HashMap<String, String>,
    /// Whether this is cloud-only (no local Ollama variant).
    pub cloud_only: bool,
    /// Cloud provider model ID, if applicable.
    pub cloud_model_id: Option<String>,
    /// Blocked tiers (quick lookup).
    pub blocked_tiers: Vec<String>,
    /// H3 (token-entropy anomaly) baseline for zp-emission-coherence.
    /// `None` when the dossier's `[entropy_baseline]` section is
    /// absent OR when its `state != "calibrated"`. Only calibrated
    /// baselines flow into the analyzer; every other state is treated
    /// as "H3 skipped for this variant" (silent, per doc).
    pub entropy_baseline: Option<EntropyBaselineSpec>,
}

/// H3 (token-entropy anomaly) baseline as declared in a model dossier's
/// `[entropy_baseline]` section. Runtime projection of the TOML; the
/// dossier file is truth.
///
/// Mirrors the `[drafter]` schema pattern: the section is always present
/// so the shape is visible in the corpus, but `state` gates whether the
/// numbers are trusted. Loader inserts calibrated baselines into
/// `zp_emission_coherence::AnalyzerConfig.entropy_baselines`; anything
/// else is skipped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyBaselineSpec {
    /// One of `"not_yet_calibrated"` or `"calibrated"`. Only
    /// `"calibrated"` baselines are inserted into the analyzer.
    pub state: String,
    /// Which variant the baseline was measured on. Loader keys the
    /// analyzer entry by this string so `Response.model` matches.
    pub target_variant: String,
    /// Mean `-log P(chosen)` over the calibration battery.
    pub mean: f64,
    /// Sample standard deviation from the calibration battery.
    pub std_dev: f64,
    /// Size of the calibration prompt set (informational).
    pub battery_prompt_count: u64,
    /// Chain receipt id for the calibration run (informational).
    pub battery_receipt: String,
    /// ISO-8601 timestamp when the calibration ran (informational).
    pub calibrated_at: String,
}

impl EntropyBaselineSpec {
    /// True if `state == "calibrated"` AND `std_dev > 0`. Both are
    /// required for H3 to produce a meaningful comparison (a zero
    /// std_dev makes the sigma computation degenerate).
    pub fn is_usable(&self) -> bool {
        self.state == "calibrated" && self.std_dev > 0.0
    }
}

impl ModelDossier {
    /// Get suitability for an intent category.
    fn suitability_for(&self, category: &IntentCategory) -> Suitability {
        let tier_name = match category {
            IntentCategory::Routing => "routing",
            IntentCategory::Conversation => "reasoning",
            IntentCategory::Stewardship => "reasoning",
            IntentCategory::ToolDispatch => "reasoning",
            IntentCategory::Evaluation { .. } => return Suitability::Viable,
        };
        self.tier_suitability
            .get(tier_name)
            .cloned()
            .unwrap_or(Suitability::Untested)
    }

    /// Get the best variant for an intent category.
    fn variant_for(&self, category: &IntentCategory) -> String {
        let tier_name = match category {
            IntentCategory::Routing => "routing",
            IntentCategory::Conversation => "reasoning",
            IntentCategory::Stewardship => "reasoning",
            IntentCategory::ToolDispatch => "reasoning",
            IntentCategory::Evaluation { target_model } => return target_model.clone(),
        };
        self.tier_variants
            .get(tier_name)
            .cloned()
            .unwrap_or_else(|| self.primary_variant.clone())
    }
}

/// The full corpus of model dossiers — loaded at startup from
/// `models/*/model_dossier.toml`. Runtime projection of the TOML files.
#[derive(Debug, Clone, Default)]
pub struct DossierCorpus {
    /// All known model families, keyed by family name.
    pub dossiers: HashMap<String, ModelDossier>,
}

impl DossierCorpus {
    /// Whether the corpus contains any dossiers.
    pub fn is_empty(&self) -> bool {
        self.dossiers.is_empty()
    }

    /// Load all dossiers from a directory containing model family subdirectories.
    ///
    /// Expected structure:
    /// ```text
    /// models/
    ///   qwen3/model_dossier.toml
    ///   gemma4/model_dossier.toml
    ///   glm5/model_dossier.toml
    /// ```
    pub fn load_from_dir(models_dir: &Path) -> Self {
        let mut dossiers = HashMap::new();

        let entries = match std::fs::read_dir(models_dir) {
            Ok(e) => e,
            Err(e) => {
                warn!(path = %models_dir.display(), error = %e, "cannot read models directory");
                return Self { dossiers };
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let dossier_path = path.join("model_dossier.toml");
            if !dossier_path.exists() {
                continue;
            }

            match Self::parse_dossier(&dossier_path) {
                Ok(dossier) => {
                    info!(family = %dossier.family, variants = ?dossier.variants, "loaded model dossier");
                    dossiers.insert(dossier.family.clone(), dossier);
                }
                Err(e) => {
                    warn!(path = %dossier_path.display(), error = %e, "failed to parse model dossier");
                }
            }
        }

        info!(count = dossiers.len(), "dossier corpus loaded");
        Self { dossiers }
    }

    /// Parse a single model_dossier.toml into a ModelDossier.
    fn parse_dossier(path: &Path) -> Result<ModelDossier, String> {
        let content = std::fs::read_to_string(path).map_err(|e| format!("read error: {}", e))?;
        let table: toml::Table = content
            .parse()
            .map_err(|e| format!("TOML parse error: {}", e))?;

        // Extract identity.
        let identity = table
            .get("identity")
            .and_then(|v| v.as_table())
            .ok_or("missing [identity] section")?;

        let family = identity
            .get("family")
            .and_then(|v| v.as_str())
            .ok_or("missing identity.family")?
            .to_string();

        let primary_variant = identity
            .get("variant_primary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let variants: Vec<String> = identity
            .get("variants_tested")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // Check if cloud-only.
        let cloud_only = identity.get("cloud").and_then(|v| v.as_table()).is_some();

        let cloud_model_id = identity
            .get("cloud")
            .and_then(|v| v.as_table())
            .and_then(|c| c.get("abacus_model_id"))
            .and_then(|v| v.as_str())
            .map(String::from);

        // Extract tier suitability.
        let mut tier_suitability = HashMap::new();
        let mut tier_variants = HashMap::new();
        let mut blocked_tiers = Vec::new();

        if let Some(tiers) = table.get("tiers").and_then(|v| v.as_table()) {
            for (tier_name, tier_val) in tiers {
                if let Some(tier_table) = tier_val.as_table() {
                    if let Some(suit_str) = tier_table.get("suitability").and_then(|v| v.as_str()) {
                        let suit = Suitability::from_str(suit_str);
                        if suit == Suitability::Blocked {
                            blocked_tiers.push(tier_name.clone());
                        }
                        tier_suitability.insert(tier_name.clone(), suit);
                    }
                    if let Some(variant) = tier_table.get("variant").and_then(|v| v.as_str()) {
                        tier_variants.insert(tier_name.clone(), variant.to_string());
                    }
                }
            }
        }

        // Extract entropy_baseline (H3 in zp-emission-coherence).
        // Section is optional; missing section → None. Parse errors on
        // individual fields degrade to default values rather than
        // failing the whole dossier — a malformed [entropy_baseline]
        // should not silently drop the model from the corpus.
        let entropy_baseline = table
            .get("entropy_baseline")
            .and_then(|v| v.as_table())
            .map(|t| EntropyBaselineSpec {
                state: t
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("not_yet_calibrated")
                    .to_string(),
                target_variant: t
                    .get("target_variant")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&primary_variant)
                    .to_string(),
                mean: t.get("mean").and_then(|v| v.as_float()).unwrap_or(0.0),
                std_dev: t.get("std_dev").and_then(|v| v.as_float()).unwrap_or(0.0),
                battery_prompt_count: t
                    .get("battery_prompt_count")
                    .and_then(|v| v.as_integer())
                    .map(|i| i.max(0) as u64)
                    .unwrap_or(0),
                battery_receipt: t
                    .get("battery_receipt")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                calibrated_at: t
                    .get("calibrated_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            });

        Ok(ModelDossier {
            family,
            primary_variant,
            variants,
            tier_suitability,
            tier_variants,
            cloud_only,
            cloud_model_id,
            blocked_tiers,
            entropy_baseline,
        })
    }

    /// Extract H3 entropy baselines from the corpus for
    /// `zp_emission_coherence::EmissionAnalyzer`. Every dossier's
    /// `[entropy_baseline]` section that is `is_usable()` (i.e. state =
    /// "calibrated" AND std_dev > 0) becomes a map entry keyed by
    /// `target_variant`. Skipped baselines are logged at info level;
    /// dossiers without a baseline section are silently ignored.
    ///
    /// Returned map fits `AnalyzerConfig.entropy_baselines` directly.
    pub fn entropy_baselines(&self) -> HashMap<String, zp_emission_coherence::EntropyBaseline> {
        let mut out = HashMap::new();
        for (family, dossier) in &self.dossiers {
            let Some(spec) = &dossier.entropy_baseline else {
                continue;
            };
            if spec.is_usable() {
                info!(
                    family = %family,
                    variant = %spec.target_variant,
                    mean = spec.mean,
                    std_dev = spec.std_dev,
                    "H3 entropy baseline loaded from dossier"
                );
                out.insert(
                    spec.target_variant.clone(),
                    zp_emission_coherence::EntropyBaseline {
                        mean: spec.mean,
                        std_dev: spec.std_dev,
                    },
                );
            } else {
                info!(
                    family = %family,
                    state = %spec.state,
                    "H3 entropy baseline skipped — dossier not calibrated or std_dev=0"
                );
            }
        }
        out
    }

    /// Get all eligible candidates for an intent category.
    fn candidates_for(&self, category: &IntentCategory) -> Vec<(&ModelDossier, Suitability)> {
        self.dossiers
            .values()
            .filter_map(|d| {
                let suit = d.suitability_for(category);
                if suit.is_eligible() {
                    Some((d, suit))
                } else {
                    None
                }
            })
            .collect()
    }
}

// ─── Router ───────────────────────────────────────────────────────

/// Inference router — selects the best model for a given intent category
/// using dossier evidence, system awareness, and operational history.
///
/// Lives on `InferenceBackend` as an associated method. The router is
/// data-driven: it reads dossier files and system state, applies a
/// ranking function, and returns a target. No external dependency.
pub struct Router;

impl Router {
    /// Select the best model for the given intent category.
    ///
    /// Evidence sources (in priority order):
    /// 1. Explicit evaluation target (IntentCategory::Evaluation)
    /// 2. Operator pin (config defaults — future: chain receipts)
    /// 3. Dossier tier suitability (blocked models excluded)
    /// 4. System pressure (memory-constrained → prefer smaller/loaded)
    /// 5. Inference tier preference (local preferred over cloud for
    ///    latency and cost, unless quality demands cloud)
    pub fn route(
        category: &IntentCategory,
        corpus: &DossierCorpus,
        awareness: Option<&SystemAwareness>,
        config: &crate::config::RegentConfig,
    ) -> RouteDecision {
        // Evaluation always targets a specific model — no routing.
        if let IntentCategory::Evaluation { target_model } = category {
            return RouteDecision {
                model: target_model.clone(),
                endpoint: config.inference_endpoint.clone(),
                tier: InferenceTier::Local,
                rationale: format!("evaluation target: {}", target_model),
                alternatives_rejected: vec![],
            };
        }

        // If corpus is empty, fall back to config defaults.
        if corpus.dossiers.is_empty() {
            return Self::route_from_config(category, config);
        }

        // Build candidate list from eligible dossier entries.
        let eligible = corpus.candidates_for(category);
        if eligible.is_empty() {
            debug!(category = %category, "no eligible dossier candidates — falling back to config");
            return Self::route_from_config(category, config);
        }

        // Score each candidate.
        let mut candidates: Vec<Candidate> = eligible
            .iter()
            .map(|(dossier, suitability)| {
                let variant = dossier.variant_for(category);
                let is_local = !dossier.cloud_only;
                let endpoint = if is_local {
                    "http://127.0.0.1:11434".to_string()
                } else {
                    config.inference_endpoint.clone()
                };
                let tier = if is_local {
                    InferenceTier::Local
                } else {
                    InferenceTier::Cloud {
                        provider: "abacus".to_string(),
                    }
                };

                // Check if loaded in Ollama.
                let is_loaded = if is_local {
                    awareness
                        .map(|a| a.loaded_models.iter().any(|m| m.name == variant))
                        .unwrap_or(false)
                } else {
                    false // cloud models aren't "loaded"
                };

                // Score: suitability is primary, loaded/local are tiebreakers.
                let suitability_score = match suitability {
                    Suitability::Recommended => 100.0,
                    Suitability::Viable => 70.0,
                    Suitability::NotRecommended => 30.0,
                    Suitability::Untested => 20.0,
                    Suitability::Blocked => 0.0, // filtered out above
                };

                let loaded_bonus = if is_loaded { 15.0 } else { 0.0 };
                let local_bonus = if is_local { 10.0 } else { 0.0 };

                // Memory pressure penalty for large local models.
                let pressure_penalty = if is_local {
                    awareness
                        .map(|a| match a.memory.level {
                            crate::context::PressureLevel::Critical => 40.0,
                            crate::context::PressureLevel::High => 20.0,
                            crate::context::PressureLevel::Moderate => 5.0,
                            crate::context::PressureLevel::Low => 0.0,
                        })
                        .unwrap_or(0.0)
                } else {
                    0.0
                };

                let score = suitability_score + loaded_bonus + local_bonus - pressure_penalty;

                Candidate {
                    model: variant,
                    endpoint,
                    tier,
                    suitability: suitability.clone(),
                    is_loaded,
                    _recent_failures: 0, // TODO: read from chain
                    score,
                }
            })
            .collect();

        // Sort by score descending.
        candidates.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Winner is the highest-scored candidate.
        let winner = &candidates[0];
        let rejected: Vec<String> = candidates[1..]
            .iter()
            .map(|c| {
                format!(
                    "{} (suitability:{:?}, score:{:.0})",
                    c.model, c.suitability, c.score
                )
            })
            .collect();

        let rationale = format!(
            "dossier:{:?} score:{:.0} loaded:{} tier:{}",
            winner.suitability,
            winner.score,
            winner.is_loaded,
            match &winner.tier {
                InferenceTier::Local => "local",
                InferenceTier::Cloud { .. } => "cloud",
            }
        );

        info!(
            category = %category,
            model = %winner.model,
            rationale = %rationale,
            alternatives = candidates.len() - 1,
            "inference route selected"
        );

        RouteDecision {
            model: winner.model.clone(),
            endpoint: winner.endpoint.clone(),
            tier: winner.tier.clone(),
            rationale,
            alternatives_rejected: rejected,
        }
    }

    /// Determine the inference tier for a model name by checking the corpus.
    /// If the model matches a cloud_model_id in any dossier, it's cloud.
    /// If it matches a variant in a non-cloud-only dossier, it's local.
    /// Otherwise heuristic: contains '/' → cloud, else local.
    pub fn infer_tier(model: &str, corpus: &DossierCorpus) -> InferenceTier {
        for dossier in corpus.dossiers.values() {
            if let Some(ref cloud_id) = dossier.cloud_model_id {
                if cloud_id == model {
                    return InferenceTier::Cloud {
                        provider: dossier.family.clone(),
                    };
                }
            }
            if !dossier.cloud_only && dossier.variants.iter().any(|v| v == model) {
                return InferenceTier::Local;
            }
        }
        if model.contains('/') {
            InferenceTier::Cloud {
                provider: "unknown".to_string(),
            }
        } else {
            InferenceTier::Local
        }
    }

    /// Fallback: route from config defaults when no dossier data exists.
    pub fn route_from_config(
        category: &IntentCategory,
        config: &crate::config::RegentConfig,
    ) -> RouteDecision {
        let (model, rationale) = match category {
            IntentCategory::Routing => (
                config.routing_model.clone(),
                "config default: routing_model".to_string(),
            ),
            IntentCategory::Conversation
            | IntentCategory::Stewardship
            | IntentCategory::ToolDispatch => (
                config.reasoning_model.clone(),
                "config default: reasoning_model".to_string(),
            ),
            IntentCategory::Evaluation { target_model } => (
                target_model.clone(),
                format!("evaluation target: {}", target_model),
            ),
        };

        debug!(
            category = %category,
            model = %model,
            "routing from config defaults (no dossier data)"
        );

        RouteDecision {
            model,
            endpoint: config.inference_endpoint.clone(),
            tier: InferenceTier::Local,
            rationale,
            alternatives_rejected: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_corpus() -> DossierCorpus {
        let mut dossiers = HashMap::new();

        // qwen3 — recommended for routing and reasoning
        let mut qwen3_tiers = HashMap::new();
        qwen3_tiers.insert("routing".into(), Suitability::Recommended);
        qwen3_tiers.insert("reasoning".into(), Suitability::Recommended);
        let mut qwen3_variants = HashMap::new();
        qwen3_variants.insert("routing".into(), "qwen3:1.7b".into());
        qwen3_variants.insert("reasoning".into(), "qwen3:8b".into());
        dossiers.insert(
            "qwen3".into(),
            ModelDossier {
                family: "qwen3".into(),
                primary_variant: "qwen3:8b".into(),
                variants: vec!["qwen3:8b".into(), "qwen3:1.7b".into()],
                tier_suitability: qwen3_tiers,
                tier_variants: qwen3_variants,
                cloud_only: false,
                cloud_model_id: None,
                blocked_tiers: vec![],
                entropy_baseline: None,
            },
        );

        // gemma4 — recommended for officer, blocked for reasoning
        let mut gemma4_tiers = HashMap::new();
        gemma4_tiers.insert("routing".into(), Suitability::NotRecommended);
        gemma4_tiers.insert("reasoning".into(), Suitability::Blocked);
        gemma4_tiers.insert("officer".into(), Suitability::Recommended);
        let mut gemma4_variants = HashMap::new();
        gemma4_variants.insert("officer".into(), "gemma4:26b-mlx".into());
        dossiers.insert(
            "gemma4".into(),
            ModelDossier {
                family: "gemma4".into(),
                primary_variant: "gemma4:26b-mlx".into(),
                variants: vec!["gemma4:26b-mlx".into()],
                tier_suitability: gemma4_tiers,
                tier_variants: gemma4_variants,
                cloud_only: false,
                cloud_model_id: None,
                blocked_tiers: vec!["reasoning".into()],
                entropy_baseline: None,
            },
        );

        // glm5 — viable for reasoning, cloud-only
        let mut glm5_tiers = HashMap::new();
        glm5_tiers.insert("routing".into(), Suitability::Untested);
        glm5_tiers.insert("reasoning".into(), Suitability::Viable);
        glm5_tiers.insert("cloud_escalation".into(), Suitability::Viable);
        let mut glm5_variants = HashMap::new();
        glm5_variants.insert("reasoning".into(), "zai-org/GLM-5.2".into());
        dossiers.insert(
            "glm5".into(),
            ModelDossier {
                family: "glm5".into(),
                primary_variant: "zai-org/GLM-5.2".into(),
                variants: vec!["zai-org/GLM-5.2".into()],
                tier_suitability: glm5_tiers,
                tier_variants: glm5_variants,
                cloud_only: true,
                cloud_model_id: Some("zai-org/GLM-5.2".into()),
                blocked_tiers: vec![],
                entropy_baseline: None,
            },
        );

        DossierCorpus { dossiers }
    }

    fn test_config() -> crate::config::RegentConfig {
        crate::config::RegentConfig {
            enabled: true,
            inference_endpoint: "https://routellm.abacus.ai/v1".into(),
            reasoning_model: "qwen3:8b".into(),
            routing_model: "qwen3:1.7b".into(),
            ..Default::default()
        }
    }

    #[test]
    fn routing_selects_recommended_local_model() {
        let corpus = test_corpus();
        let config = test_config();
        let decision = Router::route(&IntentCategory::Routing, &corpus, None, &config);
        assert_eq!(decision.model, "qwen3:1.7b");
        assert_eq!(decision.tier, InferenceTier::Local);
    }

    #[test]
    fn conversation_prefers_recommended_local_over_viable_cloud() {
        let corpus = test_corpus();
        let config = test_config();
        let decision = Router::route(&IntentCategory::Conversation, &corpus, None, &config);
        // qwen3:8b is Recommended + local bonus; glm5 is Viable + no local bonus
        assert_eq!(decision.model, "qwen3:8b");
        assert_eq!(decision.tier, InferenceTier::Local);
    }

    #[test]
    fn blocked_models_excluded() {
        let corpus = test_corpus();
        let config = test_config();
        let decision = Router::route(&IntentCategory::Conversation, &corpus, None, &config);
        // gemma4 is blocked for reasoning — should not appear
        assert!(!decision
            .alternatives_rejected
            .iter()
            .any(|r| r.contains("gemma4")));
        assert_ne!(decision.model, "gemma4:26b-mlx");
    }

    #[test]
    fn evaluation_bypasses_routing() {
        let corpus = test_corpus();
        let config = test_config();
        let decision = Router::route(
            &IntentCategory::Evaluation {
                target_model: "phi4:14b".into(),
            },
            &corpus,
            None,
            &config,
        );
        assert_eq!(decision.model, "phi4:14b");
        assert!(decision.rationale.contains("evaluation target"));
    }

    #[test]
    fn empty_corpus_falls_back_to_config() {
        let corpus = DossierCorpus::default();
        let config = test_config();
        let decision = Router::route(&IntentCategory::Conversation, &corpus, None, &config);
        assert_eq!(decision.model, "qwen3:8b"); // config default
        assert!(decision.rationale.contains("config default"));
    }

    // ── EntropyBaselineSpec parsing ─────────────────────────────────────

    fn write_dossier(dir: &Path, family: &str, extra: &str) -> std::path::PathBuf {
        let sub = dir.join(family);
        std::fs::create_dir_all(&sub).unwrap();
        let dossier = sub.join("model_dossier.toml");
        let base = format!(
            "[identity]\n\
             family = \"{fam}\"\n\
             variant_primary = \"{fam}:1b\"\n\
             variants_tested = [\"{fam}:1b\"]\n\
             \n\
             [tiers.reasoning]\n\
             suitability = \"viable\"\n\
             variant = \"{fam}:1b\"\n",
            fam = family
        );
        std::fs::write(&dossier, format!("{}{}", base, extra)).unwrap();
        dossier
    }

    #[test]
    fn parse_dossier_reads_calibrated_entropy_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        write_dossier(
            tmp.path(),
            "testfam",
            "\n[entropy_baseline]\n\
             state = \"calibrated\"\n\
             target_variant = \"testfam:1b\"\n\
             mean = 2.5\n\
             std_dev = 0.7\n\
             battery_prompt_count = 128\n\
             battery_receipt = \"regent:calibration:testfam:abc\"\n\
             calibrated_at = \"2026-08-01T12:00:00Z\"\n",
        );
        let corpus = DossierCorpus::load_from_dir(tmp.path());
        let d = corpus.dossiers.get("testfam").unwrap();
        let b = d.entropy_baseline.as_ref().unwrap();
        assert_eq!(b.state, "calibrated");
        assert_eq!(b.target_variant, "testfam:1b");
        assert!((b.mean - 2.5).abs() < 1e-9);
        assert!((b.std_dev - 0.7).abs() < 1e-9);
        assert_eq!(b.battery_prompt_count, 128);
        assert_eq!(b.battery_receipt, "regent:calibration:testfam:abc");
        assert!(b.is_usable());
    }

    #[test]
    fn parse_dossier_reads_not_yet_calibrated_entropy_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        write_dossier(
            tmp.path(),
            "testfam",
            "\n[entropy_baseline]\n\
             state = \"not_yet_calibrated\"\n\
             target_variant = \"testfam:1b\"\n\
             mean = 0.0\n\
             std_dev = 0.0\n\
             battery_prompt_count = 0\n\
             battery_receipt = \"\"\n\
             calibrated_at = \"\"\n",
        );
        let corpus = DossierCorpus::load_from_dir(tmp.path());
        let d = corpus.dossiers.get("testfam").unwrap();
        let b = d.entropy_baseline.as_ref().unwrap();
        assert_eq!(b.state, "not_yet_calibrated");
        assert!(!b.is_usable()); // state gates usability
    }

    #[test]
    fn parse_dossier_missing_entropy_baseline_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        write_dossier(tmp.path(), "testfam", "");
        let corpus = DossierCorpus::load_from_dir(tmp.path());
        let d = corpus.dossiers.get("testfam").unwrap();
        assert!(d.entropy_baseline.is_none());
    }

    #[test]
    fn entropy_baseline_calibrated_but_zero_stddev_is_not_usable() {
        let tmp = tempfile::tempdir().unwrap();
        write_dossier(
            tmp.path(),
            "testfam",
            "\n[entropy_baseline]\n\
             state = \"calibrated\"\n\
             target_variant = \"testfam:1b\"\n\
             mean = 2.5\n\
             std_dev = 0.0\n\
             battery_prompt_count = 128\n\
             battery_receipt = \"\"\n\
             calibrated_at = \"\"\n",
        );
        let corpus = DossierCorpus::load_from_dir(tmp.path());
        let b = corpus
            .dossiers
            .get("testfam")
            .unwrap()
            .entropy_baseline
            .as_ref()
            .unwrap();
        // Degenerate: std_dev=0 makes sigmas_below computation divide by zero.
        // The is_usable() guard is what keeps H3 from seeing this.
        assert!(!b.is_usable());
    }

    #[test]
    fn parse_dossier_defaults_target_variant_to_primary_variant() {
        // If [entropy_baseline] omits target_variant, loader should fall
        // back to the dossier's primary_variant so the H3 lookup still
        // has a key to match Response.model against.
        let tmp = tempfile::tempdir().unwrap();
        write_dossier(
            tmp.path(),
            "testfam",
            "\n[entropy_baseline]\n\
             state = \"calibrated\"\n\
             mean = 2.5\n\
             std_dev = 0.7\n\
             battery_prompt_count = 10\n\
             battery_receipt = \"\"\n\
             calibrated_at = \"\"\n",
        );
        let corpus = DossierCorpus::load_from_dir(tmp.path());
        let b = corpus
            .dossiers
            .get("testfam")
            .unwrap()
            .entropy_baseline
            .as_ref()
            .unwrap();
        assert_eq!(b.target_variant, "testfam:1b"); // fell back to primary
    }
}
