//! Capability types — what tools and actions the operator can use per-request.

use serde::{Deserialize, Serialize};

/// A capability granted to the operator for a specific request.
/// The policy engine determines which capabilities are active.
/// The operator only sees tools for active capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    /// Unique name of the capability
    pub name: String,
    /// The tool definitions this capability provides
    pub tools: Vec<ToolDefinition>,
    /// Which skill provides this capability (if any)
    pub source_skill: Option<String>,
}

/// A tool definition exposed to the LLM.
/// This is what the operator sees in its prompt — clean, functional, no governance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
    /// Credentials this tool requires (resolved by host-boundary injection)
    #[serde(default)]
    pub required_credentials: Vec<String>,
}

/// The result of the pipeline preparing a request.
#[derive(Debug, Clone)]
pub enum PipelineResult {
    /// Request is allowed — here's what the operator gets.
    Ready {
        capabilities: Vec<Capability>,
        active_skills: Vec<String>,
        model_preference: ModelPreference,
    },
    /// Request is denied by policy.
    Denied {
        reason: String,
        policy_module: String,
    },
    /// Request needs user interaction (Warn or Review).
    NeedsInteraction {
        decision: crate::policy::PolicyDecision,
    },
}

/// Model preference as determined by the policy engine's risk assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPreference {
    /// Preferred model class
    pub preference: ModelClass,
    /// Why this preference was chosen
    pub reason: String,
    /// Can the user override?
    pub overridable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelClass {
    /// Any model — low-risk action
    Any,
    /// Prefer a strong model — medium to high-risk action
    Strong,
    /// Require a strong model — critical-risk action
    RequireStrong,
    /// Must use a local model — data-sensitive action
    LocalOnly,
    /// Specific model requested by user or policy
    Specific(String),
}

/// Operator-facing inference tier for routing requests to (model, host) pairs.
///
/// Operators configure tier → (provider, model) in `~/ZeroPoint/config/routing.toml`.
/// The proxy resolves the tier to a concrete provider before forwarding.
/// Tiers compose with `ModelClass`: `RequireStrong` maps to `HighStakes`;
/// `LocalOnly` maps to `Local`; others use the routing config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InferenceTier {
    /// High-stakes reasoning — ~20% of budget. Default: Claude Sonnet class.
    HighStakes,
    /// Bulk agent loops and summarisation — ~60% of budget. Default: open-weight via US hosts.
    #[default]
    Bulk,
    /// Code generation and review — ~20% of budget. Default: Kimi K2.6 via Abacus.
    Coding,
    /// Local inference only — offline, privacy-sensitive. Default: Ollama.
    Local,
    /// New hosts under evaluation — receipts flagged as experimental.
    Experimental,
}
