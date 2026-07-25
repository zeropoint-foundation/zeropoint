//! Intent — the Regent's structured output from reasoning.
//!
//! After perceiving context and reasoning about it, the Regent produces
//! an Intent: what it wants to do next. Intents are the bridge between
//! reasoning and action — they get receipted before execution, so the
//! chain records what the Regent decided, not just what happened.

use serde::{Deserialize, Serialize};

/// What the Regent decided to do after reasoning.
///
/// Every intent becomes a `regent:intent:{kind}` receipt before execution.
/// If the intent requires operator approval, execution blocks until signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Intent {
    /// Respond to the operator through a cockpit surface.
    Respond {
        /// The response content.
        content: String,
        /// Which surface to deliver through (None = same as input source).
        target_surface: Option<String>,
    },

    /// Delegate a task to a sub-agent.
    Delegate {
        /// What the sub-agent should do.
        task: String,
        /// Which capability class this requires.
        capability: String,
        /// Constraints on the delegation.
        constraints: Vec<String>,
    },

    /// Execute a tool directly (within the Regent's own delegation).
    Execute {
        /// Tool name.
        tool: String,
        /// Tool parameters.
        params: serde_json::Value,
    },

    /// Store something in persistent memory.
    Remember {
        /// Memory key.
        key: String,
        /// Content to store.
        content: String,
    },

    /// Request operator approval for an action beyond current delegation.
    RequestApproval {
        /// What the Regent wants to do.
        proposed_action: String,
        /// Why it needs approval.
        reason: String,
    },

    /// No action needed — the Regent observed but has nothing to do.
    Observe {
        /// What the Regent noticed (logged to chain, not surfaced to operator).
        observation: String,
    },

    /// Continue working — the Regent has more to do in this arc.
    ///
    /// Signals the loop runner to re-enter the cognitive cycle immediately
    /// with accumulated tool results. The progress string is the one-line
    /// glanceable summary the operator sees — it must answer "what did she
    /// just do, what's next" at a glance.
    Continue {
        /// One-line progress summary. Rendered directly in cockpit surfaces.
        /// Design constraint: if the operator has to dig to understand this,
        /// the implementation has failed.
        progress: String,
    },

    /// Escalate to cloud inference (requires active CloudMandate).
    Escalate {
        /// Why local inference is insufficient.
        reason: String,
        /// The prompt to send to the cloud model.
        prompt: String,
        /// Estimated token cost.
        estimated_tokens: u64,
    },
}

impl Intent {
    /// The receipt event suffix for this intent kind.
    pub fn receipt_event(&self) -> &'static str {
        match self {
            Intent::Respond { .. } => "respond",
            Intent::Delegate { .. } => "delegate",
            Intent::Execute { .. } => "execute",
            Intent::Remember { .. } => "remember",
            Intent::RequestApproval { .. } => "request_approval",
            Intent::Observe { .. } => "observe",
            Intent::Continue { .. } => "continue",
            Intent::Escalate { .. } => "escalate",
        }
    }

    /// Whether this intent requires operator approval before execution.
    pub fn requires_approval(&self) -> bool {
        matches!(
            self,
            Intent::RequestApproval { .. } | Intent::Escalate { .. }
        )
    }
}
