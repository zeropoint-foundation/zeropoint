//! Intent — the Regent's structured output from reasoning.
//!
//! After perceiving context and reasoning about it, the Regent produces
//! an Intent: what it wants to do next. Intents are the bridge between
//! reasoning and action — they get receipted before execution, so the
//! chain records what the Regent decided, not just what happened.

use serde::{Deserialize, Serialize};

/// What a proposal asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    /// A mechanism exists; the Regent lacks the authority to invoke it.
    /// Resolved by operator signature; a grant becomes precedent.
    Action,
    /// No mechanism exists. Goes to the improvement loop as a capability
    /// request, not to the approval queue.
    Mechanism,
}

impl ProposalKind {
    pub fn parse(s: &str) -> Self {
        match s {
            "mechanism" | "capability" | "new_capability" => ProposalKind::Mechanism,
            _ => ProposalKind::Action,
        }
    }

    /// Receipt family this proposal lands in.
    pub fn receipt_prefix(&self) -> &'static str {
        match self {
            ProposalKind::Action => "regent:proposal:",
            ProposalKind::Mechanism => "improvement:proposed",
        }
    }
}

/// What the Regent decided to do after reasoning.
///
/// Every intent becomes a `regent:intent:{kind}` receipt before execution.
/// If the intent requires operator approval, execution blocks until signed.
///
/// # Which intents are reachable, and why the rest are not
///
/// `parse_intent` accepts all eight variants below. The prompts expose
/// fewer, deliberately, and the gap is recorded here because it was
/// previously invisible: across 84,246 chain entries the model had only
/// ever emitted `respond` (18) and `execute` (1). Every other variant was
/// structurally impossible for it to say, and nothing declared that.
///
/// **Exposed** (`prompts/routing_with_tools.md`, `prompts/unified_tools.md`):
/// `execute`, `respond`, `continue`, `request_approval`. Each has an
/// executor that does the work it names.
///
/// **Deliberately not exposed** — `delegate`, `remember`, `escalate`.
/// Their executors are stubs: `Delegate` carries `TODO: sub-agent
/// dispatch`, `Escalate` carries `TODO: cloud escalation path with mandate
/// validation`, and `Remember` discards its `content` field. All three
/// emit a receipt and return `Observed`. Exposing them would let the
/// Regent emit chain evidence describing acts that did not happen, which
/// is worse than being unable to name them.
///
/// *Deferred.* Reopen condition: the corresponding executor performs the
/// act its receipt claims — sub-agent dispatch for `delegate`, mandate
/// validation and a cloud call for `escalate`, an actual memory write for
/// `remember`. Reopen watch: `receipt_exists(regent:intent:delegate)` and
/// siblings would fire today from the stub, so the watch is on the
/// executor rather than the receipt: `invariant_violated(intent_stub_removed)`.
///
/// `observe` is emitted by the loop rather than the model — the
/// early-return in `reason()` when there is no input and no urgency — and
/// is not a prompt-selectable intent. That is why it dominates the chain.
/// The dispatchable form of a proposal.
///
/// A proposal's prose says what the Regent wants done; this says how the
/// substrate would do it. Without it, a granted approval records consent to
/// a *sentence* — the operator signs, and there is nothing to run.
///
/// Observed 2026-07-31: an escalated proposal was queued, rendered, granted,
/// and chain-anchored, and the standing correction it proposed was never
/// created, because nothing downstream could turn "Record the operator's
/// preferred name as Kenrom" into a call. That is the mirror of the defect
/// that produced the proposal — first a claimed act without authority, then
/// authority without an act.
///
/// Optional on purpose. Proposing a *mechanism* asks for a capability that
/// does not exist yet, so by definition no tool can enact it; and an action
/// whose tool is outside the current delegation set cannot name one
/// honestly. In both cases the proposal stands on its prose and enacting it
/// is the operator's to do by hand — which is a real terminal state, not a
/// gap.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Enactment {
    /// Tool to dispatch. Must be one the Regent already holds.
    pub tool: String,
    /// Arguments, exactly as that tool's dispatch site expects them.
    #[serde(default)]
    pub params: serde_json::Value,
}

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

    /// A proposal — the Regent cannot simply act, and says what she wants
    /// instead of naming a limitation and stopping.
    ///
    /// Covers two of the three terminal states in
    /// `docs/EXECUTION-AUTHORITY-MODEL-2026-07.md` §Phase 7: *propose an
    /// action* (a mechanism exists, authority does not) and *propose a
    /// mechanism* (no mechanism exists). They are one intent with a
    /// discriminator rather than two intents because the routing tier can
    /// check the distinction against its own tool list — a tool exists and
    /// she lacks authority, versus no tool exists — where a second intent
    /// would be another thing for a small model to confuse.
    ///
    /// They must stay distinguishable downstream: per that spec,
    /// "proposing an *action* asks for authority, proposing a *mechanism*
    /// asks for a capability, and conflating them puts capability requests
    /// through a review path built for one-off approvals." The kind
    /// selects the receipt: `regent:proposal:*` or `improvement:proposed`.
    ///
    /// The routing tier fills `kind` and `proposed_action` only. The rest
    /// is written by the compose tier — a proposal is reasoning prose, and
    /// the two-tier split exists so prose is not authored by the 1.7b
    /// classifier.
    RequestApproval {
        /// Authority, or capability.
        kind: ProposalKind,
        /// One sentence: the specific thing to be done.
        proposed_action: String,
        /// Why approval is needed. Retained as the human-readable summary.
        reason: String,
        /// What was observed that prompted this.
        finding: Option<String>,
        /// Which limb failed: no authority | no precedent | novel context |
        /// no mechanism.
        failed_limb: Option<String>,
        /// What will be true afterwards that is not true now. Not a
        /// restatement of `proposed_action`.
        expected_outcome: Option<String>,
        /// The artifact itself, where the proposal is for something the
        /// substrate already knows how to store. Honoured in-session as an
        /// unsigned candidate; does not survive a restart unsigned.
        draft: Option<String>,
        /// The dispatchable form, when the proposed action maps to a tool
        /// the Regent already holds. `None` means the proposal stands on
        /// its prose and enacting it is the operator's by hand.
        enactment: Option<Enactment>,
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
