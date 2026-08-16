//! The Regent's granted tool surface — one declaration.
//!
//! # Why this module exists
//!
//! Until 2026-08-09 this list was declared **three** times: as
//! `REGENT_TOOLS` in `zp-server` (the copy that actually confers capability,
//! by building the startup `CapabilityGrant`), and twice more in
//! `zp_regent::regent` — once inside `recover_execute_intent` and once inside
//! `sanitize_tool_name`, both as bare `&[&str]`.
//!
//! Nothing held the three together, and they drifted twice with consequences:
//!
//! - `substrate_validate` was granted and missing from both `zp-regent`
//!   copies, so a malformed emission of it fell through unsanitized and
//!   dispatched as an unknown tool.
//! - The Phase 1 artifact tools (`chart_generate`, `report_assemble`,
//!   `save_to_artifacts`) were granted 2026-08-02 and not added here, so
//!   `report_assemble','params':{…}` arrived, failed to sanitize, and
//!   dispatched as "unknown tool" while the tool existed and was reachable.
//!   Two days between the grant and the drift biting.
//!
//! # The premise that turned out to be wrong
//!
//! The docstring on `sanitize_tool_name` read: *"Neither crate depends on the
//! other in the direction that would let them share a const, so the
//! duplication is structural and only a pin can hold the three together."*
//!
//! That is false. `zp-server` depends on `zp-regent`
//! (`crates/zp-server/Cargo.toml:43`); `zp-regent` does not depend on
//! `zp-server`. The dependency runs exactly the direction needed for a shared
//! const, and had done all along. The duplication was never structural — the
//! claim that it was is what kept it alive, because it turned a fixable
//! problem into an accepted cost. Checking it took one grep.
//!
//! The corpus also referenced a pin named `granted_tools_must_be_reachable`
//! as holding one of the three. It appears in five governed documents and in
//! `tools/connection-map/connections.json`, and in **no Rust file anywhere**.
//! The safeguard on capability grants was a citation.
//!
//! # The rule
//!
//! Adding an entry here grants the Regent a capability (PIN-001: an authority
//! decision, never a lint fix). It is now one edit rather than three, and
//! there is no longer a copy that can silently disagree.

/// A tool the Regent may reach for, and the capability scope it is granted
/// under.
///
/// `scope` is what the startup `CapabilityGrant` advertises and what the gate
/// checks. It is not decorative: `browser_use` carries
/// `web:allowed_domains`, and that selector is currently **not read by
/// anything** — `ALLOWED_DOMAINS` is a hardcoded const in the dispatch arm.
/// The grant is genuinely narrow, but narrower than the delegation
/// advertises. Carried forward from the original declaration as a known gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegentTool {
    /// Dispatch name, as it appears in an `Intent::Execute`.
    pub name: &'static str,
    /// Capability scope advertised on the delegation.
    pub scope: &'static str,
}

/// Every tool the Regent is granted at startup.
///
/// Order is not significant: `sanitize_tool_name` matches with `starts_with`,
/// and no name here is a prefix of another. If that ever stops being true,
/// matching becomes order-dependent — `tool_names_are_prefix_free` fails
/// before it can bite.
pub const REGENT_TOOLS: &[RegentTool] = &[
    RegentTool {
        name: "chain_query",
        scope: "audit_chain",
    },
    RegentTool {
        name: "governance_posture",
        scope: "governance",
    },
    RegentTool {
        name: "model_evaluate",
        scope: "inference",
    },
    RegentTool {
        name: "system_status",
        scope: "system",
    },
    RegentTool {
        name: "batch_sign",
        scope: "audit_chain",
    },
    RegentTool {
        name: "chain_compact",
        scope: "audit_chain",
    },
    RegentTool {
        name: "self_configure",
        scope: "inference:endpoint,model,api_key",
    },
    RegentTool {
        name: "memory_list",
        scope: "cognition:memory_promotion",
    },
    RegentTool {
        name: "memory_review",
        scope: "cognition:memory_promotion:review_remembered",
    },
    RegentTool {
        name: "substrate_validate",
        scope: "substrate:validation:regent",
    },
    RegentTool {
        name: "browser_use",
        scope: "web:allowed_domains",
    },
    // Phase 1 report-generation tools (docs/REGENT-PHASE-0-1-DESIGN-2026-07.md).
    // chart_generate / report_assemble are pure functions returning strings;
    // save_to_artifacts writes to ~/ZeroPoint/artifacts/<hash>.<ext> and emits
    // an `artifact:library:candidate` receipt — content-addressed, bounded
    // destination, chain-anchored.
    //
    // None are approval-required: the `browser_use` precedent targets tools
    // reaching unbounded destinations, and a bounded write to operator-owned
    // artifact space is a different risk class. Revisit if a confusion
    // incident argues otherwise — matching the pattern that put `browser_use`
    // behind approval after an observed event, not preemptively.
    RegentTool {
        name: "chart_generate",
        scope: "artifact:chart",
    },
    RegentTool {
        name: "report_assemble",
        scope: "artifact:report",
    },
    RegentTool {
        name: "save_to_artifacts",
        scope: "artifact:library:write",
    },
];

/// Dispatch names only — for parsing and sanitization, which do not care
/// about scope.
pub fn tool_names() -> impl Iterator<Item = &'static str> {
    REGENT_TOOLS.iter().map(|t| t.name)
}

/// Whether a name is a granted tool. Exact match.
pub fn is_granted(name: &str) -> bool {
    REGENT_TOOLS.iter().any(|t| t.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn tool_names_are_unique() {
        let mut seen = BTreeSet::new();
        for t in REGENT_TOOLS {
            assert!(seen.insert(t.name), "duplicate tool name: {}", t.name);
            assert!(!t.name.is_empty(), "empty tool name");
            assert!(!t.scope.is_empty(), "{} has no capability scope", t.name);
        }
    }

    #[test]
    fn tool_names_are_prefix_free() {
        // `sanitize_tool_name` matches with `starts_with`. If one name were a
        // prefix of another, the shorter could shadow the longer depending on
        // iteration order, and the resulting misdispatch would look like a
        // model formatting error rather than a list problem.
        for a in tool_names() {
            for b in tool_names() {
                assert!(
                    a == b || !b.starts_with(a),
                    "{a:?} is a prefix of {b:?} — starts_with matching is no longer order-independent"
                );
            }
        }
    }

    #[test]
    fn is_granted_rejects_unknown() {
        assert!(is_granted("chain_query"));
        assert!(!is_granted("chain_quer"));
        assert!(!is_granted("rm_rf"));
    }
}
