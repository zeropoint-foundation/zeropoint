//! The invariant floor — the four capabilities a Regent has by default.
//!
//! Elaborates `docs/design/REGENT-ONBOARDING-CEREMONY-2026-09.md` §3.
//! KEEL-mandated per §II.13.9 P9 (the system acts; the operator signs
//! — and *acts* requires a bounded, always-present action space).
//! Non-refusable: a Regent without the floor is not a Regent.
//!
//! # The four capabilities
//!
//! Each satisfies the test *"if the Regent lacks this, it is not a
//! Regent — it is something else."*
//!
//! - [`RESPOND`] — reply to operator input on the operator's own
//!   input channel. Without this, the entity cannot answer its operator
//!   and is not a cognitive partner.
//!
//! - [`READ_OWN_SCOPE`] — read its own persona charter, its own name,
//!   its own receipt chain (filtered to `regent:*` and `cognitive:*`
//!   prefixes), and the substrate's governed corpus under `docs/`
//!   (Tier 1 and Tier 2). Not `crates/`. Not `docs/handoffs/`. Without
//!   this, the Regent has no self-knowledge and cannot act coherently
//!   across turns.
//!
//! - [`EMIT_COGNITIVE`] — emit `cognitive:*` receipts describing its
//!   own internal state (planning, self-observer classifications,
//!   drift-detection, proposal-generation reasoning). Not `substrate:*`,
//!   not `gate:*`, not `delegation:*`. Without this, P9 has nothing to
//!   attest to — no receipts describe what the Regent was thinking when
//!   it acted, and the Cognitive Self-Observer has no substrate to
//!   observe *into*.
//!
//! - [`PROPOSE_VIA_P9`] — emit PROPOSAL shapes without a per-proposal
//!   grant. Distinct from the *acting* capabilities above. Without this,
//!   a Regent that hits an input outside its seeded capabilities falls
//!   *silent* — it cannot even ask, cannot request its own extensions,
//!   is stuck at floor forever. Promoted from the extension catalog to
//!   the floor per REGENT-ONBOARDING-CEREMONY-2026-09 §6 open-position
//!   resolution (2026-09-06, operator sign-off B).
//!
//! # Discipline
//!
//! The four capability strings appear in the codebase exactly once —
//! here. The `invariant_floor_is_singly_declared` discipline pin
//! (`crates/zp-discipline/tests/invariant_floor_is_singly_declared.rs`)
//! enforces that no other source file names them, so any future change
//! to the floor is a change to KEEL that has to route through this file
//! or the pin turns red.

use crate::context::DelegationSummary;
use chrono::{DateTime, Utc};

/// Capability name for the *respond* floor capability.
pub const RESPOND: &str = "respond";

/// Capability name for the *read:own-scope* floor capability.
pub const READ_OWN_SCOPE: &str = "read:own-scope";

/// Capability name for the *emit:cognitive* floor capability.
pub const EMIT_COGNITIVE: &str = "emit:cognitive";

/// Capability name for the *propose:via-p9* floor capability.
pub const PROPOSE_VIA_P9: &str = "propose:via-p9";

/// The four floor capabilities as a static array, in the order they
/// appear in the design doc §3 (respond, read:own-scope, emit:cognitive,
/// propose:via-p9). Enumeration order is not load-bearing — the caps are
/// unordered as a set — but a fixed order makes their appearance in
/// prompts stable across boots, which matters for chain-anchored
/// prompt-hash comparisons.
pub const FLOOR: &[&str] = &[RESPOND, READ_OWN_SCOPE, EMIT_COGNITIVE, PROPOSE_VIA_P9];

/// Scope string for the floor capabilities. All four scope as
/// `"invariant-floor"`, indicating that the capability is KEEL-mandated
/// and not operator-configurable within this substrate binary. Extension
/// capabilities (design doc §4) will use richer scope strings.
pub const FLOOR_SCOPE: &str = "invariant-floor";

/// Build the seeded-floor delegation set for a Regent whose cognitive
/// context is being assembled at `now`.
///
/// Every call returns four fresh `DelegationSummary` values, each with
/// `granted_at = now` and no expiration. This is the substrate's
/// baseline: every Regent has these, always, from the moment of context
/// construction.
///
/// The `granted_at` uses the same clock the rest of the context uses,
/// so a receipt written later can be reasoned about against the same
/// timeline as everything else in the cycle. `expires_at = None` says
/// what it says: the floor does not expire within a Regent's lifetime.
/// Removing a floor capability requires changing this file, which
/// requires changing KEEL, which is not a runtime event.
pub fn seeded_floor(now: DateTime<Utc>) -> Vec<DelegationSummary> {
    FLOOR
        .iter()
        .map(|cap| DelegationSummary {
            capability: (*cap).to_string(),
            scope: FLOOR_SCOPE.to_string(),
            granted_at: now,
            expires_at: None,
            required_params: Vec::new(),
            optional_params: Vec::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_has_exactly_four_capabilities() {
        // A change to this count is a change to what constitutes being
        // a Regent. That is a KEEL amendment (§III.6), not a code
        // refactor. This test exists so a silent addition or removal
        // trips a red build.
        assert_eq!(
            FLOOR.len(),
            4,
            "floor size changed — KEEL amendment required, see REGENT-ONBOARDING-CEREMONY-2026-09 §3"
        );
    }

    #[test]
    fn floor_capabilities_are_the_four_named_in_the_design_doc() {
        // Names, not just count. A rename is also a KEEL-scope change.
        assert!(FLOOR.contains(&RESPOND));
        assert!(FLOOR.contains(&READ_OWN_SCOPE));
        assert!(FLOOR.contains(&EMIT_COGNITIVE));
        assert!(FLOOR.contains(&PROPOSE_VIA_P9));
    }

    #[test]
    fn seeded_floor_returns_four_delegations_each_scoped_to_invariant_floor() {
        let now = Utc::now();
        let delegations = seeded_floor(now);
        assert_eq!(delegations.len(), 4);
        for d in &delegations {
            assert_eq!(d.scope, FLOOR_SCOPE);
            assert_eq!(d.granted_at, now);
            assert!(d.expires_at.is_none(), "floor delegations do not expire");
        }
    }

    #[test]
    fn seeded_floor_capability_set_is_the_floor_capability_set() {
        let now = Utc::now();
        let delegations = seeded_floor(now);
        let mut caps: Vec<&str> = delegations.iter().map(|d| d.capability.as_str()).collect();
        caps.sort_unstable();
        let mut expected: Vec<&str> = FLOOR.to_vec();
        expected.sort_unstable();
        assert_eq!(caps, expected);
    }
}
