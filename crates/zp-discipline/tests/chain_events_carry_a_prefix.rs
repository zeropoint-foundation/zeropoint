//! Discipline: a chain event string starts with a receipt-type prefix.
//!
//! # The rule
//!
//! Every `AuditAction::SystemEvent { event }` follows `prefix + space + JSON`:
//!
//! ```text
//! cognitive:correction:violated {"correction_id":"…","severity":"critical"}
//! chain:canary:written 019fd4…
//! delegation:revoked:kenrom
//! ```
//!
//! The prefix is the receipt's *identity*. It is what `substrate_validate`
//! partitions the chain by, what `search_chain_by_action_keyword` scopes
//! against, and what the receipt-type inventory counts. A payload field named
//! `receipt_type` is documentation; the leading token is the thing every
//! consumer actually reads.
//!
//! # Why this is pinned — 2026-08-06
//!
//! Two independent subsystems had drifted to emitting the whole event as bare
//! JSON, with no prefix at all:
//!
//! - `regent:inference:classifier_decision` (Layer 2 inference routing)
//! - `emission_coherence:finding` / `:summary`
//!
//! Both computed the correct canonical receipt type and then put it *inside*
//! the payload rather than in the prefix position. `ClassifierDecision` even
//! has a `receipt_type()` method with a format test pinning its shape — the
//! right value, computed, and then not used for the one thing it was named for.
//!
//! The consequence is silent. A bare-JSON event still appends, still signs,
//! still verifies; the chain is intact. But the inventory takes the leading
//! token as the prefix, so these registered as `{"chosen_model"` and
//! `{"class"` — serde sorts keys, so the bucket name is whichever field
//! happens to sort first — and no prefix-scoped query could see them. They were
//! invisible for as long as those subsystems had been running, and surfaced
//! only because a posture check narrated the inventory out loud and the numbers
//! did not add up.
//!
//! That is the argument for a pin rather than two fixes. The same drift
//! occurred twice, independently, in the same file, with no test able to fail.
//!
//! # What this catches
//!
//! An event bound directly from a serializer: `let event =
//! serde_json::to_string(…)`. The healthy form binds a `payload` and wraps it —
//! `let event = format!("{} {}", PREFIX, payload)` — which this does not match.
//!
//! # What this does not catch
//!
//! Structural only. A `format!` whose prefix is misspelled, undeclared in
//! `KNOWN_RECEIPT_PREFIXES`, or accidentally empty passes here and is caught
//! downstream by `substrate_validate`'s unrecognized-prefix report. Between the
//! two, the pin covers the shape and the inventory covers the vocabulary.

use zp_discipline::Discipline;

#[test]
fn no_bare_json_chain_events() {
    Discipline::new("no_bare_json_chain_events")
        .cite_invariant("P6 (a tool is intent, crystallized) / P8 (one canonical path)")
        .rationale(
            "A SystemEvent must be `prefix + space + JSON`. Binding an event \
             directly from serde_json::to_string emits bare JSON, and the \
             receipt-type inventory then takes the first serialized key as the \
             prefix — so the receipt is unreachable by every prefix-scoped \
             query while still appending and verifying normally. Build the \
             payload, then wrap it: format!(\"{} {}\", PREFIX, payload).",
        )
        .forbid_pattern(r"let\s+[a-z_]*event[a-z_]*\s*=\s*serde_json::to_string")
        .forbid_pattern(r"let\s+[a-z_]*event[a-z_]*\s*=\s*match\s+serde_json::to_string")
        // The pin names the pattern it forbids, so its own source contains it.
        // zp-discipline holds the scanner and the pins and no production code.
        .allow_path("crates/zp-discipline/")
        .skip_lines_containing("//")
        .assert();
}
