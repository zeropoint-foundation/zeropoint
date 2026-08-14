//! Officer findings — the structured output of officer sweeps and watches.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Severity level for officer findings.
///
/// # Which severity governs what (DECIDED-004 MEANWHILE-3, 2026-08-12)
///
/// Two thresholds govern the Regent's response to findings. They are
/// deliberately different, and before this declaration there were five
/// unnamed sites disagreeing about which was "urgent":
///
/// - [`Severity::ATTENTION_FLOOR`] (`Error`) — **is this worth thinking
///   about?** A cycle that is *already running* reasons rather than observes,
///   and the autonomous-remediation prompt fires. Ask via
///   [`Severity::demands_attention`].
/// - [`Severity::INTERRUPT_FLOOR`] (`Critical`) — **is this worth interrupting
///   for?** Preempts the timer to force an out-of-band cycle, and survives
///   context compression while the operator is mid-conversation. Ask via
///   [`Severity::interrupts`].
///
/// The pairing is the point: `Error` means the Regent should *consider* it on
/// the next tick; `Critical` means it should not wait for one. Anything that
/// reads a severity to make a decision calls one of the two predicates. Do not
/// open-code the comparison — `severity_thresholds_have_one_source` in
/// `zp-discipline` fails the build if you do.
///
/// # On the two string forms
///
/// This enum has *two* textual spellings and they differ. `serde` emits
/// snake_case (`"error"`); [`Severity::as_context_str`] emits the `Debug`
/// spelling (`"Error"`), which is what `FindingSummary::severity` has always
/// carried onto the chain. Both are load-bearing and neither may drift:
/// composition receipts written before today hold the capitalised form, and
/// the chain is append-only, so they are history rather than a migration
/// target. `as_context_str` exists so that spelling is a pinned function with
/// a round-trip test rather than an incidental `format!("{:?}")` — swapping
/// that call for serde would have silently made every urgency check false,
/// with no compiler complaint. See PIN-002.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Routine check passed. Chain-only, no notification.
    Ok,
    /// Something worth noting but not actionable.
    Info,
    /// Degraded state that may require attention.
    Warning,
    /// Integrity or security violation requiring operator attention.
    ///
    /// At [`Severity::ATTENTION_FLOOR`]: the Regent reasons about this on a
    /// cycle it was already going to run. It does not start one.
    Error,
    /// Active compromise or data loss indicator.
    ///
    /// At [`Severity::INTERRUPT_FLOOR`]: the Regent starts a cycle for this,
    /// and it survives compression while the operator is speaking.
    Critical,
}

impl Severity {
    /// Worth thinking about on a cycle already in flight. See the type docs.
    pub const ATTENTION_FLOOR: Severity = Severity::Error;

    /// Worth starting a cycle for. See the type docs.
    pub const INTERRUPT_FLOOR: Severity = Severity::Critical;

    /// Does this finding make an in-flight cycle reason rather than observe?
    pub fn demands_attention(self) -> bool {
        self >= Self::ATTENTION_FLOOR
    }

    /// Does this finding justify preempting the timer?
    pub fn interrupts(self) -> bool {
        self >= Self::INTERRUPT_FLOOR
    }

    /// The spelling carried in `FindingSummary::severity` and thence onto the
    /// chain. Identical to `format!("{:?}", self)` — see the round-trip test.
    ///
    /// Pinned deliberately: this is a wire format with history behind it, not
    /// a display choice.
    pub fn as_context_str(self) -> &'static str {
        match self {
            Severity::Ok => "Ok",
            Severity::Info => "Info",
            Severity::Warning => "Warning",
            Severity::Error => "Error",
            Severity::Critical => "Critical",
        }
    }

    /// Inverse of [`Severity::as_context_str`].
    ///
    /// Returns `None` for anything unrecognised rather than guessing. Callers
    /// deciding urgency must treat `None` as *attention-demanding*, not as
    /// benign — an unparseable severity is a defect, and per KEEL §III.19
    /// silence is the enemy. Failing loud here is the whole point.
    pub fn from_context_str(s: &str) -> Option<Severity> {
        match s {
            "Ok" => Some(Severity::Ok),
            "Info" => Some(Severity::Info),
            "Warning" => Some(Severity::Warning),
            "Error" => Some(Severity::Error),
            "Critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

/// A single finding emitted by an officer.
///
/// Findings are the unit of officer output. Each becomes a chain receipt
/// with event format `officer:{officer_name}:{domain}:{finding_type}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Which officer emitted this finding.
    pub officer: &'static str,
    /// Domain of the finding (integrity, security, operations).
    pub domain: &'static str,
    /// Machine-readable finding type (e.g., "hash_discontinuity", "gap_detected").
    pub finding_type: String,
    /// Severity level.
    pub severity: Severity,
    /// Human-readable summary.
    pub summary: String,
    /// Machine-readable detail for downstream consumers.
    pub detail: serde_json::Value,
    /// When this finding was produced.
    pub timestamp: DateTime<Utc>,
    /// Cross-domain depth counter for loop prevention.
    /// Starts at 0 for original findings. Incremented when a finding
    /// triggers a cross-domain officer activation.
    pub cross_domain_depth: u32,
}

impl Finding {
    /// Build the chain event string: `officer:{name}:{domain}:{type}`.
    pub fn event_key(&self) -> String {
        format!(
            "officer:{}:{}:{}",
            self.officer, self.domain, self.finding_type
        )
    }
}

#[cfg(test)]
mod severity_threshold_tests {
    use super::Severity;

    const ALL: [Severity; 5] = [
        Severity::Ok,
        Severity::Info,
        Severity::Warning,
        Severity::Error,
        Severity::Critical,
    ];

    /// `as_context_str` must stay byte-identical to the `Debug` spelling.
    ///
    /// This is the pin that matters. `FindingSummary::from_finding_at` used
    /// `format!("{:?}")` for the whole life of the chain, so every historical
    /// composition receipt holds the capitalised form. `Severity` also derives
    /// `Serialize` with `rename_all = "snake_case"`, so the *other* obvious
    /// spelling is `"error"`. If someone swaps the formatter for serde — a
    /// reasonable-looking change, since snake_case is the declared wire form —
    /// every downstream `demands_attention` goes permanently false and nothing
    /// fails. This test is what fails instead.
    #[test]
    fn context_str_matches_debug_spelling() {
        for s in ALL {
            assert_eq!(
                s.as_context_str(),
                format!("{s:?}"),
                "as_context_str drifted from Debug for {s:?}. If this was \
                 deliberate, every FindingSummary on the chain still holds the \
                 old spelling — see Severity's type docs before changing it."
            );
        }
    }

    #[test]
    fn context_str_round_trips() {
        for s in ALL {
            assert_eq!(Severity::from_context_str(s.as_context_str()), Some(s));
        }
    }

    /// Unrecognised spellings are rejected rather than guessed at, including
    /// the snake_case serde form — callers treat `None` as urgent.
    #[test]
    fn unknown_severity_is_none_not_a_guess() {
        assert_eq!(Severity::from_context_str("error"), None);
        assert_eq!(Severity::from_context_str("critical"), None);
        assert_eq!(Severity::from_context_str(""), None);
    }

    /// The two thresholds are distinct and ordered. If these ever collapse,
    /// "think about it" and "wake up for it" have become the same decision and
    /// the pairing in the type docs is a lie.
    #[test]
    fn the_two_thresholds_are_distinct_and_ordered() {
        assert!(Severity::ATTENTION_FLOOR < Severity::INTERRUPT_FLOOR);

        assert!(!Severity::Warning.demands_attention());
        assert!(Severity::Error.demands_attention());
        assert!(Severity::Critical.demands_attention());

        assert!(!Severity::Error.interrupts());
        assert!(Severity::Critical.interrupts());

        // Anything that interrupts also deserves attention. The converse is
        // exactly the gap between the two floors.
        for s in ALL {
            assert!(!s.interrupts() || s.demands_attention());
        }
    }
}
