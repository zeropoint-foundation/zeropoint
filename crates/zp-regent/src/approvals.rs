//! Approval resolution — closing the loop on `Intent::RequestApproval`.
//!
//! # Why this exists
//!
//! The Regent could already ask. `Intent::RequestApproval` emits
//! `regent:intent:request_approval` to the chain and broadcasts to cockpit
//! surfaces. What did not exist was any representation of the *answer*:
//! no receipt citing the request, no pending state, nothing a later cycle
//! could read. A request was fire-and-forget, so the Regent could not
//! follow up, could not be reminded, and could not learn it had been told
//! yes.
//!
//! That is why the precedent corpus is empty. `CLAUDE.md`'s *act on
//! precedent, escalate on novelty* describes querying prior
//! operator-approved remediations — and `crates/zp-server/src/regent.rs`
//! names the query filter in a comment — but approval had no chain
//! representation, so there was never anything true to query. Building the
//! precedent query first would have produced a correct mechanism reading a
//! table that could never have rows.
//!
//! # Why resolution is an operator act, not an inference
//!
//! Resolution could have been conversational: the Regent reads "yes
//! please" and records the approval itself. That was rejected. It would
//! make the precedent corpus depend on its reading of the operator's tone,
//! which is the confabulation surface `COGNITIVE-SELF-OBSERVER` exists to
//! catch, and a single misread sentence would become permanent autonomous
//! authority.
//!
//! P9 — *the system acts; the operator signs* — settles it. Approval is a
//! signature, not a sentiment. The Regent proposes; resolution is an
//! explicit operator act carrying the request's `entry_hash`.
//!
//! # What this module does not do
//!
//! It does not implement the precedent *query*, and it does not gate any
//! autonomous action. It establishes the record those will read. A granted
//! approval here is evidence that an operator said yes to a specific
//! proposal at a specific chain position — nothing more, and deliberately
//! so, until the three-part precedent test is designed against real data.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zp_core::{AuditAction, AuditEntry};

/// Receipt the Regent emits when it asks. Already emitted today by
/// `ServerIntentExecutor` — this module reads it, it does not introduce it.
pub const EVENT_PREFIX_REQUEST: &str = "regent:intent:request_approval";

/// Operator granted the request.
pub const EVENT_PREFIX_GRANTED: &str = "regent:approval:granted";

/// Operator refused the request.
pub const EVENT_PREFIX_DENIED: &str = "regent:approval:denied";

/// How a request was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Granted,
    Denied,
}

impl Resolution {
    pub fn prefix(&self) -> &'static str {
        match self {
            Resolution::Granted => EVENT_PREFIX_GRANTED,
            Resolution::Denied => EVENT_PREFIX_DENIED,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "granted" | "grant" | "approve" | "approved" => Some(Resolution::Granted),
            "denied" | "deny" | "refuse" | "refused" => Some(Resolution::Denied),
            _ => None,
        }
    }
}

/// Compose a resolution receipt.
///
/// `request_hash` is the `entry_hash` of the `regent:intent:request_approval`
/// entry being resolved. It is the whole point of the receipt: an approval
/// that does not name what it approved is not evidence of anything.
pub fn resolution_event_string(
    resolution: Resolution,
    request_hash: &str,
    reason: Option<&str>,
    resolved_at: DateTime<Utc>,
) -> String {
    let payload = serde_json::json!({
        "request_hash": request_hash,
        "resolved_at": resolved_at.to_rfc3339(),
        "reason": reason.unwrap_or(""),
    });
    format!("{} {}", resolution.prefix(), payload)
}

/// Extract the resolved request hash from a resolution receipt.
fn parse_resolution(event: &str) -> Option<(Resolution, String)> {
    let (res, tail) = if let Some(t) = event.strip_prefix(EVENT_PREFIX_GRANTED) {
        (Resolution::Granted, t)
    } else if let Some(t) = event.strip_prefix(EVENT_PREFIX_DENIED) {
        (Resolution::Denied, t)
    } else {
        return None;
    };
    let v: serde_json::Value = serde_json::from_str(tail.trim_start()).ok()?;
    let hash = v.get("request_hash")?.as_str()?.to_string();
    Some((res, hash))
}

/// Extract the proposed action from a request receipt.
///
/// # The encoding, as it actually is
///
/// The call site reads `emit_receipt(EVENT_PREFIX_REQUEST, Some(&format!(
/// "action={}", proposed_action)))`, which is why this parser was first
/// written to expect `"{prefix} action={...}"`. It isn't that.
/// `ServerIntentExecutor::emit_receipt` joins event and detail as
/// `"{event} | {detail}"`, so what reaches the chain is:
///
/// ```text
/// regent:intent:request_approval | action=Record the operator's preferred name…
/// ```
///
/// The pipe is the house encoding for every `regent:*` receipt with a detail
/// tail, so the producer is right and this parser was wrong. Observed
/// 2026-07-31: the first real escalated proposal reached the queue and
/// rendered as `(unparsed request)` — the obligation was visible, its content
/// was not. Both forms are accepted here, because the bare form appears in
/// receipts written directly rather than through the executor, and because a
/// parser for a chain must read the history the chain already holds.
///
/// Parsed permissively: an unreadable action still yields a request. A
/// request whose text cannot be parsed is still a request awaiting an answer,
/// and dropping it would hide an outstanding obligation — which is strictly
/// worse than showing one you cannot yet read.
fn parse_request_action(event: &str) -> String {
    event
        .strip_prefix(EVENT_PREFIX_REQUEST)
        .map(|tail| {
            let tail = tail.trim_start();
            tail.strip_prefix('|').unwrap_or(tail).trim_start()
        })
        .and_then(|tail| tail.strip_prefix("action="))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "(unparsed request)".to_string())
}

#[cfg(test)]
mod request_encoding_tests {
    use super::*;

    /// The form the executor actually writes.
    #[test]
    fn reads_the_piped_form_the_executor_emits() {
        let event = "regent:intent:request_approval | action=Record the operator's \
                     preferred name as Kenrom in the standing corrections";
        assert!(parse_request_action(event).starts_with("Record the operator's"));
    }

    /// The bare form, for receipts written without the executor's joiner.
    #[test]
    fn reads_the_bare_form() {
        let event = "regent:intent:request_approval action=Grant browser_use";
        assert_eq!(parse_request_action(event), "Grant browser_use");
    }

    /// An action containing a pipe must survive — only the separator is eaten.
    #[test]
    fn keeps_pipes_inside_the_action_text() {
        let event = "regent:intent:request_approval | action=grep foo | wc -l";
        assert_eq!(parse_request_action(event), "grep foo | wc -l");
    }

    /// Unreadable is still outstanding — never dropped, never silently blank.
    #[test]
    fn unreadable_tail_still_yields_a_request() {
        for event in [
            "regent:intent:request_approval",
            "regent:intent:request_approval | ",
            "regent:intent:request_approval | action=",
            "regent:intent:request_approval | reason=something else",
        ] {
            assert_eq!(parse_request_action(event), "(unparsed request)");
        }
    }
}

/// A request and, if it has one, its answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// `entry_hash` of the request receipt — the handle for resolving it.
    pub request_hash: String,
    /// What the Regent proposed.
    pub action: String,
    /// When the Regent asked.
    pub requested_at: DateTime<Utc>,
    /// `None` while outstanding.
    pub resolution: Option<Resolution>,
    /// When it was answered.
    pub resolved_at: Option<DateTime<Utc>>,
}

impl ApprovalRequest {
    pub fn is_pending(&self) -> bool {
        self.resolution.is_none()
    }
}

/// Requests joined to their resolutions.
///
/// Same shape as `CorrectionIndex`: read both receipt families over a
/// window, join, and let the caller ask for the live set.
#[derive(Debug, Clone, Default)]
pub struct ApprovalIndex {
    requests: Vec<ApprovalRequest>,
}

impl ApprovalIndex {
    pub fn build(entries: &[AuditEntry]) -> Self {
        let mut resolutions: Vec<(Resolution, String, DateTime<Utc>)> = Vec::new();
        let mut requests: Vec<ApprovalRequest> = Vec::new();

        for e in entries {
            let AuditAction::SystemEvent { ref event } = e.action else {
                continue;
            };
            if event.starts_with(EVENT_PREFIX_REQUEST) {
                requests.push(ApprovalRequest {
                    request_hash: e.entry_hash.clone(),
                    action: parse_request_action(event),
                    requested_at: e.timestamp,
                    resolution: None,
                    resolved_at: None,
                });
            } else if let Some((res, hash)) = parse_resolution(event) {
                resolutions.push((res, hash, e.timestamp));
            }
        }

        for r in &mut requests {
            // First resolution wins. A second answer to the same request is
            // not a correction — it is a new fact about operator intent, and
            // silently letting it overwrite would make the record depend on
            // read order. Surfacing that is a later concern; determinism now.
            if let Some((res, _, at)) = resolutions
                .iter()
                .filter(|(_, h, _)| h == &r.request_hash)
                .min_by_key(|(_, _, at)| *at)
            {
                r.resolution = Some(*res);
                r.resolved_at = Some(*at);
            }
        }

        requests.sort_by_key(|r| r.requested_at);
        Self { requests }
    }

    /// Requests still awaiting an answer — newest first, since an old
    /// unanswered request is more likely stale than urgent.
    pub fn pending(&self) -> Vec<&ApprovalRequest> {
        let mut v: Vec<&ApprovalRequest> =
            self.requests.iter().filter(|r| r.is_pending()).collect();
        v.reverse();
        v
    }

    /// Every request in the window, resolved or not.
    pub fn all(&self) -> &[ApprovalRequest] {
        &self.requests
    }

    /// Granted requests — the seed of the precedent corpus, once a
    /// precedent query exists to read it.
    pub fn granted(&self) -> Vec<&ApprovalRequest> {
        self.requests
            .iter()
            .filter(|r| r.resolution == Some(Resolution::Granted))
            .collect()
    }

    /// Resolve a hash prefix to a full request hash.
    ///
    /// Operators paste short hashes. Ambiguity is an error rather than a
    /// first-match, because approving the wrong proposal is not
    /// recoverable by re-running the command.
    pub fn resolve_prefix(&self, prefix: &str) -> Result<String, String> {
        let hits: Vec<&ApprovalRequest> = self
            .requests
            .iter()
            .filter(|r| r.request_hash.starts_with(prefix))
            .collect();
        match hits.len() {
            0 => Err(format!("no approval request matching {prefix}")),
            1 => Ok(hits[0].request_hash.clone()),
            n => Err(format!(
                "{n} requests match {prefix} — use more characters"
            )),
        }
    }
}
