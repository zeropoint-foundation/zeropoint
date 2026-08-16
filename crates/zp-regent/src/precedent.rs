//! Precedent — the autonomous envelope, grown from operator signatures.
//!
//! Spec: `KEEL-2026-07.md` §III.10 ("trust corpus grows from precedent"),
//! §III.19, and the glossary definition:
//!
//! > **Precedent receipt** — chain-anchored operator-signed receipt that
//! > establishes autonomous action authority for a specific
//! > `(finding_type, remediation_verb, context_signature)` tuple. The
//! > Regent's autonomous scope is the union of currently-active precedents.
//!
//! # What precedent is not
//!
//! `emit_remediation_receipt` in `zp-server` logged "precedent established"
//! and its doc instructed future cycles to query `regent:remediation:*` to
//! decide whether autonomous action was authorised. That receipt is emitted
//! by the Regent, with `actor: System("regent")`, about its own act.
//!
//! Reading it as precedent would mean the Regent extends its own authority by
//! having acted once — the inversion of P9, and invisible, because a
//! precedent system built that way looks like it is working. §III.10 is
//! explicit that the envelope grows through *operator-signed* precedent "not
//! through declared configuration", and a self-emitted receipt is closer to
//! declared configuration than to consent.
//!
//! So precedent is sourced from `regent:approval:granted`, which carries
//! `actor: ActorId::Operator`. A remediation receipt is evidence that an act
//! happened. Only a grant is authority to repeat it.
//!
//! # Scope: exact by default, widened by declaration
//!
//! Operator decision, 2026-08-03. `context_signature` digests the *full*
//! normalised parameter set, so a signature authorises the same call and
//! nothing else. A tool may then declare fields that do not participate —
//! see [`PRECEDENT_SCOPE`] — and each such declaration widens what one
//! signature covers, which is why adding one is an operator act rather than
//! a refactor.
//!
//! The alternative considered was keying on parameter *shape*. It accrues
//! autonomy far faster and would have meant that one approved
//! `browser_use goto_url` authorised navigation to any URL — precisely the
//! failure the approval gate was added to prevent, converted into a one-time
//! toll. Narrow and slow is the right error to make here: too little
//! autonomy is an inconvenience the operator notices, too much is one they
//! do not.
//!
//! # Known incompleteness
//!
//! Two gaps, both deliberate and both worth reading before trusting this.
//!
//! **`finding_type` is absent.** KEEL's tuple has three elements; this
//! implements two. Operator-initiated proposals have no typed finding — the
//! `finding` field is free prose, which is not a key. Typed findings exist
//! for officer output (`FindingPayload`) but not for the conversational path
//! most proposals come from today. Until they do, precedent keys on
//! `(tool, context_signature)`, which is *narrower* than the specified
//! tuple, never wider: an unkeyed finding_type cannot broaden authority.
//!
//! **The chain is unsigned.** §III.10 says operator-*signed*; grants carry
//! `ActorId::Operator` but 0 of 10,018 entries observed 2026-08-01 bear a
//! signature. Precedent built now inherits that weakness — it is
//! operator-*attributed*, not operator-signed, and is exactly as strong as
//! the chain's tamper-evidence. This is not a reason to defer precedent; it
//! is a reason the signing gap is load-bearing.

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zp_core::{AuditAction, AuditEntry};

use crate::approvals::{ApprovalIndex, Resolution};
use crate::intent::Enactment;

/// Operator narrowed the autonomous envelope by withdrawing a precedent.
///
/// Per §III.10: "Revoking a precedent narrows the autonomous scope back and
/// is itself a chain event." Revocation is not deletion — the grant stays on
/// chain as the historical fact it is; this receipt says it no longer
/// authorises anything.
pub const EVENT_PREFIX_REVOKED: &str = "regent:precedent:revoked";

/// Parameters that do not participate in a tool's context signature.
///
/// Empty for every tool today, which means every precedent is exact. Adding
/// an entry widens what a single operator signature authorises for that
/// tool, permanently and for all future calls — so an addition here is a
/// change to the authority model, not a tuning knob.
///
/// The shape of a defensible entry: a field whose value cannot change what
/// the act *reaches*. `chain_compact`'s `retain` is a plausible candidate —
/// it changes how much is archived within a bounded, local, reversible
/// operation. `browser_use`'s `url` is not, and never will be.
pub const PRECEDENT_SCOPE: &[(&str, &[&str])] = &[];

/// A tuple the operator has authorised, and the signature that authorised it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Precedent {
    /// The tool. KEEL's `remediation_verb`.
    pub tool: String,
    /// Digest of the participating parameters. KEEL's `context_signature`.
    pub context_signature: String,
    /// `entry_hash` of the request the operator granted — the specific
    /// signature at the specific moment §III.10 requires every extension of
    /// autonomous scope to trace back to.
    pub granted_request: String,
    /// When the operator answered.
    pub granted_at: DateTime<Utc>,
}

/// Digest the parameters that participate in precedent for `tool`.
///
/// Canonical by construction: values are re-serialised through a `BTreeMap`
/// so key order cannot change the signature, and declared-irrelevant fields
/// are removed before hashing rather than after. A non-object `params` (null,
/// or a bare value) digests as itself — absence of parameters is a parameter
/// set, and two calls with no parameters are the same call.
pub fn context_signature(tool: &str, params: &serde_json::Value) -> String {
    let irrelevant: &[&str] = PRECEDENT_SCOPE
        .iter()
        .find(|(t, _)| *t == tool)
        .map(|(_, fields)| *fields)
        .unwrap_or(&[]);

    let canonical = match params.as_object() {
        Some(map) => {
            let kept: BTreeMap<&String, &serde_json::Value> = map
                .iter()
                .filter(|(k, _)| !irrelevant.contains(&k.as_str()))
                .collect();
            serde_json::to_string(&kept).unwrap_or_default()
        }
        None => serde_json::to_string(params).unwrap_or_default(),
    };

    let mut hasher = Sha256::new();
    hasher.update(tool.as_bytes());
    hasher.update(b"\0");
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    hex_prefix(&digest, 16)
}

fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    let mut out = String::with_capacity(chars);
    for b in bytes {
        if out.len() >= chars {
            break;
        }
        out.push_str(&format!("{b:02x}"));
    }
    out.truncate(chars);
    out
}

/// Compose a revocation receipt.
pub fn revocation_event_string(
    tool: &str,
    context_signature: &str,
    reason: Option<&str>,
    revoked_at: DateTime<Utc>,
) -> String {
    let payload = serde_json::json!({
        "tool": tool,
        "context_signature": context_signature,
        "reason": reason.unwrap_or(""),
        "revoked_at": revoked_at.to_rfc3339(),
    });
    format!("{EVENT_PREFIX_REVOKED} {payload}")
}

fn parse_revocation(event: &str) -> Option<(String, String)> {
    let tail = event.strip_prefix(EVENT_PREFIX_REVOKED)?;
    let v: serde_json::Value = serde_json::from_str(tail.trim_start()).ok()?;
    Some((
        v.get("tool")?.as_str()?.to_string(),
        v.get("context_signature")?.as_str()?.to_string(),
    ))
}

/// Does a revocation at `revoked_at` withdraw a signature given at `granted_at`?
///
/// Only if the revocation came after. A revocation withdraws the consent that
/// existed when it was made; it is not a standing ban on the call.
///
/// The first implementation removed revoked keys unconditionally, which made
/// revocation permanent and irreversible. Observed 2026-08-04: a precedent was
/// revoked, the same call was proposed and granted again, the drain enacted it
/// — the browser really did navigate — and then this index deleted the new
/// grant on the way out because the old revocation still matched the key.
/// `zp precedent list` read zero while the operator had just signed.
///
/// That failure is quiet in the worst way. The grant succeeds, the act happens
/// once through the pending-grant path, and autonomy never accrues — so the
/// operator sees a working system that simply never learns, with nothing
/// anywhere saying why.
fn revocation_supersedes(granted_at: DateTime<Utc>, revoked_at: DateTime<Utc>) -> bool {
    revoked_at >= granted_at
}

/// The Regent's current autonomous envelope.
#[derive(Debug, Clone, Default)]
pub struct PrecedentIndex {
    by_key: HashMap<(String, String), Precedent>,
}

impl PrecedentIndex {
    /// Build from chain entries.
    ///
    /// Takes the same entry slice `ApprovalIndex::build` does, and reuses it
    /// rather than re-deriving the request/resolution join: precedent is a
    /// *reading* of the approval record, not a second record beside it. If
    /// the two ever disagreed about what was granted, the operator would have
    /// no way to tell which one their signature meant.
    pub fn build(entries: &[AuditEntry]) -> Self {
        let approvals = ApprovalIndex::build(entries);

        let mut by_key: HashMap<(String, String), Precedent> = HashMap::new();
        for req in approvals.all() {
            if req.resolution != Some(Resolution::Granted) {
                continue;
            }
            // A grant with no enactment authorises nothing to repeat — the
            // operator consented to a described act the substrate has no call
            // for, and doing it remains theirs.
            let Some(Enactment { tool, params }) = req.enactment.as_ref() else {
                continue;
            };
            let sig = context_signature(tool, params);
            let at = req.resolved_at.unwrap_or(req.requested_at);
            by_key
                .entry((tool.clone(), sig.clone()))
                // Latest grant wins. This was "earliest wins" on the reasoning
                // that precedent dates from when the operator *first*
                // authorised a call — which is true only while nothing ever
                // withdraws it. Once revocation exists, the grant that matters
                // is the most recent one, because that is the one a revocation
                // has to be measured against.
                .and_modify(|p| {
                    if at > p.granted_at {
                        p.granted_at = at;
                        p.granted_request = req.request_hash.clone();
                    }
                })
                .or_insert(Precedent {
                    tool: tool.clone(),
                    context_signature: sig,
                    granted_request: req.request_hash.clone(),
                    granted_at: at,
                });
        }

        // Latest revocation per key.
        let mut revoked: HashMap<(String, String), DateTime<Utc>> = HashMap::new();
        for e in entries {
            let AuditAction::SystemEvent { ref event } = e.action else {
                continue;
            };
            if let Some(key) = parse_revocation(event) {
                revoked
                    .entry(key)
                    .and_modify(|t| {
                        if e.timestamp > *t {
                            *t = e.timestamp;
                        }
                    })
                    .or_insert(e.timestamp);
            }
        }

        // A revocation withdraws the consent that stood when it was made.
        // A signature given afterwards is new consent and stands on its own.
        by_key.retain(|key, p| match revoked.get(key) {
            Some(revoked_at) => !revocation_supersedes(p.granted_at, *revoked_at),
            None => true,
        });

        Self { by_key }
    }

    /// Does an operator signature already authorise this exact call?
    pub fn authorises(&self, tool: &str, params: &serde_json::Value) -> Option<&Precedent> {
        self.by_key
            .get(&(tool.to_string(), context_signature(tool, params)))
    }

    /// Every currently-active precedent — the autonomous envelope, entire.
    pub fn active(&self) -> Vec<&Precedent> {
        let mut v: Vec<&Precedent> = self.by_key.values().collect();
        v.sort_by(|a, b| a.granted_at.cmp(&b.granted_at));
        v
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_order_independent() {
        let a = serde_json::json!({"url": "https://x.test", "action": "goto_url"});
        let b = serde_json::json!({"action": "goto_url", "url": "https://x.test"});
        assert_eq!(
            context_signature("browser_use", &a),
            context_signature("browser_use", &b)
        );
    }

    /// The decision that makes this safe: a different URL is a different act.
    #[test]
    fn differing_values_do_not_share_precedent() {
        let a = serde_json::json!({"action": "goto_url", "url": "https://x.test"});
        let b = serde_json::json!({"action": "goto_url", "url": "https://evil.test"});
        assert_ne!(
            context_signature("browser_use", &a),
            context_signature("browser_use", &b)
        );
    }

    #[test]
    fn the_same_params_under_different_tools_differ() {
        let p = serde_json::json!({"retain": 1000});
        assert_ne!(
            context_signature("chain_compact", &p),
            context_signature("batch_sign", &p)
        );
    }

    #[test]
    fn absent_params_are_a_parameter_set() {
        let a = serde_json::json!({});
        let b = serde_json::json!({});
        assert_eq!(
            context_signature("system_status", &a),
            context_signature("system_status", &b)
        );
    }

    #[test]
    fn revocation_round_trips() {
        let at = DateTime::parse_from_rfc3339("2026-08-03T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let s = revocation_event_string("browser_use", "abc123", Some("scope creep"), at);
        assert!(s.starts_with(EVENT_PREFIX_REVOKED));
        let (tool, sig) = parse_revocation(&s).expect("parses");
        assert_eq!(tool, "browser_use");
        assert_eq!(sig, "abc123");
    }

    /// Revocation withdraws what stood at the time; it is not a permanent ban.
    #[test]
    fn a_later_grant_survives_an_earlier_revocation() {
        let t = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        // granted, then revoked → withdrawn
        assert!(revocation_supersedes(
            t("2026-08-04T10:00:00Z"),
            t("2026-08-04T11:00:00Z")
        ));
        // revoked, then granted again → stands
        assert!(!revocation_supersedes(
            t("2026-08-04T12:00:00Z"),
            t("2026-08-04T11:00:00Z")
        ));
    }

    /// Same instant resolves against the grant: a revocation is a deliberate
    /// operator act, and ambiguity should fall on the side of less authority.
    #[test]
    fn a_tie_goes_to_the_revocation() {
        let at = DateTime::parse_from_rfc3339("2026-08-04T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(revocation_supersedes(at, at));
    }

    #[test]
    fn an_empty_chain_authorises_nothing() {
        let idx = PrecedentIndex::build(&[]);
        assert!(idx.is_empty());
        assert!(idx
            .authorises("browser_use", &serde_json::json!({"url": "https://x.test"}))
            .is_none());
    }
}
