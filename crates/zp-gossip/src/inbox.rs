//! Reception-side intake limiter — Zone 3 property.
//!
//! Every Regent independently caps how many findings she processes per
//! unit time. This is the load-bearing defense of the listen-twice
//! principle (§5.1): you cannot force someone else to listen faster.

use std::collections::{HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};

use crate::finding::{ContentHash, GossipFinding};

/// Result of attempting to receive a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveResult {
    /// Finding accepted into the pending queue.
    Accepted,
    /// Finding already seen (content-addressed dedup).
    Duplicate,
    /// Intake rate limit reached for this window.
    RateLimited,
}

/// The gossip inbox — reception, dedup, and intake limiting.
///
/// The intake rate is a **Zone 3 constitutional property**. It is not
/// configurable via `config.toml`, not tunable by the operator, and not
/// adjustable by the Regent herself. Changing it requires the five-step
/// constitutional amendment ceremony.
pub struct FindingInbox {
    /// Findings awaiting verification.
    pending: VecDeque<GossipFinding>,
    /// Content hashes of all findings ever seen (dedup).
    seen: HashSet<ContentHash>,
    /// Findings processed in the current window.
    processed_this_window: u64,
    /// Current window start.
    window_start: DateTime<Utc>,
}

impl FindingInbox {
    /// Zone 3 constant: maximum findings processed per hour.
    ///
    /// This is NOT configurable. It is the reception-side enforcement
    /// of the listen-twice principle (§5.1 of the gossip design).
    /// A spammer's flood hits this limiter at every recipient independently.
    const CONSTITUTIONAL_INTAKE_RATE: u64 = 12;

    /// Zone 3 constant: intake window duration.
    const WINDOW_DURATION_SECS: i64 = 3600;

    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            seen: HashSet::new(),
            processed_this_window: 0,
            window_start: Utc::now(),
        }
    }

    /// Receive a finding from a peer.
    ///
    /// Applies dedup (content-addressed) and intake limiting (Zone 3).
    pub fn receive(&mut self, finding: GossipFinding) -> ReceiveResult {
        // Dedup by content hash — same finding from multiple paths is fine.
        if self.seen.contains(&finding.finding_id) {
            return ReceiveResult::Duplicate;
        }

        // Intake limiting (Zone 3 — constitutional, not configurable).
        self.refresh_window();
        if self.processed_this_window >= Self::CONSTITUTIONAL_INTAKE_RATE {
            return ReceiveResult::RateLimited;
        }

        self.seen.insert(finding.finding_id.clone());
        self.pending.push_back(finding);
        self.processed_this_window += 1;
        ReceiveResult::Accepted
    }

    /// Next finding ready for verification (caller spends compute allowance).
    pub fn next_for_verification(&mut self) -> Option<GossipFinding> {
        self.pending.pop_front()
    }

    /// How many findings are waiting for verification.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// How many distinct findings have been seen (lifetime).
    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }

    /// How many findings have been processed in the current window.
    pub fn processed_this_window(&self) -> u64 {
        self.processed_this_window
    }

    /// Remaining intake capacity in the current window.
    pub fn remaining_capacity(&self) -> u64 {
        Self::CONSTITUTIONAL_INTAKE_RATE.saturating_sub(self.processed_this_window)
    }

    /// Roll the window forward if the current one has expired.
    fn refresh_window(&mut self) {
        let now = Utc::now();
        if now - self.window_start > Duration::seconds(Self::WINDOW_DURATION_SECS) {
            self.window_start = now;
            self.processed_this_window = 0;
        }
    }
}

impl Default for FindingInbox {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::*;

    fn make_finding(task: &str) -> GossipFinding {
        GossipFinding::new(
            FindingType::ModelPromptCoupling,
            "qwen3".to_string(),
            Some("8b".to_string()),
            FindingPayload::ModelPromptCoupling {
                task: task.to_string(),
                result: CouplingResult::Pass,
                prompt_hash: "test".to_string(),
                conditions: vec![],
            },
            "0.42.0".to_string(),
            format!("receipt_{}", task),
            0.9,
        )
    }

    #[test]
    fn dedup_by_content_hash() {
        let mut inbox = FindingInbox::new();
        let f = make_finding("sovereign_identity");
        assert_eq!(inbox.receive(f.clone()), ReceiveResult::Accepted);
        assert_eq!(inbox.receive(f), ReceiveResult::Duplicate);
    }

    #[test]
    fn intake_rate_limiting() {
        let mut inbox = FindingInbox::new();
        for i in 0..12 {
            let r = inbox.receive(make_finding(&format!("task_{}", i)));
            assert_eq!(r, ReceiveResult::Accepted);
        }
        // 13th should be rate-limited
        assert_eq!(
            inbox.receive(make_finding("task_overflow")),
            ReceiveResult::RateLimited
        );
    }

    #[test]
    fn next_for_verification_drains() {
        let mut inbox = FindingInbox::new();
        inbox.receive(make_finding("task_a"));
        inbox.receive(make_finding("task_b"));
        assert_eq!(inbox.pending_count(), 2);
        let _ = inbox.next_for_verification();
        assert_eq!(inbox.pending_count(), 1);
    }
}
