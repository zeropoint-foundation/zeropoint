//! Lease policy primitives for standing delegations (#197).
//!
//! A lease bounds the lifetime of a `CapabilityGrant` between explicit
//! revocation and silent expiration. The grant is alive while it is renewed
//! at the configured cadence by one of its `renewal_authorities`. When
//! renewal fails, the grant transitions through a grace period and then
//! executes its `failure_mode` (halt, degrade, or continue-with-flag).
//!
//! Lease policy is **optional** — a `CapabilityGrant` with `lease_policy:
//! None` behaves exactly as it always has, with a fixed `expires_at`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Lease parameters governing a standing delegation's lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeasePolicy {
    /// How long each lease window lasts. The grant's `expires_at` advances
    /// by this amount on each successful renewal.
    pub lease_duration: Duration,

    /// Time after `expires_at` during which renewal is still accepted but
    /// the grant is flagged as "in grace period". If the grace expires
    /// without a successful renewal, `failure_mode` fires.
    pub grace_period: Duration,

    /// How often the heartbeat client SHOULD attempt renewal. Less than
    /// `lease_duration` so a single outage doesn't expire the grant.
    pub renewal_interval: Duration,

    /// What happens when renewal fails for `max_consecutive_failures` ticks
    /// AND the grace period elapses.
    pub failure_mode: LeaseFailureMode,

    /// How many consecutive renewal failures are tolerated before grace
    /// period engages.
    pub max_consecutive_failures: u32,
}

/// What the subject node does when its lease cannot be renewed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseFailureMode {
    /// Stop processing immediately. The default — fails closed.
    #[default]
    HaltOnExpiry,

    /// Drop to Tier 0 (read-only) but keep serving read requests. Useful
    /// for zones where availability matters more than write authority.
    DegradeOnExpiry,

    /// Continue with full authority but flag the operation in receipts.
    /// Dangerous — only enabled with explicit operator opt-in. Used for
    /// air-gapped scenarios where the renewal authority is unreachable
    /// by design.
    ContinueWithFlag,
}


impl LeasePolicy {
    /// Construct a sensible default lease: 8h duration, 30min grace,
    /// 2h renewal interval, halt on expiry, 3 failures before grace.
    pub fn standard_8h() -> Self {
        Self {
            lease_duration: Duration::from_secs(8 * 60 * 60),
            grace_period: Duration::from_secs(30 * 60),
            renewal_interval: Duration::from_secs(2 * 60 * 60),
            failure_mode: LeaseFailureMode::HaltOnExpiry,
            max_consecutive_failures: 3,
        }
    }

    /// Whether `renewal_interval` is shorter than `lease_duration`. A lease
    /// where the renewal interval exceeds the duration cannot be kept alive
    /// even by perfect renewal — usually a config bug.
    pub fn is_renewable(&self) -> bool {
        self.renewal_interval < self.lease_duration
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_8h_lease_is_renewable() {
        let p = LeasePolicy::standard_8h();
        assert!(p.is_renewable());
    }

    #[test]
    fn lease_with_renewal_longer_than_duration_is_not_renewable() {
        let p = LeasePolicy {
            lease_duration: Duration::from_secs(60),
            grace_period: Duration::from_secs(10),
            renewal_interval: Duration::from_secs(120),
            failure_mode: LeaseFailureMode::HaltOnExpiry,
            max_consecutive_failures: 1,
        };
        assert!(!p.is_renewable());
    }

    #[test]
    fn failure_mode_default_is_halt() {
        assert_eq!(LeaseFailureMode::default(), LeaseFailureMode::HaltOnExpiry);
    }

    #[test]
    fn lease_policy_round_trips_through_json() {
        let p = LeasePolicy::standard_8h();
        let s = serde_json::to_string(&p).unwrap();
        let r: LeasePolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(p, r);
    }
}
