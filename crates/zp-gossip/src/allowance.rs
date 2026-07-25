//! Two-allowance model — social (broadcast rate) and compute (inference budget).
//!
//! The listen-twice ratio emerges from the relationship between social
//! allowance regeneration rate and minimum broadcast cost (both Zone 3).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Error when an allowance operation fails.
#[derive(Debug, thiserror::Error)]
pub enum AllowanceError {
    #[error("insufficient allowance: need {needed:.2}, have {available:.2}")]
    Insufficient { needed: f64, available: f64 },
}

// ── Social Allowance ──────────────────────────────────────────────

/// Controls the rate at which a Regent broadcasts findings.
///
/// Listening is free. Speaking costs allowance proportional to the
/// broadcast cost floor (2 × regen_rate — the Zone 3 invariant that
/// makes the listen-twice ratio a conservation law).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialAllowance {
    /// Current pool (units).
    pub current: f64,
    /// Maximum pool size.
    pub max_pool: f64,
    /// Regeneration rate (units per hour).
    pub regen_rate: f64,
    /// Last regeneration timestamp.
    pub last_regen: DateTime<Utc>,
}

impl SocialAllowance {
    /// Create with default configuration.
    pub fn new(regen_rate: f64, max_pool: f64) -> Self {
        Self {
            current: max_pool, // start full
            max_pool,
            regen_rate,
            last_regen: Utc::now(),
        }
    }

    /// Default: 1 unit/hour, 24-unit pool.
    pub fn default_config() -> Self {
        Self::new(1.0, 24.0)
    }

    /// Minimum cost to broadcast a finding.
    ///
    /// **Zone 3 invariant:** minimum cost = 2 × regen_rate.
    /// This makes the listen-twice ratio a conservation law, not a
    /// tunable parameter. Changing it requires the five-step
    /// constitutional amendment ceremony.
    pub fn broadcast_cost(&self) -> f64 {
        2.0 * self.regen_rate
    }

    /// Regenerate allowance based on elapsed time since last regen.
    pub fn regenerate(&mut self) {
        let now = Utc::now();
        let elapsed_hours = (now - self.last_regen).num_seconds() as f64 / 3600.0;
        if elapsed_hours > 0.0 {
            self.current = (self.current + elapsed_hours * self.regen_rate).min(self.max_pool);
            self.last_regen = now;
        }
    }

    /// Whether the Regent can afford to broadcast.
    pub fn can_broadcast(&self) -> bool {
        self.current >= self.broadcast_cost()
    }

    /// Spend allowance on a broadcast. Returns cost spent.
    pub fn spend(&mut self) -> Result<f64, AllowanceError> {
        self.regenerate();
        let cost = self.broadcast_cost();
        if self.current < cost {
            return Err(AllowanceError::Insufficient {
                needed: cost,
                available: self.current,
            });
        }
        self.current -= cost;
        Ok(cost)
    }

    /// Current utilization (0.0 = empty, 1.0 = full).
    pub fn utilization(&self) -> f64 {
        if self.max_pool == 0.0 {
            0.0
        } else {
            self.current / self.max_pool
        }
    }
}

// ── Compute Allowance ─────────────────────────────────────────────

/// Controls exploratory inference budget (model evaluation, gossip
/// verification, prompt variant testing).
///
/// Regenerates based on idle time — the Regent earns compute allowance
/// when the operator isn't actively using the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeAllowance {
    /// Current pool (inference-seconds).
    pub current: f64,
    /// Maximum pool size.
    pub max_pool: f64,
    /// Base regeneration rate (units per idle-hour).
    pub regen_rate: f64,
    /// Multiplier during declared maintenance windows.
    pub maintenance_multiplier: f64,
    /// Last regeneration timestamp.
    pub last_regen: DateTime<Utc>,
    /// Whether the system is currently in a maintenance window.
    pub in_maintenance: bool,
}

impl ComputeAllowance {
    /// Create with default configuration.
    pub fn new(regen_rate: f64, max_pool: f64) -> Self {
        Self {
            current: max_pool,
            max_pool,
            regen_rate,
            maintenance_multiplier: 3.0,
            last_regen: Utc::now(),
            in_maintenance: false,
        }
    }

    /// Default: 1 unit/idle-hour, 10-unit pool.
    pub fn default_config() -> Self {
        Self::new(1.0, 10.0)
    }

    /// Regenerate based on idle time elapsed.
    pub fn regenerate(&mut self, idle_seconds: f64) {
        let idle_hours = idle_seconds / 3600.0;
        let effective_rate = if self.in_maintenance {
            self.regen_rate * self.maintenance_multiplier
        } else {
            self.regen_rate
        };
        self.current = (self.current + idle_hours * effective_rate).min(self.max_pool);
        self.last_regen = Utc::now();
    }

    /// Whether there's enough budget for a verification run.
    pub fn can_verify(&self, estimated_cost: f64) -> bool {
        self.current >= estimated_cost
    }

    /// Spend compute allowance. Returns actual cost spent.
    pub fn spend(&mut self, cost: f64) -> Result<f64, AllowanceError> {
        if self.current < cost {
            return Err(AllowanceError::Insufficient {
                needed: cost,
                available: self.current,
            });
        }
        self.current -= cost;
        Ok(cost)
    }

    /// Current utilization (0.0 = empty, 1.0 = full).
    pub fn utilization(&self) -> f64 {
        if self.max_pool == 0.0 {
            0.0
        } else {
            self.current / self.max_pool
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_twice_ratio() {
        let sa = SocialAllowance::default_config();
        // broadcast_cost should be 2× regen_rate
        assert_eq!(sa.broadcast_cost(), 2.0 * sa.regen_rate);
    }

    #[test]
    fn spend_reduces_pool() {
        let mut sa = SocialAllowance::new(1.0, 24.0);
        sa.current = 5.0;
        let cost = sa.spend().unwrap();
        assert_eq!(cost, 2.0);
        assert!((sa.current - 3.0).abs() < 0.01);
    }

    #[test]
    fn insufficient_allowance_errors() {
        let mut sa = SocialAllowance::new(1.0, 24.0);
        sa.current = 1.0; // less than broadcast_cost (2.0)
        assert!(sa.spend().is_err());
    }

    #[test]
    fn compute_maintenance_multiplier() {
        let mut ca = ComputeAllowance::new(1.0, 10.0);
        ca.current = 0.0;
        ca.in_maintenance = true;
        ca.regenerate(3600.0); // 1 hour idle
        // Should regenerate at 3× rate = 3.0 units
        assert!((ca.current - 3.0).abs() < 0.01);
    }
}
