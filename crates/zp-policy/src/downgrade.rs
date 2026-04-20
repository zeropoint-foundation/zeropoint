//! Downgrade resistance — monotonic policy version enforcement.
//!
//! Phase 3.5 (R6-4): Prevents rollback to a prior, less restrictive policy
//! version. Policy configurations carry a monotonically increasing version
//! number. The policy engine refuses to load a configuration whose version
//! is lower than the currently active version.
//!
//! ## Design
//!
//! Each policy configuration (native rule set or WASM module manifest)
//! includes a `PolicyVersion`. The `DowngradeGuard` tracks the highest
//! version seen and rejects any attempt to load a lower version.
//!
//! The version is part of the signed module metadata and cannot be forged
//! without the signing key. This prevents an attacker who gains temporary
//! access from rolling back to a more permissive policy.
//!
//! ## Example
//!
//! ```rust
//! use zp_policy::downgrade::{DowngradeGuard, PolicyVersion};
//!
//! let mut guard = DowngradeGuard::new();
//!
//! // First policy load sets the baseline.
//! assert!(guard.check_and_advance(PolicyVersion::new(1, 0, 0)).is_ok());
//!
//! // Upgrade is allowed.
//! assert!(guard.check_and_advance(PolicyVersion::new(2, 0, 0)).is_ok());
//!
//! // Downgrade is rejected.
//! assert!(guard.check_and_advance(PolicyVersion::new(1, 5, 0)).is_err());
//!
//! // Same version is allowed (idempotent reload).
//! assert!(guard.check_and_advance(PolicyVersion::new(2, 0, 0)).is_ok());
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use tracing::{info, warn};

// ============================================================================
// Policy version
// ============================================================================

/// A semantic version for policy configurations.
///
/// Follows semver ordering: major > minor > patch.
/// Only forward movement is allowed (monotonically increasing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl PolicyVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// The initial version (0.0.0) — used when no policy has been loaded yet.
    pub fn zero() -> Self {
        Self::new(0, 0, 0)
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ============================================================================
// Downgrade error
// ============================================================================

/// Error returned when a policy downgrade is attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DowngradeError {
    /// The version that was rejected.
    pub attempted: PolicyVersion,
    /// The current minimum allowed version.
    pub current: PolicyVersion,
}

impl fmt::Display for DowngradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Policy downgrade rejected: attempted v{} but minimum is v{}",
            self.attempted, self.current
        )
    }
}

impl std::error::Error for DowngradeError {}

// ============================================================================
// Downgrade guard
// ============================================================================

/// Monotonic version guard that prevents policy downgrades.
///
/// Once a policy version is loaded, no lower version can be loaded.
/// Same-version reloads are allowed (idempotent).
#[derive(Debug, Clone)]
pub struct DowngradeGuard {
    /// The highest policy version that has been successfully loaded.
    current_version: PolicyVersion,
    /// History of version transitions (for audit).
    version_history: Vec<VersionTransition>,
}

/// A record of a version transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionTransition {
    pub from: PolicyVersion,
    pub to: PolicyVersion,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl DowngradeGuard {
    /// Create a new guard with no version loaded (starts at 0.0.0).
    pub fn new() -> Self {
        Self {
            current_version: PolicyVersion::zero(),
            version_history: Vec::new(),
        }
    }

    /// Create a guard pre-loaded at a specific version.
    ///
    /// Use this when restoring from a checkpoint or reconstitution.
    pub fn with_version(version: PolicyVersion) -> Self {
        Self {
            current_version: version,
            version_history: Vec::new(),
        }
    }

    /// Check if a version is allowed and advance the guard if so.
    ///
    /// Returns `Ok(())` if the version is >= the current version.
    /// Returns `Err(DowngradeError)` if the version is lower.
    pub fn check_and_advance(&mut self, version: PolicyVersion) -> Result<(), DowngradeError> {
        if version < self.current_version {
            warn!(
                attempted = %version,
                current = %self.current_version,
                "Policy downgrade rejected"
            );
            return Err(DowngradeError {
                attempted: version,
                current: self.current_version,
            });
        }

        if version > self.current_version {
            let transition = VersionTransition {
                from: self.current_version,
                to: version,
                timestamp: chrono::Utc::now(),
            };

            info!(
                from = %self.current_version,
                to = %version,
                "Policy version advanced"
            );

            self.version_history.push(transition);
            self.current_version = version;
        }

        Ok(())
    }

    /// Check if a version is allowed without advancing the guard.
    pub fn is_allowed(&self, version: PolicyVersion) -> bool {
        version >= self.current_version
    }

    /// Get the current (minimum allowed) version.
    pub fn current_version(&self) -> PolicyVersion {
        self.current_version
    }

    /// Get the version transition history.
    pub fn history(&self) -> &[VersionTransition] {
        &self.version_history
    }
}

impl Default for DowngradeGuard {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_version_is_zero() {
        let guard = DowngradeGuard::new();
        assert_eq!(guard.current_version(), PolicyVersion::zero());
    }

    #[test]
    fn first_load_sets_baseline() {
        let mut guard = DowngradeGuard::new();
        assert!(guard.check_and_advance(PolicyVersion::new(1, 0, 0)).is_ok());
        assert_eq!(guard.current_version(), PolicyVersion::new(1, 0, 0));
    }

    #[test]
    fn upgrade_allowed() {
        let mut guard = DowngradeGuard::new();
        guard.check_and_advance(PolicyVersion::new(1, 0, 0)).unwrap();
        assert!(guard.check_and_advance(PolicyVersion::new(2, 0, 0)).is_ok());
        assert_eq!(guard.current_version(), PolicyVersion::new(2, 0, 0));
    }

    #[test]
    fn minor_upgrade_allowed() {
        let mut guard = DowngradeGuard::new();
        guard.check_and_advance(PolicyVersion::new(1, 0, 0)).unwrap();
        assert!(guard.check_and_advance(PolicyVersion::new(1, 1, 0)).is_ok());
    }

    #[test]
    fn patch_upgrade_allowed() {
        let mut guard = DowngradeGuard::new();
        guard.check_and_advance(PolicyVersion::new(1, 2, 3)).unwrap();
        assert!(guard.check_and_advance(PolicyVersion::new(1, 2, 4)).is_ok());
    }

    #[test]
    fn same_version_allowed_idempotent() {
        let mut guard = DowngradeGuard::new();
        guard.check_and_advance(PolicyVersion::new(1, 0, 0)).unwrap();
        assert!(guard.check_and_advance(PolicyVersion::new(1, 0, 0)).is_ok());
        // No history entry for same-version reload
        assert_eq!(guard.history().len(), 1); // Only the 0.0.0 → 1.0.0 transition
    }

    #[test]
    fn major_downgrade_rejected() {
        let mut guard = DowngradeGuard::new();
        guard.check_and_advance(PolicyVersion::new(2, 0, 0)).unwrap();

        let err = guard.check_and_advance(PolicyVersion::new(1, 0, 0)).unwrap_err();
        assert_eq!(err.attempted, PolicyVersion::new(1, 0, 0));
        assert_eq!(err.current, PolicyVersion::new(2, 0, 0));
    }

    #[test]
    fn minor_downgrade_rejected() {
        let mut guard = DowngradeGuard::new();
        guard.check_and_advance(PolicyVersion::new(1, 5, 0)).unwrap();

        assert!(guard.check_and_advance(PolicyVersion::new(1, 4, 0)).is_err());
    }

    #[test]
    fn patch_downgrade_rejected() {
        let mut guard = DowngradeGuard::new();
        guard.check_and_advance(PolicyVersion::new(1, 2, 5)).unwrap();

        assert!(guard.check_and_advance(PolicyVersion::new(1, 2, 4)).is_err());
    }

    #[test]
    fn is_allowed_without_advancing() {
        let mut guard = DowngradeGuard::new();
        guard.check_and_advance(PolicyVersion::new(2, 0, 0)).unwrap();

        assert!(guard.is_allowed(PolicyVersion::new(2, 0, 0)));
        assert!(guard.is_allowed(PolicyVersion::new(3, 0, 0)));
        assert!(!guard.is_allowed(PolicyVersion::new(1, 0, 0)));
    }

    #[test]
    fn version_history_tracked() {
        let mut guard = DowngradeGuard::new();
        guard.check_and_advance(PolicyVersion::new(1, 0, 0)).unwrap();
        guard.check_and_advance(PolicyVersion::new(2, 0, 0)).unwrap();
        guard.check_and_advance(PolicyVersion::new(3, 0, 0)).unwrap();

        let history = guard.history();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].from, PolicyVersion::zero());
        assert_eq!(history[0].to, PolicyVersion::new(1, 0, 0));
        assert_eq!(history[1].from, PolicyVersion::new(1, 0, 0));
        assert_eq!(history[1].to, PolicyVersion::new(2, 0, 0));
    }

    #[test]
    fn with_version_sets_baseline() {
        let mut guard = DowngradeGuard::with_version(PolicyVersion::new(5, 0, 0));
        assert_eq!(guard.current_version(), PolicyVersion::new(5, 0, 0));

        assert!(guard.check_and_advance(PolicyVersion::new(4, 0, 0)).is_err());
        assert!(guard.check_and_advance(PolicyVersion::new(5, 0, 0)).is_ok());
        assert!(guard.check_and_advance(PolicyVersion::new(6, 0, 0)).is_ok());
    }

    #[test]
    fn version_display() {
        assert_eq!(PolicyVersion::new(1, 2, 3).to_string(), "1.2.3");
        assert_eq!(PolicyVersion::zero().to_string(), "0.0.0");
    }

    #[test]
    fn version_ordering() {
        assert!(PolicyVersion::new(2, 0, 0) > PolicyVersion::new(1, 0, 0));
        assert!(PolicyVersion::new(1, 1, 0) > PolicyVersion::new(1, 0, 0));
        assert!(PolicyVersion::new(1, 0, 1) > PolicyVersion::new(1, 0, 0));
        assert!(PolicyVersion::new(1, 0, 0) == PolicyVersion::new(1, 0, 0));
    }

    #[test]
    fn downgrade_error_display() {
        let err = DowngradeError {
            attempted: PolicyVersion::new(1, 0, 0),
            current: PolicyVersion::new(2, 0, 0),
        };
        let msg = err.to_string();
        assert!(msg.contains("1.0.0"));
        assert!(msg.contains("2.0.0"));
        assert!(msg.contains("rejected"));
    }
}
