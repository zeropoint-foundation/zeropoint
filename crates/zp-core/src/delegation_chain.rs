//! Delegation chain verification — validates a chain of capability grants
//! from the root (original grant) to the leaf (most-delegated grant).
//!
//! A valid delegation chain ensures:
//! 1. Each grant references the previous one as `parent_grant_id`
//! 2. Delegation depths are monotonically increasing (0, 1, 2, ...)
//! 3. Each child's scope is a subset of its parent's scope
//! 4. Each child's trust tier is ≥ its parent's trust tier
//! 5. No child outlives its parent (expiration inheritance)
//! 6. The chain doesn't exceed the `max_delegation_depth` set by the root
//! 7. Each grant's grantor matches the previous grant's grantee (the delegator)
//! 8. All signatures verify (if present)

use crate::capability_grant::{CapabilityGrant, DelegationError};

/// A verified delegation chain — an ordered list of grants from root to leaf.
///
/// Once constructed via `DelegationChain::verify()`, the chain is guaranteed
/// to satisfy all delegation invariants.
#[derive(Debug, Clone)]
pub struct DelegationChain {
    /// Grants in order: index 0 is the root (depth 0), last is the leaf.
    grants: Vec<CapabilityGrant>,
}

/// Errors that can occur during chain verification.
#[derive(Debug, Clone)]
pub enum ChainError {
    /// The chain is empty.
    EmptyChain,
    /// The root grant has a parent (it shouldn't).
    RootHasParent,
    /// The root grant has non-zero delegation depth.
    RootDepthNonZero,
    /// A link in the chain is broken: child doesn't reference parent.
    BrokenLink {
        child_index: usize,
        expected_parent_id: String,
        actual_parent_id: Option<String>,
    },
    /// Delegation depth doesn't increment correctly.
    DepthMismatch {
        index: usize,
        expected: u8,
        actual: u8,
    },
    /// A child's scope exceeds its parent's scope.
    ScopeEscalation { index: usize },
    /// A child's grantor doesn't match the parent's grantee.
    GrantorMismatch {
        index: usize,
        expected_grantor: String,
        actual_grantor: String,
    },
    /// A grant's signature is invalid.
    InvalidSignature { index: usize },
    /// The chain exceeds the maximum delegation depth.
    DepthExceeded { depth: u8, max: u8 },
    /// A delegation error from the grant itself.
    DelegationError(DelegationError),
    /// P4 (#197): a child grant has a lease but the parent does not — a
    /// child cannot opt INTO leasing if the parent did not.
    LeaseAddedAtChild { index: usize },
    /// P4 (#197): a child's lease is longer than the parent's.
    LeaseDurationEscalation {
        index: usize,
        parent_secs: u64,
        child_secs: u64,
    },
    /// P4 (#197): a child's renewal_authorities are not a subset of the parent's.
    RenewalAuthoritiesNotSubset { index: usize },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::EmptyChain => write!(f, "delegation chain is empty"),
            ChainError::RootHasParent => write!(f, "root grant has a parent_grant_id"),
            ChainError::RootDepthNonZero => write!(f, "root grant has non-zero delegation depth"),
            ChainError::BrokenLink {
                child_index,
                expected_parent_id,
                actual_parent_id,
            } => write!(
                f,
                "broken link at index {}: expected parent '{}', found {:?}",
                child_index, expected_parent_id, actual_parent_id
            ),
            ChainError::DepthMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "depth mismatch at index {}: expected {}, found {}",
                index, expected, actual
            ),
            ChainError::ScopeEscalation { index } => {
                write!(
                    f,
                    "scope escalation at index {}: child exceeds parent scope",
                    index
                )
            }
            ChainError::GrantorMismatch {
                index,
                expected_grantor,
                actual_grantor,
            } => write!(
                f,
                "grantor mismatch at index {}: expected '{}', found '{}'",
                index, expected_grantor, actual_grantor
            ),
            ChainError::InvalidSignature { index } => {
                write!(f, "invalid signature at index {}", index)
            }
            ChainError::DepthExceeded { depth, max } => {
                write!(f, "depth {} exceeds maximum {}", depth, max)
            }
            ChainError::DelegationError(e) => write!(f, "delegation error: {}", e),
            ChainError::LeaseAddedAtChild { index } => {
                write!(
                    f,
                    "child grant at index {} has a lease but the parent does not",
                    index
                )
            }
            ChainError::LeaseDurationEscalation {
                index,
                parent_secs,
                child_secs,
            } => write!(
                f,
                "lease duration escalation at index {}: parent {}s, child {}s",
                index, parent_secs, child_secs
            ),
            ChainError::RenewalAuthoritiesNotSubset { index } => write!(
                f,
                "child at index {} has renewal_authorities outside the parent's set",
                index
            ),
        }
    }
}

impl std::error::Error for ChainError {}

impl DelegationChain {
    /// Verify a chain of grants, returning a `DelegationChain` if valid.
    ///
    /// The `grants` must be ordered from root (depth 0) to leaf (deepest delegation).
    /// All delegation invariants are checked.
    ///
    /// If `verify_signatures` is true, every grant with a signature must have
    /// a valid signature; unsigned grants are allowed (not all grants need to be signed).
    pub fn verify(
        grants: Vec<CapabilityGrant>,
        verify_signatures: bool,
    ) -> Result<Self, ChainError> {
        if grants.is_empty() {
            return Err(ChainError::EmptyChain);
        }

        // Validate root
        let root = &grants[0];
        if root.parent_grant_id.is_some() {
            return Err(ChainError::RootHasParent);
        }
        if root.delegation_depth != 0 {
            return Err(ChainError::RootDepthNonZero);
        }

        let max_depth = root.max_delegation_depth;

        // Verify signature on root if requested
        if verify_signatures && root.signature.is_some() && !root.verify_signature() {
            return Err(ChainError::InvalidSignature { index: 0 });
        }

        // Walk the chain
        for i in 1..grants.len() {
            let parent = &grants[i - 1];
            let child = &grants[i];

            // Check parent_grant_id links correctly
            match &child.parent_grant_id {
                Some(pid) if pid == &parent.id => {}
                other => {
                    return Err(ChainError::BrokenLink {
                        child_index: i,
                        expected_parent_id: parent.id.clone(),
                        actual_parent_id: other.clone(),
                    });
                }
            }

            // Check depth increments by 1
            let expected_depth = parent.delegation_depth + 1;
            if child.delegation_depth != expected_depth {
                return Err(ChainError::DepthMismatch {
                    index: i,
                    expected: expected_depth,
                    actual: child.delegation_depth,
                });
            }

            // Check depth doesn't exceed max
            if child.delegation_depth > max_depth {
                return Err(ChainError::DepthExceeded {
                    depth: child.delegation_depth,
                    max: max_depth,
                });
            }

            // Check grantor matches parent's grantee
            if child.grantor != parent.grantee {
                return Err(ChainError::GrantorMismatch {
                    index: i,
                    expected_grantor: parent.grantee.clone(),
                    actual_grantor: child.grantor.clone(),
                });
            }

            // Check scope is a subset of parent
            if !parent.capability.contains(&child.capability) {
                return Err(ChainError::ScopeEscalation { index: i });
            }

            // P4 (#197): lease invariant checks. Skip silently when neither
            // parent nor child has a lease — that's the legacy path.
            match (&parent.lease_policy, &child.lease_policy) {
                (None, Some(_)) => {
                    return Err(ChainError::LeaseAddedAtChild { index: i });
                }
                (Some(parent_lease), Some(child_lease)) => {
                    let parent_secs = parent_lease.lease_duration.as_secs();
                    let child_secs = child_lease.lease_duration.as_secs();
                    if child_secs > parent_secs {
                        return Err(ChainError::LeaseDurationEscalation {
                            index: i,
                            parent_secs,
                            child_secs,
                        });
                    }
                    // Renewal authorities ⊆ parent's. Membership compares by
                    // (ref_type, grant_id, capability_required.name) so we
                    // don't punish unrelated authority lists from being
                    // re-ordered.
                    if !is_authority_subset(&child.renewal_authorities, &parent.renewal_authorities)
                    {
                        return Err(ChainError::RenewalAuthoritiesNotSubset { index: i });
                    }
                }
                _ => {}
            }

            // Verify signature if requested
            if verify_signatures && child.signature.is_some() && !child.verify_signature() {
                return Err(ChainError::InvalidSignature { index: i });
            }
        }

        Ok(Self { grants })
    }

    /// Get the root grant (the original, non-delegated grant).
    pub fn root(&self) -> &CapabilityGrant {
        &self.grants[0]
    }

    /// Get the leaf grant (the most-delegated, "active" grant).
    pub fn leaf(&self) -> &CapabilityGrant {
        self.grants.last().unwrap()
    }

    /// Get the chain length (number of grants, including root).
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Check if the chain is empty (should never be true for a valid chain).
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Get all grants in the chain.
    pub fn grants(&self) -> &[CapabilityGrant] {
        &self.grants
    }

    /// Get the maximum delegation depth allowed by the root.
    pub fn max_depth(&self) -> u8 {
        self.root().max_delegation_depth
    }

    /// Get the current delegation depth (depth of the leaf).
    pub fn current_depth(&self) -> u8 {
        self.leaf().delegation_depth
    }

    /// Check if the chain can still be extended by delegation.
    pub fn can_extend(&self) -> bool {
        self.leaf().can_delegate()
    }
}

/// True iff every authority reference in `child` has a matching entry in
/// `parent`. References match on `(ref_type, grant_id, capability name)` —
/// re-ordering or trivial restatements of the same authority do not count
/// as escalation.
fn is_authority_subset(
    child: &[crate::authority_ref::AuthorityRef],
    parent: &[crate::authority_ref::AuthorityRef],
) -> bool {
    child.iter().all(|c| {
        parent.iter().any(|p| {
            p.ref_type == c.ref_type
                && p.grant_id == c.grant_id
                && p.capability_required.name() == c.capability_required.name()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_grant::GrantedCapability;
    use ed25519_dalek::SigningKey;

    fn make_root() -> CapabilityGrant {
        CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt_root".to_string(),
        )
        .with_max_delegation_depth(3)
    }

    #[test]
    fn test_verify_single_root() {
        let root = make_root();
        let chain = DelegationChain::verify(vec![root.clone()], false).unwrap();

        assert_eq!(chain.len(), 1);
        assert_eq!(chain.root().id, root.id);
        assert_eq!(chain.leaf().id, root.id);
        assert_eq!(chain.current_depth(), 0);
        assert!(chain.can_extend());
    }

    #[test]
    fn test_verify_two_link_chain() {
        let root = make_root();
        let child = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "receipt_1".to_string(),
            )
            .unwrap();

        let chain = DelegationChain::verify(vec![root.clone(), child.clone()], false).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.root().id, root.id);
        assert_eq!(chain.leaf().id, child.id);
        assert_eq!(chain.current_depth(), 1);
    }

    #[test]
    fn test_verify_three_link_chain() {
        let root = make_root();
        let g1 = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/*".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();
        let g2 = g1
            .delegate(
                "dave".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/logs".to_string()],
                },
                "r2".to_string(),
            )
            .unwrap();

        let chain = DelegationChain::verify(vec![root, g1, g2], false).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.current_depth(), 2);
    }

    #[test]
    fn test_verify_empty_chain_fails() {
        let err = DelegationChain::verify(vec![], false).unwrap_err();
        assert!(matches!(err, ChainError::EmptyChain));
    }

    #[test]
    fn test_verify_root_with_parent_fails() {
        let mut root = make_root();
        root.parent_grant_id = Some("fake-parent".to_string());

        let err = DelegationChain::verify(vec![root], false).unwrap_err();
        assert!(matches!(err, ChainError::RootHasParent));
    }

    #[test]
    fn test_verify_root_with_nonzero_depth_fails() {
        let mut root = make_root();
        root.delegation_depth = 1;

        let err = DelegationChain::verify(vec![root], false).unwrap_err();
        assert!(matches!(err, ChainError::RootDepthNonZero));
    }

    #[test]
    fn test_verify_broken_link_fails() {
        let root = make_root();
        let mut child = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();

        // Break the link
        child.parent_grant_id = Some("wrong-id".to_string());

        let err = DelegationChain::verify(vec![root, child], false).unwrap_err();
        assert!(matches!(err, ChainError::BrokenLink { .. }));
    }

    #[test]
    fn test_verify_depth_mismatch_fails() {
        let root = make_root();
        let mut child = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();

        // Tamper with depth
        child.delegation_depth = 5;

        let err = DelegationChain::verify(vec![root, child], false).unwrap_err();
        assert!(matches!(err, ChainError::DepthMismatch { .. }));
    }

    #[test]
    fn test_verify_grantor_mismatch_fails() {
        let root = make_root();
        let mut child = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();

        // Tamper with grantor
        child.grantor = "impostor".to_string();

        let err = DelegationChain::verify(vec![root, child], false).unwrap_err();
        assert!(matches!(err, ChainError::GrantorMismatch { .. }));
    }

    #[test]
    fn test_verify_scope_escalation_fails() {
        let root = make_root(); // scope: data/*
        let mut child = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();

        // Tamper: escalate scope beyond parent
        child.capability = GrantedCapability::Read {
            scope: vec!["secret/*".to_string()],
        };

        let err = DelegationChain::verify(vec![root, child], false).unwrap_err();
        assert!(matches!(err, ChainError::ScopeEscalation { .. }));
    }

    #[test]
    fn test_verify_with_valid_signatures() {
        let key_alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let key_bob = SigningKey::generate(&mut rand::rngs::OsRng);

        let mut root = make_root();
        root.sign(&key_alice);

        let mut child = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();
        child.sign(&key_bob);

        let chain = DelegationChain::verify(vec![root, child], true).unwrap();
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn test_verify_with_invalid_signature_fails() {
        let key_alice = SigningKey::generate(&mut rand::rngs::OsRng);

        let mut root = make_root();
        root.sign(&key_alice);

        let mut child = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();
        child.sign(&key_alice);

        // Tamper after signing
        child.grantee = "tampered".to_string();

        let err = DelegationChain::verify(vec![root, child], true).unwrap_err();
        assert!(matches!(err, ChainError::InvalidSignature { index: 1 }));
    }

    #[test]
    fn test_chain_max_depth_from_root() {
        let root = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r".to_string(),
        )
        .with_max_delegation_depth(1);

        let g1 = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["*".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();

        let chain = DelegationChain::verify(vec![root, g1], false).unwrap();
        assert_eq!(chain.max_depth(), 1);
        assert!(!chain.can_extend()); // at max depth
    }

    #[test]
    fn test_chain_depth_exceeded_fails() {
        // Build a chain that tampers depth to exceed max
        let root = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r".to_string(),
        )
        .with_max_delegation_depth(1);

        let g1 = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["*".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();

        // Manually create a fake g2 that bypasses delegate() depth check
        let mut g2 = CapabilityGrant::new(
            "charlie".to_string(),
            "dave".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r2".to_string(),
        );
        g2.parent_grant_id = Some(g1.id.clone());
        g2.delegation_depth = 2;
        g2.max_delegation_depth = 1;

        let err = DelegationChain::verify(vec![root, g1, g2], false).unwrap_err();
        assert!(matches!(err, ChainError::DepthExceeded { .. }));
    }
}
