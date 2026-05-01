//! Upstream binding verification for delegate nodes (T3).
//!
//! When a node is a delegate, its delegation receipt contains the upstream
//! genesis node's public key. This module verifies that binding — both
//! locally (receipt integrity, pubkey format) and eventually online
//! (challenge the upstream to prove it holds the key).
//!
//! Local verification can run offline. Online verification requires
//! the upstream to be reachable and is wired in a later phase.

use crate::schema::NodeRole;

/// Result of verifying a delegate's upstream binding.
#[derive(Debug, Clone)]
pub enum UpstreamBindingStatus {
    /// The delegation receipt's pubkey is well-formed and the receipt is intact.
    /// (Online verification that the upstream actually holds this key is a
    /// separate check — see `verify_upstream_binding_online` in a later phase.)
    Verified {
        upstream_addr: String,
        genesis_pubkey: String,
    },

    /// The delegation receipt exists but the pubkey field is empty or missing.
    /// This happens with pre-T3 delegation receipts or bootstrap hints.
    Unbound {
        upstream_addr: String,
    },

    /// The pubkey in the delegation receipt is malformed (not valid hex, wrong length).
    MalformedPubkey {
        upstream_addr: String,
        pubkey: String,
        reason: String,
    },

    /// The upstream's genesis pubkey doesn't match the delegation receipt.
    /// This is a potential trust redirect — the upstream has changed identity.
    PubkeyMismatch {
        expected: String,
        actual: String,
        upstream_addr: String,
    },

    /// Node is not a delegate — no upstream binding to verify.
    NotDelegate,

    /// Delegation receipt found but upstream is unreachable (online check only).
    UpstreamUnreachable {
        upstream_addr: String,
        genesis_pubkey: String,
        error: String,
    },
}

impl UpstreamBindingStatus {
    /// Whether this status represents a passing check.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Verified { .. } | Self::NotDelegate)
    }

    /// Whether this status represents a security concern.
    pub fn is_security_concern(&self) -> bool {
        matches!(self, Self::PubkeyMismatch { .. })
    }

    /// Human-readable summary for `zp doctor` output.
    pub fn summary(&self) -> String {
        match self {
            Self::Verified { upstream_addr, genesis_pubkey } => {
                let short_key = if genesis_pubkey.len() > 12 {
                    format!("{}...{}", &genesis_pubkey[..6], &genesis_pubkey[genesis_pubkey.len()-6..])
                } else {
                    genesis_pubkey.clone()
                };
                format!("Verified (upstream: {}, pubkey: ed25519:{})", upstream_addr, short_key)
            }
            Self::Unbound { upstream_addr } => {
                format!("Unbound — delegation receipt for {} has no pubkey recorded", upstream_addr)
            }
            Self::MalformedPubkey { upstream_addr, reason, .. } => {
                format!("Malformed pubkey in delegation receipt for {}: {}", upstream_addr, reason)
            }
            Self::PubkeyMismatch { expected, actual, upstream_addr } => {
                format!(
                    "PUBKEY MISMATCH — receipt says ed25519:{} but upstream {} is serving ed25519:{}",
                    &expected[..12.min(expected.len())],
                    upstream_addr,
                    &actual[..12.min(actual.len())]
                )
            }
            Self::NotDelegate => "Not a delegate — no upstream binding to verify".into(),
            Self::UpstreamUnreachable { upstream_addr, error, .. } => {
                format!("Upstream {} unreachable: {}", upstream_addr, error)
            }
        }
    }
}

/// Verify the upstream binding locally (no network access required).
///
/// Checks:
/// 1. Node is actually a delegate (has upstream binding)
/// 2. The upstream genesis pubkey in the role is non-empty
/// 3. The pubkey is well-formed hex and the correct length (32 bytes = 64 hex chars)
///
/// This does NOT verify that the upstream actually holds the key — that
/// requires an online check against the upstream node.
pub fn verify_upstream_binding_local(role: &NodeRole) -> UpstreamBindingStatus {
    match role {
        NodeRole::Delegate { upstream_addr, upstream_genesis_pubkey } => {
            // Check for empty/placeholder pubkey
            if upstream_genesis_pubkey.is_empty() {
                return UpstreamBindingStatus::Unbound {
                    upstream_addr: upstream_addr.clone(),
                };
            }

            // Strip optional "ed25519:" prefix for validation
            let raw_hex = upstream_genesis_pubkey
                .strip_prefix("ed25519:")
                .unwrap_or(upstream_genesis_pubkey);

            // Validate hex encoding
            if let Err(e) = hex::decode(raw_hex) {
                return UpstreamBindingStatus::MalformedPubkey {
                    upstream_addr: upstream_addr.clone(),
                    pubkey: upstream_genesis_pubkey.clone(),
                    reason: format!("invalid hex: {}", e),
                };
            }

            // Validate key length (Ed25519 public key = 32 bytes = 64 hex chars)
            let decoded_len = raw_hex.len() / 2;
            if decoded_len != 32 {
                return UpstreamBindingStatus::MalformedPubkey {
                    upstream_addr: upstream_addr.clone(),
                    pubkey: upstream_genesis_pubkey.clone(),
                    reason: format!("expected 32 bytes, got {}", decoded_len),
                };
            }

            UpstreamBindingStatus::Verified {
                upstream_addr: upstream_addr.clone(),
                genesis_pubkey: raw_hex.to_string(),
            }
        }
        _ => UpstreamBindingStatus::NotDelegate,
    }
}

/// Compare a delegation receipt's stored pubkey against an upstream's
/// actual genesis pubkey (obtained via API or certificate exchange).
///
/// This is the online verification counterpart to `verify_upstream_binding_local`.
/// The caller is responsible for obtaining `actual_upstream_pubkey` from the
/// upstream node (e.g., via `/api/v1/status` or certificate exchange).
pub fn verify_upstream_pubkey_match(
    expected: &str,
    actual_upstream_pubkey: &str,
) -> UpstreamBindingStatus {
    // Normalize both keys (strip optional prefix, lowercase)
    let normalize = |key: &str| -> String {
        key.strip_prefix("ed25519:")
            .unwrap_or(key)
            .to_lowercase()
    };

    let expected_norm = normalize(expected);
    let actual_norm = normalize(actual_upstream_pubkey);

    if expected_norm == actual_norm {
        UpstreamBindingStatus::Verified {
            upstream_addr: String::new(), // caller fills this in
            genesis_pubkey: expected_norm,
        }
    } else {
        UpstreamBindingStatus::PubkeyMismatch {
            expected: expected_norm,
            actual: actual_norm,
            upstream_addr: String::new(), // caller fills this in
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_delegate() {
        let status = verify_upstream_binding_local(&NodeRole::Standalone);
        assert!(matches!(status, UpstreamBindingStatus::NotDelegate));
        assert!(status.is_ok());

        let status = verify_upstream_binding_local(&NodeRole::Genesis);
        assert!(matches!(status, UpstreamBindingStatus::NotDelegate));
    }

    #[test]
    fn test_unbound_empty_pubkey() {
        let role = NodeRole::Delegate {
            upstream_addr: "192.168.1.152:17770".into(),
            upstream_genesis_pubkey: String::new(),
        };
        let status = verify_upstream_binding_local(&role);
        assert!(matches!(status, UpstreamBindingStatus::Unbound { .. }));
        assert!(!status.is_ok());
    }

    #[test]
    fn test_malformed_hex() {
        let role = NodeRole::Delegate {
            upstream_addr: "192.168.1.152:17770".into(),
            upstream_genesis_pubkey: "not-valid-hex".into(),
        };
        let status = verify_upstream_binding_local(&role);
        assert!(matches!(status, UpstreamBindingStatus::MalformedPubkey { .. }));
    }

    #[test]
    fn test_wrong_length() {
        let role = NodeRole::Delegate {
            upstream_addr: "192.168.1.152:17770".into(),
            upstream_genesis_pubkey: "abcdef".into(), // 3 bytes, not 32
        };
        let status = verify_upstream_binding_local(&role);
        assert!(matches!(status, UpstreamBindingStatus::MalformedPubkey { reason, .. } if reason.contains("expected 32")));
    }

    #[test]
    fn test_valid_pubkey() {
        // 32 bytes = 64 hex chars
        let pubkey = "a".repeat(64);
        let role = NodeRole::Delegate {
            upstream_addr: "192.168.1.152:17770".into(),
            upstream_genesis_pubkey: pubkey.clone(),
        };
        let status = verify_upstream_binding_local(&role);
        assert!(matches!(status, UpstreamBindingStatus::Verified { .. }));
        assert!(status.is_ok());
    }

    #[test]
    fn test_valid_pubkey_with_prefix() {
        let pubkey = format!("ed25519:{}", "b".repeat(64));
        let role = NodeRole::Delegate {
            upstream_addr: "192.168.1.152:17770".into(),
            upstream_genesis_pubkey: pubkey,
        };
        let status = verify_upstream_binding_local(&role);
        assert!(matches!(status, UpstreamBindingStatus::Verified { .. }));
    }

    #[test]
    fn test_pubkey_match() {
        let key = "a".repeat(64);
        let status = verify_upstream_pubkey_match(&key, &key);
        assert!(matches!(status, UpstreamBindingStatus::Verified { .. }));
    }

    #[test]
    fn test_pubkey_match_with_prefix() {
        let key = "a".repeat(64);
        let prefixed = format!("ed25519:{}", key);
        let status = verify_upstream_pubkey_match(&prefixed, &key);
        assert!(matches!(status, UpstreamBindingStatus::Verified { .. }));
    }

    #[test]
    fn test_pubkey_mismatch() {
        let key_a = "a".repeat(64);
        let key_b = "b".repeat(64);
        let status = verify_upstream_pubkey_match(&key_a, &key_b);
        assert!(matches!(status, UpstreamBindingStatus::PubkeyMismatch { .. }));
        assert!(status.is_security_concern());
    }
}
