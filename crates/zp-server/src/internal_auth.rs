//! Internal zero-trust capability tokens (P2-3).
//!
//! Every internal service boundary crossing (e.g., verification probes
//! to governed tools) requires a short-lived capability token. Tokens
//! are scoped to a specific action and target, carry a nonce for replay
//! prevention, and expire after 30 seconds.
//!
//! The signing key is derived from the operator's Ed25519 key via
//! BLAKE3 keyed derivation with context `"zeropoint internal auth v1"`.
//! This avoids exposing the operator key for high-volume internal calls.
//!
//! Addresses Shannon pentest findings SSRF-VULN-01/SSRF-VULN-02.

use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;

/// Default TTL for internal capability tokens (30 seconds).
const DEFAULT_TTL_SECS: u64 = 30;

/// Maximum nonce cache size before pruning expired entries.
const MAX_NONCE_CACHE: usize = 10_000;

/// The HTTP header name for internal capability tokens.
pub const HEADER_NAME: &str = "X-ZeroPoint-Internal-Token";

/// Errors from internal token operations.
#[derive(Debug, Clone)]
pub enum InternalAuthError {
    /// Token has expired.
    Expired,
    /// Token nonce has already been used (replay attempt).
    NonceReused,
    /// Token action does not match the expected action.
    ActionMismatch { expected: String, got: String },
    /// Token target does not match the expected target.
    TargetMismatch { expected: String, got: String },
    /// Token signature is invalid.
    BadSignature,
    /// Token could not be deserialized.
    MalformedToken(String),
}

impl fmt::Display for InternalAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InternalAuthError::Expired => write!(f, "Internal token expired"),
            InternalAuthError::NonceReused => write!(f, "Internal token nonce reused (replay)"),
            InternalAuthError::ActionMismatch { expected, got } => {
                write!(f, "Token action mismatch: expected '{}', got '{}'", expected, got)
            }
            InternalAuthError::TargetMismatch { expected, got } => {
                write!(f, "Token target mismatch: expected '{}', got '{}'", expected, got)
            }
            InternalAuthError::BadSignature => write!(f, "Internal token signature invalid"),
            InternalAuthError::MalformedToken(e) => write!(f, "Malformed internal token: {}", e),
        }
    }
}

/// A short-lived capability token for internal service calls.
///
/// Tokens are:
/// - **Scoped**: action + target restrict what the token authorizes
/// - **Short-lived**: 30-second TTL prevents stolen tokens from lingering
/// - **Non-replayable**: random nonce tracked by the issuer
/// - **Signed**: BLAKE3 keyed hash prevents forgery
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InternalCapabilityToken {
    /// What operation this token authorizes (e.g., "verify:tier1", "verify:tier2").
    pub action: String,
    /// Which target this token is scoped to (e.g., tool name "pentagi").
    pub target: String,
    /// Unix timestamp when the token was issued.
    pub issued_at: u64,
    /// Unix timestamp when the token expires.
    pub expires_at: u64,
    /// Random nonce for replay prevention (hex-encoded).
    pub nonce: String,
    /// BLAKE3 keyed hash of the token payload (hex-encoded).
    pub signature: String,
}

impl InternalCapabilityToken {
    /// Serialize to a compact header-safe string (hex-encoded JSON).
    pub fn to_header_value(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        hex::encode(json.as_bytes())
    }

    /// Deserialize from a header value (hex-encoded JSON).
    pub fn from_header_value(value: &str) -> Result<Self, InternalAuthError> {
        let bytes = hex::decode(value)
            .map_err(|e| InternalAuthError::MalformedToken(format!("hex: {}", e)))?;
        let json = String::from_utf8(bytes)
            .map_err(|e| InternalAuthError::MalformedToken(format!("utf8: {}", e)))?;
        serde_json::from_str(&json)
            .map_err(|e| InternalAuthError::MalformedToken(format!("json: {}", e)))
    }
}

/// Authority for issuing and verifying internal capability tokens.
///
/// Holds the derived HMAC key and a nonce cache for replay prevention.
/// Created once at server startup from the operator's signing key.
pub struct InternalAuthority {
    /// BLAKE3 keyed-hash key derived from the operator key.
    hmac_key: [u8; 32],
    /// Set of recently-seen nonces for replay prevention.
    /// Pruned when it exceeds MAX_NONCE_CACHE.
    seen_nonces: Mutex<HashSet<String>>,
}

impl InternalAuthority {
    /// Create a new authority by deriving the internal HMAC key
    /// from the operator's Ed25519 signing key bytes.
    ///
    /// Uses BLAKE3 key derivation with context "zeropoint internal auth v1"
    /// to produce a 32-byte key that is cryptographically independent of
    /// the signing key itself.
    pub fn new(signing_key_bytes: &[u8; 32]) -> Self {
        let derived = blake3::derive_key("zeropoint internal auth v1", signing_key_bytes);
        Self {
            hmac_key: derived,
            seen_nonces: Mutex::new(HashSet::new()),
        }
    }

    /// Issue a capability token scoped to a specific action and target.
    ///
    /// The token is valid for `DEFAULT_TTL_SECS` (30 seconds) and
    /// carries a random nonce for replay prevention.
    pub fn issue(&self, action: &str, target: &str) -> InternalCapabilityToken {
        let now = chrono::Utc::now().timestamp() as u64;
        let nonce_bytes: [u8; 16] = rand::random();
        let nonce = hex::encode(nonce_bytes);

        // Construct the payload to sign: action|target|issued_at|expires_at|nonce
        let expires_at = now + DEFAULT_TTL_SECS;
        let payload = format!("{}|{}|{}|{}|{}", action, target, now, expires_at, nonce);

        // Sign with BLAKE3 keyed hash
        let signature = blake3::keyed_hash(&self.hmac_key, payload.as_bytes())
            .to_hex()
            .to_string();

        InternalCapabilityToken {
            action: action.to_string(),
            target: target.to_string(),
            issued_at: now,
            expires_at,
            nonce,
            signature,
        }
    }

    /// Verify a capability token against expected action and target.
    ///
    /// Checks:
    /// 1. Signature is valid (BLAKE3 keyed hash matches)
    /// 2. Token has not expired
    /// 3. Action matches the expected action
    /// 4. Target matches the expected target
    /// 5. Nonce has not been seen before (replay prevention)
    pub fn verify(
        &self,
        token: &InternalCapabilityToken,
        expected_action: &str,
        expected_target: &str,
    ) -> Result<(), InternalAuthError> {
        // 1. Verify signature first (cheapest check that catches forgery)
        let payload = format!(
            "{}|{}|{}|{}|{}",
            token.action, token.target, token.issued_at, token.expires_at, token.nonce
        );
        let expected_sig = blake3::keyed_hash(&self.hmac_key, payload.as_bytes())
            .to_hex()
            .to_string();

        if token.signature != expected_sig {
            return Err(InternalAuthError::BadSignature);
        }

        // 2. Check expiration
        let now = chrono::Utc::now().timestamp() as u64;
        if now > token.expires_at {
            return Err(InternalAuthError::Expired);
        }

        // 3. Check action scoping
        if token.action != expected_action {
            return Err(InternalAuthError::ActionMismatch {
                expected: expected_action.to_string(),
                got: token.action.clone(),
            });
        }

        // 4. Check target scoping
        if token.target != expected_target {
            return Err(InternalAuthError::TargetMismatch {
                expected: expected_target.to_string(),
                got: token.target.clone(),
            });
        }

        // 5. Replay prevention — nonce must not have been seen before
        let mut seen = self.seen_nonces.lock().unwrap_or_else(|e| e.into_inner());

        // Prune if cache is too large (simple strategy: clear all)
        if seen.len() >= MAX_NONCE_CACHE {
            seen.clear();
        }

        if !seen.insert(token.nonce.clone()) {
            return Err(InternalAuthError::NonceReused);
        }

        Ok(())
    }
}

impl fmt::Debug for InternalAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InternalAuthority {{ nonces_tracked: {} }}",
            self.seen_nonces.lock().map(|s| s.len()).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_authority() -> InternalAuthority {
        InternalAuthority::new(&[42u8; 32])
    }

    #[test]
    fn test_issue_and_verify() {
        let auth = test_authority();
        let token = auth.issue("verify:tier1", "pentagi");

        assert_eq!(token.action, "verify:tier1");
        assert_eq!(token.target, "pentagi");
        assert!(token.expires_at > token.issued_at);
        assert!(!token.nonce.is_empty());
        assert!(!token.signature.is_empty());

        // Should verify successfully
        assert!(auth.verify(&token, "verify:tier1", "pentagi").is_ok());
    }

    #[test]
    fn test_replay_rejected() {
        let auth = test_authority();
        let token = auth.issue("verify:tier1", "pentagi");

        // First use succeeds
        assert!(auth.verify(&token, "verify:tier1", "pentagi").is_ok());
        // Second use fails (nonce reuse)
        assert!(matches!(
            auth.verify(&token, "verify:tier1", "pentagi"),
            Err(InternalAuthError::NonceReused)
        ));
    }

    #[test]
    fn test_action_mismatch_rejected() {
        let auth = test_authority();
        let token = auth.issue("verify:tier1", "pentagi");

        assert!(matches!(
            auth.verify(&token, "verify:tier2", "pentagi"),
            Err(InternalAuthError::ActionMismatch { .. })
        ));
    }

    #[test]
    fn test_target_mismatch_rejected() {
        let auth = test_authority();
        let token = auth.issue("verify:tier1", "pentagi");

        assert!(matches!(
            auth.verify(&token, "verify:tier1", "other-tool"),
            Err(InternalAuthError::TargetMismatch { .. })
        ));
    }

    #[test]
    fn test_forged_signature_rejected() {
        let auth = test_authority();
        let mut token = auth.issue("verify:tier1", "pentagi");
        token.signature = "deadbeef".to_string();

        assert!(matches!(
            auth.verify(&token, "verify:tier1", "pentagi"),
            Err(InternalAuthError::BadSignature)
        ));
    }

    #[test]
    fn test_expired_token_rejected() {
        let auth = test_authority();
        let mut token = auth.issue("verify:tier1", "pentagi");
        // Force expiration into the past
        token.expires_at = token.issued_at - 1;
        // Re-sign with the correct payload so signature check passes first
        let payload = format!(
            "{}|{}|{}|{}|{}",
            token.action, token.target, token.issued_at, token.expires_at, token.nonce
        );
        token.signature = blake3::keyed_hash(&auth.hmac_key, payload.as_bytes())
            .to_hex()
            .to_string();

        assert!(matches!(
            auth.verify(&token, "verify:tier1", "pentagi"),
            Err(InternalAuthError::Expired)
        ));
    }

    #[test]
    fn test_different_keys_reject() {
        let auth1 = InternalAuthority::new(&[1u8; 32]);
        let auth2 = InternalAuthority::new(&[2u8; 32]);

        let token = auth1.issue("verify:tier1", "pentagi");
        assert!(matches!(
            auth2.verify(&token, "verify:tier1", "pentagi"),
            Err(InternalAuthError::BadSignature)
        ));
    }

    #[test]
    fn test_header_roundtrip() {
        let auth = test_authority();
        let token = auth.issue("verify:tier1", "pentagi");

        let header = token.to_header_value();
        let recovered = InternalCapabilityToken::from_header_value(&header).unwrap();

        assert_eq!(recovered.action, token.action);
        assert_eq!(recovered.target, token.target);
        assert_eq!(recovered.nonce, token.nonce);
        assert_eq!(recovered.signature, token.signature);

        // Recovered token should verify
        assert!(auth.verify(&recovered, "verify:tier1", "pentagi").is_ok());
    }

    #[test]
    fn test_malformed_header_rejected() {
        assert!(matches!(
            InternalCapabilityToken::from_header_value("not-valid-hex!!!"),
            Err(InternalAuthError::MalformedToken(_))
        ));
        // Valid hex but not valid JSON
        assert!(matches!(
            InternalCapabilityToken::from_header_value(&hex::encode(b"not-json")),
            Err(InternalAuthError::MalformedToken(_))
        ));
    }
}
