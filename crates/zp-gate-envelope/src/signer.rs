//! The ZP-Sig signer — the producer half of the envelope path.
//!
//! `zp-server` holds the verifier ([`crate::parse_header`] plus
//! `EnvelopeVerifier`). This is its counterpart, and it lives in the same
//! crate for the reason stated at the crate root: two implementations of one
//! wire format is how producer-consumer pairs drift. One crate, one set of
//! helpers, both sides import it.
//!
//! # The preimage trap
//!
//! `zp_receipt::verify_signed` verifies against `value.canonical_hash()`,
//! which is `blake3(canonical_preimage())` — **not** the preimage bytes. A
//! signer that signs `canonical_preimage()` directly produces a structurally
//! perfect header that fails every verification, and the gate reports it as
//! `envelope-signature`, indistinguishable from a wrong key. This module is
//! the only place in the workspace that gets to make that choice, and the
//! `signature_verifies_against_zp_receipt` test below pins it.
//!
//! # Key provenance
//!
//! The seed comes from `zp_keys::derive_gate_signer_seed(genesis_secret)`.
//! This module deliberately does not perform that derivation — it accepts a
//! seed. Genesis handling stays with the composition root, and the
//! `no_inline_gate_signer_derivation` discipline pin stays satisfied.

use ed25519_dalek::{Signer, SigningKey};
use zp_core::provider::RequestSigner;
use zp_receipt::Signable;

use crate::{body_hash_hex, build_header, random_nonce_b64, EnvelopeClaims, SCHEME_VERSION};

/// Signs outbound substrate requests with a Genesis-derived gate key.
///
/// Construct once at startup and share via `Arc`. Holds the signing key for
/// the process lifetime and never writes it anywhere — same property as the
/// derivation it comes from.
pub struct GateRequestSigner {
    key: SigningKey,
    kid: [u8; 32],
}

impl GateRequestSigner {
    /// Build from a 32-byte gate-signer seed.
    ///
    /// The seed must be the output of `zp_keys::derive_gate_signer_seed`, so
    /// that the `kid` this signer presents matches the `expected_kid` the
    /// verifier derived from the same Genesis secret. Any other seed produces
    /// envelopes rejected as `UnknownSigner`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        let kid = key.verifying_key().to_bytes();
        Self { key, kid }
    }

    /// This signer's key id — the 32-byte Ed25519 verifying key.
    ///
    /// Structurally public (it is a public key fingerprint). Useful for
    /// asserting at startup that signer and verifier agree before any request
    /// is made, rather than discovering a mismatch as a 401 later.
    pub fn kid(&self) -> [u8; 32] {
        self.kid
    }

    /// Hex form of [`kid`](Self::kid), for logging and comparison against
    /// `EnvelopeVerifier::expected_kid_hex`.
    pub fn kid_hex(&self) -> String {
        hex::encode(self.kid)
    }

    /// Current unix time in seconds.
    ///
    /// Split out so the drift-window behaviour is testable without waiting.
    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Build a signed `Authorization` value binding method, path and body.
    pub fn sign_request(&self, method: &str, path: &str, body: &[u8], ts: i64) -> String {
        let claims = EnvelopeClaims {
            v: SCHEME_VERSION,
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            body_hash: body_hash_hex(body),
            ts,
            nonce: random_nonce_b64(),
        };
        // Sign the canonical HASH, not the preimage. See module docs.
        let sig = self.key.sign(&claims.canonical_hash());
        build_header(&claims, &self.kid, &sig.to_bytes())
    }
}

impl RequestSigner for GateRequestSigner {
    fn authorization(&self, method: &str, path: &str, body: &[u8]) -> Option<String> {
        Some(self.sign_request(method, path, body, Self::now_secs()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_header;

    fn signer() -> GateRequestSigner {
        GateRequestSigner::from_seed(&[7u8; 32])
    }

    #[test]
    fn header_parses_back() {
        let s = signer();
        let header = s.sign_request("POST", "/api/v1/proxy/ollama/v1/chat/completions", b"{}", 1_700_000_000);
        let parsed = parse_header(&header).expect("own header must parse");
        assert_eq!(parsed.v, SCHEME_VERSION);
        assert_eq!(parsed.kid, s.kid());
        assert_eq!(parsed.ts, 1_700_000_000);
    }

    /// The load-bearing test: the signature must verify through the exact
    /// primitive the gate uses. If `zp_receipt::verify_signed` ever changes
    /// what it hashes, this fails here rather than as a 401 in production.
    #[test]
    fn signature_verifies_against_zp_receipt() {
        let s = signer();
        let method = "POST";
        let path = "/api/v1/proxy/ollama/v1/chat/completions";
        let body = br#"{"model":"m","messages":[]}"#;
        let ts = 1_700_000_000;

        let header = s.sign_request(method, path, body, ts);
        let parsed = parse_header(&header).unwrap();

        // Reconstruct claims the way the verifier does: request-derived
        // method/path/body_hash, header-derived v/ts/nonce.
        let claims = parsed.clone().into_claims(
            method.to_string(),
            path.to_string(),
            body_hash_hex(body),
        );

        zp_receipt::verify_signed(&claims, &parsed.kid, &parsed.sig)
            .expect("signature must verify through the gate's own primitive");
    }

    #[test]
    fn body_binding_is_enforced() {
        let s = signer();
        let path = "/api/v1/proxy/ollama/v1/chat/completions";
        let header = s.sign_request("POST", path, b"original", 1_700_000_000);
        let parsed = parse_header(&header).unwrap();

        // Same envelope, different body → different preimage → must fail.
        let tampered = parsed.clone().into_claims(
            "POST".to_string(),
            path.to_string(),
            body_hash_hex(b"tampered"),
        );
        assert!(
            zp_receipt::verify_signed(&tampered, &parsed.kid, &parsed.sig).is_err(),
            "a body swap must break the signature"
        );
    }

    #[test]
    fn path_binding_is_enforced() {
        let s = signer();
        let body = b"{}";
        let header = s.sign_request("POST", "/api/v1/proxy/ollama/v1/chat/completions", body, 1_700_000_000);
        let parsed = parse_header(&header).unwrap();

        // Replaying the same envelope against the native Ollama route must fail.
        let elsewhere = parsed.clone().into_claims(
            "POST".to_string(),
            "/api/v1/proxy/ollama/api/pull".to_string(),
            body_hash_hex(body),
        );
        assert!(
            zp_receipt::verify_signed(&elsewhere, &parsed.kid, &parsed.sig).is_err(),
            "a path swap must break the signature"
        );
    }

    #[test]
    fn nonces_differ_between_requests() {
        let s = signer();
        let a = s.sign_request("POST", "/x", b"", 1_700_000_000);
        let b = s.sign_request("POST", "/x", b"", 1_700_000_000);
        assert_ne!(a, b, "each envelope must carry a fresh nonce");
    }

    #[test]
    fn kid_matches_derived_verifying_key() {
        let seed = [7u8; 32];
        let expected = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(GateRequestSigner::from_seed(&seed).kid(), expected);
    }

    #[test]
    fn method_is_normalised_to_uppercase() {
        let s = signer();
        let lower = s.sign_request("post", "/x", b"", 1_700_000_000);
        let parsed = parse_header(&lower).unwrap();
        let claims = parsed
            .clone()
            .into_claims("POST".to_string(), "/x".to_string(), body_hash_hex(b""));
        zp_receipt::verify_signed(&claims, &parsed.kid, &parsed.sig)
            .expect("lowercase method must sign as uppercase");
    }
}
