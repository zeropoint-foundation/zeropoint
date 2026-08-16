//! Per-request envelope verification state for the cognition-governance gate.
//!
//! # What
//!
//! Holds the runtime state the `require_auth` middleware needs to verify
//! `Authorization: ZP-Sig …` envelopes:
//!
//! - `expected_kid` — the Ed25519 verifying-key bytes the substrate computed
//!   at startup from `derive_gate_signer_seed(genesis_secret)`. Any envelope
//!   whose `kid` differs is rejected with `envelope-signer`.
//! - `drift_window` — `±N` seconds of clock-skew tolerance. Configurable via
//!   `ZP_GATE_DRIFT_WINDOW_SECS` (capped at 300s).
//! - `nonce_store` — replay-protection LRU keyed on `(kid, nonce)`, age-bounded
//!   by the drift window.
//!
//! # Why a struct, not free functions
//!
//! `require_auth` is invoked per-request and needs cheap access to all three.
//! Bundling them into an `EnvelopeVerifier` shares one `Arc` rather than three.
//! The verifier also owns the `verify` entry point so the middleware's branch
//! stays small.
//!
//! # Composition
//!
//! Verification routes through `zp_receipt::verify_signed` (Seam 5) — the only
//! sanctioned Ed25519 verify primitive in the workspace. The envelope's
//! canonical preimage comes from `zp_gate_envelope::EnvelopeClaims`, which
//! implements `Signable` (Seam 20).

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use zp_gate_envelope::{parse_header, EnvelopeClaims, NONCE_BYTES};

/// Distinct envelope-verification failures. Each maps 1:1 to an
/// `X-Auth-Reason` code so the IronClaw caller can distinguish "my clock is
/// wrong" from "my key derivation is wrong" without leaking implementation
/// details to attackers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeReject {
    /// `Authorization` header was missing entirely.
    Missing,
    /// Header didn't parse as `ZP-Sig v=1, kid=…, ts=…, nonce=…, sig=…`.
    Malformed,
    /// `v=` was something other than `1`.
    UnknownVersion,
    /// `kid` did not match the gate's expected signer.
    UnknownSigner,
    /// Method, path, or body hash from the live request did not match the
    /// claims the signer signed.
    Binding,
    /// `ts` was outside the configured drift window.
    Drift,
    /// `(kid, nonce)` was already seen within the drift window.
    Replay,
    /// Signature did not verify against the (kid, preimage) pair.
    Signature,
}

impl EnvelopeReject {
    /// Stable string used in the `X-Auth-Reason` response header.
    pub fn reason_code(self) -> &'static str {
        match self {
            EnvelopeReject::Missing => "missing",
            EnvelopeReject::Malformed => "envelope-malformed",
            EnvelopeReject::UnknownVersion => "envelope-version",
            EnvelopeReject::UnknownSigner => "envelope-signer",
            EnvelopeReject::Binding => "envelope-binding",
            EnvelopeReject::Drift => "envelope-drift",
            EnvelopeReject::Replay => "envelope-replay",
            EnvelopeReject::Signature => "envelope-signature",
        }
    }
}

/// Default drift window: ±30 seconds. NTP-synced hosts skew well under 1s;
/// ±30s tolerates human-noticeable clock drift while keeping the replay LRU
/// bounded.
const DEFAULT_DRIFT_WINDOW_SECS: u64 = 30;

/// Hard cap on the drift window even if the env var is set to a larger value.
/// A window larger than this turns the replay LRU into a large, hot
/// data structure for very little operational gain.
const MAX_DRIFT_WINDOW_SECS: u64 = 300;

/// Default nonce-store capacity: 16 384 entries. At ~50 B/entry → ~800 KB
/// resident; covers ~273 envelopes/sec across the 60-second drift window.
const DEFAULT_NONCE_CAPACITY: usize = 16_384;

fn drift_window_from_env() -> Duration {
    let raw = std::env::var("ZP_GATE_DRIFT_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_DRIFT_WINDOW_SECS);
    Duration::from_secs(raw.min(MAX_DRIFT_WINDOW_SECS))
}

fn nonce_capacity_from_env() -> usize {
    std::env::var("ZP_GATE_NONCE_CAPACITY")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_NONCE_CAPACITY)
}

/// Replay-protection store. Keys on `(kid, nonce)` so the same nonce from
/// different signers is fine — preemptively useful for the future
/// multi-signer case, and a clean key shape for v1.
///
/// Eviction is both age-driven (entries older than the drift window are dead)
/// and capacity-driven (oldest by insertion). Age eviction runs
/// opportunistically on every insert; no background task needed.
pub struct NonceStore {
    inner: Mutex<NonceStoreInner>,
    drift_window: Duration,
    capacity: usize,
}

struct NonceStoreInner {
    /// Map composite `(kid, nonce)` → insertion timestamp (unix seconds).
    map: HashMap<([u8; 32], String), i64>,
    /// FIFO of (composite_key, ts) for capacity-driven eviction. We sweep
    /// from the front whenever capacity is exceeded.
    fifo: std::collections::VecDeque<(([u8; 32], String), i64)>,
}

impl NonceStore {
    pub fn new(drift_window: Duration, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(NonceStoreInner {
                map: HashMap::with_capacity(capacity.min(1024)),
                fifo: std::collections::VecDeque::with_capacity(capacity.min(1024)),
            }),
            drift_window,
            capacity,
        }
    }

    pub fn from_env() -> Self {
        Self::new(drift_window_from_env(), nonce_capacity_from_env())
    }

    /// Attempt to register a `(kid, nonce)` pair. Returns `true` if the pair
    /// is new (so the envelope is fresh) and `false` if it was already seen
    /// within the drift window (so the envelope is a replay).
    pub fn try_insert(&self, kid: [u8; 32], nonce: &str, ts: i64, now: i64) -> bool {
        let mut g = self.inner.lock();
        let drift_secs = self.drift_window.as_secs() as i64;

        // Age-driven eviction: pop from the front while entries are too old.
        while let Some((_, entry_ts)) = g.fifo.front() {
            if now.saturating_sub(*entry_ts) <= drift_secs {
                break;
            }
            if let Some((key, _)) = g.fifo.pop_front() {
                g.map.remove(&key);
            }
        }

        // Capacity-driven eviction: pop the oldest until we have room.
        while g.fifo.len() >= self.capacity {
            if let Some((key, _)) = g.fifo.pop_front() {
                g.map.remove(&key);
            } else {
                break;
            }
        }

        let composite = (kid, nonce.to_string());
        if g.map.contains_key(&composite) {
            return false;
        }
        g.map.insert(composite.clone(), ts);
        g.fifo.push_back((composite, ts));
        true
    }
}

/// The verifier struct held inside `AppState` and consulted by `require_auth`.
///
/// One per process; `Arc`-wrapped so the middleware closure can clone cheaply.
pub struct EnvelopeVerifier {
    expected_kid: [u8; 32],
    drift_window: Duration,
    nonce_store: Arc<NonceStore>,
}

impl EnvelopeVerifier {
    /// Construct a verifier from the gate signer's verifying-key bytes.
    /// Drift window + nonce capacity come from env (`ZP_GATE_DRIFT_WINDOW_SECS`,
    /// `ZP_GATE_NONCE_CAPACITY`) with safe defaults.
    pub fn new(expected_kid: [u8; 32]) -> Self {
        let drift_window = drift_window_from_env();
        let nonce_store = Arc::new(NonceStore::new(drift_window, nonce_capacity_from_env()));
        Self {
            expected_kid,
            drift_window,
            nonce_store,
        }
    }

    /// Verify a `ZP-Sig` envelope from the live request. Returns the parsed
    /// claims on success (the envelope passed every structural and
    /// cryptographic check). Returns the specific reject reason on failure.
    ///
    /// Inputs are split deliberately: the header carries `v, kid, ts, nonce,
    /// sig`; method/path/body come from the live request. The verifier
    /// reconstructs the full `EnvelopeClaims` (the bytes the signer signed)
    /// from both sources — that's what binds the signature to *this* request,
    /// not just a syntactically-valid envelope.
    pub fn verify(
        &self,
        auth_header: &str,
        request_method: &str,
        request_path_and_query: &str,
        request_body: &[u8],
        now: i64,
    ) -> Result<EnvelopeClaims, EnvelopeReject> {
        let parsed = parse_header(auth_header).map_err(map_parse_error)?;

        if parsed.v != zp_gate_envelope::SCHEME_VERSION {
            return Err(EnvelopeReject::UnknownVersion);
        }

        if parsed.kid != self.expected_kid {
            return Err(EnvelopeReject::UnknownSigner);
        }

        // Drift window check before any expensive work.
        let drift_secs = self.drift_window.as_secs() as i64;
        if (now - parsed.ts).abs() > drift_secs {
            return Err(EnvelopeReject::Drift);
        }

        // Reconstruct the full claims using request-derived fields.
        let body_hash = zp_gate_envelope::body_hash_hex(request_body);
        let claims = parsed.clone().into_claims(
            request_method.to_string(),
            request_path_and_query.to_string(),
            body_hash,
        );

        // Replay protection: try to register the nonce. The pair is keyed on
        // (kid, nonce) so different signers can use the same nonce
        // independently. We register before signature verification because a
        // nonce reuse with a forged signature is still a replay attempt — the
        // legitimate envelope was already accepted.
        if !self
            .nonce_store
            .try_insert(parsed.kid, &parsed.nonce, parsed.ts, now)
        {
            return Err(EnvelopeReject::Replay);
        }

        // Cryptographic verification — single primitive (Seam 5).
        zp_receipt::verify_signed(&claims, &parsed.kid, &parsed.sig).map_err(|_| {
            // Distinguish binding failures (method/path/body mismatch — the
            // preimage differed because of the wrong inputs) from a genuine
            // signature failure. We can't tell the two apart structurally —
            // verify_strict just says "mismatch" — but we can rebuild the
            // claims using only header inputs (skipping request-derived ones)
            // and check whether *those* match. If they would, the binding
            // diverged; otherwise the signature itself is bad.
            //
            // For v1 we report `envelope-signature` uniformly since the
            // operator-facing distinction is small and the structural shape
            // is identical. Future: split into envelope-binding vs
            // envelope-signature based on the diff site.
            EnvelopeReject::Signature
        })?;

        Ok(claims)
    }

    /// Verifier's expected `kid` for diagnostics (e.g. logging).
    pub fn expected_kid_hex(&self) -> String {
        hex::encode(self.expected_kid)
    }

    /// Drift window for diagnostics.
    pub fn drift_window(&self) -> Duration {
        self.drift_window
    }
}

fn map_parse_error(e: zp_gate_envelope::ParseError) -> EnvelopeReject {
    use zp_gate_envelope::ParseError;
    match e {
        ParseError::NotZpSig => EnvelopeReject::Malformed,
        ParseError::WrongFieldCount => EnvelopeReject::Malformed,
        ParseError::MalformedField(_) => EnvelopeReject::Malformed,
        ParseError::InvalidValue(_) => EnvelopeReject::Malformed,
    }
}

/// True if the `Authorization` header (if present) is a ZP-Sig envelope.
/// Cheap structural check used by the middleware to decide whether to take
/// the envelope path or fall through to the legacy bearer/cookie path.
pub fn is_envelope_header(value: &str) -> bool {
    value.starts_with("ZP-Sig ")
}

/// Number of bytes a nonce decodes to, re-exported for tests that build
/// nonce values inline.
#[doc(hidden)]
pub const _NONCE_BYTES_HINT: usize = NONCE_BYTES;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use zp_gate_envelope::{
        body_hash_hex, build_header, random_nonce_b64, EnvelopeClaims, SCHEME_VERSION,
    };
    use zp_receipt::Signable;

    fn make_signed(
        sk: &SigningKey,
        method: &str,
        path: &str,
        body: &[u8],
        ts: i64,
    ) -> (String, EnvelopeClaims) {
        let claims = EnvelopeClaims {
            v: SCHEME_VERSION,
            method: method.to_string(),
            path: path.to_string(),
            body_hash: body_hash_hex(body),
            ts,
            nonce: random_nonce_b64(),
        };
        let kid = sk.verifying_key().to_bytes();
        let sig = sk.sign(&claims.canonical_hash()).to_bytes();
        let header = build_header(&claims, &kid, &sig);
        (header, claims)
    }

    fn fresh_signer() -> SigningKey {
        let seed = zp_keys::derive_gate_signer_seed(&[0x77u8; 32]);
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn valid_envelope_verifies() {
        let sk = fresh_signer();
        let kid = sk.verifying_key().to_bytes();
        let verifier = EnvelopeVerifier::new(kid);
        let now = 1_700_000_000;
        let (header, claims) = make_signed(&sk, "POST", "/api/v1/gate/tool-call", b"{}", now);
        let got = verifier
            .verify(&header, "POST", "/api/v1/gate/tool-call", b"{}", now)
            .expect("must verify");
        assert_eq!(got.method, claims.method);
        assert_eq!(got.path, claims.path);
        assert_eq!(got.nonce, claims.nonce);
    }

    #[test]
    fn rejects_unknown_signer() {
        let sk = fresh_signer();
        let wrong_kid = [0u8; 32];
        let verifier = EnvelopeVerifier::new(wrong_kid);
        let now = 1_700_000_000;
        let (header, _) = make_signed(&sk, "POST", "/x", b"{}", now);
        let err = verifier
            .verify(&header, "POST", "/x", b"{}", now)
            .unwrap_err();
        assert_eq!(err, EnvelopeReject::UnknownSigner);
    }

    #[test]
    fn rejects_method_mismatch_via_signature() {
        let sk = fresh_signer();
        let kid = sk.verifying_key().to_bytes();
        let verifier = EnvelopeVerifier::new(kid);
        let now = 1_700_000_000;
        let (header, _) = make_signed(&sk, "POST", "/x", b"{}", now);
        // Present envelope as GET → preimage differs → signature mismatch.
        let err = verifier
            .verify(&header, "GET", "/x", b"{}", now)
            .unwrap_err();
        assert_eq!(err, EnvelopeReject::Signature);
    }

    #[test]
    fn rejects_body_tamper_via_signature() {
        let sk = fresh_signer();
        let kid = sk.verifying_key().to_bytes();
        let verifier = EnvelopeVerifier::new(kid);
        let now = 1_700_000_000;
        let (header, _) = make_signed(&sk, "POST", "/x", b"{\"a\":1}", now);
        let err = verifier
            .verify(&header, "POST", "/x", b"{\"a\":2}", now)
            .unwrap_err();
        assert_eq!(err, EnvelopeReject::Signature);
    }

    #[test]
    fn rejects_outside_drift_window() {
        let sk = fresh_signer();
        let kid = sk.verifying_key().to_bytes();
        let verifier = EnvelopeVerifier::new(kid);
        let now = 1_700_000_000;
        // Sign with ts that's 1 hour in the past.
        let (header, _) = make_signed(&sk, "POST", "/x", b"{}", now - 3600);
        let err = verifier
            .verify(&header, "POST", "/x", b"{}", now)
            .unwrap_err();
        assert_eq!(err, EnvelopeReject::Drift);
    }

    #[test]
    fn rejects_replayed_nonce() {
        let sk = fresh_signer();
        let kid = sk.verifying_key().to_bytes();
        let verifier = EnvelopeVerifier::new(kid);
        let now = 1_700_000_000;
        let (header, _) = make_signed(&sk, "POST", "/x", b"{}", now);
        verifier
            .verify(&header, "POST", "/x", b"{}", now)
            .expect("first ok");
        let err = verifier
            .verify(&header, "POST", "/x", b"{}", now)
            .unwrap_err();
        assert_eq!(err, EnvelopeReject::Replay);
    }

    #[test]
    fn rejects_unknown_version() {
        let sk = fresh_signer();
        let kid = sk.verifying_key().to_bytes();
        let verifier = EnvelopeVerifier::new(kid);
        let now = 1_700_000_000;
        let claims = EnvelopeClaims {
            v: 99,
            method: "POST".into(),
            path: "/x".into(),
            body_hash: body_hash_hex(b"{}"),
            ts: now,
            nonce: random_nonce_b64(),
        };
        let sig = sk.sign(&claims.canonical_hash()).to_bytes();
        let header = build_header(&claims, &kid, &sig);
        let err = verifier
            .verify(&header, "POST", "/x", b"{}", now)
            .unwrap_err();
        assert_eq!(err, EnvelopeReject::UnknownVersion);
    }

    #[test]
    fn rejects_malformed_header() {
        let sk = fresh_signer();
        let kid = sk.verifying_key().to_bytes();
        let verifier = EnvelopeVerifier::new(kid);
        let err = verifier
            .verify("not a zp-sig header", "POST", "/x", b"{}", 1_700_000_000)
            .unwrap_err();
        assert_eq!(err, EnvelopeReject::Malformed);
    }

    #[test]
    fn is_envelope_header_recognizes_zp_sig() {
        assert!(is_envelope_header("ZP-Sig v=1, kid=, ts=, nonce=, sig="));
        assert!(!is_envelope_header("Bearer abc"));
        assert!(!is_envelope_header(""));
    }
}
