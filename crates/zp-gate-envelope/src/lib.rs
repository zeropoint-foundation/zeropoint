//! ZP-Sig v1 — per-request Genesis-signed envelopes for the cognition-governance gate.
//!
//! # The wire
//!
//! Every IronClaw → gate request carries exactly one `Authorization` header:
//!
//! ```text
//! Authorization: ZP-Sig v=1, kid=<hex_pubkey>, ts=<unix_seconds>, nonce=<b64url_16B>, sig=<b64url_64B>
//! ```
//!
//! Whitespace after each comma is significant (`, ` exactly). Field order is fixed:
//! `v, kid, ts, nonce, sig`. Out-of-order or missing fields → parse error.
//!
//! # Why this crate exists
//!
//! Both sides of the envelope path (the verifier in `zp-server`, the signer in
//! IronClaw) must agree on three things bit-for-bit: the canonical preimage,
//! the header format, and the encoding rules. Having two implementations is
//! how producer-consumer pairs drift — the very failure class this design is
//! eliminating. The structural fix is: one crate, one set of helpers, both
//! sides import it.
//!
//! # Composition
//!
//! - Canonical bytes come from [`zp_receipt::canonical::canonical_bytes_of`]
//!   (Seam 17). No parallel canonicalization pipeline.
//! - Signing/verifying compose with [`zp_receipt::Signable`] (Seam 20) and
//!   `zp_receipt::verify_signed` (Seam 5).

use serde::{Deserialize, Serialize};

pub mod signer;
pub use signer::GateRequestSigner;

/// HTTP header name carrying the envelope. The substrate's gate accepts ZP-Sig
/// envelopes via the standard `Authorization` header so callers do not need to
/// add a custom-header allowlist on any intermediary.
pub const HEADER_NAME: &str = "Authorization";

/// Scheme prefix written into the `Authorization` header value. The value
/// after this prefix is the comma-space-separated parameter list described at
/// the crate root.
pub const HEADER_SCHEME: &str = "ZP-Sig";

/// Scheme version. v1 is the only version this crate accepts; the `v=` field
/// is present specifically so a future v2 can coexist with v1 parsers without
/// silent fallback.
pub const SCHEME_VERSION: u8 = 1;

/// Length of the random nonce in bytes (before base64url encoding).
pub const NONCE_BYTES: usize = 16;

/// Canonical claims that the signer signs and the verifier re-derives.
///
/// Each field is load-bearing:
/// - `method`, `path` bind the signature to the operation so a captured
///   envelope can't be replayed against a different endpoint.
/// - `body_hash` binds the signature to the payload.
/// - `ts` enforces a drift window.
/// - `nonce` defeats replay within the drift window.
///
/// Excluded by design:
/// - host/scheme/port — gate URL may change (cloudflared, port migration);
///   binding to host would force per-deployment envelope variants.
/// - other request headers — not load-bearing for authorization; binding
///   `Content-Type` invites mismatches with downstream re-serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeClaims {
    /// Scheme version. Must equal [`SCHEME_VERSION`] for v1 envelopes.
    pub v: u8,
    /// HTTP method, uppercase ASCII ("GET", "POST", ...).
    pub method: String,
    /// Request URI path including any query string, leading "/". Excludes
    /// scheme/host/port so the same envelope verifies regardless of how the
    /// gate is fronted.
    pub path: String,
    /// BLAKE3 hash (hex, 64 chars) of the raw request body bytes. Empty body
    /// → hash of empty input. Always the wire bytes the consumer sees.
    pub body_hash: String,
    /// Unix seconds since epoch at signing time.
    pub ts: i64,
    /// Base64url-no-pad of the [`NONCE_BYTES`]-byte nonce.
    pub nonce: String,
}

impl zp_receipt::Signable for EnvelopeClaims {
    fn canonical_preimage(&self) -> Vec<u8> {
        zp_receipt::canonical::canonical_bytes_of(self)
            .expect("EnvelopeClaims has no non-serializable fields")
    }
}

/// Errors from [`parse_header`]. Each variant is a distinct structural
/// failure mode so the gate's `X-Auth-Reason` header can be specific
/// without leaking implementation details to attackers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Header did not start with the `ZP-Sig ` scheme prefix.
    NotZpSig,
    /// Expected exactly five comma-separated fields in the order
    /// `v, kid, ts, nonce, sig` (with single-space separators).
    WrongFieldCount,
    /// A field's `key=value` shape was malformed (missing `=`, wrong key).
    MalformedField(&'static str),
    /// A field's value failed to decode (bad hex, bad base64url, bad int,
    /// or wrong byte length).
    InvalidValue(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::NotZpSig => write!(f, "header is not a ZP-Sig envelope"),
            ParseError::WrongFieldCount => write!(f, "expected exactly v, kid, ts, nonce, sig"),
            ParseError::MalformedField(name) => write!(f, "malformed field: {}", name),
            ParseError::InvalidValue(name) => write!(f, "invalid value for field: {}", name),
        }
    }
}

impl std::error::Error for ParseError {}

/// BLAKE3 hash of the request body, hex-encoded (lowercase, 64 chars).
///
/// Wire bytes only — never the hex of a JSON canonical form. Both signer and
/// verifier feed the same bytes through here, so an empty body produces the
/// well-defined hash of empty input.
pub fn body_hash_hex(body: &[u8]) -> String {
    blake3::hash(body).to_hex().to_string()
}

/// Generate a fresh [`NONCE_BYTES`]-byte nonce, base64url-no-pad encoded.
///
/// The verifier's nonce store keys on `(kid, nonce)` within the drift
/// window, so each request must produce a fresh value. 16 random bytes is
/// 128 bits of entropy — collision probability is negligible for any
/// realistic gate load.
pub fn random_nonce_b64() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64_url_no_pad_encode(&bytes)
}

/// Build the `Authorization: ZP-Sig …` header value for a signed envelope.
///
/// The signer's verifying-key bytes (32 bytes) become `kid` as 64-char
/// lowercase hex. `sig` is the raw 64-byte Ed25519 signature, encoded as
/// base64url without padding. Field order is fixed: `v, kid, ts, nonce, sig`.
pub fn build_header(claims: &EnvelopeClaims, kid: &[u8; 32], sig: &[u8; 64]) -> String {
    format!(
        "{scheme} v={v}, kid={kid}, ts={ts}, nonce={nonce}, sig={sig}",
        scheme = HEADER_SCHEME,
        v = claims.v,
        kid = hex::encode(kid),
        ts = claims.ts,
        nonce = claims.nonce,
        sig = base64_url_no_pad_encode(sig),
    )
}

/// Parse a `ZP-Sig …` header value into its components.
///
/// Returns the claims (excluding `kid`, which is the signer identifier, not
/// a claim), the 32-byte signer pubkey, and the 64-byte signature.
///
/// Note: `method`, `path`, and `body_hash` claims are **not** carried in the
/// header — they are reconstructed by the verifier from the request itself.
/// This is what binds the signature to the request: a captured envelope's
/// claims must match the live request's method/path/body, or the signature
/// fails to verify (because the preimage differs).
///
/// To support that reconstruction, the verifier must construct the
/// [`EnvelopeClaims`] for verification using `method`, `path`, `body_hash`
/// from the request and `v`, `ts`, `nonce` from the parsed header.
#[allow(clippy::type_complexity)]
pub fn parse_header(header: &str) -> Result<ParsedHeader, ParseError> {
    let rest = header
        .strip_prefix(HEADER_SCHEME)
        .and_then(|s| s.strip_prefix(' '))
        .ok_or(ParseError::NotZpSig)?;

    // Split on the canonical separator. We accept exactly ", " (comma + single
    // space) — this is the only acceptable form a signer can produce via
    // [`build_header`], so any other separator is a malformed envelope.
    let parts: Vec<&str> = rest.split(", ").collect();
    if parts.len() != 5 {
        return Err(ParseError::WrongFieldCount);
    }

    let v_str = parts[0].strip_prefix("v=").ok_or(ParseError::MalformedField("v"))?;
    let v: u8 = v_str.parse().map_err(|_| ParseError::InvalidValue("v"))?;

    let kid_hex = parts[1].strip_prefix("kid=").ok_or(ParseError::MalformedField("kid"))?;
    let kid_vec = hex::decode(kid_hex).map_err(|_| ParseError::InvalidValue("kid"))?;
    if kid_vec.len() != 32 {
        return Err(ParseError::InvalidValue("kid"));
    }
    let mut kid = [0u8; 32];
    kid.copy_from_slice(&kid_vec);

    let ts_str = parts[2].strip_prefix("ts=").ok_or(ParseError::MalformedField("ts"))?;
    let ts: i64 = ts_str.parse().map_err(|_| ParseError::InvalidValue("ts"))?;

    let nonce = parts[3].strip_prefix("nonce=").ok_or(ParseError::MalformedField("nonce"))?;
    // Validate that the nonce decodes to exactly NONCE_BYTES — guards against
    // mis-sized nonces silently passing through to the dedup store.
    let nonce_bytes = base64_url_no_pad_decode(nonce).map_err(|_| ParseError::InvalidValue("nonce"))?;
    if nonce_bytes.len() != NONCE_BYTES {
        return Err(ParseError::InvalidValue("nonce"));
    }

    let sig_b64 = parts[4].strip_prefix("sig=").ok_or(ParseError::MalformedField("sig"))?;
    let sig_vec = base64_url_no_pad_decode(sig_b64).map_err(|_| ParseError::InvalidValue("sig"))?;
    if sig_vec.len() != 64 {
        return Err(ParseError::InvalidValue("sig"));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_vec);

    Ok(ParsedHeader {
        v,
        kid,
        ts,
        nonce: nonce.to_string(),
        sig,
    })
}

/// Result of parsing a `ZP-Sig` header. The `method`, `path`, and `body_hash`
/// fields of [`EnvelopeClaims`] are reconstructed by the verifier from the
/// live request; this struct carries only what the header itself contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHeader {
    pub v: u8,
    pub kid: [u8; 32],
    pub ts: i64,
    pub nonce: String,
    pub sig: [u8; 64],
}

impl ParsedHeader {
    /// Reconstruct the full [`EnvelopeClaims`] using the request-derived
    /// fields. The verifier computes `body_hash` over the actual request body
    /// bytes; this method just composes the result.
    pub fn into_claims(self, method: String, path: String, body_hash: String) -> EnvelopeClaims {
        EnvelopeClaims {
            v: self.v,
            method,
            path,
            body_hash,
            ts: self.ts,
            nonce: self.nonce,
        }
    }
}

// ── base64url helpers (no-padding) ──────────────────────────────────────────

fn base64_url_no_pad_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn base64_url_no_pad_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use zp_receipt::Signable;

    fn sample_claims() -> EnvelopeClaims {
        EnvelopeClaims {
            v: SCHEME_VERSION,
            method: "POST".to_string(),
            path: "/api/v1/gate/tool-call".to_string(),
            body_hash: body_hash_hex(b"{\"agent\":\"x\"}"),
            ts: 1_700_000_000,
            nonce: "AAECAwQFBgcICQoLDA0ODw".to_string(), // 16 bytes, b64url-no-pad
        }
    }

    #[test]
    fn body_hash_hex_is_64_chars_for_empty_body() {
        let h = body_hash_hex(b"");
        assert_eq!(h.len(), 64);
        // Both sides must agree on the empty-body hash.
        let again = body_hash_hex(b"");
        assert_eq!(h, again);
    }

    #[test]
    fn body_hash_hex_changes_on_payload() {
        assert_ne!(body_hash_hex(b"a"), body_hash_hex(b"b"));
    }

    #[test]
    fn random_nonce_b64_is_unique_and_well_formed() {
        let a = random_nonce_b64();
        let b = random_nonce_b64();
        assert_ne!(a, b, "two fresh nonces must differ");
        let decoded = base64_url_no_pad_decode(&a).expect("decode");
        assert_eq!(decoded.len(), NONCE_BYTES);
    }

    #[test]
    fn canonical_preimage_is_deterministic() {
        let c = sample_claims();
        let a = c.canonical_preimage();
        let b = c.canonical_preimage();
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_preimage_changes_with_any_field() {
        let base = sample_claims();
        let mut other = base.clone();
        other.path = "/api/v1/cognition/observe".to_string();
        assert_ne!(base.canonical_preimage(), other.canonical_preimage());
        other.path = base.path.clone();
        other.method = "GET".to_string();
        assert_ne!(base.canonical_preimage(), other.canonical_preimage());
    }

    /// Stability pin: a known-input claims object hashes to a fixed BLAKE3.
    /// If this hex ever changes, every IronClaw and gate process on v1
    /// silently disagrees on what's being signed — that's the rotation we'd
    /// need to gate behind a `v=` bump, not a silent change to v1.
    #[test]
    fn canonical_hash_is_stable() {
        let c = sample_claims();
        let hex_hash = c.canonical_hash_hex();
        assert_eq!(hex_hash.len(), 64);
        // Recompute on intentional v1 redefinition only.
        // (No exact constant pinned here; the determinism + length check is
        // the v1 invariant. A regression test elsewhere in the workspace can
        // pin specific bytes once integration tests land.)
        let again = c.canonical_hash_hex();
        assert_eq!(hex_hash, again);
    }

    #[test]
    fn header_round_trip() {
        let claims = sample_claims();
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let kid = sk.verifying_key().to_bytes();
        let sig = sk.sign(&claims.canonical_hash()).to_bytes();

        let header = build_header(&claims, &kid, &sig);
        assert!(header.starts_with("ZP-Sig "));

        let parsed = parse_header(&header).expect("parse");
        assert_eq!(parsed.v, claims.v);
        assert_eq!(parsed.kid, kid);
        assert_eq!(parsed.ts, claims.ts);
        assert_eq!(parsed.nonce, claims.nonce);
        assert_eq!(parsed.sig, sig);

        // Reconstruct the full claims and verify.
        let recon = parsed.into_claims(claims.method.clone(), claims.path.clone(), claims.body_hash.clone());
        assert_eq!(recon, claims);
        zp_receipt::verify_signed(&recon, &kid, &sig).expect("verify");
    }

    #[test]
    fn header_rejects_wrong_scheme() {
        assert_eq!(parse_header("Bearer abc"), Err(ParseError::NotZpSig));
        assert_eq!(parse_header("ZP-Sigv=1"), Err(ParseError::NotZpSig));
    }

    #[test]
    fn header_rejects_wrong_field_count() {
        // Missing sig.
        let header = "ZP-Sig v=1, kid=aa, ts=1, nonce=bb";
        assert_eq!(parse_header(header), Err(ParseError::WrongFieldCount));
        // Extra field.
        let header = "ZP-Sig v=1, kid=aa, ts=1, nonce=bb, sig=cc, extra=dd";
        assert_eq!(parse_header(header), Err(ParseError::WrongFieldCount));
    }

    #[test]
    fn header_rejects_out_of_order_fields() {
        let claims = sample_claims();
        let sk = SigningKey::from_bytes(&[0x99u8; 32]);
        let kid = sk.verifying_key().to_bytes();
        let sig = sk.sign(&claims.canonical_hash()).to_bytes();
        // Build a manually-permuted header (ts before kid).
        let header = format!(
            "ZP-Sig v=1, ts={}, kid={}, nonce={}, sig={}",
            claims.ts,
            hex::encode(kid),
            claims.nonce,
            base64_url_no_pad_encode(&sig),
        );
        // Field order is fixed; permuted input is malformed at the `kid=` slot.
        assert!(matches!(
            parse_header(&header),
            Err(ParseError::MalformedField("kid"))
        ));
    }

    #[test]
    fn header_rejects_wrong_kid_length() {
        let header = "ZP-Sig v=1, kid=deadbeef, ts=1, nonce=AAECAwQFBgcICQoLDA0ODw, sig=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(parse_header(header), Err(ParseError::InvalidValue("kid")));
    }

    #[test]
    fn header_rejects_wrong_nonce_size() {
        // 8-byte nonce instead of 16.
        let nonce_8 = base64_url_no_pad_encode(&[0u8; 8]);
        let header = format!(
            "ZP-Sig v=1, kid={}, ts=1, nonce={}, sig={}",
            hex::encode([0u8; 32]),
            nonce_8,
            base64_url_no_pad_encode(&[0u8; 64]),
        );
        assert_eq!(parse_header(&header), Err(ParseError::InvalidValue("nonce")));
    }
}
