//! `client_id` URL scheme — design decision 1.
//!
//! Per `docs/design/IDENTITY-HOSTING-ADAPTER-2026-09.md` §1: the substrate's
//! canonical identifier is a Genesis pubkey; every identity-interop surface
//! (CIMD, AGNTCY well-known, IETF-cluster URN) wants a URL or URN derived
//! from it. This module names the two surviving hosting schemes plus the
//! no-hosting fallback. It deliberately has **no** variant for the literal
//! `https://<fingerprint>.zp/...` scheme named as "Option A" in the design
//! doc's source handoff — that scheme is DNS-label-invalid for a full
//! fingerprint (see [`GenesisFingerprint`] below) independent of the "no
//! DNS-under-controlled-TLD infrastructure" problem, and reintroducing it
//! here would silently resurrect a rejected KEEL-level infrastructure
//! commitment. If a future session revisits that rejection, it should do so
//! by amending §1 of the design doc, not by adding a variant here.

use serde::{Deserialize, Serialize};

/// The Genesis pubkey fingerprint, as computed today at
/// `crates/zp-server/src/onboard/genesis.rs:359`:
/// `blake3::hash(genesis.public_key().as_ref()).to_hex().to_string()` — a
/// 64-character lowercase hex string (BLAKE3-256 output).
///
/// This type does not recompute that hash. It exists to carry the value
/// from wherever the real Genesis-ceremony code already produces it (inside
/// `zp-server/src/onboard/`, out of scope for this scaffold) into the
/// hosting-adapter code, with one structural check attached: a full
/// fingerprint does not fit in a single DNS label (RFC 1035 §2.3.4 caps a
/// label at 63 octets; the fingerprint is 64 hex characters). Neither
/// surviving scheme in [`ClientIdScheme`] needs a DNS-label-shaped
/// fingerprint — both place it in a URL *path*, which has no such limit —
/// so [`Self::fits_dns_label`] exists only to make that constraint
/// impossible to forget if a future scheme ever wants one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GenesisFingerprint(String);

/// Errors constructing a [`GenesisFingerprint`] from an untrusted string.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FingerprintError {
    #[error("genesis fingerprint must be exactly 64 lowercase hex characters, got {0} characters")]
    WrongLength(usize),
    #[error("genesis fingerprint must be lowercase hex; found non-hex byte at index {0}")]
    NotHex(usize),
}

impl GenesisFingerprint {
    /// Validate and wrap a fingerprint string. Does not compute it — the
    /// caller must have it already, from the real onboarding-ceremony code.
    pub fn parse(fingerprint: &str) -> Result<Self, FingerprintError> {
        if fingerprint.len() != 64 {
            return Err(FingerprintError::WrongLength(fingerprint.len()));
        }
        if let Some(idx) = fingerprint
            .bytes()
            .position(|b| !(b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        {
            return Err(FingerprintError::NotHex(idx));
        }
        Ok(Self(fingerprint.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `true` if this fingerprint (or a documented truncation of it) would
    /// fit a single DNS label. Always `false` for the full 64-hex-char form
    /// today — see the module doc comment. Exists so that if a future
    /// scheme genuinely needs a DNS-label-shaped identifier, the person
    /// adding it trips over this check rather than an unhelpful DNS
    /// resolution failure at hosting time.
    pub fn fits_dns_label(&self) -> bool {
        self.0.len() <= 63
    }
}

/// The surviving `client_id` hosting schemes per design doc §1/§2. Carries
/// no data of its own beyond which scheme — the actual base domain/path for
/// [`ClientIdScheme::FoundationMirror`] and [`ClientIdScheme::SelfHosted`]
/// is operator/Foundation configuration, not part of this enum, so that
/// choosing a scheme and configuring its target are separate decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientIdScheme {
    /// `https://identity.zeropoint.foundation/<fingerprint>/client.json` (or
    /// whatever base the Foundation actually stands up). Design doc §1/§2:
    /// default for Sovereign and Companion Forms, fallback for Appliance
    /// Form. Structurally identical to the existing Foundation edge-relay
    /// shape (`crates/zp-cloudflare`, `foundation_edge_signer.rs`) — an
    /// availability dependency on the Foundation, not an authority one.
    FoundationMirror,
    /// A domain the operator already owns and keeps reachable, e.g.
    /// `https://<operator-domain>/.well-known/zp/identity/<fingerprint>/client.json`
    /// (design doc §5: reconcile this path with the existing
    /// `/.well-known/zeropoint/sovereign.json` convention from
    /// `DISCOVERY-AND-BOOTSTRAP-2026-07.md` rather than inventing a second
    /// one — left to the implementation session). Design doc §1/§2: default
    /// for Appliance Form, opt-in override for Sovereign Form, not offered
    /// on Companion Form.
    SelfHosted,
    /// No hosting adapter runs at all. The substrate registers static,
    /// out-of-band client credentials directly with each external
    /// authorization server the operator chooses to use, per MCP's own
    /// "DCR... retained for backwards compatibility with authorization
    /// servers that do not support CIMD." Design doc §2: the universal
    /// fallback on every Form when the operator declines both hosting
    /// options above. There is no `client_id` URL in this mode — hence no
    /// [`GenesisFingerprint`] is even needed for it.
    PreRegistered,
}

/// Build the `client_id` URL for a hosted scheme. `todo!()` — the base
/// domain/path for each scheme is operator or Foundation configuration this
/// scaffold does not have, and [`ClientIdScheme::PreRegistered`] has no
/// URL at all (this function should not be called for it; the
/// implementation session should decide whether that's a precondition or a
/// `None` return — design doc does not decide this).
pub fn client_id_url(fingerprint: &GenesisFingerprint, scheme: ClientIdScheme) -> String {
    let _ = (fingerprint, scheme);
    todo!(
        "needs the configured base domain/path for FoundationMirror or SelfHosted; \
         see IDENTITY-HOSTING-ADAPTER-2026-09.md §5 on reconciling the self-hosted \
         path with the existing /.well-known/zeropoint/ convention"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_wrong_length() {
        assert_eq!(
            GenesisFingerprint::parse("abcd"),
            Err(FingerprintError::WrongLength(4))
        );
    }

    #[test]
    fn parse_rejects_non_hex() {
        let mut s = "a".repeat(64);
        s.replace_range(10..11, "z");
        assert_eq!(GenesisFingerprint::parse(&s), Err(FingerprintError::NotHex(10)));
    }

    #[test]
    fn parse_accepts_real_shaped_fingerprint() {
        let fp = "b".repeat(64);
        assert!(GenesisFingerprint::parse(&fp).is_ok());
    }

    #[test]
    fn full_fingerprint_does_not_fit_a_dns_label() {
        let fp = GenesisFingerprint::parse(&"c".repeat(64)).unwrap();
        assert!(
            !fp.fits_dns_label(),
            "a 64-hex-char fingerprint is 64 octets; RFC 1035 §2.3.4 caps a label at 63"
        );
    }
}
