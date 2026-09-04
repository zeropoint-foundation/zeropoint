//! The CIMD document itself.
//!
//! Field shape per the CIMD spec text preserved in
//! `docs/design/MCP-COMPOSITION-2026-08.md` Appendix B: *"The metadata
//! document MUST include at least the following properties: `client_id`,
//! `client_name`, `redirect_uris`... Clients MUST ensure the `client_id`
//! value in the metadata matches the document URL exactly."* `jwks` is
//! optional per design doc §3 (v1 ships without it).

use serde::{Deserialize, Serialize};

use crate::client_id::{ClientIdScheme, GenesisFingerprint};
use crate::client_name::RegentNameState;

/// One entry of a JSON Web Key Set. Ed25519-as-OKP shape (RFC 8037) — the
/// only key type the substrate's `client_auth_key` (design doc §3,
/// deferred) would ever produce, since KEEL §II.1 fixes Ed25519 as the
/// substrate's signing algorithm. Not populated in v1 — see
/// [`build_cimd_document`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String, // "OKP"
    pub crv: String, // "Ed25519"
    /// Base64url-encoded (no padding) raw public key bytes.
    pub x: String,
    #[serde(rename = "use")]
    pub key_use: String, // "sig"
    pub alg: String, // "EdDSA"
    /// Design doc §3: reserved context tag for this key's derivation is
    /// `"zp.cimd.client_auth.v1"` (see `client_auth_key.rs`); `kid` should
    /// be the derived key's public bytes, hex-encoded, matching the `kid`
    /// convention `GateRequestSigner::kid()` already uses for the same
    /// purpose on a different key.
    pub kid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// The published document. Field order matches the spec quote above.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CimdDocument {
    /// MUST equal the URL this document is served from — CIMD's own
    /// self-consistency check, verified by the authorization server.
    pub client_id: String,
    /// Design doc §4: committed Regent name verbatim, or the fixed
    /// pre-named marker. See [`crate::client_name`].
    pub client_name: String,
    /// Design doc §4: always exactly one entry, hosting-location-relative,
    /// invariant under active-presence handoff. See [`crate::redirect`].
    pub redirect_uris: Vec<String>,
    /// Design doc §3: absent in v1. `Some` only once `client_auth_key`
    /// (deferred) is built and a concrete AS requires `private_key_jwt`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Jwks>,
}

/// Build the document from substrate state. Pure and deterministic given
/// its inputs — no network, no `todo!()` in principle — but it is `todo!()`
/// here because it composes [`crate::client_id::client_id_url`], which
/// itself needs configuration this scaffold doesn't have (design doc §1/§2
/// were left to Ken). Once that is resolved this function's body is a
/// one-line struct literal: the hard part (what each field *should* be) is
/// already decided by design doc §4 and implemented in
/// `client_name.rs`/`redirect.rs`.
///
/// `hosting_base` is the origin `redirect_uris` is built relative to (see
/// [`crate::redirect::redirect_uris`]) — for [`ClientIdScheme::FoundationMirror`]
/// or [`ClientIdScheme::SelfHosted`] this is the same origin `client_id`
/// resolves under; unused (and should be `None`) for
/// [`ClientIdScheme::PreRegistered`], which has no hosted document at all.
pub fn build_cimd_document(
    fingerprint: &GenesisFingerprint,
    scheme: ClientIdScheme,
    hosting_base: Option<&str>,
    name_state: &RegentNameState,
) -> CimdDocument {
    let _ = (fingerprint, scheme, hosting_base, name_state);
    todo!(
        "one-line struct literal once client_id_url() has a base to derive from — \
         client_name and redirect_uris are already implemented for real in this crate; \
         see client_name.rs and redirect.rs"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the wire shape independent of the `todo!()` construction
    /// function above, so the serde contract is tested even before
    /// `build_cimd_document` has a real body.
    #[test]
    fn document_without_jwks_omits_the_field() {
        let doc = CimdDocument {
            client_id: "https://identity.zeropoint.foundation/abc/client.json".into(),
            client_name: "ZeroPoint Substrate (Regent pre-named)".into(),
            redirect_uris: vec!["https://identity.zeropoint.foundation/abc/oauth/callback".into()],
            jwks: None,
        };
        let v = serde_json::to_value(&doc).unwrap();
        assert!(v.get("jwks").is_none(), "v1 documents must omit jwks entirely, not null it");
    }
}
