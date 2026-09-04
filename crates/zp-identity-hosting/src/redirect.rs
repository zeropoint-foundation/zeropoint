//! `redirect_uris` derivation — design decision 4, second half. The
//! `redirect_uris` list itself is fully settled (this file implements it
//! for real); the endpoint that actually catches the redirect is `todo!()`
//! because its wiring is Form/adapter-dependent.
//!
//! Design doc §4's core finding: a `redirect_uris` entry must **not** point
//! at the active-presence device, because active presence migrates (KEEL
//! §V.4 handoff) on a timeline the CIMD document — cached by external
//! authorization servers — cannot track. Instead, `redirect_uris` names a
//! single fixed endpoint co-located with the hosted document itself, whose
//! only job is to catch the OAuth redirect and queue it for whichever
//! device is active presence to consume on its next cycle. That makes
//! `redirect_uris` invariant under handoff by construction: it is derived
//! once, from the hosting location, and never touched again.

/// Path segment for the redirect-capture endpoint, appended to whatever
/// origin the CIMD document itself is served from.
pub const OAUTH_CALLBACK_PATH: &str = "oauth/callback";

/// The `redirect_uris` list for a hosted CIMD document: always exactly one
/// entry, at `{hosting_base}/oauth/callback`. `hosting_base` is the same
/// origin `client_id` resolves under (e.g.
/// `https://identity.zeropoint.foundation/<fingerprint>` for the
/// Foundation-mirror scheme, or the operator's own domain path for
/// self-hosted) — trailing slashes are tolerated and normalized away.
pub fn redirect_uris(hosting_base: &str) -> Vec<String> {
    let base = hosting_base.trim_end_matches('/');
    vec![format!("{base}/{OAUTH_CALLBACK_PATH}")]
}

/// What a captured redirect hand-off looks like once the callback endpoint
/// below receives it. Deliberately does not decide (design doc §7) whether
/// this becomes a chain-anchored receipt (once `MCP-COMPOSITION-2026-08.md`
/// §6.1's MCP-as-Extension ceremony lands and gives it a receipt family to
/// live in) or a plain in-memory/on-disk queued item until then — both
/// implementations can produce this same struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedAuthorizationCode {
    pub code: String,
    /// Echoed back verbatim, per OAuth's CSRF-binding convention — the
    /// caller that initiated the authorization request is responsible for
    /// matching this against what it sent, not this module.
    pub state: String,
}

/// `todo!()` — the actual HTTP handler that receives the OAuth redirect and
/// produces a [`CapturedAuthorizationCode`]. Left unimplemented because its
/// wiring is Form-and-adapter-dependent (design doc §6): for
/// [`crate::client_id::ClientIdScheme::SelfHosted`] this is a route on the
/// substrate's own HTTP listener (Appliance Form's always-on server, or a
/// Sovereign-Form operator's self-hosted listener); for
/// [`crate::client_id::ClientIdScheme::FoundationMirror`] this is a new
/// inbound route on the Foundation Worker, the mirror image of its existing
/// outbound edge-relay path — Foundation-side infrastructure, out of this
/// crate's authority per design doc §7.
pub fn handle_oauth_redirect(query_string: &str) -> CapturedAuthorizationCode {
    let _ = query_string;
    todo!("Form/adapter-dependent HTTP wiring — see IDENTITY-HOSTING-ADAPTER-2026-09.md §6")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_exactly_one_redirect_uri() {
        let uris = redirect_uris("https://identity.zeropoint.foundation/abc123");
        assert_eq!(uris.len(), 1);
        assert_eq!(
            uris[0],
            "https://identity.zeropoint.foundation/abc123/oauth/callback"
        );
    }

    #[test]
    fn trailing_slash_on_base_is_normalized() {
        let uris = redirect_uris("https://identity.zeropoint.foundation/abc123/");
        assert_eq!(
            uris[0],
            "https://identity.zeropoint.foundation/abc123/oauth/callback"
        );
    }

    #[test]
    fn redirect_uri_has_no_per_device_component() {
        // The whole point: nothing device-identifying goes into this URL.
        let uris = redirect_uris("https://identity.zeropoint.foundation/abc123");
        assert!(!uris[0].contains("device"));
    }
}
