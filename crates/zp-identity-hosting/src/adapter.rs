//! The `IdentityHostingAdapter` port, and one stub per surviving
//! [`crate::client_id::ClientIdScheme`].
//!
//! Mirrors `crates/zp-cloudflare/src/adapter/mod.rs`'s stated philosophy:
//! ports are defined upstream and are pure ZeroPoint (no vendor types);
//! adapters implement a port using a specific vendor's or transport's
//! primitives; every adapter has a documented, structurally-supported
//! fallback so no single vendor becomes load-bearing for the port itself.
//! Here the three "vendors" are the Foundation's Cloudflare Worker, the
//! operator's own listener, and "no network at all" (pre-registration).

use async_trait::async_trait;

use crate::client_id::GenesisFingerprint;
use crate::document::CimdDocument;

/// Where a publish call put the document, for logging/observation. Not a
/// receipt — per `crates/zp-cloudflare`'s rule 2 ("All ZP↔CF transitions
/// emit receipts"), the real adapter implementations should additionally
/// emit a chain-anchored receipt at every boundary crossing; that emission
/// is implementation-session work, not represented in this scaffold type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedLocation {
    pub url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum HostingError {
    #[error("hosting target unreachable: {0}")]
    Unreachable(String),
    #[error("operator has not opted in to this hosting mode")]
    NotOptedIn,
    #[error("hosting adapter not yet implemented: {0}")]
    Unimplemented(&'static str),
}

/// The port every hosting mode implements. Kept deliberately small — two
/// methods — because everything else about *what* gets published
/// ([`CimdDocument`] construction) is already decided in `document.rs`,
/// `client_name.rs`, and `redirect.rs`; this trait is only about *where*.
#[async_trait]
pub trait IdentityHostingAdapter: Send + Sync {
    /// Publish (or re-publish, on naming/renaming — design doc §4) the
    /// document. Idempotent: calling this again with an unchanged document
    /// must be a no-op from the outside, since the naming ceremony's
    /// post-naming propagation hook (design doc §4) may call this on every
    /// cognitive cycle boundary, not just on an actual change.
    async fn publish(&self, doc: &CimdDocument) -> Result<PublishedLocation, HostingError>;

    /// The base origin this adapter serves the document under, for a given
    /// fingerprint — what [`crate::client_id::client_id_url`] and
    /// [`crate::redirect::redirect_uris`] both need as their `hosting_base`
    /// input. Distinct from `publish`'s return value because this must be
    /// computable *before* a first successful publish (to build the
    /// document that gets published in the first place).
    fn hosting_base(&self, fingerprint: &GenesisFingerprint) -> String;
}

/// Design doc §1 Option B / §2 default for Sovereign and Companion Forms,
/// fallback for Appliance Form. Structurally identical in shape to the
/// existing Foundation edge-relay adapter
/// (`crates/zp-cloudflare`, keyed with
/// `zp-keys/src/foundation_edge_signer.rs`'s domain-separated key) — an
/// availability dependency on the Foundation, never an authority one (the
/// document this adapter publishes is already Genesis-signed before it
/// ever reaches the Foundation).
pub struct FoundationMirrorAdapter {
    // Real fields (implementation session): the Foundation Worker's base
    // URL, and whatever client the adapter uses to reach it — almost
    // certainly reusing machinery already in `crates/zp-cloudflare`'s
    // adapter layer rather than inventing a second HTTP client.
}

#[async_trait]
impl IdentityHostingAdapter for FoundationMirrorAdapter {
    async fn publish(&self, doc: &CimdDocument) -> Result<PublishedLocation, HostingError> {
        let _ = doc;
        todo!(
            "needs the Foundation Worker's new inbound route — design doc §6, \
             'Foundation-side' — which does not exist yet"
        )
    }

    fn hosting_base(&self, fingerprint: &GenesisFingerprint) -> String {
        let _ = fingerprint;
        todo!("needs the Foundation's actual configured base domain")
    }
}

/// Design doc §1 Option D / §2 default for Appliance Form, opt-in override
/// for Sovereign Form, not offered on Companion Form.
pub struct SelfHostedAdapter {
    // Real fields (implementation session): the substrate's own HTTP
    // listener handle/route registrar, and the operator-configured domain
    // this is served under. ACME certificate management (design doc §7,
    // named as an open sub-decision) lives beside this, not inside it.
}

#[async_trait]
impl IdentityHostingAdapter for SelfHostedAdapter {
    async fn publish(&self, doc: &CimdDocument) -> Result<PublishedLocation, HostingError> {
        let _ = doc;
        todo!(
            "needs a route on the substrate's own listener plus the /oauth/callback \
             capture route from redirect.rs — design doc §6"
        )
    }

    fn hosting_base(&self, fingerprint: &GenesisFingerprint) -> String {
        let _ = fingerprint;
        todo!(
            "needs the operator's configured domain, and design doc §5's reconciliation \
             with the existing /.well-known/zeropoint/ path convention"
        )
    }
}

/// Design doc §2's universal fallback. Does not host anything —
/// `publish` and `hosting_base` are both structurally unreachable for this
/// mode (there is no [`CimdDocument`] to publish and no URL for it to live
/// at; the operator registers credentials by hand at each external AS
/// instead). Kept as a type, not omitted, so callers that iterate over
/// "the operator's chosen adapter" have an explicit no-op case to match on
/// rather than an `Option<Box<dyn IdentityHostingAdapter>>` whose `None`
/// case silently means the same thing.
pub struct PreRegistrationAdapter;

#[async_trait]
impl IdentityHostingAdapter for PreRegistrationAdapter {
    async fn publish(&self, doc: &CimdDocument) -> Result<PublishedLocation, HostingError> {
        let _ = doc;
        Err(HostingError::Unimplemented(
            "PreRegistrationAdapter does not publish — see design doc §2's fallback row",
        ))
    }

    fn hosting_base(&self, fingerprint: &GenesisFingerprint) -> String {
        let _ = fingerprint;
        todo!("PreRegistrationAdapter has no hosting base; callers should not reach this")
    }
}
