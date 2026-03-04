//! ZeroPoint Introduction Protocol — governed trust establishment between nodes.
//!
//! This crate implements the handshake protocol that allows two ZeroPoint nodes
//! to establish a trust relationship. The protocol is:
//!
//! 1. **Initiator** sends an `IntroductionRequest` containing its certificate chain
//! 2. **Responder** verifies the chain using `zp-keys`
//! 3. **Responder** constructs a `PolicyContext` with `ActionType::PeerIntroduction`
//!    and evaluates it against the policy engine
//! 4. If the policy engine allows it, responder sends an `IntroductionResponse`
//!    with its own chain
//! 5. Both sides now have verified chains and can exchange capabilities
//!
//! The introduction protocol does NOT implement policy decisions — it generates
//! the `PolicyContext` that the policy engine evaluates. This keeps the separation
//! between mechanism (zp-keys) and governance (zp-policy) clean.

pub mod protocol;
pub mod error;
pub mod request;
pub mod response;

pub use error::IntroductionError;
pub use protocol::{IntroductionOutcome, verify_introduction};
pub use request::IntroductionRequest;
pub use response::IntroductionResponse;
