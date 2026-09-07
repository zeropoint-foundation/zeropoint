//! Identity hosting adapter — scaffold, not implementation.
//!
//! # What this crate is
//!
//! The substrate-side half of the pattern named in
//! `docs/design/MCP-COMPOSITION-2026-08.md` §5.1: *"a single hosting adapter
//! that publishes a canonical URL derived from the Genesis pubkey
//! fingerprint... satisfies every [identity interop] surface's identifier
//! requirement simultaneously."* This crate builds the document that gets
//! published (`document`, `client_name`, `redirect`), names the surviving
//! URL-scheme choices (`client_id`), and defines the port every hosting
//! mode implements against (`adapter`) — following the same ports /
//! adapters / substitutable-adapters split `crates/zp-cloudflare` already
//! uses for the Foundation edge relay.
//!
//! Full design reasoning, the four decisions this scaffold assumes, and
//! what is deliberately left as `todo!()` and why: see
//! `docs/design/IDENTITY-HOSTING-ADAPTER-2026-09.md`.
//!
//! # What this crate is not
//!
//! It is not wired into anything. It is **not a workspace member** — it
//! does not appear in the root `Cargo.toml` `members` list, deliberately,
//! so that registering it (and the `cargo check -p zp-identity-hosting`
//! that should immediately follow) is the implementation session's first
//! step, not something this design pass did unreviewed. Every function
//! whose body depends on a decision `IDENTITY-HOSTING-ADAPTER-2026-09.md`
//! left to Ken is `todo!()`. Functions whose logic was fully settled by
//! that document ([`client_name`] and [`redirect`]'s `redirect_uris`) are
//! implemented for real, with tests, ready to move into `zp-server`
//! verbatim once this crate is wired in.
//!
//! # Layout
//!
//! ```text
//! src/
//! ├── lib.rs             (this file)
//! ├── client_id.rs        ClientIdScheme + the GenesisFingerprint newtype
//! ├── document.rs          CimdDocument, Jwk/Jwks, build_cimd_document()
//! ├── adapter.rs            IdentityHostingAdapter port + per-mode stubs
//! ├── client_name.rs        settled: client_name derivation (real impl)
//! ├── redirect.rs            settled: redirect_uris derivation (real impl)
//! └── client_auth_key.rs     deferred (design §3): JWKS signer derivation
//! ```

pub mod adapter;
pub mod client_auth_key;
pub mod client_id;
pub mod client_name;
pub mod document;
pub mod redirect;

pub use adapter::{HostingError, IdentityHostingAdapter, PublishedLocation};
pub use client_id::{ClientIdScheme, GenesisFingerprint};
pub use client_name::RegentNameState;
pub use document::{build_cimd_document, CimdDocument, Jwk, Jwks};
