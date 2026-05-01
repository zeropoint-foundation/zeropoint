//! Unified ZeroPoint Configuration
//!
//! Single source of truth for all ZeroPoint configuration, with provenance
//! tracking so operators (and `zp config show`) can see *where* each value
//! came from.
//!
//! # Resolution order (lowest to highest priority)
//!
//! 1. **Compiled defaults** — hardcoded sane values
//! 2. **System config** — `~/ZeroPoint/config.toml`
//! 3. **Project config** — `./zeropoint.toml` (if present in cwd or ancestors)
//! 4. **Environment variables** — `ZP_*` overrides
//! 5. **CLI flags** — `--port`, `--bind`, etc.
//!
//! Every resolved value carries its [`Source`] so diagnostics can explain
//! exactly why a setting has a particular value.

pub mod error;
pub mod provenance;
pub mod resolve;
pub mod schema;
pub mod topology;
pub mod upstream;
pub mod validate;

pub use error::ConfigError;
pub use provenance::{Source, Sourced};
pub use resolve::ConfigResolver;
pub use schema::{ZpConfig, NodeRole};
pub use topology::{derive_node_role, config_hint_role, TransitionInfo, detect_role_transition};
pub use upstream::{UpstreamBindingStatus, verify_upstream_binding_local, verify_upstream_pubkey_match};
pub use validate::validate;
