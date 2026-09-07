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
pub use resolve::{ConfigResolver, ShadowedAtBoot};
pub use schema::{AcknowledgedListener, NodeRole, ZpConfig, REGENT_INFERENCE_ENDPOINT_SENTINEL};
pub use topology::{
    config_hint_role, derive_node_role, derive_node_role_with_hint, detect_role_transition,
    TransitionInfo,
};
pub use upstream::{
    verify_upstream_binding_local, verify_upstream_pubkey_match, UpstreamBindingStatus,
};
pub use validate::validate;
