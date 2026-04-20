//! Revocation index — re-exported from `zp-receipt::revocation`.
//!
//! The canonical implementation lives in `zp-receipt` so that both
//! `zp-audit` and `zp-verify` can use it without circular dependencies.
//! This module re-exports it for backward compatibility.

pub use zp_receipt::revocation::RevocationIndex;
