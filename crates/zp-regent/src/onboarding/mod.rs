//! Regent onboarding — the ceremony that constitutes the substrate's
//! true initial position for the Regent.
//!
//! Elaborates `docs/design/REGENT-ONBOARDING-CEREMONY-2026-09.md`.
//!
//! This is the substrate's answer to the finding of 2026-09-06: booting
//! with zero standing grants produced PROPOSAL responses to every
//! operator input, even trivial ones like `"Say ready."`. That state
//! is not P9 — P9 says *the system acts; the operator signs*, and
//! *acts* requires a bounded action space. The bounding comes from
//! the delegation graph.
//!
//! # First implementation slice — the invariant floor only
//!
//! This module currently ships the *floor* — the four capabilities a
//! Regent has by KEEL-mandated default, non-refusable. The four-part
//! ceremony (naming, persona charter, seed delegations selection,
//! or-not) that the design doc describes is not yet implemented; the
//! floor auto-applies at Regent construction, and every Regent boots
//! with exactly this set until the ceremony surfaces exist.
//!
//! # What is deferred
//!
//! - The extension catalog (`floor.rs` §"What the floor does *not*
//!   include").
//! - The operator-facing ceremony rites (naming, persona charter, catalog
//!   picker, or-not path).
//! - `zp regent onboard / extend / revoke / recharter / rename`
//!   subcommands.
//! - Persona charter storage.
//! - Chain-anchored `delegation:seed:invariant` receipts on boot (they
//!   come with the ceremony that establishes them).

pub mod floor;
