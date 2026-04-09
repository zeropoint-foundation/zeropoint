//! # zp-verify — ZeroPoint Invariant Catalog Verifier (v0)
//!
//! This crate is the executable form of the ZeroPoint Invariant Catalog
//! (`security/pentest-2026-04-06/INVARIANT-CATALOG-v0.md`). It walks an
//! ordered sequence of [`zp_receipt::Receipt`] values and reports, per
//! catalog rule, whether the chain is well-formed.
//!
//! ## Scope of v0
//!
//! v0 implements three rules — the smallest set that would have caught
//! the AUDIT-01 finding from the 2026-04-06 pentest the moment it
//! happened:
//!
//! - **P1 — Chain extension.** Each non-root receipt must reference its
//!   predecessor by id, and its content hash must match its body.
//! - **M3 — Hash-chain continuity.** No gaps; every parent reference
//!   resolves; the chain forms a single connected sequence from a root
//!   to the tip.
//! - **M4 — Trajectory monotonicity.** Timestamps along the chain are
//!   non-decreasing.
//!
//! Other rules (P2 delegation, P3 the gate, M1 gate coverage, M2
//! constitutional persistence, M6 sovereignty preservation, the cross-
//! layer X-rules, the discovery rules) are deliberately deferred to v1
//! and v2 per `docs/ARCHITECTURE-2026-04.md` Phase 1.
//!
//! ## What this crate is not
//!
//! - It is not a runtime. It does not execute, sign, or store anything.
//! - It does not re-verify Ed25519 signatures. That is `zp-receipt`'s
//!   `verify_signature`. The catalog assumes signature verification has
//!   already happened upstream and treats signature failure as a P1
//!   reject reported separately if the caller asks for it.
//! - It does not depend on `zp-audit`'s storage. It walks whatever
//!   `&[Receipt]` you give it, in the order you give it. The verifier
//!   is a parser, not a database client.
//!
//! ## Typical use
//!
//! ```ignore
//! use zp_verify::{Verifier, VerifyReport};
//!
//! let report: VerifyReport = Verifier::new().verify(&receipts);
//! if report.is_well_formed() {
//!     println!("chain accepted: {} receipts, all rules pass", receipts.len());
//! } else {
//!     for v in report.violations() {
//!         eprintln!("{}: {} at index {}", v.rule, v.message, v.index);
//!     }
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod chain_entry;
mod report;
mod rules;

pub use chain_entry::ChainEntry;
pub use report::{RuleId, VerifyReport, Violation};
pub use rules::{p1_chain_extension, m3_hash_chain_continuity, m4_trajectory_monotonicity};

/// The v0 verifier. Stateless. Configure with which rules to run, then
/// call [`Verifier::verify`] on a slice of receipts in chain order.
///
/// By default all v0 rules are enabled (P1, M3, M4).
#[derive(Debug, Clone)]
pub struct Verifier {
    /// Run P1 — Chain extension.
    pub run_p1: bool,
    /// Run M3 — Hash-chain continuity.
    pub run_m3: bool,
    /// Run M4 — Trajectory monotonicity.
    pub run_m4: bool,
}

impl Default for Verifier {
    fn default() -> Self {
        Self {
            run_p1: true,
            run_m3: true,
            run_m4: true,
        }
    }
}

impl Verifier {
    /// Construct a verifier with all v0 rules enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the enabled rules against `receipts`, in order, and return a
    /// [`VerifyReport`].
    ///
    /// The slice is treated as the chain in derivation order — index 0
    /// is the root, index `len-1` is the tip. The verifier does not
    /// re-sort.
    pub fn verify<T: ChainEntry>(&self, receipts: &[T]) -> VerifyReport {
        let mut report = VerifyReport::new(receipts.len());

        if self.run_p1 {
            for v in p1_chain_extension(receipts) {
                report.push(v);
            }
        }
        if self.run_m3 {
            for v in m3_hash_chain_continuity(receipts) {
                report.push(v);
            }
        }
        if self.run_m4 {
            for v in m4_trajectory_monotonicity(receipts) {
                report.push(v);
            }
        }

        report
    }
}

#[cfg(test)]
mod tests;
