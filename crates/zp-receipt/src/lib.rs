//! # ZeroPoint Receipt
//!
//! Portable, cryptographically verifiable proof that an action was executed.
//!
//! This crate is the protocol-level primitive for the ZeroPoint trust layer.
//! It is intentionally standalone — no dependency on the rest of ZeroPoint —
//! so that any service can generate, verify, and chain receipts.
//!
//! ## Quick Start
//!
//! ```rust
//! use zp_receipt::{Receipt, ReceiptType, Status, Action, ActionType};
//!
//! let receipt = Receipt::execution("my-executor")
//!     .status(Status::Success)
//!     .action(Action::code_execution("python", 0))
//!     .finalize();
//!
//! assert!(receipt.verify_hash());
//! ```
//!
//! ## With Signing
//!
//! ```rust,ignore
//! use zp_receipt::{Receipt, ReceiptType, Status, Signer};
//!
//! let signer = Signer::generate();
//! let receipt = Receipt::execution("my-executor")
//!     .status(Status::Success)
//!     .sign(&signer)
//!     .finalize();
//!
//! assert!(receipt.verify_signature(signer.public_key_bytes()).unwrap());
//! ```

mod builder;
pub mod canonical;
mod chain;
mod epoch;
mod hasher;
pub mod revocation;
mod types;
mod validation;
mod verifier;

#[cfg(feature = "signing")]
mod signer;

#[cfg(feature = "pq-signing")]
mod pq_signer;

#[cfg(feature = "pq-signing")]
mod hybrid_signer;

#[cfg(feature = "otel")]
mod otel;

// Re-export everything at crate root
pub use builder::ReceiptBuilder;
pub use chain::{ChainError, ReceiptChain, ReceiptChainEntry};
pub use epoch::{compute_merkle_root, Direction, Epoch, EpochCompactor, EpochError, MerkleProof, ProofStep};
pub use hasher::canonical_hash;
pub use types::*;
pub use validation::{validate_receipt_type, ValidationError, TypeRules, rules_for};
pub use revocation::RevocationIndex;
pub use verifier::{ReceiptVerifier, VerificationError, VerificationResult};

#[cfg(feature = "signing")]
pub use signer::Signer;

#[cfg(feature = "pq-signing")]
pub use pq_signer::PqSigner;

#[cfg(feature = "pq-signing")]
pub use hybrid_signer::HybridSigner;

#[cfg(feature = "otel")]
pub use otel::ReceiptSpanExporter;
