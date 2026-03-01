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
mod chain;
mod hasher;
mod types;
mod verifier;

#[cfg(feature = "signing")]
mod signer;

#[cfg(feature = "otel")]
mod otel;

// Re-export everything at crate root
pub use builder::ReceiptBuilder;
pub use chain::{ChainEntry, ChainError, ReceiptChain};
pub use hasher::canonical_hash;
pub use types::*;
pub use verifier::{ReceiptVerifier, VerificationError, VerificationResult};

#[cfg(feature = "signing")]
pub use signer::Signer;

#[cfg(feature = "otel")]
pub use otel::ReceiptSpanExporter;
