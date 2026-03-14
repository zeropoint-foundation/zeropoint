# zp-receipt

Portable, cryptographically verifiable proof that an action was executed.

This is the protocol-level primitive for the ZeroPoint trust layer. It is intentionally standalone — no dependency on the rest of ZeroPoint — so that any service can generate, verify, and chain receipts.

## Modules

- **builder** — Fluent API for constructing receipts
- **signer** — Ed25519 signing and verification
- **hasher** — Blake3 content-addressed hashing
- **chain** — Hash-chained receipt sequences with integrity verification
- **verifier** — Receipt and chain verification
- **types** — Core receipt types, status codes, and action descriptors
- **epoch** — Timestamp and ordering primitives

## Quick Start

```rust
use zp_receipt::{Receipt, Status, Action};

let receipt = Receipt::execution("my-executor")
    .status(Status::Success)
    .action(Action::code_execution("python", 0))
    .finalize();

assert!(receipt.verify_hash());
```

## Design

Every receipt is self-verifying: the hash covers all fields, and an optional Ed25519 signature binds the receipt to a specific key in the ZeroPoint key hierarchy. Receipts are designed to be portable — they can be verified offline, by any party, without contacting the issuing node.
