# course-examples

Compilable source code for every lab in the [ZeroPoint Builder Course](https://zeropoint.global/course).

These examples are the single source of truth for course code. The course page fetches them from this directory at render time, ensuring students always see code that compiles against the current API.

## Running Labs

```bash
# Run a specific lab
cargo run --example lab01_first_key -p course-examples

# Build all labs (CI does this)
cargo build --examples -p course-examples

# List available labs
cargo run --example -p course-examples
```

## Lab Index

| Example | Module | Topic |
|---------|--------|-------|
| lab01_first_key | 1 | Key hierarchy: Genesis → Operator → Agent |
| lab02_signing | 2 | Ed25519 signing and verification |
| lab03_capability_grants | 3 | Capability grants with constraints |
| lab04_delegation_chains | 4 | Three-level delegation with invariant checking |
| lab05_policy_engine | 5 | Policy engine with graduated decisions |
| lab06_governance_gate | 6 | Guard → Policy → Audit pipeline |
| lab07_receipts | 7 | Receipt chains with hash verification |
| lab08_audit_trail | 8 | Persisted audit trail with chain verification |
| lab09_discovery | 9 | Mesh discovery with loopback interfaces |
| lab10_presence_plane | 10 | Dual-backend presence plane |
| lab11_adversarial | 11 | Relay reciprocity and reputation signals |
| lab12_reputation | 12 | Reputation scoring with time decay |
| lab13_consensus | 13 | Receipt-based consensus |
| lab14_epoch_compaction | 14 | Epoch compaction with merkle proofs |
| lab15_wasm_policy | 15 | WASM policy module loading |
| lab16_capstone | 16 | Full integration |

## Design

Lab 0 (Environment Setup) is bash-only and has no Rust example file.

Each example is a standalone `fn main()` (or `#[tokio::main]` for async labs) that demonstrates the module's concepts. The course page at zeropoint.global/course fetches these files from the GitHub raw content API.
