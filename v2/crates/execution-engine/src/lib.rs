//! # ZeroPoint Deterministic Execution Engine
//!
//! A Deno-inspired polyglot sandbox that replaces Docker as the isolation
//! boundary for agentic code execution. Every code execution request from
//! Agent Zero (or any framework) runs through this engine instead of inside
//! a framework-owned container.
//!
//! ## Design Principles
//!
//! 1. **No Docker dependency** — Process-level isolation using OS primitives
//!    (namespaces on Linux, sandbox-exec on macOS, restricted tokens on Windows).
//!    Docker is optional infrastructure, not a requirement.
//!
//! 2. **Polyglot by design** — Python, Node.js, and Shell are first-class
//!    runtimes with dedicated executors. Each runtime gets its own sandboxed
//!    process with controlled filesystem, network, and resource access.
//!
//! 3. **Deterministic receipting** — Every execution produces an `ExecutionReceipt`
//!    with input hash, output hash, timing, resource usage, and the runtime
//!    environment attestation. Identical inputs produce identical receipt hashes.
//!
//! 4. **Permission-based capabilities** — Like Deno's `--allow-read`, `--allow-net`,
//!    etc., each execution request declares what capabilities it needs. The engine
//!    grants only what the policy allows.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    Execution Engine                                 │
//! │                                                                     │
//! │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐          │
//! │  │ Python        │  │ Node.js       │  │ Shell         │          │
//! │  │ Executor      │  │ Executor      │  │ Executor      │          │
//! │  │               │  │               │  │               │          │
//! │  │ - venv pool   │  │ - worker pool │  │ - restricted  │          │
//! │  │ - pip sandbox │  │ - npm sandbox │  │   PATH        │          │
//! │  │ - timeout     │  │ - timeout     │  │ - no network  │          │
//! │  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘          │
//! │          │                  │                   │                  │
//! │          ▼                  ▼                   ▼                  │
//! │  ┌─────────────────────────────────────────────────────────────┐  │
//! │  │                    Sandbox Layer                             │  │
//! │  │  - Process isolation (namespace/seccomp/sandbox-exec)       │  │
//! │  │  - Filesystem: tmpdir only, no host access                  │  │
//! │  │  - Network: denied by default, allowlist per-request        │  │
//! │  │  - Resources: CPU time limit, memory limit, output limit    │  │
//! │  └─────────────────────────────────────────────────────────────┘  │
//! │                              │                                     │
//! │                              ▼                                     │
//! │  ┌─────────────────────────────────────────────────────────────┐  │
//! │  │                    Receipt Layer                             │  │
//! │  │  - Input hash (blake3 of code + args)                       │  │
//! │  │  - Output hash (blake3 of stdout + stderr + exit code)      │  │
//! │  │  - Timing (wall clock, CPU user, CPU sys)                   │  │
//! │  │  - Resource usage (peak memory, bytes written)              │  │
//! │  │  - Runtime attestation reference (from deployment receipt)  │  │
//! │  └─────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

pub mod engine;
pub mod error;
pub mod executor;
pub mod receipt;
pub mod sandbox;

pub use engine::{EngineStatus, ExecOutcome, ExecutionEngine, ExecutionRequest};
pub use error::ExecutionError;
pub use executor::Runtime;
pub use receipt::{bytes_to_hex, ExecutionReceipt};
pub use sandbox::{SandboxCapability, SandboxConfig};
