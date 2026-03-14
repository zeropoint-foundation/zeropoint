# execution-engine

Deterministic polyglot sandbox for governed code execution.

A Deno-inspired isolation boundary that replaces Docker as the execution environment for agentic code. Every execution request runs through this engine with declared capabilities, producing a cryptographic receipt.

## Modules

- **engine** — Core execution engine with runtime dispatch
- **executor** — Per-language executors (Python, Node.js, Shell)
- **sandbox** — OS-level process isolation (namespaces on Linux, sandbox-exec on macOS)
- **receipt** — Execution receipt generation with input/output hashing
- **error** — Execution error types

## Design Principles

1. **No Docker dependency** — Process-level isolation using OS primitives. Docker is optional infrastructure, not a requirement.
2. **Polyglot by design** — Python, Node.js, and Shell are first-class runtimes with dedicated executors.
3. **Deterministic receipting** — Every execution produces an `ExecutionReceipt` with input hash, output hash, timing, and resource usage. Identical inputs produce identical receipt hashes.
4. **Permission-based capabilities** — Like Deno's `--allow-read`, `--allow-net`, each request declares what it needs. The engine grants only what the policy allows.
