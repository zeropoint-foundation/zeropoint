# Architecture Map

**Document type:** Derived reference. Generated, not authored.

**Generated** by `tools/architecture-map/architecture_map.py` from commit `a097fbd`. Derived, not authored — regenerate rather than edit.

47 crates · 222,565 lines · 44 workspace members


## Layer 0

| Crate | Purpose | Status | Wiring | Fan-in | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---:|---|---|---:|---|
| `zp-receipt` | ZeroPoint Receipt — portable, cryptographically verifiable proof of execution | member | consumed | 16 | — | course-examples, trust-triangle, zp-audit, zp-cli, zp-core, zp-gate-envelope, zp-keys, zp-memory, zp-mesh, zp-observation, zp-officers, zp-pipeline, zp-regent, zp-server, zp-trace, zp-verify | 7,731 | yes |
| `zp-config` | Unified configuration with provenance tracking for ZeroPoint | member | consumed | 4 | — | zp-cli, zp-hardening-tests, zp-regent, zp-server | 2,142 | yes |
| `zp-net` | Canonical loopback networking primitives for the ZeroPoint substrate. | member | consumed | 4 | — | zp-cli, zp-configure, zp-hardening-tests, zp-server | 484 | yes |
| `zp-anchor` | ZeroPoint Truth Anchor — pluggable DLT abstraction for external chain verification | member | consumed | 3 | — | zp-anchor-ots, zp-cli, zp-server | 320 | yes |
| `zp-content` | Content-addressed storage trait and local backends for ZeroPoint signed artifacts | member | consumed | 2 | — | zp-artifacts, zp-server | 763 | yes |
| `mle-star-engine` | MLE STAR inspired expertise pre-learning engine for ZeroPoint | member | consumed | 1 | — | zp-server | 2,895 | yes |
| `monte-carlo-engine` | Extensible Monte Carlo simulation engine for ZeroPoint | member | consumed | 1 | — | zp-server | 3,495 | yes |
| `zp-emission-coherence` | Regent emission-coherence detection: Heuristics 1–3 (n-gram repetition, length-distribution collapse, token… | member | consumed | 1 | — | zp-regent | 1,073 | yes |
| `zp-inference-observer` | Tails DFlash observation JSONL events and exposes them as typed values for substrate-side receipt emission. | member | consumed | 1 | — | zp-server | 456 | yes |
| `zp-sensors` | Event-driven sensor layer for ZeroPoint governance — kqueue process/file watches and port discovery | member | consumed | 1 | — | zp-server | 1,527 | yes |
| `zp-verbs` | Generated Rust types for the ZeroPoint v1 verb set (protobuf schema → Rust via tonic-build) | member | consumed | 1 | — | zp-server | 77 | yes |
| `zp-bench` | F4 — performance falsifiers (Criterion benchmarks) for ZeroPoint's governance gate | member | bench | 0 | — | — | 496 | yes |
| `zp-cloudflare` | Adapter crate — implements ZeroPoint port traits using Cloudflare primitives | member | unwired | 0 | — | — | 109 | yes |
| `zp-discipline` | Discipline-pin tests: structural conventions enforced as build-failing tests | member | test | 0 | — | — | 5,721 | yes |
| `zp-identity-hosting` | CIMD / identity-hosting-adapter scaffold — publishes a Genesis-fingerprint-derived HTTPS identity document.… | orphan | unwired | 0 | — | — | 717 | yes |
| `zp-memory-index` | `zp-memory-index` — vector index wrapper for substrate-governed memory retrieval. | member | unwired | 0 | — | — | 436 | yes |
| `zp-preflight` | Pre-flight diagnostic tool for ZeroPoint installation readiness | member | entrypoint | 0 | — | — | 1,038 | yes |

## Layer 1

| Crate | Purpose | Status | Wiring | Fan-in | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---:|---|---|---:|---|
| `zp-core` | ZeroPoint v2 — shared types, traits, and error definitions | member | consumed | 25 | zp-receipt | course-examples, trust-triangle, zp-audit, zp-cli, zp-configure, zp-engine, zp-gate-envelope, zp-gossip, zp-hardening-tests, zp-host, zp-introduction, zp-keys, zp-learning, zp-llm, zp-memory, zp-mesh, zp-observation, zp-officers, zp-ontology, zp-pipeline, zp-policy, zp-regent, zp-server, zp-trace, zp-trust | 9,285 | yes |
| `zp-verify` | Receipt and chain verification utilities for ZeroPoint | member | consumed | 3 | zp-receipt | zp-audit, zp-cli, zp-hardening-tests | 1,379 | yes |
| `zp-anchor-ots` | OpenTimestamps backend for the ZeroPoint TruthAnchor trait — the anchor floor | member | consumed | 1 | zp-anchor | zp-server | 805 | yes |
| `zp-artifacts` | Artifact library — content-addressed, signed, lifecycle-managed renderings for ZeroPoint | member | consumed | 1 | zp-content | zp-server | 1,411 | yes |

## Layer 2

| Crate | Purpose | Status | Wiring | Fan-in | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---:|---|---|---:|---|
| `zp-audit` | zp-audit: Hash-chained, always-on audit trail for ZeroPoint v2. | member | consumed | 10 | zp-core, zp-receipt, zp-verify | course-examples, zp-cli, zp-hardening-tests, zp-host, zp-mesh, zp-officers, zp-pipeline, zp-policy, zp-regent, zp-server | 6,822 | yes |
| `zp-trust` | ZeroPoint Trust Infrastructure (zp-trust) | member | consumed | 7 | zp-core | course-examples, zp-cli, zp-configure, zp-engine, zp-mesh, zp-pipeline, zp-server | 2,377 | yes |
| `zp-keys` | ZeroPoint key hierarchy — genesis → operator → agent key derivation, signing, and verification | member | consumed | 6 | zp-core, zp-receipt | course-examples, trust-triangle, zp-cli, zp-hardening-tests, zp-introduction, zp-server | 12,504 | yes |
| `zp-gate-envelope` | Per-request Genesis-signed envelopes for the ZeroPoint cognition-governance gate (the 'ZP-Sig' Authorizatio… | member | consumed | 2 | zp-core, zp-receipt | zp-cli, zp-server | 663 | yes |
| `zp-observation` | Receipt-backed observational memory for ZeroPoint agents | member | consumed | 2 | zp-core, zp-receipt | zp-memory, zp-server | 3,088 | yes |
| `zp-ontology` | Ontology layer + Cartographer — derived object graph over the ZeroPoint receipt chain | member | consumed | 2 | zp-core | zp-regent, zp-server | 3,121 | yes |
| `zp-learning` | ZeroPoint Learning Loop — episode recording and pattern detection. | member | consumed | 1 | zp-core | zp-pipeline | 1,622 | yes |
| `zp-llm` | LLM provider pool with risk-based routing for ZeroPoint v2 | member | consumed | 1 | zp-core | zp-pipeline | 1,689 | yes |
| `zp-gossip` | Gossip network for Regent collective intelligence — typed findings, allowance economics, intake limiting | member | unwired | 0 | zp-core | — | 827 | yes |
| `zp-trace` | Harness-agnostic trace and guard — the ToolGate contract ZeroPoint installs in a coding harness's dispatch … | orphan | unwired | 0 | zp-core, zp-receipt | — | 581 | yes |

## Layer 3

| Crate | Purpose | Status | Wiring | Fan-in | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---:|---|---|---:|---|
| `zp-policy` | ZeroPoint Policy Engine - native Rust rules + optional WASM policy module runtime | member | consumed | 6 | zp-audit, zp-core | course-examples, trust-triangle, zp-cli, zp-host, zp-pipeline, zp-server | 4,614 | yes |
| `zp-mesh` | Sovereign mesh transport for ZeroPoint agents — Reticulum-compatible cryptographic networking | member | consumed | 4 | zp-audit, zp-core, zp-receipt, zp-trust | course-examples, zp-cli, zp-pipeline, zp-server | 18,092 | yes |
| `zp-engine` | ZeroPoint shared engine — scan, configure, vault, and provider logic used by both server and CLI | member | consumed | 3 | zp-core, zp-trust | zp-cli, zp-configure, zp-server | 6,200 | yes |
| `zp-officers` | System Officer Cadre — dormant integrity/security/operations monitors for ZeroPoint | member | consumed | 3 | zp-audit, zp-core, zp-receipt | zp-cli, zp-regent, zp-server | 8,301 | yes |
| `zp-introduction` | ZeroPoint introduction protocol — governed cross-node trust establishment | member | consumed | 1 | zp-core, zp-keys | trust-triangle | 467 | yes |
| `zp-memory` | Memory promotion engine for ZeroPoint's cognition plane | member | consumed | 1 | zp-core, zp-observation, zp-receipt | zp-server | 3,665 | yes |

## Layer 4

| Crate | Purpose | Status | Wiring | Fan-in | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---:|---|---|---:|---|
| `zp-host` | Host-function boundary — the typed contract through which all privileged side effects must pass. | member | consumed | 4 | zp-audit, zp-core, zp-policy | execution-engine, zp-cli, zp-pipeline, zp-server | 1,008 | yes |
| `zp-configure` | ZeroPoint tool configuration engine — the Semantic Sed library shared by CLI and server | member | consumed | 2 | zp-core, zp-engine, zp-net, zp-trust | zp-cli, zp-server | 4,546 | yes |
| `zp-regent` | The Regent — ZeroPoint's apex cognitive entity, governing on behalf of the sovereign operator | member | consumed | 1 | zp-audit, zp-config, zp-core, zp-emission-coherence, zp-officers, zp-ontology, zp-receipt | zp-server | 19,499 | yes |
| `trust-triangle` | Trust Triangle — ZeroPoint reference implementation demonstrating cross-domain governance | orphan | entrypoint | 0 | zp-core, zp-introduction, zp-keys, zp-policy, zp-receipt | — | 1,348 | yes |

## Layer 5

| Crate | Purpose | Status | Wiring | Fan-in | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---:|---|---|---:|---|
| `execution-engine` | ZeroPoint Deterministic Execution Engine — sandboxed polyglot code execution without Docker | member | consumed | 1 | zp-host | zp-pipeline | 1,800 | yes |

## Layer 6

| Crate | Purpose | Status | Wiring | Fan-in | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---:|---|---|---:|---|
| `zp-pipeline` | ZeroPoint Request Pipeline | member | consumed | 3 | execution-engine, zp-audit, zp-core, zp-host, zp-learning, zp-llm, zp-mesh, zp-policy, zp-receipt, zp-trust | course-examples, zp-cli, zp-server | 7,159 | yes |

## Layer 7

| Crate | Purpose | Status | Wiring | Fan-in | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---:|---|---|---:|---|
| `zp-server` | ZeroPoint v2 Server Library | member | consumed | 2 | mle-star-engine, monte-carlo-engine, zp-anchor, zp-anchor-ots, zp-artifacts, zp-audit, zp-config, zp-configure, zp-content, zp-core, zp-engine, zp-gate-envelope, zp-host, zp-inference-observer, zp-keys, zp-memory, zp-mesh, zp-net, zp-observation, zp-officers, zp-ontology, zp-pipeline, zp-policy, zp-receipt, zp-regent, zp-sensors, zp-trust, zp-verbs | zp-cli, zp-hardening-tests | 44,649 | yes |
| `course-examples` | ZeroPoint Builder Course — compilable lab examples | member | example | 0 | zp-audit, zp-core, zp-keys, zp-mesh, zp-pipeline, zp-policy, zp-receipt, zp-trust | — | 1,437 | yes |

## Layer 8

| Crate | Purpose | Status | Wiring | Fan-in | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---:|---|---|---:|---|
| `zp-cli` | ZeroPoint v2 CLI — primary interface for developers | member | entrypoint | 0 | zp-anchor, zp-audit, zp-config, zp-configure, zp-core, zp-engine, zp-gate-envelope, zp-host, zp-keys, zp-mesh, zp-net, zp-officers, zp-pipeline, zp-policy, zp-receipt, zp-server, zp-trust, zp-verify | — | 20,653 | yes |
| `zp-hardening-tests` | Regression replay test harness for Shannon pentest vulnerabilities | member | test | 0 | zp-audit, zp-config, zp-core, zp-keys, zp-net, zp-server, zp-verify | — | 3,473 | yes |

## Attention

- **Load-bearing** (fan-in ≥ 3, 15): `zp-core` (25), `zp-receipt` (16), `zp-audit` (10), `zp-trust` (7), `zp-keys` (6), `zp-policy` (6), `zp-config` (4), `zp-host` (4), `zp-mesh` (4), `zp-net` (4), `zp-anchor` (3), `zp-engine` (3), `zp-officers` (3), `zp-pipeline` (3), `zp-verify` (3)
- **Unwired** (5): `zp-cloudflare`, `zp-gossip`, `zp-identity-hosting`, `zp-memory-index`, `zp-trace` — fan-in 0 *and* no bin, test, bench or example target. This is the C2 set; the harness-reached crates below are not in it.
- **Reached by harness only** (4): `zp-bench` (bench), `course-examples` (example), `zp-discipline` (test), `zp-hardening-tests` (test). A test target on a workspace member runs under `cargo test --workspace` in CI; a bench target runs only if something invokes `cargo bench`, and nothing in `.github/workflows` does.
- **Not described by any governed document** (0): none
- **Outside the workspace** (3): `trust-triangle` (orphan), `zp-identity-hosting` (orphan), `zp-trace` (orphan)
