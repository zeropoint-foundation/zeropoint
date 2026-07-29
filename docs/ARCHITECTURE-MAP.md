# Architecture Map

**Generated** by `tools/architecture-map/architecture_map.py` from commit `a952b50`. Derived, not authored — regenerate rather than edit.

44 crates · 194,526 lines · 41 workspace members


## Layer 0

| Crate | Purpose | Status | Wiring | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---|---|---|---|
| `mle-star-engine` | MLE STAR inspired expertise pre-learning engine for ZeroPoint | member | consumed | — | zp-server | 2,895 | yes |
| `monte-carlo-engine` | Extensible Monte Carlo simulation engine for ZeroPoint | member | consumed | — | zp-server | 3,495 | yes |
| `zp-anchor` | ZeroPoint Truth Anchor — pluggable DLT abstraction for external chain verification | member | consumed | — | zp-cli, zp-server | 320 | yes |
| `zp-bench` | F4 — performance falsifiers (Criterion benchmarks) for ZeroPoint's governance gate | member | unwired | — | — | 515 | **no** |
| `zp-cloudflare` | Adapter crate — implements ZeroPoint port traits using Cloudflare primitives | member | unwired | — | — | 109 | **no** |
| `zp-config` | Unified configuration with provenance tracking for ZeroPoint | member | consumed | — | zp-cli, zp-hardening-tests, zp-regent, zp-server | 1,603 | yes |
| `zp-content` | Content-addressed storage trait and local backends for ZeroPoint signed artifacts | member | consumed | — | zp-artifacts, zp-server | 747 | **no** |
| `zp-discipline` | Discipline-pin tests: structural conventions enforced as build-failing tests | member | unwired | — | — | 2,752 | yes |
| `zp-emission-coherence` | Regent emission-coherence detection: Heuristics 1–3 (n-gram repetition, length-distribution collapse, token… | standalone | entrypoint | — | — | 1,067 | yes |
| `zp-inference-observer` | Tails DFlash observation JSONL events and exposes them as typed values for substrate-side receipt emission. | standalone | entrypoint | — | — | 457 | yes |
| `zp-memory-index` | `zp-memory-index` — vector index wrapper for substrate-governed memory retrieval. | member | unwired | — | — | 409 | yes |
| `zp-net` | Canonical loopback networking primitives for the ZeroPoint substrate. | member | consumed | — | zp-cli, zp-configure, zp-hardening-tests, zp-server | 484 | **no** |
| `zp-preflight` | Pre-flight diagnostic tool for ZeroPoint installation readiness | member | entrypoint | — | — | 1,038 | **no** |
| `zp-receipt` | ZeroPoint Receipt — portable, cryptographically verifiable proof of execution | member | consumed | — | course-examples, trust-triangle, zp-audit, zp-cli, zp-core, zp-gate-envelope, zp-keys, zp-memory, zp-mesh, zp-observation, zp-officers, zp-pipeline, zp-regent, zp-server, zp-verify | 7,348 | yes |
| `zp-sensors` | Event-driven sensor layer for ZeroPoint governance — kqueue process/file watches and port discovery | member | consumed | — | zp-server | 1,407 | yes |
| `zp-verbs` | Generated Rust types for the ZeroPoint v1 verb set (protobuf schema → Rust via tonic-build) | member | consumed | — | zp-server | 77 | yes |

## Layer 1

| Crate | Purpose | Status | Wiring | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---|---|---|---|
| `zp-artifacts` | Artifact library — content-addressed, signed, lifecycle-managed renderings for ZeroPoint | member | consumed | zp-content | zp-server | 1,368 | **no** |
| `zp-core` | ZeroPoint v2 — shared types, traits, and error definitions | member | consumed | zp-receipt | course-examples, trust-triangle, zp-audit, zp-cli, zp-configure, zp-engine, zp-gossip, zp-hardening-tests, zp-host, zp-introduction, zp-keys, zp-learning, zp-llm, zp-memory, zp-mesh, zp-observation, zp-officers, zp-pipeline, zp-policy, zp-regent, zp-server, zp-skills, zp-trust | 8,178 | yes |
| `zp-gate-envelope` | Per-request Genesis-signed envelopes for the ZeroPoint cognition-governance gate (the 'ZP-Sig' Authorizatio… | member | consumed | zp-receipt | zp-server | 421 | yes |
| `zp-verify` | Receipt and chain verification utilities for ZeroPoint | member | consumed | zp-receipt | zp-audit, zp-cli, zp-hardening-tests | 1,385 | yes |

## Layer 2

| Crate | Purpose | Status | Wiring | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---|---|---|---|
| `zp-audit` | zp-audit: Hash-chained, always-on audit trail for ZeroPoint v2. | member | consumed | zp-core, zp-receipt, zp-verify | course-examples, zp-cli, zp-hardening-tests, zp-host, zp-mesh, zp-officers, zp-pipeline, zp-policy, zp-regent, zp-server | 6,394 | yes |
| `zp-gossip` | Gossip network for Regent collective intelligence — typed findings, allowance economics, intake limiting | member | unwired | zp-core | — | 827 | yes |
| `zp-keys` | ZeroPoint key hierarchy — genesis → operator → agent key derivation, signing, and verification | member | consumed | zp-core, zp-receipt | course-examples, trust-triangle, zp-cli, zp-hardening-tests, zp-introduction, zp-server | 12,305 | yes |
| `zp-learning` | ZeroPoint Learning Loop — episode recording and pattern detection. | member | consumed | zp-core | zp-pipeline | 1,622 | yes |
| `zp-llm` | LLM provider pool with risk-based routing for ZeroPoint v2 | member | consumed | zp-core | zp-pipeline | 1,785 | yes |
| `zp-observation` | Receipt-backed observational memory for ZeroPoint agents | member | consumed | zp-core, zp-receipt | zp-memory, zp-server | 3,105 | yes |
| `zp-skills` | ZeroPoint v2 — skill registry and matching system | member | consumed | zp-core | zp-pipeline | 731 | yes |
| `zp-trust` | ZeroPoint Trust Infrastructure (zp-trust) | member | consumed | zp-core | course-examples, zp-cli, zp-configure, zp-engine, zp-mesh, zp-pipeline, zp-server | 2,313 | yes |

## Layer 3

| Crate | Purpose | Status | Wiring | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---|---|---|---|
| `zp-engine` | ZeroPoint shared engine — scan, configure, vault, and provider logic used by both server and CLI | member | consumed | zp-core, zp-trust | zp-cli, zp-configure, zp-server | 6,197 | yes |
| `zp-introduction` | ZeroPoint introduction protocol — governed cross-node trust establishment | member | consumed | zp-core, zp-keys | trust-triangle | 467 | yes |
| `zp-memory` | Memory promotion engine for ZeroPoint's cognition plane | member | consumed | zp-core, zp-observation, zp-receipt | zp-server | 3,588 | yes |
| `zp-mesh` | Sovereign mesh transport for ZeroPoint agents — Reticulum-compatible cryptographic networking | member | consumed | zp-audit, zp-core, zp-receipt, zp-trust | course-examples, zp-cli, zp-pipeline, zp-server | 17,954 | yes |
| `zp-officers` | System Officer Cadre — dormant integrity/security/operations monitors for ZeroPoint | member | consumed | zp-audit, zp-core, zp-receipt | zp-cli, zp-regent, zp-server | 6,781 | yes |
| `zp-policy` | ZeroPoint Policy Engine - native Rust rules + optional WASM policy module runtime | member | consumed | zp-audit, zp-core | course-examples, trust-triangle, zp-cli, zp-host, zp-pipeline, zp-server | 4,538 | yes |

## Layer 4

| Crate | Purpose | Status | Wiring | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---|---|---|---|
| `trust-triangle` | Trust Triangle — ZeroPoint reference implementation demonstrating cross-domain governance | orphan | unwired | zp-core, zp-introduction, zp-keys, zp-policy, zp-receipt | — | 1,348 | **no** |
| `zp-configure` | ZeroPoint tool configuration engine — the Semantic Sed library shared by CLI and server | member | consumed | zp-core, zp-engine, zp-net, zp-trust | zp-cli, zp-server | 4,478 | yes |
| `zp-host` | Host-function boundary — the typed contract through which all privileged side effects must pass. | member | consumed | zp-audit, zp-core, zp-policy | execution-engine, zp-cli, zp-pipeline, zp-server | 767 | yes |
| `zp-regent` | The Regent — ZeroPoint's apex cognitive entity, governing on behalf of the sovereign operator | member | consumed | zp-audit, zp-config, zp-core, zp-officers, zp-receipt | zp-server | 12,113 | yes |

## Layer 5

| Crate | Purpose | Status | Wiring | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---|---|---|---|
| `execution-engine` | ZeroPoint Deterministic Execution Engine — sandboxed polyglot code execution without Docker | member | consumed | zp-host | zp-pipeline | 1,778 | yes |

## Layer 6

| Crate | Purpose | Status | Wiring | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---|---|---|---|
| `zp-pipeline` | ZeroPoint Request Pipeline | member | consumed | execution-engine, zp-audit, zp-core, zp-host, zp-learning, zp-llm, zp-mesh, zp-policy, zp-receipt, zp-skills, zp-trust | course-examples, zp-cli, zp-server | 6,928 | yes |

## Layer 7

| Crate | Purpose | Status | Wiring | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---|---|---|---|
| `course-examples` | ZeroPoint Builder Course — compilable lab examples | member | unwired | zp-audit, zp-core, zp-keys, zp-mesh, zp-pipeline, zp-policy, zp-receipt, zp-trust | — | 1,436 | **no** |
| `zp-server` | ZeroPoint v2 Server Library | member | consumed | mle-star-engine, monte-carlo-engine, zp-anchor, zp-artifacts, zp-audit, zp-config, zp-configure, zp-content, zp-core, zp-engine, zp-gate-envelope, zp-host, zp-keys, zp-memory, zp-mesh, zp-net, zp-observation, zp-officers, zp-pipeline, zp-policy, zp-receipt, zp-regent, zp-sensors, zp-trust, zp-verbs | zp-cli, zp-hardening-tests | 38,456 | yes |

## Layer 8

| Crate | Purpose | Status | Wiring | Depends on | Used by | LOC | Doc'd |
|---|---|---|---|---|---|---|---|
| `zp-cli` | ZeroPoint v2 CLI — primary interface for developers | member | entrypoint | zp-anchor, zp-audit, zp-config, zp-configure, zp-core, zp-engine, zp-host, zp-keys, zp-mesh, zp-net, zp-officers, zp-pipeline, zp-policy, zp-receipt, zp-server, zp-trust, zp-verify | — | 19,188 | yes |
| `zp-hardening-tests` | Regression replay test harness for Shannon pentest vulnerabilities | member | unwired | zp-audit, zp-config, zp-core, zp-keys, zp-net, zp-server, zp-verify | — | 3,352 | yes |

## Attention

- **Unwired** (8): `course-examples`, `trust-triangle`, `zp-bench`, `zp-cloudflare`, `zp-discipline`, `zp-gossip`, `zp-hardening-tests`, `zp-memory-index`
- **Not described by any governed document** (8): `course-examples`, `trust-triangle`, `zp-artifacts`, `zp-bench`, `zp-cloudflare`, `zp-content`, `zp-net`, `zp-preflight`
- **Outside the workspace** (3): `trust-triangle` (orphan), `zp-emission-coherence` (standalone), `zp-inference-observer` (standalone)
