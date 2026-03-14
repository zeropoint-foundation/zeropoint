# Changelog

All notable changes to ZeroPoint will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Edge Sovereignty domain in security footprint and whitepaper roadmap
- Mesh discovery with Reticulum transport integration
- Trust Triangle reference implementation (`trust-triangle` crate)
- Cross-node trust establishment (`zp-introduction` crate)
- Key hierarchy and signing primitives (`zp-keys` crate)
- Default governance gate policy module (`policies/default-gate`)
- Interactive governance simulation at zeropoint.global/playground
- Piper TTS narration system for whitepaper and playground
- Deployment guide for Cloudflare Pages + Hetzner VPS

### Fixed
- Resolved all Clippy warnings across zp-policy, zp-mesh, zp-server
- Fixed `test_guard_blocks_blocklisted_actors` actor key format mismatch
- Resolved Clippy warnings in epoch.rs

### Infrastructure
- CI pipeline: build, test, clippy (`-D warnings`), fmt check on all PRs
- Multi-stage Dockerfile with non-root runtime and health check
- Dual licensing: MIT and Apache 2.0

## [0.1.0] - 2025-01-01

### Added
- Initial workspace with 16 crates
- Core governance primitives: trust tiers, policy engine, audit trail
- GovernanceGate pipeline: Guard → Policy → Execute → Audit
- Constitutional rules: HarmPrincipleRule, SovereigntyRule
- Cryptographic receipts with Ed25519 signing and Blake3 hashing
- WASM policy module runtime via Wasmtime
- Axum HTTP API server with 15 endpoints
- Mesh networking with Web Discovery and Reticulum transports
- LLM provider routing with governance integration
- Skill registry and adaptive learning loop
- Sandboxed polyglot execution engine
- CLI interface
