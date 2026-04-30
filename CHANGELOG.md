# Changelog

All notable changes to ZeroPoint will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-04-29

Open-source trust infrastructure for the agentic age. This release represents the shift from internal governance engine to harness-agnostic trust substrate.

### Positioning

ZeroPoint is now positioned as the trust layer beneath agent harnesses — not competing with them, but making them trustworthy. The architecture supports pi, Claude Code, Codex, and any MCP-capable agent framework through a two-layer extension model (trace + guard).

### Core Architecture
- **Receipt-based abacus** — every action produces an Ed25519-signed, Blake3 hash-chained receipt. 16µs per signed receipt, 47K entries/sec chain verification
- **Canonicalization framework** — constitutive identity for agents, tools, and providers. System, provider, and tool canonicalization on startup with parent entity references
- **Governance gate** — Guard → Policy → Execute → Audit pipeline with trust tier enforcement, reversibility annotations, and content scanning
- **Chain verification CLI** — `zp verify` produces trajectory attestations with complete chain walk
- **Entity discovery scanner** — `zp discover` identifies uncanonicalized entities
- **Content scanner** — `zp scan` pre-canonicalization gate for MCP tools
- **Health checks** — `zp doctor` validates system integrity
- **Post-quantum agility** — receipt format includes algorithm identifiers for future migration

### Fleet & Delegation
- **Standing delegation** with automated lease renewal — fleet nodes maintain time-bound Ed25519-signed capability grants with 2-hour renewal cycle
- **Fleet node registry** with heartbeat (30s interval), status tracking, and policy distribution
- **Live deployment** — Python Sentinel on ASUS RT-AX58U router participating in trust mesh with Rust Core server on workstation
- **Six trust tiers** (T0–T5) with graduated autonomy enforcement

### Sentinel (Network Edge)
- Multi-platform installer: ASUS Merlin, OpenWrt, Linux systemd, Docker
- DNS filtering with Steven Black blocklists
- Device monitoring with DHCP lease tracking and rogue device detection
- Anomaly detection: DNS spikes, port scans, DGA domains, device floods
- Ed25519 mesh identity with fleet heartbeat and lease renewal client
- Blake3 hash-chained SQLite audit ledger
- Alert notifications via Ntfy, Slack, or webhook

### Truth Anchoring
- `TruthAnchor` trait in `zp-anchor` crate (~300 lines) — pluggable interface for external truth anchoring
- Anchor types: `AnchorCommitment`, `AnchorReceipt`, `AnchorTrigger`, `AnchorVerification`
- Hedera HCS designated as reference backend (integration grant in preparation)

### Mesh Network
- Ed25519 + X25519 keypairs with 128-bit destination hash addressing
- Forward-secret encrypted channels via X25519 ECDH + HKDF
- Signed, typed message carriers (receipts, delegations, announces)
- Dual-backend discovery: Web relay (privacy-preserving) + Reticulum broadcast
- Compatible with Reticulum nodes running MeshChat, Sideband, or NomadNet

### Documentation & Site
- Complete whitepaper: Portable Trust Thesis
- Formal primitives specification (6 productions, 13 invariants, 4 cross-layer rules)
- Falsification guide pairing every claim with the test that would disprove it
- Architecture specification with trust model and governance grammar
- Interactive demos: Governance Playground, Sentinel Configurator, Course
- Refreshed zeropoint.global with substrate narrative and support infrastructure
- Blog post: "Trust Shouldn't Be a Feature"

### Harness Integration Roadmap
- Priority targets: pi (reference, both layers), Claude Code (hooks + MCP), Codex (hooks + MCP)
- Second tier: Google ADK (MCP-native), Microsoft Agent Framework (middleware)
- Third tier: LangGraph (callbacks), Junie (MCP + guidelines)
- Shared `zp-mcp-server` implementation serves all MCP-capable harnesses

### Infrastructure
- 22+ Rust crates, 700+ tests, all passing
- GitHub Sponsors and Open Collective integration
- FUNDING.yml for GitHub sponsor button
- CI pipeline: build, test, clippy (`-D warnings`), fmt check
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
