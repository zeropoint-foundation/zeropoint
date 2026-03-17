<p align="center">
  <strong>◈ Z E R O P O I N T</strong><br>
  <em>Portable trust infrastructure for the Agentic Age</em>
</p>

<p align="center">
  <a href="https://github.com/zeropoint-foundation/zeropoint/actions/workflows/ci.yml"><img src="https://github.com/zeropoint-foundation/zeropoint/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/zeropoint-foundation/zeropoint/releases"><img src="https://img.shields.io/github/v/release/zeropoint-foundation/zeropoint?include_prereleases&label=release" alt="Release"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License"></a>
  <a href="https://zeropoint.global"><img src="https://img.shields.io/badge/docs-zeropoint.global-7eb8da" alt="Docs"></a>
</p>

---

ZeroPoint provides the cryptographic primitives that let any participant — human, agent, service, or device — carry verifiable identity, earned reputation, and auditable history across trust boundaries, without depending on any single platform.

Every action produces a **signed receipt**. Every receipt chains into a **tamper-evident ledger**. Every participant holds an **Ed25519 keypair** — not an account, not a token, a *key*. Trust is computed, not granted.

## Get Started

### ZeroPoint Core (Rust)

```bash
git clone https://github.com/zeropoint-foundation/zeropoint.git
cd zeropoint
cargo build --workspace
cargo test --workspace

# Launch the server
bash deploy/install.sh
zp serve
```

The server starts on `http://localhost:3000`. Try evaluating a governance guard:

```bash
curl -X POST http://localhost:3000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action": "deploy surveillance toolkit", "trust_tier": "Tier1"}'
```

### ZeroPoint Sentinel (Network Edge)

One-line install for routers, Linux boxes, Raspberry Pis, or Docker:

```bash
curl -fsSL https://zeropoint.global/sentinel/install.sh | sh
```

Or specify a platform:

```bash
# ASUS Merlin routers
curl -fsSL https://zeropoint.global/sentinel/install.sh | sh -s -- --platform merlin

# OpenWrt / GL.iNet / Turris
curl -fsSL https://zeropoint.global/sentinel/install.sh | sh -s -- --platform openwrt

# Ubuntu, Debian, Fedora, Raspberry Pi
curl -fsSL https://zeropoint.global/sentinel/install.sh | sh -s -- --platform linux

# Docker
docker run -d --name zp-sentinel -v sentinel-data:/data ghcr.io/zeropoint-foundation/sentinel:latest
```

**[Open the Install Configurator →](https://zeropoint-foundation.github.io/zeropoint/tools/sentinel/configurator.html)**

## Architecture

ZeroPoint is a Rust workspace of focused crates designed to be transport-agnostic and participant-agnostic — the same primitives work for humans, agents, services, and devices.

```
                    ┌─────────────────────────────────────────────┐
                    │              ZeroPoint Core                  │
                    │                                             │
                    │  Identity ─── Receipts ─── Capabilities     │
                    │     │            │              │            │
                    │     └──── Governance Pipeline ──┘            │
                    │          Guard → Policy → Audit             │
                    └─────────────┬───────────────────────────────┘
                                  │
                    ┌─────────────┼───────────────────┐
                    │             │                    │
              ┌─────▼─────┐ ┌────▼─────┐  ┌──────────▼──────────┐
              │  Sentinel  │ │   Mesh   │  │   Agent Frameworks   │
              │  (Router)  │ │ Network  │  │  (LangGraph, etc.)   │
              └───────────┘ └──────────┘  └─────────────────────┘
```

The governance pipeline follows a strict sequence: **Guard → Policy → Execute → Audit**. Constitutional rules (HarmPrincipleRule, SovereigntyRule) are non-removable — they cannot be overridden by any policy or configuration.

## Core Primitives

| Primitive | What it does |
|-----------|-------------|
| **Identity** | Ed25519 + X25519 keypairs. You are your key, not your account. Destination-hash addressing for mesh routing. |
| **Receipts** | Blake3 hash-chained, Ed25519-signed records of every action. Tamper-evident by construction. |
| **Capabilities** | Scoped, time-bound, delegatable authorization grants with constraint evaluation. |
| **Governance** | Constitutional rules enforced at the protocol level. Guard → Policy → Audit pipeline. |
| **Mesh** | Reticulum-compatible transport. AgentAnnounce, capability exchange, policy sync, reputation. |

## Project Structure

```
zeropoint/
├── crates/
│   ├── zp-core          # Identity, receipts, capabilities, trust tiers
│   ├── zp-audit         # Blake3 hash-chained audit trail + collective verification
│   ├── zp-trust         # Ed25519 signing primitives
│   ├── zp-policy        # WASM policy engine + constitutional rules
│   ├── zp-mesh          # Mesh networking: identity, links, routing, discovery
│   ├── zp-receipt       # Receipt building, signing, hashing, verification
│   ├── zp-pipeline      # GovernanceGate: Guard → Policy → Execute → Audit
│   ├── zp-server        # Axum HTTP/WebSocket API server
│   ├── zp-llm           # LLM integration layer
│   ├── zp-skills        # Skill/capability registry
│   ├── zp-learning      # Adaptive learning
│   ├── zp-cli           # Command-line interface
│   └── execution-engine # Sandboxed command execution
├── tools/
│   ├── sentinel/        # Multi-platform network sentinel
│   │   ├── install.sh              # Universal installer (auto-detect)
│   │   ├── zp_sentinel/            # Python governance modules
│   │   ├── platforms/merlin/       # ASUS Merlin profile
│   │   ├── platforms/openwrt/      # OpenWrt profile
│   │   ├── platforms/linux-systemd/# Standard Linux profile
│   │   ├── platforms/docker/       # Docker profile + Dockerfile
│   │   └── configurator.html       # Interactive install configurator
│   └── merlin-sentinel/ # Legacy single-platform package
├── policies/            # Default governance gate WASM policies
├── deploy/              # Deployment configs (Caddy, systemd)
└── Dockerfile           # Multi-stage production build
```

## ZeroPoint Sentinel

The Sentinel extends the trust mesh to your network edge. It runs on routers, Raspberry Pis, or any Linux box — monitoring DNS queries, tracking devices, detecting anomalies, and participating in the mesh as a first-class cryptographic peer.

| Feature | Description |
|---------|-------------|
| **DNS Filtering** | Steven Black blocklists. Every query governed by policy. |
| **Device Monitoring** | DHCP lease tracking, MAC blocking, rogue device detection. |
| **Anomaly Detection** | DNS spikes, port scans, DGA domains, device floods. |
| **Audit Trail** | Blake3 hash-chained SQLite ledger. Tamper-evident. |
| **Alert Notifications** | Push to Ntfy, Slack, or any webhook. Critical alerts repeat until ack'd. |
| **Mesh Participation** | Ed25519 identity, AgentAnnounce protocol, heartbeat. |

Supported platforms: **ASUS Merlin** · **OpenWrt** · **Linux (systemd)** · **Docker**

**[Sentinel Documentation →](https://zeropoint.global/sentinel)**

## Mesh Network

Every participant in ZeroPoint — Core, Sentinel, agent framework, service — communicates via the mesh transport layer (`zp-mesh`). The mesh provides:

| Layer | What |
|-------|------|
| **Identity** | Ed25519 + X25519 keypairs with 128-bit destination hash addressing |
| **Links** | Forward-secret encrypted channels via X25519 ECDH + HKDF |
| **Envelopes** | Signed, typed message carriers (receipts, delegations, announces) |
| **Discovery** | Dual-backend: Web relay (privacy-preserving) + Reticulum broadcast |
| **Capability Exchange** | Bilateral negotiation during link establishment |
| **Policy Sync** | WASM policy modules propagate across the mesh |
| **Reputation** | Observable behavior → weighted scores → policy-gated decisions |

Compatible with [Reticulum](https://reticulum.network) nodes running MeshChat, Sideband, or NomadNet.

## Interactive Demos

The [zeropoint.global](https://zeropoint.global) site includes live demos:

- **[Governance Playground](https://zeropoint.global/playground.html)** — Evaluate guards, inspect policy decisions, explore delegation chains
- **[Sentinel Configurator](https://zeropoint.global/sentinel/configurator.html)** — Interactive platform selector and install generator
- **[Course](https://zeropoint.global/course.html)** — Learn ZeroPoint from first principles

## Documentation

| Resource | Link |
|----------|------|
| Project Site | [zeropoint.global](https://zeropoint.global) |
| Whitepaper | [Portable Trust Thesis](https://zeropoint.global/ZeroPoint_Whitepaper_v1.0.pdf) |
| Sentinel Docs | [zeropoint.global/sentinel](https://zeropoint.global/sentinel) |
| Deployment Guide | [deploy/README.md](deploy/README.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Security Policy | [SECURITY.md](SECURITY.md) |

## License

MIT / Apache-2.0

---

<p align="center">
  <em>One protocol. One graph. End to end.</em><br>
  Built by <a href="https://thinkstreamlabs.ai">ThinkStream Labs</a>
</p>
