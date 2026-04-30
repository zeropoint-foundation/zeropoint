<p align="center">
  <strong>◈ Z E R O P O I N T</strong><br>
  <em>Open-source trust infrastructure for the agentic age</em>
</p>

<p align="center">
  <a href="https://github.com/zeropoint-foundation/zeropoint/actions/workflows/ci.yml"><img src="https://github.com/zeropoint-foundation/zeropoint/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/zeropoint-foundation/zeropoint/releases"><img src="https://img.shields.io/github/v/release/zeropoint-foundation/zeropoint?include_prereleases&label=release" alt="Release"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License"></a>
  <a href="https://zeropoint.global"><img src="https://img.shields.io/badge/docs-zeropoint.global-7eb8da" alt="Docs"></a>
</p>

---

AI agents are making real decisions — writing code, calling APIs, moving data across trust boundaries. Every agent harness tracks what happened differently, but none of them can *prove* it. Audit trails are proprietary, non-portable, and break the moment you switch tools.

ZeroPoint is the trust layer that works across all of them. Every action produces a **signed receipt**. Every receipt chains into a **tamper-evident ledger**. Every participant — human, agent, service, or device — holds an **Ed25519 keypair**, not an account. The governance layer doesn't care which harness produced the action. The audit chain is continuous regardless of which agent framework you're running today or will switch to tomorrow.

We don't compete with agent harnesses. We make them trustworthy.

## How It Works with Your Agent Framework

ZeroPoint integrates with agent harnesses as a two-layer extension — no forking, no modifications to the harness core:

```
    ┌──────────┐  ┌────────────┐  ┌─────────┐  ┌─────────┐
    │    pi    │  │ Claude Code │  │  Codex  │  │  yours  │
    └────┬─────┘  └─────┬──────┘  └────┬────┘  └────┬────┘
         │              │              │             │
    ┌────▼──────────────▼──────────────▼─────────────▼────┐
    │              @zeropoint/trace                        │
    │   Passive receipt emission via MCP · hooks · events  │
    ├─────────────────────────────────────────────────────┤
    │              @zeropoint/guard                        │
    │   Capability checks before trust-boundary actions    │
    └────────────────────────┬────────────────────────────┘
                             │
    ┌────────────────────────▼────────────────────────────┐
    │              ZeroPoint Core                          │
    │                                                     │
    │  Identity ─── Receipts ─── Capabilities             │
    │     │            │              │                    │
    │     └──── Governance Pipeline ──┘                    │
    │          Guard → Policy → Audit                     │
    └────────────────────────┬────────────────────────────┘
                             │
    ┌────────────┬───────────┼────────────┬───────────────┐
    │            │           │            │               │
    ▼            ▼           ▼            ▼               ▼
 Sentinel     Mesh      Fleet Mgmt    Cockpit      Hedera HCS
 (Router)   Network     & Delegation  Dashboard    (Anchoring)
```

**Trace layer** — universal, passive, append-only. Hooks into any harness's event lifecycle to write provenance receipts on every tool call. Works via MCP (Model Context Protocol), hooks, or callbacks. A few hundred lines per adapter. This is the adoption wedge.

**Guard layer** — harness-specific, active. Checks capability grants before trust-boundary actions. Can block unauthorized tool calls. The harness opts into being governed, not just observed. This is where the real governance value lives.

A single `zp-mcp-server` gives trace-layer coverage to any MCP-capable harness automatically.

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

## Core Primitives

| Primitive | What it does |
|-----------|-------------|
| **Identity** | Ed25519 + X25519 keypairs. You are your key, not your account. Destination-hash addressing for mesh routing. |
| **Receipts** | Blake3 hash-chained, Ed25519-signed records of every action. Tamper-evident by construction. 16µs per signed receipt. |
| **Capabilities** | Scoped, time-bound, delegatable authorization grants with constraint evaluation. Standing delegation with automated lease renewal. |
| **Governance** | Constitutional rules enforced at the protocol level. Guard → Policy → Audit pipeline. Non-removable invariants. |
| **Fleet** | Heterogeneous node registry with heartbeat, lease renewal, policy distribution. Rust, Python, and TypeScript nodes in the same mesh. |
| **Mesh** | Reticulum-compatible transport. AgentAnnounce, capability exchange, policy sync, reputation. |

## What's Running Today

This is not vaporware. The fleet is live:

- **ZP Core** (Rust) on workstation — governance gate, receipt chain, fleet registry, SSE event stream, cockpit dashboard
- **ZP Sentinel** (Python) on ASUS RT-AX58U router — DNS monitoring, device tracking, anomaly detection, Ed25519 mesh identity
- **Fleet heartbeat** every 30 seconds between Sentinel and Core
- **Standing delegation** with automated lease renewal every 2 hours, Ed25519-signed
- **22+ Rust crates**, 700+ tests, all passing
- **16µs** per signed receipt, **47K entries/sec** chain verification

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
│   ├── zp-server        # Axum HTTP/WebSocket API server + fleet management
│   ├── zp-anchor        # Truth anchoring trait (Hedera HCS reference backend)
│   ├── zp-verify        # Chain verification + trajectory attestation
│   ├── zp-cli           # Command-line interface (serve, verify, doctor, scan, delegate)
│   └── execution-engine # Sandboxed command execution
├── tools/
│   └── sentinel/        # Multi-platform network sentinel
│       ├── install.sh              # Universal installer (auto-detect)
│       ├── zp_sentinel/            # Python: governance gate, mesh, lease, monitoring
│       ├── platforms/merlin/       # ASUS Merlin profile
│       ├── platforms/openwrt/      # OpenWrt profile
│       ├── platforms/linux-systemd/# Standard Linux profile
│       ├── platforms/docker/       # Docker profile + Dockerfile
│       └── configurator.html       # Interactive install configurator
├── policies/            # Default governance gate WASM policies
├── deploy/              # Deployment configs (Caddy, systemd)
└── Dockerfile           # Multi-stage production build
```

## Sentinel

The Sentinel extends the trust mesh to your network edge. It runs on routers, Raspberry Pis, or any Linux box — monitoring DNS queries, tracking devices, detecting anomalies, and participating in the mesh as a first-class cryptographic peer with standing delegation and automated lease renewal.

| Feature | Description |
|---------|-------------|
| **DNS Filtering** | Steven Black blocklists. Every query governed by policy. |
| **Device Monitoring** | DHCP lease tracking, MAC blocking, rogue device detection. |
| **Anomaly Detection** | DNS spikes, port scans, DGA domains, device floods. |
| **Audit Trail** | Blake3 hash-chained SQLite ledger. Tamper-evident. |
| **Alert Notifications** | Push to Ntfy, Slack, or any webhook. Critical alerts repeat until ack'd. |
| **Fleet Participation** | Ed25519 identity, fleet heartbeat, standing delegation, lease renewal. |

Supported platforms: **ASUS Merlin** · **OpenWrt** · **Linux (systemd)** · **Docker**

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
  <em>Trust shouldn't be a feature. It should be the substrate.</em><br>
  Built by <a href="https://thinkstreamlabs.ai">ThinkStream Labs</a>
</p>
