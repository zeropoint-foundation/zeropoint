# ZeroPoint

**Portable trust infrastructure for the post-platform internet.**

ZeroPoint provides the cryptographic primitives that let any participant — human, agent, service, or device — carry verifiable identity, earned reputation, and auditable history across trust boundaries, without depending on any single platform.

## Core Primitives

- **Identity** — Ed25519 keypairs. You are your key, not your account.
- **Receipts** — Hash-chained, signed records of every action. Tamper-evident by construction.
- **Capabilities** — Scoped, time-bound, delegatable authorization grants.
- **Governance** — Constitutional rules (Do No Harm, Sovereignty Is Sacred) enforced at the protocol level, not the policy level.

## Quick Start

```bash
# Clone and build
git clone https://github.com/zeropoint-foundation/zeropoint.git
cd zeropoint
cargo build --workspace

# Test
cargo test --workspace

# Install and launch
bash deploy/install.sh
zp serve
```

The server starts on `http://localhost:3000`. Try:

```bash
# Health check
curl http://localhost:3000/health

# Evaluate a governance guard
curl -X POST http://localhost:3000/api/v1/guard/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action": "deploy surveillance toolkit", "trust_tier": "Tier1"}'
```

## Project Structure

```
zeropoint/
├── crates/
│   ├── zp-core       # Identity, receipts, capabilities, trust tiers
│   ├── zp-audit       # Hash-chained audit trail
│   ├── zp-policy      # Policy engine + constitutional rules
│   ├── zp-trust       # Trust scoring and reputation
│   ├── zp-pipeline    # GovernanceGate: Guard → Policy → Execute → Audit
│   ├── zp-server      # Axum HTTP API (15 endpoints)
│   ├── zp-llm         # LLM integration layer
│   ├── zp-skills      # Skill/capability registry
│   ├── zp-learning    # Adaptive learning
│   ├── zp-mesh        # Mesh networking primitives
│   ├── zp-receipt     # Receipt building, signing, hashing, verification
│   ├── execution-engine # Sandboxed command execution
│   └── zp-cli         # Command-line interface
├── policies/          # Default governance gate policies
└── Dockerfile         # Multi-stage production build

zeropoint.global/      # Project site + interactive demos
deploy/                # Caddyfile, deployment guide
```

## Interactive Demos

The [zeropoint.global](https://zeropoint.global) site includes two interactive demos that connect to a live `zp-server` backend:

- **Governance Playground** — Evaluate guards, inspect policy decisions, explore delegation chains
- **Receipt Chain Visualizer** — Watch hash-chained receipts form in real time, simulate tamper detection

## Documentation

- [Whitepaper](https://zeropoint.global/whitepaper) — Full technical specification including the Portable Trust Thesis
- [Deployment Guide](deploy/README.md) — Cloudflare Pages + Hetzner VPS setup (~$5/month)
- [Contributing](CONTRIBUTING.md) — How to contribute, grounded in the Four Tenets
- [Security Policy](SECURITY.md) — Responsible disclosure

## Architecture

ZeroPoint is a Rust workspace of focused crates, designed to be transport-agnostic (HTTP, TCP, UDP, mesh) and participant-agnostic (same primitives for humans, agents, services, devices).

The governance pipeline follows a strict sequence: **Guard → Policy → Execute → Audit**. Constitutional rules (HarmPrincipleRule, SovereigntyRule) are non-removable — they cannot be overridden by any policy or configuration.

## License

MIT / Apache-2.0

---

Built by [ThinkStream Labs](https://thinkstreamlabs.ai)
