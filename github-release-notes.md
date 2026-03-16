# v0.1.0: Trust is Infrastructure

**First public release of ZeroPoint — cryptographic governance infrastructure for autonomous agent systems.**

## Highlights

- **Real CLI governance** with persistent audit chains and tamper-evident verification
- **Developer courses** (SDK track + Internals track) — learn governance from the ground up
- **WASM policy modules** — author and deploy custom governance gates
- **Sovereign distribution** via NomadNet (Reticulum mesh network) — zero DNS, zero CDN required
- **Framework-agnostic** — govern any agentic system, any stack

## What's New

### Governance Gates (Real)
`zp gate eval`, `zp audit log`, `zp audit verify` now use the production GovernanceGate and AuditStore. Audit chains are SQLite-backed, hash-chained for tamper evidence, and remain valid across CLI invocations.

**Key fix:** Chain-head-sync bug resolved. Audit integrity is guaranteed.

### WASM Policy Modules
Full lifecycle management for custom governance gates:
- `zp policy load <path>` — Load compiled WASM policy module
- `zp policy list` — Show loaded policies
- `zp policy status <policy>` — Check policy state
- `zp policy verify <policy>` — Verify policy integrity
- `zp policy remove <policy>` — Unload a policy

Author in Rust, compile to WASM, deploy without recompilation.

### Scoped Capability Keys
Issue keys with fine-grained capabilities:
```
zp keys issue --name my-agent --capabilities "tool:read,tool:filesystem:read"
```

Agents can only act within their granted scope. No overprivilege, no privilege escalation.

### Mesh Distribution (NomadNet)
ZeroPoint is available over Reticulum mesh network at `89.167.86.60:4243`. Download verified with BLAKE3. No DNS lookups. No certificate authority. Sovereign infrastructure for governed systems.

### Core Architecture
- **Cryptographic identity:** Ed25519 key hierarchies with delegation chains
- **5-layer gate stack:** Identity → Scope → Policy → Audit → Verification
- **Tamper-evident audit trails:** Hash-chained receipts, cryptographically verified
- **Presence Plane:** Dual-backend mesh networking for agent discovery and coordination
- **Adversarial model:** Designed to survive compromise; governance is verifiable, not reliant on trust

## Courses

### Track 2: SDK Developer Course
**4 hours | Self-paced | No Rust required**

Learn ZeroPoint through the CLI and HTTP API.

- Module 1: Bootstrap an agent identity (`zp init`)
- Module 2: Scoped capability keys
- Module 3: The 5-layer constitutional gate stack
- Module 4: Custom WASM governance gates
- Module 5: Tamper-evident audit chains
- Module 6: HTTP API integration

→ [zeropoint.global/course-sdk.html](https://zeropoint.global/course-sdk.html)

### Track 3: Internals Course
**20 hours | Deep dive | Rust level**

Master ZeroPoint's architecture and threat model.

- 14 modules covering key hierarchies, signing, capability grants, delegation chains, policy engine, governance gates, receipts, audit trails, mesh identity, peer communication, audit challenges, WASM policy modules, and a governed agent fleet capstone.

→ [zeropoint.global/course.html](https://zeropoint.global/course.html)

## Getting Started

### Install
```bash
cargo install --path crates/zp-cli
```

### Quick Start
```bash
# Bootstrap an agent
zp init

# Issue a scoped capability key
zp keys issue --name my-agent --capabilities "tool:read"

# Evaluate a gate
zp gate eval "tool:filesystem:read" --resource "/data/test.csv"

# Check the audit log
zp audit log

# Verify audit chain integrity
zp audit verify
```

### HTTP API
```bash
# Start the server
zp server --port 7071

# Issue keys (HTTP)
curl -X POST http://localhost:7071/api/v1/keys/issue \
  -H "Content-Type: application/json" \
  -d '{"name":"my-agent","capabilities":["tool:read"]}'

# Evaluate a gate (HTTP)
curl -X POST http://localhost:7071/api/v1/gate/eval \
  -H "Content-Type: application/json" \
  -d '{"gate":"tool:filesystem:read","resource":"/data/test.csv"}'
```

## Philosophy

**Trust is Infrastructure.**

Agents need governance built into their identity from day one—not bolted on after the fact. ZeroPoint provides:

- **Cryptographic identity** that proves who an agent is
- **Governance gates** that enforce what an agent can do
- **Audit trails** that prove what actually happened
- **Mesh networking** that enables coordination without central authority

It's framework-agnostic. Works with any agent system.

## Links

- **Website:** [zeropoint.global](https://zeropoint.global)
- **Repository:** [github.com/zeropoint-foundation/zeropoint](https://github.com/zeropoint-foundation/zeropoint)
- **SDK Course:** [zeropoint.global/course-sdk.html](https://zeropoint.global/course-sdk.html)
- **Internals Course:** [zeropoint.global/course.html](https://zeropoint.global/course.html)
- **NomadNet Node:** `89.167.86.60:4243` (Reticulum mesh)

## Contributors

Open source. MIT licensed. Contributions welcome.

---

**What's Next?**

- Distributed consensus for multi-agent governance
- Reputation and trust scoring
- Advanced WASM policy composition
- Integration with major agent frameworks

Take the course. Star the repo. Join the mesh. Build trustworthy systems.

—Ken Romero, Founder, ThinkStream Labs
