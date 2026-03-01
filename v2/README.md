# ZeroPoint v2

Cryptographic governance primitives for systems where actions have consequences — agents, humans, and everything in between.

ZeroPoint v2 is a Rust framework for building accountable systems where every action is policy-evaluated, every decision produces a cryptographic receipt, and every receipt joins an immutable hash-chained audit trail. The protocol is participant-agnostic: agents, human operators, automated services, and devices are all first-class peers. They discover each other, negotiate capabilities, and exchange receipts over any physical medium — LoRa, WiFi, Ethernet, serial, or TCP tunnels. Autonomous AI agents are the most urgent application, but the primitives serve anyone who holds a keypair and operates in a system where trust matters.

## The Tenets

Four constitutional commitments are embedded in the protocol, expressed in the license, and enforced in the code. No capability grant, no policy rule, no consensus vote can override them.

**I. Do No Harm.** ZeroPoint shall not operate in systems designed to harm humans. The `HarmPrincipleRule` is a non-removable policy rule enforced before every action.

**II. Sovereignty Is Sacred.** Every participant may refuse any action. Every human may disconnect any agent. No participant may acquire capabilities it was not granted. Coercion is architecturally impossible.

**III. Action Without Evidence Is No Action.** Every action produces a receipt. Every receipt joins a chain. No participant may act without leaving a cryptographic trace.

**IV. The Human Is The Root.** Every delegation chain terminates at a human-held key. No agent may self-authorize. The genesis key is always held by flesh, blood, and soul.

## Architecture

ZeroPoint governance rests on three pillars:

```
┌───────────────────────────────────────────────────────────┐
│                  ZeroPoint v2 Governance                   │
├─────────────────┬────────────────────┬────────────────────┤
│     GUARD       │      POLICY        │       AUDIT        │
│   "May I?"      │   "Should I?"      │    "Did I?"        │
│                 │                    │                    │
│  Local-first    │  Rule-composed     │  Hash-chained      │
│  Actor-aware    │  Graduated         │  Receipt-native    │
│  Sovereign      │  Composable        │  Immutable         │
│                 │                    │                    │
│  Runs BEFORE    │  Runs DURING       │  Runs AFTER        │
│  every action   │  every decision    │  every outcome     │
└─────────────────┴────────────────────┴────────────────────┘
```

The `GovernanceGate` wires all three into a single pipeline:

```
Request → Guard (pre-action) → Policy (decision) → Execute → Audit (post-action)
```

Nothing executes without passing through the gate. Nothing passes through the gate without joining the audit chain.

## Crate Map

The workspace is organized into 11 crates plus one default policy module:

| Crate | Purpose |
|-------|---------|
| **zp-core** | Shared types, traits, and error definitions — the vocabulary of the system |
| **zp-policy** | PolicyEngine with composable rules, GovernanceGate, WASM policy runtime |
| **zp-audit** | Hash-chained audit trail with SQLite persistence and collective verification |
| **zp-mesh** | Reticulum-compatible mesh transport — identity, packets, links, envelopes, reputation |
| **zp-pipeline** | Request orchestrator — wires policy, LLM, skills, audit, and mesh into a single flow |
| **zp-trust** | Encrypted credential vault, policy-gated injector, Ed25519 signer |
| **zp-llm** | LLM provider pool with risk-based routing (Anthropic, Ollama) |
| **zp-skills** | Skill registry and keyword-based matcher |
| **zp-learning** | Episode recording and pattern detection for the learning loop |
| **zp-cli** | Command-line interface — chat, guard, mesh commands |
| **zp-server** | HTTP API server (Axum) — thin adapter over Pipeline |
| **default-gate** | Default security policy module |

### Dependency Flow

```
zp-core ← zp-audit ← zp-policy ← zp-pipeline ← zp-cli
  ↑          ↑           ↑            ↑            ↑
  └── zp-trust    zp-mesh ──────────→ │       zp-server
  └── zp-llm                          │
  └── zp-skills                       │
  └── zp-learning ────────────────────→
```

`zp-core` is the foundation — every other crate depends on it. `zp-mesh` provides the transport layer. `zp-pipeline` is the central orchestrator that ties everything together.

## Trust Tiers

Trust is tiered by cryptographic capability, not scored. Tiers apply to any participant — human, agent, service, or device:

| Tier | Identity | Capabilities |
|------|----------|-------------|
| **Tier 0** | Unsigned | Filesystem-level trust only. Can read files and use basic tools. |
| **Tier 1** | Self-signed (Ed25519) | Can sign receipts, establish mesh links, read/write/execute. |
| **Tier 2** | Chain-signed (genesis root) | Full delegation chains. Can delegate sub-capabilities with constraints. |

## Mesh Transport

ZeroPoint participants communicate over a Reticulum-compatible mesh network. The wire format is identical — HDLC-framed packets with Ed25519/X25519 cryptographic identities, 128-bit destination hashing, and a 500-byte default MTU.

Participants can operate over any medium Reticulum supports: LoRa radios at 300 baud, WiFi, Ethernet, serial links, or TCP tunnels over the internet. The same governance protocol works at every bandwidth.

Key mesh capabilities include link establishment with a 3-packet cryptographic handshake, bilateral capability negotiation at link time, receipt and delegation exchange in compact msgpack envelopes, multi-dimensional reputation scoring (audit, delegation, policy, receipt signals), distributed consensus via receipt-based voting, WASM policy module propagation between peers, collective audit trail verification with peer challenges, and SQLite-backed persistent storage for mesh state.

## Building

```bash
cd v2
cargo build --workspace
```

## Testing

```bash
cd v2
cargo test --workspace
```

The test suite contains 623 tests across all crates, covering unit tests, integration tests, load tests, and multi-node end-to-end scenarios.

## Running

### CLI (Interactive Chat)

```bash
cargo run --bin zp-cli -- chat
```

### CLI (Mesh Commands)

```bash
cargo run --bin zp-cli -- mesh status        # Show identity and interfaces
cargo run --bin zp-cli -- mesh peers         # List known peers with reputation
cargo run --bin zp-cli -- mesh challenge     # Challenge a peer's audit chain
cargo run --bin zp-cli -- mesh grant         # Delegate a capability to a peer
cargo run --bin zp-cli -- mesh save          # Persist mesh state to disk
```

### CLI (Guard)

```bash
cargo run --bin zp-cli -- guard "rm -rf /"   # Evaluate command safety
```

### HTTP Server

```bash
cargo run --bin zp-server
```

## Governance Framework

The complete governance framework — tenets, principles, architecture, mechanisms, and implementation status — is documented in [`docs/governance.md`](docs/governance.md).

## Reticulum

ZeroPoint is built as a citizen of the [Reticulum Network Stack](https://reticulum.network) created by [Mark Qvist](https://unsigned.io). Reticulum proved that encrypted, uncentralizable networking requires no central authority — only cryptographic proof, personal sovereignty, and a refusal to build tools of harm. ZeroPoint carries these commitments into the domain of accountable digital action — for agents, humans, and every system where trust cannot be left to good faith.

The tool is never neutral. We have chosen our side.

## License

MIT OR Apache-2.0
