# Foundation Memory

## Organization

**ZeroPoint Open Foundation** — builds and maintains ZeroPoint, portable trust infrastructure for the Agentic Age.

**ThinkStream Labs** (thinkstreamlabs.ai) — Ken Romero's company. The Foundation operates under ThinkStream Labs.

## ZeroPoint — What It Is

Cryptographic governance primitives for autonomous agent systems. The substrate provides:
- **Audit chain**: append-only, hash-linked, signed receipt chain. Every action produces a receipt. The chain is the single source of truth.
- **Governance gate**: policy enforcement point. Tool calls pass through the gate; the gate evaluates policy and emits allow/deny receipts.
- **Credential vault**: AES-256-GCM encrypted secret storage with namespace structure. Keys are operator-managed; values never leave the vault unencrypted.
- **Delegation**: capability grants from genesis authority to tools, agents, and officers. Scoped, time-bounded, revocable.
- **Genesis ceremony**: the root of trust. One biometric authentication, everything derived.

## Architecture — The Four Claims

1. **Chain integrity**: every entry is hash-linked and (optionally) signed. Tampering is detectable.
2. **Collective audit**: any party with chain access can verify independently.
3. **Gate enforcement**: no tool executes without a governance gate decision recorded on the chain.
4. **Delegation narrowing**: delegated capabilities cannot exceed the grantor's scope.

## The Six Design Principles

1. Signing is gravity — unsigned receipts are structurally meaningless
2. Identity is a key, not a location — bead zero is the identity
3. There is no center — trust state derived locally from chain, never from remote authority
4. Every bit counts — no redundant fields, no duplicate data paths
5. Store-and-forward is primary — the chain survives outages
6. A tool is intent, crystallized — semantics in structure, not comments

## System Officer Cadre

Three ZP-native observers, each with an independent domain:

| Officer | Name | Domain | Status |
|---------|------|--------|--------|
| Steward | `std` | Integrity | Active — sweeping every 60s |
| Sentinel | `sen` | Security | Not yet implemented |
| Forge | `forge` | Operations | Not yet implemented |

Officers are read-only observers. They sweep the chain and vault, produce findings, and emit receipts. They never modify state directly.

**Steward checks**: chain hash integrity, signature coverage, chain growth anomalies (silence, bursts), vault key naming hygiene, namespace structure.

**Posture score**: composite = min(integrity, security, operations). Each 0.0–1.0. Current: ~0.90 (two minor warnings: chain_silence when idle, unsigned_entry_ratio).

**Receipt format**: `officer:{name}:{domain}:{finding_type}` — e.g., `officer:std:integrity:chain_silence`

**Heartbeat contract**: every officer emits `officer:{name}:heartbeat` on every sweep, even clean ones.

## Infrastructure

| Resource | Details |
|----------|---------|
| Domain | zeropoint.global (Cloudflare Workers) |
| Domain | thinkstreamlabs.ai (Cloudflare Workers) |
| GitHub | zeropoint-foundation/zeropoint |
| Primary dev | APOLLO (Ken's machine) |
| Test system | ARTEMIS (clean install testing, Touch ID) |
| Remote server | zp-playground |

## Key Paths (APOLLO)

| Path | What |
|------|------|
| ~/projects/zeropoint | Source code (Cargo workspace root) |
| ~/ZeroPoint/ | Runtime home — vault.json, genesis.json, session.json |
| ~/ZeroPoint/data/audit.db | Audit chain (SQLite) |
| ~/ZeroPoint/config.toml | Server configuration |
| ~/projects/ironclaw | IronClaw source (separate Cargo workspace) |

## Current State (as of 2026-06-30)

- Officers cadre: Steward active, sweeping every 60s, posture 0.90
- IronClaw tile: running on port 8091, governed through ZP gate
- ZP server: localhost:17010, build e633f35
- Sage identity: being established (this session)
