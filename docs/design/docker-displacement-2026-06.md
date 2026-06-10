# Docker Displacement via ZP Governance
**Date:** 2026-06-10  
**Status:** Design note — no implementation yet  
**Origin:** IronClaw launch walkthrough; Docker required for Postgres + code execution sandbox

---

## The observation

Docker currently appears in IronClaw's dependency chain for two reasons:

1. **PostgreSQL** — the agent's state store, run as a Docker container.
2. **Code execution sandbox** — `SANDBOX_ENABLED=true`, `SANDBOX_IMAGE`, Docker-backed isolation for untrusted code.

Both are infrastructure answers to governance questions. Docker provides isolation via OS-level containment (container boundary, cgroups, namespacing). ZP provides isolation via protocol-level governance (gate, delegation scope, receipt chain). These are parallel approaches to the same underlying concern: *what is this agent allowed to do, and how do we enforce it?*

---

## Why Docker is the wrong primary control

Docker isolation is location-based and centralized — the container boundary is the enforcement point, and Docker daemon is the authority. This conflicts with two ZP design principles:

- **Principle 2 (Identity is a key, not a location)** — trust derives from cryptographic identity, not from which container something runs in.
- **Principle 3 (There is no center)** — Docker daemon is a centralized dependency; if it's not running, nothing launches. That's fragility, not governance.

The ZP answer to "can this agent execute this code?" is: the gate decides, before execution, based on a chain-anchored delegation grant. If the operator has issued a `tool_call` grant scoped to `["bash"]`, the gate allows bash. If not, the gate denies regardless of whether a Docker container is available. Docker sandbox at that point is defense-in-depth, not the primary control.

---

## The displacement trajectory

**Code execution sandbox:**  
Gate enforcement (Claim 4) is the primary control. `tool_call` grants with narrowed scope (`["bash"]`, `["python"]`, specific tool names) replace container-level isolation as the authorization layer. Docker sandbox becomes optional defense-in-depth for genuinely untrusted third-party code — a narrow, shrinking surface as operator-governed agents become the norm.

**PostgreSQL:**  
Separate state store with its own auth model = second trust boundary running parallel to the chain. Architecture Principle 5 ("store-and-forward is primary") points toward the chain as the durable substrate. External DB becomes a derived cache rather than a source of truth. Agent state that matters (decisions, delegations, capability exercises) belongs on the chain; ephemeral working state can live in-process or in a lightweight embedded store (SQLite is already used for the audit chain itself).

**The residual Docker case:**  
Truly untrusted third-party code where OS-level containment is warranted even after the gate has approved. This is a legitimate but narrow use case — more relevant for a multi-tenant platform than for a single-operator sovereign agent. Under ZP governance, the operator is the authority; their Genesis-rooted delegation defines the trust surface. Container isolation adds little when the operator already controls what runs.

---

## Practical implication

The framing "check if Docker is up before launching IronClaw" is the wrong fix. The right arc:

1. Route IronClaw's code execution decisions through the ZP gate (`tool_call` grant, narrowed scope).
2. Once the gate is the primary control, make Docker optional — fall back to a process-isolated sandbox or in-process execution with scope enforcement.
3. Move PostgreSQL toward a chain-anchored state model: chain as source of truth, SQLite or in-process store as derived cache, Docker Postgres as an optional convenience for development.

The test for displacement: *if Docker is not running, does IronClaw degrade gracefully with ZP governance still intact?* Today the answer is no — Docker is required. The target is yes — ZP governance holds, Docker is optional.

---

## Connections

- **Claim 4** (ToolCall gate enforcement) — the primary control that displaces Docker sandbox
- **Architecture Principle 5** (store-and-forward is primary) — the principle that displaces Docker Postgres
- **Part VIII** (Compute Surface Awareness) — Docker daemon appears in `zp ps` as `KnownSystem { category: "container runtime" }`; its absence should be a graceful degradation signal, not a hard dependency
- **Singular sovereign root** — one credential ceremony, everything derived; Docker adds a second dependency chain outside that model
