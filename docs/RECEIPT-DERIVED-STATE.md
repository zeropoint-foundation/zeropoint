# Receipt-Derived State: A Formal Treatment

## The Core Theorem

**State is never stored. State is derived.**

Given an append-only receipt chain `C` and a tool identifier `t`, the current state of `t` is a pure function over the subsequence of receipts relevant to `t`:

```
state(t) = reduce(filter(C, t))
```

This function is:

- **Deterministic**: Same chain → same state. Always.
- **Portable**: Any observer with access to `C` independently computes identical state. No coordination required.
- **Auditable**: The derivation path is the proof. There is no hidden state to trust — only receipts to verify.
- **Temporally complete**: State at any historical point `T` is computable by truncating the chain at `T`. The system has perfect memory with zero storage of mutable state.

This is not a caching strategy. This is not event sourcing bolted onto a database. This is the elimination of stored state as a concept. The chain is the only truth. Everything else is a projection.

---

## Why This Matters for Autonomous Systems

In the Agentic Age, the question isn't "what is the system doing?" — it's "why should I believe what the system says it's doing?"

Traditional architectures answer with stored state: a `status` column in a database, a health check endpoint that returns `{"ok": true}`, a dashboard that polls and renders. Every one of these is a claim without a proof. The `status` column can be stale. The health check can lie. The dashboard can render cached data from minutes ago.

Receipt-derived state eliminates this entire class of trust failures. When ZeroPoint reports that IronClaw is `running`, that conclusion is backed by a specific receipt — `tool:health:up:ironclaw` at timestamp `T`, observed by the proxy when it forwarded a request and received a `200`. When it reports that pentagi is `blocked`, that's backed by `tool:dep:needed:pentagi:postgres` and `tool:dep:failed:pentagi:port:5432` with the exact occupant identified. The state IS the chain. The derivation IS the audit trail.

For agents operating autonomously, this property is not optional — it is the foundation of accountable action. An agent that restarts a crashed tool can point to the exact receipt sequence that justified its decision: `tool:health:down` → `tool:crashed` → policy allows auto-recovery → `tool:launched`. A human reviewer, days later, replays the same chain and reaches the same conclusion. No logs to correlate, no timestamps to reconcile, no "the dashboard said it was down" hand-waving.

---

## The Six Receipt Categories

ZeroPoint's receipt taxonomy covers the full lifecycle of a governed tool:

### 1. Lifecycle (Explicit Events)

Emitted by ZeroPoint orchestration at well-defined state transitions:

| Receipt | Meaning |
|---------|---------|
| `tool:configured:{name}` | `.env` written, credentials resolved |
| `tool:preflight:passed:{name}` | All infrastructure checks green |
| `tool:preflight:failed:{name}` | One or more checks failed |
| `tool:launched:{name}` | Process spawned |
| `tool:stopped:{name}` | Graceful shutdown |
| `tool:crashed:{name}` | Non-zero exit or OOM |
| `tool:setup:complete:{name}` | Tool's own first-run finished |

These are the backbone. Every tool passes through a defined lifecycle, and every transition is a receipt.

### 2. Health (Observed by Proxy)

The reverse proxy is not just a router — it is a passive health sensor. Every proxied request implicitly tests tool liveness:

| Receipt | Trigger |
|---------|---------|
| `tool:health:up:{name}` | Proxy received 2xx/3xx from tool |
| `tool:health:down:{name}` | Proxy got connection refused or timeout |
| `tool:health:degraded:{name}` | Proxy received 5xx from tool |

Health receipts are **sampled** — emitted immediately on state change (up→down, down→up) and throttled to 30-second intervals during steady state. This prevents chain flooding while preserving the resolution needed for accurate state derivation.

The key insight: **health monitoring is a side effect of governance**. There is no separate health check system, no polling loop, no synthetic probes. The proxy observes real traffic and reports what it sees. If nobody is talking to the tool, health goes stale — which is itself meaningful signal.

### 3. Dependencies (Learned, Not Configured)

Nobody tells ZeroPoint that IronClaw needs Postgres. It discovers this:

| Receipt | Source |
|---------|--------|
| `tool:dep:needed:{name}:{dep}` | Preflight found `DATABASE_URL` in `.env` but service unreachable |
| `tool:dep:satisfied:{name}:{dep}` | Preflight confirmed dependency available |
| `tool:dep:failed:{name}:{dep}` | Dependency could not be started (port conflict, crash, etc.) |

Over time, these receipts build a dependency graph purely from observation:

```
ironclaw  ──needs──► postgres
ironclaw  ──needs──► docker
pentagi   ──needs──► postgres
pentagi   ──needs──► redis
pentagi   ──needs──► docker
OpenMAIC  ──needs──► docker
```

This graph enables topological sort for optimal launch ordering, cascade detection (postgres down → ironclaw + pentagi affected), and recovery prioritization (restart the root cause first, not the symptoms).

The graph is never stored. It is derived from `dep:` receipts on every query. New dependencies appear automatically when new tools are configured. Stale dependencies age out as new preflight receipts supersede old ones.

### 4. Port Management

Port assignments are also receipts, not database rows:

| Receipt | Meaning |
|---------|---------|
| `tool:port:assigned:{name}:{port}` | ZP allocated port from managed range |
| `tool:port:released:{name}` | Port returned to pool |

The PortAllocator maintains a persisted JSON file for fast lookup, but the chain is authoritative. An auditor can reconstruct the complete port assignment history from receipts alone.

### 5. Infrastructure Conflicts

A novel receipt type that emerged from practical necessity:

| Receipt | Meaning |
|---------|---------|
| `tool:dep:failed:{name}:port:{port}` | Tool's compose service needs a host port that is already occupied |

This receipt carries metadata identifying the occupant — the specific process or container blocking the port. It transforms a buried Docker networking error into a first-class governance event visible on the chain, in the dashboard, and to any agent querying system state.

### 6. Traffic (Sampled)

Aggregate traffic signals for capacity planning and anomaly detection:

| Receipt | Meaning |
|---------|---------|
| `tool:traffic:request:{name}` | Proxied request (sampled at 60s intervals) |
| `tool:traffic:error:{name}` | Proxied request returned error |

---

## The State Machine

The state derivation engine reduces a tool's receipt history into one of nine phases:

```
Unknown → Configured → Ready → Starting → Running ⇄ Degraded
                    ↘ Blocked                      ↓
                                                  Down → (auto-recover?)
                                        Stopped ←─┘
                                        Crashed ←─┘
```

The derivation algorithm:

1. Collect all state-relevant receipts for the tool
2. Sort by timestamp, newest first
3. The most recent event determines the base phase
4. Apply health staleness rules (no health receipt in 120s → stale)
5. Apply benefit-of-the-doubt for recently launched tools

This is a **pure function**. It takes a list of receipts and returns a phase. No database query, no mutex, no shared state. Any observer running the same function over the same receipts computes the same phase.

---

## The Implications

### For Dashboards

A dashboard is a projection of the chain onto a visual surface. It doesn't store tool state — it calls `derive_system_state()` and renders the result. Refresh the page, get the same state. Open the page on a different machine with chain access, see the same state. There is no "dashboard state" that can drift from reality.

### For Agents

An autonomous agent querying `/api/v1/system/state` receives the same derived state as the dashboard. Its decisions are grounded in receipts, not assertions. When it takes action (restart a tool, allocate a port, escalate a conflict), it emits its own receipts — extending the chain with auditable evidence of its reasoning.

An agent's decision is reproducible: given the chain state at the moment of decision, any reviewer can verify that the action was justified. This is the foundation of **accountable autonomy**.

### For Remote Auditors

A remote auditor with a copy of the chain can independently derive the complete system history without access to the running system. They can verify that every tool launch was preceded by a passing preflight, that every port assignment was from the managed range, that health monitoring was continuous, and that recovery actions followed policy.

The chain is the audit. There is no separate audit log to reconcile.

### For Multi-Node Systems

When ZeroPoint scales to multiple nodes (mesh topology), the chain replicates. Each node derives state from its local copy. Consistency follows from chain consistency — if two nodes have the same chain, they compute the same state. No distributed state coordination, no consensus protocol for tool status, no split-brain scenarios for health monitoring.

The receipt chain transforms distributed state into a replicated log problem, which is well-solved.

---

## What This Eliminates

| Traditional Pattern | Receipt-Derived Equivalent |
|---|---|
| `status` column in a database | Derived from most recent lifecycle receipt |
| Health check polling loop | Side effect of proxy traffic |
| Dependency configuration file | Learned from `.env` analysis and preflight observation |
| Port allocation table | Derived from `port:assigned`/`port:released` receipts |
| Dashboard state cache | Stateless projection — `derive_system_state()` on every render |
| Separate audit log | The chain IS the audit log |
| State reconciliation jobs | Impossible — there is only one source of truth |
| "Last known good" fallbacks | The chain has complete history; any point is recoverable |

---

## The Deeper Principle

The receipt chain is not a logging system. It is a **commitment device**.

When ZeroPoint emits `tool:health:up:ironclaw`, it is not logging an observation — it is making a cryptographically signed commitment that at timestamp `T`, the proxy observed a successful response from IronClaw. This commitment is immutable, ordered, and independently verifiable.

State derived from commitments is fundamentally different from state stored in a database. A database row says "the current state is X." A receipt chain says "here is the complete evidence from which you can compute that the current state is X." The first requires trust in the writer. The second requires only trust in the derivation function, which is open, deterministic, and auditable.

This is what makes receipt-derived state the correct foundation for autonomous systems. In a world where agents act on behalf of humans, the question is never "what does the system say?" — it is "why should I believe what the system says?" The receipt chain answers that question by construction.

---

*ZeroPoint — Trust is infrastructure.*
