# Tool State Engine — Receipt-Derived System State

**Status**: Implemented (v0.1)
**Author**: Ken + Claude
**Date**: 2026-03-26

## Core Principle

> **State is never stored, only derived.**

There is no `tool_status` field in a database. State is a pure function
over the receipt chain:

```
current_state(tool) = reduce(receipts_for(tool))
```

Any observer with access to the chain — a dashboard, an agent, a remote
auditor — independently derives the same state. The chain is the single
source of truth. This makes state **portable**.

## Receipt Taxonomy

Every meaningful event in a tool's lifecycle produces a receipt on the
hash-linked audit chain. Receipts are organized into six categories:

### Lifecycle (emitted by ZP orchestration)

| Event | Trigger | Emitter |
|-------|---------|---------|
| `tool:configured:{name}` | .env written, creds resolved | preflight |
| `tool:preflight:passed:{name}` | all infra checks green | preflight |
| `tool:preflight:failed:{name}` | one or more checks failed | preflight |
| `tool:launched:{name}` | process spawned | launch handler |
| `tool:stopped:{name}` | graceful shutdown | (future) |
| `tool:crashed:{name}` | non-zero exit or OOM | (future) |
| `tool:setup:complete:{name}` | tool's own first-run finished | tool self-report |

### Health (emitted by proxy from observed traffic)

| Event | Trigger | Sampling |
|-------|---------|----------|
| `tool:health:up:{name}` | proxy got 2xx/3xx | Every 30s or on state change |
| `tool:health:down:{name}` | connection refused / timeout | Immediate on state change |
| `tool:health:degraded:{name}` | proxy got 5xx | Every 30s or on state change |

Health receipts are **sampled**, not emitted on every request. The sampler
tracks the last emission per tool and fires when:
- Health status changes (up→down, down→up) — immediate
- Same status but 30+ seconds since last emission — periodic

### Dependencies (inferred from preflight + launch failures)

| Event | Meaning |
|-------|---------|
| `tool:dep:needed:{name}:{dep}` | Tool needs this service |
| `tool:dep:satisfied:{name}:{dep}` | Dependency confirmed available |
| `tool:dep:failed:{name}:{dep}` | Dependency could not be started |

Dependencies are **learned from observations**, not configured. When
IronClaw's preflight detects `DATABASE_URL` in `.env` and Docker is
running, it emits `tool:dep:satisfied:ironclaw:postgres`. When Docker
is down, it emits `tool:dep:needed:ironclaw:postgres`.

### Port Management

| Event | Meaning |
|-------|---------|
| `tool:port:assigned:{name}:{port}` | ZP assigned port from 9100-9199 range |
| `tool:port:released:{name}` | Port returned to pool |

### Traffic (heavily sampled — for aggregate stats)

| Event | Sampling |
|-------|----------|
| `tool:traffic:request:{name}` | At most once per 60s per tool |
| `tool:traffic:error:{name}` | At most once per 60s per tool |

## State Machine

The state engine derives one of nine phases from the receipt timeline.
The **most recent event wins** — timestamp comparison determines phase.

```
                   ┌──────────────────────────────────────────────────┐
                   │                                                  │
 ┌─────────┐  configured  ┌────────────┐  preflight   ┌──────────┐  │
 │ Unknown ├────────────►│ Configured ├──────────────►│ Ready    │  │
 └─────────┘             └────────────┘  :passed      └────┬─────┘  │
                   ▲            │                           │        │
                   │            │ preflight:failed    launched       │
                   │            ▼                           │        │
                   │     ┌────────────┐              ┌─────▼─────┐  │
                   │     │ Blocked    │              │ Starting  │  │
                   │     └────────────┘              └─────┬─────┘  │
                   │                                       │        │
                   │                              health:up│        │
                   │                                       ▼        │
                   │  stopped/crashed             ┌────────────┐   │
                   └─────────────────────────────┤  Running    │   │
                                                 └──────┬─────┘   │
                                                        │         │
                                              health:down│        │
                                                        ▼         │
                                                 ┌────────────┐   │
                                                 │  Down      ├───┘
                                                 └────────────┘
```

### Phase derivation algorithm

```rust
fn derive_phase(receipts) -> Phase {
    // Collect the most recent timestamp for each event type
    // Sort by timestamp descending
    // The newest event determines the phase:
    //   healthy  → Running (unless stale → Down)
    //   unhealthy → Down
    //   degraded → Degraded
    //   launched → Starting
    //   preflight_passed → Ready
    //   preflight_failed → Blocked
    //   configured → Configured
    //   stopped → Stopped
    //   crashed → Crashed
}
```

### Health staleness

A `health:up` receipt older than 120 seconds is considered **stale**.
If no fresh health signal exists and the tool was launched recently
(within 10 minutes), it gets the benefit of the doubt → `Running`.
Otherwise → `Down`.

This handles idle tools gracefully: a tool with no traffic isn't dead,
it's just quiet. But a tool that was getting traffic and suddenly stops
getting health receipts is probably down.

## Dependency Graph

The dependency graph is **never configured — it's learned**.

```
ironclaw ──needs──► postgres
ironclaw ──needs──► docker
pentagi  ──needs──► postgres
pentagi  ──needs──► redis
pentagi  ──needs──► docker
```

This graph is built by scanning `dep:needed` and `dep:satisfied`
receipts. It enables:

- **Smart launch ordering**: topological sort → start deps first
- **Cascade detection**: postgres down → ironclaw + pentagi affected
- **Recovery prioritization**: restart the root cause, not symptoms

### Launch order computation

```rust
fn launch_order(graph) -> Vec<Vec<String>> {
    // Topological sort with parallel layers:
    // Layer 0: [docker, postgres, redis]  ← no deps, start first
    // Layer 1: [ironclaw, pentagi]        ← depend on layer 0
    // Within each layer, tools can start in parallel.
}
```

## System State API

`GET /api/v1/system/state` returns the complete derived state:

```json
{
  "timestamp": "2026-03-26T22:15:00Z",
  "tools": {
    "ironclaw": {
      "phase": "running",
      "configured_at": "2026-03-26T21:55:35Z",
      "preflight_at": "2026-03-26T22:00:00Z",
      "launched_at": "2026-03-26T22:01:00Z",
      "last_healthy_at": "2026-03-26T22:14:45Z",
      "preflight_passed": true,
      "assigned_port": 9100,
      "dependencies": [
        { "name": "postgres", "satisfied": true },
        { "name": "docker", "satisfied": true }
      ],
      "total_requests": 47,
      "total_errors": 0,
      "health_age_secs": 15,
      "health_stale": false
    }
  },
  "summary": {
    "total": 3,
    "running": 2,
    "down": 1,
    "blocked": 0
  },
  "attention_needed": ["agent-zero"],
  "dependency_graph": {
    "ironclaw": ["postgres", "docker"],
    "pentagi": ["postgres", "redis", "docker"]
  },
  "launch_order": [
    ["docker", "postgres", "redis"],
    ["ironclaw", "pentagi"]
  ]
}
```

## What This Enables

### For Agents

An agent that needs IronClaw doesn't shell out to `curl localhost:9100`.
It calls `GET /api/v1/system/state` and checks:

```python
if state.tools.ironclaw.phase == "running":
    proceed()
elif state.tools.ironclaw.phase == "down":
    emit("tool:dep:needed:my-agent:ironclaw")
    wait_for("tool:health:up:ironclaw")
```

The agent reads and writes receipts — the chain is the coordination
medium. No direct tool-to-tool communication needed.

### For the MLE STAR / Monte Carlo Engines

The receipt chain is a time-series dataset. Over weeks of operation:

- Which tools fail most often? (count `crashed` receipts per tool)
- What's the mean time between failures?
- What dependencies are fragile? (count `dep:failed` per dep)
- What's the optimal pre-warm strategy? (analyze launch timing patterns)
- What's the cost per tool-hour? (correlate with LLM proxy receipts)

The engines analyze receipt history to predict failures, recommend
infrastructure changes, and optimize the tool fleet.

### For Remote Auditors

The chain is cryptographically linked (each receipt hashes the previous).
An external auditor can:

1. Fetch the chain
2. Verify hash integrity
3. Derive the same system state independently
4. Confirm that every tool action was authorized by policy
5. Trace any incident back to its root cause via receipt timeline

This is **portable trust** — the audit trail travels with the system.

## File Map

| File | Role |
|------|------|
| `tool_state.rs` | State derivation engine, SystemState, phase machine |
| `tool_proxy.rs` | Reverse proxy with health receipt emission |
| `tool_ports.rs` | Port allocator, .env.zp sidecar |
| `tool_chain.rs` | Receipt emission, chain queries (existing) |
| `onboard/preflight.rs` | Dependency receipt emission |

## Future Work

- **WebSocket proxy**: Forward WS connections through the proxy
- **Auto-recovery**: When phase = Down, automatically relaunch
- **Health endpoint convention**: `GET /health` on each tool for structured health checks
- **Receipt signing**: Sign health receipts with the server's Genesis key
- **Cascade alerts**: When a dependency goes down, mark all dependents as "at risk"
- **Receipt pruning**: Compact old traffic receipts while preserving lifecycle events
