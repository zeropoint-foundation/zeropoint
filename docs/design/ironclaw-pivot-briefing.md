# IRONCLAW PIVOT BRIEFING

## Context for CLIC — Strategic Redirection of GAR First Tenant

**ThinkStream Labs** · April 2026
**Document:** ZP-GAR-PIVOT-001 · **Classification:** Internal / Strategic
**Supersedes:** Nothing — this document *supplements* ZP-GAR-SPEC-001 (governed-agent-runtime.md)
**Decision maker:** Ken (ThinkStream Labs)
**Decision:** IronClaw replaces Hermes as the first fully-governed tenant of the ZeroPoint GAR.

---

## 1. Why the Pivot

Hermes was selected as the first tenant because of its breadth — 510k LOC, 61 tools, 15+ messaging platforms, 8 memory backends. That breadth is real, but it creates friction that works against a clean governance demonstration:

- **Competing subsystems.** Hermes has its own credential management, its own memory provider system, its own skill verification, its own cron scheduler, its own subprocess orchestration. Each competes with ZP's equivalent. Governing Hermes means *replacing or wrapping* each of these — and Hermes's architecture makes some of those wraps fragile (e.g., the `memory` tool bypasses `pre_tool_call` hooks entirely).

- **Python↔Rust boundary.** ZP's core is Rust. Hermes is Python. Every integration point crosses a language boundary via subprocess, HTTP, or bridge process. The AG-UI bridge we built (`services/hermes-bridge/bridge.py`) works, but it's a translation layer on top of a translation layer.

- **One-shot CLI, not a daemon.** Hermes runs a single query and exits. It doesn't bind a port. The bridge had to wrap it as a per-request subprocess spawner. This is not how a governed tenant should behave — it fights the process model.

- **Observed, not governed.** After weeks of integration work, Hermes is still only *observed* through the AG-UI proxy. It can still use its own auth, its own memory, its own file access outside the governed pipeline. Sealing those channels requires deep framework surgery.

IronClaw, by contrast, was sitting on the ZP dashboard the entire time — genesis-bound, chain-verified, green status. The investigation below explains why it's the right first tenant.

---

## 2. What IronClaw Is

IronClaw is a secure personal AI assistant written in Rust. ~202k LOC (40% of Hermes's size, but similar architectural complexity). Apache 2.0 / MIT dual-licensed. Built by NEAR AI.

**Repository:** https://github.com/nearai/ironclaw
**Local installation:** ~/projects/ironclaw/ (currently v0.19.0, latest is v0.26.0 — upgrade needed before governance work)
**ZP status:** Genesis-bound. Receipt chain exists: `rcpt-genesis → rcpt-cfg-ic → rcpt-preflight → rcpt-port → rcpt-launched → rcpt-health`

---

## 3. Why IronClaw Is Better for First Governance

### 3.1 Same Language, Same Ecosystem

IronClaw is Rust. ZP is Rust. No language boundary. No bridge process. No subprocess spawning per request. IronClaw runs as a daemon with a persistent web gateway. It binds ports, streams SSE events, and serves project files — all things a governed tenant should do.

### 3.2 Already Inside the Trust Boundary

IronClaw is already genesis-bound on the ZP dashboard. The canonicalization chain exists. Hermes never got past "observed." IronClaw has Year Zero.

### 3.3 Governance Hooks Were Designed In

IronClaw has a `CockpitProvider` trait (`src/cockpit.rs`) specifically designed for governance dashboards. The trait defines `snapshot()` and `subscribe()` methods. The web gateway already stores `Arc<dyn CockpitProvider>` in `GatewayState` and serves `/api/cockpit/snapshot` (REST) and `/api/cockpit/events` (SSE). The implementation is skeletal — but the architecture is there. This is not a seam we're *finding* in someone else's code; it's a seam that was *built for us*.

### 3.4 Approval Pipeline Is Native

IronClaw's tool execution pipeline already has a governance-shaped flow:

```
Tool Request → Schema Validation → Autonomy Check (allowlist)
→ Approval Check (requires_approval → pause loop)
→ Timeout Wrapper → Execute → Sanitize Output → Return
```

The `approval_needed` event is a *native SSE event type*. AG-UI has no equivalent — this is a governance primitive that IronClaw already streams. The approval gate returns `LoopOutcome::NeedApproval`, which the web gateway holds until the user (or ZP) decides.

### 3.5 Credential System Aligns

IronClaw uses AES-256-GCM encryption with per-secret HKDF-SHA256 key derivation. Credentials are injected at the HTTP boundary for WASM tools — the tool code never sees raw values. There's also leak detection (Aho-Corasick multi-pattern scanning) on both request and response. This aligns with ZP's vault model rather than competing with it.

### 3.6 The Browser Harness Trick Works

IronClaw serves project files at `/projects/{project_id}/{path}` through its web gateway, behind auth, with path traversal guards and MIME type detection. The agent can write HTML to `~/.ironclaw/projects/cockpit/index.html` via the `file` builtin tool → the gateway serves it → Browser Harness points there → the agent mutates the file → the browser updates. Same trick Hermes uses, but more structured and already receipted through the tool pipeline.

### 3.7 SSE Event Model Maps to AG-UI

IronClaw's `SseEvent` enum (`src/channels/web/types.rs`) has 14 variants:

| IronClaw Event | AG-UI Equivalent |
|---|---|
| `response` | `TEXT_MESSAGE_CONTENT` |
| `stream_chunk` | `TEXT_MESSAGE_CONTENT` (token-level) |
| `thinking` | `REASONING_CONTENT` |
| `tool_started` | `TOOL_CALL_START` |
| `tool_completed` | `TOOL_CALL_END` |
| `tool_result` | `TOOL_CALL_END` (with output) |
| `approval_needed` | No AG-UI equivalent (governance-native) |
| `status` | `ACTIVITY_STATUS` |
| `job_started` | `RUN_STARTED` |
| `error` | Custom |
| `auth_required` / `auth_completed` | Custom |
| `heartbeat` | keepalive |
| `job_message` | `TEXT_MESSAGE_CONTENT` (scoped to job) |

Wire format: `{"type":"<variant>", ...fields}` via `#[serde(tag = "type")]`. Structurally identical to AG-UI typing. An adapter is thin translation, not rewrite.

---

## 4. What the GAR Spec Needs to Change

The GAR spec (ZP-GAR-SPEC-001, revision 1.2) is Hermes-centric throughout. For the IronClaw pivot:

### 4.1 Header / Metadata
- **First Tenant** changes from "Hermes Agent (Nous Research)" to "IronClaw (NEAR AI)"
- Version, LOC, star count updated accordingly
- Companion specs may need IronClaw-specific equivalents

### 4.2 Section 2 (Problem Statement)
- The five governance gaps still apply universally. IronClaw exhibits them too (memory writes, tool execution, network access, subprocess spawning via Docker orchestrator). The framing remains valid — just re-cite with IronClaw-specific examples.

### 4.3 Section 3.1 (Wrapper Model)
- The wrapper model still applies, but IronClaw's architecture offers a **tighter integration mode**: direct Rust trait implementation. Instead of wrapping a foreign process, ZP can implement `CockpitProvider` and inject it into IronClaw's `GatewayState`. The wrapper is still correct for enforcement, but the governance bridge is a library dependency, not a process boundary.
- The MCP-server tenancy mode (§3.1.1) still applies — IronClaw has a full MCP client (`src/tools/mcp/`).

### 4.4 Section 3.2 (Five Mediation Surfaces)
- All five surfaces exist in IronClaw. Re-map the "Hermes Usage" column:
  - **Model API:** 7+ LLM providers via `LlmProvider` trait, hot-reloadable in v0.26.0
  - **Filesystem:** `~/.ironclaw/workspace/` (hybrid BM25 + vector search), project files
  - **Subprocess:** Docker orchestrator (`src/orchestrator/`), WASM sandboxed tools, shell tool
  - **Network:** HTTP tool with SSRF protection, domain allowlisting per WASM tool
  - **IPC:** SSE/WebSocket to web gateway, orchestrator↔worker container comms

### 4.5 Section 5 (Governance Surfaces in Detail)
- **Memory governance (§5.1):** IronClaw's workspace system replaces Hermes's MEMORY.md + memory providers. The seam is the `file` builtin tool and workspace write path. Layer-aware persistence already detects sensitive content and redirects. No need for exclusive memory-provider plugin — the workspace *is* the memory, and it already has a sanitizer scanning writes for prompt injection.
- **Tool governance (§5.3):** The dispatch gate maps directly to IronClaw's `Autonomy` check + `requires_approval` gate. No `pre_tool_call` hook gymnastics needed — the approval flow is first-class.
- **Browser/subprocess governance (§5.3):** IronClaw's Docker orchestrator already uses per-job bearer tokens and per-container credential grants. The `ZPBrowserExecutionEnvelope` concept maps to IronClaw's existing capability model.
- **Skill governance (§5.2):** IronClaw has a skills system. Verification lifecycle applies.
- **Cron/scheduled governance (§5.6):** IronClaw has a routine engine (`src/agent/routine_engine.rs`) with cron and event-based triggers.

### 4.6 Hermes-Specific Sections
- All file:line citations (e.g., `hermes_cli/plugins.py:158`, `agent/memory_manager.py:315-329`) need IronClaw equivalents
- §11 (piggyback opportunities) needs rewrite for IronClaw's infrastructure
- The four companion interfaces (`zp-hermes-interfaces.md`) need IronClaw equivalents

---

## 5. Integration Roadmap (IronClaw-Specific)

### Tier 1: Observable Governance (Days)
- Implement `CockpitProvider` trait — wire `snapshot()` to return live state from agent loop, tool registry, cost guard
- Wire `subscribe()` to broadcast turn completions, tool executions, approval decisions as `CockpitEvent`s
- The plumbing exists: cockpit handlers serve `/api/cockpit` and `/api/cockpit/events`
- **Estimated effort:** ~200 LOC

### Tier 2: Active Governance (Focused Week)
- Hook tool execution pipeline to emit ZP receipts at each gate (autonomy, approval, timeout, sanitize)
- Hook LLM calls at the `LlmProvider` trait boundary — receipt every inference
- Wire workspace writes to emit memory receipts
- **This is the line where IronClaw goes from "observed" to "governed"**
- **Estimated effort:** ~500 LOC

### Tier 3: Full Cognition Plane (Two Weeks)
- Trust chain with genesis/operator/agent key hierarchy — IronClaw signs its own receipts as a governed sub-identity
- Audit stream recording with full receipt taxonomy
- Memory governance — every workspace write receipted, searchable, decayable by policy
- Hedera settlement (if desired at this stage)
- **Estimated effort:** ~1500 LOC

---

## 6. Immediate Next Steps

1. **Upgrade IronClaw** from v0.19.0 to v0.26.0. Re-apply local modifications (6 commits on `staging-tested`). Verify against new ownership model and tool permission system.
2. **Revise GAR spec** revision 1.3 with IronClaw as first tenant. Preserve Hermes content as "Future Tenant" appendix — the analysis is valuable for when Hermes comes second.
3. **Implement CockpitProvider** (Tier 1) as the first concrete governance wire.
4. **Build AG-UI adapter** for IronClaw's SSE events — thin translation layer, not a bridge process.

---

## 7. What Hermes Becomes

Hermes is not abandoned. It remains the most capable agent framework in terms of breadth. But it becomes the *second* tenant, not the first. The integration work already done (AG-UI proxy, bridge, event mapping) is reusable. The GAR spec's Hermes analysis is preserved — it's a roadmap for Phase 2 multi-tenancy.

The strategic sequence:
1. **IronClaw** — prove full-stack governance works, including the cognition plane
2. **Hermes** — apply the proven model to a larger, more complex tenant
3. **Any AG-UI-compatible agent** — the model generalizes

---

*This document is a supplement to ZP-GAR-SPEC-001. It does not replace the spec — it redirects its first tenant while preserving the architectural framework.*
