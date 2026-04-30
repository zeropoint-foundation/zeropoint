# ZEROPOINT — Governed Agent Runtime

## Architecture Specification

**ThinkStream Labs** · April 2026 · Revision 1.4
**Document:** ZP-GAR-SPEC-001 · **Classification:** Internal / Strategic
**First Tenant:** IronClaw (NEAR AI) · v0.26.0, ~202k LOC Rust, Apache 2.0 / MIT, 23+ builtin tools, 7+ LLM providers, 6 channel types, WASM sandbox, MCP client, Docker orchestrator
**Second Tenant (roadmap):** Hermes Agent (Nous Research) · v0.10.0, ~510k LOC Python, 61 tools, 15+ messaging gateways — see Appendix A
**Roadmap position:** Phase 4 of the ZeroPoint architecture (`docs/ARCHITECTURE-2026-04.md`)
**Companion specs:** Visual language (`docs/design/zp-visual-language.md`), IronClaw pivot briefing (`docs/design/ironclaw-pivot-briefing.md`)
**Protocol stack:** MCP (agents↔tools, have), MCP Apps (tools→UI, adopting), AG-UI (agents↔frontends, have), A2UI (declarative UI-as-data, shaping toward), A2A (agents↔agents, deferred to Phase 3)
**Precursor to:** Cognitive accountability layer (`docs/future-work/cognitive-accountability.md`, Phase 4 roadmap item)

> **Revision 1.4 (2026-04-25):** Three major additions. (1) Generative UI protocol alignment: new §3.2 defines the three-layer UI architecture (data layer, component catalog, transport adapters) shaped to A2UI, MCP Apps, and AG-UI conventions; new §5.9 specifies the governance component catalog; §3.1.1 updated with MCP Apps `_meta.ui.resourceUri` pattern; implementation phases updated with MCP Apps (Phase 1), catalog schema (Phase 1.5), and A2UI adapter (Phase 2). (2) Canonicalization elevated to first-class architectural concept: new §3.4 articulates canonicalization as the constitutive primitive — the only governance mechanism that establishes what *exists* rather than recording what happened. Canon woven through core thesis, executive summary, problem statement (new sixth governance gap), and strategic positioning. The canonicalization invariant ("nothing executes in a governed context without a canon") formalized as structural enforcement. (3) Receipt chain confirmed as the canonical data layer — AG-UI, A2UI, and MCP Apps are projections, not competing formats.

> **Revision 1.3 (2026-04-25):** First tenant pivoted from Hermes to IronClaw. IronClaw is already genesis-bound on the ZP dashboard with a complete receipt chain (`rcpt-genesis → rcpt-cfg-ic → rcpt-preflight → rcpt-port → rcpt-launched → rcpt-health`). Tenant-specific sections rewritten with IronClaw source citations. Hermes analysis preserved as Appendix A. New §5.8 covers IronClaw's native approval pipeline. New §11 catalogs structural advantages.

> **Previous revisions:** See git history. Revision 1.2 contained the full Hermes capability scan with file:line citations.

---

> **Core Thesis:** ZeroPoint is the runtime, not the accessory. Agent frameworks provide discovery and continuity. ZeroPoint provides provenance, bounded authority, canonical identity, and portable governance. Every governed entity — agent, tool, provider, skill, memory tier — is canonicalized: cryptographically anchored to the operator's genesis identity via a signed receipt chain. Without canon, an entity does not exist in the governance domain. With canon, its identity is permanent, its provenance is verifiable, and its trust is portable. For IronClaw, governance is not a wrapper bolted on from outside — it is a trait implemented from within, enforced at every dispatch boundary, anchored at every canonicalization point.

> **Design Principle:** IronClaw may discover. ZeroPoint must decide. Canon makes it real.

---

## 1. Executive Summary

The ZeroPoint Governed Agent Runtime (GAR) is a process-level containment and governance layer that runs autonomous AI agents as managed tenants. Rather than relying on plugin contracts or cooperative hooks, the GAR enforces governance at the operating system boundary: agents operate inside controlled namespaces where every I/O surface is mediated, receipted, and policy-gated.

The first supported tenant is IronClaw from NEAR AI, a secure personal AI assistant written in Rust with defense-in-depth security, WASM-sandboxed tool execution, AES-256-GCM credential encryption, and a native governance cockpit interface. IronClaw represents a different design philosophy than the breadth-first agent frameworks: it prioritizes security architecture, sandboxed extensibility, and trait-based composability.

IronClaw was selected as first tenant for three structural reasons. First, it is already genesis-bound — the canonicalization chain exists (`rcpt-genesis → rcpt-cfg-ic → rcpt-preflight → rcpt-port → rcpt-launched → rcpt-health`), anchoring IronClaw's operational existence to the operator's genesis identity. This is not a configuration record — it is a cryptographic assertion of identity. IronClaw has a Year Zero, and every subsequent action traces back to it. Second, it shares ZP's implementation language (Rust), eliminating the process-boundary translation layer that cross-language integration demands. Third, IronClaw was designed with a `CockpitProvider` trait (`src/cockpit.rs`) explicitly intended for external governance dashboards — this is a seam built for ZP, not discovered in someone else's code.

The GAR does not replace what IronClaw is good at. It constitutionalizes it. IronClaw continues to manage tools, execute tasks, maintain workspace memory, and interact with the world. ZeroPoint decides what may persist, what may execute, what counts as a trusted capability, and what gets receipted. Canonicalization is the bridge between these roles: it transforms IronClaw's operational assets (tools, providers, skills) into governed entities with verifiable provenance, tamper-evident identity, and portable trust.

---

## 2. Problem Statement

Modern agent frameworks are converging on a common capability set: persistent memory, learned skills, tool use, browser automation, scheduled execution, and multi-agent orchestration. This creates a new category of software: the durable autonomous actor.

The governance gap is that these capabilities accrete without formal trust boundaries:

- **Memory writes are not policy-gated.** An agent can silently promote speculation into trusted fact. IronClaw's workspace system has a sanitizer scanning for prompt injection on system files (`src/workspace/mod.rs`), but writes are not receipted or classified by trust tier.
- **Skill creation is not verified.** IronClaw's skill system (`src/skills/`) allows agent-driven skill management. A learned behavior becomes trusted because it worked once.
- **Tool execution is gated but not receipted.** IronClaw's approval pipeline (`LoopOutcome::NeedApproval` in `src/agent/dispatcher.rs:30`) pauses for user consent, but decisions are not cryptographically signed or hash-linked into an audit chain.
- **Subprocess spawning is observed but not bounded.** The Docker orchestrator (`src/orchestrator/`) uses per-job bearer tokens and per-container credential grants, but these are IronClaw-internal — not anchored to an external trust authority.
- **Cost tracking is enforced but not attested.** The cost guard (`src/agent/cost_guard.rs`) enforces daily budgets and hourly rate limits, but spending is not receipted as governance evidence.
- **Nothing has canonical identity.** Tools, providers, skills, and the agent itself exist as configuration artifacts — files on disk, entries in a database, rows in a settings table. They have no cryptographic anchor to the operator's authority. A tool is trusted because it is present, not because it was recognized. A provider is used because it is configured, not because it was constituted. There is no Year Zero, no verifiable chain of authority, no way to prove that the entity running now is the same entity that was authorized then.

IronClaw specifically exhibits these patterns in a more disciplined form than most agent frameworks — it already has approval gates, credential isolation, and leak detection. This is not a criticism of IronClaw; it is a recognition that IronClaw has reached the point where its internal security controls can be elevated to governance primitives by connecting them to an external trust authority.

> **The Core Contrast:**
> IronClaw asks: *How do we make an agent that is secure by construction?*
> ZeroPoint asks: *How do we make that security provable, auditable, policy-compliant, and portable across ecosystems?*
> Canonicalization answers: *By giving every governed entity an unforgeable identity anchored to the operator's authority — so that "secure" is not a claim, but a chain.*

---

## 3. Architecture Overview

### 3.1 Integration Model

The GAR uses a **trait-based integration model** for IronClaw. Unlike the wrapper model required for foreign-language agents (see Appendix A for the Hermes wrapper architecture), IronClaw's Rust implementation allows ZP to participate as a library dependency implementing IronClaw's own governance traits.

The integration surface is the `CockpitProvider` trait (`src/cockpit.rs:48`):

```rust
#[async_trait]
pub trait CockpitProvider: Send + Sync {
    async fn snapshot(&self) -> CockpitSnapshot;
    fn subscribe(&self) -> broadcast::Receiver<CockpitEvent>;
}
```

The web gateway stores `Arc<dyn CockpitProvider>` in `GatewayState` and serves it via `/api/cockpit/snapshot` (REST) and `/api/cockpit/events` (SSE). ZP implements this trait, providing live governance data to IronClaw's own UI surface. This is governance integrated at the type level, not bolted on at the process boundary.

**Why this works where a wrapper would not:**

- **Same language.** ZP and IronClaw are both Rust. No serialization boundary, no bridge process, no subprocess-per-request spawning.
- **Trait injection.** IronClaw's architecture uses trait objects throughout (`LlmProvider`, `Database`, `Tool`, `CockpitProvider`). ZP provides implementations. The agent doesn't need to be wrapped — it needs to be composed.
- **Daemon, not CLI.** IronClaw runs as a persistent web gateway binding ports 17771/17772. It doesn't exit after one query. This is how a governed tenant should behave — stable process identity, persistent SSE streams, queryable state.

**The wrapper model is still correct for enforcement.** Even with trait-based integration, ZP remains the outer authority. IronClaw's process runs under ZP's credential injection (`.env.zp`), port allocation (from the PortAllocator), and health monitoring (reverse proxy 2xx checks). The trait integration adds *visibility*; the process boundary adds *enforcement*. Both are necessary.

### 3.1.1 MCP-Server Tenancy (parallel mode)

ZeroPoint can also expose itself as an MCP server that the agent connects to and calls as a tool. IronClaw ships a full MCP client (`src/tools/mcp/client.rs`, `auth.rs`, `config.rs`) supporting stdio and HTTP transports with OAuth and auto-reconnection. Any MCP-capable agent — IronClaw, Claude Code, Cursor, LangGraph — can connect to ZP by adding a single entry to its MCP config.

In MCP-server mode, ZP exposes governance primitives as callable tools:

- `zp.gate_tool_call(tool_name, args_hash, run_id)` → `{allow, reason}`
- `zp.memory_propose(tier, content)` → `{accepted, receipt_id}`
- `zp.skill_canonicalize(skill_id, content_hash)` → `{signed, canonicalization_anchor}`
- `zp.envelope_request(scope, ttl)` → `{envelope_jwt, expires_at}`

**MCP Apps extension.** Each governance tool declares an optional `_meta.ui.resourceUri` pointing to a `ui://` resource that renders the tool's output as interactive HTML in a sandboxed iframe. This is the MCP Apps pattern (Jan 2026, co-authored by Anthropic and OpenAI): tools that return structured data *also* declare a companion UI resource that any MCP host (Claude, ChatGPT, VS Code, Goose) can render inline. For governance, this means:

- `zp.gate_tool_call` → `ui://zp/gate-decision` renders the approval gate UI (decision rationale, receipt anchor, policy context) as an interactive panel, not a JSON blob.
- `zp.memory_propose` → `ui://zp/memory-proposal` renders the memory classification UI (content preview, tier assignment, sanitizer results) with accept/reject controls.
- `zp.skill_canonicalize` → `ui://zp/skill-verification` renders the skill verification pipeline (hash, provenance chain, quarantine status) as a step-through flow.
- `zp.envelope_request` → `ui://zp/envelope-grant` renders the capability envelope (scope, TTL, chain position) with visual trust indicators.

The `ui://` resources are self-contained HTML pages that call back to ZP's MCP server for fresh data. They are served from ZP's governance asset directory and versioned alongside the receipt schema. The iframe sandbox ensures the UI cannot escape its rendering context — governance surfaces are isolated from the agent's own UI. This is the universal distribution surface: any MCP-capable host becomes a governance dashboard without requiring IronClaw's web gateway or the full abacus visualization stack.

Architectural implications:

- **Agent-side transparency.** When the gate is a tool the agent calls, the agent *knows* it is being governed. It can plan accordingly: query the gate before attempting a risky action, request an envelope before a long-running task, propose memory writes through `zp.memory_propose` instead of writing blindly. This is the structural enforcement of Principle 7 ("Contact does not commit") — the agent's *contact* with capability happens via the gate-tool query; the *commit* happens after the gate's answer.
- **Universal adoption story.** Trait-based integration is a per-framework engineering project (albeit a clean one for Rust agents). MCP integration is a one-line config entry. The ambition that "governed becomes a property an agent runtime *implements*" (§9) is reachable in practice once ZP is reachable as an MCP endpoint.
- **Coexistence.** The two modes compose. The trait integration provides deep visibility (live snapshots, SSE event streams, type-safe governance data). MCP-server mode adds agent-aware governance planning on top. Both feed into the same receipt chain.

### 3.2 Generative UI Architecture

The emerging protocol landscape defines four complementary standards for agent-UI interaction. ZP must be shaped to all four, not committed exclusively to any one.

| Protocol | Role | ZP Status | What It Means for Governance |
|----------|------|-----------|------------------------------|
| **MCP** | Agents↔tools | Have | Governance primitives exposed as callable tools (`zp.gate_tool_call`, `zp.memory_propose`, etc.) |
| **MCP Apps** | Tools→interactive UI | Adopting | Governance tools return interactive HTML (abacus, chain explorer, approval gate) that renders in sandboxed iframes inside Claude, ChatGPT, VS Code, Goose |
| **AG-UI** | Agents↔frontends (streaming) | Have | Real-time governance events streamed to agent frontends via SSE/WebSocket |
| **A2UI** | Declarative UI-as-data | Shaping toward | Governance UI defined as structured JSON-L with a component catalog; transport-agnostic — works over MCP, AG-UI, A2A, SSE, REST |
| **A2A** | Agents↔agents | Deferred (Phase 3) | Multi-agent governance; IronClaw's Docker orchestrator handles the immediate case |

#### The Three-Layer Separation

ZP's governance UI architecture separates three concerns, aligned with A2UI's design philosophy:

**Layer 1: Data (the receipt chain).** This is ZP's canonical representation. Receipts are signed, hash-linked, timestamped structured data. The receipt chain is the source of truth. All UI representations are projections of this data — never the other way around. The chain already supports JSON Pointer (RFC 6901) addressable paths, which is the same binding mechanism A2UI uses for component↔data references.

**Layer 2: Component Catalog (`zp-governance-catalog.json`).** A JSON schema defining governance UI components: their types, property schemas, data bindings, and rendering constraints. This catalog is the contract between ZP's data layer and any frontend that wants to render governance surfaces. Components include: receipt viewer, chain explorer, approval gate, cost burn chart, wire inspector, bead detail view, tool execution timeline, and canonicalization anchor display. The catalog is inspired by A2UI's extensible component model but does not require full A2UI compliance on day one — the *shape* must be right so adoption is additive, not a rewrite.

**Layer 3: Transport Adapters.** Each adapter projects the same governance data and components through a different protocol:

- **MCP Apps adapter:** Governance tools declare `_meta.ui.resourceUri` pointing to `ui://` resources. The abacus, cockpit, and chain explorer are served as interactive HTML in sandboxed iframes. The app calls back to ZP's MCP server for fresh receipt data. This is the universal distribution surface — any MCP host (Claude, ChatGPT, VS Code, Goose) becomes a governance dashboard without IronClaw's web gateway.

- **AG-UI adapter:** Translates IronClaw's `SseEvent` variants (and ZP's own governance events) into AG-UI's 16 event types for streaming to agent frontends. This remains the real-time observation channel.

- **A2UI adapter (future):** Emits `createSurface`, `updateComponents`, `updateDataModel` messages referencing the governance catalog. Any A2UI-compatible frontend renders governance UIs from the catalog. This is the declarative middle of the generative UI spectrum — between the controlled (hand-built abacus) and open-ended (Browser Harness trick) poles.

- **IronClaw native adapter:** The `CockpitProvider` trait implementation. Serves governance data through IronClaw's own SSE/WebSocket channels. This is the tightest integration — type-safe, no translation layer.

#### The Generative UI Spectrum for Governance

The conference taxonomy (controlled → declarative → open-ended) maps directly to ZP's governance surfaces:

| Approach | ZP Implementation | Best For |
|----------|-------------------|----------|
| **Controlled** | Abacus, cockpit panels — hand-built, deterministic, pixel-perfect | Core governance surfaces where visual consistency and trust matter most |
| **Declarative** | Component catalog assembled by the agent from `zp-governance-catalog.json` | Long tail of governance UIs — custom dashboards, filtered receipt views, per-tenant monitoring. Agent picks "show me cost burn for this week" and ZP returns components from the catalog |
| **Open-ended** | Browser Harness trick — agent writes arbitrary HTML to IronClaw's project file serving directory | Novel one-off visualizations, third-party experiences, experimental governance surfaces |

In practice, ZP uses all three: controlled for the core governance surfaces, declarative for most dynamic governance queries, and open-ended for exploration and prototyping.

#### Architectural Principle: Receipts Are Canonical, Protocols Are Projections

The receipt chain is not one format among many. It is the single source of truth. AG-UI events, A2UI surfaces, MCP Apps resources, and IronClaw SSE events are all *projections* of the receipt chain into different rendering contexts. This means:

- Adding a new protocol adapter never changes the data model.
- Any governance UI can be verified against the receipt chain — the projection is auditable.
- Protocol evolution (A2UI v0.9 → v1.0, AG-UI changes, new MCP Apps features) is absorbed at the adapter layer without touching the governance core.
- The governance catalog can be served through *any* transport because it references receipt data via JSON Pointer paths, not protocol-specific payloads.

This is Principle 7 ("Contact does not commit") applied to the UI layer: contact with a rendering protocol does not commit ZP to that protocol's data model. The receipt chain commits; the protocols render.

### 3.3 Five Mediation Surfaces

Every agent framework, regardless of its internal architecture, touches the outside world through five surfaces. The GAR mediates all five:

| Surface | IronClaw Usage | ZP Mediation | Integration Point |
|---------|---------------|--------------|-------------------|
| **Model API** | 7+ providers via `LlmProvider` trait (`src/llm/`), hot-reloadable in v0.26.0 | Every inference receipted on `cognition:inference:ironclaw` wire. Token usage metered. Credentials injected from ZP vault — agent never sees raw keys. | `LlmProvider` trait boundary |
| **Filesystem** | `~/.ironclaw/workspace/` — hybrid BM25 + vector search, layer-aware persistence, project file serving | Memory writes gated and receipted. Workspace sanitizer (`src/workspace/mod.rs`) already scans for prompt injection — ZP elevates this to a governance primitive. | Workspace write path + `file` builtin tool |
| **Subprocess** | Docker orchestrator (`src/orchestrator/`), WASM sandboxed tools, shell builtin, per-job bearer tokens | Pre-dispatch gate on every tool call. Docker containers get explicit envelopes. WASM tools already run in Wasmtime sandbox with capability-based permissions. | Tool dispatch pipeline (`src/agent/dispatcher.rs`) |
| **Network** | HTTP builtin tool with SSRF protection, per-WASM-tool domain allowlisting, leak detection | Per-task domain allowlists. WASM credential injection at host boundary (`src/tools/wasm/credential_injector.rs`). | HTTP tool + WASM allowlist (`src/tools/wasm/allowlist.rs`) |
| **IPC** | SSE/WebSocket to web gateway, orchestrator↔worker container comms, MCP server communication | ZP-mediated channels for all real-time communication. Receipted at the event boundary. | `SseEvent` enum (`src/channels/web/types.rs:121`) |

### 3.4 Canonicalization

Every other governance primitive in ZeroPoint is *reactive*. The dispatch gate blocks a bad tool call. The receipt proves something happened. The quarantine holds an untrusted artifact. Canonicalization is the only primitive that is *constitutive* — it does not record what happened, it establishes what *exists*.

Before canonicalization, IronClaw is a process. A binary. A config file and a port number. After canonicalization, IronClaw is a governed identity with a Year Zero — a cryptographically anchored existence whose every subsequent action can be traced back to the moment it was constituted. The difference is the difference between "this process is running" and "this entity has been recognized by the governance authority as a legitimate participant in the trust system."

#### What Canonicalization Creates

Canonicalization is the act of anchoring an entity to the genesis identity via a signed receipt chain. The chain is the proof. The entity types that can be canonicalized are:

| Entity | Canon Receipt | What It Anchors |
|--------|--------------|-----------------|
| **System** | `system:canonicalized` | The ZeroPoint instance itself. Emitted during genesis. Year Zero. |
| **Agent** | `agent:canonicalized` | A governed tenant (IronClaw). Anchors its operational existence to the operator's genesis identity. |
| **Tool** | `tool:canonicalized` | A registered tool in the tenant's dispatch pipeline. Anchors the tool's identity to the agent that runs it. |
| **Provider** | `provider:canonicalized` | An LLM provider endpoint. Anchors the inference surface to the governance chain. |
| **Skill** | `skill:canonicalized` | A verified, signed skill artifact. Anchors learned behavior to a provenance chain. |
| **Memory tier** | `memory:canonicalized` | A classified workspace partition. Anchors trust classification to governance policy. |

Each canonicalization receipt carries a content hash of the entity at the moment of recognition, a parent reference linking it to the canonicalizing authority, and a timestamp establishing the entity's Year Zero. The chain is: `genesis → system → agent → {tools, providers, skills, memory}`. Every entity traces back to genesis. No orphans.

#### Why Canonicalization Matters

**Identity permanence.** A canonicalized entity's identity lives in the chain, not in the process. You can restart IronClaw, upgrade it from v0.19.0 to v0.26.0, migrate it to a different host — the canonical identity persists because it is anchored to the receipt chain, not to a PID or a config path. This is what makes governance durable across the lifecycle of the system, not just within a single session.

**Provenance.** Every entity can answer the question: *who authorized my existence, and when?* Not "who configured me" — configuration is a mechanical act. Canonicalization is a governance act. The operator's genesis key signs the system; the system canonicalizes the agent; the agent's governed identity anchors its tools and providers. The chain of authority is explicit, auditable, and unforgeable.

**Tamper evidence.** The content hash in the canonicalization receipt is a snapshot of the entity at the moment of recognition. If the entity changes after canonicalization — a tool binary is swapped, a provider endpoint is redirected, a skill is silently modified — the hash diverges from the on-disk reality. You don't need real-time monitoring to detect tampering; the chain itself is the evidence. Re-hash, compare, and the discrepancy announces itself.

**Downgrade resistance.** You cannot silently replace a canonicalized entity with an older, less secure version. The chain records the version at the time of canonicalization. A downgrade attempt produces a new entity with a different hash that has not been canonicalized — the governance gate rejects it because it has no canon. This is the structural enforcement of forward progress: every canonicalized entity is the *latest recognized version*, and reverting requires explicit operator action that is itself receipted.

**Trust portability.** In Phase 4 (multi-tenancy), a canonicalized skill exported from one GAR instance carries its canonicalization receipt. The receiving instance can verify the chain: was this skill proposed, quarantined, verified, signed, and activated? By whom? When? The receipt is the portable proof. Without canonicalization, trust is local — a skill is trusted because it exists in this directory on this machine. With canonicalization, trust is portable — a skill is trusted because its provenance chain is verifiable by any GAR instance that recognizes the issuing authority.

**Governance without runtime.** Canonicalization receipts exist even when the system is off. The chain can be audited cold — no running process required. An external auditor can examine the receipt chain, verify every signature, trace every entity back to genesis, and confirm the governance posture of the entire system without access to the live runtime. This is governance as data, not governance as software.

#### The Canonicalization Invariant

> **Nothing executes in a governed context without a canon.**

This is the invariant that binds canonicalization to the dispatch gate. When the governance gate evaluates a tool call, it checks: is this tool canonicalized? If not, the call is blocked — regardless of policy, regardless of approval status, regardless of the operator's preferences. Canon is the prerequisite for governance participation. An uncanonicalized entity is invisible to the trust system.

The invariant cascades:

- An uncanonicalized tool cannot be dispatched.
- An uncanonicalized provider cannot serve inference.
- An uncanonicalized skill cannot be activated.
- An uncanonicalized agent cannot emit governed receipts.

This is not policy — it is structure. Policy decides *what* a canonicalized entity may do. Canonicalization decides *whether it exists at all* in the governance domain.

#### IronClaw's Year Zero

IronClaw's canonicalization chain is already complete:

```
rcpt-genesis → rcpt-cfg-ic → rcpt-preflight → rcpt-port → rcpt-launched → rcpt-health
```

This chain establishes IronClaw's governed existence from the operator's genesis ceremony through configuration, preflight verification, port allocation, launch, and health confirmation. Every subsequent receipt IronClaw emits — tool calls, memory writes, inference requests, approval decisions — is linked to this chain. The chain is IronClaw's identity. Not its binary. Not its config. The chain.

> **Design Principle:** Configuration makes an agent run. Canonicalization makes it *exist* in the governance domain. The difference is the difference between a process and an identity.

---

## 4. Containment Model

### 4.1 Trust Source: Gate and Chain, Not Containment Layer

The first architectural commitment of the GAR is that ZeroPoint's trust guarantees come from two places: the dispatch gate and the audit chain. Neither requires kernel-level containment to function. A single-process deployment with a robust gate already enforces the substrate's claims about authority and provenance.

This is intentional and load-bearing. Containment software (Docker, OrbStack, Linux namespaces, Virtualization.framework) is a useful additional defense, but it is not where ZP's trust comes from. If the substrate's correctness depended on Docker working correctly, every Docker Desktop bug would become a ZP outage — a poor foundation for a decade-long trust system.

> **Principle:** Containment hardens the perimeter. The gate and the chain define the trust.

### 4.2 Isolation as a Continuum

Isolation is not binary. The right level depends on the threat model. From cheapest to most invasive:

| Level | Mechanism | Threat Model |
|-------|-----------|--------------|
| **1. Bare process + gate** | IronClaw runs as the operator's user. Pre-dispatch gate mediates every tool call. | Default. Threat: agent makes a wrong tool call. The gate handles this. |
| **2. Process-level constraints** | rlimits, dropped env, restricted PATH, FS write tree restrictions, subprocess caps. | Adds defense-in-depth against runaway behavior. Native, no daemon. |
| **3. Native sandbox** | macOS `sandbox-exec` profile or Linux `bubblewrap`/seccomp. IronClaw's WASM sandbox (Wasmtime) already provides Level 3 for extension tools. | Threat: agent or tool attempts FS or network access outside its scope. |
| **4. Separate machine** | IronClaw on a dedicated host, ZP on another. Network is the boundary. | Threat: host-level compromise of either side. Production posture for Sovereign Mode. |
| **5. Container or VM** | Linux namespaces, Virtualization.framework, Docker, etc. IronClaw's orchestrator already uses Docker for sandbox jobs. | Threat: multi-tenant isolation, regulated environments, full kernel separation. |

For ZP's primary threat model — *the LLM made a bad call* — Level 1 is sufficient because the gate is the actual enforcement point. IronClaw already provides Level 3 for WASM tools (Wasmtime sandbox with capability-based permissions, memory/CPU/timeout limits) and Level 5 for sandbox jobs (Docker containers with per-job bearer tokens). ZP elevates these existing mechanisms with receipt-based attestation.

### 4.3 Single-Machine Baseline (APOLLO posture)

The current reference deployment is single-machine: ZP and IronClaw both run on APOLLO (M4 Mac Mini). The dispatch gate at `POST /api/v1/gate/tool-call` is the enforcement boundary. IronClaw runs as the operator's user with ZP-injected credentials (`.env.zp`). This is the configuration we ship and harden first.

IronClaw-specific hardening already in place:

- WASM tools run in Wasmtime component model with capability-based permissions (`src/tools/wasm/capabilities.rs`)
- Credential injection at host boundary — WASM code never sees raw secret values (`src/tools/wasm/credential_injector.rs`)
- Leak detection (Aho-Corasick multi-pattern scanning) on both request and response (`src/safety/`)
- SSRF protection and DNS rebinding checks on HTTP tool (`src/tools/builtin/http.rs`)
- Per-WASM-tool domain allowlisting (`src/tools/wasm/allowlist.rs`)
- Per-WASM-tool rate limiting (`src/tools/wasm/rate_limiter.rs`)

Recommended additions at this level (Phase 2 hardening):

- Restricted PATH for the IronClaw process
- Read-only mount of the operator's home except for IronClaw's working tree
- Workspace integrity monitoring — content-hash receipts on every accepted write; periodic re-hash detects tampering
- macOS `sandbox-exec` profile (complementing IronClaw's existing WASM sandbox)

### 4.4 Production Posture: Separate Host

For Sovereign Mode, the production posture is a dedicated host running IronClaw (and only IronClaw-related processes), with ZP on the operator's primary machine. The network is the trust boundary; the operator's local Sentinel monitors it. This eliminates whole classes of host-level concerns — credential theft, FS escalation, lateral movement — without requiring container correctness.

### 4.5 Container/VM Profiles (Optional)

Container and VM containment remain available for operators whose threat model demands them. IronClaw's Docker orchestrator already manages container lifecycle for sandbox jobs — this infrastructure can be extended to run IronClaw itself under containment for regulated environments.

> **Operational caveat:** Operators choosing Level 5 should understand they are taking on operational complexity that can dwarf the substrate's own. This is a deliberate trade for stronger isolation, not a free upgrade.

---

## 5. Governance Surfaces in Detail

### 5.1 Memory Governance

IronClaw's memory system is the workspace (`src/workspace/mod.rs`, ~1,790 LOC). It provides a filesystem-like API over structured content:

```
~/.ironclaw/workspace/
├── README.md, MEMORY.md, HEARTBEAT.md (system files)
├── context/ (identity, vision, priorities)
├── daily/ (logs, YYYY-MM-DD.md)
└── projects/ (arbitrary structure)
```

Search is hybrid: full-text BM25 + semantic vector embeddings via reciprocal rank fusion. Documents are chunked (`ChunkConfig`: 512 tokens, 256 overlap) and embedded via configurable providers (NEAR AI, OpenAI, Ollama).

#### The Workspace Write Seam

Every workspace write flows through the `file` builtin tool (`src/tools/builtin/file.rs`), which is subject to the standard tool dispatch pipeline — including the approval gate. The workspace already has a `Sanitizer` scanning writes to system-prompt-injected paths (MEMORY.md, SOUL.md, etc.) using Aho-Corasick patterns and regexes; high-severity matches are rejected.

This is the governance seam. ZP intercepts at the tool dispatch boundary (not at a memory-provider plugin interface as with Hermes) and classifies the proposed write before commit.

#### Memory Classification

Every proposed memory write is classified before commit:

| Tier | Description | Policy |
|------|-------------|--------|
| **Ephemeral** | Working context, scratch, session-local | Auto-discard on session end. No receipt. |
| **Attributed Fact** | User preferences, stated facts, operator-authorized data | Typed, timestamped, policy-scoped. Receipt on create/update/delete. |
| **Procedural** | Learned workflows, skill memories, inferred patterns | Quarantined until verification pipeline passes. Receipt on promotion. |
| **Constitutional** | Delegation boundaries, prohibited inferences, persona constraints | Operator-only write. Immutable receipt. Cannot be overridden by agent. |

#### Layer-Aware Persistence

IronClaw already has a layer system (`src/workspace/layer.rs`) that detects sensitive content and redirects writes to private vs. shared layers. ZP formalizes this: the layer decision becomes a governance classification, and the redirect is receipted as a policy-driven action.

#### Read-Path Integrity

Workspace files are plaintext on disk. If a separate process can write to `~/.ironclaw/workspace/`, it can inject content that IronClaw will read back as trusted memory. Mitigations, in order of cost:

- **Detection:** content-hash receipts on every accepted write; periodic re-hash compares on-disk content against last receipted state. Tampering produces a divergence.
- **Restriction:** IronClaw runs as a user whose home directory is otherwise read-only. Combined with `sandbox-exec` (Level 3), this narrows the attack surface.
- **Encryption-at-rest:** IronClaw's `SecretsCrypto` (`src/secrets/mod.rs`) already implements AES-256-GCM with HKDF key derivation. Extending this to workspace files is architecturally natural.

### 5.2 Skill Governance

IronClaw's skill system (`src/skills/`) allows agent-driven skill management. Skills live in the workspace and are managed via skill tools. The GAR introduces a formal skill lifecycle:

- **Proposed:** IronClaw proposes a new skill via the skill tool. ZP intercepts at the tool dispatch boundary and emits an `askl-` receipt.
- **Quarantined:** The skill is held until verification. IronClaw cannot use it yet.
- **Verified:** Deterministic checks run: schema validation, policy compliance, operator review (if required).
- **Signed:** ZeroPoint signs the skill artifact with its canonicalization key.
- **Active:** The skill becomes visible to IronClaw. A canonicalization receipt anchors it on the skill wire.
- **Revoked/Superseded:** A revocation receipt removes the skill.

#### WASM Tool Governance

IronClaw's WASM extension system (`src/tools/wasm/`) provides the strongest existing sandboxing of any agent framework we've evaluated. WASM tools run in Wasmtime with:

- Capability-based permissions declared in `capabilities.json` (`src/tools/wasm/capabilities.rs`)
- Endpoint allowlisting per tool (`src/tools/wasm/allowlist.rs`)
- Credential injection at host boundary — WASM code never sees raw values (`src/tools/wasm/credential_injector.rs`)
- Leak detection on both request and response
- Rate limiting per tool (`src/tools/wasm/rate_limiter.rs`)
- Memory/CPU/timeout limits

This is already a governance model. ZP's contribution is receipting: every WASM tool installation, execution, and capability grant becomes a signed, hash-linked receipt on the tool wire. The sandbox provides containment; ZP provides attestation.

#### Adaptive Capability Quarantine

IronClaw's tool builder can dynamically create WASM tools from natural language. Any tool generated this way is quarantined as an unsigned candidate until reviewed, tested, and signed. This prevents silent mutation of the trusted execution substrate. The contract is the architectural enforcement of Principle 7 ("Contact does not commit") — the agent may *contact* a new capability to complete a task, but only operator review *commits* it as a reusable tool.

### 5.3 Execution Governance

Every tool dispatch in IronClaw is mediated through a multi-stage pipeline. The pipeline is defined in `src/agent/dispatcher.rs` and documented in `src/agent/CLAUDE.md`:

```
Tool Request
    → Schema Validation (parameters match schema)
    → Autonomy Check (allowed_tools whitelist, src/tools/autonomy.rs)
    → Approval Check (requires_approval → LoopOutcome::NeedApproval)
    → Timeout Wrapper (tool-specific timeout)
    → Execute (call tool via execute_tool_with_safety)
    → Sanitize Output (scrub secrets, escape dangerous content)
    → Return to LLM
```

This pipeline is the natural home for ZP's dispatch gate. Every stage is a receipt emission point.

#### Autonomy Denylist

IronClaw maintains a static denylist of tools that cannot run in autonomous (daemon/cron) mode (`src/tools/autonomy.rs:8-26`):

```rust
pub const AUTONOMOUS_TOOL_DENYLIST: &[&str] = &[
    "routine_create", "routine_update", "routine_delete", "routine_fire",
    "event_emit", "create_job", "job_prompt", "restart",
    "tool_install", "tool_auth", "tool_activate", "tool_remove", "tool_upgrade",
    "skill_install", "skill_remove", "secret_list", "secret_delete",
];
```

ZP elevates this from a static list to a policy-driven decision. The operator's policy determines which tools are available in which execution contexts, and every autonomy decision is receipted.

#### Approval Pipeline (Native)

IronClaw's approval system is the closest thing to a native governance primitive in any agent framework we've seen. The flow:

1. Tool declares `requires_approval` via the `Tool` trait (`src/agent/scheduler.rs`). Three levels: `Always`, `UnlessAutoApproved`, `Never`.
2. Dispatcher evaluates approval requirement. If needed, returns `LoopOutcome::NeedApproval { pending }` (`src/agent/dispatcher.rs:30`).
3. Web gateway stores `PendingApproval` in session state and emits `approval_needed` SSE event (`src/channels/web/types.rs:172`).
4. User approves or denies via WebSocket (`WsClientMessage::Approval`).
5. v0.26.0 adds persistent "always approve" decisions for the v2 engine path.

This is already a governance gate. ZP's contribution: every approval decision (allow, deny, always-approve) becomes a signed receipt. The receipt includes the tool name, parameters hash, approval context, and the identity of the approver. The receipt chain proves not just what happened, but who authorized it.

#### Docker Orchestrator

IronClaw's orchestrator (`src/orchestrator/`, ~200 LOC) manages Docker container lifecycle for sandbox jobs:

- Per-job bearer tokens
- LLM proxying through the orchestrator
- Credential grants scoped to the job
- Container isolation for untrusted execution

ZP wraps this with execution envelopes: the orchestrator requests a `ZPExecutionEnvelope` from ZP before spawning a container. The envelope specifies allowed domains, max duration, permitted action categories, and credential scope. Every container lifecycle event (spawn, health, completion) is receipted.

#### Shell Tool

IronClaw's shell tool (`src/tools/builtin/shell.rs`) provides command execution with environment scrubbing and command injection detection. This is already gated by the approval pipeline (shell requires approval by default). ZP receipts every shell execution with command hash, working directory, and exit code.

### 5.4 Model API Governance

IronClaw's `LlmProvider` trait (`src/llm/`) abstracts 7+ providers: NEAR AI, Anthropic, OpenAI, Ollama, OpenAI-compatible, AWS Bedrock, and aggregator endpoints. v0.26.0 adds hot-reload of provider configurations from settings.

The GAR mediates inference at the trait boundary:

- Every inference request is receipted on the `cognition:inference:ironclaw` wire: model, token count, cost (from `src/agent/cost_guard.rs`), conversation context hash, timestamp.
- Credential injection happens via ZP vault → `.env.zp` → IronClaw's config. The agent's `SecretsCrypto` encrypts at rest; ZP controls what gets decrypted and when.
- Token budgets are already enforced by the cost guard (`CostGuardConfig`: `max_cost_per_day_cents`, `max_actions_per_hour`). ZP receipts budget events: every `CostLimitExceeded` (daily budget or hourly rate) becomes a governance event.
- Response content is available for policy inspection via the SSE `thinking` and `response` events.

### 5.5 Reasoning Attestation and the Autoregressive Surface

The five surfaces defined in Section 3.2 are I/O boundaries — places where the agent's computation touches external state. They answer the question: *what did the agent do?* But there is a sixth concern that is not a surface in the same sense, yet may be more important than any of them: the autoregressive reasoning chain that *produces* the decisions which manifest at those surfaces.

#### Autoregression as Universal Computational Principle

If autoregressive token generation is understood not merely as a language modeling technique but as a universal computational principle — a fundamental mode of computation alongside recursion, iteration, and reduction — then the reasoning chain is not "useful provenance." It is the primary computational substrate. The tool calls, memory writes, skill proposals, and browser actions that appear at the five I/O surfaces are side effects. The autoregressive unfolding is the computation itself.

This reframes the GAR's architecture. Without reasoning attestation, the GAR governs the *side effects* of computation without governing the *computation that produces them*. It is analogous to an operating system that controls file I/O and network access but has no concept of process memory or instruction tracing.

#### Two-Layer Governance

The GAR therefore requires two governance layers, not one:

- **Enforcement layer** (five surfaces): Controls what the agent *can do*. Physically enforced by process boundaries, WASM sandbox, network proxy, and credential injection. Operates at the I/O boundary.
- **Attestation layer** (reasoning chain): Proves *why the agent did what it did*. Captures the autoregressive chain of thought and cryptographically links it to the receipts it produces.

Both are necessary. Neither is sufficient alone. Enforcement without attestation is a well-contained black box. Attestation without enforcement is a well-documented escape artist.

#### Reasoning Hash Linkage

Every receipt emitted at an I/O surface carries a `reasoning_hash` — a content-addressed reference to the chain of thought that produced the decision. The full reasoning chain is stored separately (it can be large), but the hash creates a verifiable link:

- You cannot tamper with the reasoning after the fact without invalidating the receipt.
- You cannot claim a receipt was produced by a reasoning chain it wasn't.
- You can trace any action back through the autoregressive unfolding that generated it.
- You can detect when a sequence of individually benign actions derives from a chain of thought that, taken as a whole, violates policy.

#### IronClaw's Reasoning Surface

IronClaw already streams reasoning via the `thinking` SSE event (`src/channels/web/types.rs:124`):

```rust
#[serde(rename = "thinking")]
Thinking {
    message: String,
    thread_id: Option<String>,
},
```

This provides the raw material for reasoning attestation. ZP captures the thinking stream, hashes it, and links the hash to subsequent action receipts. The `stream_chunk` event provides token-level granularity when needed.

#### The Local Model Imperative

Remote model APIs return the final output of autoregressive computation. They do not expose intermediate token probabilities, rejected continuations, or internal state. A local model running under GAR containment can expose its full generation trace.

For the same reason you would want `strace` on a contained process, you want the full token-by-token unfolding of the autoregressive computation. **If autoregression is computation, and you need to govern computation, you need access to the execution trace — not just the return value.**

The GAR distinguishes:

- **Attested inference:** Local model, full generation trace captured, reasoning hash verifiable. Highest trust tier.
- **Observed inference:** Remote API, prompt and response captured, reasoning chain opaque. Lower trust tier.
- **Unattested inference:** No reasoning capture. Not permitted in sovereign mode.

### 5.6 Routine and Autonomous Execution

IronClaw's routine engine (`src/agent/routine_engine.rs`) supports cron-based and event-based scheduled execution. The autonomy denylist (§5.3) restricts which tools are available in autonomous mode.

ZP governance for routines:

- **Schedule receipt:** `cron.scheduled` claim when a routine is created, recording trigger expression, routine content hash, and the operator session that authorized it.
- **Fire-time policy:** The operator chooses `auto-approve`, `notify-then-fire`, or `require-explicit-envelope`. The default for Sovereign Mode is `require-explicit-envelope` — autonomous executions need a signed approval before they can fire.
- **Fire receipt:** `cron.fired` claim hash-linked to the schedule receipt, opening the run's audit trace.
- **Autonomy denylist enforcement:** ZP can dynamically extend the denylist via policy, beyond IronClaw's static `AUTONOMOUS_TOOL_DENYLIST`.

### 5.7 Channel and Messaging Surface

IronClaw supports 6 channel types: CLI REPL, Web Gateway (SSE/WebSocket), HTTP webhooks, WASM channels (Telegram, Slack), Signal integration, and MCP. The web gateway (`src/channels/web/server.rs`, 3,726 LOC) is the primary interactive surface.

#### Inbound Authority

All inbound messages flow through the channel's `receive()` implementation. The web gateway authenticates via bearer token (`src/channels/web/auth.rs`) with constant-time comparison. ZP policy can restrict which channels carry full operator authority and rate-limit per sender.

#### Outbound Governance

Outbound messages flow through the channel's `send()` path. ZP applies secrets-leakage scanning on outbound content (IronClaw's leak detector already scans tool outputs — extending this to channel output is natural). Every outbound message gets a `gateway.outbound` receipt with content hash.

#### Project File Serving (the Browser Harness trick)

IronClaw's web gateway serves project files at `/projects/{project_id}/{path}` (`src/channels/web/server.rs:376-379`), behind auth, with path traversal guards and MIME type detection. This is the mechanism by which IronClaw can build and mutate its own UI:

1. Agent writes HTML via the `file` builtin tool to `~/.ironclaw/projects/cockpit/index.html`
2. Gateway serves it at `https://localhost:17771/projects/cockpit/`
3. Browser Harness points there
4. Agent mutates the file → browser refreshes → new UI

Every write flows through the tool dispatch pipeline, so it's gated and receiptable. This is a governance-native cockpit generation mechanism — the agent builds its own observation surface through governed channels.

### 5.8 SSE Event Model and AG-UI Mapping

IronClaw's `SseEvent` enum (`src/channels/web/types.rs:121-214`) defines 14 event variants streamed over SSE. The wire format is `{"type":"<variant>", ...fields}` via `#[serde(tag = "type")]`. These map to AG-UI's event model:

| IronClaw Event | AG-UI Equivalent | Governance Wire |
|---|---|---|
| `response` | `TEXT_MESSAGE_CONTENT` | `cognition:response:ironclaw` |
| `stream_chunk` | `TEXT_MESSAGE_CONTENT` (token-level) | `cognition:stream:ironclaw` |
| `thinking` | `REASONING_CONTENT` | `cognition:reasoning:ironclaw` |
| `tool_started` | `TOOL_CALL_START` | `gate:tool:start:ironclaw` |
| `tool_completed` | `TOOL_CALL_END` | `gate:tool:end:ironclaw` |
| `tool_result` | `TOOL_CALL_END` (with output) | `gate:tool:result:ironclaw` |
| `approval_needed` | No AG-UI equivalent (governance-native) | `gate:approval:ironclaw` |
| `status` | `ACTIVITY_STATUS` | `telemetry:status:ironclaw` |
| `job_started` | `RUN_STARTED` | `lifecycle:job:ironclaw` |
| `job_message` | `TEXT_MESSAGE_CONTENT` (scoped) | `cognition:job:ironclaw` |
| `auth_required` / `auth_completed` | Custom | `lifecycle:auth:ironclaw` |
| `error` | Custom | `telemetry:error:ironclaw` |
| `heartbeat` | keepalive | (not receipted) |

An AG-UI adapter is a thin translation layer, not a rewrite. IronClaw's event model is structurally aligned with AG-UI — both use typed JSON events over SSE. The adapter can be implemented as IronClaw's `/add-sse-event` skill for new events, or as an external proxy for zero-touch translation.

### 5.9 Governance Component Catalog

The governance component catalog (`zp-governance-catalog.json`) is a JSON schema defining every governance UI component that ZP can render through any transport adapter. It is the Layer 2 contract from §3.2 — the bridge between the receipt chain (Layer 1) and the transport adapters (Layer 3).

**Design shape.** The catalog follows A2UI's extensible component model: each component is a self-describing JSON object with a type identifier, property schema, data bindings, and rendering constraints. ZP does not require full A2UI compliance on day one — the schema is shaped so that adding A2UI transport is additive, not a rewrite.

**Component schema:**

```json
{
  "component": "zp:receipt-viewer",
  "version": "1.0",
  "properties": {
    "receipt_id": { "type": "string", "binding": "/receipts/{id}" },
    "show_chain": { "type": "boolean", "default": true },
    "depth": { "type": "integer", "default": 3 }
  },
  "data_bindings": {
    "receipt": { "$ref": "/receipts/{receipt_id}", "method": "GET" },
    "chain": { "$ref": "/receipts/{receipt_id}/chain?depth={depth}", "method": "GET" }
  },
  "rendering": {
    "min_width": 320,
    "preferred_width": 640,
    "interactive": true,
    "refresh": "on_event"
  }
}
```

**Data bindings use JSON Pointer (RFC 6901) paths** into the receipt chain, the same addressing mechanism A2UI uses for component↔data references. This means the same component definition works whether the transport is MCP Apps (iframe fetches `/receipts/{id}` via MCP call-back), AG-UI (receipt data pushed as event payload), A2UI (data model update references the pointer), or IronClaw native (trait method returns the struct directly).

**Catalog components (Phase 1–2):**

| Component | Type | Purpose | Data Source |
|-----------|------|---------|-------------|
| Receipt viewer | `zp:receipt-viewer` | Single receipt with hash, signature, chain position, and payload | `/receipts/{id}` |
| Chain explorer | `zp:chain-explorer` | Interactive receipt chain traversal with parent/child navigation | `/receipts/{id}/chain` |
| Approval gate | `zp:approval-gate` | Live approval decision UI with policy context and one-click approve/deny | `/gate/pending` |
| Cost burn chart | `zp:cost-burn` | Token spend over time with budget limits and per-model breakdown | `/telemetry/cost` |
| Wire inspector | `zp:wire-inspector` | Single governance wire with bead positions and receipt flow | `/wires/{wire_id}` |
| Bead detail | `zp:bead-detail` | Expanded bead view with receipt payload, provenance, and chain links | `/wires/{wire_id}/beads/{position}` |
| Tool timeline | `zp:tool-timeline` | Chronological tool execution history with gate decisions | `/gate/history` |
| Canonicalization anchor | `zp:canon-anchor` | Visual trust indicator showing canonicalization chain from genesis | `/canon/{entity_id}` |
| Memory tier view | `zp:memory-tier` | Workspace writes classified by trust tier with sanitizer results | `/memory/tiers` |
| Skill verification | `zp:skill-verification` | Skill lifecycle pipeline (proposed → quarantined → verified → active) | `/skills/{skill_id}/status` |

**Rendering constraints.** Each component declares minimum width, preferred width, whether it is interactive (accepts user input like approve/deny), and its refresh strategy (`on_event` for SSE-driven updates, `poll` for periodic refresh, `static` for one-shot). Transport adapters use these constraints to decide layout: MCP Apps iframes respect `min_width`; AG-UI frontends use `refresh: on_event` to wire SSE subscriptions; A2UI surfaces map `interactive: true` to input-capable component types.

**Versioning.** Components are versioned independently. The catalog carries a `catalog_version` and each component carries its own `version`. Transport adapters declare which catalog version they support. Breaking changes increment the component version; the adapter translates or falls back to a supported version. This follows the same principle as Principle 7 — the catalog commits to a component contract; the adapter adapts to what the transport can render.

**Extension model.** Third-party governance components can be registered in the catalog by adding entries with a namespace prefix (e.g., `tenant:custom-dashboard`). The catalog validates component schemas at registration time. This enables per-tenant governance UIs without modifying ZP's core catalog — the extension contributes components; ZP provides the data bindings and rendering infrastructure.

---

## 6. Receipt Schema

Every mediated event produces a receipt on ZeroPoint's audit chain. The GAR extends the existing receipt type system with agent-runtime-specific types:

| Receipt Type | Prefix / Claim Type | Emitted When |
|-------------|---------------------|--------------|
| AgentSessionClaim | `agsn-` | Agent process session starts/stops |
| GateAllowed | `gate.tool_call.allowed` | Pre-dispatch gate permits a tool call |
| GateBlocked | `gate.tool_call.blocked` | Pre-dispatch gate denies a tool call |
| GateApproved | `gate.approval.granted` | User approves a tool requiring approval (IronClaw-native) |
| GateDenied | `gate.approval.denied` | User denies a tool requiring approval |
| GateAlwaysApprove | `gate.approval.always` | User sets permanent auto-approve for a tool (v0.26.0) |
| MemoryProposed | `memory.proposed` | Agent proposes a workspace write |
| MemoryAccepted | `memory.accepted` | Workspace write classified and committed |
| MemoryDenied | `memory.denied` | Workspace write rejected by policy |
| MemoryQuarantined | `memory.quarantined` | Workspace write held pending verification |
| SkillProposalClaim | `askl-` | Agent creates or modifies a skill |
| SkillPromotionClaim | `apro-` | Skill passes verification and becomes active |
| WasmToolInstalled | `tool.wasm.installed` | WASM extension installed |
| WasmToolExecuted | `tool.wasm.executed` | WASM tool execution receipted (with sandbox metadata) |
| WasmToolCapabilityGrant | `tool.wasm.capability` | Capability granted to a WASM tool |
| SubprocessClaim | `asub-` | Any subprocess spawned (shell, Docker container) |
| InferenceRequestClaim | `ainf-` | Model API call, with provider, model, token count, cost |
| CostLimitClaim | `cost.limit.exceeded` | Daily budget or hourly rate limit triggered |
| ReasoningTraceClaim | `artr-` | Autoregressive generation trace stored, hash linked to action receipts |
| CapabilityQuarantineClaim | `aqrn-` | New capability artifact quarantined pending review |
| CronScheduled | `cron.scheduled` | Agent schedules an autonomous routine |
| CronFired | `cron.fired` | Routine engine fires a scheduled task |
| ChannelInbound | `channel.inbound` | Inbound message reaches IronClaw from any channel |
| ChannelOutbound | `channel.outbound` | Outbound message leaves IronClaw via any channel |
| ProjectFileWrite | `project.file.write` | Agent writes to project file serving directory |
| DockerContainerSpawn | `container.spawn` | Orchestrator spawns a Docker container for sandbox job |
| DockerContainerComplete | `container.complete` | Sandbox job container completes (with exit code) |

All receipts use the existing ZeroPoint receipt chain semantics: hash-linked, signed, timestamped, and policy-scoped. The CanonicalizedClaim type (`cano-`) from Phase 7 anchors each agent, memory tier, and skill on its own wire. The visual surface for these wires is specified in `docs/design/zp-visual-language.md` (the four lenses: Abacus, Weave, CodeFlow, Walk).

---

## 7. Implementation Phases

### Phase 1: Trait Integration and Observable Governance (MVP) — Next

**Goal:** Implement `CockpitProvider` for IronClaw. Live governance data flowing through IronClaw's own UI surface. Minimum viable governance — trust comes from the gate and the chain.

Deliverables:

- Implement `CockpitProvider` trait: `snapshot()` returns live state from agent loop, tool registry, cost guard, workspace. `subscribe()` broadcasts turn completions, tool executions, approval decisions as `CockpitEvent`s.
- Wire cockpit handlers: `/api/cockpit/snapshot` (REST) and `/api/cockpit/events` (SSE) already exist in IronClaw's web gateway (`src/channels/web/handlers/cockpit.rs`).
- AG-UI adapter: thin translation layer mapping IronClaw's `SseEvent` variants to AG-UI event types for the existing abacus visualization.
- Receipt emission at the tool dispatch boundary: every `LoopOutcome::NeedApproval`, every approval decision, every tool completion.
- MCP Apps metadata on governance tools: add `_meta.ui.resourceUri` declarations to `zp.gate_tool_call`, `zp.memory_propose`, `zp.skill_canonicalize`, and `zp.envelope_request`. Build the four `ui://zp/*` HTML resources (approval gate, memory proposal, skill verification, envelope grant) as self-contained pages that call back to ZP's MCP server for data. This makes any MCP host a governance dashboard from day one.

**Estimated effort:** ~200 LOC Rust for the `CockpitProvider` implementation, ~100 LOC for the AG-UI adapter, ~400 LOC HTML/JS for the four MCP Apps governance resources.

**Prerequisite (complete):** IronClaw upgraded from v0.19.0 to v0.26.0. Local modifications re-applied. Verified against v0.25.0 ownership model (`Owned` trait, `OwnershipCache`) and v0.25.0+ database-backed tool permissions.

### Phase 1.5: Active Governance — Gate, Receipt, and Catalog

**Goal:** Every tool dispatch, every inference call, and every workspace write produces a signed ZP receipt. IronClaw transitions from "observed" to "governed." The governance component catalog is defined and the first components are renderable through all active transport adapters.

Deliverables:

- Hook tool execution pipeline at each gate: autonomy check, approval gate, timeout, sanitize. Each is a receipt emission point.
- Hook `LlmProvider` trait boundary: receipt every inference with provider, model, tokens, cost.
- Hook workspace writes: receipt every `file` tool write with content hash, classification tier, and layer decision.
- MCP server exposure: ZP as MCP server with `zp.gate_tool_call`, `zp.memory_propose`, `zp.skill_canonicalize`, `zp.envelope_request`. IronClaw connects via MCP config.
- Cost guard integration: receipt every budget event from `CostGuard`.
- Define `zp-governance-catalog.json` (§5.9): schema for the first six governance components (receipt viewer, chain explorer, approval gate, cost burn, wire inspector, tool timeline). Each component specifies type, property schema, JSON Pointer data bindings, and rendering constraints.
- Implement catalog rendering through MCP Apps adapter: the `ui://zp/*` resources from Phase 1 now render components from the catalog rather than hand-coded HTML. The catalog is the single source of component definitions.
- Validate catalog shape against A2UI v0.9 component model: ensure component schemas, data binding paths, and rendering constraints are A2UI-compatible so that adding the A2UI adapter in Phase 2 is additive.

**Estimated effort:** ~500 LOC Rust + ~300 LOC JSON schema for the catalog.

### Phase 2: Full Cognition Plane

**Goal:** Trust chain with genesis/operator/agent key hierarchy. IronClaw signs its own receipts as a governed sub-identity. Memory governance with classified tiers. Reasoning attestation. Full governance component catalog with A2UI-compatible emission.

Deliverables:

- Agent key hierarchy: IronClaw receives a delegated signing key from ZP. Receipts are signed by the agent's own key, which chains to the operator's key, which chains to genesis.
- Memory classification: workspace writes classified into four tiers (ephemeral, attributed, procedural, constitutional). Policy-driven tier assignment.
- Reasoning attestation: `thinking` event stream captured, hashed, and linked to subsequent action receipts.
- Skill verification pipeline: proposed → quarantined → verified → signed → active → revoked.
- WASM tool governance: installation, capability grants, and execution receipted.
- Routine governance: schedule/fire receipts with policy-driven approval requirements.
- Complete governance catalog (§5.9): all ten core components defined and renderable. Extension model active — tenant-namespaced components registerable.
- A2UI adapter (experimental): emit `createSurface`, `updateComponents`, `updateDataModel` messages referencing the governance catalog. Validate against A2UI v1.0 (if released) or latest v0.9 spec.

**Estimated effort:** ~1,500 LOC Rust + ~200 LOC for A2UI adapter.

### Phase 3: Multi-Agent Orchestration

**Goal:** Governed parallel workstreams with sub-containment for sandbox jobs and delegated tasks.

- Per-container governance via IronClaw's Docker orchestrator
- Per-job receipt chains linked to parent session
- Capability envelope chains for delegated work
- Fleet dashboard showing all active agents, capability scopes, and receipt activity

### Phase 4: Portable Governance and Multi-Tenancy

**Goal:** ZeroPoint GAR runs any agent framework, not just IronClaw. Portable identity and reputation.

- Generalized agent manifest format (`agent.yaml`)
- Second tenant: Hermes Agent (see Appendix A for integration roadmap)
- Third tenant: Claude Agent SDK, OpenAI Agents SDK, or similar
- Cross-agent skill portability with receipt-preserving export/import
- Operator reputation and trust tier portability across GAR instances
- Marketplace for verified skills with provenance chains

---

## 8. Sovereign Mode Profile

The GAR ships with a hardened default configuration called Sovereign Mode:

- Built-in local memory only. No external memory providers.
- Only explicitly approved model endpoints. No aggregator routing by default.
- No third-party telemetry or analytics.
- All filesystem access rooted to approved paths.
- MCP servers allowlisted by policy. Default: none.
- WASM tools capability-scoped with endpoint allowlisting. No unrestricted network access.
- Shell tool requires approval by default (already true in IronClaw).
- All credentials injected from ZeroPoint vault via `.env.zp`. Agent's `SecretsCrypto` handles encryption-at-rest.
- Docker sandbox jobs run with scoped bearer tokens and per-container credential grants.
- Channel outbound messages scanned for secret leakage.

> **Sovereign Mode in One Sentence:** IronClaw as a front-end cognition and work engine. ZeroPoint as the sovereign control plane. No third parties in the trust path unless the operator explicitly adds them.

---

## 9. Strategic Positioning

The GAR is not an IronClaw plugin. It is an operating environment that runs IronClaw as its first supported engine. This distinction matters for six reasons:

- **The layer that doesn't exist yet.** IronClaw's security model — WASM sandbox, credential encryption, leak detection, approval gates — protects the operator from the agent's tools. None of it protects against what the agent itself can do, autonomously, over time, across sessions and platforms. That is the layer ZP adds. Nobody else has documented doing this. First-mover.

- **Canonical identity as the foundation.** Every other governance system in this space operates on configuration artifacts — tools exist because they're in a directory, providers exist because they're in a config file. ZP is the only system where every governed entity has a cryptographic identity anchored to the operator's genesis authority (§3.4). This is not a feature — it is the foundation that makes every other governance primitive trustworthy. A dispatch gate that checks policy is useful. A dispatch gate that checks policy *and* verifies the tool's canonical identity is governance. The canon is what separates ZP from "a policy engine with a receipt log."

- **Independence:** ZeroPoint does not depend on IronClaw's internal API stability. The `CockpitProvider` trait is a stable integration surface. If IronClaw's internals change, the trait implementation adapts — the governance model does not. The canonicalization chain persists across upgrades — IronClaw's identity survives version changes because it lives in the chain, not in the binary.

- **Generality:** The same five-surface mediation model applies to any agent framework. Claude Code, Cursor, Devin, Hermes — they all have filesystem, network, subprocess, model API, and IPC surfaces. Build the integration right once and IronClaw is just the first tenant. Canonicalization generalizes too: any agent that receives a delegated signing key from ZP and emits receipts against it has a canonical identity.

- **Substrate, not product:** ZP is not competing with agent frameworks. It is the layer underneath every governed deployment of every agent framework. The right analogy is the cluster of standards (cgroups, namespaces, OCI) that made containers tractable. ZP's role in agent governance is the same: a substrate other people's products run on. Canonicalization is the equivalent of an OCI image digest — the content-addressed identity that makes the entity portable, verifiable, and trustworthy regardless of where it runs.

- **Universal adoption:** The goal is universal adoption of governed alignment, not market share for a single ZP-branded runtime. The MCP-server tenancy mode (§3.1.1) means any MCP-capable agent integrates by adding a single config entry. Hermes proves the breadth; IronClaw proves the depth; ZeroPoint provides the assurance; the standard is what spreads. Canonicalization is what makes the standard meaningful — without it, "governed" is a claim. With it, "governed" is a verifiable chain.

> **The standards play:** The integration interfaces (cockpit provider, execution envelope, skill receipt, capability quarantine) are the contract. The dispatch gate, audit chain, canonicalization authority, and MCP governance tools are the enforcement. Both are open. The ambition is that "governed" becomes a property an agent runtime *implements*, the way "encrypted" became a property a transport implements — and ZP defines what governance means by being the first credible reference. Canonicalization is the verb. The receipt chain is the proof. The standard is the invitation.

---

## 10. Risk Register

| Risk | Severity | Mitigation |
|------|----------|------------|
| WASM tool builder creates capabilities that outpace verification | **HIGH** | Capability quarantine is mandatory. No bypass path. Dynamically-generated WASM tools are quarantined until signed by ZP. |
| Workspace files are plaintext on disk at Level 1 | **HIGH** | Content-hash receipts on every accepted write; periodic re-hash detects tampering. IronClaw's `SecretsCrypto` can be extended to workspace encryption. |
| IronClaw discovers new I/O channels | MEDIUM | Default-deny egress at the proxy. Periodic IronClaw release audits to map new surfaces. The tool dispatch pipeline already covers tool-class additions. |
| IronClaw v0.25.0+ ownership model changes break governance integration | MEDIUM | Align with `Owned` trait pattern and `OwnershipCache` before building governance on top. Upgrade is a prerequisite, not a deferred task. |
| Container correctness fragility on macOS | MEDIUM | Single-machine baseline (Level 1) does not depend on container tooling. IronClaw's WASM sandbox provides Level 3 for extensions without Docker. |
| "Always approve" persistence (v0.26.0) creates ungoverned tool execution | MEDIUM | ZP receipts every always-approve decision. Policy can override: sovereign mode disables always-approve for high-risk tools. |
| Cost guard operates in-process without external verification | MEDIUM | ZP receipts cost events and maintains independent token accounting. Discrepancies trigger alerts. |
| Hot-reload of LLM provider configs (v0.26.0) changes governance surface at runtime | MEDIUM | Provider changes receipted. Policy can require re-attestation after provider hot-reload. |
| Community adoption friction | MEDIUM | MCP-server mode available for agents that want receipts without trait integration. Gradual ramp. |
| macOS-only deployment limits Phase 4 portability | LOW | Linux containment profiles preserved as Level 5; IronClaw supports both PostgreSQL and libSQL backends. |

---

## 11. Structural Advantages (IronClaw-Specific)

These are places where IronClaw's architecture aligns with ZP's governance model by design rather than by retrofit. They are *non-work* — integration surface that exists without ZP having to build it.

| Advantage | IronClaw Asset | What ZP Avoids Building |
|---|---|---|
| **Governance trait** | `CockpitProvider` trait with `snapshot()` + `subscribe()` methods (`src/cockpit.rs`) | The entire governance dashboard integration surface. IronClaw built it for us. |
| **SSE event pipeline** | 14-variant `SseEvent` enum with typed JSON wire format (`src/channels/web/types.rs`) | Real-time event streaming infrastructure. Already serves `/api/cockpit/events`. |
| **Approval pipeline** | `LoopOutcome::NeedApproval` + `approval_needed` SSE event + WebSocket approval/deny | The hardest governance primitive — pausing agent execution for human review. Already works. |
| **Credential isolation** | AES-256-GCM + HKDF key derivation + WASM credential injection + leak detection | The entire credential security stack. ZP provides the vault; IronClaw handles the crypto. |
| **WASM sandbox** | Wasmtime component model with capability-based permissions | Level 3 isolation for extension tools without containers. |
| **Autonomy denylist** | `AUTONOMOUS_TOOL_DENYLIST` in `src/tools/autonomy.rs` | Static policy enforcement for autonomous execution. ZP extends it dynamically. |
| **Cost tracking** | `CostGuard` with daily budget + hourly rate limiting (`src/agent/cost_guard.rs`) | Token accounting and budget enforcement. ZP receipts what IronClaw already tracks. |
| **Tool dispatch pipeline** | Schema validation → autonomy → approval → timeout → execute → sanitize | Every governance hook point, in order, already wired. |
| **Project file serving** | `/projects/{project_id}/{path}` with auth + path traversal guards | The Browser Harness trick — agent-built UI through governed channels. |
| **Safety layer** | `ironclaw_safety` crate + `src/safety/` — prompt injection detection, content sanitization, policy rules with severity levels | Defense-in-depth that *aligns* with ZP rather than competing. |
| **Same language** | Rust throughout | No bridge process, no serialization boundary, no subprocess-per-request. Type-safe governance. |
| **Genesis-bound** | Receipt chain already exists: `rcpt-genesis → rcpt-cfg-ic → rcpt-preflight → rcpt-port → rcpt-launched → rcpt-health` | Canonicalization is done. Year Zero exists. |

The thrust: ZP's value-add is policy, signing, and the receipt chain. The mechanical plumbing (approval gates, sandboxing, credential isolation, event streaming, cost tracking) is already there. Building governance "on top of" IronClaw's existing architecture is not a retrofit — it's activating hooks that were designed to be connected.

---

## Appendix A: Hermes Agent Integration Roadmap (Second Tenant)

The full Hermes analysis from revision 1.2 is preserved here as the roadmap for Phase 4 multi-tenancy. Hermes (510k LOC Python, 95k stars, 61 tools, 15+ messaging platforms) represents the breadth case — governance of a complex, multi-subsystem agent with competing memory backends, its own credential management, and a one-shot CLI execution model.

Key differences from the IronClaw integration:

- **Wrapper model required.** Hermes is Python. The integration crosses a language boundary via subprocess + HTTP bridge. The AG-UI bridge (`services/hermes-bridge/bridge.py`) spawns Hermes per-request and translates stdout to AG-UI events.
- **Competing subsystems.** Hermes has its own OAuth, its own memory provider system (8 backends), its own skill hub with supply-chain risk, its own cron scheduler, its own 15+ messaging gateways. Each competes with ZP's equivalent and must be wrapped or replaced.
- **Memory seam is a plugin interface.** Hermes's `MemoryManager.on_memory_write` at `agent/memory_manager.py:315-329`, registered via `add_provider()` at `:97`. ZP registers as exclusive memory provider (`kind: exclusive` at `hermes_cli/plugins.py:158`).
- **Pre-dispatch gate is a plugin hook.** `pre_tool_call` fires for every tool dispatch including `code_execute` Python sandbox RPC and `delegate_task` child agents (verified against source — both traverse the hook).
- **Six governance gaps require Hermes upstream contributions:** terminal backend awareness, cron fire-time governance, gateway inbound/outbound governance, memory read-path hook.
- **Ten piggyback opportunities** where Hermes infrastructure avoids ZP re-implementation: prompt-injection scanning, session log replay, MCP client transport, skill provenance lockfile, memory provider plugin kind, process-global plugin singleton, session origin metadata, gateway message metadata, terminal session ID, routing signature metadata.

The full details — file:line citations, seam analysis, coverage verification, and implementation phases — are preserved in git history (revision 1.2, commit date 2026-04-24).

---

> *Nobody puts ZP in the corner.*

*Trust is infrastructure.*

---

**Companion specs (internal):**
- `docs/design/ironclaw-pivot-briefing.md` — strategic rationale for the tenant pivot
- `docs/design/zp-visual-language.md` — the abacus / weave / codeflow / walk lenses for the observation surface
- `docs/ARCHITECTURE-2026-04.md` — substrate operating spec (Part V½ design principles, including Principle 7: "Contact does not commit")
- `docs/future-work/cognitive-accountability.md` — the three-layer accountability stack and the trace layer this work precedes

**External sources:**
- [IronClaw Repository](https://github.com/nearai/ironclaw)
- [IronClaw v0.26.0 Release](https://github.com/nearai/ironclaw/releases/tag/ironclaw-v0.26.0)
- [IronClaw Web Gateway — DeepWiki](https://deepwiki.com/nearai/ironclaw/4.2-web-gateway)
- [AG-UI Protocol](https://docs.ag-ui.com/introduction)
- [MCP Apps Specification](https://modelcontextprotocol.io/specification/2025-06-18/server/utilities/mcp-apps) — interactive UI resources for MCP tools (Anthropic + OpenAI, Jan 2026)
- [A2UI Protocol](https://google.github.io/A2UI/) — Agent-to-User Interface, declarative UI-as-data (Google, v0.9)
- [A2A Protocol](https://google.github.io/A2A/) — Agent-to-Agent Protocol (Google)
- [Hermes Agent Repository](https://github.com/NousResearch/hermes-agent) (Second Tenant)
