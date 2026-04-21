# ZEROPOINT — Governed Agent Runtime

## Architecture Specification

**ThinkStream Labs** · April 2026 · Revision 1.0
**Document:** ZP-GAR-SPEC-001 · **Classification:** Internal / Strategic
**First Tenant:** Hermes Agent (Nous Research)
**Roadmap position:** Phase 4 of the ZeroPoint architecture (`docs/ARCHITECTURE-2026-04.md`)
**Precursor to:** Cognitive accountability layer (`docs/future-work/cognitive-accountability.md`)

---

> **Core Thesis:** ZeroPoint is the runtime, not the accessory. Agent frameworks like Hermes provide discovery and continuity. ZeroPoint provides provenance, bounded authority, and portable governance. The wrapper architecture enforces this at the process boundary — governance is physical, not contractual.

> **Design Principle:** Hermes may discover. ZeroPoint must decide.

---

## 1. Executive Summary

The ZeroPoint Governed Agent Runtime (GAR) is a process-level containment and governance layer that runs autonomous AI agents as managed tenants. Rather than relying on plugin contracts or cooperative hooks, the GAR enforces governance at the operating system boundary: agents operate inside controlled namespaces where every I/O surface is mediated, receipted, and policy-gated.

The first supported tenant is Hermes Agent from Nous Research, a self-improving agent framework with persistent memory, autonomous skill creation, browser automation via Browser Harness, and multi-agent subprocess orchestration. Hermes represents the leading edge of persistent agent capability, with over 106,000 GitHub stars and an architecture explicitly designed for long-lived, cross-session operation.

The GAR does not replace what Hermes is good at. It constitutionalizes it. Hermes continues to discover patterns, propose skills, manage continuity, and interact with the world. ZeroPoint decides what may persist, what may execute, what counts as a trusted capability, and what gets receipted.

---

## 2. Problem Statement

Modern agent frameworks are converging on a common capability set: persistent memory, learned skills, tool use, browser automation, scheduled execution, and multi-agent orchestration. This creates a new category of software: the durable autonomous actor.

The governance gap is that these capabilities accrete without formal trust boundaries:

- **Memory writes are not policy-gated.** An agent can silently promote speculation into trusted fact.
- **Skill creation is not verified.** A learned behavior becomes trusted because it worked once.
- **Browser actions are not bounded.** Self-healing execution can extend the operational surface mid-task.
- **Subprocess spawning is not receipted.** Parallel workers can act without attestation.
- **Third-party integrations blur data boundaries.** Memory providers like Honcho can transmit conversation data to external services without clear operator disclosure.

Hermes specifically exhibits all five patterns. Its documentation explicitly markets persistent memory, self-improving skills, Browser Harness integration, subagent spawning, and pluggable memory providers as core features. This is not a criticism of Hermes; it is a recognition that Hermes has reached the frontier where governance becomes structurally necessary.

> **The Core Contrast:**
> Hermes asks: *How do we make an agent that grows with you?*
> ZeroPoint asks: *How do we make that growth provable, bounded, policy-compliant, and portable across ecosystems?*

---

## 3. Architecture Overview

### 3.1 Wrapper Model

The GAR uses a wrapper architecture, not a plugin model. ZeroPoint is the outer process that spawns, contains, and mediates the agent. This is the only architecture where governance is enforced rather than hoped for.

**Alternatives considered and rejected:**

- **Plugin model:** ZeroPoint implements Hermes plugin interfaces (memory provider, tool hooks). Rejected because the host agent controls the lifecycle and can bypass the plugin. Governance depends on the agent honoring its own contracts.

- **Sidecar model:** ZeroPoint runs alongside as an observer with advisory gates. Useful for Phase 0 auditing but insufficient for enforcement. Advisory gates can be ignored without filesystem control.

- **Wrapper model (selected):** ZeroPoint owns the process boundary. The agent cannot reach the outside world except through ZP-controlled channels. Governance is physical, enforced by the kernel.

### 3.2 Five Mediation Surfaces

Every agent framework, regardless of its internal architecture, touches the outside world through five surfaces. The GAR mediates all five:

| Surface | Hermes Usage | ZP Mediation |
|---------|-------------|--------------|
| **Model API** | OpenRouter, Anthropic, OpenAI, local models | HTTP proxy with allowlisted endpoints. Every inference request/response receipted. Token usage metered. |
| **Filesystem** | ~/.hermes/memory/, ~/.hermes/skills/, session logs, config | Overlay filesystem. Reads pass through; writes gated, classified, and receipted before commit. |
| **Subprocess** | Browser Harness, git worktrees, shell commands, child Hermes instances | Controlled exec path. Every spawn requires capability token. Output captured and receipted. |
| **Network** | Browser Harness web access, webhooks, MCP servers, scheduled tasks | Network namespace. Only ZP proxy reachable. Per-task domain allowlists for browser. |
| **IPC** | Hermes-to-Browser Harness via WebSocket/stdio, parent-child agent comms | ZP is parent of both processes. All IPC routes through ZP-controlled channels. |

---

## 4. Containment Model

### 4.1 Linux Namespace Isolation

The primary deployment target is a Linux VPS, which aligns with how the Hermes community already deploys (the reference tutorial recommends VPS deployment for 24/7 operation). The GAR uses three Linux kernel mechanisms for containment:

#### Mount Namespace + Overlay Filesystem

Hermes sees a virtual filesystem where its home directory (~/.hermes/) is an overlay mount. The lower layer is a ZP-managed read-only snapshot of approved state. The upper layer captures all Hermes writes. ZeroPoint periodically reviews the upper layer, classifies changes (memory, skill, config, artifact), applies policy, and either commits approved changes to the lower layer or quarantines them.

- Memory writes are classified into four tiers: ephemeral working context (discardable), user facts/preferences (typed, timestamped, policy-scoped), procedural skill memories (verification-required), and operational receipts (immutable).
- Skill file writes trigger the skill verification pipeline before becoming active.
- Config file writes are logged but generally passed through (the operator controls config).

#### Network Namespace

Hermes runs in an isolated network namespace where the only reachable endpoint is ZeroPoint's local proxy. All outbound connections are mediated:

- **Model API calls:** Proxied to operator-approved endpoints only. No OpenRouter by default; the operator explicitly configures which model providers are reachable.
- **Browser Harness traffic:** Per-task domain allowlists. The browser can only reach domains specified in the task's capability envelope.
- **All other egress:** Denied by default. MCP servers, webhooks, and external services must be explicitly allowlisted in policy.

#### PID Namespace

Hermes runs in its own PID namespace. It can see and manage its own subprocesses (Browser Harness, git operations, child agents) but cannot observe or signal processes outside its containment. ZeroPoint, as the parent process in the host namespace, can observe and manage all contained processes.

### 4.2 macOS Deployment

macOS does not support Linux namespaces. Two alternative containment strategies are available:

- **Virtualization.framework:** Run the GAR inside a lightweight Linux VM on Apple Silicon. Near-native performance with full namespace support. Preferred for development.
- **sandbox-exec profiles:** macOS sandbox profiles can restrict filesystem access and network egress. Less granular than namespaces but sufficient for cooperative containment.

---

## 5. Governance Surfaces in Detail

### 5.1 Memory Governance

Hermes persistence currently uses MEMORY.md, USER.md, and SQLite FTS5 for session search, with optional pluggable memory providers (Honcho, ByteRover, agentmemory). The GAR replaces all external memory backends and interposes on the built-in persistence.

#### Memory Classification

Every memory write is classified before commit:

| Tier | Description | Policy |
|------|-------------|--------|
| **Ephemeral** | Working context, scratch, session-local | Auto-discard on session end. No receipt. |
| **Attributed Fact** | User preferences, stated facts, operator-authorized data | Typed, timestamped, policy-scoped. Receipt on create/update/delete. |
| **Procedural** | Learned workflows, skill memories, inferred patterns | Quarantined until verification pipeline passes. Receipt on promotion. |
| **Constitutional** | Delegation boundaries, prohibited inferences, persona constraints | Operator-only write. Immutable receipt. Cannot be overridden by agent. |

#### Honcho and Third-Party Elimination

The GAR's sovereign mode disables all external memory providers by default. Hermes's pluggable memory system (v0.7.0+) makes this straightforward: the GAR simply does not make external provider endpoints reachable from within the network namespace. Hermes falls back to its built-in local persistence, which the overlay filesystem captures and governs.

### 5.2 Skill Governance

Hermes's self-improving skill system creates and refines domain skills from experience. Skills live in ~/.hermes/skills/ and are managed via the skill_manage tool. In ungoverned Hermes, a skill becomes trusted simply because it was created. The GAR introduces a formal skill lifecycle:

- **Proposed:** Hermes writes a new skill file to the overlay upper layer. ZeroPoint detects the write.
- **Quarantined:** The skill is held in the overlay, not committed to the approved lower layer. Hermes cannot use it yet.
- **Verified:** Deterministic checks run: schema validation, policy compliance, test harness (if available), operator review (if required).
- **Signed:** ZeroPoint signs the skill artifact with its canonicalization key and commits it to the lower layer.
- **Active:** The skill appears in Hermes's visible filesystem. A canonicalization receipt anchors it on the skill wire.
- **Revoked/Superseded:** A revocation receipt removes the skill from the approved layer. Hermes can no longer see or use it.

> **Adaptive Capability Quarantine:** Browser Harness can create new DOM helpers and workarounds mid-task (self-healing). These are new operational capabilities, not just adaptive uses of existing ones. Any browser-side artifact generated during self-healing is quarantined as an unsigned candidate until reviewed, tested, and signed. This prevents silent mutation of the trusted execution substrate.

### 5.3 Execution Governance

Every subprocess Hermes spawns requires a capability envelope from ZeroPoint:

#### Browser Harness Sessions

- Hermes proposes a browser task with a natural-language objective.
- ZeroPoint issues a BrowserExecutionEnvelope specifying: allowed domains, max duration, permitted action categories (read-only, form-fill, transaction), and whether self-healing artifacts should be quarantined or auto-approved.
- Browser Harness operates within the envelope. Domain violations are blocked at the network proxy.
- Every browser action chain is receipted: navigation, DOM interaction, data extraction, and any new helper created.
- On completion, extracted data is classified before promotion to memory.

#### Git Worktree Operations

- Hermes proposes a coding task. ZeroPoint mints a TaskReceipt and allocates a worktree.
- All edits occur inside the isolated branch/worktree.
- Deterministic validation runs: linting, tests, policy checks.
- ZeroPoint signs the result and either merges, rejects, or requests revision.
- The worktree becomes an attested construction bay, not an unmonitored sandbox.

#### Subagent Spawning

Hermes can spawn child Hermes instances for parallel work. In the GAR:

- Each child agent runs in its own sub-containment with its own overlay and capability scope.
- Subagents inherit a subset of the parent's permissions, never more.
- Parent-child communication is receipted at the IPC boundary.
- Subagent memory is isolated (Hermes already does skip_memory=True for subagents).

### 5.4 Model API Governance

The GAR's HTTP proxy mediates all inference traffic:

- Operator configures allowed model endpoints (Anthropic, OpenAI, local Ollama, etc.). No OpenRouter by default.
- Every inference request is logged: model, token count, conversation context hash, timestamp.
- Response content is available for policy inspection (content filtering, PII detection).
- Token budgets can be enforced per-task, per-session, or per-agent.
- Credential injection happens at the proxy. Hermes never sees raw API keys; the proxy injects them from ZeroPoint's vault.

### 5.5 Reasoning Attestation and the Autoregressive Surface

The five surfaces defined in Section 3.2 are I/O boundaries — places where the agent's computation touches external state. They answer the question: *what did the agent do?* But there is a sixth concern that is not a surface in the same sense, yet may be more important than any of them: the autoregressive reasoning chain that *produces* the decisions which manifest at those surfaces.

#### Autoregression as Universal Computational Principle

If autoregressive token generation is understood not merely as a language modeling technique but as a universal computational principle — a fundamental mode of computation alongside recursion, iteration, and reduction — then the reasoning chain is not "useful provenance." It is the primary computational substrate. The tool calls, memory writes, skill proposals, and browser actions that appear at the five I/O surfaces are side effects. The autoregressive unfolding is the computation itself.

This reframes the GAR's architecture. Without reasoning attestation, the GAR governs the *side effects* of computation without governing the *computation that produces them*. It is analogous to an operating system that controls file I/O and network access but has no concept of process memory or instruction tracing. You can contain what the process touches, but you cannot reason about what it is doing or intending to do.

#### Two-Layer Governance

The GAR therefore requires two governance layers, not one:

- **Enforcement layer** (five surfaces): Controls what the agent *can do*. Physically enforced by kernel namespaces, overlay filesystem, and network proxy. Operates at the I/O boundary.

- **Attestation layer** (reasoning chain): Proves *why the agent did what it did*. Captures the autoregressive chain of thought and cryptographically links it to the receipts it produces. Operates around the computation that generates decisions.

Both are necessary. Neither is sufficient alone. Enforcement without attestation is a well-contained black box. Attestation without enforcement is a well-documented escape artist.

#### Reasoning Hash Linkage

Every receipt emitted at an I/O surface carries a `reasoning_hash` — a content-addressed reference to the chain of thought that produced the decision. The full reasoning chain is stored separately (it can be large), but the hash creates a verifiable link:

- You cannot tamper with the reasoning after the fact without invalidating the receipt.
- You cannot claim a receipt was produced by a reasoning chain it wasn't.
- You can trace any action back through the autoregressive unfolding that generated it.
- You can detect when a sequence of individually benign actions derives from a chain of thought that, taken as a whole, violates policy.

This provides **causal provenance across the autoregressive boundary** — not just "what happened" but "what computation produced what happened."

#### The Local Model Imperative

This section has a direct architectural consequence: remote model APIs become a governance limitation, not just a cost tradeoff.

A remote API (Anthropic, OpenAI, OpenRouter) returns the final output of autoregressive computation. It does not expose the intermediate token probabilities, rejected continuations, or internal state. You are trusting the provider's output to faithfully represent the computation, with no ability to independently verify.

A local model running under GAR containment can expose its full generation trace: every token, its probability distribution, the context window state at each step, and the full chain of thought including any reasoning tokens that were generated but not surfaced in the final output.

For the same reason you would want `strace` or `ptrace` on a contained process, you want the full token-by-token unfolding of the autoregressive computation. **If autoregression is computation, and you need to govern computation, you need access to the execution trace — not just the return value.**

This does not mean remote APIs are prohibited. It means the GAR should distinguish between:

- **Attested inference:** Local model, full generation trace captured, reasoning hash verifiable. Highest trust tier.
- **Observed inference:** Remote API, prompt and response captured, reasoning chain opaque. Lower trust tier. Suitable for non-critical tasks.
- **Unattested inference:** No reasoning capture. Not permitted in sovereign mode.

The operator's policy determines which trust tier is required for which categories of action.

---

## 6. Receipt Schema

Every mediated event produces a receipt on ZeroPoint's audit chain. The GAR extends the existing receipt type system with agent-runtime-specific types:

| Receipt Type | Prefix | Emitted When |
|-------------|--------|--------------|
| AgentSessionClaim | `agsn-` | Agent container starts/stops |
| MemoryWriteClaim | `amem-` | Any memory file created, updated, or deleted |
| SkillProposalClaim | `askl-` | Agent creates or modifies a skill file |
| SkillPromotionClaim | `apro-` | Skill passes verification and becomes active |
| BrowserSessionClaim | `abro-` | Browser Harness session starts, with envelope details |
| BrowserActionClaim | `abra-` | Individual browser action chain receipted |
| SubprocessClaim | `asub-` | Any subprocess spawned (git, shell, child agent) |
| InferenceRequestClaim | `ainf-` | Model API call proxied |
| WorktreeResultClaim | `awtr-` | Coding task in worktree completed or abandoned |
| CapabilityQuarantineClaim | `aqrn-` | New capability artifact quarantined pending review |
| ReasoningTraceClaim | `artr-` | Autoregressive generation trace stored, hash linked to action receipts |

All receipts use the existing ZeroPoint receipt chain semantics: hash-linked, signed, timestamped, and policy-scoped. The CanonicalizedClaim type (`cano-`) from Phase 7 anchors each agent, memory tier, and skill on its own wire.

---

## 7. Implementation Phases

### Phase 1: Contained Execution (MVP)

**Goal:** Run Hermes inside a ZeroPoint-managed Linux container with all five surfaces mediated. Minimum viable governance.

- Linux namespace containment (mount, network, PID)
- Overlay filesystem for ~/.hermes/ with write capture
- HTTP proxy for model API calls with endpoint allowlist
- Network proxy with default-deny egress
- Receipt emission for session start/stop, memory writes, and subprocess spawns
- CLI: `zp agent start hermes`, `zp agent status`, `zp agent logs`

### Phase 2: Skill and Memory Governance

**Goal:** Classified memory tiers, skill verification pipeline, and Browser Harness execution envelopes.

- Memory write classification (ephemeral, attributed, procedural, constitutional)
- Skill lifecycle: proposed → quarantined → verified → signed → active → revoked
- BrowserExecutionEnvelope with per-task domain allowlists
- Adaptive Capability Quarantine for self-healing artifacts
- Canonicalization receipts for each skill and memory entity

### Phase 3: Multi-Agent Orchestration

**Goal:** Governed parallel workstreams with sub-containment for child agents.

- Per-subagent containment with inherited/scoped permissions
- Worktree-as-construction-bay pattern with attested merge
- Parent-child IPC receipting
- Task delegation receipts with capability envelope chains
- Fleet dashboard showing all active agents, their capability scopes, and receipt activity

### Phase 4: Portable Governance

**Goal:** ZeroPoint GAR runs any agent framework, not just Hermes. Portable identity and reputation.

- Generalized agent manifest format (agent.yaml describing I/O surfaces and capability requirements)
- Second tenant: Claude Code, Cursor, or Devin running under GAR
- Cross-agent skill portability with receipt-preserving export/import
- Operator reputation and trust tier portability across GAR instances
- Marketplace for verified skills with provenance chains

---

## 8. Sovereign Mode Profile

The GAR ships with a hardened default configuration called Sovereign Mode. This is the recommended deployment profile for security-sensitive operations:

- Built-in local memory only. No Honcho, ByteRover, or external memory providers.
- No OpenRouter. Only explicitly approved model endpoints.
- No third-party telemetry or analytics.
- All filesystem access rooted to approved paths.
- MCP servers allowlisted by policy. Default: none.
- Tools capability-scoped. No unrestricted shell access.
- No remote messaging gateways unless mediated by ZeroPoint policy.
- No skill install/publish except through signed ZP channels.
- Browser Harness attached to a local hardened Chromium instance under policy scope.
- All credentials injected from ZeroPoint vault. Agent never sees raw secrets.

> **Sovereign Mode in One Sentence:** Hermes as a front-end cognition and work engine. ZeroPoint as the sovereign control plane. No third parties in the trust path unless the operator explicitly adds them.

---

## 9. Strategic Positioning

The GAR is not a Hermes plugin. It is an operating environment that runs Hermes as its first supported engine. This distinction matters for three reasons:

- **Independence:** ZeroPoint does not depend on Hermes's plugin API stability. If Hermes changes its interfaces, the wrapper adapts at the containment boundary, not inside the agent.

- **Generality:** The same five-surface mediation model applies to any agent framework. Claude Code, Cursor, Devin, Codex — they all have filesystem, network, subprocess, model API, and IPC surfaces. Build the wrapper right once and Hermes is just the first tenant.

- **Market position:** ZeroPoint is not one of many Hermes add-ons. It is the governed agent runtime layer that the entire ecosystem needs. Hermes proves the demand; ZeroPoint provides the assurance.

---

## 10. Risk Register

| Risk | Severity | Mitigation |
|------|----------|------------|
| Self-improvement outpaces verification | **HIGH** | Skill quarantine is mandatory, not advisory. No bypass path exists in the overlay. |
| Hermes discovers new I/O channels | MEDIUM | Network namespace blocks all undiscovered egress. Periodic Hermes release audits to map new surfaces. |
| Overlay performance overhead | LOW | OverlayFS is kernel-native, near-zero overhead for reads. Write batching amortizes commit cost. |
| macOS containment weaker than Linux | MEDIUM | Recommend Virtualization.framework for production macOS. sandbox-exec for development only. |
| Community adoption friction | MEDIUM | Phase 0 sidecar mode available for users who want receipts without containment. Gradual ramp. |
| Agent circumvents proxy via DNS | LOW | Network namespace has no external DNS. All resolution goes through ZP proxy. |

---

> *Nobody puts ZP in the corner.*

*Trust is infrastructure.*

---

**Sources:**
- [Hermes Agent Repository](https://github.com/NousResearch/hermes-agent)
- [Hermes Agent v0.7.0 Release Notes](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.4.3)
- [Hermes Configuration Reference](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/configuration.md)
- [Hermes Browser Automation Docs](https://hermes-agent.nousresearch.com/docs/user-guide/features/browser)
- [Browser Harness Repository](https://github.com/browser-use/browser-harness)
- [Hermes Security Model](https://github.com/mudrii/hermes-agent-docs/blob/main/security.md)
- [Hermes Skills Architecture](https://github.com/mudrii/hermes-agent-docs/blob/main/skills.md)
