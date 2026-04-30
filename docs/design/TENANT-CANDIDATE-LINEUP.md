# ZeroPoint Tenant Candidate Lineup

**Date:** 2026-04-25
**Purpose:** Assessment of agent frameworks, runtimes, and infrastructure layers as potential GAR tenants or ZeroPoint integration targets. Each candidate is evaluated on: what it does, its current governance posture, what ZeroPoint adds, integration surface, and adoption.

This is a living document. Candidates move, merge, and die. Update as the landscape shifts.

---

## Competitive Context: Read This First

Before the tenant lineup, two developments that reshape the field as of April 2026:

### Microsoft Agent Governance Toolkit (released April 2, 2026)

This is a direct competitor. Microsoft released an open-source (MIT) governance toolkit that explicitly covers all 10 OWASP Agentic AI Top 10 risks. Seven packages: Agent OS (policy engine, <0.1ms p99), Agent Mesh (DID-based identity, Ed25519, IATP protocol), Agent Runtime (execution rings), Agent SRE (circuit breakers, SLOs), Agent Compliance (EU AI Act, HIPAA, SOC2 mapping), Agent Marketplace (Ed25519 plugin signing), Agent Lightning (RL training governance). Multi-language: Python, Rust, TypeScript, Go, .NET. Integrates with LangChain, CrewAI, OpenAI Agents SDK, LangGraph, PydanticAI, Microsoft Agent Framework, Haystack, and Google ADK.

**What they got right:** Framework-agnostic design, Ed25519 signatures, execution rings, trust scoring (0–1000 dynamic scale), OWASP coverage as a first-class goal, stateless policy engine.

**What they're missing (ZeroPoint's differentiation):**
- **No receipt chain.** Policy decisions are enforced but not chain-linked. There is no hash-linked, immutable governance history. No cold auditability. Governance exists while the toolkit is running — turn it off and the governance disappears. This is governance-as-software, not governance-as-data.
- **No canonicalization.** Entities are assumed to exist and then governed. There is no constitutive act — no moment where the operator cryptographically commits to an entity's existence.
- **No trajectory.** Trust scoring is dynamic (good) but state-based (a score at a moment), not trajectory-based (the full history of how trust was earned, narrowed, and delegated). The score tells you where you are; the chain tells you how you got there.
- **No governance without runtime.** This is the critical gap. Their compliance module grades the system while it's running. Hand an auditor the artifacts and ask them to verify cold — they can't. They need the toolkit running, the policies loaded, the scoring engine active. ZeroPoint's chain file and a verifier binary is all an auditor needs.
- **Platform dependency.** The "stateless" claim is about horizontal scaling, not about independence from infrastructure. The toolkit runs on Azure App Service, requires container orchestration, depends on runtime services. ZeroPoint's governance is a file.

**Strategic read:** Microsoft's toolkit validates the market (governance for autonomous agents is now a recognized need) and sets the baseline (OWASP coverage, framework integration, policy enforcement). ZeroPoint's differentiation is everything above the baseline: the receipt chain, canonicalization, cold auditability, governance-as-data. The four primitives are things Microsoft's toolkit does not and cannot do with its current architecture, because they require a fundamentally different commitment — that governance is data, not software.

### Google Gemini Enterprise Agent Platform (April 2026)

Google's approach: every agent gets a unique cryptographic ID, an Agent Registry provides a single source of truth for all agents/tools/skills, and an Agent Gateway enforces access control at runtime. Deployed on Cloud Run or GKE, agents inherit managed infrastructure, authentication, and observability.

**Relevance:** Platform-level governance tied to Google Cloud. Impressive infrastructure but cloud-locked. No portable governance — your audit trail lives in Google's telemetry, not in a self-verifying artifact you own. No cold auditability. No sovereignty. The antithesis of ZeroPoint's thesis (portable trust, operator sovereignty, governance without runtime). Not a competitor in philosophy — a competitor in enterprise sales conversations.

---

## Tenant Candidates

### Tier 1: High Suitability — Large user base, explicit governance gaps

---

#### 1. Cline

**What it is:** Open-source AI coding agent. VS Code extension. 5M+ developers. Plan/Act modes, MCP integration, terminal-first workflows. The most mature MCP integration of any coding agent.

**Current governance posture:**
- Permissions: Human-in-the-loop (user clicks Approve for every file change and terminal command). UX layer, not cryptographic. No proof that permission was granted — just that the UI was shown.
- Sandbox: None. Code runs in the user's environment. "Your code stays where it belongs — inside your environment" is a privacy claim, not a security claim.
- Audit: None. No receipt chain, no governance history, no way to prove what the agent did after the fact.
- Enterprise: SSO, RBAC, remote config. Governance at the team-management level, not at the action level.

**What ZeroPoint adds:**
- Every tool invocation receipted. Every file edit is a signed governance event, not just a "user clicked Allow."
- Canonicalization of tools and providers — the agent's capabilities are constituted, not assumed.
- Cold-auditable history. "What did the agent do during that 3am deployment?" is answerable without Cline running.
- Delegation chains. Enterprise teams can delegate narrowing authority — a junior dev's Cline instance has a provably smaller capability envelope than a senior's.

**Integration surface:** MCP. Cline already speaks MCP natively. ZeroPoint as an MCP governance server sits in the path between Cline and its tools. No Cline code changes required for basic integration.

**Adoption leverage:** 5M developers. The largest potential tenant base.

**Complexity:** Low for MCP-layer governance. Medium for deep integration (canonicalizing Cline's internal tool registry).

---

#### 2. KiloCode

**What it is:** Agentic coding platform. VS Code, JetBrains, CLI, cloud, mobile. 1.5M+ users, #1 on OpenRouter, 25T+ tokens processed. Multi-mode agents (Architect, Coder, Debugger, custom). MCP marketplace. Fork of the Cline/Roo Code lineage.

**Current governance posture:**
- Permissions: UX layer. "Allow/Deny" dialogs. Explicitly not a security boundary.
- Subagent isolation: **Broken.** Open issue #7402 — subagents don't inherit caller's permission restrictions. A subagent spawned by a restricted parent can do things the parent can't.
- Sandbox: None. Documentation says "run in Docker if you need isolation."
- Audit: None beyond whatever the LLM provider logs.

**What ZeroPoint adds:**
- Fixes the subagent permission inheritance gap with delegation chains — authority can only narrow, structurally enforced by the grammar, not by checking a config flag.
- Canonicalization of each agent mode (Architect, Coder, Debugger) as a distinct governed entity with its own capability envelope.
- The MCP marketplace becomes a governed marketplace — every tool is canonicalized, every tool invocation is receipted.

**Integration surface:** MCP marketplace is the natural insertion point. ZeroPoint governance server as a required MCP server in the marketplace.

**Adoption leverage:** 1.5M users, 25T tokens. Significant scale.

**Complexity:** Medium. The subagent hierarchy needs structural work beyond what MCP-layer governance provides.

---

#### 3. OpenHands (f.k.a. OpenDevin)

**What it is:** Open-source AI-powered software development platform. 68.6K GitHub stars, $18.8M Series A. Python SDK for building, running, and scaling coding agents. Multi-agent support with agent specialization.

**Current governance posture:**
- Sandbox: Docker-based (Daytona integration). Each agent gets an isolated container, torn down post-session. **The strongest sandbox story of any candidate.**
- V1 SDK: Moving from mandatory Docker to optional sandboxing with LocalWorkspace by default. **This is a regression in isolation** — trading security for developer friction reduction.
- Event sourcing: V1 uses immutable event logs for state, enabling replay and recovery. **This is the closest any candidate comes to ZeroPoint's receipt chain**, but without cryptographic integrity (no signatures, no hash-linking, no cold auditability).
- Audit: Event logs exist but are not self-verifying. An adversary who controls the storage can modify history without detection.

**What ZeroPoint adds:**
- Cryptographic integrity on top of their existing event sourcing. Their event log becomes a receipt chain — same data, now signed and hash-linked. The upgrade path is unusually clean.
- Cold auditability. Their event logs currently require the OpenHands runtime to replay. With ZeroPoint receipts, the governance history is verifiable by anyone with the chain file.
- Canonicalization fills the gap that their V1 "optional sandboxing" creates — even without a Docker sandbox, every agent and tool is canonicalized, and every action is receipted.

**Integration surface:** Event sourcing architecture aligns naturally. ZeroPoint receipt emission can wrap their existing event emission. Python SDK integration.

**Adoption leverage:** 68.6K stars, VC-backed, active development. The V1 transition is a window of opportunity — they're rebuilding their event system anyway.

**Complexity:** Medium-high. Deep integration (wrapping event emission) is more valuable but more involved than MCP-layer governance.

**Note:** OpenHands is the candidate whose architecture is most philosophically aligned with ZeroPoint. They already believe in event sourcing as state. They just haven't taken the step to cryptographic integrity.

---

### Tier 2: Good Suitability — Significant frameworks with governance needs

---

#### 4. CrewAI

**What it is:** Python framework for multi-agent orchestration. Role-playing autonomous agents that collaborate on complex tasks. Crews (autonomous collaboration) and Flows (enterprise orchestration). Enterprise platform (CrewAI AMP) with managed deployment.

**Current governance posture:**
- Enterprise: CrewAI AMP provides "security & governance built-in with authorization, audits, isolation, and policy enforcement." Platform-level, not portable.
- NemoClaw integration: Infrastructure-level policy enforcement via NVIDIA's stack. Runtime enforcement — blocks actions that violate security policies even if agent logic changes.
- Open source: The open-source framework has no built-in governance. It's an orchestration layer, not a governance layer.

**What ZeroPoint adds:**
- Portable governance for the open-source framework — teams using CrewAI outside of AMP get governance.
- Receipt chain for crew execution. Every agent handoff, every tool invocation, every delegation is a signed governance event. The crew's execution history is a cold-auditable trajectory.
- Cross-crew trust. When crews from different organizations interact (CrewAI's roadmap direction), ZeroPoint's cross-mesh trust provides the composition mechanism.

**Integration surface:** Task decorators (CrewAI's native extension point). Microsoft's governance toolkit already integrates here — ZeroPoint should too.

**Adoption leverage:** Leading multi-agent framework. Enterprise customers via AMP.

**Complexity:** Medium. Task decorator integration is well-defined. Deep integration with Flows requires more work.

---

#### 5. Microsoft Agent Framework (AutoGen successor)

**What it is:** The production-ready convergence of AutoGen and Semantic Kernel. Multi-agent orchestration with sequential, concurrent, handoff, group chat, and Magentic-One patterns. Session-based state management, type safety, middleware, telemetry, graph-based workflows. Streaming, checkpointing, human-in-the-loop, pause/resume.

**Current governance posture:**
- Middleware pipeline: The native extension point for governance. Microsoft's own Agent Governance Toolkit integrates here.
- Human-in-the-loop: Built-in approval workflows with quorum logic.
- Checkpointing: Session state can be saved and resumed — but not cryptographically committed.

**What ZeroPoint adds:**
- The governance layer that Microsoft's own toolkit doesn't provide: receipt chains, canonicalization, cold auditability. ZeroPoint as a middleware plugin provides what the Agent Governance Toolkit misses.
- This is a "governance-on-governance" play — ZeroPoint sits beneath Microsoft's policy enforcement and provides the cryptographic proof layer that makes policy decisions verifiable after the fact.

**Integration surface:** Middleware pipeline. Well-documented, designed for exactly this kind of extension.

**Adoption leverage:** Microsoft ecosystem. Enterprise adoption.

**Complexity:** Medium. Middleware integration is clean. The political complexity (Microsoft has their own governance story) is higher than the technical complexity.

---

#### 6. AG2 (AutoGen community fork)

**What it is:** Community-led fork of AutoGen 0.2. Backward-compatible with the legacy GroupChat-style API. Ground-up "AG2 Beta" redesign with streaming, event-driven architecture, dependency injection, typed tools. Original creators retain control of PyPI packages and Discord.

**Current governance posture:**
- Minimal. Community-governed project focused on agent orchestration, not agent governance. The Beta's event-driven architecture is a potential integration point but has no cryptographic integrity.

**What ZeroPoint adds:**
- Everything. AG2 has no governance layer. ZeroPoint provides the full stack — canonicalization, receipting, delegation chains, cold auditability.
- The Beta's event-driven architecture is a natural fit for receipt emission.

**Integration surface:** Event-driven architecture in Beta. Callback system in stable.

**Adoption leverage:** Smaller than Microsoft Agent Framework but independent community. Researchers and prototypers.

**Complexity:** Low-medium. Less enterprise infrastructure to navigate than Microsoft's stack.

---

### Tier 3: Complementary Layers — Not tenants, but integration targets

---

#### 7. OB1 (Open Brain) — Nate B. Jones

**What it is:** Personal knowledge infrastructure. Postgres + pgvector + MCP server. One database, one AI gateway. 10 MCP tools for thought capture, search, browsing. $0.10/month self-hosted. ~260 GitHub stars.

**Current governance posture:**
- Auth: Single long-lived API key. No per-tool permissions, no delegation, no audit.
- Memory: No provenance. No chain integrity. No canonicalization. A thought captured today is indistinguishable from one modified yesterday. No way to prove a memory wasn't tampered with.
- Audit: None beyond Postgres logs.

**What ZeroPoint adds:**
- Memory tier governance. Every thought capture is a receipted event. Memory promotion (observation → working → reference) follows the governed pipeline with human review gates.
- Provenance. "Who wrote this memory, when, and what was the context?" becomes a verifiable chain, not a database query.
- Canonicalization of the memory store itself — the store is a governed entity with a canonical identity, not just a database.

**Integration surface:** MCP. OB1 already exposes MCP tools. ZeroPoint governance wraps the MCP interface.

**Adoption leverage:** Small but growing. The "personal knowledge" angle is compelling for individual operators.

**Complexity:** Low. MCP integration is straightforward. The deeper question is whether OB1's architecture (Supabase + pgvector) can support receipt chain storage efficiently.

**Strategic note:** OB1 is interesting not as a large-scale tenant but as a proof-of-concept for governed memory. A demo that shows "your personal AI memory, but every thought is receipted and you can prove it was never tampered with" is a powerful narrative.

---

#### 8. Google Agent Development Kit (ADK)

**What it is:** Google's open-source event-driven framework for building stateful AI agents. Graph-based orchestration, multi-agent support, MCP integration. Deploys to Cloud Run, GKE, or local.

**Current governance posture:**
- Agent Identity: Unique cryptographic ID per agent. Auditable trail.
- Agent Registry: Single source of truth for agents, tools, skills. Discovery and governance.
- Agent Gateway: Runtime enforcement of access control.
- **Cloud-locked.** All governance features require Google Cloud deployment. No portable governance, no cold auditability, no operator sovereignty.

**What ZeroPoint adds:**
- Portable governance for ADK agents running outside Google Cloud. The agent's governance history travels with the agent, not with the platform.
- Cold auditability. Google's governance requires their infrastructure. ZeroPoint's requires a file.

**Integration surface:** Plugin system (Microsoft's toolkit already integrates). MCP support.

**Adoption leverage:** Google ecosystem. Enterprise.

**Complexity:** Medium. The governance layer is a complement to Google's, not a replacement — political positioning matters.

---

### Tier 4: Watch List — Early, niche, or evolving

---

#### 9. Aider

**What it is:** AI pair programming in the terminal. 100+ language support. Repository-wide codebase mapping. Clean, focused, CLI-first.

**Current governance posture:**
- None. No permissions model, no sandbox, no audit. Aider operates with the user's full filesystem permissions. It's a power tool, not a governed tool.

**What ZeroPoint adds:**
- Everything. But Aider's philosophy is minimalist CLI tooling — governance may feel like overhead to its user base.

**Integration surface:** Limited. No MCP, no plugin system, no middleware. Integration would require Aider code changes or a wrapper.

**Adoption leverage:** Popular in the CLI-first developer community but smaller than Cline/KiloCode.

**Complexity:** High relative to value. Aider's architecture isn't designed for extensibility.

---

## The Lineup at a Glance

| # | Candidate | Category | Users/Stars | Governance Gap | ZP Integration | Priority |
|---|-----------|----------|-------------|---------------|----------------|----------|
| 1 | Cline | Coding agent | 5M devs | No receipting, no audit, UX-only permissions | MCP (clean) | **High** |
| 2 | KiloCode | Coding agent | 1.5M users | Broken subagent isolation, no sandbox | MCP marketplace | **High** |
| 3 | OpenHands | Coding agent | 68.6K stars | Event sourcing without crypto integrity | Event wrapping | **High** |
| 4 | CrewAI | Multi-agent | Leading framework | No portable governance in OSS | Task decorators | Medium |
| 5 | MS Agent Framework | Multi-agent | MS ecosystem | Checkpoints without crypto commitment | Middleware | Medium |
| 6 | AG2 | Multi-agent | Community | No governance layer | Event system | Medium |
| 7 | OB1 | Memory | ~260 stars | No provenance, no audit, no tamper evidence | MCP | Medium |
| 8 | Google ADK | Agent framework | Google ecosystem | Cloud-locked governance | Plugin system | Low |
| 9 | Aider | Coding agent | Popular CLI | No governance at all | Needs wrapper | Low |

---

## The Integration Thesis

ZeroPoint is not competing with these frameworks — it is the governance substrate they are all missing. The pattern is consistent across every candidate:

- They all enforce policies at runtime. None produce cryptographic proof of policy decisions.
- They all have some form of identity. None treat identity as a constitutive act by the operator.
- They all log events. None produce self-verifying, cold-auditable governance histories.
- They all manage trust. None model trust as a verifiable trajectory.

Microsoft's Agent Governance Toolkit gets closest — Ed25519 signatures, execution rings, trust scoring, OWASP coverage. But it is governance-as-software. ZeroPoint is governance-as-data. That is not a feature difference. It is an architectural commitment that changes what is possible.

The question for each tenant is not "can ZeroPoint govern it?" (yes, via MCP or native integration) but "what story does governing it tell?" The best tenant integrations are the ones where the governance gap is visible to the tenant's own users — where the upgrade from "trust the UI" to "verify the chain" is something a developer can feel.

---

## Next Steps

1. **Prototype: Cline + ZeroPoint MCP governance.** Cline's MCP maturity makes it the lowest-friction first integration. A demo where every Cline tool invocation produces a signed receipt is achievable with the existing codebase.
2. **Engage OpenHands.** Their V1 event sourcing redesign is a window. An open conversation about cryptographic integrity for their event log could lead to a deep integration.
3. **Differentiation doc vs. Microsoft.** The Agent Governance Toolkit is April 2, 2026 — three weeks old. ZeroPoint needs a clear, published differentiation that names it directly and explains why governance-as-data beats governance-as-software.
4. **Watch Google.** Their Agent Identity (cryptographic ID per agent) and Agent Registry (single source of truth) echo ZeroPoint's canonicalization. If they add chain integrity, the differentiation narrows. If they stay cloud-locked, ZeroPoint's portability is the permanent wedge.

---

*Every framework on this list enforces governance while running. None of them prove governance after stopping. That is the gap. That is ZeroPoint.*
